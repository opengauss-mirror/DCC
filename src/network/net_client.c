/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * net_client.c
 *    network process
 *
 * IDENTIFICATION
 *    src/network/net_client.c
 *
 * -------------------------------------------------------------------------
 */

#include "util_defs.h"
#include "net_client.h"

#ifdef __cplusplus
extern "C" {
#endif

static net_state_t g_net = {0};

static inline status_t cs_check_cmd(const void *channel, const cs_packet_t *pack, uint8 cmd)
{
    CM_ASSERT(channel != NULL);
    CM_ASSERT(pack != NULL);
    if (SECUREC_UNLIKELY(cmd >= DCC_CMD_CEIL)) {
        LOG_DEBUG_ERR("[NET]invalid command %u", cmd);
        return CM_ERROR;
    } else {
        return CM_SUCCESS;
    }
}

static status_t conn_ssl_requst(net_channel_t *channel, uint32 ssl_req, uint8 cmd)
{
    uint32 ssl_ack;
    uint32 ack_size;
    bool32 ready = CM_FALSE;

    cs_pipe_t *pipe = &channel->pipe;
    cs_packet_t *send_pack = &channel->send_pack;
    cs_init_set(send_pack, CS_LOCAL_VERSION);
    send_pack->head->cmd = cmd;
    CM_RETURN_IFERR(cs_put_int32(send_pack, ssl_req));
    if (cs_write(pipe, send_pack) != CM_SUCCESS) {
        LOG_RUN_ERR("[NET]pipe write ssl req failed.");
        return CM_ERROR;
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, pipe->connect_timeout, &ready) != CM_SUCCESS) {
        LOG_RUN_ERR("[NET]pipe wait ssl ack failed.");
        return CM_ERROR;
    }
    if (!ready) {
        LOG_RUN_ERR("[NET]wait for reply timeout: %dms", pipe->connect_timeout);
        return CM_ERROR;
    }

    if (cmd == DCC_CMD_LOOPBACK) {
        cs_packet_t *recv_pack = &channel->recv_pack;
        if (cs_read(pipe, recv_pack, CM_TRUE) != CM_SUCCESS) {
            LOG_RUN_ERR("[NET]pipe read ssl ack1 failed.");
            return CM_ERROR;
        }
        cs_init_get(recv_pack);
        CM_RETURN_IFERR(cs_get_int32(recv_pack, (int32 *)&ssl_ack));
        if (recv_pack->head->cmd != cmd || ssl_ack != ssl_req) {
            LOG_RUN_ERR("[NET]pipe ssl_ack=%u or cmd=%u error.", ssl_ack, recv_pack->head->cmd);
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }

    // read server ssl ack
    if (cs_read_bytes(pipe, (char *)&ssl_ack, sizeof(ssl_ack), (int32 *)&ack_size) != CM_SUCCESS) {
        LOG_RUN_ERR("[NET]pipe read ssl ack0 failed.");
        return CM_ERROR;
    }
    ssl_ack = CS_DIFFERENT_ENDIAN(pipe->options) ? cs_reverse_int32(ssl_ack) : ssl_ack;
    if (ack_size != sizeof(ssl_ack) || ssl_ack != ssl_req) {
        LOG_RUN_ERR("[NET]pipe ssl_ack=%u or size=%u error.", ssl_ack, ack_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t conn_ssl_establish(net_channel_t *channel, conn_option_t *option)
{
    CM_RETURN_IFERR(conn_ssl_requst(channel, CSO_SUPPORT_SSL, DCC_CMD_SSL));

    ssl_ctx_t *ssl_fd;
    ssl_config_t para = { 0 };
    ssl_config_t *client_ssl_para = &option->ssl_para;
    para.ca_file = client_ssl_para->ca_file;
    para.key_file = client_ssl_para->key_file;
    para.cert_file = client_ssl_para->cert_file;
    para.crl_file = client_ssl_para->crl_file;
    para.key_password = client_ssl_para->key_password;
    para.cipher = client_ssl_para->cipher;
    para.verify_peer = CM_TRUE;
    char *key_pwd = (char *)client_ssl_para->key_password;

    /* check certificate file access permission */
    if (para.ca_file) {
        CM_RETURN_IFERR_EX(
            cs_ssl_verify_file_stat(para.ca_file), (void)memset_s(key_pwd, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN));
    }
    if (para.key_file) {
        CM_RETURN_IFERR_EX(
            cs_ssl_verify_file_stat(para.key_file), (void)memset_s(key_pwd, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN));
    }
    if (para.cert_file) {
        CM_RETURN_IFERR_EX(
            cs_ssl_verify_file_stat(para.cert_file), (void)memset_s(key_pwd, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN));
    }
    if (para.crl_file) {
        CM_RETURN_IFERR_EX(
            cs_ssl_verify_file_stat(para.crl_file), (void)memset_s(key_pwd, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN));
    }

    /* create the ssl connector - init ssl and load certs */
    ssl_fd = cs_ssl_create_connector_fd(&para);

    /* erase key_password for security issue */
    MEMS_RETURN_IFERR(memset_sp(key_pwd, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN));

    if (ssl_fd == NULL) {
        LOG_RUN_ERR("[NET]channel ssl_create_connector_fd failed.");
        return CM_ERROR;
    }
    channel->ssl_connector_fd = ssl_fd;

    /* connect to the server */
    if (cs_ssl_connect(ssl_fd, &channel->pipe) != CM_SUCCESS) {
        LOG_RUN_ERR("[NET]channel ssl_connect failed.");
        return CM_ERROR;
    }

    /* verify if ssl channel ok. */
    CM_RETURN_IFERR(conn_ssl_requst(channel, CSO_SUPPORT_SSL, DCC_CMD_LOOPBACK));

    return CM_SUCCESS;
}

static inline status_t cs_register_channel(void *channel)
{
    struct epoll_event ev;
    int fd = (int)((net_channel_t *)channel)->pipe.link.tcp.sock;

    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT;
    ev.data.ptr = channel;
    if (epoll_ctl(g_net.async_thread.epollfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        LOG_RUN_ERR("[NET]register channel failed.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[NET]register sucessfully.");

    return CM_SUCCESS;
}

static inline void cs_unregister_channel(const void *channel)
{
    int fd = (int)((net_channel_t *)channel)->pipe.link.tcp.sock;

    if (epoll_ctl(g_net.async_thread.epollfd, EPOLL_CTL_DEL, fd, NULL) != 0) {
        LOG_RUN_ERR("[NET] unregister channel failed.");
        return;
    }

    LOG_DEBUG_INF("[NET]unregister sucessfully.");
}

static inline status_t cs_set_oneshot(net_channel_t *channel)
{
    struct epoll_event ev;
    int fd = (int)channel->pipe.link.tcp.sock;

    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT;
    ev.data.ptr = (void *)channel;

    if (epoll_ctl(g_net.async_thread.epollfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        LOG_DEBUG_ERR("[NET] set_oneshot failed.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[NET] set_oneshot success.");
    return CM_SUCCESS;
}

void cs_disconnect_channel(void *channel)
{
    if (channel == NULL) {
        LOG_DEBUG_ERR("[NET]channel is already null.");
        return;
    }

    ((net_channel_t *)channel)->pipe_active = CM_FALSE;

    if (((net_channel_t *)channel)->ssl_connector_fd != NULL) {
        cs_ssl_free_context(((net_channel_t *)channel)->ssl_connector_fd);
        ((net_channel_t *)channel)->ssl_connector_fd = NULL;
    }

    if (((net_channel_t *)channel)->is_async == CM_TRUE) {
        async_thread_info_t *athread = &g_net.async_thread;
        cm_spin_lock(&athread->lock, NULL);
        if (athread->ref_cnt > 1) {
            cs_unregister_channel(channel);
            athread->status = ASYNC_THREAD_STATUS_PAUSING;
            while (athread->status != ASYNC_THREAD_STATUS_PAUSED && !athread->thread.closed) {
                cm_sleep(1);
            }
            athread->status = ASYNC_THREAD_STATUS_RUNNING;
            athread->ref_cnt--;
        } else {
            athread->ref_cnt = 0;
            cm_close_thread(&athread->thread);
            (void)epoll_close(athread->epollfd);
        }
        cm_spin_unlock(&athread->lock);
    }

    cs_disconnect(&((net_channel_t *)channel)->pipe);
    cs_try_free_packet_buffer(&((net_channel_t *)channel)->send_pack);
    cs_try_free_packet_buffer(&((net_channel_t *)channel)->recv_pack);
    free(channel);
    LOG_RUN_INF("[NET]disconnect success.");
}

static void *cs_connect_channel(const char *url, const void *clt_handle, const conn_option_t *option)
{
    /* alloc channel */
    net_channel_t *channel = (net_channel_t *)malloc(sizeof(net_channel_t));
    if (channel == NULL) {
        LOG_RUN_ERR("[NET]alloc channel memory for peer %s failed, size=%lu", url, sizeof(net_channel_t));
        return NULL;
    }
    if (memset_sp(channel, sizeof(net_channel_t), 0, sizeof(net_channel_t)) != EOK) {
        LOG_RUN_ERR("[NET]memset channel for peer %s failed, size=%lu", url, sizeof(net_channel_t));
        CM_FREE_PTR(channel);
        return NULL;
    }

    /* init pipe param */
    cs_pipe_t *pipe = &channel->pipe;
    pipe->connect_timeout = option->connect_timeout;
    pipe->socket_timeout = option->socket_timeout;
    pipe->l_onoff = 1;
    pipe->l_linger = 1;

    /* connect */
    if (cs_connect(url, &channel->pipe, NULL) != CM_SUCCESS) {
        LOG_RUN_ERR("[NET]connect to %s failed, error code=%d, error info=%s",
            url, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        CM_FREE_PTR(channel);
        return NULL;
    }
    channel->pipe_active = CM_TRUE;
    cs_init_pack(&channel->send_pack, pipe->options, CM_MAX_PACKET_SIZE);
    cs_init_pack(&channel->recv_pack, pipe->options, CM_MAX_PACKET_SIZE);
    channel->clt_handle = (void *)clt_handle;

     /* use ssl */
    if (pipe->options & CSO_SUPPORT_SSL) {
        if (conn_ssl_establish(channel, (conn_option_t *)option) != CM_SUCCESS) {
            LOG_RUN_ERR("[NET]conn ssl establish failed, error code=%d, error info=%s",
                cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            cs_disconnect_channel(channel);
            return NULL;
        }
        LOG_RUN_INF("[NET]ssl is enabled.");
    }
    LOG_RUN_INF("[NET]connect to peer %s success. pipe_options=%u.",
        url, pipe->options);
    return (void *)channel;
}

void *cs_connect_sync_channel(const char *url, const void *clt_handle, const conn_option_t *option)
{
    return cs_connect_channel(url, clt_handle, option);
}

void cs_register_msg_process(uint8 cmd, msg_proc_t proc)
{
    if (cmd >= DCC_CMD_CEIL) {
        LOG_RUN_ERR("[NET]cmd=%u invalid, register proc failed.", cmd);
        return;
    }
    g_net.proc[cmd] = proc;
    LOG_RUN_INF("[NET]register proc to cmd(%d) success.", cmd);
}

static void net_process_msg(net_channel_t *channel)
{
    if (cs_read(&channel->pipe, &channel->recv_pack, CM_TRUE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[NET]read message failed, error code=%d, error info=%s",
            cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        cs_disconnect(&channel->pipe);
        return;
    }
    (void)cs_set_oneshot(channel);

    cs_init_get(&channel->recv_pack);
    cs_packet_head_t *head = channel->recv_pack.head;
    if (SECUREC_UNLIKELY(head->cmd >= DCC_CMD_CEIL)) {
        LOG_DEBUG_ERR("[NET]invalid command %u", head->cmd);
        return;
    }
    msg_proc_t proc = g_net.proc[head->cmd];
    if (SECUREC_UNLIKELY(proc == NULL)) {
        LOG_DEBUG_ERR("[NET]message handling function is not registered for cmd %u", head->cmd);
        return;
    }

    (void)cm_atomic_inc(&(channel->recv_count));
    LOG_DEBUG_INF("[NET]recv async message: size[%u], cmd[%u], result[%u], "
                  "flag[%u], version[%u], serial_number[%u]",
                  head->size, head->cmd, head->result,
                  head->flags, head->version, head->serial_number);
#ifdef DB_MEC_DUMP
    cm_dump_mem(head, head->size);
#endif

    if (proc(&channel->recv_pack, channel->clt_handle) != CM_SUCCESS) {
        LOG_DEBUG_WAR("[NET]process async message failed: size[%u], cmd[%u], result[%u], "
                      "flag[%u], version[%u], serial_number[%u]",
                      head->size, head->cmd, head->result,
                      head->flags, head->version, head->serial_number);
    }
    return;
}

static void net_async_channel_entry(thread_t *thread)
{
    bool32 ready = CM_FALSE;
    cm_set_thread_name("net_async_channel_entry");
    int loop, nfds;
    net_channel_t *channel;
    struct epoll_event events[CM_EV_WAIT_NUM];
    struct epoll_event *ev = NULL;

    LOG_RUN_INF("[NET]async recv thread started, tid:%lu", thread->id);
    async_thread_info_t *athread = &g_net.async_thread;
    athread->status = ASYNC_THREAD_STATUS_RUNNING;
    while (!thread->closed) {
        if (athread->status == ASYNC_THREAD_STATUS_PAUSING) {
            athread->status = ASYNC_THREAD_STATUS_PAUSED;
        }
        nfds = epoll_wait(athread->epollfd, events, CM_EV_WAIT_NUM, CM_EV_WAIT_TIMEOUT);
        if (nfds == 0) {
            continue;
        }
        if (nfds < 0) {
            if (cm_get_os_error() != EINTR) {
                LOG_DEBUG_ERR("[NET]failed to wait for pkt, OS error:%d", cm_get_os_error());
            }
            continue;
        }

        for (loop = 0; loop < nfds; loop++) {
            ev = &events[loop];
            channel = (net_channel_t *)ev->data.ptr;

            if (channel->pipe_active != CM_TRUE) {
                LOG_DEBUG_WAR("[NET]channel pipe inactive, return. send(%lld), recv(%lld)",
                    channel->send_count, channel->recv_count);
                continue;
            }

            if (cs_wait(&channel->pipe, CS_WAIT_FOR_READ, (int32)CM_POLL_WAIT, &ready) != CM_SUCCESS) {
                LOG_DEBUG_ERR("[NET]channel pipe wait failed, return. send(%lld), recv(%lld)",
                    channel->send_count, channel->recv_count);
                cs_disconnect(&channel->pipe);
                continue;
            }
            if (!ready) {
                continue;
            }

            net_process_msg(channel);
        }
    }
    LOG_RUN_INF("[NET]async recv thread closed, tid:%lu.", thread->id);
}

void *cs_connect_async_channel(const char *url, const void *clt_handle, const conn_option_t *option)
{
    /* connect */
    net_channel_t *channel = (net_channel_t *)cs_connect_channel(url, clt_handle, option);
    if (channel == NULL) {
        LOG_RUN_ERR("[NET]async connect peer %s failed.", url);
        return NULL;
    }
    channel->is_async = CM_TRUE;

    /* all async channels in a process share one thread. */
    async_thread_info_t *athread = &g_net.async_thread;
    cm_spin_lock(&athread->lock, NULL);
    if (athread->ref_cnt == 0) {
#ifdef WIN32
        if (epoll_init() != CM_SUCCESS) {
            cm_spin_unlock(&athread->lock);
            LOG_RUN_ERR("[NET]:epoll init failed.");
            cs_disconnect_channel(channel);
            return NULL;
        }
#endif
        athread->epollfd = epoll_create1(0);
        if (athread->epollfd == -1) {
            cm_spin_unlock(&athread->lock);
            LOG_RUN_ERR("[NET]:epoll creat failed, os error=%d", cm_get_os_error());
            cs_disconnect_channel(channel);
            return NULL;
        }
        /* create recv thread */
        if (cm_create_thread(net_async_channel_entry, 0, NULL, &athread->thread) != CM_SUCCESS) {
            cm_spin_unlock(&athread->lock);
            LOG_RUN_ERR("[NET]failed to create recv thread for async channel");
            cs_disconnect_channel(channel);
            return NULL;
        }
    }
    athread->ref_cnt++;
    cm_spin_unlock(&athread->lock);

    if (cs_register_channel(channel) != CM_SUCCESS) {
        cs_disconnect_channel(channel);
        return NULL;
    }
    LOG_RUN_INF("[NET]async channel connect success. channel, ref_cnt=%u.", athread->ref_cnt);
    return (void *)channel;
}

cs_packet_t *cs_get_send_pack(const void *channel)
{
    if (channel == NULL) {
        LOG_DEBUG_ERR("[NET]channel is null.");
        return NULL;
    }

    return &((net_channel_t *)channel)->send_pack;
}

status_t cs_remote_call(void *channel, cs_packet_t *pack, uint8 cmd)
{
    CM_RETURN_IFERR(cs_check_cmd(channel, pack, cmd));

    uint8 req_cmd = cmd;
    pack->head->cmd = req_cmd;
    pack->head->serial_number = ((net_channel_t *)channel)->serial_no++;
    uint32 serial_no = pack->head->serial_number;

    cs_pipe_t *pipe = &((net_channel_t *)channel)->pipe;
    cs_packet_t *ack = &((net_channel_t *)channel)->recv_pack;
    if (cs_call_timed(pipe, pack, ack) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[NET]cs call failed, cmd=%u, serial_no=%u, error code=%d, error info=%s",
            req_cmd, serial_no, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }

    if (req_cmd != ack->head->cmd || serial_no != ack->head->serial_number) {
        LOG_DEBUG_ERR("[NET]cs call recv info not match, cmd=%u, serial_no=%u, recv_cmd=%u, recv_serial_no=%u",
            req_cmd, serial_no, ack->head->cmd, ack->head->serial_number);
        return CM_ERROR;
    }
    (void)cm_atomic_inc(&((net_channel_t *)channel)->send_count);
    (void)cm_atomic_inc(&((net_channel_t *)channel)->recv_count);
    LOG_DEBUG_INF("[NET]remote call success, cmd=%u, serial_no=%u", req_cmd, serial_no);
    return CM_SUCCESS;
}

cs_packet_t *cs_get_recv_pack(const void *channel)
{
    if (channel == NULL) {
        LOG_DEBUG_ERR("[NET]channel is null.");
        return NULL;
    }

    return &((net_channel_t *)channel)->recv_pack;
}

status_t cs_remote_call_no_wait(void *channel, cs_packet_t *pack, uint8 cmd)
{
    CM_RETURN_IFERR(cs_check_cmd(channel, pack, cmd));

    pack->head->cmd = cmd;
    pack->head->serial_number = ((net_channel_t *)channel)->serial_no++;

    cs_pipe_t *pipe = &((net_channel_t *)channel)->pipe;
    if (cs_write(pipe, pack) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[NET]cs write failed, cmd=%u, serial_no=%u, error code=%d, error info=%s",
            cmd, pack->head->serial_number, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }

    (void)cm_atomic_inc(&((net_channel_t *)channel)->send_count);
    LOG_DEBUG_INF("[NET]write success, cmd=%u, serial_no=%u", cmd, pack->head->serial_number);
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
