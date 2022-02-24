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
 * clt_core.c
 *
 *
 * IDENTIFICATION
 *    src/client/clt_core.c
 *
 * -------------------------------------------------------------------------
 */

#include "clt_core.h"
#include "clt_msg_adaptor.h"
#include "dcc_msg_protocol.h"
#include "net_client.h"
#include "dcc_msg_cmd.h"
#include "cm_timer.h"
#include "cm_error.h"
#include "cm_thread.h"
#include "cm_file.h"
#include "cm_utils.h"

#define URL_SPLIT_CHAR      ','
#define URL_END_CHAR        '\0'
#define TIMEOUT_ONE_THIRD   3
#define CIPHER_KEY_FILE     ".cipher"
#define RAND_KEY_FILE       ".rand"
#define CLT_MEM_2_FIXED     (2)

static status_t clt_resuming_watch(clt_handle_t *handle);

static status_t clt_init_async_conn(clt_handle_t *handle);

static status_t clt_send_request(clt_handle_t *handle, uint8 cmd, const void *request);

static status_t clt_rcv_response(clt_handle_t *handle, uint8 cmd);

// format of response
// | ------------------- eof(uint32) --------------------- |
// | ------------------ count(uint32) -------------------- |
// | ------ key len(uint32) | key | val len | val | ------ |
// | ------------- repeat (count - 1) times ---------------|
// read eof and count
static inline status_t parse_response(cs_packet_t *pack, clt_handle_t *handle)
{
    CM_RETURN_IFERR(cs_get_int32(pack, (int32 *) &handle->eof));
    CM_RETURN_IFERR(cs_get_int32(pack, (int32 *) &handle->kv_cnt));
    handle->pack_offset = pack->offset;
    return CM_SUCCESS;
}

static status_t clt_create_conn(clt_handle_t *handle, bool32 is_sync);

static void clt_close_conn(clt_handle_t *handle, bool32 is_sync);

static void clt_hb_thread_entry(thread_t *thread);

static status_t clt_hb_proc(cs_packet_t *pack, void *handle);

static status_t clt_watch_proc(cs_packet_t *packet, void *handle);

static status_t clt_parse_url(clt_handle_t *handle, char *server_list);

static void clt_try_next_url(clt_handle_t *handle, bool32 is_sync);

static inline status_t clt_init_pack(cs_packet_t **packet, void *channel)
{
    *packet = cs_get_send_pack(channel);
    CM_CHECK_NULL_PTR(*packet);
    cs_init_set(*packet, CS_LOCAL_VERSION);
    return CM_SUCCESS;
}

static inline void clt_get_rcv_pack(cs_packet_t **rcv_pack, void *channel)
{
    *rcv_pack = cs_get_recv_pack(channel);
    if (*rcv_pack == NULL) {
        return;
    }
    cs_init_get(*rcv_pack);
}

static inline void clt_poll_next_url(atomic32_t *idx, int32 server_cnt)
{
    if (server_cnt == 0) {
        return;
    }
    int32 old_leader_idx = cm_atomic32_get(idx);
    (void) cm_atomic32_cas(idx, old_leader_idx, (old_leader_idx + 1) % server_cnt);
}

static status_t clt_read_key_rand(clt_handle_t *handle)
{
    int file;
    int size;
    int len = 0;
    status_t ret;
    char real_path[CM_FILE_NAME_BUFFER_SIZE] = {0};
    char buf[CM_FULL_PATH_BUFFER_SIZE] = {0};

    CM_RETURN_IFERR(realpath_file(handle->key_file, real_path, CM_FILE_NAME_BUFFER_SIZE));
    len = sprintf_s(buf, CM_FULL_PATH_BUFFER_SIZE, "%s%s", real_path, RAND_KEY_FILE);
    if (len < 0 || ((uint32) len) > CM_FULL_PATH_BUFFER_SIZE) {
        return CM_ERROR;
    }
    CM_RETURN_IFERR(cm_open_file(buf, O_BINARY | O_RDWR, &file));
    ret = cm_read_file(file, handle->cipher.rand, RANDOM_LEN, &size);
    if (ret != CM_SUCCESS || size < RANDOM_LEN) {
        cm_close_file(file);
        return CM_ERROR;
    }
    ret = cm_read_file(file, handle->cipher.salt, RANDOM_LEN, &size);
    if (ret != CM_SUCCESS || size < RANDOM_LEN) {
        cm_close_file(file);
        return CM_ERROR;
    }
    ret = cm_read_file(file, handle->cipher.IV, RANDOM_LEN, &size);
    if (ret != CM_SUCCESS || size < RANDOM_LEN) {
        cm_close_file(file);
        return CM_ERROR;
    }

    cm_close_file(file);
    return CM_SUCCESS;
}

static status_t clt_read_cipher(clt_handle_t *handle)
{
    int file;
    int len;
    status_t ret;
    char buf[CM_FULL_PATH_BUFFER_SIZE] = {0};

    len = sprintf_s(buf, CM_FULL_PATH_BUFFER_SIZE, "%s%s", handle->key_file, CIPHER_KEY_FILE);
    if (len < 0 || ((uint32) len) > CM_FULL_PATH_BUFFER_SIZE) {
        return CM_ERROR;
    }
    CM_RETURN_IFERR(cm_open_file(buf, O_BINARY | O_RDWR, &file));

    ret = cm_read_file(file, handle->cipher.cipher_text, CM_PASSWD_MAX_LEN, (int32 *) &handle->cipher.cipher_len);
    if (ret != CM_SUCCESS) {
        cm_close_file(file);
        return CM_ERROR;
    }

    cm_close_file(file);
    return CM_SUCCESS;
}

static status_t clt_init_ssl_option(clt_handle_t *handle, const dcc_open_option_t *open_option)
{
    status_t ret;

    if (open_option->ca_file != NULL) {
        uint32 ca_size = (uint32) strlen(open_option->ca_file) + 1;
        handle->ca_file = malloc(CM_FULL_PATH_BUFFER_SIZE);
        if (handle->ca_file == NULL) {
            CM_THROW_ERROR(DCC_CLI_NO_MEMORY_ERR, "");
            return CM_ERROR;
        }
        MEMS_RETURN_IFERR(memcpy_sp(handle->ca_file, CM_FULL_PATH_BUFFER_SIZE, open_option->ca_file, ca_size));
    }

    if (open_option->crt_file != NULL) {
        handle->crt_file = malloc(CM_FULL_PATH_BUFFER_SIZE);
        if (handle->crt_file == NULL) {
            CM_THROW_ERROR(DCC_CLI_NO_MEMORY_ERR, "");
            return CM_ERROR;
        }
        uint32 crt_size = (uint32) strlen(open_option->crt_file) + 1;
        MEMS_RETURN_IFERR(memcpy_sp(handle->crt_file, CM_FULL_PATH_BUFFER_SIZE, open_option->crt_file, crt_size));
    }

    if (open_option->key_file != NULL) {
        handle->key_file = malloc(CM_FULL_PATH_BUFFER_SIZE);
        if (handle->key_file == NULL) {
            CM_THROW_ERROR(DCC_CLI_NO_MEMORY_ERR, "");
            return CM_ERROR;
        }
        uint32 key_size = (uint32) strlen(open_option->key_file) + 1;
        MEMS_RETURN_IFERR(memcpy_sp(handle->key_file, CM_FULL_PATH_BUFFER_SIZE, open_option->key_file, key_size));

        handle->passwd = (uchar *) malloc(CM_PASSWD_MAX_LEN);
        if (handle->passwd == NULL) {
            CM_THROW_ERROR(DCC_CLI_NO_MEMORY_ERR, "");
            return CM_ERROR;
        }

        ret = clt_read_cipher(handle);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[CLI]decode cipher failed");
            return CM_ERROR;
        }

        ret = clt_read_key_rand(handle);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[CLI]decode key failed");
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

status_t clt_init_handle(clt_handle_t **handle, const dcc_open_option_t *open_option)
{
    status_t ret;
    *handle = malloc(sizeof(clt_handle_t));
    if (*handle == NULL) {
        CM_THROW_ERROR(DCC_CLI_NO_MEMORY_ERR, "");
        return CM_ERROR;
    }
    MEMS_RETURN_IFERR(memset_sp(*handle, sizeof(clt_handle_t), 0, sizeof(clt_handle_t)));

    ret = clt_parse_url(*handle, open_option->server_list);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(DCC_CLI_ENDPOINTS_FORMAT_ERR, "");
        LOG_RUN_ERR("[CLI]the endpoints's format is wrong");
        return CM_ERROR;
    }
    if (open_option->clt_name == NULL) {
        CM_THROW_ERROR(DCC_CLI_ENDPOINTS_FORMAT_ERR, "");
        LOG_RUN_ERR("[CLI]the clt_name is NULL");
        return CM_ERROR;
    }
    size_t len = strlen(open_option->clt_name) + 1;
    MEMS_RETURN_IFERR(memcpy_sp((*handle)->clt_name, MAX_CLI_NAME_ZIE, open_option->clt_name, len));

    ret = clt_init_ssl_option(*handle, open_option);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[CLI]init ssl option failed");
        return CM_ERROR;
    }

    ret = clt_watch_pool_init(&(*handle)->watch_manager);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[CLI]init watcher manager failed");
        return CM_ERROR;
    }

    (*handle)->time_out = open_option->time_out;
    (*handle)->hb_interval = open_option->time_out / TIMEOUT_ONE_THIRD;
    (void) cm_atomic32_add(&(*handle)->conn_idx, (int32) cm_random((*handle)->server_cnt));
    return CM_SUCCESS;
}

static status_t clt_parse_url(clt_handle_t *handle, char *server_list)
{
    int32 server_cnt = 0;
    text_t text, l_text, r_text;
    cm_str2text(server_list, &text);
    while (text.len != 0) {
        if (server_cnt > MAX_SERVER_SIZE) {
            return CM_ERROR;
        }
        cm_split_text(&text, URL_SPLIT_CHAR, URL_END_CHAR, &l_text, &r_text);
        handle->server_texts[server_cnt] = malloc(l_text.len + 1);
        if (handle->server_texts[server_cnt] == NULL) {
            CM_THROW_ERROR(DCC_CLI_NO_MEMORY_ERR, "");
            return CM_ERROR;
        }
        MEMS_RETURN_IFERR(memcpy_sp(handle->server_texts[server_cnt], l_text.len, l_text.str, l_text.len));
        handle->server_texts[server_cnt][l_text.len] = URL_END_CHAR;

        cm_str2text_safe(r_text.str, r_text.len, &text);
        LOG_DEBUG_INF("[CLI]the endpoint%u is: %s", server_cnt, handle->server_texts[server_cnt]);
        server_cnt++;
    }
    handle->server_cnt = server_cnt;
    return CM_SUCCESS;
}

status_t clt_init_conn(clt_handle_t *handle)
{
    status_t ret;
    ret = clt_process_sync_cmd(handle, DCC_CMD_CONNECT, NULL, handle->server_cnt + 1);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[CLI]connect to leader failed");
        return ret;
    }
    return CM_SUCCESS;
}

static status_t clt_init_async_conn(clt_handle_t *handle)
{
    status_t ret;

    CM_RETURN_IFERR(cm_event_init(&handle->async_channel_event));
    ret = cm_create_thread(clt_hb_thread_entry, SIZE_M(CLT_MEM_2_FIXED), (void *) handle,
        &handle->async_channel_thread);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[CLI]create hb thread failed");
        return ret;
    }

    return CM_SUCCESS;
}

void clt_register_net_proc(void)
{
    cs_register_msg_process(DCC_CMD_WATCH, clt_watch_proc);
    cs_register_msg_process(DCC_CMD_HEARTBEAT, clt_hb_proc);
}

void clt_deinit(clt_handle_t **handle)
{
    if (*handle == NULL) {
        return;
    }
    cm_event_notify(&(*handle)->async_channel_event);
    cm_close_thread(&(*handle)->async_channel_thread);
    cm_event_destory(&(*handle)->async_channel_event);

    clt_close_conn((*handle), CM_FALSE);
    clt_close_conn((*handle), CM_TRUE);
}

static void clt_hb_thread_entry(thread_t *thread)
{
    status_t ret;
    cs_packet_t *send_pack = NULL;
    clt_handle_t *handle = (clt_handle_t *) thread->argument;

    while (!thread->closed) {
        if (handle->async_connected == CLT_NOT_CONNECTED) {
            if (handle->try_times >= (uint32)(handle->server_cnt)) {
                cm_sleep(MICROSECS_PER_MILLISEC);
                handle->try_times = 0;
            }
            if (handle->channel[ASYNC_CHANNEL_IDX] != NULL) {
                clt_close_conn(handle, CM_FALSE);
            }
            ret = clt_create_conn(handle, CM_FALSE);
            handle->try_times++;
            if (ret != CM_SUCCESS) {
                LOG_RUN_ERR("[CLI]create async conn failed");
                continue;
            }
            handle->async_connected = CLT_CONNECTING;
        }

        (void) clt_init_pack(&send_pack, handle->channel[ASYNC_CHANNEL_IDX]);
        ret = cs_remote_call_no_wait(handle->channel[ASYNC_CHANNEL_IDX], send_pack, DCC_CMD_HEARTBEAT);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[CLI]send hb message failed");
            clt_try_next_url(handle, CM_FALSE);
        }
        (void) cm_event_timedwait(&handle->async_channel_event, handle->hb_interval);
    }
}

static status_t clt_hb_proc(cs_packet_t *pack, void *handle)
{
    status_t ret;
    connect_res_t connect_res;
    clt_handle_t *hd = (clt_handle_t *) handle;
    if (pack->head->result != CM_SUCCESS || pack->head->cmd != DCC_CMD_HEARTBEAT) {
        LOG_DEBUG_ERR("[CLI]the format of hb is wrong, cmd:%hhu, code:%hhu", pack->head->cmd, pack->head->result);
        clt_try_next_url(hd, CM_FALSE);
        cm_event_notify(&hd->async_channel_event);
        return CM_ERROR;
    }

    ret = decode_connect_res(pack, &connect_res);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[CLI]decode connect response failed");
        clt_try_next_url(hd, CM_FALSE);
        cm_event_notify(&hd->async_channel_event);
        return CM_ERROR;
    }

    if (hd->async_connected != CLT_CONNECTED) {
        hd->async_connected = CLT_CONNECTED;
        hd->session_id = connect_res.session_id;
        hd->try_times = 0;

        ret = clt_resuming_watch(handle);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[CLI]resuming watch failed");
        }
        cm_event_notify(&hd->async_channel_event);
    }
    return CM_SUCCESS;
}

static status_t clt_watch_proc(cs_packet_t *packet, void *handle)
{
    text_t key;
    status_t ret;
    clt_handle_t *hd = (clt_handle_t *) handle;
    watch_res_t watch_res;
    ret = decode_watch_res(packet, &watch_res);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[CLI]decode watch res failed");
    }
    dcc_watch_result_t watch_result;
    convert_watch_response(&watch_res, &watch_result);
    uint32 is_prefix = watch_res.is_dir;
    cm_str2text_safe(watch_res.key, watch_res.key_size, &key);
    ret = clt_watch_pool_call(hd->watch_manager, &key, is_prefix, &watch_result);
    return ret;
}

static status_t clt_create_conn(clt_handle_t *handle, bool32 is_sync)
{
    status_t ret;
    uint32 passwd_len;
    conn_option_t option = {
        .connect_timeout = CM_CONNECT_TIMEOUT,
        .socket_timeout = handle->time_out,
        .ssl_para = {0}
    };

    if (handle->key_file != NULL) {
        ret = cm_decrypt_pwd(&handle->cipher, handle->passwd, &passwd_len);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[CLI]decrypt pwd failed");
            MEMS_RETURN_IFERR(memset_sp(handle->passwd, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN));
            return CM_ERROR;
        }
    }
    option.ssl_para.key_password = (char *) handle->passwd;
    option.ssl_para.key_file = handle->key_file;
    option.ssl_para.ca_file = handle->ca_file;
    option.ssl_para.cert_file = handle->crt_file;

    uint32 channel_idx = is_sync == CM_TRUE ? SYNC_CHANNEL_IDX : ASYNC_CHANNEL_IDX;
    uint32 server_idx = (uint32) (is_sync == CM_TRUE ? cm_atomic32_get(&handle->conn_idx) :
                                  cm_atomic32_get(&handle->conn_idx));
    if (is_sync) {
        handle->channel[channel_idx] = cs_connect_sync_channel(handle->server_texts[server_idx], (void *) handle,
            &option);
    } else {
        handle->channel[channel_idx] = cs_connect_async_channel(handle->server_texts[server_idx], (void *) handle,
            &option);
    }

    if (handle->key_file != NULL) {
        MEMS_RETURN_IFERR(memset_sp(handle->passwd, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN));
    }

    return handle->channel[channel_idx] == NULL ? CM_ERROR : CM_SUCCESS;
}

static void clt_close_conn(clt_handle_t *handle, bool32 is_sync)
{
    status_t ret;
    cs_packet_t *send_pack = NULL;
    uint32 channel_id = is_sync == CM_TRUE ? SYNC_CHANNEL_IDX : ASYNC_CHANNEL_IDX;
    if (handle->channel[channel_id] == NULL) {
        return;
    }

    (void) clt_init_pack(&send_pack, handle->channel[channel_id]);
    ret = cs_remote_call_no_wait(handle->channel[channel_id], send_pack, DCC_CMD_DISCONNECT);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[CLI]send close pack failed");
    }
    cs_disconnect_channel(handle->channel[channel_id]);
    handle->channel[channel_id] = NULL;
}

static void clt_try_next_url(clt_handle_t *handle, bool32 is_sync)
{
    uint32 idx = ASYNC_CHANNEL_IDX;
    if (is_sync) {
        idx = SYNC_CHANNEL_IDX;
        handle->sync_connected = CM_FALSE;
    } else {
        handle->async_connected = CLT_NOT_CONNECTED;
    }
    clt_close_conn(handle, is_sync);
    handle->channel[idx] = NULL;
    clt_poll_next_url(&handle->conn_idx, handle->server_cnt);
}

static status_t clt_send_request(clt_handle_t *handle, uint8 cmd, const void *request)
{
    cs_packet_t *send_pack;
    if (handle->sync_connected == CM_FALSE) {
        clt_close_conn(handle, CM_TRUE);
        CM_RETURN_IFERR(clt_create_conn(handle, CM_TRUE));
    }
    CM_RETURN_IFERR(clt_init_pack(&send_pack, handle->channel[SYNC_CHANNEL_IDX]));
    CM_RETURN_IFERR(encode_request(cmd, request, &send_pack));
    return cs_remote_call(handle->channel[SYNC_CHANNEL_IDX], send_pack, cmd);
}

static status_t clt_rcv_response(clt_handle_t *handle, uint8 cmd)
{
    status_t ret;
    cs_packet_t *rcv_pack = NULL;
    clt_get_rcv_pack(&rcv_pack, handle->channel[SYNC_CHANNEL_IDX]);
    if (rcv_pack->head->result != CM_SUCCESS) {
        return rcv_pack->head->result;
    }

    if (cmd == DCC_CMD_GET || cmd == DCC_CMD_FETCH) {
        // when get update the key index
        handle->kv_idx = 0;
        ret = parse_response(rcv_pack, handle);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[CLI]parse response failed");
            return CM_ERROR;
        }
    } else if (cmd == DCC_CMD_PUT && handle->is_sequence) {
        cs_get_int32(rcv_pack, (int32 *) &handle->sequence_no);
    }

    return CM_SUCCESS;
}

status_t clt_process_sync_cmd(clt_handle_t *handle, uint8 cmd, void *request, int32 try_cnt)
{
    status_t ret;
    for (int32 i = 0; i < try_cnt; i++) {
        ret = clt_send_request(handle, cmd, request);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[CLI]failed to send %hhu request", cmd);
            clt_try_next_url(handle, CM_TRUE);
            continue;
        }
        ret = clt_rcv_response(handle, cmd);
        if (ret == CM_SUCCESS) {
            handle->sync_connected = CM_TRUE;
            return CM_SUCCESS;
        } else {
            clt_try_next_url(handle, CM_TRUE);
            LOG_DEBUG_ERR("[CLI]failed to receive %hhu response", cmd);
        }
    }
    return CM_ERROR;
}

status_t clt_wait_session_id(clt_handle_t *handle)
{
    if (!handle->async_td_created) {
        CM_RETURN_IFERR(clt_init_async_conn(handle));
        handle->async_td_created = CM_TRUE;
    }
    uint32 cnt = 0;
    date_t now = g_timer()->now;
    while (handle->async_connected != CLT_CONNECTED) {
        if (cnt < TIMEOUT_ONE_THIRD) {
            (void) cm_event_timedwait(&handle->async_channel_event, handle->hb_interval);
        } else {
            break;
        }
        cnt++;
    }
    if (handle->async_connected != CLT_CONNECTED) {
        LOG_RUN_ERR("[CLI]the async conn is disconnected, time: %lld", g_timer()->now - now);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// format of response
// | ------------------- eof(uint32) --------------------- |
// | ------------------ count(uint32) -------------------- |
// | ------ key len(uint32) | key | val len | val | ------ |
// | ------------- repeat (count - 1) times ---------------|
// read data
status_t clt_fetch_from_pack(clt_handle_t *handle, dcc_result_t *result)
{
    void *data = NULL;
    CM_CHECK_NULL_PTR(result);

    if (handle->kv_idx == handle->kv_cnt && handle->eof == CM_TRUE) {
        CM_THROW_ERROR(DCC_SRV_KEY_NOT_EXISTED, "");
        return CM_ERROR;
    }

    if (handle->kv_idx == handle->kv_cnt && handle->eof == CM_FALSE) {
        LOG_DEBUG_INF("[CLI]fetch another pack of data from: %u", handle->kv_idx);
        CM_RETURN_IFERR(clt_process_sync_cmd(handle, DCC_CMD_FETCH, NULL, CLT_NO_TRY_CNT));
        LOG_DEBUG_INF("[CLI]fetch another pack of data success");
    }

    result->eof = ((handle->kv_idx + 1 == handle->kv_cnt) && handle->eof == CM_TRUE) ? CM_TRUE : CM_FALSE;

    cs_packet_t *pack = NULL;
    clt_get_rcv_pack(&pack, handle->channel[SYNC_CHANNEL_IDX]);
    pack->offset = handle->pack_offset;

    // key len
    CM_RETURN_IFERR(cs_get_int32(pack, (int32 *) &result->key_len));
    if (result->key_len == 0) {
        CM_THROW_ERROR(DCC_CLI_KEY_IS_EMPTY, "");
        return CM_ERROR;
    }
    // key
    CM_RETURN_IFERR(cs_get_data(pack, result->key_len, &data));

    errno_t errcode = memcpy_sp((void *)result->key, MAX_KEY_SIZE, data, result->key_len);
    if (errcode != EOK) {
        LOG_RUN_ERR("[CLI]copy key:%u failed", result->key_len);
        return CM_ERROR;
    }

    // val len
    CM_RETURN_IFERR(cs_get_int32(pack, (int32 *) &result->val_len));
    if (result->val_len != 0) {
        // val
        CM_RETURN_IFERR(cs_get_data(pack, result->val_len, &data));
        errcode = memcpy_sp((void *) result->val, MAX_VAL_SIZE, data, result->val_len);
        if (errcode != EOK) {
            LOG_RUN_ERR("[CLI]copy val:%u failed", result->val_len);
            return CM_ERROR;
        }
    }
    handle->kv_idx++;
    handle->pack_offset = pack->offset;
    LOG_DEBUG_INF("[CLI]fetch data success from: %u", handle->kv_idx);

    return CM_SUCCESS;
}

static status_t clt_watch_when_exception(clt_handle_t *handle, uint8 cmd)
{
    uint32 cnt = 0;
    dcc_string_t text;
    dcc_option_t option;
    clt_watch_node_t *tmp;
    watch_request_t request;
    clt_watch_node_t *cur = handle->watch_manager->watch_key_list->first;
    while (cur != NULL) {
        cnt++;
        tmp = cur->next;
        text.len = cur->clt_watch_iv.begin.len;
        text.data = cur->clt_watch_iv.begin.str;
        option.watch_op.prefix = 0;
        CM_RETURN_IFERR(clt_wait_session_id(handle));
        convert_watch_request(&text, handle->session_id, &option, &request);
        CM_RETURN_IFERR(clt_process_sync_cmd(handle, cmd, &request, CLT_TRY_ONCE));
        cur = tmp;
    }
    LOG_DEBUG_INF("[CLI]dcc resuming watch key, cnt: %u", cnt);

    cnt = 0;
    cur = handle->watch_manager->watch_group_list->first;
    while (cur != NULL) {
        tmp = cur->next;
        text.len = cur->clt_watch_iv.begin.len;
        text.data = cur->clt_watch_iv.begin.str;
        option.watch_op.prefix = 1;
        CM_RETURN_IFERR(clt_wait_session_id(handle));
        convert_watch_request(&text, handle->session_id, &option, &request);
        CM_RETURN_IFERR(clt_process_sync_cmd(handle, cmd, &request, CLT_TRY_ONCE));
        cur = tmp;
    }
    LOG_DEBUG_INF("[CLI]dcc resuming watch group, cnt: %u", cnt);

    return CM_SUCCESS;
}

static status_t clt_resuming_watch(clt_handle_t *handle)
{
    status_t ret;
    cm_spin_lock(&handle->latch, NULL);
    ret = clt_watch_when_exception(handle, DCC_CMD_WATCH);
    cm_spin_unlock(&handle->latch);
    return ret;
}

status_t clt_parse_children(clt_handle_t *handle, dcc_array_t *result)
{
    uint32 idx = 0;
    uint32 cnt = 0;
    char *key = NULL;
    uint32 key_len = 0;
    uint32 eof = CM_TRUE;
    cs_packet_t *packet = NULL;
    result->count = 0;
    clt_get_rcv_pack(&packet, handle->channel[SYNC_CHANNEL_IDX]);
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &eof));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &cnt));
    if (!eof) {
        CM_THROW_ERROR(DCC_SRV_MESSAGE_TOO_LARGE, "");
        return CM_ERROR;
    }
    if (cnt == 0) {
        result->strings = NULL;
        return CM_SUCCESS;
    }
    result->strings = (dcc_string_t **) malloc(sizeof(dcc_string_t *) * cnt);
    if (result->strings == NULL) {
        return CM_ERROR;
    }
    for (; idx < cnt; idx++) {
        CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &key_len));
        if (key_len <= 0) {
            CM_THROW_ERROR(DCC_CLI_KEY_IS_EMPTY, "");
            return CM_ERROR;
        }
        CM_RETURN_IFERR(cs_get_data(packet, key_len, (void **) &key));
        result->strings[idx] = (dcc_string_t *) malloc(sizeof(dcc_string_t) + key_len);
        if (result->strings[idx] == NULL) {
            LOG_RUN_ERR("[CLI]alloc memory: %u failed", key_len);
            return CM_ERROR;
        }
        result->count++;
        result->strings[idx]->len = key_len;
        result->strings[idx]->data = (char *) result->strings[idx] + sizeof(dcc_string_t);
        MEMS_RETURN_IFERR(memcpy_sp(result->strings[idx]->data, key_len, key, key_len));
    }
    return CM_SUCCESS;
}

status_t clt_get_lease_info_from_pack(clt_handle_t *handle, dcc_lease_info_t *lease_info)
{
    net_channel_t *chan =  (net_channel_t *)(handle->channel[SYNC_CHANNEL_IDX]);
    cs_packet_t *pack = &chan->recv_pack;
    cs_init_get(pack);
    CM_RETURN_IFERR(cs_get_int32(pack, (int32 *)&lease_info->ttl));
    CM_RETURN_IFERR(cs_get_int32(pack, (int32 *)&lease_info->remain_ttl));
    return CM_SUCCESS;
}

int clt_lease_keep_alive(clt_handle_t *handle, const dcc_string_t *lease_name)
{
    status_t ret;
    lease_request_t lease_req;
    lease_req.lease_name.str = lease_name->data;
    lease_req.lease_name.len = lease_name->len;
    cm_spin_lock(&handle->latch, NULL);
    ret = clt_process_sync_cmd(handle, DCC_CMD_LEASE_RENEW, (void *)&lease_req, handle->server_cnt);
    cm_spin_unlock(&handle->latch);
    return ret;
}

