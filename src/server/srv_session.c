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
 * srv_session.c
 *
 * IDENTIFICATION
 *    src/server/srv_session.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_memory.h"
#include "dcc_msg_cmd.h"
#include "dcc_msg_protocol.h"
#include "srv_instance.h"
#include "srv_session.h"
#include "srv_agent.h"
#include "executor.h"
#include "srv_watch.h"
#include "util_defs.h"
#include "srv_param.h"
#include "executor_defs.h"
#include "executor_utils.h"

typedef struct st_srv_exc_get_ack {
    bool32 eof;
    uint32 fetch_nums;
} srv_exc_get_ack_t;

static inline status_t srv_send_rsp(session_t *session, int32 result)
{
    cs_packet_t *pack = NULL;
    pack = &session->agent->send_pack;
    pack->head->cmd = session->agent->recv_pack.head->cmd;
    pack->head->serial_number = session->agent->recv_pack.head->serial_number;
    pack->head->result = (uint8)result;
    return cs_write(session->pipe, pack);
}

static status_t srv_sess_exec_put(session_t *session)
{
    cs_packet_t *recv_pack = session->recv_pack;
    text_t data_buf = {
        .len = recv_pack->head->size - sizeof(cs_packet_head_t),
        .str = recv_pack->buf + sizeof(cs_packet_head_t) };
    status_t ret = exc_put(session->stg_handle, &data_buf, session->write_key, &session->index);
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        return srv_send_rsp(session, cm_get_error_code());
    }
    return CM_SUCCESS;
}

static inline status_t srv_sess_build_get_rsp(cs_packet_t *pack, const text_t *key, const text_t *value)
{
    CM_RETURN_IFERR(cs_put_text(pack, key));
    CM_RETURN_IFERR(cs_put_text(pack, value));
    return CM_SUCCESS;
}

static inline uint32 kv_actual_key_size(const text_t *key)
{
    return CM_ALIGN4(key->len) + sizeof(uint32);
}

static inline uint32 kv_actual_size(const text_t *key, const text_t *val)
{
    return CM_ALIGN4(key->len) + CM_ALIGN4(val->len) + 2 * sizeof(uint32);
}

static inline status_t srv_send_query_rsp(session_t *session, bool32 eof, uint32 fetch_nums, status_t ret)
{
    cs_packet_t *send_pack = session->send_pack;
    srv_exc_get_ack_t *ack = (srv_exc_get_ack_t *)(send_pack->buf + sizeof(cs_packet_head_t));
    ack->eof = eof;
    ack->fetch_nums = fetch_nums;
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        return srv_send_rsp(session, cm_get_error_code());
    }
    return srv_send_rsp(session, CM_SUCCESS);
}

static status_t srv_sess_fetch_key(session_t *session, text_t *key, uint32 read_level)
{
    text_t value;
    cs_packet_t *send_pack = session->send_pack;
    status_t status = exc_get(session->stg_handle, key, &value, read_level, &session->qry_eof);
    if (status != CM_SUCCESS || session->qry_eof) {
        return srv_send_query_rsp(session, CM_TRUE, 0, status);
    }

    status = srv_sess_build_get_rsp(send_pack, key, &value);
    uint32 fetch_num = status == CM_SUCCESS ? 1 : 0;
    return srv_send_query_rsp(session, CM_TRUE, fetch_num, status);
}

static status_t srv_fetch_internal(session_t *session, uint32 *fetch_nums)
{
    text_t key, value;
    cs_packet_t *send_pack = session->send_pack;

    while (!session->qry_eof) {
        CM_RETURN_IFERR(exc_cursor_fetch(session->stg_handle, &key, &value));
        if (send_pack->head->size + kv_actual_size(&key, &value) > CM_MAX_PACKET_SIZE) {
            return CM_SUCCESS;
        }
        CM_RETURN_IFERR(srv_sess_build_get_rsp(send_pack, &key, &value));
        (*fetch_nums)++;
        CM_RETURN_IFERR(exc_cursor_next(session->stg_handle, &session->qry_eof));
    }
    return CM_SUCCESS;
}

static inline status_t srv_sess_fetch_dir(session_t *session, text_t *dir, uint32 read_level)
{
    uint32 fetch_nums = 0;

    status_t ret = exc_open_cursor(session->stg_handle, dir, read_level, &session->qry_eof);
    if (ret != CM_SUCCESS || session->qry_eof) {
        return srv_send_query_rsp(session, CM_TRUE, 0, ret);
    }

    ret = srv_fetch_internal(session, &fetch_nums);
    return srv_send_query_rsp(session, session->qry_eof, fetch_nums, ret);
}

static status_t srv_sess_prepare_get(session_t *session, read_request_t *read_req)
{
    status_t ret;
    cs_packet_t *recv_pack = session->recv_pack;

    if (session->stg_handle == NULL) {
        CM_RETURN_IFERR(exc_alloc_handle(&session->stg_handle));
        ret = exc_read_handle4table(session->stg_handle, EXC_DCC_KV_TABLE);
        if (ret != CM_SUCCESS) {
            exc_free_handle(session->stg_handle);
            session->stg_handle = NULL;
            return CM_ERROR;
        }
    }

    return decode_read_request(recv_pack, read_req);
}

static status_t srv_sess_exec_get(session_t *session)
{
    read_request_t read_req;
    cs_packet_t *send_pack = session->send_pack;

    CM_RETURN_IFERR(cm_reserve_space(send_pack, sizeof(srv_exc_get_ack_t)));
    if (srv_sess_prepare_get(session, &read_req) != CM_SUCCESS) {
        return srv_send_query_rsp(session, CM_TRUE, 0, CM_ERROR);
    }

    text_t key = {.str = read_req.key, .len = (uint32)read_req.key_size};
    if (!read_req.is_dir) {
        return srv_sess_fetch_key(session, &key, read_req.read_level);
    }

    return srv_sess_fetch_dir(session, &key, read_req.read_level);
}

static status_t srv_sess_exec_fetch(session_t *session)
{
    uint32 fetch_nums = 0;
    cs_packet_t *send_pack = session->send_pack;

    CM_RETURN_IFERR(cm_reserve_space(send_pack, sizeof(srv_exc_get_ack_t)));
    if (session->stg_handle == NULL) {
        return srv_send_query_rsp(session, CM_TRUE, 0, CM_ERROR);
    }

    status_t ret = srv_fetch_internal(session, &fetch_nums);
    return srv_send_query_rsp(session, session->qry_eof, fetch_nums, ret);
}

static status_t srv_sess_children_internal(session_t *session, uint32 *nums)
{
    text_t key, value;
    cs_packet_t *send_pack = session->send_pack;
    while (!session->qry_eof) {
        CM_RETURN_IFERR(exc_cursor_fetch(session->stg_handle, &key, &value));
        if (send_pack->head->size + kv_actual_key_size(&key) > CM_MAX_PACKET_SIZE) {
            return CM_ERROR;
        }
        CM_RETURN_IFERR(cs_put_text(session->send_pack, &key));
        CM_RETURN_IFERR(exc_cursor_next(session->stg_handle, &session->qry_eof));
        ++(*nums);
    }
    return CM_SUCCESS;
}

static status_t srv_sess_exec_children(session_t *session)
{
    uint32 fetch_nums = 0;
    read_request_t read_req;
    cs_packet_t *send_pack = session->send_pack;

    CM_RETURN_IFERR(cm_reserve_space(send_pack, sizeof(srv_exc_get_ack_t)));
    if (srv_sess_prepare_get(session, &read_req) != CM_SUCCESS) {
        return srv_send_query_rsp(session, CM_TRUE, 0, CM_ERROR);
    }
    text_t key = {.str = read_req.key, .len = (uint32)read_req.key_size};
    status_t ret = exc_open_cursor(session->stg_handle, &key, read_req.read_level, &session->qry_eof);
    if (ret != CM_SUCCESS || session->qry_eof) {
        return srv_send_query_rsp(session, CM_TRUE, 0, ret);
    }
    ret = srv_sess_children_internal(session, &fetch_nums);
    return srv_send_query_rsp(session, session->qry_eof == 0 ? CM_FALSE : CM_TRUE, fetch_nums, ret);
}

static status_t srv_sess_exec_delete(session_t *session)
{
    cs_packet_t *recv_pack = session->recv_pack;
    text_t data_buf = {
        .len = recv_pack->head->size - sizeof(cs_packet_head_t),
        .str = recv_pack->buf + sizeof(cs_packet_head_t) };
    status_t ret = exc_del(session->stg_handle, &data_buf, session->write_key, &session->index);
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        return srv_send_rsp(session, cm_get_error_code());
    }
    return CM_SUCCESS;
}

static status_t srv_sess_exec_watch(session_t *session)
{
    watch_request_t req;
    cs_packet_t *recv_pack = session->recv_pack;

    if (decode_watch_request(recv_pack, &req) != CM_SUCCESS) {
        return srv_send_rsp(session, ERR_DECODE_REQUEST);
    }
    text_t watch_key = {0};
    text_t key = {.str = req.key, .len = req.key_size};
    dcc_option_t option = { 0 };
    option.watch_op.is_prefix = req.is_dir;
    option.sid = req.session_id;
    status_t ret = exc_watch(session->stg_handle, &key, srv_proc_watch_event, &option, &watch_key);
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        return srv_send_rsp(session, cm_get_error_code());
    } else {
        if (watch_key.str != NULL) {
            sess_watch_record_t *watch_record = (sess_watch_record_t *) exc_alloc(sizeof(sess_watch_record_t));
            watch_record->is_prefix = option.watch_op.is_prefix;
            watch_record->session_id = req.session_id;
            watch_record->key.len = watch_key.len;
            watch_record->key.str = watch_key.str;
            watch_record->prev = NULL;
            watch_record->next = session->watch_head;
            if (session->watch_head != NULL) {
                session->watch_head->prev = watch_record;
            }
            session->watch_head = watch_record;
        }
    }
    return srv_send_rsp(session, CM_SUCCESS);
}

static inline void srv_delete_record(sess_watch_record_t **head, sess_watch_record_t *to_deleted)
{
    if (to_deleted->prev != NULL) {
        to_deleted->prev->next = to_deleted->next;
    }
    if (to_deleted->next != NULL) {
        to_deleted->next->prev = to_deleted->prev;
    }
    if (to_deleted == *head) {
        *head = to_deleted->next;
    }
}

static status_t srv_sess_exec_unwatch(session_t *session)
{
    watch_request_t req;
    cs_packet_t *recv_pack = session->recv_pack;

    if (decode_watch_request(recv_pack, &req) != CM_SUCCESS) {
        return srv_send_rsp(session, ERR_DECODE_REQUEST);
    }
    text_t key = { .str = req.key, .len = req.key_size };
    dcc_option_t option = { 0 };
    option.watch_op.is_prefix = req.is_dir;
    option.sid = req.session_id;
    sess_watch_record_t *cur = session->watch_head;
    sess_watch_record_t *to_deleted = NULL;
    while (cur != NULL) {
        if (cm_text_equal(&cur->key, &key) && cur->is_prefix == req.is_dir) {
            to_deleted = cur;
            break;
        }
        cur = cur->next;
    }
    status_t ret = exc_unwatch(session->stg_handle, &key, &option);
    if (ret == CM_SUCCESS && to_deleted != NULL) {
        srv_delete_record(&session->watch_head, to_deleted);
        exc_free(to_deleted);
        return srv_send_rsp(session, CM_SUCCESS);
    } else {
        util_convert_exc_errno();
        return srv_send_rsp(session, cm_get_error_code());
    }
}

static status_t srv_sess_exec_lease_create(session_t *session)
{
    cs_packet_t *recv_pack = session->recv_pack;
    text_t data_buf = {
        .len = recv_pack->head->size - sizeof(cs_packet_head_t),
        .str = recv_pack->buf + sizeof(cs_packet_head_t) };
    status_t ret = exc_lease_create(session->stg_handle, &data_buf, session->write_key, &session->index);
    if (ret != CM_SUCCESS) {
        return srv_send_rsp(session, ret);
    }
    return CM_SUCCESS;
}

static status_t srv_sess_exec_lease_destroy(session_t *session)
{
    cs_packet_t *recv_pack = session->recv_pack;
    text_t data_buf = {
        .len = recv_pack->head->size - sizeof(cs_packet_head_t),
        .str = recv_pack->buf + sizeof(cs_packet_head_t) };
    status_t ret = exc_lease_destroy(session->stg_handle, &data_buf, session->write_key, &session->index);
    if (ret != CM_SUCCESS) {
        return srv_send_rsp(session, ret);
    }
    return CM_SUCCESS;
}

static status_t srv_sess_exec_lease_renew(session_t *session)
{
    cs_packet_t *recv_pack = session->recv_pack;
    text_t data_buf = {
        .len = recv_pack->head->size - sizeof(cs_packet_head_t),
        .str = recv_pack->buf + sizeof(cs_packet_head_t) };
    status_t ret = exc_lease_renew(session->stg_handle, &data_buf, session->write_key, &session->index);
    if (ret != CM_SUCCESS) {
        return srv_send_rsp(session, ret);
    }
    return CM_SUCCESS;
}

static status_t srv_sess_exec_lease_query(session_t *session)
{
    cs_packet_t *recv_pack = session->recv_pack;
    cs_packet_t *send_pack = session->send_pack;
    int32 cmd;
    CM_RETURN_IFERR(cs_get_int32(recv_pack, &cmd));
    text_t leasename;
    CM_RETURN_IFERR(cs_get_text(recv_pack, &leasename));
    exc_lease_info_t lease_info;
    status_t status = exc_lease_query(session->stg_handle, &leasename, &lease_info);
    if (status != CM_SUCCESS) {
        return srv_send_rsp(session, status);
    }
    CM_RETURN_IFERR(cs_put_int32(send_pack, lease_info.ttl));
    CM_RETURN_IFERR(cs_put_int32(send_pack, lease_info.remain_ttl));
    return srv_send_rsp(session, CM_SUCCESS);
}

static inline status_t srv_conn_hb_proc(session_t *session)
{
    cs_packet_t *pack = session->send_pack;
    bool8 is_leader = exc_is_leader();
    connect_res_t rsp = {
        .session_id = session->id,
        .is_leader = (uint32)is_leader };
    CM_RETURN_IFERR(encode_connect_res(pack, &rsp));
    return srv_send_rsp(session, CM_SUCCESS);
}

static status_t srv_service_connect(session_t *session)
{
    return srv_conn_hb_proc(session);
}

static status_t srv_service_ssl_req(session_t *session)
{
    uint32 client_ssl_req;
    uint32 srv_ssl_ack = CSO_SUPPORT_SSL;
    cs_packet_t *recv_pack = &session->agent->recv_pack;

    CM_RETURN_IFERR(cs_get_int32(recv_pack, (int32 *)&client_ssl_req));
    if (client_ssl_req != CSO_SUPPORT_SSL) {
        LOG_RUN_ERR("[SESS]srv recv ssl req=%u invalid.", client_ssl_req);
        return CM_ERROR;
    }

    if (g_srv_inst->ssl_acceptor_fd == NULL) {
        LOG_RUN_ERR("[SESS]srv ssl_acceptor_fd null.");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(cs_send_bytes(session->pipe, (const char *)&srv_ssl_ack, sizeof(srv_ssl_ack)));

    if (cs_ssl_accept(g_srv_inst->ssl_acceptor_fd, session->pipe) != CM_SUCCESS) {
        LOG_RUN_ERR("[SESS]srv ssl accept failed");
        return CM_ERROR;
    }
    LOG_RUN_INF("[SESS]srv ssl init ok.");
    return CM_SUCCESS;
}

static status_t srv_service_loopback(session_t *session)
{
    /* send back as is */
    if (cs_write(session->pipe, &session->agent->recv_pack) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SESS]loopback write failed, sid=%u, error code=%d, error info=%s",
            session->id, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void srv_unwatch_by_sess_id(session_t *session)
{
    status_t ret;
    if (session->watch_head == NULL) {
        return;
    }
    dcc_option_t option = {0};
    sess_watch_record_t *cur = session->watch_head;
    while (cur != NULL) {
        option.sid = cur->session_id;
        option.watch_op.is_prefix = cur->is_prefix;
        ret = exc_unwatch(NULL, &cur->key, &option);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[SESS]unwatch key %.*s failed", cur->key.len, cur->key.str);
        }
        exc_free(cur);
        cur = cur->next;
    }
    session->watch_head = NULL;
}

static inline status_t srv_kill_sess(session_t *session)
{
    srv_unwatch_by_sess_id(session);
    reactor_unregister_session(session);
    srv_process_free_session(session);
    return CM_SUCCESS;
}

static status_t srv_service_disconnect(session_t *session)
{
    return srv_kill_sess(session);
}

static status_t srv_service_heartbeat(session_t *session)
{
    return srv_conn_hb_proc(session);
}

typedef status_t (*srv_cmd_proc_t)(session_t *session);

static srv_cmd_proc_t g_srv_cmd_processor[] = {
    [DCC_CMD_CONNECT]    = srv_service_connect,
    [DCC_CMD_SSL]        = srv_service_ssl_req,
    [DCC_CMD_LOOPBACK]   = srv_service_loopback,
    [DCC_CMD_DISCONNECT] = srv_service_disconnect,
    [DCC_CMD_HEARTBEAT]  = srv_service_heartbeat,
    [DCC_CMD_PUT]        = srv_sess_exec_put,
    [DCC_CMD_GET]        = srv_sess_exec_get,
    [DCC_CMD_FETCH]      = srv_sess_exec_fetch,
    [DCC_CMD_CHILDREN]   = srv_sess_exec_children,
    [DCC_CMD_DELETE]     = srv_sess_exec_delete,
    [DCC_CMD_WATCH]      = srv_sess_exec_watch,
    [DCC_CMD_UNWATCH]    = srv_sess_exec_unwatch,
    [DCC_CMD_LEASE_CREATE] = srv_sess_exec_lease_create,
    [DCC_CMD_LEASE_DESTROY] = srv_sess_exec_lease_destroy,
    [DCC_CMD_LEASE_RENEW] = srv_sess_exec_lease_renew,
    [DCC_CMD_LEASE_QRY] = srv_sess_exec_lease_query,
    [DCC_CMD_CEIL]       = NULL,
};

static inline void srv_process_init_session(session_t *session)
{
    cs_init_get(session->recv_pack);
    cs_init_set(session->send_pack, CS_LOCAL_VERSION);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    /* reset packet memory to find pointer from context to packet memory */
    (void)memset_s(session->agent->recv_pack.buf, session->agent->recv_pack.buf_size,
        'Z', session->agent->recv_pack.buf_size);
#endif
}

static inline status_t srv_read_packet(session_t *session)
{
    if (cs_read(session->pipe, &session->agent->recv_pack, CM_FALSE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("srv read packet fail, sessId=%u", session->id);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t srv_process_command(session_t *session)
{
    srv_process_init_session(session);

    if (srv_read_packet(session) != CM_SUCCESS) {
        return srv_kill_sess(session);
    }

    /* process request command */
    uint32 cmd = (uint32)session->agent->recv_pack.head->cmd;
    session->serial_number = session->agent->recv_pack.head->serial_number;
    session->start_proc_time = g_timer()->now;
    LOG_DEBUG_INF("[SESS] begin to process recv msg command:%u", cmd);

    if (cmd == DCC_CMD_UNKONOW || cmd >= DCC_CMD_CEIL) {
        LOG_DEBUG_ERR("[SESS] process recv msg command:%u invalid", cmd);
        return srv_send_rsp(session, ERR_INVALID_CMD_TYPE);
    }

    srv_cmd_proc_t cmd_proc_func = g_srv_cmd_processor[cmd];
    if (cmd_proc_func(session) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SESS] process recv msg command:%u failed", cmd);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[SESS] process recv msg command:%u successfully", cmd);
    if (cmd == DCC_CMD_GET || cmd == DCC_CMD_FETCH || cmd == DCC_CMD_WATCH || cmd == DCC_CMD_UNWATCH) {
        cm_stat_record((uint32)(cmd - DCC_CMD_OP_BEGIN), (uint64)(g_timer()->now - session->start_proc_time));
    }
    return CM_SUCCESS;
}

static status_t srv_attach_reactor(session_t *session)
{
    CM_CHECK_NULL_PTR(session);
    return reactor_register_session(session);
}

static inline void srv_set_session_pipe(session_t *session, const cs_pipe_t *pipe)
{
    if (pipe != NULL) {
        session->pipe_entity = *pipe;
        session->pipe = &session->pipe_entity;
    } else {
        session->pipe = NULL;
    }
}

static void srv_reset_session(session_t *session, const cs_pipe_t *pipe)
{
    srv_set_session_pipe(session, pipe);
    session->stg_handle = NULL;

    LOG_DEBUG_INF("[SESS] reset session %u", session->id);
}

static void srv_try_reuse_session(session_t **session, const cs_pipe_t *pipe, bool32 *reused)
{
    session_pool_t *pool = &g_srv_inst->session_pool;
    biqueue_node_t *node = NULL;

    *session = NULL;
    *reused = CM_FALSE;

    if (biqueue_empty(&pool->idle_sessions)) {
        return;
    }

    cm_spin_lock(&pool->lock, NULL);
    node = biqueue_del_head(&pool->idle_sessions);
    if (node == NULL) {
        cm_spin_unlock(&pool->lock);
        return;
    }
    *session = OBJECT_OF(session_t, node);
    cm_spin_unlock(&pool->lock);

    srv_reset_session(*session, pipe);
    *reused = CM_TRUE;

    LOG_DEBUG_INF("[SESS] srv try reuse session succeed, sessid:%u", (*session)->id);
    return;
}

static bool8 is_srv_session_over_max_limit(const session_pool_t *pool)
{
    return (pool->hwm >= pool->max_sessions);
}

static status_t srv_new_session(const cs_pipe_t *pipe, session_t **session)
{
    session_pool_t *pool = &g_srv_inst->session_pool;

    if (is_srv_session_over_max_limit(pool)) {
        return CM_ERROR;
    }

    session_t *sess = (session_t *)malloc(sizeof(session_t));
    if (sess == NULL) {
        return CM_ERROR;
    }
    if (memset_s(sess, sizeof(session_t), 0, sizeof(session_t)) != EOK) {
        CM_FREE_PTR(sess);
        return CM_ERROR;
    }

    srv_set_session_pipe(sess, pipe);

    cm_spin_lock(&pool->lock, NULL);
    sess->id = pool->hwm;
    pool->sessions[sess->id] = sess;
    pool->hwm++;
    cm_spin_unlock(&pool->lock);

    LOG_DEBUG_INF("[SESS] srv alloc new session succeed, sessid:%u", sess->id);
    *session = sess;
    return CM_SUCCESS;
}

status_t srv_alloc_session(session_t **session, const cs_pipe_t *pipe, session_type_e type)
{
    bool32 reused = CM_FALSE;
    status_t ret;
    session_t *sess = NULL;

    srv_try_reuse_session(&sess, pipe, &reused);
    if (!reused) {
        ret = srv_new_session(pipe, &sess);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }

    sess->ses_type = type;
    sess->index = 0;
    sess->qry_eof = CM_TRUE;
    // update sess write_key
    (sess->serial_id)++;
    uint32 node_id = g_srv_inst->sess_apply_mgr.node_id;
    uint64 write_key = node_id;
    write_key = (write_key << EXC_BIT_MOVE_TWO_BYTES) | sess->id;
    write_key = (write_key << EXC_BIT_MOVE_FOUR_BYTES) | sess->serial_id;
    sess->write_key = write_key;
    LOG_DEBUG_INF("[SESS] update sess write_key:%llx, nodeid:%u sessid:%u serial_id:%u",
        sess->write_key, node_id, sess->id, sess->serial_id);

    if (type == SESSION_TYPE_API && sess->req_buf == NULL) {
        sess->req_buf = (char *)malloc(SRV_SESS_API_REQ_BUFF_LEN);
        if (sess->req_buf == NULL) {
            LOG_DEBUG_ERR("[SESS] srv_alloc_session malloc req_buf failed");
            srv_return_session(sess);
            return CM_ERROR;
        }
    }

    *session = sess;

    LOG_DEBUG_INF("[SESS] srv alloc session succeed, sessid:%u", sess->id);

    return CM_SUCCESS;
}

static void srv_save_remote_host(const cs_pipe_t *pipe, session_t *session)
{
    if (pipe->type == CS_TYPE_TCP) {
        (void)cm_inet_ntop((struct sockaddr *)&pipe->link.tcp.remote.addr,
                           session->os_host, (int)CM_HOST_NAME_BUFFER_SIZE);
    }
    return;
}

status_t srv_create_session(const cs_pipe_t *pipe)
{
    session_t *session = NULL;

    CM_CHECK_NULL_PTR(pipe);

    // try to reuse free session, if failed, create a new one
    if (srv_alloc_session(&session, pipe, SESSION_TYPE_CS) != CM_SUCCESS) {
        return CM_ERROR;
    }

    srv_save_remote_host(pipe, session);

    if (srv_attach_reactor(session) != CM_SUCCESS) {
        LOG_RUN_WAR("[SESS] session(%u) attach reactor failed", session->id);
        srv_release_session(session);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void srv_deinit_session(session_t *session)
{
    if (session->pipe != NULL) {
        cs_disconnect(session->pipe);
    }
    if (session->stg_handle != NULL) {
        exc_free_handle(session->stg_handle);
        session->stg_handle = NULL;
    }
    session->is_reg = CM_FALSE;
    session->proto_type = PROTO_TYPE_UNKNOWN;
    session->os_host[0] = '\0';
    return;
}

void srv_return_session(session_t *session)
{
    session_pool_t *sess_pool = &g_srv_inst->session_pool;
    session->reactor = NULL;
    session->is_free = CM_TRUE;
    cm_spin_lock(&sess_pool->lock, NULL);
    biqueue_add_tail(&sess_pool->idle_sessions, QUEUE_NODE_OF(session));
    cm_spin_unlock(&sess_pool->lock);

    LOG_DEBUG_INF("[SESS] try return session %u", session->id);
}

void srv_release_session(session_t *session)
{
    srv_deinit_session(session);
    CM_MFENCE;
    srv_return_session(session);
}

status_t srv_init_session_pool(void)
{
    srv_inst_t *instance = srv_get_instance();
    CM_ASSERT(instance != NULL);

    session_pool_t *session_pool = &instance->session_pool;
    MEMS_RETURN_IFERR(memset_s(session_pool, sizeof(session_pool_t), 0, sizeof(session_pool_t)));

    session_pool->lock = 0;
    biqueue_init(&instance->session_pool.idle_sessions);
    session_pool->hwm = 0;
    param_value_t param_value;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_MAX_SESSIONS, &param_value));
    session_pool->max_sessions = param_value.uint32_val;

    return CM_SUCCESS;
}

void srv_kill_all_session(void)
{
    uint32 i;
    srv_inst_t *instance = srv_get_instance();
    CM_ASSERT(instance != NULL);

    session_pool_t *session_pool = &instance->session_pool;
    /* kill all user session */
    for (i = 0; i < session_pool->hwm; i++) {
        session_t *sess = session_pool->sessions[i];
        if (sess == NULL) {
            continue;
        }
        if (sess->ses_type == SESSION_TYPE_API) {
            CM_FREE_PTR(sess->req_buf);
        }
        if (sess->is_reg && !(sess->is_free)) {
            if (srv_kill_sess(sess) != CM_SUCCESS) {
                LOG_RUN_ERR("[SESS] srv kill sess error");
            }
        }
        CM_FREE_PTR(session_pool->sessions[i]);
    }
    LOG_RUN_INF("[SESS] kill all session end");
    return;
}

void srv_wait_all_session_free(void)
{
    uint32 i;
    session_pool_t *pool = &g_srv_inst->session_pool;
    for (;;) {
        for (i = 0; i < pool->hwm; i++) {
            if (!pool->sessions[i]->is_free) {
                break;
            }
        }
        if (i >= pool->hwm) {
            break;
        }
        cm_sleep(CM_SLEEP_50_FIXED);
    }
}

status_t srv_get_sess_by_id(uint32 sessid, session_t **session)
{
    if (sessid >= CM_MAX_SESSIONS) {
        LOG_DEBUG_ERR("[SESS] invalid session id:%u", sessid);
        return CM_ERROR;
    }

    srv_inst_t *instance = srv_get_instance();
    CM_ASSERT(instance != NULL);
    session_pool_t *session_pool = &instance->session_pool;
    session_t *sess = session_pool->sessions[sessid];
    if (sess == NULL) {
        LOG_DEBUG_ERR("[SESS] get null sess by id:%u", sessid);
        return CM_ERROR;
    }
    if (sess->id != sessid || (sess->pipe != NULL && sess->is_reg == CM_FALSE)) {
        LOG_DEBUG_ERR("[SESS] failed to get sess by id:%u, sess info:is_reg:%u sessid:%u",
            sessid, sess->is_reg, sess->id);
        return CM_ERROR;
    }

    *session = sess;
    return CM_SUCCESS;
}

static status_t srv_sess_apply_send_rsp(session_t *session, sess_apply_inst_t *apply_inst,
    const sess_consense_obj_t *obj, int8 cmd_result)
{
    cs_packet_t *pack = &apply_inst->pack;
    cs_init_set(pack, CS_LOCAL_VERSION);
    pack->head->cmd = (uint8)obj->cmd;
    pack->head->serial_number = session->serial_number;
    pack->head->result = (uint8)cmd_result;
    cs_put_int32(pack, obj->sequence);
    status_t ret = cs_write(session->pipe, pack);
    if (ret == CM_SUCCESS && (obj->cmd == DCC_CMD_PUT || obj->cmd == DCC_CMD_DELETE)) {
        cm_stat_record((uint32)(obj->cmd - DCC_CMD_OP_BEGIN),
                       (uint64)(g_timer()->now - session->start_proc_time));
    }
    return ret;
}

static status_t srv_sess_apply_node(sess_apply_inst_t *apply_inst, const sess_consense_obj_t* obj)
{
    session_t *session = NULL;

    LOG_DEBUG_INF("[SESS APPLY] sess begin to apply node with index:%llu nodeid:%u sid:%u cmd:%u cmd_result:%u",
        obj->index, obj->nodeid, obj->sid, obj->cmd, obj->cmd_result);

    int ret = srv_get_sess_by_id(obj->sid, &session);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SESS APPLY] ignore session apply node since failed to get sess by id:%u cmd:%u",
            obj->sid, obj->cmd);
        return CM_ERROR;
    }

    if (obj->serial_id != session->serial_id) {
        LOG_DEBUG_ERR("[SESS APPLY] invalid session apply node with obj_serial_id:%u sess_serial_id:%u", obj->serial_id,
            session->serial_id);
        return CM_ERROR;
    }

    if (!(obj->cmd == DCC_CMD_PUT || obj->cmd == DCC_CMD_DELETE ||
        obj->cmd == DCC_CMD_LEASE_CREATE || obj->cmd == DCC_CMD_LEASE_DESTROY || obj->cmd == DCC_CMD_LEASE_RENEW)) {
        LOG_DEBUG_ERR("[SESS APPLY] invalid session apply node cmd type:%u", obj->cmd);
        return srv_sess_apply_send_rsp(session, apply_inst, obj, CM_ERROR);
    }

    if (session->pipe != NULL) {
        /* send response command */
        int8 cmd_result = (obj->cmd_result == CM_TRUE) ? CM_SUCCESS : CM_ERROR;
        ret = srv_sess_apply_send_rsp(session, apply_inst, obj, cmd_result);
    } else {
        cm_event_notify(&session->event);
    }

    LOG_DEBUG_INF("[SESS APPLY] processed sess apply node with index:%llu nodeid:%u sid:%u cmd:%u cmd_result:%u ret:%d",
        obj->index, obj->nodeid, obj->sid, obj->cmd, obj->cmd_result, ret);

    return ret;
}

static void srv_sess_apply_entry(thread_t *thread)
{
    cm_set_thread_name("dcc_srv_sess_apply");
    LOG_RUN_INF("srv sess apply thread started, tid:%lu, close:%u", thread->id, thread->closed);

    sess_apply_inst_t *apply_inst = (sess_apply_inst_t *)thread->argument;
    biqueue_t *apply_que = &apply_inst->apply_que;
    biqueue_node_t *node = NULL;
    sess_consense_obj_t *obj = NULL;

    while (!thread->closed) {
        if (biqueue_empty(apply_que)) {
            (void)cm_event_timedwait(&apply_inst->event, CM_SLEEP_1_FIXED);
            continue;
        }
        cm_spin_lock(&apply_inst->lock, NULL);
        node = biqueue_del_head(apply_que);
        cm_spin_unlock(&apply_inst->lock);
        if (node == NULL) {
            continue;
        }
        obj = OBJECT_OF(sess_consense_obj_t, node);
        int ret = srv_sess_apply_node(apply_inst, obj);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[SESS APPLY] srv sess apply node failed, index %llu nodeid:%u sid:%u cmd:%u cmd_result:%u",
                obj->index, obj->nodeid, obj->sid, obj->cmd, obj->cmd_result);
        }
        exc_free(obj);
    }
    LOG_RUN_INF("srv sess apply proc thread closed, tid:%lu, close:%u", thread->id, thread->closed);

    cm_release_thread(thread);
}

status_t srv_init_sess_apply_mgr(void)
{
    sess_apply_mgr_t *sess_apply_mgr = &g_srv_inst->sess_apply_mgr;
    sess_apply_inst_t *apply_inst = NULL;

    MEMS_RETURN_IFERR(memset_s(sess_apply_mgr, sizeof(sess_apply_mgr_t), 0, sizeof(sess_apply_mgr_t)));
    param_value_t param;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SESS_APPLY_INST_NUM, &param));
    sess_apply_mgr->apply_inst_num = param.uint32_val;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_NODE_ID, &param));
    sess_apply_mgr->node_id = param.uint32_val;

    for (uint32 i = 0; i < sess_apply_mgr->apply_inst_num; i++) {
        apply_inst = (sess_apply_inst_t *)malloc(sizeof(sess_apply_inst_t));
        if (apply_inst == NULL) {
            LOG_RUN_ERR("[SESS] srv_init_sess_apply_mgr malloc failed.");
            return CM_ERROR;
        }
        int ret = memset_s(apply_inst, sizeof(sess_apply_inst_t), 0, sizeof(sess_apply_inst_t));
        if (ret != EOK) {
            CM_FREE_PTR(apply_inst);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return CM_ERROR;
        }
        apply_inst->id = i;
        if (cm_event_init(&apply_inst->event) != CM_SUCCESS) {
            CM_FREE_PTR(apply_inst);
            LOG_RUN_ERR("[SESS] srv_init_sess_apply_mgr init apply_inst event failed.");
            return CM_ERROR;
        }

        biqueue_init(&apply_inst->apply_que);
        cs_init_pack(&apply_inst->pack, 0, CM_MAX_PACKET_SIZE);
        sess_apply_mgr->appy_inst[i] = apply_inst;
        ret = cm_create_thread(srv_sess_apply_entry, 0, (void *)apply_inst, &apply_inst->thread);
        if (ret != CM_SUCCESS) {
            CM_FREE_PTR(sess_apply_mgr->appy_inst[i]);
            LOG_RUN_ERR("[SESS] create sess apply thread failed");
            return CM_ERROR;
        }
    }
    sess_apply_mgr->is_ready = CM_TRUE;

    LOG_RUN_INF("srv init sess apply mgr succeed.");

    return CM_SUCCESS;
}

void srv_uninit_sess_apply_mgr(void)
{
    sess_apply_mgr_t *apply_mgr = &g_srv_inst->sess_apply_mgr;
    for (uint32 i = 0; i < apply_mgr->apply_inst_num; i++) {
        if (apply_mgr->appy_inst[i] != NULL) {
            cm_close_thread(&apply_mgr->appy_inst[i]->thread);
        }
        CM_FREE_PTR(apply_mgr->appy_inst[i]);
    }
}

status_t srv_sess_consensus_proc(const exc_consense_obj_t* obj)
{
    sess_apply_mgr_t *sess_apply_mgr = &g_srv_inst->sess_apply_mgr;

    uint32 serial_id = obj->key & 0xFFFFFFFF;
    uint32 sid = (obj->key >> EXC_BIT_MOVE_FOUR_BYTES) & 0x0FFFF;
    uint32 nodeid = (obj->key >> EXC_BIT_MOVE_SIX_BYTES);

    LOG_DEBUG_INF("[SESS CB] received session consensus proc with index:%llu nodeid:%u sid:%u serial_id:%u cmd:%u "
        "cmd_result:%u", obj->index, nodeid, sid, serial_id, obj->cmd, obj->cmd_result);

    if (sess_apply_mgr->is_ready != CM_TRUE) {
        LOG_DEBUG_WAR("[SESS CB] sess_apply_mgr hasn't been inited and ready when srv sess consensus proc");
        return CM_SUCCESS;
    }

    if (sess_apply_mgr->node_id != nodeid) {
        LOG_DEBUG_INF("[SESS CB] ignore sess consensus proc with nodeid:%u, local nodeid:%u",
            nodeid, sess_apply_mgr->node_id);
        return CM_SUCCESS;
    }

    uint32 apply_inst_idx = sid % sess_apply_mgr->apply_inst_num;
    sess_apply_inst_t *apply_inst = sess_apply_mgr->appy_inst[apply_inst_idx];
    sess_consense_obj_t *sess_obj = (sess_consense_obj_t *)exc_alloc(sizeof(sess_consense_obj_t));
    if (sess_obj == NULL) {
        LOG_DEBUG_ERR("[SESS CB] srv_sess_consensus_proc alloc sess consensus obj failed.");
        return CM_ERROR;
    }
    sess_obj->cmd = obj->cmd;
    sess_obj->sid = sid;
    sess_obj->nodeid = nodeid;
    sess_obj->serial_id = serial_id;
    sess_obj->index = obj->index;
    sess_obj->cmd_result = obj->cmd_result;
    sess_obj->sequence = obj->sequence;
    sess_obj->prev = sess_obj->next = NULL;
    cm_spin_lock(&apply_inst->lock, NULL);
    biqueue_add_tail(&apply_inst->apply_que, QUEUE_NODE_OF(sess_obj));
    cm_spin_unlock(&apply_inst->lock);
    cm_event_notify(&apply_inst->event);

    return CM_SUCCESS;
}

