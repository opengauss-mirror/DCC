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
 * srv_api.c
 *    server API
 *
 * IDENTIFICATION
 *    src/server/srv_api.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcc_interface.h"
#include "cm_timer.h"
#include "cm_error.h"
#include "cm_log.h"
#include "cm_latch.h"
#include "srv_logger.h"
#include "util_error.h"
#include "srv_param.h"
#include "executor.h"
#include "storage.h"
#include "dcc_msg_cmd.h"
#include "srv_session.h"
#include "srv_instance.h"
#include "cm_profile_stat.h"
#include "dcc_cmd_parse.h"
#include "srv_cmd_exe.h"
#include "dcf_interface.h"
#include "executor_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

static latch_t g_dcc_latch = {0};

#define SRV_WAIT_COMMIT_TIMEOUT_DEFAULT (5000) // ms
#define SRV_WAIT_COMMIT_EVENT_TIMEOUT (50) // ms
#define DCC_SPLIT_STRING            " "
#define DCC_ENCLOSE_CHAR            0
#define DCC_CMD_PARAMETER_CNT       16
#define DCC_TRY_BLOCK_CNT           20

typedef enum en_server_status {
    DCC_SRV_UNINIT = 0,
    DCC_SRV_RUNNING,
    DCC_SRV_STOP,
} srv_status_t;

static srv_status_t g_srv_status = DCC_SRV_UNINIT;

// block leader put/delete
typedef struct st_srv_dcc_block {
    volatile bool8 srv_blocked;
    cm_event_t srv_block_event;
    uint32 srv_wait_timeout_ms;
} srv_dcc_block_t;

static srv_dcc_block_t g_srv_dcc_block;

g_DCC_LIB_VERSION;

EXPORT_API const char *GETLIBVERSION()
{
#ifdef WIN32
    return NULL;
#else
    return str_DCC_LIB_VERSION;
#endif
}

#ifdef WIN32

const char *dcc_get_version(void)
{
    return "NONE";
}

#else

#endif

static srv_status_t srv_get_status(void)
{
    return g_srv_status;
}

static void srv_set_status(srv_status_t new_status)
{
    g_srv_status = new_status;
}

#define CHECK_SRV_STATUS(exp_status)                   \
    do {                                               \
        if (srv_get_status() != (exp_status)) {        \
            CM_THROW_ERROR(ERR_SERVER_STOPPED, "");    \
            return CM_ERROR;                           \
        }                                              \
    } while (0)

static inline status_t srv_check_handle_key(const void *handle, const dcc_text_t *key)
{
    CM_CHECK_NULL_PTR(handle);
    CM_CHECK_NULL_PTR(key);
    if (key->len > SRV_MAX_KEY_SIZE) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_VALUE, "");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline status_t srv_check_val(const dcc_text_t *val)
{
    CM_CHECK_NULL_PTR(val);
    if (val->len > SRV_MAX_VAL_SIZE) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_VALUE, "");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t srv_wait_commit(session_t *sess, uint32 timout)
{
    uint32 wait_time = 0;
    uint32 cmd_timout = (timout > 0) ? (timout * MILLISECS_PER_SECOND) : SRV_WAIT_COMMIT_TIMEOUT_DEFAULT;
    for (;;) {
        if (cm_event_timedwait(&sess->event, SRV_WAIT_COMMIT_EVENT_TIMEOUT) == CM_SUCCESS) {
            break;
        }
        wait_time += SRV_WAIT_COMMIT_EVENT_TIMEOUT;
        if (wait_time >= cmd_timout) {
            CM_THROW_ERROR(ERR_API_COMMIT_TIMEOUT, "");
            LOG_DEBUG_ERR("[API] srv api wait commit timeout.");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static int srv_check_and_block(void)
{
    date_t begin = g_timer()->now;
    while (g_srv_dcc_block.srv_blocked == CM_TRUE) {
        if (g_timer()->now - begin > g_srv_dcc_block.srv_wait_timeout_ms * MICROSECS_PER_MILLISEC) {
            break;
        }
        (void) cm_event_timedwait(&g_srv_dcc_block.srv_block_event, CM_SLEEP_1_FIXED);
    }
    if (g_srv_dcc_block.srv_blocked == CM_TRUE) {
        CM_THROW_ERROR(ERR_SERVER_IS_BLOCKED, "");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t srv_new_instance(void)
{
    if (g_srv_inst == NULL) {
        g_srv_inst = (srv_inst_t *) malloc(sizeof(srv_inst_t));
        if (g_srv_inst == NULL) {
            LOG_RUN_ERR("[API] srv_new_instance malloc failed.");
            return CM_ERROR;
        }
    }
    errno_t errcode = memset_s(g_srv_inst, sizeof(srv_inst_t), 0, sizeof(srv_inst_t));
    if (errcode != EOK) {
        CM_FREE_PTR(g_srv_inst);
        return CM_ERROR;
    }

    g_srv_inst->attr.inst_type = INST_TYPE_API;

    if (srv_init_session_pool() != CM_SUCCESS) {
        LOG_RUN_ERR("[API] srv failed to init session pool");
        CM_FREE_PTR(g_srv_inst);
        return CM_ERROR;
    }
    LOG_RUN_INF("[API] dcc srv init session pool succeed.");

    return CM_SUCCESS;
}


static status_t srv_init_stat_info(void)
{
    if (cm_profile_stat_init() != CM_SUCCESS) {
        LOG_RUN_ERR("[API] init profile stat failed");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(cm_register_stat_item(DCC_PUT, "DCCPut", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_register_stat_item(DCC_GET, "DCCGet", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_register_stat_item(DCC_FETCH, "DCCFetch", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_register_stat_item(DCC_DELETE, "DCCDel", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_register_stat_item(DCC_WATCH, "DCCWatch", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_register_stat_item(DCC_UNWATCH, "DCCUnwatch", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_register_stat_item(DCC_DB_PUT, "DBPut", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_register_stat_item(DCC_DB_GET, "DBGet", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_register_stat_item(DCC_DB_DEL, "DBDel", STAT_UNIT_MS, STAT_INDICATOR_AVG, NULL));

    return CM_SUCCESS;
}

static status_t srv_instance_init()
{
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_instance_startup = CM_FALSE;

    cm_reset_error();
    init_dcc_errno_desc();
    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        LOG_RUN_ERR("[API] cm_start_timer failed");
        return CM_ERROR;
    }

    // srv logger init
    if (init_logger() != CM_SUCCESS) {
        LOG_RUN_ERR("[API] init_logger failed");
        return CM_ERROR;
    }
    LOG_RUN_INF("[API] dcc init logger succeed.");

    if (srv_init_stat_info() != CM_SUCCESS) {
        LOG_RUN_ERR("[API] init profile stat failed");
        return CM_ERROR;
    }
    exc_try_self_recovery();
    LOG_RUN_INF("[API] dcc check if need try_self_recovery end.");
    CM_RETURN_IFERR(exc_check_first_init());
    // stg start
    if (db_startup(STARTUP_MODE_OPEN) != CM_SUCCESS) {
        LOG_RUN_ERR("[API] db_startup failed");
        exc_try_self_recovery();
        return CM_ERROR;
    }
    LOG_RUN_INF("[API] dcc db_startup succeed.");

    // executor start
    if (exc_init() != CM_SUCCESS) {
        db_shutdown();
        LOG_RUN_ERR("[API] executor module init failed");
        exc_try_self_recovery();
        return CM_ERROR;
    }
    CM_RETURN_IFERR(exc_init_done_tryclean());
    LOG_RUN_INF("[API] dcc init executor succeed.");

    if (srv_new_instance() != CM_SUCCESS) {
        db_shutdown();
        exc_deinit();
        LOG_RUN_ERR("[API] srv new instance failed");
        return CM_ERROR;
    }
    if (srv_init_sess_apply_mgr() != CM_SUCCESS) {
        srv_uninit_sess_apply_mgr();
        db_shutdown();
        exc_deinit();
        LOG_RUN_ERR("[API] srv init sess apply mgr failed");
        return CM_ERROR;
    }
    LOG_RUN_INF("[API] dcc create srv instance and init sess apply mgr succeed.");

    (void) exc_register_consensus_proc(srv_sess_consensus_proc);

    LOG_RUN_INF("[API] dcc srv instance init succeed.");

    return CM_SUCCESS;
}

static status_t srv_init_block(void)
{
    g_srv_dcc_block.srv_blocked = CM_FALSE;
    g_srv_dcc_block.srv_wait_timeout_ms = 0;
    if (cm_event_init(&g_srv_dcc_block.srv_block_event) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_start(void)
{
    cm_reset_error();
    init_dcc_errno_desc();
    cm_latch_x(&g_dcc_latch, 0, NULL);
    if (srv_get_status() == DCC_SRV_RUNNING) {
        cm_unlatch(&g_dcc_latch, NULL);
        CM_THROW_ERROR(ERR_SERVER_STOPPED, "");
        LOG_RUN_INF("[API] srv_get_status failed");
        return CM_ERROR;
    }

    if (srv_instance_init() != CM_SUCCESS) {
        cm_unlatch(&g_dcc_latch, NULL);
        CM_THROW_ERROR(ERR_SERVER_START_FAILED, "");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(srv_init_block());
    srv_set_status(DCC_SRV_RUNNING);
    cm_unlatch(&g_dcc_latch, NULL);

    param_value_t param_value;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_SUPPRESS_ENABLE, &param_value));
    cm_log_param_instance()->log_suppress_enable = (param_value.uint32_val == 1) ? CM_TRUE : CM_FALSE;
    LOG_RUN_INF("[API] dcc srv start succeed.");

    return CM_SUCCESS;
}

int srv_dcc_stop(void)
{
    cm_reset_error();
    init_dcc_errno_desc();
    cm_profile_stat_uninit();

    cm_latch_x(&g_dcc_latch, 0, NULL);
    if (srv_get_status() != DCC_SRV_RUNNING) {
        cm_unlatch(&g_dcc_latch, NULL);
        CM_THROW_ERROR(ERR_SERVER_STOPPED, "");
        return CM_ERROR;
    }

    exc_deinit();
    db_shutdown();
    srv_uninit_sess_apply_mgr();

    if (g_srv_inst->attr.inst_type == INST_TYPE_API) {
        srv_kill_all_session();
        CM_FREE_PTR(g_srv_inst);
    }

    cm_close_timer(g_timer());
    srv_set_status(DCC_SRV_STOP);
    cm_unlatch(&g_dcc_latch, NULL);

    LOG_RUN_INF("[API] dcc srv stop succeed.");
    uninit_logger();

    return CM_SUCCESS;
}

int srv_dcc_set_param(const char *param_name, const char *param_value)
{
    CM_CHECK_NULL_PTR(param_name);
    cm_reset_error();
    init_dcc_errno_desc();
    if (cm_str_equal(param_name, "SSL_PWD_PLAINTEXT")) {
        LOG_OPER("[API] dcc set param, param_name=%s param_value=%s", param_name, "***");
    } else {
        LOG_OPER("[API] dcc set param, param_name=%s param_value=%s", param_name, param_value);
    }

    return srv_set_param(param_name, param_value);
}

int srv_dcc_register_status_notify(dcc_cb_status_notify_t cb_func)
{
    cm_reset_error();
    return exc_register_status_notify_proc(cb_func);
}

int srv_dcc_register_log_output(usr_cb_log_output_t cb_func)
{
    cm_reset_error();
    if (cb_func == NULL) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_VALUE, "callback function is", "NULL");
        return CM_ERROR;
    }
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_write = (usr_cb_log_output_t) cb_func;
    return CM_SUCCESS;
}

int srv_dcc_alloc_handle(void **handle)
{
    cm_reset_error();
    init_dcc_errno_desc();
    CM_CHECK_NULL_PTR(handle);
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);

    session_t *sess = NULL;
    int ret = srv_alloc_session(&sess, NULL, SESSION_TYPE_API);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_MALLOC_MEM, "alloc server session");
        LOG_DEBUG_ERR("[API] srv api alloc session failed.");
        return CM_ERROR;
    }

    // alloc stg handle
    if (exc_alloc_handle(&sess->stg_handle) != CM_SUCCESS) {
        CM_FREE_PTR(sess->req_buf);
        srv_return_session(sess);
        CM_THROW_ERROR(ERR_MALLOC_MEM, "alloc storage handle");
        LOG_DEBUG_ERR("[API] srv api alloc db stg handle failed");
        return CM_ERROR;
    }

    if (exc_read_handle4table(sess->stg_handle, EXC_DCC_KV_TABLE) != CM_SUCCESS) {
        exc_free_handle(sess->stg_handle);
        sess->stg_handle = NULL;
        CM_FREE_PTR(sess->req_buf);
        srv_return_session(sess);
        CM_THROW_ERROR(ERR_MALLOC_MEM, "alloc storage handle");
        LOG_DEBUG_ERR("[API] srv api alloc db stg handle failed");
        return CM_ERROR;
    }

    if (cm_event_init(&sess->event) != CM_SUCCESS) {
        exc_free_handle(sess->stg_handle);
        sess->stg_handle = NULL;
        CM_FREE_PTR(sess->req_buf);
        srv_return_session(sess);
        CM_THROW_ERROR(ERR_MALLOC_MEM, "init session event");
        LOG_DEBUG_ERR("[API] srv create event failed.");
        return CM_ERROR;
    }

    *handle = (void *) sess;
    return CM_SUCCESS;
}

void srv_dcc_free_handle(void *handle)
{
    cm_reset_error();
    if (srv_get_status() != DCC_SRV_RUNNING) {
        return;
    }

    session_t *sess = (session_t *) handle;
    exc_free_handle(sess->stg_handle);
    sess->stg_handle = NULL;
    if (sess->ses_type == SESSION_TYPE_API) {
        CM_FREE_PTR(sess->req_buf);
    }
    srv_return_session(sess);
}

static inline status_t srv_dcc_put_uint32(text_t *buff, uint32 value)
{
    *(uint32 *) (buff->str + buff->len) = value;
    buff->len += sizeof(uint32);
    return CM_SUCCESS;
}

static status_t srv_dcc_put_text(text_t *buff, uint32 buff_len, const text_t *text)
{
    *(uint32 *) (buff->str + buff->len) = text->len;
    buff->len += sizeof(uint32);
    if (text->len == 0) {
        return CM_SUCCESS;
    }
    MEMS_RETURN_IFERR(memcpy_s(buff->str + buff->len, buff_len - buff->len, text->str, text->len));
    buff->len += CM_ALIGN4(text->len);
    return CM_SUCCESS;
}

int srv_dcc_get(const void *handle, dcc_text_t *range, const dcc_option_t *option,
                dcc_text_t *key, dcc_text_t *value, unsigned int *eof)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_RETURN_IFERR(srv_check_handle_key(handle, range));
    CM_CHECK_NULL_PTR(key);
    CM_CHECK_NULL_PTR(option);
    CM_CHECK_NULL_PTR(value);
    CM_CHECK_NULL_PTR(eof);
    int ret;
    int64 now = g_timer()->now;

    if (!option->read_op.is_prefix) {
        *key = *range;
        ret = exc_get(((session_t *) handle)->stg_handle, (text_t *) key, (text_t *) value,
            (uint32)option->read_op.read_level, eof);
        if (ret != CM_SUCCESS) {
            util_convert_exc_errno();
            LOG_DEBUG_ERR("[API] exc get failed or eof, ret:%d eof:%u", ret, *eof);
            return CM_ERROR;
        }
        if (*eof  == CM_TRUE) {
            CM_THROW_ERROR(ERR_KEY_NOT_FOUND, "");
            return CM_ERROR;
        }
        cm_stat_record(DCC_GET, (uint64) (g_timer()->now - now));
        return CM_SUCCESS;
    }
    ret = exc_open_cursor(((session_t *) handle)->stg_handle, (text_t *) range,
        (uint32)option->read_op.read_level, eof);
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        LOG_DEBUG_ERR("[API] exc open cursor failed or eof, ret:%d eof:%u", ret, *eof);
        return CM_ERROR;
    }
    if (*eof  == CM_TRUE) {
        CM_THROW_ERROR(ERR_KEY_NOT_FOUND, "");
        return CM_ERROR;
    }
    ret = exc_cursor_fetch(((session_t *) handle)->stg_handle, (text_t *) key, (text_t *) value);
    if (ret == CM_SUCCESS) {
        cm_stat_record(DCC_GET, (uint64) (g_timer()->now - now));
    } else {
        util_convert_exc_errno();
    }
    return ret;
}

int srv_dcc_fetch(const void *handle, dcc_text_t *key, dcc_text_t *value, const dcc_option_t *option,
    unsigned int *eof)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_RETURN_IFERR(srv_check_handle_key(handle, key));
    CM_CHECK_NULL_PTR(value);
    CM_CHECK_NULL_PTR(option);
    CM_CHECK_NULL_PTR(eof);
    int64 now = g_timer()->now;

    if (!option->read_op.is_prefix) {
        *eof = CM_TRUE;
        cm_stat_record(DCC_FETCH, (uint64) (g_timer()->now - now));
        return CM_SUCCESS;
    }

    int ret = exc_cursor_next(((session_t *) handle)->stg_handle, eof);
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        LOG_DEBUG_ERR("[API] exc cursor next failed or eof, ret:%d eof:%u", ret, *eof);
        return CM_ERROR;
    }
    if (*eof  == CM_TRUE) {
        CM_THROW_ERROR(ERR_KEY_NOT_FOUND, "");
        return CM_ERROR;
    }
    ret = exc_cursor_fetch(((session_t *) handle)->stg_handle, (text_t *) key, (text_t *) value);
    if (ret == CM_SUCCESS) {
        cm_stat_record(DCC_FETCH, (uint64) (g_timer()->now - now));
    } else {
        util_convert_exc_errno();
    }
    return ret;
}

int srv_dcc_put(const void *handle, const dcc_text_t *key, const dcc_text_t *value, dcc_option_t *option)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_RETURN_IFERR(srv_check_handle_key(handle, key));
    CM_RETURN_IFERR(srv_check_val(value));
    CM_CHECK_NULL_PTR(option);
    CM_RETURN_IFERR(srv_check_and_block());
    int64 now = g_timer()->now;

    session_t *sess = (session_t *) handle;
    CM_CHECK_NULL_PTR(sess->req_buf);

    text_t req = {
        .len = 0,
        .str = sess->req_buf};
    CM_RETURN_IFERR(srv_dcc_put_uint32(&req, DCC_CMD_PUT));
    CM_RETURN_IFERR(srv_dcc_put_uint32(&req, option->write_op.sequence));
    CM_RETURN_IFERR(srv_dcc_put_uint32(&req, option->write_op.not_existed));
    CM_RETURN_IFERR(srv_dcc_put_text(&req, SRV_SESS_API_REQ_BUFF_LEN, (text_t *) value));
    text_t exp_val = {
        .len = option->write_op.expect_val_size,
        .str = option->write_op.expect_value};
    CM_RETURN_IFERR(srv_dcc_put_text(&req, SRV_SESS_API_REQ_BUFF_LEN, &exp_val));
    uint32 lease_len = 0;
    CM_RETURN_IFERR(srv_dcc_put_uint32(&req, lease_len));
    CM_RETURN_IFERR(srv_dcc_put_text(&req, SRV_SESS_API_REQ_BUFF_LEN, (text_t *) key));

    int ret = exc_put(sess->stg_handle, &req, sess->write_key, &sess->index);
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        return CM_ERROR;
    }
    ret = srv_wait_commit(sess, option->cmd_timeout);
    if (ret == CM_SUCCESS) {
        cm_stat_record(DCC_PUT, (uint64) (g_timer()->now - now));
    } else {
        util_convert_exc_errno();
    }
    return ret;
}

int srv_dcc_delete(const void *handle, const dcc_text_t *key, const dcc_option_t *option)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_RETURN_IFERR(srv_check_handle_key(handle, key));
    CM_CHECK_NULL_PTR(option);
    CM_RETURN_IFERR(srv_check_and_block());
    int64 now = g_timer()->now;

    session_t *sess = (session_t *) handle;
    CM_CHECK_NULL_PTR(sess->req_buf);
    text_t req = {
        .len = 0,
        .str = sess->req_buf};
    CM_RETURN_IFERR(srv_dcc_put_uint32(&req, DCC_CMD_DELETE));
    CM_RETURN_IFERR(srv_dcc_put_uint32(&req, option->del_op.is_prefix));
    CM_RETURN_IFERR(srv_dcc_put_text(&req, SRV_SESS_API_REQ_BUFF_LEN, (text_t *) key));
    int ret = exc_del(sess->stg_handle, &req, sess->write_key, &sess->index);
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        return CM_ERROR;
    }
    ret = srv_wait_commit(sess, option->cmd_timeout);
    if (ret == CM_SUCCESS) {
        cm_stat_record(DCC_DELETE, (uint64) (g_timer()->now - now));
    } else {
        util_convert_exc_errno();
    }
    return ret;
}

int srv_dcc_watch(const void *handle, dcc_text_t *key, dcc_watch_proc_t proc, dcc_option_t *option)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_RETURN_IFERR(srv_check_handle_key(handle, key));
    CM_CHECK_NULL_PTR(proc);
    CM_CHECK_NULL_PTR(option);
    int64 now = g_timer()->now;

    option->sid = ((session_t *) handle)->id;
    int ret = exc_watch(((session_t *) handle)->stg_handle, (text_t *) (void *) key, proc, option, NULL);
    if (ret == CM_SUCCESS) {
        cm_stat_record(DCC_WATCH, (uint64) (g_timer()->now - now));
    } else {
        util_convert_exc_errno();
    }
    return ret;
}

int srv_dcc_unwatch(const void *handle, dcc_text_t *key)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_RETURN_IFERR(srv_check_handle_key(handle, key));
    int64 now = g_timer()->now;
    dcc_option_t option = {.sid = 0};

    option.sid = ((session_t *) handle)->id;
    int ret = exc_unwatch(((session_t *) handle)->stg_handle, (text_t *) (void *) key, &option);
    if (ret == CM_SUCCESS) {
        cm_stat_record(DCC_UNWATCH, (uint64) (g_timer()->now - now));
    } else {
        util_convert_exc_errno();
    }
    return ret;
}

const char *srv_dcc_get_version(void)
{
    cm_reset_error();
    return dcc_get_version();
}

int srv_dcc_get_errorno(void)
{
    return cm_get_error_code();
}

const char *srv_dcc_get_error(int code)
{
    return cm_get_errormsg(code);
}

int srv_dcc_get_node_status(dcc_node_status_t *node_stat)
{
    cm_reset_error();
    int ret = exc_node_is_healthy(node_stat);
    if (ret != CM_SUCCESS) {
        util_convert_exc_errno();
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_exec_cmd(void *handle, const dcc_text_t *cmd_line, dcc_text_t *ans_buf)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_CHECK_NULL_PTR(handle);
    CM_CHECK_NULL_PTR(cmd_line);
    if (cmd_line->len == 0) {
        return CM_ERROR;
    }
    CM_CHECK_NULL_PTR(cmd_line->value);
    CM_CHECK_NULL_PTR(ans_buf);
    session_t *session = (session_t *) handle;
    CM_CHECK_NULL_PTR(session->req_buf);
    MEMS_RETURN_IFERR(memset_sp(session->req_buf, SRV_SESS_API_REQ_BUFF_LEN, 0, SRV_SESS_API_REQ_BUFF_LEN));

    text_t left;
    text_t right;
    text_t cmd = {
        .len = cmd_line->len,
        .str = cmd_line->value
    };

    int argc = 0;
    text_t argv[DCC_CMD_PARAMETER_CNT];
    do {
        if (argc == DCC_CMD_PARAMETER_CNT) {
            CM_THROW_ERROR(ERR_INVALID_PARAMETER_VALUE, "cmd param num", "count is larger than 16");
            return CM_ERROR;
        }
        cm_trim_text(&cmd);
        cm_split_text(&cmd, (DCC_SPLIT_STRING)[0], DCC_ENCLOSE_CHAR, &left, &right);
        argv[argc] = left;
        cmd = right;
        argc++;
    } while (right.str != NULL);

    ans_buf->value = session->req_buf;
    ans_buf->len = 0;

    ctl_command_t ctl_command = {0};
    ctl_command.command_option.read_level = DCC_READ_LEVEL_CONSISTENT;
    int ret = ctl_parse_process(argv, argc, 0, &ctl_command);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_INVALID_CMD_CONTENT, "command content is error");
        return CM_ERROR;
    }

    return srv_exec_cmd_process(session, &ctl_command, ans_buf);
}

int srv_dcc_query_cluster_info(char *buffer, unsigned int length)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_CHECK_NULL_PTR(buffer);
    int len = dcf_query_cluster_info(buffer, length);
    if (len == 0) {
        CM_THROW_ERROR(ERR_DCF_INTERNAL, "");
        LOG_RUN_ERR("[API] dcf_query_cluster_info: error_no:%d, error_msg:%s",
            dcf_get_errorno(),
            dcf_get_error(dcf_get_errorno()));
        return 0;
    }
    return len;
}

int srv_dcc_query_leader_info(unsigned int *node_id)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    CM_CHECK_NULL_PTR(node_id);
    *node_id = exc_get_leader_id();
    if (*node_id == EXC_INVALID_NODE_ID) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_set_blocked(unsigned int is_block, unsigned int wait_timeout_ms)
{
    uint32 cnt = 0;
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    LOG_OPER("[API] dcc set blocked, is_block=%u wait_timeout_ms=%u", is_block, wait_timeout_ms);
    g_srv_dcc_block.srv_blocked = is_block == 0 ? CM_FALSE : CM_TRUE;
    g_srv_dcc_block.srv_wait_timeout_ms = wait_timeout_ms;
    cm_event_notify(&g_srv_dcc_block.srv_block_event);
    if (g_srv_dcc_block.srv_blocked) {
        while (!exc_is_idle() && cnt < DCC_TRY_BLOCK_CNT) {
            cm_sleep(CM_SLEEP_50_FIXED);
            cnt++;
        }
        return cnt < DCC_TRY_BLOCK_CNT ? CM_SUCCESS : CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_set_work_mode(dcc_work_mode_t work_mode, unsigned int vote_num)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    LOG_OPER("[API] dcc set work mode, work_mode=%d vote_num=%u", work_mode, vote_num);
    int ret = dcf_set_work_mode(DCC_STREAM_ID, work_mode, vote_num);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_DCF_INTERNAL, "");
        LOG_DEBUG_ERR(
            "[API] dcf_set_work_mode: error_no:%d, error_msg:%s", dcf_get_errorno(), dcf_get_error(dcf_get_errorno()));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_demote_follower(void)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    LOG_OPER("[API] dcc demote follower");
    int ret = dcf_demote_follower(DCC_STREAM_ID);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_DCF_INTERNAL, "");
        LOG_DEBUG_ERR("[API] dcf_demote_follower: error_no:%d, error_msg:%s",
            dcf_get_errorno(),
            dcf_get_error(dcf_get_errorno()));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_set_election_priority(unsigned long long priority)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    LOG_DEBUG_INF("[API]dcf_set_election_priority, priority :%llu", priority);

    int ret = dcf_set_election_priority(DCC_STREAM_ID, priority);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_DCF_INTERNAL, "");
        LOG_DEBUG_ERR("[API] dcf_set_election_priority: error_no:%d, error_msg:%s",
            dcf_get_errorno(), dcf_get_error(dcf_get_errorno()));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_promote_leader(unsigned int node_id, unsigned int wait_timeout_ms)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    LOG_OPER("dcc promote leader, node_id:%u wait_timeout:%u", node_id, wait_timeout_ms);
    int ret = dcf_promote_leader(DCC_STREAM_ID, node_id, wait_timeout_ms);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_DCF_INTERNAL, "");
        LOG_DEBUG_ERR(
            "[API] dcf_promote_leader: error_no:%d, error_msg:%s", dcf_get_errorno(), dcf_get_error(dcf_get_errorno()));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_backup(const char *bak_format)
{
    cm_reset_error();
    CHECK_SRV_STATUS(DCC_SRV_RUNNING);
    LOG_OPER("[API] dcc backup");
    int ret = exc_backup(bak_format);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[API] dcc backup failed: error_no:%d, error_msg:%s",
            dcf_get_errorno(), dcf_get_error(dcf_get_errorno()));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_restore(const char *restore_path)
{
    cm_reset_error();
    LOG_OPER("[API] dcc restore");
    int ret = exc_restore(restore_path, NULL, NULL);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[API] dcc restore failed: error_no:%d, error_msg:%s",
            dcf_get_errorno(), dcf_get_error(dcf_get_errorno()));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int srv_dcc_set_dcf_param(const char *param_name, const char *param_value)
{
    CM_CHECK_NULL_PTR(param_name);
    cm_reset_error();
    init_dcc_errno_desc();

    return dcf_set_param(param_name, param_value);
}

#ifdef __cplusplus
}
#endif
