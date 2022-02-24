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
 * clt_interface.c
 *
 *
 * IDENTIFICATION
 *    src/client/clt_interface.c
 *
 * -------------------------------------------------------------------------
 */

#include "interface/clt_interface.h"
#include "clt_core.h"
#include "dcc_msg_cmd.h"
#include "clt_msg_adaptor.h"
#include "cm_error.h"
#include "cm_timer.h"
#include "cm_ip.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLT_SEQUENCE_BUFF_SIZE 11

static uint32 g_dcc_clt_ref = 0;
static spinlock_t g_dcc_clt_latch = {0};

static void clt_free_handle(clt_handle_t **handle);

static inline status_t clt_check_arguments(
    const clt_handle_t *handle, const dcc_string_t *key, const dcc_option_t *option)
{
    if (handle == NULL || key == NULL || key->data == NULL || key->len == 0 || key->len > MAX_KEY_SIZE ||
        option == NULL) {
        CM_THROW_ERROR(DCC_CLI_BAD_ARGUMENTS, "");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline void clt_register_err(void)
{
    cm_register_error(DCC_OK, "OK");
    cm_register_error(DCC_SRV_KEY_NOT_EXISTED, "key not existed");
    cm_register_error(DCC_SRV_MESSAGE_TOO_LARGE, "the message is too large");
    cm_register_error(DCC_CLI_NO_MEMORY_ERR, "not enough memory");
    cm_register_error(DCC_CLI_BAD_ARGUMENTS, "invalid arguments");
    cm_register_error(DCC_CLI_ENDPOINTS_FORMAT_ERR, "the endpoints format is wrong");
    cm_register_error(DCC_CLI_KEY_IS_EMPTY, "the key is empty");
}

int dcc_open(const dcc_open_option_t *open_option, void **handle)
{
    status_t ret;
    cm_reset_error();
    CM_CHECK_NULL_PTR(handle);
    LOG_RUN_INF("[CLI]dcc open begin");

    cm_spin_lock(&g_dcc_clt_latch, NULL);
    if (g_dcc_clt_ref == 0) {
        clt_register_err();
        clt_register_net_proc();
        ret = cm_start_timer(g_timer());
        if (ret != CM_SUCCESS) {
            cm_spin_unlock(&g_dcc_clt_latch);
            return CM_ERROR;
        }
    }
    g_dcc_clt_ref++;
    cm_spin_unlock(&g_dcc_clt_latch);

    *handle = NULL;
    ret = clt_init_handle((clt_handle_t **) handle, open_option);
    if (ret != CM_SUCCESS) {
        clt_free_handle((clt_handle_t **) handle);
        return ret;
    }

    ret = clt_init_conn((clt_handle_t *) *handle);
    if (ret != CM_SUCCESS) {
        clt_deinit((clt_handle_t **) handle);
        clt_free_handle((clt_handle_t **) handle);
        return ret;
    }

    LOG_RUN_INF("[CLI]dcc open end");
    return CM_SUCCESS;
}


static void clt_free_handle(clt_handle_t **handle)
{
    cm_spin_lock(&g_dcc_clt_latch, NULL);
    if (g_dcc_clt_ref == 1) {
        cm_close_timer(g_timer());
    }
    g_dcc_clt_ref--;
    cm_spin_unlock(&g_dcc_clt_latch);

    if (*handle == NULL) {
        return;
    }

    clt_watch_pool_deinit((*handle)->watch_manager);
    for (int32 i = 0; i < (*handle)->server_cnt; i++) {
        CM_FREE_PTR((*handle)->server_texts[i]);
    }

    CM_FREE_PTR((*handle)->passwd);
    CM_FREE_PTR((*handle)->ca_file);
    CM_FREE_PTR((*handle)->crt_file);
    CM_FREE_PTR((*handle)->key_file);
    CM_FREE_PTR((*handle)->lease_ctx);
    CM_FREE_PTR(*handle);
}


void dcc_close(void **handle)
{
    cm_reset_error();
    if (handle == NULL || *handle == NULL) {
        return;
    }
    LOG_RUN_INF("[CLI]dcc close begin");
    clt_handle_t *clt_hd = (clt_handle_t *)*handle;
    if (clt_hd->lease_ctx != NULL) {
        text_t lease = { .str = clt_hd->lease_ctx->name, .len = strlen(clt_hd->lease_ctx->name) };
        clt_lease_del(&lease);
    }
    clt_deinit((clt_handle_t **) handle);
    clt_free_handle((clt_handle_t **) handle);
    LOG_RUN_INF("[CLI]dcc close end");
}

void dcc_set_log(dcc_cb_log_output_t log_write)
{
    cm_log_param_instance()->log_write = (usr_cb_log_output_t) log_write;
    cm_log_param_instance()->log_level = MAX_LOG_LEVEL;
}

int dcc_get(void *handle, const dcc_string_t *key, const dcc_option_t *option, dcc_result_t *result)
{
    status_t ret;
    CM_CHECK_NULL_PTR(result);
    read_request_t request;
    clt_handle_t *hd = (clt_handle_t *) handle;

    cm_reset_error();
    CM_RETURN_IFERR(clt_check_arguments(hd, key, option));
    CM_CHECK_NULL_PTR(result);

    convert_get_request(key, option, &request);
    cm_spin_lock(&hd->latch, NULL);
    ret = clt_process_sync_cmd(hd, DCC_CMD_GET, &request, hd->server_cnt);
    if (ret != CM_SUCCESS) {
        cm_spin_unlock(&hd->latch);
        return ret;
    }
    ret = clt_fetch_from_pack(hd, result);
    cm_spin_unlock(&hd->latch);
    return ret;
}

int dcc_fetch(void *handle, dcc_result_t *result)
{
    status_t ret;
    cm_reset_error();
    CM_CHECK_NULL_PTR(handle);
    clt_handle_t *hd = (clt_handle_t *) handle;
    cm_spin_lock(&hd->latch, NULL);
    ret = clt_fetch_from_pack((clt_handle_t *) handle, result);
    cm_spin_unlock(&hd->latch);
    return ret;
}

int dcc_getchildren(void *handle, const dcc_string_t *key, const dcc_option_t *option,  dcc_array_t *result)
{
    status_t ret;
    cm_reset_error();
    read_request_t request;
    clt_handle_t *hd = (clt_handle_t *) handle;
    CM_RETURN_IFERR(clt_check_arguments(hd, key, option));
    CM_CHECK_NULL_PTR(result);
    convert_getchild_req(key, option, &request);
    cm_spin_lock(&hd->latch, NULL);
    ret = clt_process_sync_cmd(hd, DCC_CMD_CHILDREN, &request, hd->server_cnt);
    if (ret != CM_SUCCESS) {
        cm_spin_unlock(&hd->latch);
        return ret;
    }
    ret = clt_parse_children(handle, result);
    if (ret != CM_SUCCESS) {
        dcc_deinit_array(result);
        cm_spin_unlock(&hd->latch);
        return ret;
    }
    cm_spin_unlock(&hd->latch);
    return CM_SUCCESS;
}

void dcc_deinit_array(dcc_array_t *array)
{
    if (array == NULL) {
        return;
    }
    for (uint32 i = 0; i < array->count; i++) {
        CM_FREE_PTR(array->strings[i]);
    }
    CM_FREE_PTR(array->strings);
    array->count = 0;
}

int dcc_put(void *handle, const dcc_string_t *key, const dcc_string_t *val, const dcc_option_t *option,
    dcc_string_t *sequence_buf)
{
    int32 len;
    status_t ret;
    write_request_t request;
    clt_handle_t *hd = (clt_handle_t *) handle;

    cm_reset_error();
    CM_RETURN_IFERR(clt_check_arguments(hd, key, option));
    if (val->len > MAX_VAL_SIZE ||
        (option->put_op.sequence == 1 &&
        (sequence_buf == NULL || sequence_buf->data == NULL || sequence_buf->len < CLT_SEQUENCE_BUFF_SIZE))) {
        CM_THROW_ERROR(DCC_CLI_BAD_ARGUMENTS, "");
        return CM_ERROR;
    }

    convert_put_request(key, val, option, &request);
    cm_spin_lock(&hd->latch, NULL);
    hd->is_sequence = option->put_op.sequence == 0 ? CM_FALSE : CM_TRUE;
    ret = clt_process_sync_cmd(hd, DCC_CMD_PUT, &request, hd->server_cnt);
    if (hd->is_sequence) {
        len = sprintf_s(sequence_buf->data, CLT_SEQUENCE_BUFF_SIZE - 1, "%d", hd->sequence_no);
        if (len < 0) {
            LOG_RUN_ERR("[CLI]sprint failed");
            cm_spin_unlock(&hd->latch);
            return CM_ERROR;
        }
        sequence_buf->data[len] = '\0';
    }
    cm_spin_unlock(&hd->latch);
    return ret;
}

int dcc_delete(void *handle, const dcc_string_t *key, const dcc_option_t *option)
{
    status_t ret;
    del_request_t request;
    clt_handle_t *hd = (clt_handle_t *) handle;

    cm_reset_error();
    CM_RETURN_IFERR(clt_check_arguments(hd, key, option));
    convert_del_request(key, option, &request);

    cm_spin_lock(&hd->latch, NULL);
    ret = clt_process_sync_cmd(hd, DCC_CMD_DELETE, &request, hd->server_cnt);
    cm_spin_unlock(&hd->latch);
    return ret;
}

static status_t clt_watch(clt_handle_t *handle, const dcc_string_t *key, dcc_watch_proc_t proc, uint8 cmd,
                          const dcc_option_t *option)
{
    status_t ret;
    text_t text;
    watch_request_t request;

    cm_str2text_safe(key->data, key->len, &text);

    CM_RETURN_IFERR(clt_wait_session_id(handle));
    convert_watch_request(key, handle->session_id, option, &request);
    LOG_DEBUG_INF("[CLI]watch, cmd: %hhu, session_id: %u", cmd, handle->session_id);
    cm_spin_lock(&handle->latch, NULL);
    ret = clt_process_sync_cmd(handle, cmd, &request, handle->server_cnt);
    cm_spin_unlock(&handle->latch);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (cmd == DCC_CMD_WATCH) {
        ret = clt_watch_pool_add(handle->watch_manager, option->watch_op.prefix, &text, proc);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[CLI]add watch proc failed");
            return ret;
        }
    } else if (cmd == DCC_CMD_UNWATCH) {
        clt_watch_pool_del(handle->watch_manager, option->unwatch_op.prefix, &text);
    }

    return CM_SUCCESS;
}

int dcc_watch(void *handle, const dcc_string_t *key, const dcc_watch_proc_t proc, const dcc_option_t *option)
{
    cm_reset_error();
    clt_handle_t *hd = (clt_handle_t *) handle;
    CM_RETURN_IFERR(clt_check_arguments(handle, key, option));
    CM_CHECK_NULL_PTR(proc);

    return (int) clt_watch(hd, key, proc, DCC_CMD_WATCH, option);
}

int dcc_unwatch(void *handle, const dcc_string_t *key, const dcc_option_t *option)
{
    cm_reset_error();
    clt_handle_t *hd = (clt_handle_t *) handle;
    CM_RETURN_IFERR(clt_check_arguments(handle, key, option));
    return (int) clt_watch(hd, key, NULL, DCC_CMD_UNWATCH, option);
}

int dcc_lease_mgr_init(const dcc_open_option_t *open_option)
{
    return clt_lease_mgr_init(open_option);
}

void dcc_lease_mgr_deinit(void)
{
    clt_lease_mgr_deinit();
}

int dcc_lease_create(void *handle, const dcc_string_t *lease_name, const unsigned int ttl,
    const unsigned int is_keep_alive)
{
    status_t ret;
    lease_request_t lease_req;
    clt_handle_t *hd = (clt_handle_t *) handle;

    cm_reset_error();
    if (handle == NULL || lease_name == NULL || lease_name->data == NULL || lease_name->len == 0 ||
        lease_name->len >= MAX_LEASE_NAME_SIZE) {
        CM_THROW_ERROR(DCC_CLI_BAD_ARGUMENTS, "");
        return CM_ERROR;
    }
    if (ttl == 0) {
        CM_THROW_ERROR(DCC_CLI_BAD_ARGUMENTS, "");
        return CM_ERROR;
    }

    lease_req.lease_name.str = lease_name->data;
    lease_req.lease_name.len = lease_name->len;
    lease_req.ttl = ttl;
    cm_spin_lock(&hd->latch, NULL);
    ret = clt_process_sync_cmd(hd, DCC_CMD_LEASE_CREATE, (void *)&lease_req, hd->server_cnt);
    cm_spin_unlock(&hd->latch);
    if (ret != CM_SUCCESS || !is_keep_alive) {
        return ret;
    }

    hd->lease_ctx = (clt_lease_ctx_t *)malloc(sizeof(clt_lease_ctx_t));
    if (hd->lease_ctx == NULL) {
        CM_THROW_ERROR(DCC_CLI_NO_MEMORY_ERR, "");
        return CM_ERROR;
    }
    if (memcpy_s(hd->lease_ctx->name, MAX_LEASE_NAME_SIZE, lease_name->data, lease_name->len) != EOK) {
        CM_FREE_PTR(hd->lease_ctx);
        return CM_ERROR;
    }
    hd->lease_ctx->name[lease_name->len] = '\0';
    hd->lease_ctx->ttl = ttl;
    ret = clt_lease_add((const text_t *)lease_name, ttl);
    return ret;
}

int dcc_lease_keep_alive(void *handle, const dcc_string_t *lease_name)
{
    status_t ret;
    cm_reset_error();
    if (handle == NULL || lease_name == NULL || lease_name->data == NULL || lease_name->len == 0 ||
        lease_name->len >= MAX_LEASE_NAME_SIZE) {
        CM_THROW_ERROR(DCC_CLI_BAD_ARGUMENTS, "");
        return CM_ERROR;
    }
    ret = clt_lease_keep_alive((clt_handle_t *)handle, lease_name);
    return ret;
}

int dcc_lease_destroy(void *handle, const dcc_string_t *lease_name)
{
    status_t ret;
    lease_request_t lease_req;
    clt_handle_t *hd = (clt_handle_t *) handle;

    cm_reset_error();
    if (handle == NULL || lease_name == NULL || lease_name->data == NULL || lease_name->len == 0 ||
        lease_name->len >= MAX_LEASE_NAME_SIZE) {
        CM_THROW_ERROR(DCC_CLI_BAD_ARGUMENTS, "");
        return CM_ERROR;
    }

    clt_lease_del((const text_t *)lease_name);
    lease_req.lease_name.str = lease_name->data;
    lease_req.lease_name.len = lease_name->len;
    cm_spin_lock(&hd->latch, NULL);
    ret = clt_process_sync_cmd(hd, DCC_CMD_LEASE_DESTROY, (void *)&lease_req, hd->server_cnt);
    cm_spin_unlock(&hd->latch);
    return ret;
}

int dcc_lease_query(void *handle, const dcc_string_t *lease_name, dcc_lease_info_t *lease_info)
{
    status_t ret;
    lease_request_t lease_req;
    clt_handle_t *hd = (clt_handle_t *)handle;

    cm_reset_error();
    if (handle == NULL || lease_name == NULL || lease_name->data == NULL || lease_name->len == 0 ||
        lease_name->len >= MAX_LEASE_NAME_SIZE) {
        CM_THROW_ERROR(DCC_CLI_BAD_ARGUMENTS, "");
        return CM_ERROR;
    }
    lease_req.lease_name.str = lease_name->data;
    lease_req.lease_name.len = lease_name->len;
    cm_spin_lock(&hd->latch, NULL);
    ret = clt_process_sync_cmd(hd, DCC_CMD_LEASE_QRY, (void *)&lease_req, hd->server_cnt);
    if (ret != CM_SUCCESS) {
        cm_spin_unlock(&hd->latch);
        return CM_ERROR;
    }
    (void)clt_get_lease_info_from_pack((clt_handle_t *)handle, lease_info);
    cm_spin_unlock(&hd->latch);
    return ret;
}

int dcc_get_errorno(void)
{
    return cm_get_error_code();
}

const char *dcc_get_error(int errorno)
{
    return cm_get_errormsg(errorno);
}

g_DCC_LIB_VERSION;

static const char *GETLIBVERSION(void)
{
#ifdef WIN32
    return NULL;
#else
    return str_DCC_LIB_VERSION;
#endif
}

#ifdef WIN32

static const char *dcc_get_version(void)
{
    return "NONE";
}

#else

#endif

const char *dcc_clt_get_version(void)
{
    cm_reset_error();
    return dcc_get_version();
}

#ifdef __cplusplus
}
#endif
