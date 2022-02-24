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
 * gstor_handle.c
 *    gstor handle
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_handle.c
 *
 * -------------------------------------------------------------------------
 */

#include "gstor_handle.h"
#include "gstor_instance.h"

static void knl_reset_session(knl_session_t *knl_session, bool32 inc_serial_id)
{
    knl_session->status = SESSION_INACTIVE;
    knl_session->ssn = 0;
    knl_session->spid = 0;
    if (inc_serial_id) {
        knl_session->serial_id += 1;
    }
    knl_session->canceled = GS_FALSE;
    knl_session->force_kill = GS_FALSE;
    knl_session->killed = GS_FALSE;
    knl_session->autotrace = GS_FALSE;
    knl_session->trig_ui = NULL;
    knl_session->lock_wait_timeout = knl_session->kernel->attr.lock_wait_timeout;
    knl_session->thread_shared = GS_FALSE;
    knl_session->interactive_altpwd = GS_FALSE;
    CM_ASSERT(knl_session->page_stack.depth == 0);
}

static inline bool32 knl_session_in_trans(knl_session_t *knl_session)
{
    xact_status_t status = knl_xact_status(knl_session);
    return (status != XACT_END ||
        knl_xa_xid_valid(&knl_session->rm->xa_xid) ||
        knl_session->rm->query_scn != GS_INVALID_ID64 ||
        knl_session->rm->svpt_count > 0);
}

static void knl_release_trans(knl_session_t *knl_session)
{
    do {
        if (knl_session_in_trans(knl_session)) {
            GS_LOG_DEBUG_WAR("The transaction is not over. session id = %u", knl_session->id);
            knl_rollback(knl_session, NULL);
        }
        unlock_tables_directly(knl_session);
        (void)knl_release_auton_rm(knl_session);
    } while (KNL_IS_AUTON_SE(knl_session));
}

void knl_cleanup_session(knl_session_t *knl_session)
{
    knl_release_trans(knl_session);
    knl_close_temp_tables(knl_session, DICT_TYPE_TEMP_TABLE_SESSION);
    knl_release_temp_dc(knl_session);
    if (knl_session->page_stack.depth != 0) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "session->knl_session.page_stack.depth(%u) == 0",
            knl_session->page_stack.depth);
    }
    knl_reset_session(knl_session, GS_FALSE);

    knl_destroy_se_alcks(knl_session);

#ifdef DB_DEBUG_VERSION
    knl_clear_syncpoint_action(knl_session);
#endif /* DB_DEBUG_VERSION */
}

void knl_free_session(knl_session_t *knl_session)
{
    uint32 id = knl_session->id;
    knl_destroy_session(&g_instance->kernel, id);
    CM_FREE_PTR(knl_session->stack);
    CM_FREE_PTR(knl_session);
    g_instance->kernel.sessions[id] = NULL;
}

void knl_free_sys_sessions(void)
{
    for (uint32 i = 0; i < GS_SYS_SESSIONS; i++) {
        knl_session_t *session = g_instance->kernel.sessions[i];
        if (session != NULL) {
            knl_free_session(session);
        }
    }
}

static void knl_init_new_session(knl_session_t *knl_session, cm_stack_t *stack, char *plog_buf)
{
    knl_instance_t *kernel = &g_instance->kernel;

    cm_spin_lock(&g_instance->lock, NULL);
    uint32 sid = g_instance->hwm;
    knl_session->id = sid;
    kernel->sessions[sid] = knl_session;
#if defined(__arm__) || defined(__aarch64__)
    CM_MFENCE;
#endif
    g_instance->hwm++;
    kernel->assigned_sessions++;
    cm_spin_unlock(&g_instance->lock);
    knl_init_session(kernel, sid, knl_session->uid, plog_buf, stack);
}

static status_t alloc_session_memory(knl_instance_t *kernel, knl_session_t **knl_session)
{
    uint32 mem_size = sizeof(knl_session_t);

    uint32 len =
        sizeof(mtrl_context_t) + sizeof(mtrl_segment_t) * (kernel->attr.max_temp_tables * 2 - GS_MAX_MATERIALS);

    mem_size += len;
    len = (uint32)(sizeof(knl_temp_cache_t) * kernel->attr.max_temp_tables);

    mem_size += len;
    len = (uint32)(sizeof(void *) * kernel->attr.max_temp_tables);

    mem_size += len;
    char *buf = (char *)malloc(mem_size);
    if (buf == NULL) {
        GS_LOG_RUN_INF("[alloc_session_memory] alloc memory %u failed", mem_size);
        return GS_ERROR;
    }

    errno_t rc_memzero = memset_s(buf, mem_size, 0, mem_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        GS_LOG_RUN_INF("[alloc_session_memory] memset failed, err code %d", rc_memzero);
        return GS_ERROR;
    }

    *knl_session = (knl_session_t *)buf;
    buf += sizeof(knl_session_t);

    (*knl_session)->temp_mtrl = (mtrl_context_t *)buf;
    buf += sizeof(mtrl_context_t) + sizeof(mtrl_segment_t) * (kernel->attr.max_temp_tables * 2 - GS_MAX_MATERIALS);

    (*knl_session)->temp_table_cache = (knl_temp_cache_t *)buf;
    (*knl_session)->temp_table_capacity = kernel->attr.max_temp_tables;

    buf += sizeof(knl_temp_cache_t) * kernel->attr.max_temp_tables;
    (*knl_session)->temp_dc_entries = (void *)buf;
    return GS_SUCCESS;
}

static inline void calc_private_buff_len(uint32 *stack_size, uint32 *plog_size, uint32 *buf_size)
{
    knl_attr_t *attr = &g_instance->kernel.attr;

    *buf_size = sizeof(cm_stack_t);

    *stack_size = g_instance->attr.stack_size;
    *buf_size  += *stack_size;

    *plog_size = attr->page_size * GS_PLOG_PAGES;
    *buf_size += *plog_size;

    // column + offsets + lens + data
    uint32 update_buf_size = (uint32)(attr->max_column_count * sizeof(uint16) * 3 + attr->page_size);
    *buf_size += update_buf_size;
}

static status_t alloc_private_buff(cm_stack_t **stack, char **plog_buf, char **update_buf)
{
    char *stack_buf = NULL;
    uint32 stack_size, plog_size, buf_size;

    calc_private_buff_len(&stack_size, &plog_size, &buf_size);
    if (buf_size == 0) {
        GS_LOG_RUN_INF("[alloc_private_buff] invalid buffer size %u", buf_size);
        return GS_ERROR;
    }

    char *buf = (char *)malloc(buf_size);
    if (buf == NULL) {
        GS_LOG_RUN_INF("[alloc_private_buff] alloc mem %u failed", buf_size);
        return GS_ERROR;
    }

    errno_t ret = memset_s(buf, buf_size, 0, buf_size);
    if (ret != EOK) {
        CM_FREE_PTR(buf);
        GS_LOG_RUN_INF("[alloc_private_buff] memset failed, err code %d", ret);
        return GS_ERROR;
    }
    *stack      = (cm_stack_t *)buf;
    stack_buf   = buf + sizeof(cm_stack_t);
    *plog_buf   = stack_buf + stack_size;
    *update_buf = (*plog_buf) + plog_size;
    cm_stack_init(*stack, stack_buf, stack_size);
    return GS_SUCCESS;
}

static inline void knl_set_update_info(knl_instance_t *kernel, knl_session_t *knl_session, char *update_buf)
{
    knl_session->update_info.columns = (uint16 *)update_buf;
    // column_count * sizeof(uint16)
    knl_session->update_info.offsets = (uint16 *)(knl_session->update_info.columns + kernel->attr.max_column_count);
    // column_count * sizeof(uint16)
    knl_session->update_info.lens = (uint16 *)(knl_session->update_info.offsets + kernel->attr.max_column_count);
    // page size
    knl_session->update_info.data = (char *)(knl_session->update_info.lens + kernel->attr.max_column_count);
}

status_t knl_alloc_session(knl_session_t **knl_session)
{
    uint16 rmid;
    char *plog_buf         = NULL;
    char *update_buf       = NULL;
    cm_stack_t *stack      = NULL;
    knl_instance_t *kernel = &g_instance->kernel;

    GS_RETURN_IFERR(alloc_session_memory(kernel, knl_session));

    if (knl_alloc_rm(&rmid) != GS_SUCCESS) {
        CM_FREE_PTR(*knl_session);
        return GS_ERROR;
    }

    if (alloc_private_buff(&stack, &plog_buf, &update_buf) != GS_SUCCESS) {
        knl_release_rm(rmid);
        CM_FREE_PTR(*knl_session);
        return GS_ERROR;
    }

    /* set rm to session before session init, init rm later */
    (*knl_session)->rmid = rmid;
    (*knl_session)->rm   = g_instance->rm_pool.rms[rmid];
    knl_init_new_session(*knl_session, stack, plog_buf);
    knl_set_update_info(kernel, *knl_session, update_buf);
    return GS_SUCCESS;
}

status_t knl_alloc_sys_sessions(void)
{
    knl_session_t *knl_session = NULL;
    for (uint32 i = 0; i < GS_SYS_SESSIONS; i++) {
        GS_RETURN_IFERR(knl_alloc_session(&knl_session));
    }
    return GS_SUCCESS;
}

status_t knl_alloc_cursor(knl_cursor_t **cursor)
{
    knl_instance_t *kernel = &g_instance->kernel;
    uint32 ext_size = (uint32)(kernel->attr.max_column_count * sizeof(uint16));
    // kernel->attr.cursor_size:2 pages(row + page_buf) + 2 ext_size(offsets + lens)
    uint32 mem_size = kernel->attr.cursor_size + 3 * ext_size;

    *cursor = (knl_cursor_t *)malloc(mem_size);
    if (*cursor == NULL) {
        GS_LOG_RUN_INF("[srv_alloc_knl_cursor] alloc mem %u failed", mem_size);
        return GS_ERROR;
    }
    /* 2 pages, one is for cursor->row, one is for cursor->page_buf */
    char *ext_buf = (*cursor)->buf + 2 * kernel->attr.page_size;
    (*cursor)->offsets = (uint16 *)ext_buf;
    ext_buf += ext_size;
    (*cursor)->lens = (uint16 *)ext_buf;
    ext_buf += ext_size;
    (*cursor)->update_info.columns = (uint16 *)ext_buf;
    ext_buf += ext_size;
    (*cursor)->update_info.offsets = (uint16 *)ext_buf;
    ext_buf += ext_size;
    (*cursor)->update_info.lens = (uint16 *)ext_buf;
    KNL_INIT_CURSOR(*cursor);
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
