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
 * storage.c
 *    storage
 *
 * IDENTIFICATION
 *    src/storage/storage.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_text.h"
#include "srv_param.h"
#include "db_handle.h"
#include "gstor_adpt.h"
#include "gstor_executor.h"
#include "storage.h"

typedef void(*db_shutdown_t)(void);
typedef int(*db_startup_t)(char *path, db_startup_mode_t startup_mode);
typedef void(*db_free_t)(void *handle);
typedef void(*db_clean_t)(void *handle);
typedef int(*db_alloc_t)(void **handle);
typedef int(*db_open_t)(void *handle, const char *table_name);
typedef int(*db_begin_t)(void *handle);
typedef int(*db_commit_t)(void *handle);
typedef int(*db_rollback_t)(void *handle);
typedef int(*db_del_t)(void *handle, char *key, uint32 key_len, bool32 prefix, uint32 *count);
typedef int(*db_put_t)(void *handle, char *key, uint32 key_len, char *val, uint32 val_len);
typedef int(*db_get_t)(void *handle, char *key, uint32 key_len, char **val, uint32 *val_len, bool32 *eof);
typedef int(*db_cursor_next_t)(void *handle, bool32 *eof);
typedef int(*db_open_cursor_t)(void *handle, char *key, uint32 key_len, uint32 flags, bool32 *eof);
typedef int(*db_cursor_fetch_t)(void *handle, char **key, uint32 *key_len, char **val, uint32 *val_len);
typedef int(*db_backup_t)(void *handle, const char *bak_format);
typedef int(*db_restore_t)(void *handle, const char *restore_path, const char *old_path, const char *new_path);

typedef struct st_db {
    db_put_t          put;
    db_del_t          del;
    db_get_t          get;
    db_free_t         free;
    db_alloc_t        alloc;
    db_open_t         open_table;
    db_clean_t        clean;
    db_begin_t        begin;
    db_commit_t       commit;
    db_startup_t      startup;
    db_shutdown_t     shutdown;
    db_rollback_t     rollback;
    db_open_cursor_t  open_cursor;
    db_cursor_next_t  cursor_next;
    db_cursor_fetch_t cursor_fetch;
    db_backup_t       backup;
    db_restore_t      restore;
}db_t;

typedef enum en_dbtype {
    DB_TYPE_GSTOR = 0,
    DB_TYPE_CEIL  = 1,
}dbtype_t;

static const db_t g_dbs[] = {
    { gstor_put, gstor_del, gstor_get, gstor_free, gstor_alloc, gstor_open_table, gstor_clean, gstor_begin,
      gstor_commit, gstor_startup, gstor_shutdown, gstor_rollback, gstor_open_cursor, gstor_cursor_next,
      gstor_cursor_fetch, gstor_backup, gstor_restore},
};

static const db_t *g_curr_db = NULL;
#define STG_HANDLE  (g_curr_db)

static handle_pool_t g_handle_pool;
#define HANDLE_POOL (&g_handle_pool)

#define STG_CHECK_DB_STARTUP                                     \
    do {                                                         \
        if (STG_HANDLE == NULL) {                                \
            LOG_DEBUG_ERR("[STG] Please call db_startup first"); \
            return CM_ERROR;                                     \
        }                                                        \
    } while (0)

static inline void init_g_handle_pool(void)
{
    HANDLE_POOL->hwm  = 0;
    HANDLE_POOL->lock = 0;
    biqueue_init(&HANDLE_POOL->idle_list);
}

static inline void destroy_db_handle(db_handle_t *db_handle)
{
    STG_HANDLE->free(db_handle->handle);
    CM_FREE_PTR(db_handle);
}

static inline void deinit_g_handle_pool(void)
{
    for (uint32 i = 0; i < HANDLE_POOL->hwm; ++i) {
        db_handle_t *db_handle = HANDLE_POOL->handles[i];
        if (db_handle == NULL) {
            continue;
        }
        destroy_db_handle(db_handle);
    }
}

status_t db_startup(db_startup_mode_t startup_mode)
{
    param_value_t data_path, dbtype;
    char real_data_path[CM_FILE_NAME_BUFFER_SIZE] = {0};
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_DATA_PATH, &data_path));
    if (CM_IS_EMPTY_STR(data_path.str_val)) {
        LOG_RUN_ERR("[STG] data path is empty");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(realpath_file(data_path.str_val, real_data_path, CM_FILE_NAME_BUFFER_SIZE));

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_DB_TYPE, &dbtype));
    switch (dbtype.uint32_val) {
        case DB_TYPE_GSTOR:
            CM_RETURN_IFERR(load_gstor_params(real_data_path));
            break;
        default:
            LOG_RUN_ERR("[STG] dbtype %u not supported now", dbtype.uint32_val);
            return CM_ERROR;
    }
    gstor_set_log_path(cm_log_param_instance()->log_home);
    if (g_dbs[dbtype.uint32_val].startup(real_data_path, startup_mode) != CM_SUCCESS) {
        LOG_RUN_ERR("[STG] db %u startup failed", dbtype.uint32_val);
        return CM_ERROR;
    }

    STG_HANDLE = &g_dbs[dbtype.uint32_val];
    init_g_handle_pool();
    return CM_SUCCESS;
}

void db_shutdown(void)
{
    deinit_g_handle_pool();
    if (STG_HANDLE == NULL) {
        return;
    }
    STG_HANDLE->shutdown();
}

static inline void return_free_handle(db_handle_t *db_handle)
{
    cm_spin_lock(&HANDLE_POOL->lock, NULL);
    biqueue_add_tail(&HANDLE_POOL->idle_list, QUEUE_NODE_OF(db_handle));
    cm_spin_unlock(&HANDLE_POOL->lock);
}

static inline bool32 reuse_handle(db_handle_t **handle)
{
    if (biqueue_empty(&HANDLE_POOL->idle_list)) {
        return CM_FALSE;
    }

    cm_spin_lock(&HANDLE_POOL->lock, NULL);
    biqueue_node_t *node = biqueue_del_head(&HANDLE_POOL->idle_list);
    if (node == NULL) {
        cm_spin_unlock(&HANDLE_POOL->lock);
        return CM_FALSE;
    }

    *handle = OBJECT_OF(db_handle_t, node);
    cm_spin_unlock(&HANDLE_POOL->lock);
    return CM_TRUE;
}

status_t db_alloc(void **handle)
{
    STG_CHECK_DB_STARTUP;

    if (reuse_handle((db_handle_t**)handle)) {
        return CM_SUCCESS;
    }

    param_value_t param_val;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_MAX_HANDLE, &param_val));

    db_handle_t *db_handle = (db_handle_t*)malloc(sizeof(db_handle_t));
    if (db_handle == NULL) {
        LOG_DEBUG_ERR("[STG] alloc memory failed");
        return CM_ERROR;
    }
    if (STG_HANDLE->alloc(&db_handle->handle) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG] alloc handle from db failed");
        CM_FREE_PTR(db_handle);
        return CM_ERROR;
    }
    db_handle->next = db_handle->prev = NULL;

    cm_spin_lock(&HANDLE_POOL->lock, NULL);
    if (HANDLE_POOL->hwm > param_val.uint32_val) {
        cm_spin_unlock(&HANDLE_POOL->lock);
        LOG_DEBUG_ERR("[STG] handle count is more than the MAX %u", param_val.uint32_val);
        destroy_db_handle(db_handle);
        return CM_ERROR;
    }
    HANDLE_POOL->handles[HANDLE_POOL->hwm++] = db_handle;
    cm_spin_unlock(&HANDLE_POOL->lock);
    *handle = db_handle;
    return CM_SUCCESS;
}

void db_free(void *handle)
{
    db_handle_t *db_handle = ((db_handle_t*)handle);

    if (STG_HANDLE != NULL) {
        STG_HANDLE->clean(db_handle->handle);
    }
    return_free_handle(db_handle);
}

status_t db_open_table(void *handle, const char *table_name)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->open_table(((db_handle_t*)handle)->handle, table_name);
}

status_t db_put(void *handle, text_t *key, text_t *val)
{
    STG_CHECK_DB_STARTUP;
    int64 now = g_timer()->now;
    status_t ret = STG_HANDLE->put(((db_handle_t*)handle)->handle, key->str, key->len, val->str, val->len);
    if (ret == CM_SUCCESS) {
        cm_stat_record(DCC_DB_PUT, (uint64)(g_timer()->now - now));
    }
    return ret;
}

status_t db_del(void *handle, text_t *key, bool32 prefix, uint32 *count)
{
    STG_CHECK_DB_STARTUP;
    int64 now = g_timer()->now;
    status_t ret = STG_HANDLE->del(((db_handle_t*)handle)->handle, key->str, key->len, prefix, count);
    if (ret == CM_SUCCESS) {
        cm_stat_record(DCC_DB_DEL, (uint64)(g_timer()->now - now));
    }
    return ret;
}

status_t db_get(void *handle, text_t *key, text_t *val, bool32 *eof)
{
    STG_CHECK_DB_STARTUP;
    status_t ret = STG_HANDLE->get(((db_handle_t*)handle)->handle, key->str, key->len, &val->str, &val->len, eof);
    return ret;
}

status_t db_open_cursor(void *handle, text_t *key, uint32 flags, bool32 *eof)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->open_cursor(((db_handle_t*)handle)->handle, key->str, key->len, flags, eof);
}

status_t db_cursor_next(void *handle, bool32 *eof)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->cursor_next(((db_handle_t*)handle)->handle, eof);
}

status_t db_cursor_fetch(void *handle, text_t *key, text_t *val)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->cursor_fetch(((db_handle_t*)handle)->handle, &key->str, &key->len, &val->str, &val->len);
}

status_t db_begin(void *handle)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->begin(((db_handle_t*)handle)->handle);
}

status_t db_commit(void *handle)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->commit(((db_handle_t*)handle)->handle);
}

status_t db_rollback(void *handle)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->rollback(((db_handle_t*)handle)->handle);
}

status_t db_bakup(void *handle, const char *bak_format)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->backup(((db_handle_t*)handle)->handle, bak_format);
}

status_t db_restore(void *handle, const char *restore_path, const char *old_path, const char *new_path)
{
    STG_CHECK_DB_STARTUP;
    return STG_HANDLE->restore(((db_handle_t*)handle)->handle, restore_path, old_path, new_path);
}