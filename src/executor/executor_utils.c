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
 * executor_utils.c
 *
 *
 * IDENTIFICATION
 *    src/executor/executor_utils.c
 *
 * -------------------------------------------------------------------------
 */

#include "executor_utils.h"
#include "storage.h"
#include "util_error.h"
#include "util_defs.h"
#include "dcf_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

static exc_write_handle g_write_handle = {.handle = NULL, .opened_tabled_id = CM_INVALID_ID32};

#define EXC_WR_HANDLE               (g_write_handle.handle)
#define EXC_WR_HD_TABLE_ID          (g_write_handle.opened_tabled_id)
#define EXC_MSG_STORGE_FAIL_NUM     (1000)


static const char *g_dcc_tables[] = {EXC_DCC_KV_TABLE, EXC_DCC_SQN_KV_TABLE,
                                     EXC_DCC_LEASE_KV_TABLE, EXC_DCC_RESERVED_KV_TABLE};

static status_t exc_open_table4wrhandle(uint32 table_id)
{
    if (EXC_WR_HD_TABLE_ID == table_id) {
        return CM_SUCCESS;
    }

    status_t ret = db_open_table(EXC_WR_HANDLE, g_dcc_tables[table_id - 1]);
    if (ret != CM_SUCCESS) {
        EXC_WR_HD_TABLE_ID = CM_INVALID_ID32;
        LOG_RUN_ERR("[EXC] open table %s failed", g_dcc_tables[table_id - 1]);
        return CM_ERROR;
    }
    EXC_WR_HD_TABLE_ID = table_id;

    return CM_SUCCESS;
}

static inline void exc_wr_handle_rollback(void)
{
    LOG_RUN_ERR("[EXC] execute command failed.");
    (void) db_rollback(EXC_WR_HANDLE);
    (void) fflush(stdout);
    exit(0);
}

status_t exc_wr_handle_init(void)
{
    if (EXC_WR_HANDLE == NULL) {
        if (db_alloc(&EXC_WR_HANDLE) != CM_SUCCESS) {
            CM_THROW_ERROR(ERR_EXC_INIT_FAILED, "init global param");
            LOG_DEBUG_ERR("[EXC] alloc write handle failed");
            return CM_ERROR;
        }
        for (uint32 i = 0; i < DCC_RESERVED_TABLE_ID; i++) {
            if (db_open_table(EXC_WR_HANDLE, g_dcc_tables[i]) != CM_SUCCESS) {
                CM_THROW_ERROR(ERR_EXC_INIT_FAILED, "open table failed");
                LOG_DEBUG_ERR("[EXC] open table %u failed", i);
                return CM_ERROR;
            }
        }
    }
    return CM_SUCCESS;
}

void exc_wr_handle_deinit(void)
{
    if (g_write_handle.handle != NULL) {
        db_free(g_write_handle.handle);
        g_write_handle.handle = NULL;
        g_write_handle.opened_tabled_id = CM_INVALID_ID32;
    }
}

void exc_wr_handle_put(uint32 table_id, text_t *key, text_t *val)
{
    if (exc_open_table4wrhandle(table_id) != CM_SUCCESS) {
        exit(0);
    }
    for (uint32 i = 0; i < EXC_MSG_STORGE_FAIL_NUM; i++) {
        if (db_put(EXC_WR_HANDLE, key, val) == CM_SUCCESS) {
            return;
        }
        cm_sleep(CM_SLEEP_5_FIXED);
    }
    exc_wr_handle_rollback();
}

void exc_wr_handle_delete(uint32 table_id, text_t *key, bool32 prefix, uint32 *count)
{
    if (exc_open_table4wrhandle(table_id) != CM_SUCCESS) {
        exit(0);
    }
    for (uint32 i = 0; i < EXC_MSG_STORGE_FAIL_NUM; i++) {
        if (db_del(EXC_WR_HANDLE, key, prefix, count) == CM_SUCCESS) {
            return;
        }
        cm_sleep(CM_SLEEP_5_FIXED);
    }
    exc_wr_handle_rollback();
}

status_t exc_wr_handle_get(uint32 table_id, text_t *key, text_t *val, bool32 *eof)
{
    CM_RETURN_IFERR(exc_open_table4wrhandle(table_id));
    return db_get(EXC_WR_HANDLE, key, val, eof);
}

void exc_wr_handle_begin(void)
{
    (void) db_begin(EXC_WR_HANDLE);
}

void exc_wr_handle_commit(void)
{
    (void) db_commit(EXC_WR_HANDLE);
}

void exc_wr_handle_write_commit(uint32 table_id, text_t *key, text_t *val)
{
    exc_wr_handle_begin();
    exc_wr_handle_put(table_id, key, val);
    exc_wr_handle_commit();
}

int exc_backup(const char *bak_format)
{
    return (int)db_bakup(EXC_WR_HANDLE, bak_format);
}

int exc_restore(const char *restore_path, const char *old_path, const char *new_path)
{
    if (db_startup(STARTUP_MODE_NOMOUNT) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] db_startup with nomount mode failed");
        return CM_ERROR;
    }

    void *handle = NULL;
    int ret = db_alloc(&handle);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] db_alloc handle for restore failed");
        return CM_ERROR;
    }

    ret = db_restore(handle, restore_path, old_path, new_path);
    if (ret != CM_SUCCESS) {
        db_free(handle);
        db_shutdown();
        LOG_DEBUG_ERR("[EXC] db_restore failed");
        return CM_ERROR;
    }

    db_shutdown();
    return CM_SUCCESS;
}

status_t exc_path_join(char *buf, uint32 buf_size, const char *path, const char *filename)
{
    MEMS_RETURN_IFERR(strcpy_sp(buf, buf_size, path));
    MEMS_RETURN_IFERR(strcat_sp(buf, CM_FILE_NAME_BUFFER_SIZE, "/"));
    MEMS_RETURN_IFERR(strcat_sp(buf, CM_FILE_NAME_BUFFER_SIZE, filename));

    return CM_SUCCESS;
}

status_t exc_remove_dir(const char *path)
{
    LOG_RUN_INF("[EXC] remove directory %s...", path);
#ifndef WIN32
    struct dirent *dirp = NULL;
    char filepath[CM_FILE_NAME_BUFFER_SIZE] = {0};

    DIR *dir = opendir(path);
    if (dir == NULL) {
        return CM_ERROR;
    }

    while ((dirp = readdir(dir)) != NULL) {
        if ((strcmp(dirp->d_name, ".") == 0) || (strcmp(dirp->d_name, "..") == 0)) {
            continue;
        }

        if (exc_path_join(filepath, CM_FILE_NAME_BUFFER_SIZE, path, dirp->d_name) != CM_SUCCESS) {
            LOG_RUN_ERR("[EXC]splic dir/file %s to path %s failed", dirp->d_name, path);
            (void)closedir(dir);
            return CM_ERROR;
        }

        if (cm_dir_exist(filepath)) {
            if (exc_remove_dir(filepath) == CM_SUCCESS) {
                continue;
            }
            (void)closedir(dir);
            return CM_ERROR;
        }

        if (cm_remove_file(filepath) != CM_SUCCESS) {
            (void)closedir(dir);
            return CM_ERROR;
        }
    }
    (void)closedir(dir);
    return cm_remove_file(path);
#else
    LOG_RUN_ERR("[EXC]win32 not support rm dir now.");
    return CM_ERROR;
#endif
}

uint32 exc_get_leader_id(void)
{
    uint32 node_id = EXC_INVALID_NODE_ID;
    char ip[CM_MAX_IP_LEN];
    uint32 port;
    int ret = dcf_query_leader_info(DCC_STREAM_ID, ip, CM_MAX_IP_LEN, &port, &node_id);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC] get_leader_id: error_no:%d, error_msg:%s",
            dcf_get_errorno(),
            dcf_get_error(dcf_get_errorno()));
        return EXC_INVALID_NODE_ID;
    }
    return node_id;
}

#ifdef __cplusplus
}
#endif