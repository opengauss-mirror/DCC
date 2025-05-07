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
 * storage.h
 *    storage header file
 *
 * IDENTIFICATION
 *    src/storage/storage.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __STORAGE_H__
#define __STORAGE_H__

#include "cm_types.h"
#include "cm_error.h"
#include "cm_text.h"
#include "cm_profile_stat.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_db_startup_mode {
    STARTUP_MODE_OPEN = 0,
    STARTUP_MODE_NOMOUNT = 1,
} db_startup_mode_t;

void db_shutdown(void);

status_t db_startup(db_startup_mode_t startup_mode);

void db_free(void *handle);

status_t db_alloc(void **handle);

status_t db_open_table(void *handle, const char *table_name);

status_t db_del(void *handle, text_t *key, bool32 prefix, uint32 *count);

status_t db_put(void *handle, text_t *key, text_t *val);

status_t db_get(void *handle, text_t *key, text_t *val, bool32 *eof);

status_t db_open_cursor(void *handle, text_t *key, uint32 flags, bool32 *eof);

status_t db_cursor_next(void *handle, bool32 *eof);

status_t db_cursor_fetch(void *handle, text_t *key, text_t *val);

status_t db_begin(void *handle);

status_t db_commit(void *handle);

status_t db_rollback(void *handle);

status_t db_bakup(void *handle, const char *bak_format);

status_t db_restore(void *handle, const char *restore_path, const char *old_path, const char *new_path);

#ifdef __cplusplus
}
#endif

#endif
