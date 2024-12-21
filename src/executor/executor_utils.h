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
 * executor_utils.h
 *
 *
 * IDENTIFICATION
 *    src/executor/executor_utils.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_EXECUTOR_UTILS_H__
#define __DCC_EXECUTOR_UTILS_H__


#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif


#define DCC_KV_TABLE_ID             ((uint32)1)
#define DCC_SEQUENCE_TABLE_ID       ((uint32)2)
#define DCC_LEASE_TABLE_ID          ((uint32)3)
#define DCC_RESERVED_TABLE_ID       ((uint32)4)
#define EXC_DCC_KV_TABLE            ((char *)"SYS_KV")
#define EXC_DCC_SQN_KV_TABLE        ((char *)"SYS_SEQUENCE_KV")
#define EXC_DCC_LEASE_KV_TABLE      ((char *)"SYS_LEASE_KV")
#define EXC_DCC_RESERVED_KV_TABLE   ((char *)"SYS_DCC_KV")

#define DCC_STREAM_ID               1
#define EXC_INVALID_NODE_ID         0
#define EXC_3X_FIXED                3

typedef struct st_exc_util_handle {
    void *handle;
    uint32 opened_tabled_id;
} exc_write_handle;

status_t exc_wr_handle_init(void);

void exc_wr_handle_deinit(void);

void exc_wr_handle_put(uint32 table_id, text_t *key, text_t *val);

void exc_wr_handle_delete(uint32 table_id, text_t *key, bool32 prefix, uint32 *count);

status_t exc_wr_handle_get(uint32 table_id, text_t *key, text_t *val, bool32 *eof);

void exc_wr_handle_begin(void);

void exc_wr_handle_commit(void);

void exc_wr_handle_write_commit(uint32 table_id, text_t *key, text_t *val);

int exc_backup(const char *bak_format);

int exc_restore(const char *restore_path, const char *old_path, const char *new_path);

status_t exc_path_join(char *buf, uint32 buf_size, const char *path, const char *filename);

status_t exc_remove_dir(const char *path);

uint32 exc_get_leader_id(void);

#ifdef __cplusplus
}
#endif

#endif