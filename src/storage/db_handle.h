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
 * db_handle.h
 *    db handle
 *
 * IDENTIFICATION
 *    src/storage/db_handle.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SRV_SESSION_POOL_H__
#define __SRV_SESSION_POOL_H__

#include "storage.h"
#include "cm_types.h"
#include "cm_queue.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_db_handle {
    void  *handle;
    struct st_db_handle *prev;
    struct st_db_handle *next;
}db_handle_t;

typedef struct st_handle_pool {
    uint32       hwm;
    spinlock_t   lock;
    biqueue_t    idle_list;
    db_handle_t *handles[CM_MAX_SESSIONS];
} handle_pool_t;

#ifdef __cplusplus
}
#endif

#endif