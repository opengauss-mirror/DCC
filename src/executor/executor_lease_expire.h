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
 * executor_lease_expire.h
 *    executor lease expire
 *
 * IDENTIFICATION
 *    src/executor/executor_lease_expire.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_EXECUTOR_LEASE_EXPIRE_H__
#define __DCC_EXECUTOR_LEASE_EXPIRE_H__

#include "storage.h"
#include "executor.h"
#include "executor_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_lease_expire_ele_t {
    char *name;
    uint64 expire_time;
    uint32 idx;
} lease_expire_ele_t;

typedef struct st_lease_expire_pque {
    uint32 capacity;
    uint32 size;
    lease_expire_ele_t **eles;
} lease_expire_pque_t;

status_t exc_pque_init(lease_expire_pque_t *pque, uint32 maxnum);
void exc_pque_deinit(lease_expire_pque_t *pque);
status_t exc_pque_insert(lease_expire_pque_t *pque, lease_expire_ele_t *ele);
status_t exc_pque_delete(lease_expire_pque_t *pque, uint32 idx);
status_t exc_pque_delete_min(lease_expire_pque_t *pque, lease_expire_ele_t **min);
status_t exc_pque_adjust(lease_expire_pque_t *pque, uint32 idx);
void exc_pque_get_min(lease_expire_pque_t *pque, lease_expire_ele_t **min);
void exc_proc_lease_expire(lease_expire_pque_t *pque, spinlock_t *lock);

#ifdef __cplusplus
}
#endif

#endif
