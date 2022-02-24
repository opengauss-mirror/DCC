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
 * executor_lease.h
 *    executor lease
 *
 * IDENTIFICATION
 *    src/executor/executor_lease.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_EXECUTOR_LEASE_H__
#define __DCC_EXECUTOR_LEASE_H__

#include "storage.h"
#include "executor.h"
#include "executor_defs.h"
#include "executor_lease_expire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXC_LEASE_MAX_NUM 1024
#define EXC_LEASE_NAME_PREFIX "LEASE/"
#define EXC_LEASE_NAME_PREFIX_LEN ((uint32)strlen(EXC_LEASE_NAME_PREFIX))
#define EXC_LEASE_KEY_PREFIX "LEASEKEY/"
#define EXC_LEASE_KEY_PREFIX_LEN ((uint32)strlen(EXC_LEASE_KEY_PREFIX))

typedef struct st_key_item {
    char   *key;
    struct st_key_item *next;
    struct st_key_item *prev;
    struct st_key_bucket *bucket;
} key_item_t;

typedef struct st_key_bucket {
    spinlock_t lock;
    key_item_t *first;
} key_bucket_t;

typedef struct st_lease_key_pool {
    uint32 bucket_cnt;
    key_bucket_t buckets[1];
} lease_key_pool_t;

typedef struct st_lease_item {
    char *name;
    uint32 ttl;
    date_t renew_time; // us
    lease_key_pool_t *key_pool;
    lease_expire_ele_t *expire_ele;
    struct st_lease_item *next;
    struct st_lease_item *prev;
    struct st_lease_bucket *bucket;
} lease_item_t;

typedef struct st_lease_bucket {
    spinlock_t    lock;
    lease_item_t *first;
} lease_bucket_t;

typedef struct st_lease_pool {
    uint32 bucket_cnt;
    lease_bucket_t buckets[1];
} lease_pool_t;

typedef struct st_lease_mgr {
    lease_pool_t *lease_pool;
    spinlock_t lock;
    lease_expire_pque_t pque;
    thread_t expire;
} lease_mgr_t;

status_t exc_lease_mgr_init(void);
void exc_lease_mgr_deinit(void);
status_t exc_cb_consensus_lease_create(const text_t *leasename, uint32 ttl);
status_t exc_cb_consensus_lease_destroy(const text_t *leasename);
status_t exc_cb_consensus_lease_renew(const text_t *leasename);
status_t exc_cb_consensus_lease_sync(const text_t *leasename, const date_t renew_time);
status_t exc_cb_consensus_lease_attach(text_t *key, const text_t *leasename);
status_t exc_cb_consensus_lease_detach(text_t *key, const text_t *leasename);
status_t exc_lease_promote(void);
void exc_lease_demote(void);
#ifdef __cplusplus
}
#endif

#endif
