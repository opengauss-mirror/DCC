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
 * executor_watch.h
 *
 *
 * IDENTIFICATION
 *    src/executor/executor_watch.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_EXECUTOR_WATCH_H__
#define __DCC_EXECUTOR_WATCH_H__

#include "storage.h"
#include "executor.h"
#include "executor_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXC_WATCH_BUCKET_NUM    10000

typedef struct st_watch_obj {
    uint32 sid;
    dcc_watch_proc_t proc;
    struct st_watch_obj *next;
    struct st_watch_obj *prev;
}watch_obj_t;

typedef struct st_watch_item {
    char        *key;
    bool32       valid;
    uint32       ref_count;
    spinlock_t   lock;
    watch_obj_t *first;
    struct st_watch_item   *next;
    struct st_watch_item   *prev;
    struct st_watch_bucket *bucket;
}watch_item_t;

typedef struct st_watch_bucket {
    spinlock_t    lock;
    watch_item_t *first;
}watch_bucket_t;

typedef struct st_watch_pool {
    uint32 bucket_count;
    watch_bucket_t buckets[1];
}watch_pool_t;

#define HASH_LIST_INSERT(list, item)      \
    do {                                  \
        (item)->next = (list)->first;     \
        (item)->prev = NULL;              \
        if ((list)->first != NULL) {      \
            (list)->first->prev = (item); \
        }                                 \
        (list)->first = (item);           \
    } while (0)

#define HASH_LIST_REMOVE(list, item_obj)               \
    do {                                               \
        if ((item_obj)->prev != NULL) {                \
            (item_obj)->prev->next = (item_obj)->next; \
        }                                              \
                                                       \
        if ((item_obj)->next != NULL) {                \
            (item_obj)->next->prev = (item_obj)->prev; \
        }                                              \
                                                       \
        if ((item_obj) == (list)->first) {             \
            (list)->first = (item_obj)->next;          \
        }                                              \
        (item_obj)->prev = NULL;                       \
        (item_obj)->next = NULL;                       \
    } while (0)

status_t exc_watch_init(void);

void exc_watch_deinit(void);

status_t exc_watch_cb_proc(msg_entry_t* entry, int event_type);

status_t exc_add_watch(const text_t *key, uint32 sid, dcc_watch_proc_t proc, text_t* watch_key);

void exc_del_watch(const text_t *key, uint32 sid);

#ifdef __cplusplus
}
#endif

#endif
