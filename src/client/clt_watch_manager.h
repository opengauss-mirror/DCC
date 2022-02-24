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
 * clt_watch_manager.h
 *
 *
 * IDENTIFICATION
 *    src/client/clt_watch_manager.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CLT_MANAGER_MANAGER_H__
#define __CLT_MANAGER_MANAGER_H__

#include "interface/clt_interface.h"
#include "cm_error.h"
#include "cm_hash_pool.h"
#include "cm_list.h"
#include "cm_text.h"
#include "dcc_range_cmp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_clt_watch_node {
    iv_t clt_watch_iv;
    dcc_watch_proc_t proc;
    struct st_clt_watch_node *next;
    struct st_clt_watch_node *prev;
} clt_watch_node_t;

typedef struct st_clt_watch_list {
    clt_watch_node_t *first;
    spinlock_t lock;
    uint32 node_cnt;
} clt_watch_list_t;

typedef struct st_clt_watch_manager {
    clt_watch_list_t *watch_key_list;
    clt_watch_list_t *watch_group_list;
} clt_watch_manager_t;

#define CLT_HASH_LIST_INSERT(list, item)  \
    do {                                  \
        (item)->next = (list)->first;     \
        (item)->prev = NULL;              \
        if ((list)->first != NULL) {      \
            (list)->first->prev = (item); \
        }                                 \
        (list)->first = (item);           \
    } while (0)

#define CLT_HASH_LIST_REMOVE(list, item)       \
    do {                                       \
        if ((item)->prev != NULL) {            \
            (item)->prev->next = (item)->next; \
        }                                      \
                                               \
        if ((item)->next != NULL) {            \
            (item)->next->prev = (item)->prev; \
        }                                      \
                                               \
        if ((item) == (list)->first) {         \
            (list)->first = (item)->next;      \
        }                                      \
        (item)->prev = NULL;                   \
        (item)->next = NULL;                   \
    } while (0)

static inline void clt_free_watch_obj(clt_watch_node_t *watch_obj)
{
    clt_watch_node_t *tmp;
    if (watch_obj == NULL) {
        return;
    }
    while (watch_obj != NULL) {
        tmp = watch_obj->next;
        CM_FREE_PTR(watch_obj);
        watch_obj = tmp;
    }
}

status_t clt_watch_pool_init(clt_watch_manager_t **watch_manager);

void clt_watch_pool_deinit(clt_watch_manager_t *watch_manager);

status_t clt_watch_pool_add(clt_watch_manager_t *watch_manager, bool32 is_prefix, const text_t *key,
                            const dcc_watch_proc_t watch_proc);

void clt_watch_pool_del(clt_watch_manager_t *watch_manager, bool32 is_prefix, const text_t *key);

status_t clt_watch_pool_call(clt_watch_manager_t *watch_manager, const text_t *key, uint32 is_prefix,
    const dcc_watch_result_t *result);

#ifdef __cplusplus
}
#endif

#endif