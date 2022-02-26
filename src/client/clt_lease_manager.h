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
 * clt_lease_manager.h
 *
 *
 * IDENTIFICATION
 *    src/client/clt_lease_manager.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CLT_LEASE_MANAGER_H__
#define __CLT_LEASE_MANAGER_H__

#include "cm_error.h"
#include "cm_list.h"
#include "cm_text.h"
#include "interface/clt_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_clt_lease_node {
    char *name;
    uint32 ttl;
    uint64 next_renew_time;
    struct st_clt_lease_node *next;
    struct st_clt_lease_node *prev;
} clt_lease_node_t;

typedef struct st_clt_lease_list {
    clt_lease_node_t *first;
    spinlock_t lock;
} clt_lease_list_t;

typedef struct st_clt_lease_mgr {
    clt_lease_list_t lease_list;
    thread_t lease_alive_thread;
    void *handle;
} clt_lease_mgr_t;

status_t clt_lease_mgr_init(const dcc_open_option_t *open_option);
void clt_lease_mgr_deinit(void);
status_t clt_lease_add(const text_t *leasename, uint32 ttl);
void clt_lease_del(const text_t *leasename);

#ifdef __cplusplus
}
#endif

#endif
