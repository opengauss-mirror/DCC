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
 * clt_lease_manager.c
 *
 *
 * IDENTIFICATION
 *    src/client/clt_lease_manager.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_text.h"
#include "cm_date_to_text.h"
#include "util_defs.h"
#include "clt_defs.h"
#include "clt_core.h"
#include "clt_watch_manager.h"
#include "clt_lease_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

static clt_lease_mgr_t *clt_lease_mgr = NULL;
#define CLT_LEASE_MGR clt_lease_mgr
#define CLT_LEASE_RENEW_PERIOD_DIVISOR (3) // one-third of ttl
#define CLT_LEASE_CHECK_RENEW_INTERVAL 1000 // ms

static clt_lease_node_t *clt_lease_list_find(clt_lease_list_t *lease_list, const text_t *leasename)
{
    clt_lease_node_t *cur = lease_list->first;
    while (cur != NULL) {
        if (cm_text_str_equal(leasename, cur->name) == 0) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

static clt_lease_node_t *alloc_lease_node(const text_t *leasename, const uint32 ttl)
{
    uint32 size = sizeof(clt_lease_node_t) + leasename->len + 1;
    clt_lease_node_t *lease_node = (clt_lease_node_t *)malloc(size);
    if (lease_node == NULL) {
        LOG_DEBUG_ERR("[CLI] new lease node item memory alloc failed");
        return NULL;
    }
    errno_t errcode = memset_s(lease_node, size, 0, size);
    if (errcode != EOK) {
        CM_FREE_PTR(lease_node);
        return lease_node;
    }
    lease_node->name = (char*)lease_node + sizeof(clt_lease_node_t);
    errcode = memcpy_s(lease_node->name, leasename->len + 1, leasename->str, leasename->len);
    if (errcode != EOK) {
        CM_FREE_PTR(lease_node);
        return lease_node;
    }
    lease_node->name[leasename->len] = '\0';
    lease_node->ttl = ttl;
    lease_node->next_renew_time = cm_clock_now_ms() +
        (uint64)ttl * MILLISECS_PER_SECOND / CLT_LEASE_RENEW_PERIOD_DIVISOR;
    return lease_node;
}

status_t clt_lease_add(const text_t *leasename, uint32 ttl)
{
    if (CLT_LEASE_MGR == NULL) {
        LOG_DEBUG_ERR("[CLI] clt lease manager is NULL");
        return CM_ERROR;
    }
    clt_lease_list_t *lease_list = &CLT_LEASE_MGR->lease_list;
    cm_spin_lock(&lease_list->lock, NULL);
    clt_lease_node_t *item = clt_lease_list_find(lease_list, leasename);
    if (item != NULL) {
        LOG_DEBUG_ERR("[CLI] add lease already exist in lease mgr list, name:%s", leasename->str);
        cm_spin_unlock(&lease_list->lock);
        return CM_ERROR;
    }
    clt_lease_node_t *lease = alloc_lease_node(leasename, ttl);
    if (lease == NULL) {
        LOG_DEBUG_ERR("[CLI]alloc lease node failed");
        cm_spin_unlock(&lease_list->lock);
        return CM_ERROR;
    }
    CLT_HASH_LIST_INSERT(lease_list, lease);
    cm_spin_unlock(&lease_list->lock);

    LOG_DEBUG_INF("[CLI] add lease node, name:%s ttl:%u next_renew_time:%llu", leasename->str, ttl,
        lease->next_renew_time);
    return CM_SUCCESS;
}

void clt_lease_del(const text_t *leasename)
{
    if (CLT_LEASE_MGR == NULL) {
        LOG_DEBUG_ERR("[CLI] clt lease manager is NULL");
        return;
    }
    clt_lease_list_t *lease_list = &CLT_LEASE_MGR->lease_list;
    cm_spin_lock(&lease_list->lock, NULL);
    clt_lease_node_t *item = clt_lease_list_find(lease_list, leasename);
    if (item == NULL) {
        LOG_DEBUG_INF("[CLI] del lease not exist in lease mgr list, name:%s", leasename->str);
        cm_spin_unlock(&lease_list->lock);
        return;
    }
    CLT_HASH_LIST_REMOVE(lease_list, item);
    cm_spin_unlock(&lease_list->lock);
    CM_FREE_PTR(item);

    LOG_DEBUG_INF("[CLI] del lease node, name:%s", leasename->str);
}

static void clt_free_lease_nodes(clt_lease_node_t *lease_node)
{
    clt_lease_node_t *tmp;
    if (lease_node == NULL) {
        return;
    }
    while (lease_node != NULL) {
        tmp = lease_node->next;
        CM_FREE_PTR(lease_node);
        lease_node = tmp;
    }
}

static void clt_lease_mgr_keep_alive(void)
{
    clt_lease_list_t *lease_list = &CLT_LEASE_MGR->lease_list;
    cm_spin_lock(&lease_list->lock, NULL);
    clt_lease_node_t *cur = lease_list->first;
    while (cur != NULL) {
        if (cur->next_renew_time > cm_clock_now_ms()) {
            cur = cur->next;
            continue;
        }
        dcc_string_t lease_name = {
            .data = cur->name, .len = strlen(cur->name) };
        int ret = clt_lease_keep_alive((clt_handle_t *)CLT_LEASE_MGR->handle, &lease_name);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[CLI] clt lease keep alive failed, name:%s", cur->name);
            cur = cur->next;
            continue;
        }
        cur->next_renew_time = cm_clock_now_ms() +
            (uint64)(cur->ttl) * MILLISECS_PER_SECOND / CLT_LEASE_RENEW_PERIOD_DIVISOR;
        LOG_DEBUG_INF("[CLI] clt lease mgr renew lease, name:%s next_renew_time:%llu", cur->name, cur->next_renew_time);
        cur = cur->next;
    }
    cm_spin_unlock(&lease_list->lock);
    return;
}

static void clt_lease_alive_thread_entry(thread_t *thread)
{
    while (!thread->closed) {
        clt_lease_mgr_keep_alive();
        cm_sleep(CLT_LEASE_CHECK_RENEW_INTERVAL);
    }
}

status_t clt_lease_mgr_init(const dcc_open_option_t *open_option)
{
    if (CLT_LEASE_MGR != NULL) {
        return CM_SUCCESS;
    }

    size_t total_size = sizeof(clt_lease_mgr_t);
    total_size = CM_ALIGN8(total_size);
    CLT_LEASE_MGR = (clt_lease_mgr_t *)malloc(total_size);
    if (CLT_LEASE_MGR == NULL) {
        LOG_DEBUG_ERR("[CLI] lease mgr init malloc memory failed %zu", total_size);
        return CM_ERROR;
    }
    if (memset_s(CLT_LEASE_MGR, total_size, 0, total_size) != EOK) {
        CM_FREE_PTR(CLT_LEASE_MGR);
        return CM_ERROR;
    }

    int ret = dcc_open(open_option, &CLT_LEASE_MGR->handle);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[CLI] lease mgr init dcc open handle for lease failed");
        return CM_ERROR;
    }

    if (cm_create_thread(clt_lease_alive_thread_entry, 0, NULL, &CLT_LEASE_MGR->lease_alive_thread) != CM_SUCCESS) {
        dcc_close(&CLT_LEASE_MGR->handle);
        CM_FREE_PTR(CLT_LEASE_MGR);
        LOG_RUN_ERR("[CLI] create lease alive thread failed");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void clt_lease_mgr_deinit(void)
{
    if (CLT_LEASE_MGR == NULL) {
        return;
    }
    if (!CLT_LEASE_MGR->lease_alive_thread.closed) {
        cm_close_thread(&CLT_LEASE_MGR->lease_alive_thread);
    }
    dcc_close(&CLT_LEASE_MGR->handle);
    cm_spin_lock(&CLT_LEASE_MGR->lease_list.lock, NULL);
    clt_free_lease_nodes(CLT_LEASE_MGR->lease_list.first);
    cm_spin_unlock(&CLT_LEASE_MGR->lease_list.lock);
    CM_FREE_PTR(CLT_LEASE_MGR);
}

#ifdef __cplusplus
}
#endif
