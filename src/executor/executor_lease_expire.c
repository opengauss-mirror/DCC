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
 * executor_lease_expire.c
 *    executor lease expire
 *
 * IDENTIFICATION
 *    src/executor/executor_lease_expire.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_hash_pool.h"
#include "cm_hash.h"
#include "cm_text.h"
#include "util_defs.h"
#include "dcf_interface.h"
#include "executor_lease_expire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXC_PQUE_MIN_ELE_IDX 1
#define EXC_PQUE_2_FIXED 2

static inline uint32 exc_pque_child(uint32 i)
{
    return i * EXC_PQUE_2_FIXED;
}
static inline uint32 exc_pque_parent(uint32 i)
{
    return i / EXC_PQUE_2_FIXED;
}

status_t exc_pque_init(lease_expire_pque_t *pque, uint32 maxnum)
{
    CM_CHECK_NULL_PTR(pque);
    uint32 size = (maxnum + 1) * (uint32)sizeof(lease_expire_ele_t *);
    pque->eles = (lease_expire_ele_t **)exc_alloc(size);
    MEMS_RETURN_IFERR(memset_s(pque->eles, size, 0, size));
    pque->size = 0;
    pque->capacity = maxnum;
    return CM_SUCCESS;
}

void exc_pque_deinit(lease_expire_pque_t *pque)
{
    if (pque == NULL) {
        return;
    }
    for (uint32 i = EXC_PQUE_MIN_ELE_IDX; i <= pque->size; i++) {
        exc_free(pque->eles[i]);
    }
    exc_free(pque->eles);
    return;
}

static inline bool32 exc_pque_is_full(const lease_expire_pque_t *pque)
{
    if (pque == NULL) {
        return CM_FALSE;
    }
    return (pque->capacity == pque->size);
}

static inline bool32 exc_pque_is_empty(const lease_expire_pque_t *pque)
{
    if (pque == NULL) {
        return CM_FALSE;
    }
    return (pque->size == 0);
}

static inline void exc_pque_exch(lease_expire_pque_t *pque, uint32 i, uint32 j)
{
    lease_expire_ele_t *tmp = pque->eles[j];
    pque->eles[j] = pque->eles[i];
    pque->eles[i] = tmp;
    pque->eles[j]->idx = j;
    pque->eles[i]->idx = i;
}

static bool32 exc_pque_sink(lease_expire_pque_t *pque, uint32 idx)
{
    uint32 tmpidx = idx;
    uint32 size = pque->size;
    do {
        uint32 lchild = 2 * tmpidx;
        if (lchild == 0 || lchild > size) {
            break;
        }
        uint32 minchild = lchild;
        uint32 rchild = lchild + 1;
        if (rchild <= size && pque->eles[rchild]->expire_time < pque->eles[lchild]->expire_time) {
            minchild = rchild;
        }
        if (pque->eles[minchild]->expire_time >= pque->eles[tmpidx]->expire_time) {
            break;
        }
        exc_pque_exch(pque, tmpidx, minchild);
        tmpidx = minchild;
    } while (CM_TRUE);
    return (tmpidx != idx);
}

static bool32 exc_pque_swim(lease_expire_pque_t *pque, uint32 idx)
{
    uint32 tmpidx = idx;
    do {
        uint32 parent = tmpidx / 2 ;
        if (parent == 0 || pque->eles[parent]->expire_time <= pque->eles[tmpidx]->expire_time) {
            break;
        }
        exc_pque_exch(pque, parent, tmpidx);
        tmpidx = parent;
    } while (CM_TRUE);
    return (tmpidx != idx);
}

status_t exc_pque_adjust(lease_expire_pque_t *pque, uint32 idx)
{
    CM_CHECK_NULL_PTR(pque);
    if (!exc_pque_sink(pque, idx)) {
        (void)exc_pque_swim(pque, idx);
    }
    LOG_DEBUG_INF("[EXC LEASE] pque adjust success for idx:%u", idx);
    return CM_SUCCESS;
}

status_t exc_pque_insert(lease_expire_pque_t *pque, lease_expire_ele_t *ele)
{
    CM_CHECK_NULL_PTR(pque);
    CM_CHECK_NULL_PTR(ele);
    if (exc_pque_is_full(pque)) {
        LOG_DEBUG_ERR("[EXC LEASE] pque is full");
        return CM_ERROR;
    }

    uint32 i = pque->size + 1;
    pque->eles[i] = ele;
    pque->eles[i]->idx = i;
    for (; i > EXC_PQUE_MIN_ELE_IDX && pque->eles[exc_pque_parent(i)]->expire_time > ele->expire_time;) {
        exc_pque_exch(pque, i, exc_pque_parent(i));
        i = exc_pque_parent(i);
    }
    pque->size++;
    LOG_DEBUG_INF("[EXC LEASE] pque insert success for ele, lease:%s expire_time:%llu ", ele->name, ele->expire_time);
    return CM_SUCCESS;
}

status_t exc_pque_delete(lease_expire_pque_t *pque, uint32 idx)
{
    CM_CHECK_NULL_PTR(pque);
    uint32 last_idx = pque->size;
    if (idx < EXC_PQUE_MIN_ELE_IDX || idx > last_idx) {
        LOG_DEBUG_ERR("[EXC LEASE] pque delete with invalid idx:%u last_idx:%u", idx, last_idx);
        return CM_ERROR;
    }
    lease_expire_ele_t *ele = pque->eles[idx];
    LOG_DEBUG_INF("[EXC LEASE] pque delete with lease name:%s expire_time:%llu", ele->name, ele->expire_time);
    if (idx == last_idx) {
        pque->size--;
        return CM_SUCCESS;
    }
    exc_pque_exch(pque, idx, last_idx);
    pque->size--;
    return exc_pque_adjust(pque, idx);
}

void exc_pque_get_min(lease_expire_pque_t *pque, lease_expire_ele_t **min)
{
    if (exc_pque_is_empty(pque)) {
        LOG_DEBUG_INF("[EXC LEASE] pque is empty when get min");
        return;
    }
    uint32 idx = 1;
    *min = pque->eles[idx];
    return;
}

status_t exc_pque_delete_min(lease_expire_pque_t *pque, lease_expire_ele_t **min)
{
    CM_CHECK_NULL_PTR(pque);

    uint32 i;
    uint32 minChild;
    if (exc_pque_is_empty(pque)) {
        LOG_DEBUG_ERR("[EXC LEASE] priority queue is empty\n");
        return CM_ERROR;
    }

    *min = pque->eles[EXC_PQUE_MIN_ELE_IDX];
    lease_expire_ele_t *last = pque->eles[pque->size];
    pque->size--;
    if (pque->size == 0) {
        LOG_DEBUG_INF("[EXC LEASE] pque deleted last ele, name:%s expire_time:%llu", (*min)->name, (*min)->expire_time);
        pque->eles[EXC_PQUE_MIN_ELE_IDX] = NULL;
        return CM_SUCCESS;
    }

    for (i = EXC_PQUE_MIN_ELE_IDX; exc_pque_child(i) <= pque->size; i = minChild) {
        minChild = exc_pque_child(i);
        if (minChild != pque->size && pque->eles[minChild + 1]->expire_time < pque->eles[minChild]->expire_time) {
            minChild += 1;
        }
        if (pque->eles[minChild]->expire_time >= last->expire_time) {
            break;
        }
        pque->eles[i] = pque->eles[minChild];
        pque->eles[i]->idx = i;
    }
    pque->eles[i] = last;
    pque->eles[i]->idx = i;
    if (*min != NULL) {
        LOG_DEBUG_INF("[EXC LEASE] pque deleted min ele, name:%s expire_time:%llu", (*min)->name, (*min)->expire_time);
    }
    return CM_SUCCESS;
}

void exc_proc_lease_expire(lease_expire_pque_t *pque, spinlock_t *lock)
{
    lease_expire_ele_t *min = NULL;
    timespec_t now = cm_clock_now_ms();
    cm_spin_lock(lock, NULL);
    exc_pque_get_min(pque, &min);
    cm_spin_unlock(lock);
    while (min != NULL && min->expire_time <= now) {
        LOG_DEBUG_INF("[EXC LEASE] get min pque ele expire, name:%s expire_time:%llu", min->name, min->expire_time);
        uint32 offset = 0;
        uint32 size = (uint32)(2 * sizeof(uint32) + strlen(min->name));
        size = CM_ALIGN4(size);
        char *buff = (char *)exc_alloc(size);
        text_t leaseid = {
            .str = min->name, .len = strlen(min->name) };
        uint32 cmd = DCC_CMD_LEASE_EXPIRE;
        exc_put_uint32(buff, cmd, &offset);
        if (exc_put_text(buff, size, &leaseid, &offset) != CM_SUCCESS) {
            exc_free(buff);
            return;
        }
        uint64 index;
        if (dcf_universal_write(EXC_STREAM_ID_DEFAULT, buff, size, 0, &index) != CM_SUCCESS) {
            exc_free(buff);
            return;
        }
        LOG_DEBUG_INF("[EXC LEASE] ele expire proposed, ele's name:%s", min->name);
        exc_free(buff);
        cm_spin_lock(lock, NULL);
        status_t ret = exc_pque_delete_min(pque, &min);
        cm_spin_unlock(lock);
        if (ret != CM_SUCCESS) {
            return;
        }
        exc_free(min);
        min = NULL;
        cm_spin_lock(lock, NULL);
        exc_pque_get_min(pque, &min);
        cm_spin_unlock(lock);
    }
}

#ifdef __cplusplus
}
#endif

