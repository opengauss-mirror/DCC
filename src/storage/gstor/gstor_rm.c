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
 * gstor_rm.c
 *    transaction resource manager pool interface
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_rm.c
 *
 * -------------------------------------------------------------------------
 */
#include "gstor_rm.h"
#include "cm_log.h"
#include "cm_ip.h"
#include "gstor_instance.h"


void rm_pool_init(rm_pool_t *rm_pool)
{
    uint32 i;

    rm_pool->lock = 0;
    rm_pool->hwm = 0;
    rm_pool->capacity = 0;
    rm_pool->page_count = 0;

    rm_pool->free_list.count = 0;
    rm_pool->free_list.first = GS_INVALID_ID16;
    rm_pool->free_list.last = GS_INVALID_ID16;

    for (i = 0; i < GS_MAX_RM_BUCKETS; i++) {
        rm_pool->buckets[i].lock = 0;
        rm_pool->buckets[i].count = 0;
        rm_pool->buckets[i].first = GS_INVALID_ID16;
    }
}

void rm_pool_deinit(rm_pool_t *rm_pool)
{
    for (uint32 i = 0; i < g_instance->rm_pool.page_count; i++) {
        CM_FREE_PTR(g_instance->rm_pool.pages[i]);
    }
    g_instance->rm_pool.page_count = 0;
}

static inline knl_rm_t *rm_addr(rm_pool_t *pool, uint32 id)
{
    uint32 page_id = id / GS_EXTEND_RMS;
    uint32 slot_id = id % GS_EXTEND_RMS;
    return (knl_rm_t *)(pool->pages[page_id] + slot_id * sizeof(knl_rm_t));
}

static status_t rm_pool_extend(rm_pool_t *pool)
{
    char *buf = NULL;
    size_t alloc_size;
    errno_t ret;

    if (pool->capacity >= g_instance->kernel.attr.max_rms) {
        GS_THROW_ERROR(ERR_TOO_MANY_RM_OBJECTS, g_instance->kernel.attr.max_rms);
        GS_LOG_RUN_WAR("too many rm objects");
        return GS_ERROR;
    }

    CM_ASSERT(pool->page_count < GS_MAX_RM_PAGES);

    alloc_size = sizeof(knl_rm_t) * GS_EXTEND_RMS;
    buf = (char *)malloc(alloc_size);
    if (buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)alloc_size, "alloc rm");
        GS_LOG_RUN_WAR("alloc rm failed");
        return GS_ERROR;
    }

    ret = memset_sp(buf, alloc_size, 0, alloc_size);
    knl_securec_check(ret);

    pool->capacity += GS_EXTEND_RMS;
    pool->pages[pool->page_count++] = buf;

    return GS_SUCCESS;
}

static status_t rm_alloc(rm_pool_t *rm_pool, uint16 *rmid)
{
    knl_rm_t *rm = NULL;

    if (rm_pool->free_list.count == 0 && rm_pool->hwm == rm_pool->capacity) {
        if (rm_pool_extend(rm_pool) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (rm_pool->free_list.count == 0) {
        *rmid = rm_pool->hwm;
        rm = rm_addr(rm_pool, *rmid);
        knl_init_rm(rm, *rmid);

        rm_pool->rms[rm_pool->hwm] = rm;
        g_instance->kernel.rms[rm_pool->hwm] = rm;
        rm_pool->hwm++;
        g_instance->kernel.rm_count++;
    } else {
        *rmid = rm_pool->free_list.first;
        rm = rm_addr(rm_pool, *rmid);
        CM_ASSERT(rm->id == *rmid);

        rm_pool->free_list.first = rm->next;
        rm_pool->free_list.count--;
        if (rm_pool->free_list.count == 0) {
            rm_pool->free_list.first = GS_INVALID_ID16;
            rm_pool->free_list.last = GS_INVALID_ID16;
        }
    }

    return GS_SUCCESS;
}

static inline void rm_release(rm_pool_t *rm_pool, uint16 rmid)
{
    knl_rm_t *rm = rm_pool->rms[rmid];

    CM_ASSERT(rmid != GS_INVALID_ID16 && rm->id == rmid);
    rm->sid = GS_INVALID_ID16;
    rm->uid = GS_INVALID_ID32;
    rm->next = GS_INVALID_ID16;

    if (rm_pool->free_list.count == 0) {
        rm->prev = GS_INVALID_ID16;
        rm_pool->free_list.first = rmid;
        rm_pool->free_list.last = rmid;
    } else {
        rm->prev = rm_pool->free_list.last;
        rm_pool->rms[rm_pool->free_list.last]->next = rmid;
        rm_pool->free_list.last = rmid;
    }

    rm_pool->free_list.count++;
}

static inline void rm_add_to_bucket(rm_pool_t *rm_pool, rm_bucket_t *bucket, uint16 rmid, uint8 status)
{
    knl_rm_t *rm = NULL;

    if (bucket->first != GS_INVALID_ID16) {
        rm = rm_pool->rms[bucket->first];
        rm->xa_prev = rmid;
    }

    rm = rm_pool->rms[rmid];
    rm->xa_status = status;
    rm->xa_next = bucket->first;

    bucket->first = rmid;
    bucket->count++;
}

static inline uint16 rm_find_from_bucket(rm_pool_t *rm_pool, rm_bucket_t *bucket, knl_xa_xid_t *xa_xid)
{
    uint16 rmid = bucket->first;
    knl_rm_t *rm = NULL;

    while (rmid != GS_INVALID_ID16) {
        rm = rm_pool->rms[rmid];

        if (knl_xa_xid_equal(xa_xid, &rm->xa_xid)) {
            return rmid;
        }

        rmid = rm->xa_next;
    }

    return rmid;
}

static inline void rm_remove_from_bucket(rm_pool_t *rm_pool, rm_bucket_t *bucket, uint16 rmid)
{
    knl_rm_t *rm = NULL;

    CM_ASSERT(bucket->count > 0);

    rm = rm_pool->rms[rmid];
    if (rm->xa_prev != GS_INVALID_ID16) {
        rm_pool->rms[rm->xa_prev]->xa_next = rm->xa_next;
    }

    if (rm->xa_next != GS_INVALID_ID16) {
        rm_pool->rms[rm->xa_next]->xa_prev = rm->xa_prev;
    }

    if (rmid == bucket->first) {
        bucket->first = rm->xa_next;
    }

    bucket->count--;
    knl_xa_reset_rm(rm);
}

status_t knl_alloc_rm(uint16 *rmid)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;

    cm_spin_lock(&rm_pool->lock, NULL);
    if (rm_alloc(rm_pool, rmid) != GS_SUCCESS) {
        cm_spin_unlock(&rm_pool->lock);
        return GS_ERROR;
    }
    cm_spin_unlock(&rm_pool->lock);

    rm = rm_pool->rms[*rmid];
    rm->prev = GS_INVALID_ID16;
    rm->next = GS_INVALID_ID16;
    return GS_SUCCESS;
}

void knl_release_rm(uint16 rmid)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;

    cm_spin_lock(&rm_pool->lock, NULL);
    rm_release(rm_pool, rmid);
    cm_spin_unlock(&rm_pool->lock);
}

status_t knl_alloc_auton_rm(knl_handle_t handle)
{
    knl_session_t *knl_session = (knl_session_t *)handle;
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;
    uint16 rmid;

    cm_spin_lock(&rm_pool->lock, NULL);
    if (rm_alloc(rm_pool, &rmid) != GS_SUCCESS) {
        cm_spin_unlock(&rm_pool->lock);
        return GS_ERROR;
    }
    cm_spin_unlock(&rm_pool->lock);

    rm = rm_pool->rms[rmid];
    rm->prev = knl_session->rmid;
    rm->next = GS_INVALID_ID16;

    knl_session->rm->next = rmid;
    knl_set_session_rm(knl_session, rmid);
    return GS_SUCCESS;
}

status_t knl_release_auton_rm(knl_handle_t handle)
{
    knl_session_t *knl_session = (knl_session_t *)handle;
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;
    uint16 curr, prev;
    status_t status = GS_SUCCESS;

    curr = knl_session->rmid;
    rm = knl_session->rm;

    prev = rm->prev;
    if (prev == GS_INVALID_ID16) {
        return GS_SUCCESS;
    }

    if (knl_xact_status(knl_session) != XACT_END) {
        knl_rollback(knl_session, NULL);
        GS_THROW_ERROR(ERR_TXN_IN_PROGRESS, "detect active transaction at the end of autonomous session");
        status = GS_ERROR;
    }

    rm = rm_pool->rms[prev];
    rm->next = GS_INVALID_ID16;

    knl_session->rmid = prev;
    knl_session->rm = rm;

    cm_spin_lock(&rm_pool->lock, NULL);
    rm_release(rm_pool, curr);
    cm_spin_unlock(&rm_pool->lock);

    return status;
}

uint16 knl_get_xa_xid(knl_xa_xid_t *xa_xid)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    rm_bucket_t *bucket = NULL;
    uint16 rmid;
    uint32 hash;

    hash = knl_xa_xid_hash(xa_xid);
    bucket = &rm_pool->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    rmid = rm_find_from_bucket(rm_pool, bucket, xa_xid);
    cm_spin_unlock(&bucket->lock);

    return rmid;
}

bool32 knl_add_xa_xid(knl_xa_xid_t *xa_xid, uint16 rmid, uint8 status)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    rm_bucket_t *bucket = NULL;
    uint16 temp;
    uint32 hash;

    hash = knl_xa_xid_hash(xa_xid);
    bucket = &rm_pool->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    temp = rm_find_from_bucket(rm_pool, bucket, xa_xid);
    if (temp != GS_INVALID_ID16) {
        cm_spin_unlock(&bucket->lock);
        return GS_FALSE;
    }

    rm_add_to_bucket(rm_pool, bucket, rmid, status);
    cm_spin_unlock(&bucket->lock);
    return GS_TRUE;
}

void knl_delete_xa_xid(knl_xa_xid_t *xa_xid)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    rm_bucket_t *bucket = NULL;
    uint16 rmid;
    uint32 hash;

    hash = knl_xa_xid_hash(xa_xid);
    bucket = &rm_pool->buckets[hash];

    cm_spin_lock(&bucket->lock, NULL);
    rmid = rm_find_from_bucket(rm_pool, bucket, xa_xid);
    if (rmid == GS_INVALID_ID16) {
        cm_spin_unlock(&bucket->lock);
        return;
    }

    rm_remove_from_bucket(rm_pool, bucket, rmid);
    cm_spin_unlock(&bucket->lock);
}

static inline void assign_trans_to_bg_rollback(knl_rm_t *rm)
{
    undo_t *undo = &g_instance->kernel.undo_ctx.undos[rm->tx_id.seg_id];
    g_instance->kernel.tran_ctx.rollback_num = g_instance->kernel.attr.tx_rollback_proc_num;
    undo->items[rm->tx_id.item_id].rmid = g_instance->kernel.sessions[SESSION_ID_ROLLBACK]->rmid;
}

void knl_shrink_xa_rms(knl_handle_t handle, bool32 force)
{
    knl_session_t *knl_session = (knl_session_t *)handle;
    uint16 org_rmid = knl_session->rmid;
    knl_rm_t *org_rm = knl_session->rm;
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    bool32 release_rm = GS_FALSE;
    knl_rm_t *rm = NULL;
    uint64 timeout;

    for (uint16 i = 0; i < rm_pool->hwm; i++) {
        GS_BREAK_IF_TRUE(knl_session->canceled);
        GS_BREAK_IF_TRUE(knl_session->killed);

        rm = rm_pool->rms[i];
        GS_CONTINUE_IFTRUE(!knl_xa_xid_valid(&rm->xa_xid));

        knl_session->rmid = i;
        knl_session->rm = rm;

        cm_spin_lock(&rm->lock, NULL);
        if (rm->xa_status == XA_PENDING) {
            if (force) {
                lock_free_sch_group(knl_session);
                // used for rollback procs to recover table locks of current residual xa transaction
                assign_trans_to_bg_rollback(rm);
                knl_tx_reset_rm(rm);
                GS_LOG_DEBUG_INF("lock free sch group of pending rm.rmid %u", i);
                release_rm = GS_TRUE;
            }
        }

        if (rm->xa_status == XA_SUSPEND) {
            timeout = (uint64)(KNL_NOW(knl_session) - rm->suspend_time);
            if (force || timeout / MICROSECS_PER_SECOND > rm->suspend_timeout) {
                knl_rollback(knl_session, NULL);
                GS_LOG_DEBUG_INF("rollback timeout suspend rm.rmid %u", i);
                release_rm = GS_TRUE;
            }
        }

        if (release_rm) {
            rm->xa_status = XA_INVALID;
        }
        cm_spin_unlock(&rm->lock);

        if (release_rm) {
            knl_delete_xa_xid(&rm->xa_xid);
            cm_spin_lock(&rm_pool->lock, NULL);
            rm_release(rm_pool, i);
            cm_spin_unlock(&rm_pool->lock);
        }
        release_rm = GS_FALSE;
    }

    knl_session->rmid = org_rmid;
    knl_session->rm = org_rm;
}

static bool32 knl_attach_rm(
    knl_session_t *knl_session, knl_xa_xid_t *xa_xid, uint8 exp_status, uint8 status, bool8 release)
{
    rm_pool_t *rm_pool = &g_instance->rm_pool;
    knl_rm_t *rm = NULL;
    uint16 rmid, curr;

    rmid = knl_get_xa_xid(xa_xid);
    if (rmid == GS_INVALID_ID16) {
        return GS_FALSE;
    }

    rm = rm_pool->rms[rmid];

    if (rm->xa_status != exp_status) {
        return GS_FALSE;
    }

    cm_spin_lock(&rm->lock, NULL);
    if (rm->xa_status != exp_status || !knl_xa_xid_equal(xa_xid, &rm->xa_xid)) {
        cm_spin_unlock(&rm->lock);
        return GS_FALSE;
    }

    /* the transaction branch can not be ended in one session, but resumed in another one */
    if ((rm->xa_flags & KNL_XA_NOMIGRATE) &&
        exp_status == XA_SUSPEND &&
        status == XA_START &&
        rm->sid != knl_session->id) {
        cm_spin_unlock(&rm->lock);
        return GS_FALSE;
    }

    rm->xa_status = status;
    cm_spin_unlock(&rm->lock);

    curr = knl_session->rmid;

    knl_session->rmid = rmid;
    knl_session->rm = rm;
    rm->sid = knl_session->id;

    if (release) {
        CM_ASSERT(curr != GS_INVALID_ID16);
        cm_spin_lock(&rm_pool->lock, NULL);
        rm_release(rm_pool, curr);
        cm_spin_unlock(&rm_pool->lock);
    }

    return GS_TRUE;
}

void knl_detach_suspend_rm(knl_handle_t handle, uint16 new_rmid)
{
    knl_session_t *knl_session = (knl_session_t *)handle;
    knl_rm_t *rm = knl_session->rm;

    CM_ASSERT(rm != NULL);
    rm->xa_status = XA_SUSPEND;
    rm->suspend_time = KNL_NOW(knl_session);
    if (!(rm->xa_flags & KNL_XA_NOMIGRATE)) {
        rm->sid = GS_INVALID_ID16;
    }

    knl_set_session_rm(knl_session, new_rmid);
}

bool32 knl_attach_suspend_rm(knl_handle_t handle, knl_xa_xid_t *xa_xid, uint8 status, bool8 release)
{
    return knl_attach_rm((knl_session_t *)handle, xa_xid, XA_SUSPEND, status, release);
}

void knl_detach_pending_rm(knl_handle_t handle, uint16 new_rmid)
{
    knl_session_t *knl_session = (knl_session_t *)handle;
    knl_rm_t *rm = knl_session->rm;

    CM_ASSERT(rm != NULL);
    rm->xa_status = XA_PENDING;
    rm->sid = GS_INVALID_ID16;

    knl_set_session_rm(knl_session, new_rmid);
}

bool32 knl_attach_pending_rm(knl_handle_t handle, knl_xa_xid_t *xa_xid)
{
    return knl_attach_rm((knl_session_t *)handle, xa_xid, XA_PENDING, XA_PHASE2, GS_FALSE);
}
