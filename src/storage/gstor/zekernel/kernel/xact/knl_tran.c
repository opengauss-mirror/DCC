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
 * knl_tran.c
 *    kernel transaction interface routines
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/xact/knl_tran.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_tran.h"
#include "cm_gts_timestamp.h"
#include "knl_lob.h"
#include "rcr_btree.h" 
#include "pcr_btree.h"
#include "knl_context.h"
#include "temp_btree.h"
#include "pcr_heap.h"
#include "knl_table.h"
#include "knl_xa.h"
#include "index_common.h"

pcr_itl_t g_init_pcr_itl = { .scn = 0, .xid.value = 0, .undo_page.value = 0, .undo_slot = 0, .flags = 0 };

static inline void tx_reset_rm(knl_rm_t *rm)
{
    lock_reset(rm);
    lob_items_reset(rm);
    rm->tx_id.value = GS_INVALID_ID64;
    rm->txn = NULL;
    rm->xid.value = GS_INVALID_ID64;
    rm->svpt_count = 0;
    rm->ssn = 0;
    rm->begin_lsn = GS_INVALID_ID64;
    rm->temp_has_undo = GS_FALSE;
    rm->noredo_undo_pages.count = 0;
    rm->noredo_undo_pages.first = INVALID_UNDO_PAGID;
    rm->noredo_undo_pages.last = INVALID_UNDO_PAGID;
}

void knl_tx_reset_rm(void *rm)
{
    tx_reset_rm((knl_rm_t *)rm);
}

status_t tx_area_init_impl(knl_session_t *session, uint32 lseg_no, uint32 rseg_no, bool32 is_extend)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;
    tx_item_t *item = NULL;
    uint32 txn_no, page_no, seg_no;
    uint32 id;

    if (is_extend && ctx->extend_cnt == 0) {
        ctx->extend_segno = lseg_no;
    }

    /* init each undo segment transaction area info */
    for (seg_no = lseg_no; seg_no < rseg_no; seg_no++) {
        undo = &ctx->undos[seg_no];
        undo->lock = 0;
        undo->ow_scn = DB_CURR_SCN(session);
        undo->capacity = UNDO_DEF_TXN_PAGE * TXN_PER_PAGE;
        if (is_extend) {
            uint64 buf_size = knl_txn_buffer_size(session->kernel->attr.page_size, 1);
            undo->items = (tx_item_t *)malloc((size_t)buf_size);
            if (undo->items == NULL) {
                GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extend undo segments");
                return GS_ERROR;
            }
            ctx->extend_cnt++;
        } else {
            undo->items = (tx_item_t *)(session->kernel->attr.tran_buf + seg_no * undo->capacity * sizeof(tx_item_t));
        }
        
        undo->free_items.count = 0;
        undo->free_items.first = GS_INVALID_ID32;
        undo->free_items.last = GS_INVALID_ID32;

        id = 0;
        for (txn_no = 0; txn_no < TXN_PER_PAGE; txn_no++) {
            for (page_no = 0; page_no < UNDO_DEF_TXN_PAGE; page_no++) {
                item = &undo->items[id];
                item->xmap.seg_id = seg_no;
                item->xmap.slot = (uint16)(page_no * TXN_PER_PAGE + txn_no);
                item->lock = 0;
                item->prev = GS_INVALID_ID32;
                item->next = GS_INVALID_ID32;
                item->rmid = GS_INVALID_ID16;
                item->in_progress = GS_FALSE;
                item->systime = KNL_NOW(session);
                id++;
            }
        }
    }

    return GS_SUCCESS;
}

status_t tx_area_init(knl_session_t *session, uint32 lseg_no, uint32 rseg_no)
{
    tx_area_t *area = &session->kernel->tran_ctx;

    /* global area info */
    area->scn_lock = 0;
    area->seri_lock = 0;
    area->rollback_num = 0;

    return tx_area_init_impl(session, lseg_no, rseg_no, GS_FALSE);
}

void tx_extend_deinit(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = NULL;

    for (uint32 i = ctx->extend_segno; i < ctx->extend_segno + ctx->extend_cnt; i++) {
        undo = &ctx->undos[i];
        CM_FREE_PTR(undo->items);
    }
}

static inline tx_id_t xmap_get_txid(knl_session_t *session, xmap_t xmap)
{
    tx_id_t tx_id;
    tx_id.seg_id = xmap.seg_id;
    tx_id.item_id = xmap.slot % TXN_PER_PAGE * UNDO_DEF_TXN_PAGE + xmap.slot / TXN_PER_PAGE;
    return tx_id;
}

tx_id_t tx_xmap_get_txid(knl_session_t *session, xmap_t xmap)
{
    return xmap_get_txid(session, xmap);
}

static inline tx_item_t *xmap_get_item(knl_session_t *session, xmap_t xmap)
{
    tx_id_t tx_id = xmap_get_txid(session, xmap);
    undo_t *undo = &session->kernel->undo_ctx.undos[tx_id.seg_id];
    return &undo->items[tx_id.item_id];
}

static inline void tx_bind_segid(knl_session_t *session, knl_rm_t *rm, uint64 global_segid)
{
    uint32 active_undo_segments = UNDO_ACTIVE_SEGMENT_COUNT;
    uint32 auton_trans_segments = UNDO_AUTON_TRANS_SEGMENT_COUNT;

    if (!UNDO_IS_AUTON_BIND_OWN || active_undo_segments <= auton_trans_segments) {
        rm->undo_segid = (uint32)(global_segid % active_undo_segments);
    } else {
        rm->undo_segid = (uint32)(global_segid % (active_undo_segments - auton_trans_segments) + auton_trans_segments);
    }

    rm->tx_id.seg_id = (uint32)(global_segid % (UNDO_SEGMENT_COUNT - auton_trans_segments) + auton_trans_segments);
}

static inline void tx_bind_auton_segid(knl_session_t *session, knl_rm_t *rm, uint64 global_segid)
{
    uint32 active_undo_segments = UNDO_ACTIVE_SEGMENT_COUNT;
    uint32 auton_trans_segments = UNDO_AUTON_TRANS_SEGMENT_COUNT;

    if (!UNDO_IS_AUTON_BIND_OWN || active_undo_segments <= auton_trans_segments) {
        rm->undo_segid = (uint32)(global_segid % active_undo_segments);
    } else {
        rm->undo_segid = (uint32)(global_segid % auton_trans_segments);
    }

    rm->tx_id.seg_id = (uint32)(global_segid % auton_trans_segments);
}

static inline undo_t *tx_bind_undo(knl_session_t *session, knl_rm_t *rm)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    uint64 global_segid;

    rm->undo_page_info.undo_rid = g_invalid_undo_rowid;
    rm->undo_page_info.undo_fs = 0;
    rm->undo_page_info.encrypt_enable = GS_FALSE;
    rm->undo_page_info.undo_log_encrypt = GS_FALSE;

    rm->noredo_undo_page_info.undo_rid = g_invalid_undo_rowid;
    rm->noredo_undo_page_info.undo_fs = 0;
    rm->noredo_undo_page_info.encrypt_enable = GS_FALSE;
    rm->noredo_undo_page_info.undo_log_encrypt = GS_FALSE;

    global_segid = (uint64)cm_atomic_inc(&session->kernel->undo_segid);

    if (rm->prev == GS_INVALID_ID16) {
        tx_bind_segid(session, rm, global_segid);
    } else {
        tx_bind_auton_segid(session, rm, global_segid);
    }

    return &ctx->undos[rm->tx_id.seg_id];
}

static status_t txn_alloc(knl_session_t *session, knl_rm_t *rm)
{
    undo_t *undo = tx_bind_undo(session, rm);

    cm_spin_lock(&undo->lock, &session->stat_txn_list);
    if (undo->free_items.count == 0) {
        cm_spin_unlock(&undo->lock);
        GS_THROW_ERROR(ERR_TOO_MANY_PENDING_TRANS);
        return GS_ERROR;
    }

    rm->tx_id.item_id = undo->free_items.first;
    undo->stat.txn_cnts++;
    undo->free_items.count--;
    if (undo->free_items.count == 0) {
        undo->free_items.first = GS_INVALID_ID32;
        undo->free_items.last = GS_INVALID_ID32;
    } else {
        undo->free_items.first = undo->items[rm->tx_id.item_id].next;
        knl_panic(undo->free_items.first != GS_INVALID_ID32);
        undo->items[undo->free_items.first].prev = GS_INVALID_ID32;
    }
    cm_spin_unlock(&undo->lock);

    return GS_SUCCESS;
}

static void txn_release(knl_session_t *session, tx_id_t tx_id)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = &ctx->undos[tx_id.seg_id];

    if (tx_id.item_id >= undo->capacity) {
        return;
    }

    /* release temp table hold_rmid */
    knl_temp_cache_t *temp_table_ptr = NULL;
    for (uint32 i = 0; i < session->temp_table_count; i++) {
        temp_table_ptr = &session->temp_table_cache[i];
        if (temp_table_ptr->hold_rmid == session->rmid) {
            temp_table_ptr->hold_rmid = GS_INVALID_ID32;
        }
    }
    
    cm_spin_lock(&undo->lock, &session->stat_txn_list);
    if (undo->free_items.count == 0) {
        undo->free_items.count = 1;
        undo->free_items.first = tx_id.item_id;
        undo->free_items.last = tx_id.item_id;
        undo->items[tx_id.item_id].prev = GS_INVALID_ID32;
    } else {
        undo->items[undo->free_items.last].next = tx_id.item_id;
        undo->items[tx_id.item_id].prev = undo->free_items.last;
        undo->free_items.last = tx_id.item_id;
        undo->free_items.count++;
    }
    undo->items[tx_id.item_id].next = GS_INVALID_ID32;
    cm_spin_unlock(&undo->lock);
}

void tx_area_release_impl(knl_session_t *session, uint32 lseg_no, uint32 rseg_no)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    tx_item_t *item = NULL;
    undo_t *undo = NULL;
    txn_t *txn = NULL;
    uint32 i, seg_no;
    tx_id_t tx_id;

    for (seg_no = lseg_no; seg_no < rseg_no; seg_no++) {
        undo = &ctx->undos[seg_no];

        for (i = 0; i < undo->capacity; i++) {
            item = &undo->items[i];
            txn = txn_addr(session, item->xmap);
            if (txn->status == (uint8)XACT_END) {
                tx_id.seg_id = item->xmap.seg_id;
                tx_id.item_id = i;
                txn_release(session, tx_id);
            }
        }
    }
}

void tx_area_release(knl_session_t *session)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    tx_area_t *area = &session->kernel->tran_ctx;
    uint32 rcy_rm_id = 0;
    bool32 need_rcy = GS_FALSE;
    uint16 txn_rcy_rmid[GS_MAX_ROLLBACK_PROC];
    undo_t *undo = NULL;
    tx_item_t *item = NULL;
    txn_t *txn = NULL;
    uint32 i, seg_no;
    tx_id_t tx_id;

    for (i = 0; i < GS_MAX_ROLLBACK_PROC; i++) {
        txn_rcy_rmid[i] = session->kernel->sessions[SESSION_ID_ROLLBACK + i]->rmid;
    }

    for (seg_no = 0; seg_no < core_ctrl->undo_segments; seg_no++) {
        undo = &ctx->undos[seg_no];

        for (i = 0; i < undo->capacity; i++) {
            item = &undo->items[i];
            txn = txn_addr(session, item->xmap);
            if (txn->status == (uint8)XACT_END) {
                tx_id.seg_id = item->xmap.seg_id;
                tx_id.item_id = i;
                txn_release(session, tx_id); 
            } else {
                item->rmid = txn_rcy_rmid[rcy_rm_id % session->kernel->attr.tx_rollback_proc_num];
                rcy_rm_id++;
                need_rcy = GS_TRUE;
            }
        }
    }

    area->rollback_num = need_rcy ? session->kernel->attr.tx_rollback_proc_num : 0;
}

void tx_rollback_items(knl_session_t *session, thread_t *thread, undo_t *undo)
{
    knl_rm_t *rm = session->rm;
    tx_item_t *item = NULL;
    txn_t *txn = NULL;
    uint32 id;
    status_t status;

    for (id = 0; id < undo->capacity; id++) {
        if (thread->closed) {
            break;
        }

        item = &undo->items[id];
        if (item->rmid != session->rmid) {
            continue;
        }

        txn = txn_addr(session, item->xmap);

        switch (txn->status) {
            case XACT_PHASE1:
                status = xa_recover(session, item, txn, id);
                knl_panic(status == GS_SUCCESS);
                break;
            case XACT_PHASE2:
            case XACT_BEGIN:
                tx_rm_attach_trans(rm, item, txn, id);
                knl_rollback(session, NULL);
                break;
            case XACT_END:
            default:
                break;
        }
    }
}

void tx_area_rollback(knl_session_t *session, thread_t *thread)
{
    tx_area_t *area = &session->kernel->tran_ctx;
    undo_context_t *ctx = &session->kernel->undo_ctx;
    uint32 seg_no;

    if ((!DB_IS_READONLY(session)) && DB_IS_BG_ROLLBACK_SE(session) && DB_IN_BG_ROLLBACK(session)) {
        for (seg_no = 0; seg_no < UNDO_SEGMENT_COUNT; seg_no++) {
            if (thread->closed) {
                break;
            }

            tx_rollback_items(session, thread, &ctx->undos[seg_no]);
        }

        (void)cm_atomic_dec(&area->rollback_num);
    }
}

inline txn_t *txn_addr(knl_session_t *session, xmap_t xmap)
{
    uint32 page_capacity = TXN_PER_PAGE;
    undo_t *undo = &session->kernel->undo_ctx.undos[xmap.seg_id];
    txn_page_t *txn_page = undo->txn_pages[xmap.slot / page_capacity];
    return &txn_page->items[xmap.slot % page_capacity];
}

status_t tx_begin(knl_session_t *session)
{
    knl_rm_t *rm = session->rm;
    undo_t *undo = NULL;
    tx_item_t *tx_item = NULL;
    txn_t *txn = NULL;
    undo_page_id_t page_id;

    if (session->kernel->undo_ctx.is_switching) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",when swithching undo space");
        return GS_ERROR;
    }

    uint64 begin_time = KNL_NOW(session);

    if (txn_alloc(session, rm) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (KNL_IS_AUTON_SE(session)) {
        session->kernel->stat.auto_txn_alloc_times += KNL_NOW(session) - begin_time;
    } else {
        session->kernel->stat.txn_alloc_times += KNL_NOW(session) - begin_time;
    }

    undo = &session->kernel->undo_ctx.undos[rm->tx_id.seg_id];
    tx_item = &undo->items[rm->tx_id.item_id];
    page_id = undo->segment->txn_page[tx_item->xmap.slot / TXN_PER_PAGE];
    rm->xid.xmap = tx_item->xmap;

    log_atomic_op_begin(session);

    begin_time = KNL_NOW(session);

    buf_enter_page(session, PAGID_U2N(page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    txn = txn_addr(session, tx_item->xmap);
    cm_spin_lock(&tx_item->lock, &session->stat_txn);
    txn->xnum++;
    txn->status = (uint8)XACT_BEGIN;
    txn->undo_pages.count = 0;
    txn->undo_pages.first = INVALID_UNDO_PAGID;
    txn->undo_pages.last = INVALID_UNDO_PAGID;
    tx_item->rmid = session->rmid;
    rm->xid.xnum = txn->xnum;
    cm_spin_unlock(&tx_item->lock);

    rm->txn = txn;
    log_put(session, RD_TX_BEGIN, &rm->xid, sizeof(xid_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, GS_TRUE);

    if (KNL_IS_AUTON_SE(session)) {
        session->kernel->stat.auto_txn_page_waits += KNL_NOW(session) - begin_time;
    } else {
        session->kernel->stat.txn_page_waits += KNL_NOW(session) - begin_time;
    }

    log_atomic_op_end(session);

    rm->begin_lsn = session->curr_lsn;
    tx_item->systime = KNL_NOW(session);
    return GS_SUCCESS;
}

/*
 * if call this function, must lock scn_lock first
 */
knl_scn_t tx_inc_scn(knl_session_t *session, uint32 seg_id, txn_t *txn, knl_scn_t xa_scn)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    tx_area_t *area = &session->kernel->tran_ctx;
    knl_scn_t scn;
    timeval_t now;
    time_t init_time;
    status_t status;
    knl_scn_t gts_scn;
    uint64 seq = 1;
    undo_t *undo = &ctx->undos[seg_id];

    init_time = DB_INIT_TIME(session);

    if (TX_XA_CONSISTENCY(session)) {
        status = gts_get_lcl_timestamp(&gts_scn);
        KNL_SCN_TO_TIMESEQ(gts_scn, &now, seq, CM_GTS_BASETIME);
        seq++;
        knl_panic(status == GS_SUCCESS);
    } else {
        (void)cm_gettimeofday(&now);
    }

    cm_spin_lock(&area->scn_lock, &session->stat_inc_scn);

    if (xa_scn != GS_INVALID_ID64) {
        scn = xa_scn;
        if (scn > KNL_GET_SCN(&session->kernel->scn)) {
            KNL_SET_SCN(&session->kernel->scn, scn);
        }
    } else {
        scn = knl_inc_scn(init_time, &now, seq, &session->kernel->scn, session->kernel->attr.systime_inc_threshold);
    }

    if (undo->ow_scn < txn->scn && txn->status != (uint8)XACT_PHASE1) {
        undo->ow_scn = txn->scn;
    }

    cm_spin_unlock(&area->scn_lock);

    return scn;
}

static inline void tx_end_stat(knl_session_t *session, txn_t *txn, tx_item_t *item)
{
    if (txn->status == (uint8)XACT_BEGIN) {
        session->stat.local_txn_times += (KNL_NOW(session) - item->systime);
    } else if (txn->status == (uint8)XACT_PHASE1 || txn->status == (uint8)XACT_PHASE2) {
        session->stat.xa_txn_times += (KNL_NOW(session) - item->systime);
    } else {
        // Never happened until error.
        knl_panic(0);
    }
}

/*
 * end transaction
 * From now on, we are going to overwrite commit scn to transaction,
 * save the max overwritten scn to global transaction area. If we are
 * in rollback process, overwrite 0 to transaction, so the following
 * allocation of itl can reuse itl related to current transaction
 * immediately 'causing no rows or keys are related with the itl.
 */
static void tx_end(knl_session_t *session, bool32 is_commit, knl_scn_t xa_scn)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    tx_area_t *area = &session->kernel->tran_ctx;
    knl_rm_t *rm = session->rm;
    txn_t *txn = rm->txn;
    undo_t *tx_undo = &ctx->undos[rm->tx_id.seg_id];
    tx_item_t *tx_item = &tx_undo->items[rm->tx_id.item_id];
    undo_page_id_t page_id = tx_undo->segment->txn_page[tx_item->xmap.slot / TXN_PER_PAGE];
    bool32 has_logic = (session->kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON);
    rd_tx_end_t redo;

    rm->need_copy_logic_log = LOG_HAS_LOGIC_DATA(session);
    rm->nolog_insert = GS_FALSE;
    undo_t *undo = &ctx->undos[UNDO_GET_SESSION_UNDO_SEGID(session)];

    redo.xmap = rm->xid.xmap;
    redo.is_auton = 0;
    redo.is_commit = (uint8)is_commit;
    tx_end_stat(session, txn, tx_item);

    /* from now on, we are entering transaction end progress */
    tx_item->in_progress = GS_TRUE;

    if (session->kernel->attr.serialized_commit) {
        cm_spin_lock(&area->seri_lock, &session->stat_seri_commit);
    }

    uint64 begin_time = KNL_NOW(session);
    log_atomic_op_begin(session);
    buf_enter_page(session, PAGID_U2N(page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    cm_spin_lock(&tx_item->lock, &session->stat_txn);
    txn->scn = tx_inc_scn(session, rm->tx_id.seg_id, txn, xa_scn);
    tx_item->rmid = GS_INVALID_ID16;
    txn->status = (uint8)XACT_END;
    cm_spin_unlock(&tx_item->lock);
    cm_atomic_set(&session->kernel->commit_scn, (int64)txn->scn);

    redo.scn = txn->scn;
    redo.aligned = 0;
    log_put(session, RD_TX_END, &redo, sizeof(rd_tx_end_t), LOG_ENTRY_FLAG_NONE);
    if (has_logic && knl_xa_xid_valid(&rm->xa_xid)) {
        log_append_data(session, &rm->xa_xid, sizeof(knl_xa_xid_t));
    }
    buf_leave_page(session, GS_TRUE);

    if (KNL_IS_AUTON_SE(session)) {
        session->kernel->stat.auto_txn_page_end_waits += KNL_NOW(session) - begin_time;
    } else {
        session->kernel->stat.txn_page_end_waits += KNL_NOW(session) - begin_time;
    }

    if (txn->undo_pages.count > 0 && session->rm != NULL) {
        undo_release_pages(session, undo, &txn->undo_pages, GS_TRUE);
        session->rm->txn_alarm_enable = GS_TRUE;
    }

    if (session->rm != NULL && session->rm->noredo_undo_pages.count > 0) {
        undo_release_pages(session, undo, &rm->noredo_undo_pages, GS_FALSE);
    }

    log_atomic_op_end(session);

    if (session->kernel->attr.serialized_commit) {
        cm_spin_unlock(&area->seri_lock);
    }

    tx_item->in_progress = GS_FALSE;
    cm_release_cond(&rm->cond);
}

static inline void tx_release(knl_session_t *session)
{
    knl_rm_t *rm = session->rm;

    lock_free(session, rm);
    txn_release(session, rm->tx_id);

    tx_reset_rm(rm);
}

static inline void tx_copy_logic_log(knl_session_t *session)
{
    knl_rm_t *rm = session->rm;

    rm->need_copy_logic_log = LOG_HAS_LOGIC_DATA(session);
    if (rm->need_copy_logic_log) {
        log_atomic_op_begin(session);
        log_atomic_op_end(session);
        log_commit(session);
    }
}

static inline void tx_delete_xa_xid(knl_session_t *session)
{
    if (knl_xa_xid_valid(&session->rm->xa_xid)) {
        g_knl_callback.delete_xa_xid(&session->rm->xa_xid);
    }
}

void tx_commit(knl_session_t *session, knl_scn_t xa_scn)
{
    knl_rm_t *rm = session->rm;

    rm->isolevel = session->kernel->attr.db_isolevel;
    rm->query_scn = GS_INVALID_ID64;

    if (session->temp_table_count != 0) {
        knl_close_temp_tables(session, DICT_TYPE_TEMP_TABLE_TRANS);
    }

    if (rm->txn == NULL || rm->txn->status == (uint8)XACT_END) {
        tx_copy_logic_log(session);
        rm->svpt_count = 0;
        return;
    }

    // to recycle lob deleted pages
    if (rm->lob_items.count != 0) {
        lob_free_delete_pages(session);
        lob_items_free(session);
    }

    tx_end(session, GS_TRUE, xa_scn);
    log_commit(session);
    tx_release(session);
    g_knl_callback.accumate_io(session, IO_TYPE_COMMIT);
}

static inline status_t tx_is_invalid_xid(knl_session_t *session, xid_t xid)
{
    if (xid.xmap.seg_id >= UNDO_SEGMENT_COUNT
        || (xid.xmap.slot / TXN_PER_PAGE) >= UNDO_DEF_TXN_PAGE) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "invalid xid , exceed max segment count or def txn pages");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t knl_commit_force(knl_handle_t handle, knl_xid_t *xid)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;
    tx_item_t *item = NULL;
    txn_t *txn = NULL;
    xid_t force_xid;
    tx_id_t tx_id;
    uint32 i;

    if (!DB_IS_RESTRICT(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return GS_ERROR;
    }

    if (rm->txn != NULL) {
        GS_THROW_ERROR(ERR_TXN_IN_PROGRESS, "cur session is in transaction,can't commit force transaction.");
        return GS_ERROR;
    }

    force_xid.xmap.seg_id = xid->seg_id;
    force_xid.xmap.slot = xid->slot;
    force_xid.xnum = xid->xnum;

    if (tx_is_invalid_xid(session, force_xid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    item = xmap_get_item(session, force_xid.xmap);
    txn = txn_addr(session, force_xid.xmap);

    for (i = SESSION_ID_ROLLBACK; i <= SESSION_ID_ROLLBACK_EDN; i++) {
        if (item->rmid == session->kernel->sessions[i]->rmid) {
            break;
        }
    }

    if (i > SESSION_ID_ROLLBACK_EDN
        || txn->status == (uint8)XACT_END 
        || txn->xnum != xid->xnum) {
        GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "invalid xid , not found residual transaction");
        return GS_ERROR;
    }

    /* if the xa trans status is XACT_PHASE2, force commit it as normal residual transaction */
    if (txn->status == (uint8)XACT_PHASE1) {
        GS_THROW_ERROR(ERR_XATXN_IN_PROGRESS, "can't commit force residual XA transaction.");
        return GS_ERROR;
    }

    tx_id = xmap_get_txid(session, force_xid.xmap);
    tx_rm_attach_trans(rm, item, txn, tx_id.item_id);
    knl_commit(handle);
    return GS_SUCCESS;
}

void knl_commit(knl_handle_t handle)
{
    knl_session_t *session = (knl_session_t *)handle;
    g_knl_callback.before_commit(handle);
    tx_commit(session, GS_INVALID_ID64);
    session->stat.commits++;
    tx_delete_xa_xid(session);
}

static void tx_undo_one_row(knl_session_t *session, undo_row_t *row, undo_page_t *page, int32 slot,
    knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    switch (row->type) {
        case UNDO_HEAP_INSERT:
            heap_undo_insert(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_HEAP_DELETE:
        case UNDO_HEAP_DELETE_ORG:
        case UNDO_HEAP_COMPACT_DELETE:
        case UNDO_HEAP_COMPACT_DELETE_ORG:
            heap_undo_delete(session, row, page, slot);
            break;
        case UNDO_HEAP_UPDATE:
        case UNDO_HEAP_UPDATE_FULL:
            heap_undo_update(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_BTREE_INSERT:
            btree_undo_insert(session, row, page, slot, dc);
            break;
        case UNDO_BTREE_DELETE:
            btree_undo_delete(session, row, page, slot, dc);
            break;
        case UNDO_CREATE_INDEX:
            btree_undo_create(session, row, page, slot);
            break;
        case UNDO_LOB_INSERT:
            lob_undo_insert(session, row, page, slot, dc);
            break;
        case UNDO_LOB_DELETE_COMMIT:
            lob_undo_delete_commit(session, row, page, slot);
            break;
        case UNDO_TEMP_HEAP_INSERT:
            temp_heap_undo_insert(session, row, page, slot);
            break;
        case UNDO_TEMP_HEAP_BINSERT:
            temp_heap_undo_batch_insert(session, row, page, slot);
            break;
        case UNDO_TEMP_HEAP_DELETE:
            temp_heap_undo_delete(session, row, page, slot);
            break;
        case UNDO_TEMP_HEAP_UPDATE:
        case UNDO_TEMP_HEAP_UPDATE_FULL:
            temp_heap_undo_update(session, row, page, slot);
            break;
        case UNDO_TEMP_BTREE_INSERT:
            temp_btree_undo_insert(session, row, page, slot, dc);
            break;
        case UNDO_TEMP_BTREE_BINSERT:
            temp_btree_undo_batch_insert(session, row, page, slot, dc);
            break;
        case UNDO_TEMP_BTREE_DELETE:
            temp_btree_undo_delete(session, row, page, slot, dc);
            break;
        case UNDO_LOB_DELETE:
            lob_undo_delete(session, row, page, slot);
            break;
        case UNDO_HEAP_INSERT_MIGR:
            heap_undo_insert_migr(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_HEAP_UPDATE_LINKRID:
            heap_undo_update_linkrid(session, row, page, slot);
            break;
        case UNDO_HEAP_DELETE_MIGR:
            heap_undo_delete_migr(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_PCRH_ITL:
            pcrh_undo_itl(session, row, page, slot, dc, heap_assist);
            break;
        case UNDO_PCRH_INSERT:
            pcrh_undo_insert(session, row, page, slot);
            break;
        case UNDO_PCRH_DELETE:
        case UNDO_PCRH_COMPACT_DELETE:
            pcrh_undo_delete(session, row, page, slot);
            break;
        case UNDO_PCRH_UPDATE:
        case UNDO_PCRH_UPDATE_FULL:
            pcrh_undo_update(session, row, page, slot);
            break;
        case UNDO_PCRH_UPDATE_LINK_SSN:
            pcrh_undo_update_link_ssn(session, row, page, slot);
            break;
        case UNDO_PCRH_UPDATE_NEXT_RID:
            pcrh_undo_update_next_rid(session, row, page, slot);
            break;
        case UNDO_PCRH_BATCH_INSERT:
            pcrh_undo_batch_insert(session, row, page, slot);
            break;
        case UNDO_PCRB_ITL:
            pcrb_undo_itl(session, row, page, slot);
            break;
        case UNDO_PCRB_INSERT:
            pcrb_undo_insert(session, row, page, slot, dc);
            break;
        case UNDO_PCRB_DELETE:
            pcrb_undo_delete(session, row, page, slot, dc);
            break;
        case UNDO_PCRB_BATCH_INSERT:
            pcrb_undo_batch_insert(session, row, page, slot, dc);
            break;
        case UNDO_LOB_DELETE_COMMIT_RECYCLE:
            lob_undo_delete_commit_recycle(session, row, page, slot);
            break;
        default:
            knl_panic_log(0, "row type is unknown, panic info: page %u-%u type %u row type %u",
                          AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, row->type);
            break;
    }
}

void tx_rollback_one_row(knl_session_t *session, undo_row_t *row, undo_page_t *page, int32 slot)
{
    knl_dictionary_t dc;
    heap_undo_assist_t heap_assist;
    page_id_t page_id;
    uint32 i;

    heap_assist.rows = 0;
    heap_assist.heap = NULL;
    heap_assist.need_latch = GS_FALSE;
    dc.handle = NULL;
    page_id = AS_PAGID(page->head.id);

    log_atomic_op_begin(session);

    tx_undo_one_row(session, row, page, slot, &dc, &heap_assist);

    if (heap_assist.need_latch) {
        cm_latch_x(&heap_assist.heap->latch, session->id, &session->stat_heap);
        tx_undo_one_row(session, row, page, slot, &dc, &heap_assist);
        cm_unlatch(&heap_assist.heap->latch, &session->stat_heap);
    }

    // The cleanup of undo row should be in the same atomic operation
    // with rollback to avoid log partial write which would cause
    // rollback a roll-backed row after recovery.
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_PINNED);
    row->is_cleaned = 1;
    if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
        log_put(session, RD_UNDO_CLEAN, &slot, sizeof(int32), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    for (i = 0; i < heap_assist.rows; i++) {
        session->change_list = heap_assist.change_list[i];
        heap_try_change_map(session, heap_assist.heap, heap_assist.page_id[i]);
    }

    if (dc.handle != NULL) {
        dc_close(&dc);
    }
}

static void tx_free_undo_pages(knl_session_t *session, undo_page_list_t *free_list, page_id_t last_page_id,
                               bool32 need_redo)
{
    undo_context_t *ctx = &session->kernel->undo_ctx;
    undo_t *undo = &ctx->undos[UNDO_GET_SESSION_UNDO_SEGID(session)];
    knl_rm_t *rm = session->rm;
    txn_t *txn = rm->txn;
    undo_page_id_t txn_page_id;
    undo_page_list_t *tx_undo_page_list = NULL;
    rd_undo_chg_txn_t redo;

    txn_get_owner(session, rm->xid.xmap, &txn_page_id);

    log_atomic_op_begin(session);
    buf_enter_page(session, PAGID_U2N(txn_page_id), LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (need_redo) {
        tx_undo_page_list = &txn->undo_pages;
    } else {
        tx_undo_page_list = &rm->noredo_undo_pages;
    }

    knl_panic_log(tx_undo_page_list->count >= free_list->count, "undo page count is smaller than free count, "
                  "panic info: page %u-%u type %u undo page count %u free count %u", txn_page_id.file,
                  txn_page_id.page, ((page_head_t *)CURR_PAGE)->type, tx_undo_page_list->count, free_list->count);
    tx_undo_page_list->count -= free_list->count;
    if (tx_undo_page_list->count == 0) {
        tx_undo_page_list->first = INVALID_UNDO_PAGID;
        tx_undo_page_list->last = INVALID_UNDO_PAGID;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(last_page_id), "last page id is invalid, panic info: txn_page %u-%u type %u",
                      txn_page_id.file, txn_page_id.page, ((page_head_t *)CURR_PAGE)->type);
        tx_undo_page_list->last = PAGID_N2U(last_page_id);
    }

    if (need_redo) {
        redo.xmap = rm->xid.xmap;
        redo.undo_pages = *tx_undo_page_list;
        log_put(session, RD_UNDO_CHANGE_TXN, &redo, sizeof(rd_undo_chg_txn_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, need_redo);

    undo_release_pages(session, undo, free_list, need_redo);
    log_atomic_op_end(session);
}

/*
 * rollback undo record on undo pages
 * rollback from current_slot in begin page to target_slot in end page,
 * if end page is a invalid page_id, rollback all undo-chained-pages generated by current transaction
 * only in end transaction scenario could we free undo pages in rollback
 */
static void tx_rollback_pages(knl_session_t *session, undo_page_id_t undo_page_id, undo_rowid_t *svpt_urid,
                              bool32 need_redo)
{
    knl_rm_t *rm = session->rm;
    int32 slot, min_slot;
    uint16 end_slot;
    undo_page_t *page = NULL;
    undo_row_t *row = NULL;
    buf_ctrl_t *ctrl = NULL;
    page_id_t page_id, prev;
    undo_page_list_t free_list;
    bool32 need_release = (svpt_urid == NULL && rm->svpt_count == 0);
    free_list.count = 0;
    page_id = PAGID_U2N(undo_page_id);
    if (rm->nolog_insert) {
        return;
    }

    while (!IS_INVALID_PAGID(page_id)) {
        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_PINNED);
        page = (undo_page_t *)CURR_PAGE;
        end_slot = page->begin_slot;
        prev = PAGID_U2N(page->prev);
        ctrl = session->curr_page_ctrl;
        buf_leave_page(session, GS_FALSE);

        if (svpt_urid != NULL && IS_SAME_PAGID(svpt_urid->page_id, page_id)) {
            knl_panic_log(svpt_urid->slot >= end_slot, "slot abnormal, panic info: page %u-%u type %u "
                          "svpt_urid slot %u end_slot %u", AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page,
                          page->head.type, svpt_urid->slot, end_slot);
            end_slot = svpt_urid->slot;
        }

        min_slot = (int32)end_slot;
        for (slot = (int32)page->rows - 1; slot >= min_slot; slot--) {
            row = UNDO_ROW(page, slot);
            knl_panic_log(row->xid.value == rm->xid.value, "the xid of row and rm are not equal, panic info: "
                          "page %u-%u type %u row xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                          AS_PAGID(page->head.id).page, page->head.type, row->xid.value, rm->xid.value);

            if (!row->is_cleaned) {
                tx_rollback_one_row(session, row, page, slot);
            }
        }

        BUF_UNPIN(ctrl);

        if (svpt_urid != NULL && IS_SAME_PAGID(svpt_urid->page_id, page_id)) {
            break;  // rollback to savepoint
        }

        if (need_release) {
            if (free_list.count == 0) {
                free_list.first = as_undo_page_id(page_id);
                free_list.last = as_undo_page_id(page_id);
            } else {
                free_list.first = as_undo_page_id(page_id);
            }
            free_list.count++;

            if (free_list.count == GS_EXTENT_SIZE) {
                tx_free_undo_pages(session, &free_list, prev, need_redo);
                free_list.count = 0;
            }
        }
        
        page_id = prev;
    }
}

/*
 * release savepoint whose lsn bigger than the parameter lsn on rm when rollback.
 */
static void tx_release_named_savepoint(knl_session_t *session, knl_savepoint_t *savepoint)
{
    int i;
    knl_rm_t *rm = session->rm;

    if (savepoint == NULL) {
        rm->svpt_count = 0;
        return;
    }
    
    if (rm->svpt_count == 0) {
        return;
    }

    if (savepoint->name[0] != '\0') {
        for (i = rm->svpt_count - 1; i >= 0; i--) {
            if (cm_str_equal_ins(savepoint->name, rm->save_points[i].name)) {
                break;
            }
        }
    } else {
        for (i = rm->svpt_count - 1; i >= 0; i--) {
            if (rm->save_points[i].lsn <= savepoint->lsn) {
                break;
            }
        }
    }

    if (i < 0) {
        rm->svpt_count = 0;
    } else {
        rm->svpt_count = i + 1;
    }
}

void tx_rollback(knl_session_t *session, knl_savepoint_t *savepoint)
{
    knl_rm_t *rm = session->rm;

    /* release savepoint on the rm */
    tx_release_named_savepoint(session, savepoint);

    if (rm->txn == NULL || rm->txn->status == (uint8)XACT_END) {
        if (savepoint == NULL) {
            rm->isolevel = session->kernel->attr.db_isolevel;
            rm->query_scn = GS_INVALID_ID64;
        }
        return;
    }

    /* Only the savepoint in current transaction is valid. */
    if (savepoint != NULL && savepoint->xid == rm->xid.value) {
        knl_panic(savepoint->lsn != GS_INVALID_ID64 || DB_IS_BG_ROLLBACK_SE(session)
                  || IS_INVALID_PAGID(savepoint->urid.page_id) || knl_xa_xid_valid(&rm->xa_xid));
        tx_rollback_pages(session, rm->undo_page_info.undo_rid.page_id, &savepoint->urid, GS_TRUE);
        tx_rollback_pages(session, rm->noredo_undo_page_info.undo_rid.page_id, &savepoint->noredo_urid, GS_FALSE);

        g_knl_callback.invalidate_cursor(session, savepoint->lsn);
    } else {
        knl_panic(rm->begin_lsn != GS_INVALID_ID64 || DB_IS_BG_ROLLBACK_SE(session) || knl_xa_xid_valid(&rm->xa_xid));
        tx_rollback_pages(session, rm->undo_page_info.undo_rid.page_id, NULL, GS_TRUE);
        tx_rollback_pages(session, rm->noredo_undo_page_info.undo_rid.page_id, NULL, GS_FALSE);

        g_knl_callback.invalidate_cursor(session, rm->begin_lsn);
    }

    /* Current savepoint is valid or rm has named savepoint, don't end transaction */
    if (savepoint != NULL && (savepoint->xid == rm->xid.value || rm->svpt_count > 0)) {
        lob_reset_svpt(session, savepoint);
        lock_free_to_svpt(session, savepoint);
        lock_reset_to_svpt(session, savepoint);
    } else {
        if (rm->lob_items.count != 0) {
            lob_items_free(session);
        }

        tx_end(session, GS_FALSE, GS_INVALID_ID64);
        tx_release(session);
        if (session->temp_table_count != 0) {
            knl_close_temp_tables(session, DICT_TYPE_TEMP_TABLE_TRANS);
        }
    }

    if (savepoint == NULL) {
        rm->isolevel = session->kernel->attr.db_isolevel;
        rm->query_scn = GS_INVALID_ID64;
    }
}

void knl_rollback(knl_handle_t handle, knl_savepoint_t *savepoint)
{
    knl_session_t *session = (knl_session_t *)handle;
    knl_rm_t *rm = session->rm;

    if (session->rm->nolog_insert) {
        GS_LOG_RUN_WAR("End the whole transaction without rolling back row data because it has had a log free insert, \
rmid: %d, xid(%d, %d, %d).", session->rmid, rm->xid.xmap.seg_id, rm->xid.xmap.slot, rm->xid.xnum);
        tx_rollback(session, NULL);
    } else {
        tx_rollback(session, savepoint);
    }

    if (savepoint == NULL) {
        tx_delete_xa_xid(session);
    }

    session->dist_ddl_id = NULL;

    session->stat.rollbacks++;
}

/*
 * get transaction info
 * get transaction info by transaction xid
 * @param kernel session, is_scan, xid, trans info
 */
static void tx_get_info(knl_session_t *session, bool32 is_scan, xid_t xid, txn_info_t *txn_info)
{
    txn_snapshot_t snapshot;

    tx_get_snapshot(session, xid.xmap, &snapshot);

    if (xid.xnum == snapshot.xnum) {
        /*
         * Transaction version is same with us, we get trans info directly from
         * current transaction. If transaction is in XACT_END status, we just return it.
         * If transaction is active or transaction is ending in progress and current
         * behavior is itl-reuse, we will read history version or reuse other itl.
         */
        txn_info->is_owscn = GS_FALSE;

        if (snapshot.status == (uint8)XACT_PHASE1 || snapshot.status == (uint8)XACT_PHASE2) {
            txn_info->scn = snapshot.scn;
            txn_info->status = (uint8)snapshot.status;
        } else if (snapshot.status != (uint8)XACT_END || (snapshot.in_progress && !is_scan)) {
            txn_info->scn = DB_CURR_SCN(session);
            txn_info->status = (uint8)XACT_BEGIN;
        } else {
            txn_info->scn = snapshot.scn;
            txn_info->status = (uint8)XACT_END;
        }
    } else if (xid.xnum + 1 == snapshot.xnum && snapshot.status == (uint8)XACT_BEGIN) {
        /*
         * To increase transaction info retention time, we would not overwrite
         * transaction scn when we are reusing a committed transaction. So, we
         * can get commit version from current transaction directly.
         */
        txn_info->scn = snapshot.scn;
        txn_info->is_owscn = GS_FALSE;
        txn_info->status = (uint8)XACT_END;
    } else {
        /* commit info has been overwritten, get from undo global overwrite area */
        undo_t *undo = &session->kernel->undo_ctx.undos[xid.xmap.seg_id];
        txn_info->status = (uint8)XACT_END;
        txn_info->is_owscn = GS_TRUE;
        txn_info->scn = undo->ow_scn;
    }
}

void tx_get_itl_info(knl_session_t *session, bool32 is_scan, itl_t *itl, txn_info_t *txn_info)
{
    if (itl->is_active) {
        tx_get_info(session, is_scan, itl->xid, txn_info);
    } else {
        txn_info->scn = itl->scn;
        txn_info->is_owscn = (bool8)itl->is_owscn;
        txn_info->status = (uint8)XACT_END;
    }
}

void tx_get_pcr_itl_info(knl_session_t *session, bool32 is_scan, pcr_itl_t *itl, txn_info_t *txn_info)
{
    if (itl->is_active) {
        if (!itl->is_hist) {
            tx_get_info(session, is_scan, itl->xid, txn_info);
        } else {
            txn_info->scn = DB_CURR_SCN(session);
            txn_info->is_owscn = GS_FALSE;
            txn_info->status = (uint8)XACT_BEGIN;
        }
    } else {
        txn_info->scn = itl->scn;
        txn_info->is_owscn = (bool8)itl->is_owscn;
        txn_info->status = (uint8)XACT_END;
    }
}

static status_t tx_check_wait_valid(knl_session_t *session)
{
    if (session->dead_locked) {
        GS_THROW_ERROR(ERR_DEAD_LOCK, "transaction", session->id);
        GS_LOG_ALARM(WARN_DEADLOCK, "'instance-name':'%s'}", session->kernel->instance_name);
        return GS_ERROR;
    }

    if (session->itl_dead_locked) {
        GS_THROW_ERROR(ERR_DEAD_LOCK, "itl", session->id);
        GS_LOG_ALARM(WARN_DEADLOCK, "'instance-name':'%s'}", session->kernel->instance_name);
        return GS_ERROR;
    }

    if (session->lock_dead_locked) {
        GS_THROW_ERROR(ERR_DEAD_LOCK, "table", session->id);
        GS_LOG_ALARM(WARN_DEADLOCK, "'instance-name':'%s'}", session->kernel->instance_name);
        return GS_ERROR;
    }

    if (session->canceled) {
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);
        return GS_ERROR;
    }

    if (session->killed) {
        GS_THROW_ERROR(ERR_OPERATION_KILLED);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline void tx_reset_deadlock_flag(knl_session_t *session)
{
    session->itl_dead_locked = GS_FALSE;
    session->dead_locked = GS_FALSE;
    session->lock_dead_locked = GS_FALSE;
}

/*
 * transaction wait
 * transaction concurrency control interface
 * Wait for the end of the transaction which hold the heap row or btree key.
 * @param kernel session, timeout(in milliseconds)
 */
status_t tx_wait(knl_session_t *session, uint32 timeout, wait_event_t event)
{
    knl_rm_t *wait_rm = NULL;
    txn_snapshot_t snapshot;
    date_t begin_time;
    status_t status;

    tx_get_snapshot(session, session->wxid.xmap, &snapshot);
    if (snapshot.xnum != session->wxid.xnum || snapshot.status == (uint8)XACT_END) {
        session->wxid.value = GS_INVALID_ID64;
        return GS_SUCCESS;
    }

    begin_time = KNL_NOW(session);
    tx_reset_deadlock_flag(session);
    session->wrmid = snapshot.rmid;
    wait_rm = session->kernel->rms[snapshot.rmid];

    knl_begin_session_wait(session, event, GS_TRUE);

    for (;;) {
        if (cm_wait_cond(&wait_rm->cond, TX_WAIT_INTERVEL)) {
            tx_get_snapshot(session, session->wxid.xmap, &snapshot);
            if (snapshot.xnum != session->wxid.xnum || snapshot.status == (uint8)XACT_END) {
                status = GS_SUCCESS;
                break;
            }
        }

        if (timeout != 0 && (KNL_NOW(session) - begin_time) / (date_t)MICROSECS_PER_MILLISEC > (date_t)timeout) {
            GS_THROW_ERROR(ERR_LOCK_TIMEOUT);
            status = GS_ERROR;
            break;
        }

        if (tx_check_wait_valid(session) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        tx_get_snapshot(session, session->wxid.xmap, &snapshot);
        if (snapshot.xnum != session->wxid.xnum || snapshot.status == (uint8)XACT_END) {
            status = GS_SUCCESS;
            break;
        }
    }

    knl_end_session_wait(session);
    session->stat.con_wait_time += session->wait.usecs;
    tx_reset_deadlock_flag(session);
    session->wrmid = GS_INVALID_ID16;
    session->wxid.value = GS_INVALID_ID64;

    return status;
}

inline void tx_get_snapshot(knl_session_t *session, xmap_t xmap, txn_snapshot_t *snapshot)
{
    tx_item_t *tx_item = xmap_get_item(session, xmap);
    txn_t *txn = txn_addr(session, xmap);

    cm_spin_lock(&tx_item->lock, &session->stat_txn);
    snapshot->xnum = txn->xnum;
    snapshot->scn = txn->scn;
    snapshot->rmid = tx_item->rmid;
    snapshot->status = txn->status;
    snapshot->in_progress = tx_item->in_progress;
    cm_spin_unlock(&tx_item->lock);
}

void txn_get_owner(knl_session_t *session, xmap_t xmap, undo_page_id_t *page_id)
{
    undo_t *undo = &session->kernel->undo_ctx.undos[xmap.seg_id];
    *page_id = undo->segment->txn_page[xmap.slot / TXN_PER_PAGE];
}

void tx_rollback_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;

    cm_set_thread_name("rollback"); 
    GS_LOG_RUN_INF("rollback thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
        /*
         * make it works when it reach to WAIT_CLEAN,
         * because we will drop nologging tables during `db_drop_nologging_table',
         * if we want to lock a row which is locked by a running transaction,
         * we can wait tx_rollback_proc to undo it,
         * otherwise, deadlock maybe occurred, example(1->2->3->1):
         * 1. tx_rollback_proc wait db_open;
         * 2. db_open wait db_drop_nologging_table;
         * 3. db_clean_nologging_guts wait tx_rollback_proc to rollback a running transaction;
         */
        if (session->kernel->db.status >= DB_STATUS_WAIT_CLEAN) { 
            if (!DB_IS_READONLY(session) && !DB_IS_MAINTENANCE(session)) {
                break;
            }
        }
        cm_sleep(200);
    }

    if (!thread->closed) {
        tx_area_rollback(session, thread); 
    }

    GS_LOG_RUN_INF("rollback thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

status_t tx_rollback_start(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    uint32 i;

    for (i = 0; i < session->kernel->attr.tx_rollback_proc_num; i++) {
        if (cm_create_thread(tx_rollback_proc, 0, kernel->sessions[SESSION_ID_ROLLBACK + i],
                             &kernel->tran_ctx.rollback_proc[i]) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void tx_rollback_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    tx_area_t *ctx = &kernel->tran_ctx;

    for (uint32 i = 0; i < session->kernel->attr.tx_rollback_proc_num; i++) {
        cm_close_thread(&ctx->rollback_proc[i]);
    }
}

status_t txn_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    txn_page_t *page = (txn_page_t *)page_head;
    txn_t *txn = NULL;
    page_id_t first, last;

    /* page size if 8192, bigger than sizeof(page_head_t) + sizeof(page_tail_t) */
    uint32 count = (PAGE_SIZE(page->head) - sizeof(page_head_t) - sizeof(page_tail_t)) / sizeof(txn_t);
    cm_dump(dump, "txn page information\n");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 slot = 0; slot < count; slot++) {
        txn = &page->items[slot];

        first = PAGID_U2N(txn->undo_pages.first);
        last = PAGID_U2N(txn->undo_pages.last);

        cm_dump(dump, "\titems[%u] ", slot);
        cm_dump(dump, "\txnum: %-3u", txn->xnum);
        cm_dump(dump, "\tstatus: %s", txn_status((xact_status_t)txn->status));
        cm_dump(dump, "\tscn: %llu", txn->scn);
        cm_dump(dump, "\tundo_pages: count %u first %u-%u last %u-%u\n", txn->undo_pages.count,
                (uint32)first.file, (uint32)first.page, (uint32)last.file, (uint32)last.page);
        CM_DUMP_WRITE_FILE(dump);
    }

    return GS_SUCCESS;
}

void tx_record_sql(knl_session_t *session)
{
    text_t sql_text;

    sql_text.str = (char *)cm_push(session->stack, RECORD_SQL_SIZE);
    sql_text.len = RECORD_SQL_SIZE;
    if (sql_text.str == NULL || g_knl_callback.get_sql_text(session->id, &sql_text) != GS_SUCCESS) {
        cm_reset_error();
    } else {
        GS_LOG_RUN_ERR("sql detail: %s", T2S(&sql_text));
    }
    cm_pop(session->stack);
}
