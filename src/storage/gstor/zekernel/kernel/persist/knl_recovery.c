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
 * knl_recovery.c
 *    kernel recovery definitions
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/persist/knl_recovery.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_recovery.h"
#include "knl_log_mgr.h"
#include "cm_log.h"
#include "cm_checksum.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctlg.h"

void log_get_manager(log_manager_t **lmgr, uint32 *count)
{
    *lmgr = g_lmgrs;
    *count = LMGR_COUNT;
}

static bool32 abr_supported_redo_type(log_type_t type)
{
    switch (type) {
        /* following space redo do not modify page context */
        case RD_SPC_CREATE_SPACE:
        case RD_SPC_REMOVE_SPACE:
        case RD_SPC_EXTEND_DATAFILE:
        case RD_SPC_TRUNCATE_DATAFILE:
            return GS_FALSE;
        default:
            break;
    }

    if (type >= LOG_TYPE_LREP && type <= LOG_TYPE_LOGIC) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static bool32 rcy_is_skip(knl_session_t *session, log_type_t type)
{
    if ((session->kernel->rcy_ctx.abr_rcy_flag || session->kernel->rcy_ctx.is_file_repair) &&
        !abr_supported_redo_type(type)) {
        return GS_TRUE;
    }

    if (RD_TYPE_IS_ENTER_PAGE(type) || RD_TYPE_IS_LEAVE_PAGE(type) || session->page_stack.depth == 0) {
        return GS_FALSE;
    }

    if (DB_IS_OPEN(session) && (type == RD_TX_END || type == RD_XA_PHASE1)) {
        /*
         * gbp log analyze proc will replay txn redo, and maintain txn area, but it can not forward scn
         * only lrpl proc can forward scn, so we do not skip RD_TX_END and RD_XA_PHASE1 in rcy_is_skip
         * is_skip will been judged in rd_tx_end and rd_xa_phase1
         */
        return GS_FALSE;
    }

    return session->page_stack.is_skip[session->page_stack.depth - 1];
}

static inline bool32 rcy_pcn_verifiable(knl_session_t *session, log_entry_t *log)
{
    return (bool32)(DB_IS_RCY_CHECK_PCN(session)
                    && !RD_TYPE_IS_ENTER_PAGE(log->type)
                    && !RD_TYPE_IS_LEAVE_PAGE(log->type)
                    && log->type != RD_LOGIC_OPERATION
                    && session->page_stack.depth > 0
                    && session->curr_page_ctrl->page->pcn != 0
                    && !rd_log_is_format_page(log->type));
}

static void rcy_replay_pcn_verify(knl_session_t *session, log_entry_t *log, pcn_verify_t *log_pcns,
                                  uint32 log_pcns_size)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rd_enter_page_t *rd  = NULL;
    datafile_t *df = NULL;
    bool32 changed = GS_FALSE;

    if (RD_TYPE_IS_ENTER_PAGE(log->type)) {
        rd = (rd_enter_page_t *)log->data;
        df = DATAFILE_GET(rd->file);
        knl_panic_log(session->page_stack.depth < log_pcns_size, "the page_stack's depth is more than log_pcns_size, "
                      "panic info: log_pcns_size %u log_pcns_size %u", session->page_stack.depth, log_pcns_size);
        log_pcns[session->page_stack.depth].failed = GS_FALSE;
        if (SPACE_IS_NOLOGGING(SPACE_GET(df->space_id)) || (rd->options & ENTER_PAGE_NO_READ)) {
            log_pcns[session->page_stack.depth].skip = GS_TRUE;
            return;
        }
        log_pcns[session->page_stack.depth].pcn = rd->pcn;
        log_pcns[session->page_stack.depth].skip = GS_FALSE;
        return;
    }

    if (RD_TYPE_IS_LEAVE_PAGE(log->type)) {
        if (!log_pcns[session->page_stack.depth - 1].failed) {
            return;
        }
        
        changed = *(bool32 *)log->data;
        if (changed) {
            knl_panic_log(GS_FALSE, "log entry pcn %u not equal page pcn %u.page_id: %u-%u, lsn: %llu, curr_file: %s",
                          log_pcns[session->page_stack.depth - 1].pcn, session->curr_page_ctrl->page->pcn,
                          session->curr_page_ctrl->page_id.file, session->curr_page_ctrl->page_id.page,
                          session->curr_lsn, ctx->files[ctx->curr_file].ctrl->name);
        }
        log_pcns[session->page_stack.depth - 1].failed = GS_FALSE;
        return;
    }

    if (rcy_pcn_verifiable(session, log)) {
        if (log_pcns[session->page_stack.depth - 1].skip) {
            return;
        }
        // RD_TX_END and RD_XA_PHASE1 will not set to skip in rcy_is_skip when lrpl perform
        if (DB_IS_OPEN(session) && (log->type == RD_TX_END || log->type == RD_XA_PHASE1) &&
            session->page_stack.is_skip[session->page_stack.depth - 1]) {
            return;
        }

        if (log_pcns[session->page_stack.depth - 1].pcn != session->curr_page_ctrl->page->pcn) {
            log_pcns[session->page_stack.depth - 1].failed = GS_TRUE;
        }
    }
}

void rcy_flexible_sleep(knl_session_t *session, rcy_context_t *rcy, rcy_bucket_t *bucket)
{
    if (!DB_IS_OPEN(session) || rcy->last_lrpl_time == 0) {
        cm_spin_sleep(); // when db is in recover, just sleep 100ns
        return;
    }
    if (g_timer()->now - rcy->last_lrpl_time > RCY_SLEEP_TIME_THRESHOLD) {
        cm_sleep(100);
        return;
    }

    if (bucket != NULL && (g_timer()->now - bucket->last_replay_time > RCY_SLEEP_TIME_THRESHOLD)) {
        cm_sleep(100);
        return;
    }

    if (rcy->replay_no_lag) {
        cm_sleep(1);
    } else {
        cm_spin_sleep();
    }
}

static inline void rcy_replay_entry(knl_session_t *session, log_entry_t *log, pcn_verify_t *log_pcns,
                                    uint32 log_pcns_size)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    if (!rcy_is_skip(session, log->type)) {
        rcy_replay_pcn_verify(session, log, log_pcns, log_pcns_size);
        if (!ctx->check_punch_proc[log->type](session, log)) {
            ctx->replay_procs[log->type](session, log);
        }
    }
}

static void rcy_analysis_entry(knl_session_t *session, log_entry_t *log)
{
    log_context_t *ctx = &session->kernel->redo_ctx;

    knl_panic_log(ctx->analysis_procs[log->type] != NULL, "current analysis_procs is NULL.");
    /* always analysis it if this log is gbp_unsafe or gbp_safe */
    if (ctx->analysis_procs[log->type] == gbp_aly_unsafe_entry ||
        ctx->analysis_procs[log->type] == gbp_aly_safe_entry) {
        ctx->analysis_procs[log->type](session, log, session->curr_lsn);
    } else {
        /* because we may replay log during log analysis, so we must follow `skip' logical */
        if (!rcy_is_skip(session, log->type)) {
            ctx->analysis_procs[log->type](session, log, session->curr_lsn);
        }
    }
}

void rcy_wait_preload_complete(knl_session_t *session)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;

    if (!rcy->paral_rcy) {
        return;
    }
    for (uint32 i = 0; i < rcy->preload_proc_num; i++) {
        while (rcy->preload_info[i].curr < (uint32)rcy->preload_hwm) {
            cm_spin_sleep();
        }
    }
}

void rcy_wait_replay_complete(knl_session_t *session)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    errno_t ret;

    if (!rcy->paral_rcy) {
        return;
    }

    rcy_wait_preload_complete(session);
    ret = memset_sp(rcy->page_bitmap, sizeof(uint16) * GS_RCY_MAX_PAGE_BITMAP_LEN, 0,
                    sizeof(uint16) * GS_RCY_MAX_PAGE_BITMAP_LEN);
    knl_securec_check(ret);
    for (uint32 i = 0; i < rcy->capacity; i++) {
        while (rcy->bucket[i].head != rcy->bucket[i].tail) {
            cm_spin_sleep();
        }
    }
    rcy->wait_stats_view[WAIT_RELAPY_COUNT]++;

    rcy->page_list_count = 0;
    rcy->tx_end_count = 0;
    rcy->current_tid = 0;
    rcy->preload_hwm = 0;
    for (uint32 i = 0; i < rcy->preload_proc_num; i++) {
        rcy->preload_info[i].group_id = 0;
        rcy->preload_info[i].curr = i;
    }
    gbp_unsafe_redo_check(session);
}

static void rcy_wait_cond(knl_session_t *session, rcy_bucket_t *bucket, uint32 index, volatile uint32 *curr,
    uint32 target, uint32 *wait_count)
{
    uint32 sleep_times = 0;

    if (bucket != NULL) {
        bucket->waiting_index = index;
        while (*curr + 1 < target) {
            cm_timedwait_eventfd(&bucket->eventfd, 1);
        }
        bucket->waiting_index = GS_INVALID_ID32;
    }

    for (;;) {
        if (*curr == target) {
            break;
        }

        sleep_times++;
        if (SECUREC_UNLIKELY(sleep_times == session->kernel->attr.rcy_sleep_interval)) {
            (*wait_count)++;
            cm_spin_sleep();
            sleep_times = 0;
            continue;
        }
#ifndef WIN32
        for (uint32 i = 0; i < sleep_times; i++) {
            fas_cpu_pause();
        }
#endif
    }
}

static void rcy_wakeup_next(rcy_context_t *rcy, uint8 next_bucket_id, uint32 waiting_index)
{
    if (next_bucket_id == GS_INVALID_ID8) {
        return;
    }

    if (rcy->bucket[next_bucket_id].waiting_index == waiting_index) {
        cm_wakeup_eventfd(&rcy->bucket[next_bucket_id].eventfd);
    }
}

static status_t rcy_paral_replay_entry(knl_session_t *session, rcy_bucket_t *bucket, log_entry_t *log,
                                       rcy_paral_group_t *paral_group, pcn_verify_list_t pcn_list)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    pcn_verify_t *log_pcns = pcn_list.list;
    uint32 log_pcns_size = pcn_list.count;
    uint32 wait_count = 0;

    if (RD_TYPE_IS_ENTER_PAGE(log->type)) {
        rd_enter_page_t *redo = (rd_enter_page_t *)log->data;
        uint32 index = paral_group->items[paral_group->curr_enter_id].page_index;
        rcy_page_t *page = &rcy->page_list[index];
        knl_panic_log(redo->file == page->file && redo->page == page->page, "the redo is not match to page, "
                      "panic info: page %u-%u redo %u-%u", page->page, page->file, redo->file, redo->page);
        uint32 group_slot = paral_group->items[paral_group->curr_enter_id].slot;
        uint8 next_bucket_id = paral_group->items[paral_group->curr_enter_id].next_bucket_id;

        rcy_wait_cond(session, bucket, index, &page->current_group, group_slot, &wait_count);
        rcy_replay_entry(session, log, log_pcns, log_pcns_size);

        page_head_t *page_head = (page_head_t *)CURR_PAGE;
        if (SECUREC_LIKELY(page_head != NULL)) {
            rcy->wait_stats_view[page_head->type] += wait_count;
        }
        paral_group->curr_enter_id++;
        rcy_wakeup_next(rcy, next_bucket_id, index);
        return GS_SUCCESS;
    }

    if (log->type == RD_TX_END || log->type == RD_XA_PHASE1) {
        rcy_wait_cond(session, bucket, paral_group->tx_id, &rcy->current_tid, paral_group->tx_id, &wait_count);
        rcy_replay_entry(session, log, log_pcns, log_pcns_size);
        rcy->wait_stats_view[TXN_END_WAIT_COUNT] += wait_count;
        rcy->current_tid++;
        rcy_wakeup_next(rcy, paral_group->tx_next_bid, paral_group->tx_id + 1);
        return GS_SUCCESS;
    }

    rcy_replay_entry(session, log, log_pcns, log_pcns_size);
    return GS_SUCCESS;
}

static void rcy_replay_group_end(knl_session_t *session)
{
    if (session->dirty_count > 0) {
        ckpt_enque_page(session);
    }

    if (SECUREC_UNLIKELY(session->gbp_dirty_count > 0)) {
        gbp_enque_pages(session);
    }

    if (session->changed_count > 0) {
        log_set_page_lsn(session, session->curr_lsn, session->curr_lfn);
    }
}

static status_t rcy_paral_replay_group(knl_session_t *session, rcy_bucket_t *bucket, log_context_t *ctx,
                                       rcy_paral_group_t *paral_group)
{
    uint32 offset;
    log_entry_t *log = NULL;
    log_group_t *group = paral_group->group;
    pcn_verify_t log_pcns[KNL_MAX_PAGE_STACK_DEPTH] = {0};
    pcn_verify_list_t pcn_list;

    pcn_list.list = log_pcns;
    pcn_list.count = KNL_MAX_PAGE_STACK_DEPTH;

    session->curr_lsn = group->lsn;
    offset = sizeof(log_group_t);

    while (offset < group->size) {
        log = (log_entry_t *)((char *)group + offset);
        if (rcy_paral_replay_entry(session, bucket, log, paral_group, pcn_list) != GS_SUCCESS) {
            return GS_ERROR;
        }
        offset += log->size;
    }

    rcy_replay_group_end(session);
    return GS_SUCCESS;
}

static void rcy_replay_group(knl_session_t *session, log_context_t *ctx, log_group_t *group)
{
    uint32 offset;
    log_entry_t *log = NULL;
    knl_session_t *se  = session->kernel->sessions[SESSION_ID_KERNEL];
    pcn_verify_t log_pcns[KNL_MAX_PAGE_STACK_DEPTH] = { 0 };

    se->curr_lsn = group->lsn;
    offset = sizeof(log_group_t);

    while (offset < group->size) {
        log = (log_entry_t *)((char *)group + offset);
        rcy_replay_entry(se, log, log_pcns, KNL_MAX_PAGE_STACK_DEPTH);
        offset += log->size;
    }
    rcy_replay_group_end(se);
}

/* when GBP enabled, analyze standby redo log group, set page latest lsn to gbp aly item */
static void rcy_analysis_group(knl_session_t *session, log_context_t *ctx, log_group_t *group)
{
    uint32 offset;
    log_entry_t *log = NULL;
    knl_session_t *se = session->kernel->sessions[SESSION_ID_KERNEL];

    if (SESSION_IS_LOG_ANALYZE(session)) {
        se = session; // use aly session for log analysis
    }

    ctx->gbp_aly_lsn = group->lsn;
    se->curr_lsn = group->lsn;
    offset = sizeof(log_group_t);

    while (offset < group->size) {
        log = (log_entry_t *)((char *)group + offset);
        rcy_analysis_entry(se, log);
        offset += log->size;
    }
    rcy_replay_group_end(se);
}

bool32 rcy_page_already_added(rcy_paral_group_t *paral_group, uint32 page_index, uint32* inpage_slot)
{
    for (uint32 i = 0; i < paral_group->enter_count; i++) {
        if (page_index == paral_group->items[i].page_index) {
            *inpage_slot = paral_group->items[i].slot;
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

bool32 rcy_get_page_index(rcy_context_t *rcy_ctx, uint32 page, uint32 file, uint32 *index)
{
    uint32 page_index;
    rcy_page_t *page_info = NULL;
    uint32 bucket_id = (file + HASH_SEED * page) * HASH_SEED % GS_RCY_MAX_PAGE_COUNT;
    rcy_page_bucket_t *bucket = &rcy_ctx->page_bucket[bucket_id];
    uint16 *bitmap = &rcy_ctx->page_bitmap[bucket_id / UINT16_BITS];
    uint16 map_idx = bucket_id % UINT16_BITS;

    if (!btree_get_bitmap(bitmap, map_idx)) {
        bucket->first = 0;
        bucket->count = 0;
        btree_set_bitmap(bitmap, map_idx);
    }

    page_index = bucket->first;
    for (uint32 i = 0; i < bucket->count; i++) {
        page_info = &rcy_ctx->page_list[page_index];
        if (page_info->file == file && page_info->page == page) {
            *index = page_index;
            return GS_TRUE;
        }
        page_index = page_info->hash_next;
    }

    *index = rcy_ctx->page_list_count;
    page_info = &rcy_ctx->page_list[*index];
    page_info->hash_next = bucket->first;
    bucket->count++;
    bucket->first = *index;
    rcy_ctx->page_list_count++;
    return GS_FALSE;
}

void rcy_add_page(rcy_page_t *pages, rcy_paral_group_t *paral_group, rd_enter_page_t *rd, rcy_context_t *rcy)
{
    bool32 is_exist;
    uint32 index = 0;
    uint32 group_count = 0;
    uint32 page = rd->page;
    uint32 file = rd->file;
    uint32 slot = 0;

    is_exist = rcy_get_page_index(rcy, page, file, &index);
    if (is_exist) {
        group_count = pages[index].group_count;
        if (!rcy_page_already_added(paral_group, index, &slot)) {
            pages[index].group_count++;
            slot = group_count;
        }
        // let previous RD_ENTER_PAGE entry know the bucket id which replay next RD_ENTER_PAGE entry
        pages[index].prev_enter->next_bucket_id = (uint8)(paral_group->group->rmid % rcy->capacity);
        // reset prev_enter to current RD_ENTER_PAGE entry
        pages[index].prev_enter = &paral_group->items[paral_group->enter_count];

        paral_group->items[paral_group->enter_count].page_index = index;
        paral_group->items[paral_group->enter_count].slot = slot;
        paral_group->items[paral_group->enter_count].next_bucket_id = GS_INVALID_ID8;
        paral_group->enter_count++;
    } else {
        pages[index].page = page;
        pages[index].file = file;
        pages[index].group_count = 1;
        pages[index].current_group = 0;
        pages[index].option = rd->options;
        pages[index].gid = paral_group->id;
        pages[index].prev_enter = &paral_group->items[paral_group->enter_count];

        paral_group->items[paral_group->enter_count].page_index = index;
        paral_group->items[paral_group->enter_count].slot = 0;
        paral_group->items[paral_group->enter_count].next_bucket_id = GS_INVALID_ID8;
        paral_group->enter_count++;
    }
}

static bool32 rcy_contain_spc_log(uint8 type)
{
    switch (type) {
        case RD_SPC_CREATE_SPACE:
        case RD_SPC_REMOVE_SPACE:
        case RD_SPC_CREATE_DATAFILE:
        case RD_SPC_REMOVE_DATAFILE:
        case RD_SPC_EXTEND_DATAFILE:
        case RD_SPC_TRUNCATE_DATAFILE:
        case RD_SPC_EXTEND_UNDO_SEGMENTS:
            return GS_TRUE;
        default:
            return GS_FALSE;
    }
}

static void rcy_add_pages(rcy_paral_group_t *paral_group, log_group_t *group, uint32 group_slot,
                          rcy_context_t *rcy, bool32 *logic, rcy_paral_group_t **next_group)
{
    rcy_page_t *pages = rcy->page_list;
    uint32 offset = sizeof(log_group_t);
    log_entry_t *log = NULL;
    rd_enter_page_t *rd = NULL;
    uint32 page_count = 0;

    paral_group->group = group;
    paral_group->curr_enter_id = 0;
    paral_group->enter_count = 0;
    paral_group->tx_id = 0;
    paral_group->id = group_slot;
    *logic = GS_FALSE;

    while (offset < group->size) {
        log = (log_entry_t *)((char *)group + offset);
        if (RD_TYPE_IS_ENTER_PAGE(log->type)) {
            rd = (rd_enter_page_t *)log->data;
            rcy_add_page(pages, paral_group, rd, rcy);
            page_count++;
        }
        if (log->type == RD_TX_END || log->type == RD_XA_PHASE1) {
            paral_group->tx_id = rcy->tx_end_count;
            paral_group->tx_next_bid = GS_INVALID_ID8;
            rcy->tx_end_count++;

            if (paral_group->tx_id > 0) {
                // let previous tx group know the bucket id which replay next tx group
                rcy->prev_tx_group->tx_next_bid = (uint8)(paral_group->group->rmid % rcy->capacity);
            }
            rcy->prev_tx_group = paral_group; // reset prev_tx_group to current tx group
        }
        if (log->type == RD_LOGIC_OPERATION || rcy_contain_spc_log(log->type)) {
            *logic = GS_TRUE;
        }
        offset += log->size;
    }

    knl_panic_log(page_count == paral_group->enter_count, "the page_count is not equal to paral_group's enter_count, "
                  "panic info: page_count %u enter_count %u.", page_count, paral_group->enter_count);
    *next_group = (rcy_paral_group_t *)(&paral_group->items[page_count]);
}

static void rcy_add_replay_bucket(rcy_paral_group_t *paral_group, rcy_context_t *rcy)
{
    rcy_bucket_t *bucket = NULL;
    uint32 id;
    uint32 ctrl_id;

    id = paral_group->group->rmid % rcy->capacity;
    bucket = &rcy->bucket[id];

    ctrl_id = (bucket->tail + 1) % bucket->count;

    for (;;) {
        if (SECUREC_UNLIKELY(ctrl_id == bucket->head)) {
            rcy->wait_stats_view[BUCKET_OVERFLOW_COUNT]++;
            cm_spin_sleep();
        } else {
            break;
        }
    }

    cm_spin_lock(&bucket->lock, NULL);
    bucket->first[bucket->tail] = paral_group;
    bucket->tail = ctrl_id;
    cm_spin_unlock(&bucket->lock);
}

void rcy_release_lock_pages(knl_session_t *session, rcy_paral_group_t *paral_group)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    rcy_page_t *page = NULL;
    uint32 i = 0;
    uint32 index = 0;

    for (i = 0; i < paral_group->enter_count; i++) {
        index = paral_group->items[i].page_index;
        page = &rcy->page_list[index];
        knl_panic_log(page->group_count >= page->current_group, "the page's group_count is smaller than current_group,"
                      " panic info: page %u-%u group_count %u current_group %u",
                      page->page, page->file, page->group_count, page->current_group);
        if (page->current_group > paral_group->items[i].slot) {
            continue;
        }
        knl_panic_log(page->current_group == paral_group->items[i].slot,
            "page's current_group is not equal to paral_group's slot, panic info: page %u-%u current_group %u slot %u",
            page->page, page->file, page->current_group, paral_group->items[i].slot);
        page->current_group++;
    }
    paral_group->enter_count = 0;
}

static void rcy_replay_logic_group(knl_session_t *session, rcy_paral_group_t *paral_group)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rcy_context_t *rcy = &kernel->rcy_ctx;

    for (uint32 j = 0; j < rcy->capacity; j++) {
        while (rcy->bucket[j].head != rcy->bucket[j].tail) {
            cm_spin_sleep();
        }
    }

    if (rcy_paral_replay_group(session, NULL, ctx, paral_group) == GS_SUCCESS) {
        rcy_release_lock_pages(session, paral_group);
    }
}

static void rcy_paral_replay_batch(knl_session_t *session, log_cursor_t *cursor, log_batch_t *batch)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    log_group_t *group = NULL;
    bool32 logic = GS_FALSE;
    rcy_paral_group_t *next_paral_group = NULL;
    uint32 group_slot = rcy->curr_group_id;
    knl_session_t *redo_ssesion = session->kernel->sessions[SESSION_ID_KERNEL];

    for (;;) {
        group = log_fetch_group(ctx, cursor);
        if (SECUREC_UNLIKELY(group == NULL)) {
            break;
        }
        // record curr replay lsn in redo_ssesion when paral recovery, it will be used in gbp_page_verify
        // because redo_curr_lsn must >= page lsn during lrpl, if gbp_page_lsn > redo_curr_lsn, means gbp page can used
        redo_ssesion->curr_lsn = group->lsn;
        rcy_add_pages(rcy->curr_group, group, group_slot, rcy, &logic, &next_paral_group);
        group_slot++;
        rcy->curr_group_id = group_slot;
        cm_atomic_set(&rcy->preload_hwm, (int64)rcy->page_list_count);
        if (logic) {
            // redo log has logic log, must replay by order
            rcy->wait_stats_view[LOGIC_GROUP_COUNT]++;
            rcy_replay_logic_group(session, rcy->curr_group);
        } else {
            rcy_add_replay_bucket(rcy->curr_group, rcy);
        }
        DB_SET_LSN(kernel->db.ctrl.core.lsn, group->lsn);
        rcy->curr_group = next_paral_group;
    }

    DB_SET_LFN(&ctx->lfn, batch->head.point.lfn);
    return;
}

void rcy_init_log_cursor(log_cursor_t *cursor, log_batch_t *batch)
{
    char *ptr = (char *)batch + sizeof(log_batch_t);
    cursor->part_count = batch->part_count;
    knl_panic_log(batch->part_count > 0, "the batch's part_count is abnormal, panic info: part_count %u",
                  batch->part_count);
    knl_panic_log(batch->part_count <= GS_MAX_LOG_BUFFERS,
                  "the batch's part_count is more than max limit, panic info: part_count %u", batch->part_count);

    for (uint32 i = 0; i < batch->part_count; i++) {
        cursor->parts[i] = (log_part_t *)ptr;
        cursor->offsets[i] = sizeof(log_part_t);
        ptr = (ptr + cursor->parts[i]->size) + sizeof(log_part_t);
    }
}

void rcy_replay_batch(knl_session_t *session, log_batch_t *batch)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    log_cursor_t cursor;

    rcy_init_log_cursor(&cursor, batch);
    if (rcy->paral_rcy) {
        rcy_paral_replay_batch(session, &cursor, batch);
    } else {
        log_group_t *group = log_fetch_group(ctx, &cursor);
        while (group != NULL) {
            rcy_replay_group(session, ctx, group);
            DB_SET_LSN(kernel->db.ctrl.core.lsn, group->lsn);
            group = log_fetch_group(ctx, &cursor);
        }
        DB_SET_LFN(&ctx->lfn, batch->head.point.lfn);
        gbp_unsafe_redo_check(session);
    }
}

/* when GBP enabled, analyze standby redo log batch */
void rcy_analysis_batch(knl_session_t *session, log_batch_t *batch)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    gbp_aly_ctx_t *aly = &kernel->gbp_aly_ctx;
    log_cursor_t cursor;

    rcy_init_log_cursor(&cursor, batch);

    /* need set analysis lfn before analysis groups */
    DB_SET_LFN(&ctx->analysis_lfn, batch->head.point.lfn);

    log_group_t *group = log_fetch_group(ctx, &cursor);
    while (group != NULL) {
        rcy_analysis_group(session, ctx, group);

        if (aly->is_closing) {
            return;
        }
        group = log_fetch_group(ctx, &cursor);
    }
}

uint64 rcy_fetch_batch_lsn(knl_session_t *session, log_batch_t *batch)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    log_cursor_t cursor;

    rcy_init_log_cursor(&cursor, batch);

    log_group_t *group = log_fetch_group(ctx, &cursor);

    knl_panic_log(group != NULL, "the group is NULL.");
    return group->lsn;
}

bool32 rcy_validate_batch(log_batch_t *batch, log_batch_tail_t *tail)
{
    if (batch->head.magic_num == LOG_MAGIC_NUMBER && tail->magic_num == LOG_MAGIC_NUMBER
        && batch->head.point.lfn == tail->point.lfn && batch->size != 0
        && batch->raft_index != GS_INVALID_ID64) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

static inline void rcy_next_file(knl_session_t *session, log_point_t *point, bool32 *need_more_log)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    reset_log_t *reset_log = &session->kernel->db.ctrl.core.resetlogs;
    database_t *db = &session->kernel->db;
    lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;

    if (!lrcv->wait_info.waiting && LOG_POINT_FILE_EQUAL(*point, ctx->files[ctx->curr_file].head)) {
        *need_more_log = (db->status != DB_STATUS_RECOVERY) && db->status != DB_STATUS_REDO_ANALYSIS;
    } else if (point->rst_id < reset_log->rst_id &&
               point->asn == reset_log->last_asn &&
               (uint64)point->lfn == reset_log->last_lfn) {
        point->rst_id++;
        point->asn++;
        point->block_id = 0;
        *need_more_log = GS_TRUE;
    } else if (!SESSION_IS_LOG_ANALYZE(session) && session->kernel->rcy_ctx.loading_curr_file) {
        *need_more_log = GS_TRUE;
    } else if (SESSION_IS_LOG_ANALYZE(session) && session->kernel->gbp_aly_ctx.loading_curr_file) {
        *need_more_log = GS_TRUE;
    } else {
        point->asn++;
        point->block_id = 0;
        *need_more_log = GS_TRUE;
        GS_LOG_RUN_INF("[RCY] Move log point to [%u-%u/%u/%llu]",
                       (uint32)point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
    }
}

static bool32 rcy_prepare_standby_batch(knl_session_t *session, log_point_t *point, log_batch_t *batch,
                                        bool32 *need_more_log)
{
    uint32 file_id;
    log_file_t *file = NULL;
    database_t *db = &session->kernel->db;
    reset_log_t *rst_log = &db->ctrl.core.resetlogs;

    if (point->rst_id >= rst_log->rst_id || batch->head.point.lfn <= rst_log->last_lfn) {
        return GS_TRUE;
    }

    /*
     * point->rst_id < rst_log->rst_id && batch->head.point.lfn > rst_log->last_lfn
     * We should reset file write_pos and update next batch point.
     */
    GS_LOG_RUN_INF("[RCY] find useless batch at point [%u-%u/%u/%llu] in %s recovery, rstlog [%u-%u/%llu]",
                   point->rst_id, point->asn, point->block_id, (uint64)point->lfn,
                   (db->status == DB_STATUS_RECOVERY) ? "rcy" : "lrpl",
                   rst_log->rst_id, rst_log->last_asn, rst_log->last_lfn);

    /* maxrst_id <= 2^18, cannot oveflow */
    file_id = log_get_id_by_asn(session, (uint32)point->rst_id, point->asn, NULL);
    if (file_id != GS_INVALID_ID32) {
        file = session->kernel->redo_ctx.files + file_id;
        file->head.write_pos = (uint64)point->block_id * file->ctrl->block_size;
        log_flush_head(session, file);
        log_unlatch_file(session, file_id);
    }

    rcy_next_file(session, point, need_more_log);

    return GS_FALSE;
}

static bool32 rcy_prepare_batch(knl_session_t *session, log_point_t *point, log_batch_t *batch,
                                bool32 *need_more_log, bool32 is_analysis)
{
    database_t *db = &session->kernel->db;
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_point_t max_lrp_point;
    uint64 valid_lfn;

    if (!DB_IS_PRIMARY(db) && db->status == DB_STATUS_RECOVERY && !DB_IS_RAFT_ENABLED(session->kernel)) {
        max_lrp_point = db->ctrl.core.lrp_point;
        if (KNL_GBP_SAFE(session->kernel) && log_cmp_point(&max_lrp_point, &ctx->gbp_lrp_point) < 0) {
            max_lrp_point = ctx->gbp_lrp_point;
        }

        /* if use gbp, it should at least recover to max{local_lrp_point, gbp_lrp_point} */
        if (log_cmp_point(&max_lrp_point, point) == 0) {
            *need_more_log = GS_FALSE;
            GS_LOG_RUN_INF("standby recover no need more log.core_lrp_point[%u-%u-%u-%llu],gbp_lrp_point[%u-%u-%u-%llu]",
                           db->ctrl.core.lrp_point.rst_id, db->ctrl.core.lrp_point.asn, db->ctrl.core.lrp_point.block_id,
                           (uint64)db->ctrl.core.lrp_point.lfn, ctx->gbp_lrp_point.rst_id, ctx->gbp_lrp_point.asn,
                           ctx->gbp_lrp_point.block_id, (uint64)ctx->gbp_lrp_point.lfn);
            return GS_FALSE;
        } else {
            if (batch->head.magic_num != LOG_MAGIC_NUMBER || !LFN_IS_CONTINUOUS(batch->head.point.lfn, ctx->lfn)) {
                rcy_next_file(session, point, need_more_log);
                return GS_FALSE;
            }
            return rcy_prepare_standby_batch(session, point, batch, need_more_log);
        }
    }

    valid_lfn = is_analysis ? ctx->analysis_lfn : ctx->lfn;
    if (batch->head.magic_num != LOG_MAGIC_NUMBER || !LFN_IS_CONTINUOUS(batch->head.point.lfn, valid_lfn)) {
        rcy_next_file(session, point, need_more_log);
        return GS_FALSE;
    }

    if (DB_IS_PRIMARY(db)) {
        return GS_TRUE;
    }

    return rcy_prepare_standby_batch(session, point, batch, need_more_log);
}

status_t rcy_verify_checksum(knl_session_t *session, log_batch_t *batch)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    uint16 org_cks;
    uint32 new_cks;
    uint64 raft_index = 0;

    if (DB_IS_CHECKSUM_OFF(session) || batch->checksum == GS_INVALID_CHECKSUM) {
        return GS_SUCCESS;
    }

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        raft_index = batch->raft_index;
        batch->raft_index = GS_INVALID_ID64;
    }

    org_cks = batch->checksum;
    batch->checksum = GS_INVALID_CHECKSUM;
    new_cks = cm_get_checksum(batch, batch->size);
    batch->checksum = org_cks;
    if (org_cks != REDUCE_CKS2UINT16(new_cks)) {
        GS_LOG_RUN_ERR("invalid batch checksum.asn %u block_id %u lfn %llu rst_id %llu "
                       "size %u org_cks %u new_cks %u checksum level %s",
                       batch->head.point.asn, batch->head.point.block_id, (uint64)batch->head.point.lfn,
                       (uint64)batch->head.point.rst_id, batch->size, org_cks, REDUCE_CKS2UINT16(new_cks),
                       knl_checksum_level(cks_level));
        GS_THROW_ERROR(ERR_CHECKSUM_FAILED, "");
        return GS_ERROR;
    }
    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        batch->raft_index = raft_index;
    }

    return GS_SUCCESS;
}

/* GBP failover triggered, need skip remain redo log batchs */
static inline bool32 rcy_gbp_triggered(knl_session_t *session, bool32 *need_more_log)
{
    gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;

    if (!KNL_RECOVERY_WITH_GBP(session->kernel) && knl_failover_triggered(session->kernel) &&
        aly_ctx->is_done && !aly_ctx->has_return_replay) {
        aly_ctx->has_return_replay = GS_TRUE;
        *need_more_log = GS_TRUE;
        return GS_TRUE;
    }
    return GS_FALSE;
}

static bool32 rcy_pitr_replay_end(rcy_context_t *rcy, log_batch_t *batch, log_point_t *point, bool32 *need_more_log)
{
    if (batch->scn <= rcy->max_scn) {
        return GS_FALSE;
    }

    GS_LOG_RUN_INF("[RCY] pitr replay end at point [%u-%u/%u/%llu]",
                   (uint32)point->rst_id, point->asn, point->block_id, (uint64)point->lfn);
    if (point->block_id > 1) {
        point->asn = point->asn + 1; // if block_id > 1, it means the half of current file has been replayed
    }
    *need_more_log = GS_FALSE;
    return GS_TRUE;
}

static status_t rcy_try_decrypt(knl_session_t *session, log_batch_t *batch, bool32 is_analysis)
{
    if (!batch->encrypted) {
        return GS_SUCCESS;
    }

    if (!is_analysis) {
        log_context_t *ctx = &session->kernel->redo_ctx;
        return log_decrypt(session, batch, ctx->logwr_cipher_buf, ctx->logwr_cipher_buf_size);
    } else {
        gbp_aly_ctx_t *aly_ctx = &session->kernel->gbp_aly_ctx;
        return log_decrypt(session, batch, aly_ctx->log_decrypt_buf.aligned_buf, (uint32)aly_ctx->log_decrypt_buf.buf_size);
    }
}

void rcy_set_points(knl_session_t *session, log_point_t *point, bool32 is_analysis, bool32 paral_rcy)
{
    if (!is_analysis) {
        if (!paral_rcy) {
            ckpt_set_trunc_point(session, point);
            gbp_queue_set_trunc_point(session, point);
        }
        log_reset_point(session, point);
    } else {
        log_reset_analysis_point(session, point);
    }
}

status_t rcy_replay(knl_session_t *session, log_point_t *point, uint32 data_size, log_batch_t *batch,
    uint32 block_size, bool32 *need_more_log, bool32 *replay_fail, bool32 is_analysis)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    bool32 first_batch = GS_TRUE;
    bool32 thread_closing = GS_FALSE;

    CM_SET_VALUE_IF_NOTNULL(replay_fail, GS_FALSE);

    if (data_size == 0) {
        rcy_next_file(session, point, need_more_log);
        return GS_SUCCESS;
    }

    while (data_size >= sizeof(log_batch_t)) {
        if (!rcy_prepare_batch(session, point, batch, need_more_log, is_analysis)) {
            CM_SET_VALUE_IF_NOTNULL(replay_fail, GS_TRUE);
            return GS_SUCCESS;
        }

        if (data_size < batch->space_size) {
            if (first_batch) {
                *need_more_log = GS_FALSE;
                CM_SET_VALUE_IF_NOTNULL(replay_fail, GS_TRUE);
                GS_LOG_RUN_ERR("recovery failed, invalid batch(%u,%u).", point->asn, point->block_id);
                return GS_SUCCESS;
            }
            *need_more_log = GS_TRUE;
            return GS_SUCCESS;
        }

        if (rcy_gbp_triggered(session, need_more_log)) {
            return GS_SUCCESS;
        }

        if (!LFN_IS_CONTINUOUS(batch->head.point.lfn, point->lfn)) {
            *need_more_log = GS_FALSE;
            CM_SET_VALUE_IF_NOTNULL(replay_fail, GS_TRUE);
            GS_LOG_RUN_ERR("recovery failed, invalid batch lfn(%llu:%llu).", (uint64)batch->head.point.lfn,
                           (uint64)point->lfn);
            return GS_SUCCESS;
        }

        if (rcy_pitr_replay_end(rcy, batch, point, need_more_log)) {
            return GS_SUCCESS;
        }

        if (db_terminate_lfn_reached(session, point->lfn)) {
            *need_more_log = GS_FALSE;
            GS_LOG_RUN_INF("[UPGRADE] recovery finished while lfn reach %llu", (uint64)point->lfn);
            return GS_SUCCESS;
        }

        if (!rcy_validate_batch(batch, tail)) {
            *need_more_log = GS_FALSE;
            CM_SET_VALUE_IF_NOTNULL(replay_fail, GS_TRUE);
            GS_LOG_RUN_ERR("recovery failed, invalid batch[%u-%u/%u] size %u head [%llu/%llu/%llu] tail [%llu/%llu]",
                           point->rst_id, point->asn, point->block_id, batch->size, batch->head.magic_num,
                           (uint64)batch->head.point.lfn, batch->raft_index, tail->magic_num, (uint64)tail->point.lfn);
            return GS_SUCCESS;
        }
        first_batch = GS_FALSE;
        if (rcy_verify_checksum(session, batch) != GS_SUCCESS) {
            *need_more_log = GS_FALSE;
            CM_SET_VALUE_IF_NOTNULL(replay_fail, GS_TRUE);
            GS_LOG_RUN_ERR("[RCY] recovery failed");
            return GS_SUCCESS;
        }
        if (rcy_try_decrypt(session, batch, is_analysis) != GS_SUCCESS) {
            *need_more_log = GS_FALSE;
            rcy->log_decrypt_failed = GS_TRUE;
            CM_SET_VALUE_IF_NOTNULL(replay_fail, GS_TRUE);
            GS_LOG_RUN_ERR("[RCY] recovery failed");
            return GS_SUCCESS;
        }

        point->lfn = batch->head.point.lfn;
        point->block_id += batch->space_size / block_size;
        rcy->cur_pos += batch->space_size;
        session->kernel->redo_ctx.curr_scn = batch->scn;
        if (!DB_IS_PRIMARY(&session->kernel->db)) {
            if (!is_analysis) {
                log_reset_point(session, point);
            } else {
                log_reset_analysis_point(session, point);
            }
        }

        if (!is_analysis) {
            rcy_replay_batch(session, batch);
            thread_closing = session->kernel->lrpl_ctx.is_closing;
        } else {
            rcy_analysis_batch(session, batch);
            thread_closing = session->kernel->gbp_aly_ctx.is_closing;
        }

        if (thread_closing) {
            rcy_wait_replay_complete(session);
            ckpt_set_trunc_point(session, point);
            gbp_queue_set_trunc_point(session, point);
            return GS_SUCCESS;
        }
        data_size -= batch->space_size;
        GS_LOG_DEBUG_INF("[RCY] Replay log to [%u-%u/%u/%llu], scn %llu", (uint32)point->rst_id, point->asn,
                         point->block_id, (uint64)point->lfn, session->kernel->redo_ctx.curr_scn);

        rcy_set_points(session, point, is_analysis, rcy->paral_rcy);
        session->kernel->redo_ctx.curr_replay_point = *point;

        batch = (log_batch_t *)((char *)batch + batch->space_size);
        tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    }

    *need_more_log = GS_TRUE;
    return GS_SUCCESS;
}

status_t rcy_analysis(knl_session_t *session, log_point_t *point, uint32 data_size, log_batch_t *batch,
                      uint32 block_size, bool32 *need_more_log)
{
    return rcy_replay(session, point, data_size, batch, block_size, need_more_log, NULL, GS_TRUE);
}

/* Only when doing auto block recover(page repair), we try to find archive log from backup */
static bool32 rcy_load_backup_arch(knl_session_t *session, uint32 asn, char *buf, uint32 buf_size)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    char *path = bak->record.path;
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t ret;

    if (!(IS_BLOCK_RECOVER(session) || IS_FILE_RECOVER(session))) {
        return GS_FALSE;
    }

     /* when repairing data file to load arch from backupset, backupset with compress or enctyption is not supported */
    if (IS_FILE_RECOVER(session) && IS_ENCTYPT_OR_COMPRESS_BACKUPSET(bak)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "replaying log in backupset to repairing file",
            "backupset with compress or enctyption");
        return GS_FALSE;
    }

    bak_generate_bak_file(session, path, BACKUP_ARCH_FILE, 0, asn, 0, file_name);

    if (cm_file_exist(file_name)) {
        ret = strcpy_sp(buf, buf_size, file_name);
        knl_securec_check(ret);
        GS_LOG_DEBUG_INF("[ABR] find backup archive log %s", file_name);
        return GS_TRUE;
    }

    for (uint32 i = 0; i < bak->depend_num; i++) {
        path = bak->depends[i].file_dest;
        bak_generate_bak_file(session, path, BACKUP_ARCH_FILE, 0, asn, 0, file_name);
        if (cm_file_exist(file_name)) {
            ret = strcpy_sp(buf, buf_size, file_name);
            knl_securec_check(ret);
            GS_LOG_DEBUG_INF("[ABR] find backup archive log %s", file_name);
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static status_t rcy_init_compress(knl_session_t *session, arch_file_t *file)
{
    GS_LOG_RUN_INF("[RCY] arc compressed log %s", file->name);
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    rcy_ctx->cur_pos = 0;
    rcy_ctx->write_len = 0;
    rcy_ctx->cmp_file_offset = (int64)file->head.block_size;
    if (knl_compress_alloc(file->head.cmp_algorithm, &rcy_ctx->cmp_ctx, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return knl_compress_init(file->head.cmp_algorithm, &rcy_ctx->cmp_ctx, GS_FALSE);
}

static status_t rcy_is_arch_compressed(arch_file_t *file, bool32 *is_compress)
{
    *is_compress = GS_FALSE;
    if (file->head.cmp_algorithm == COMPRESS_NONE) {
        return GS_SUCCESS;
    }
    if (file->head.cmp_algorithm != COMPRESS_ZSTD) {
        GS_LOG_RUN_ERR("arch compressed mode expected compress algorithm is zstd, actual is %s",
            bak_compress_algorithm_name(file->head.cmp_algorithm));
        GS_THROW_ERROR(ERR_BACKUP_RESTORE, "recovery check arch compress algorithm",
            "arch compressed mode expected compress algorithm is zstd, actual is zlib or lz4");
        return GS_ERROR;
    }
    *is_compress = GS_TRUE;
    return GS_SUCCESS;
}

status_t rcy_load_arch(knl_session_t *session, uint32 rst_id, uint32 asn, arch_file_t *file, bool32 *is_compress)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE];
    bak_t *bak = &session->kernel->backup_ctx.bak;

    if (!arch_get_archived_log_name(session, rst_id, asn, ARCH_DEFAULT_DEST, file_name, GS_FILE_NAME_BUFFER_SIZE)) {
        arch_set_archive_log_name(session, rst_id, asn, ARCH_DEFAULT_DEST, file_name, GS_FILE_NAME_BUFFER_SIZE);
        if (!cm_file_exist(file_name)) {
            if (bak->record.device == DEVICE_UDS) {
                GS_LOG_RUN_ERR("[RECOVERY] failed to get archived log file[%u-%u]", rst_id, asn);
                GS_THROW_ERROR(ERR_BACKUP_RESTORE, "repair", "because the lost of rcy point log");
                return GS_ERROR;
            } else if (!rcy_load_backup_arch(session, asn, file_name, GS_FILE_NAME_BUFFER_SIZE)) {
                GS_LOG_RUN_ERR("[RECOVERY] failed to get archived log file[%u-%u]", rst_id, asn);
                return GS_ERROR;
            }
        }
    }

    if (strcmp(file->name, file_name) == 0) {
        return rcy_is_arch_compressed(file, is_compress);
    }

    if (file->handle != GS_INVALID_HANDLE) {
        cm_close_device(DEV_TYPE_FILE, &file->handle);
    }

    errno_t ret = strcpy_sp(file->name, GS_FILE_NAME_BUFFER_SIZE, file_name);
    knl_securec_check(ret);
    /* file->handle is closed in rcy_close_file */
    if (log_get_file_head(file->name, &file->head) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (log_verify_head_checksum(session, &file->head, file->name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (rcy_is_arch_compressed(file, is_compress) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint32 flag = *is_compress ? O_SYNC : knl_redo_io_flag(session);
    if (cm_open_device(file->name, DEV_TYPE_FILE, flag, &file->handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RECOVERY] failed to open %s", file->name);
        return GS_ERROR;
    }

    return (*is_compress == GS_FALSE) ? GS_SUCCESS : rcy_init_compress(session, file);
}

static void rcy_move_buf_data(rcy_context_t *rcy_ctx)
{
    if (rcy_ctx->cur_pos == 0) {
        return;
    }
    char *buf = rcy_ctx->read_buf.aligned_buf;
    uint32 data_len = rcy_ctx->write_len - rcy_ctx->cur_pos;
    if (data_len != 0) {
        errno_t ret = memmove_s(buf, (size_t)rcy_ctx->read_buf.buf_size, buf + rcy_ctx->cur_pos, data_len);
        knl_securec_check(ret);
    }
    rcy_ctx->cur_pos = 0;
    rcy_ctx->write_len = data_len;
}

static status_t rcy_deal_first_arch_file(rcy_context_t *rcy_ctx, log_point_t *point,
                                         knl_compress_t *cmp_ctx, arch_file_t *file) 
{
    int64 targe_pos = point->block_id * file->head.block_size - file->head.block_size;
    aligned_buf_t *cmp_read_buf = &rcy_ctx->cmp_read_buf;
    aligned_buf_t *batch_buf = &rcy_ctx->read_buf;
    rcy_ctx->cur_arc_read_pos = 0;
    int32 read_size;
    for (;;) {
        if (cm_seek_file(file->handle, rcy_ctx->cmp_file_offset, SEEK_SET) != rcy_ctx->cmp_file_offset) {
            GS_LOG_RUN_ERR("[RCY] failed to seek log file %s", file->name);
            return GS_ERROR;
        }
        if (cm_read_file(file->handle, cmp_read_buf->aligned_buf, (int32)GS_ARC_COMPRESS_BUFFER_SIZE,
            &read_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (read_size == 0) {
            knl_compress_free(file->head.cmp_algorithm, cmp_ctx, GS_FALSE);
            break;
        }
        rcy_ctx->cmp_file_offset += read_size;
        knl_compress_set_input(file->head.cmp_algorithm, cmp_ctx, cmp_read_buf->aligned_buf, (uint32)read_size);
        cmp_ctx->finished = GS_FALSE;
        while (!cmp_ctx->finished) {
            if (knl_decompress(file->head.cmp_algorithm, cmp_ctx, GS_FALSE, batch_buf->aligned_buf,
                (uint32)batch_buf->buf_size) != GS_SUCCESS) {
                return GS_ERROR;
            }
            rcy_ctx->cur_arc_read_pos += cmp_ctx->write_len;
            if (rcy_ctx->cur_arc_read_pos >= targe_pos) {
                rcy_ctx->cmp_file_offset = rcy_ctx->cmp_file_offset - read_size + cmp_ctx->zstd_in_buf.pos;
                break;
            }
        }
        if (rcy_ctx->cur_arc_read_pos >= targe_pos) {
            break;
        }
    }
    /* len <= 64M, (uint32)size cannot overflow */
    uint32 len = (uint32)(rcy_ctx->cur_arc_read_pos - targe_pos);
    uint32 start = rcy_ctx->cmp_ctx.write_len - len;
    char *buf = rcy_ctx->read_buf.aligned_buf;
    errno_t ret = memmove_s(buf, (size_t)rcy_ctx->read_buf.buf_size, buf + start, len);
    rcy_ctx->write_len = len;
    knl_securec_check(ret);

    rcy_ctx->is_first_arch_file = GS_FALSE;
    return GS_SUCCESS;
}

static status_t rcy_load_arch_compressed_file(knl_session_t *session, log_point_t *point,
                                              uint32 *data_size, arch_file_t *arch_file)
{
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    knl_compress_t *cmp_ctx = &rcy_ctx->cmp_ctx;
    arch_file_t *file = &rcy_ctx->arch_file;
    aligned_buf_t *cmp_read_buf = &rcy_ctx->cmp_read_buf;
    aligned_buf_t *batch_buf = &rcy_ctx->read_buf;

    if (rcy_ctx->is_first_arch_file) {
        if (cm_aligned_realloc(GS_MAX_BATCH_SIZE, "rcy", batch_buf) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_MAX_BATCH_SIZE, "rcy");
            return GS_ERROR;
        }
        if (rcy_deal_first_arch_file(rcy_ctx, point, cmp_ctx, file) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    rcy_move_buf_data(rcy_ctx);

    int32 read_size;
    if (cm_seek_file(file->handle, rcy_ctx->cmp_file_offset, SEEK_SET) != rcy_ctx->cmp_file_offset) {
        GS_LOG_RUN_ERR("[RCY] failed to seek log file %s", file->name);
        return GS_ERROR;
    }
    if (cm_read_file(file->handle, cmp_read_buf->aligned_buf, (int32)GS_ARC_COMPRESS_BUFFER_SIZE,
        &read_size) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (read_size == 0) {
        knl_compress_free(file->head.cmp_algorithm, cmp_ctx, GS_FALSE);
        *data_size = rcy_ctx->write_len;
        return GS_SUCCESS;
    }
    knl_compress_set_input(file->head.cmp_algorithm, cmp_ctx, cmp_read_buf->aligned_buf, (uint32)read_size);
    if (knl_decompress(file->head.cmp_algorithm, cmp_ctx, GS_FALSE, batch_buf->aligned_buf + rcy_ctx->write_len,
        (uint32)batch_buf->buf_size - rcy_ctx->write_len) != GS_SUCCESS) {
        return GS_ERROR;
    }
    rcy_ctx->cmp_file_offset = rcy_ctx->cmp_file_offset + cmp_ctx->zstd_in_buf.pos;
    rcy_ctx->write_len += cmp_ctx->write_len;
    *data_size = rcy_ctx->write_len;
    return GS_SUCCESS;
}

status_t rcy_load_arch_file(knl_session_t *session, log_point_t *point, uint32 *data_size, arch_file_t *file,
                            aligned_buf_t *align_buf)
{
    uint64 buf_size = (uint64)align_buf->buf_size;
    char *buf = align_buf->aligned_buf;

    if (file->head.write_pos < (uint64)point->block_id * file->head.block_size) {
        *data_size = 0;
        return GS_SUCCESS;
    }

    uint64 size = file->head.write_pos - (uint64)point->block_id * file->head.block_size;
    if (size > buf_size) {
        size = buf_size;
    }

    int64 offset = (int64)point->block_id * file->head.block_size;
    /* size <= buf_size, (int32)size cannot overflow */
    if (cm_read_device(DEV_TYPE_FILE, file->handle, offset, buf, (int32)size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[RECOVERY] failed to read %s, offset %llu", file->name,
                       (uint64)point->block_id * file->head.block_size);
        rcy_close_file(session);
        return GS_ERROR;
    }

    *data_size = (uint32)size;

    return GS_SUCCESS;
}

status_t rcy_load_from_arch(knl_session_t *session, log_point_t *point, uint32 *data_size, arch_file_t *file,
                            aligned_buf_t *align_buf)
{
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    
    bool32 is_compress = GS_FALSE;
    if (rcy_load_arch(session, (uint32)point->rst_id, point->asn, file, &is_compress) != GS_SUCCESS)  { /* max rst_id <= 2^18, cannot overflow */
        rcy_close_file(session);
        return GS_ERROR;
    }

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    if (is_compress) {
        if (rcy_load_arch_compressed_file(session, point, data_size, file) != GS_SUCCESS) {
            knl_compress_free(file->head.cmp_algorithm, &rcy_ctx->cmp_ctx, GS_FALSE);
            rcy_close_file(session);
            return GS_ERROR;
        }
    } else {
        if (rcy_load_arch_file(session, point, data_size, file, align_buf) != GS_SUCCESS) {
            rcy_close_file(session);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t rcy_load_from_online(knl_session_t *session, uint32 file_id, log_point_t *point, uint32 *data_size,
                              int32 *handle, aligned_buf_t *align_buf)
{
    uint64 size;
    uint64 buf_size = (uint64)align_buf->buf_size;
    log_context_t *ctx = &session->kernel->redo_ctx;
    log_file_t *file = &ctx->files[file_id];
    bak_t *bak = &session->kernel->backup_ctx.bak;
    char *buf = align_buf->aligned_buf;

    if (point->block_id == 0) {
        point->block_id = 1;
    }

    if (session->kernel->db.status == DB_STATUS_RECOVERY || session->kernel->db.status == DB_STATUS_REDO_ANALYSIS ||
        (bak->is_building && bak->record.attr.level == 1) || bak->record.is_repair) {
        size = (uint64)file->ctrl->size;
        if ((int64)point->block_id * file->ctrl->block_size + (int64)buf_size > file->ctrl->size) {
            size = (uint64)file->ctrl->size - (uint64)point->block_id * file->ctrl->block_size;
        }
    } else {
        size = file->head.write_pos - (uint64)point->block_id * file->ctrl->block_size;
    }

    if (size == 0) {
        log_unlatch_file(session, file_id);
        return GS_SUCCESS;
    }

    if (size > buf_size) {
        size = buf_size;
    }

    if (cm_open_device(file->ctrl->name, file->ctrl->type, knl_redo_io_flag(session), handle) != GS_SUCCESS) {
        log_unlatch_file(session, file_id);
        GS_LOG_RUN_ERR("[RECOVERY] failed to open %s", file->ctrl->name);
        return GS_ERROR;
    }
    /* size <= buf_size, (uint32)size cannot overflow */
    if (cm_read_device(file->ctrl->type, *handle, (int64)point->block_id * file->ctrl->block_size, buf,
                       (uint32)size) != GS_SUCCESS) {
        log_unlatch_file(session, file_id);
        GS_LOG_RUN_ERR("[RECOVERY] failed to read %s, offset %u", file->ctrl->name, point->block_id);
        cm_close_device(file->ctrl->type, handle);
        return GS_ERROR;
    }

    *data_size = (uint32)size;
    log_unlatch_file(session, file_id);
    return GS_SUCCESS;
}

static inline bool32 rcy_group_pages_preloaded(rcy_context_t *rcy, uint32 group_id)
{
    if (rcy->preload_proc_num == 0) {
        return GS_TRUE;
    }

    uint32 min = rcy->preload_info[0].group_id;
    for (uint32 i = 1; i < rcy->preload_proc_num; i++) {
        min = (min < rcy->preload_info[i].group_id) ? min : rcy->preload_info[i].group_id;
    }
    return (min > group_id);
}

void rcy_perform(knl_session_t *session, rcy_bucket_t *bucket)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    rcy_paral_group_t *ctrl = NULL;

    if (bucket->head == bucket->tail) {
        rcy_flexible_sleep(session, rcy, bucket);
        return;
    }

    cm_spin_lock(&bucket->lock, NULL);
    if (SECUREC_UNLIKELY(bucket->head == bucket->tail)) {
        cm_spin_unlock(&bucket->lock);
        return;
    }
    ctrl = bucket->first[bucket->head];
    cm_spin_unlock(&bucket->lock);

    bucket->last_replay_time = g_timer()->now;
    if (!rcy_group_pages_preloaded(rcy, ctrl->id)) {
        rcy_flexible_sleep(session, rcy, NULL);
        return;
    }

    if (rcy_paral_replay_group(session, bucket, ctx, ctrl) != GS_SUCCESS) {
        return;
    }
    rcy_release_lock_pages(session, ctrl);

    if (bucket->head != bucket->tail) {
        bucket->head = (bucket->head + 1) % bucket->count;
    }
}

static void rcy_release_session(knl_session_t *session)
{
    g_knl_callback.release_knl_session(session);
}

void rcy_proc(thread_t *thread)
{
    rcy_bucket_t *bucket = (rcy_bucket_t *)thread->argument;
    knl_session_t *session = bucket->session;

    cm_set_thread_name("rcy_proc");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    for (;;) {
        if (thread->closed && bucket->head == bucket->tail) {
            break;
        }
        if (session->kernel->rcy_ctx.rcy_end) {
            rcy_replay_group_end(session);
            break;
        }

        rcy_perform(session, bucket);
    }
    rcy_release_session(session);
    KNL_SESSION_CLEAR_THREADID(session);
}

static status_t rcy_alloc_buffer(rcy_context_t *rcy)
{
    rcy->buf = (char *)malloc(GS_RCY_BUF_SIZE); // 4M
    if (rcy->buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_RCY_BUF_SIZE, "bucket");
        return GS_ERROR;
    }
    errno_t ret = memset_sp(rcy->buf, GS_RCY_BUF_SIZE, 0, GS_RCY_BUF_SIZE);
    knl_securec_check(ret);

    rcy->page_list = (rcy_page_t *)malloc(GS_MAX_BATCH_SIZE); // 64M
    if (rcy->page_list == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, GS_MAX_BATCH_SIZE, "page list");
        CM_FREE_PTR(rcy->buf);
        return GS_ERROR;
    }
    ret = memset_sp(rcy->page_list, GS_MAX_BATCH_SIZE, 0, GS_MAX_BATCH_SIZE);
    knl_securec_check(ret);

    rcy->group_list = (rcy_paral_group_t *)malloc(GS_MAX_BATCH_SIZE); // 64M
    if (rcy->group_list == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, GS_MAX_BATCH_SIZE, "group list");
        CM_FREE_PTR(rcy->buf);
        CM_FREE_PTR(rcy->page_list);
        return GS_ERROR;
    }
    ret = memset_sp(rcy->group_list, GS_MAX_BATCH_SIZE, 0, GS_MAX_BATCH_SIZE);
    knl_securec_check(ret);

    rcy->page_bucket = (rcy_page_bucket_t *)malloc(sizeof(rcy_page_bucket_t) * GS_RCY_MAX_PAGE_COUNT); // 32M
    if (rcy->page_bucket == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(rcy_page_bucket_t) * GS_RCY_MAX_PAGE_COUNT, "page bucket");
        CM_FREE_PTR(rcy->buf);
        CM_FREE_PTR(rcy->page_list);
        CM_FREE_PTR(rcy->group_list);
        return GS_ERROR;
    }
    ret = memset_sp(rcy->page_bucket, GS_RCY_MAX_PAGE_COUNT * sizeof(rcy_page_bucket_t), 0,
                    sizeof(rcy_page_bucket_t) * GS_RCY_MAX_PAGE_COUNT);
    knl_securec_check(ret);

    rcy->page_bitmap = (uint16 *)malloc(sizeof(uint16) * GS_RCY_MAX_PAGE_BITMAP_LEN); // 512K
    if (rcy->page_bitmap == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(uint16) * GS_RCY_MAX_PAGE_BITMAP_LEN, "page bucket");
        CM_FREE_PTR(rcy->buf);
        CM_FREE_PTR(rcy->page_list);
        CM_FREE_PTR(rcy->group_list);
        CM_FREE_PTR(rcy->page_bucket);
        return GS_ERROR;
    }
    ret = memset_sp(rcy->page_bitmap, sizeof(uint16) * GS_RCY_MAX_PAGE_BITMAP_LEN, 0,
                    sizeof(uint16) * GS_RCY_MAX_PAGE_BITMAP_LEN);
    knl_securec_check(ret);

    return GS_SUCCESS;
}

static inline void rcy_free_buffer(rcy_context_t *rcy)
{
    CM_FREE_PTR(rcy->buf);
    CM_FREE_PTR(rcy->page_list);
    CM_FREE_PTR(rcy->group_list);
    CM_FREE_PTR(rcy->page_bucket);
    CM_FREE_PTR(rcy->page_bitmap);
}

status_t rcy_init_context(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    if (!rcy->paral_rcy) {
        return GS_SUCCESS;
    }

    if (rcy_alloc_buffer(rcy) != GS_SUCCESS) {
        return GS_ERROR;
    }

    rcy->abr_rcy_flag = GS_FALSE;
    rcy->abr_pagid = INVALID_PAGID;
    GS_LOG_RUN_INF("[RCY] init context finish");
    return GS_SUCCESS;
}

// load redo log from log files from the given recovery point offset.
status_t rcy_load(knl_session_t *session, log_point_t *point, uint32 *data_size, uint32 *block_size)
{
    uint32 file_id;
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    log_context_t *ctx = &session->kernel->redo_ctx;
    status_t status;

    if (session->kernel->rcy_ctx.paral_rcy) {
        rcy_wait_replay_complete(session);
    }

    if (IS_BLOCK_RECOVER(session) && rcy_ctx->abr_db_status == DB_STATUS_OPEN) {
        status = rcy_load_from_arch(session, point, data_size, &rcy_ctx->arch_file, &rcy_ctx->read_buf);
        *block_size = (uint32)rcy_ctx->arch_file.head.block_size;
        return status;
    }

    log_lock_logfile(session);
    file_id = log_get_id_by_asn(session, (uint32)point->rst_id, point->asn,
                                &rcy_ctx->loading_curr_file); /* max rst_id <= 2^18, cannot oveflow */
    log_unlock_logfile(session);

    if (file_id != GS_INVALID_ID32) {          
        /* rcy_ctx->read_buf.buf_size <= 64M, cannot oveflow */
        status = rcy_load_from_online(session, file_id, point, data_size, rcy_ctx->handle + file_id, 
                                      &rcy_ctx->read_buf);
        *block_size = ctx->files[file_id].ctrl->block_size;
    } else {
        status = rcy_load_from_arch(session, point, data_size, &rcy_ctx->arch_file, &rcy_ctx->read_buf);
        *block_size = (uint32)rcy_ctx->arch_file.head.block_size;
    }
    return status;
}

status_t rcy_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    rcy_context_t *rcy = &kernel->rcy_ctx;

    errno_t ret = memset_sp(rcy, sizeof(rcy_context_t), 0, sizeof(rcy_context_t));
    knl_securec_check(ret);

    rcy_eventfd_init(rcy);

    rcy->capacity = GS_DEFAULT_PARAL_RCY;
    for (uint32 i = 0; i < RCY_WAIT_STATS_COUNT; i++) {
        rcy->wait_stats_view[i] = 0;
    }

    for (uint32 i = 0; i < LMGR_COUNT; i++) {
        ctx->replay_procs[g_lmgrs[i].type] = g_lmgrs[i].replay_proc;
        ctx->analysis_procs[g_lmgrs[i].type] = g_lmgrs[i].analysis_proc;
        ctx->check_punch_proc[g_lmgrs[i].type] = g_lmgrs[i].check_punch_proc;
        knl_panic_log(g_lmgrs[i].analysis_proc != NULL, "current analysis_proc is NULL.");
    }
    rcy->paral_rcy = GS_FALSE;
    if (kernel->attr.log_replay_processes > GS_DEFAULT_PARAL_RCY) {
        rcy->paral_rcy = GS_TRUE;
        rcy->capacity = kernel->attr.log_replay_processes;
    }
    if (rcy->read_buf.alloc_buf == NULL) {
        int64 size = (int64)LOG_LGWR_BUF_SIZE(session);
        if (cm_aligned_malloc(size, "rcy", &rcy->read_buf) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    if (rcy->paral_rcy) {
        if (rcy->read_buf2.alloc_buf == NULL) {
            int64 size = (int64)LOG_LGWR_BUF_SIZE(session);
            if (cm_aligned_malloc(size, "rcy second buf", &rcy->read_buf2) != GS_SUCCESS) {
                cm_aligned_free(&rcy->read_buf);
                return GS_ERROR;
            }
        }
        rcy->swich_buf = GS_FALSE;
    }
    if (cm_aligned_malloc((int64)GS_ARC_COMPRESS_BUFFER_SIZE, "rcy process", &rcy->cmp_read_buf) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_ARC_COMPRESS_BUFFER_SIZE, "rcy process");
        return GS_ERROR;
    }

    rcy->arch_file.handle = GS_INVALID_HANDLE;
    for (uint32 i = 0; i < GS_MAX_LOG_FILES; i++) {
        rcy->handle[i] = GS_INVALID_HANDLE;
    }

    rcy->max_scn = GS_INVALID_ID64;
    rcy->action = RECOVER_NORMAL;
    return rcy_init_context(session);
}

void rcy_close(knl_session_t *session)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;

    rcy->is_closing = GS_TRUE;
    rcy_close_proc(session);
    for (;;) {
        if (!rcy->is_working) {
            break;
        }
    }
    cm_aligned_free(&rcy->cmp_read_buf);
    cm_aligned_free(&rcy->read_buf);
    cm_aligned_free(&rcy->read_buf2);
    rcy_free_buffer(rcy);
}

void rcy_close_file(knl_session_t *session)
{
    rcy_context_t *rcy_ctx = &session->kernel->rcy_ctx;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_file_t *files = redo_ctx->files;
    uint32 i;

    if (SESSION_IS_LOG_ANALYZE(session)) {
        return; // gbp aly session's log file handle is closed in gbp_aly_proc
    }
    cm_close_file(rcy_ctx->arch_file.handle);
    rcy_ctx->arch_file.handle = GS_INVALID_HANDLE;
    rcy_ctx->arch_file.name[0] = '\0';

    for (i = 0; i < GS_MAX_LOG_FILES; i++) {
        cm_close_device(files[i].ctrl->type, &rcy_ctx->handle[i]);
    }
}

static status_t rcy_reset_file(knl_session_t *session, log_point_t *point)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *ctx = &kernel->redo_ctx;
    log_file_t *file = NULL;

    if (log_set_file_asn(session, point->asn, GS_INVALID_ID32) != GS_SUCCESS) {
        return GS_ERROR;
    }

    file = &ctx->files[kernel->db.ctrl.core.log_first];
    /* file->head.write_pos / file->head.block_size < max int32, cannot overflow */
    point->block_id = (uint32)(file->head.write_pos / (uint32)file->head.block_size);
    ctx->free_size += log_file_freesize(file);
    return GS_SUCCESS;
}

/*
 * if curr_point resides in the window (gbp_begin_point, gbp_rcy_point), we can speed up recovery by
 * moving curr_point forward to gbp_rcy_point.
 */
static void rcy_try_use_gbp(knl_session_t *session, log_point_t *curr_point)
{
    if (KNL_GBP_SAFE(session->kernel) &&
        KNL_GBP_FOR_RECOVERY(session->kernel) &&
        !KNL_RECOVERY_WITH_GBP(session->kernel) &&
        gbp_replay_in_window(session, *curr_point)) {
        if (session->kernel->rcy_ctx.paral_rcy) {
            rcy_wait_replay_complete(session);
        }

        if (KNL_GBP_SAFE(session->kernel)) { // recheck again, gbp status may set unsafe when rcy_wait_replay_complete
            gbp_knl_begin_read(session, curr_point);
        }
    }
}

static status_t rcy_analysis_all_redo(knl_session_t *session, log_point_t *curr_point)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_batch_t *batch = NULL;
    bool32 need_more_log = GS_FALSE;
    uint32 data_size = 0;
    uint32 block_size;

    while (rcy_load(session, curr_point, &data_size, &block_size) == GS_SUCCESS) {
        batch = (log_batch_t*)rcy->read_buf.aligned_buf;
        if (log_need_realloc_buf(batch, &rcy->read_buf, "rcy", GS_MAX_BATCH_SIZE)) {
            continue;
        }

        if (rcy_analysis(session, curr_point, data_size, batch, block_size, &need_more_log) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (!need_more_log) {
            break;
        }
    }

    return GS_SUCCESS;
}

/*
 * For _GBP_FOR_RECOVERY == TRUE, analyze redo log when database restart
 * then use GBP at recover stage to accelerate DB open speed
 * Notice: standby redo analysis process is gbp_aly_proc, not use this function
 */
static status_t rcy_redo_analysis(knl_session_t *session, log_point_t *curr_point)
{
    knl_instance_t *kernel = session->kernel;
    log_context_t *redo_ctx = &kernel->redo_ctx;
    log_point_t rcy_begin_point = *curr_point;
    errno_t ret;

    redo_ctx->rcy_with_gbp = GS_FALSE;
    redo_ctx->last_rcy_with_gbp = GS_FALSE;
    ret = memset_sp(&redo_ctx->redo_end_point, sizeof(log_point_t), 0, sizeof(log_point_t));
    knl_securec_check(ret);

    if (!kernel->db.recover_for_restore && KNL_GBP_ENABLE(kernel) && KNL_GBP_FOR_RECOVERY(kernel)) {
        log_reset_analysis_point(session, curr_point);
        gbp_reset_unsafe(session);
        kernel->db.status = DB_STATUS_REDO_ANALYSIS;

        GS_LOG_RUN_INF("[GBP] log analysis: from file:%u,point:%u,lfn:%llu\n",
                       curr_point->asn, curr_point->block_id, (uint64)curr_point->lfn);
        (void)cm_gettimeofday(&redo_ctx->replay_stat.analyze_begin);

        if (rcy_analysis_all_redo(session, curr_point) != GS_SUCCESS) {
            return GS_ERROR;
        }

        redo_ctx->redo_end_point = *curr_point;
        (void)cm_gettimeofday(&redo_ctx->replay_stat.analyze_end);
        redo_ctx->replay_stat.analyze_elapsed = TIMEVAL_DIFF_US(&redo_ctx->replay_stat.analyze_begin,
                                                                &redo_ctx->replay_stat.analyze_end);

        GS_LOG_RUN_INF("[GBP] log analysis: end with file:%u,point:%u,lfn:%llu\n",
                       curr_point->asn, curr_point->block_id, (uint64)curr_point->lfn);

        cm_sleep(200); // wait gbp background process connected
        if (gbp_pre_check(session, redo_ctx->redo_end_point)) {
            gbp_knl_check_end_point(session);

            GS_LOG_RUN_INF("[GBP] gbp_rcy_point: rst_id:%u,file:%u,point:%u,lfn:%llu\n",
                           (uint32)redo_ctx->gbp_rcy_point.rst_id, redo_ctx->gbp_rcy_point.asn,
                           redo_ctx->gbp_rcy_point.block_id, (uint64)redo_ctx->gbp_rcy_point.lfn);
            GS_LOG_RUN_INF("[GBP] gbp lfn gap:%llu, gbp_rcy_lfn:%llu\n",
                           (uint64)(curr_point->lfn - redo_ctx->gbp_rcy_point.lfn),
                           (uint64)redo_ctx->gbp_rcy_point.lfn);
        }
    } else {
        gbp_set_unsafe(session, RD_TYPE_END);
    }

    rcy_try_use_gbp(session, &rcy_begin_point);
    *curr_point = rcy_begin_point;
    return GS_SUCCESS;
}

status_t rcy_recover_check(knl_session_t *session, log_point_t curr_point, log_point_t lrp_point)
{
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    uint64 consistent_lfn = session->kernel->db.ctrl.core.consistent_lfn;
    uint64 rcy_point_lfn = session->kernel->db.ctrl.core.rcy_point.lfn;

    GS_LOG_RUN_INF("[RCY] recovery real end with file:%u,point:%u,lfn:%llu", curr_point.asn, curr_point.block_id,
        (uint64)curr_point.lfn);
    GS_LOG_RUN_INF("[RCY] current lfn %llu, rcy point lfn %llu, consistent point %llu, lrp point lfn %llu",
                   (uint64)curr_point.lfn, (uint64)rcy_point_lfn, (uint64)consistent_lfn, (uint64)lrp_point.lfn);
    if (curr_point.lfn >= lrp_point.lfn) {
        return GS_SUCCESS;
    }

    if (RCY_IGNORE_CORRUPTED_LOG(rcy)) {
        GS_LOG_RUN_WAR("[RCY] database can not recover to lrp point");
        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_INVALID_RCV_END_POINT,
        curr_point.asn, curr_point.block_id, lrp_point.asn, lrp_point.block_id);
    return GS_ERROR;
}

bool32 db_terminate_lfn_reached(knl_session_t *session, uint64 curr_lfn)
{
    database_t *db = &session->kernel->db;

    if (DB_IS_PRIMARY(db) || db->terminate_lfn == GS_INVALID_LFN) {
        return GS_FALSE;
    }
    knl_panic(curr_lfn <= db->terminate_lfn);

    return ((curr_lfn == db->terminate_lfn) ? GS_TRUE : GS_FALSE);
}

status_t rcy_recover(knl_session_t *session)
{
    log_point_t curr_point = session->kernel->db.ctrl.core.rcy_point;
    log_point_t lrp_point = session->kernel->db.ctrl.core.lrp_point;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_context_t *log = &session->kernel->redo_ctx;
    log_batch_t *batch = NULL;
    bool32 need_more_log = GS_FALSE;
    uint32 data_size = 0;
    uint32 block_size;

    log_reset_point(session, &lrp_point);
    log_reset_analysis_point(session, &lrp_point);
    ckpt_set_trunc_point(session, &curr_point);
    gbp_queue_set_trunc_point(session, &curr_point);
    session->kernel->redo_ctx.lfn = curr_point.lfn;
    session->kernel->redo_ctx.analysis_lfn = curr_point.lfn;
    session->kernel->redo_ctx.curr_replay_point = curr_point;
    session->kernel->ckpt_ctx.trunc_lsn = (uint64)session->kernel->db.ctrl.core.lsn;
    session->kernel->rcy_ctx.rcy_end = GS_FALSE;

    /* redo log analysis, if GBP is usable, move curr_point forward to gbp_rcy_point, skip some redo log */
    if (rcy_redo_analysis(session, &curr_point) != GS_SUCCESS) {
        rcy_close_file(session);
        GS_LOG_RUN_ERR("[RCY] database redo analysis failed");
        return GS_ERROR;
    }
    /* after log analysis, reset redo context */
    session->kernel->redo_ctx.lfn = curr_point.lfn;
    session->kernel->db.status = DB_STATUS_RECOVERY;
    (void)cm_gettimeofday(&log->replay_stat.replay_begin);

    GS_LOG_RUN_INF("[RCY] database start recovery");
    GS_LOG_RUN_INF("[RCY] recovery from file:%u,point:%u,lfn:%llu", curr_point.asn, curr_point.block_id,
                   (uint64)curr_point.lfn);
    GS_LOG_RUN_INF("[RCY] recovery expected least end with file:%u,point:%u,lfn:%llu", lrp_point.asn, lrp_point.block_id,
                   (uint64)lrp_point.lfn);

    rcy_init_proc(session);

    rcy->replay_no_lag = GS_FALSE;
    rcy->is_working = GS_TRUE;
    session->kernel->rcy_ctx.is_first_arch_file = GS_TRUE;
    while (rcy_load(session, &curr_point, &data_size, &block_size) == GS_SUCCESS) {
        if (rcy->is_closing) {
            rcy_close_file(session);
            GS_LOG_RUN_ERR("database recovery aborted");
            return GS_ERROR;
        }

        batch = (log_batch_t *)rcy->read_buf.aligned_buf;
        if (log_need_realloc_buf(batch, &rcy->read_buf, "rcy", GS_MAX_BATCH_SIZE)) {
            continue;
        }
        rcy->curr_group = rcy->group_list;
        rcy->curr_group_id = 0;
        if (rcy_replay(session, &curr_point, data_size, batch, block_size, &need_more_log, NULL, GS_FALSE) != GS_SUCCESS) {
            rcy_close_file(session);
            return GS_ERROR;
        }
        rcy_try_use_gbp(session, &curr_point);

        if (!need_more_log) {
            break;
        }
    }

    cm_spin_lock(&rcy->lock, NULL);
    rcy->is_working = GS_FALSE;

    if (rcy->is_closing) {
        cm_spin_unlock(&rcy->lock);
        rcy_close_file(session);
        GS_LOG_RUN_ERR("database recovery aborted");
        return GS_ERROR;
    }

    cm_spin_unlock(&rcy->lock);
    (void)cm_gettimeofday(&log->replay_stat.replay_end);
    log->replay_stat.replay_elapsed = TIMEVAL_DIFF_US(&log->replay_stat.replay_begin, &log->replay_stat.replay_end);

    rcy_wait_replay_complete(session);
    rcy_close_proc(session);
    rcy->rcy_end = GS_TRUE;
    rcy_close_file(session);

    /* set next generate lfn equal to the previous lfn plus 1 */
    log->buf_lfn[0] = log->lfn + 1;
    log->buf_lfn[1] = log->lfn + 2;

    if (rcy_recover_check(session, curr_point, lrp_point) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (session->kernel->db.recover_for_restore && !RCY_IGNORE_CORRUPTED_LOG(rcy)) {
        if (rcy_reset_file(session, &curr_point) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (IS_PITR_RECOVER(rcy)) {
            GS_LOG_RUN_INF("[RCY] pitr clear useless archive logs");
            arch_reset_archfile(session, curr_point.asn - 1);
        }
    } else {
        log_reset_file(session, &curr_point);
    }

    log_reset_analysis_point(session, &curr_point);
    if (KNL_GBP_ENABLE(session->kernel)) {
        gbp_reset_unsafe(session);
    }

    if (DB_IS_RAFT_ENABLED(session->kernel)) {
        session->kernel->raft_ctx.flush_point = curr_point;
        session->kernel->db.is_readonly = GS_TRUE;
        session->kernel->db.ctrl.core.db_role = REPL_ROLE_PHYSICAL_STANDBY;
    }

    ckpt_set_trunc_point(session, &log->curr_point);
    return GS_SUCCESS;
}

static status_t rcy_alloc_session(knl_instance_t *kernel, knl_session_t **session)
{
    if (g_knl_callback.alloc_knl_session(GS_TRUE, (knl_handle_t *)session) != GS_SUCCESS) {
        return GS_ERROR;
    }
    (*session)->curr_lsn = GS_INVALID_LSN;

    return GS_SUCCESS;
}

void rcy_update_preload_info(rcy_preload_info_t *info, rcy_context_t *rcy, rcy_wait_stats_e rcy_event)
{
    info->curr += rcy->preload_proc_num;
    rcy->wait_stats_view[rcy_event]++;
}

void rcy_preload_proc(thread_t *thread)
{
    rcy_preload_info_t *info = (rcy_preload_info_t *)thread->argument;
    knl_session_t *session = info->session;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    page_id_t page_id;
    buf_ctrl_t *ctrl = NULL;
    status_t status;

    cm_set_thread_name("rcy_preload");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    for (;;) {
        if (thread->closed) {
            break;
        }

        uint32 preload_hwm = (uint32)cm_atomic_get(&rcy->preload_hwm);
        if (preload_hwm <= info->curr) {
            info->group_id = rcy->curr_group_id;
            rcy_flexible_sleep(session, rcy, NULL);
            continue;
        }

        info->group_id = rcy->page_list[info->curr].gid;
        if (rcy->page_list[info->curr].option & ENTER_PAGE_NO_READ) {
            rcy_update_preload_info(info, rcy, ENTER_PAGE_NO_READ);
            continue;
        }

        page_id.file = rcy->page_list[info->curr].file;
        page_id.page = rcy->page_list[info->curr].page;

        /* RTO = 0, disable prefetch when db is recovery from GBP */
        if (SECUREC_UNLIKELY(KNL_RECOVERY_WITH_GBP(session->kernel) || IS_INVALID_PAGID(page_id))) {
            ctrl = NULL;
            rcy_update_preload_info(info, rcy, PRELOAD_BUFFER_PAGES);
            continue;
        }

        if (page_compress(session, page_id)) {
            ctrl = buf_try_alloc_compress(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL, BUF_ADD_HOT);
        } else {
            ctrl = buf_try_alloc_ctrl(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL, BUF_ADD_HOT);
        }

        if (ctrl == NULL) {
            rcy_update_preload_info(info, rcy, PRELOAD_BUFFER_PAGES);
            continue;
        }
        knl_panic(ctrl->load_status == (uint8)BUF_NEED_LOAD);

        if (page_compress(session, page_id)) {
            status = buf_load_group(session, ctrl);
        } else {
            status = buf_load_page(session, ctrl, page_id);
        }

        if (status != GS_SUCCESS) {
            rcy_update_preload_info(info, rcy, PRELOAD_BUFFER_PAGES);
            buf_unlatch(session, ctrl, GS_TRUE);
            continue;
        }
        rcy->wait_stats_view[PRELOAD_DISK_PAGES]++;

        buf_unlatch(session, ctrl, GS_TRUE);
        info->curr += rcy->preload_proc_num;
    }

    rcy_release_session(session);
    KNL_SESSION_CLEAR_THREADID(session);
}

void rcy_init_proc(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    rcy_bucket_t *bucket = NULL;
    uint32 bucket_count;
    errno_t ret;
    uint32 i = 0;

    if (kernel->attr.log_replay_processes > GS_DEFAULT_PARAL_RCY) {
        rcy->paral_rcy = GS_TRUE;
        rcy->capacity = kernel->attr.log_replay_processes;
        rcy->preload_proc_num = kernel->attr.rcy_preload_processes;
    } else {
        rcy->paral_rcy = GS_FALSE;
        rcy->preload_proc_num = 0;
    }

    if (!rcy->paral_rcy) {
        return;
    }

    rcy->replay_no_lag = GS_FALSE;
    rcy->swich_buf = GS_FALSE;
    bucket_count = GS_RCY_BUF_SIZE / sizeof(rcy_paral_group_t *);
    rcy->page_list_count = 0;
    rcy->preload_hwm = 0;
    rcy->rcy_end = GS_FALSE;
    ret = memset_s(rcy->page_bucket, (uint32)(GS_RCY_MAX_PAGE_COUNT * sizeof(rcy_page_bucket_t)), 0,
                   sizeof(rcy_page_bucket_t) * GS_RCY_MAX_PAGE_COUNT);
    knl_securec_check(ret);

    for (i = 0; i < rcy->capacity; i++) {
        bucket = &rcy->bucket[i];
        bucket->count = bucket_count / rcy->capacity;
        bucket->lock = 0;
        bucket->head = 0;
        bucket->tail = 0;
        bucket->first = (rcy_paral_group_t **)(rcy->buf + i * bucket->count * sizeof(rcy_paral_group_t *));
        bucket->last_replay_time = g_timer()->now;
        bucket->id = i;

        cm_init_eventfd(&bucket->eventfd);
        if (rcy_alloc_session(kernel, &bucket->session) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("rcy proc init failed as alloc session failed now=%u, capacity=%u", i, rcy->capacity);
            break;
        }

        if (cm_create_thread(rcy_proc, 0, bucket, &bucket->thread) != GS_SUCCESS) {
            rcy_release_session(bucket->session);
            GS_LOG_RUN_ERR("rcy proc init failed as create thread failed now=%u, capacity=%u", i, rcy->capacity);
            break;
        }
    }

    GS_LOG_RUN_INF("[RCY] start %u rcy processes with capacity %u", i, rcy->capacity);

    if (i < rcy->capacity) {
        if (i > GS_DEFAULT_PARAL_RCY) {
            rcy->capacity = i;
            rcy->paral_rcy = GS_TRUE;
        } else {
            rcy->paral_rcy = GS_FALSE;
        }
    }

    for (i = 0; i < rcy->preload_proc_num; i++) {
        rcy->preload_info[i].group_id = 0;
        rcy->preload_info->curr = i;

        if (rcy_alloc_session(kernel, &rcy->preload_info[i].session) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("rcy preload proc as alloc session failed now=%u, capacity=%u", i, rcy->preload_proc_num);
            break;
        }

        if (cm_create_thread(rcy_preload_proc, 0, &rcy->preload_info[i], &rcy->preload_thread[i]) != GS_SUCCESS) {
            rcy_release_session(rcy->preload_info[i].session);
            GS_LOG_RUN_ERR("rcy preload proc as create thread failed now=%u, capacity=%u", i, rcy->preload_proc_num);
            break;
        }
    }

    GS_LOG_RUN_INF("[RCY] start %u rcy preload processes with capacity %u", i, rcy->preload_proc_num);

    rcy->preload_proc_num = (i < rcy->preload_proc_num) ? i : rcy->preload_proc_num;
    return;
}

void rcy_close_proc(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    rcy_context_t *rcy = &kernel->rcy_ctx;
    rcy_bucket_t *bucket = NULL;
    uint32 i;

    if (!rcy->paral_rcy) {
        return;
    }

    rcy->last_lrpl_time = 0;  // make sure parallel threads close immediately
    for (i = 0; i < rcy->capacity; i++) {
        bucket = &rcy->bucket[i];
        cm_close_thread(&bucket->thread);
        cm_release_eventfd(&bucket->eventfd);
    }

    for (i = 0; i < rcy->preload_proc_num; i++) {
        cm_close_thread(&rcy->preload_thread[i]);
    }
    rcy->swich_buf = GS_FALSE;
    GS_LOG_RUN_INF("[RCY] replay processes closed");
}

#ifdef LOG_DIAG
static inline void log_diag_entry(knl_session_t *session, log_entry_t *log)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    char *page = NULL;

    if (ctx->replay_procs[log->type] == NULL) {
        GS_LOG_RUN_WAR("undefined replay function for log type: %d\n", log->type);
        knl_panic(0);
        return;
    }

    page = session->curr_page;
    session->curr_page = session->log_diag_page[session->page_stack.depth - 1];

    ctx->replay_procs[log->type](session, log);
    session->curr_page = page;
}

void log_diag_page(knl_session_t *session)
{
    log_entry_t *entry = NULL;
    uint32 offset;
    uint32 group_pages = 0;

    session->log_diag = GS_TRUE;
    offset = session->page_stack.log_begin[session->page_stack.depth - 1];

    // only replay those logs which belong to current page
    while (offset < ((log_group_t *)session->log_buf)->size) {
        entry = (log_entry_t *)(session->log_buf + offset);
        offset += entry->size;
        if (RD_TYPE_IS_ENTER_PAGE(entry->type)) {
            group_pages++;
            continue;
        } else if (RD_TYPE_IS_LEAVE_PAGE(entry->type)) {
            knl_panic_log(group_pages != 0, "the group_pages is zero.");
            group_pages--;
            continue;
        }

        if (group_pages == 1) {
            log_diag_entry(session, entry);
        }
    }
    session->log_diag = GS_FALSE;
}
#endif

void rcy_replay_logic(knl_session_t *session, log_entry_t *log)
{
    logic_op_t *op_type = (logic_op_t *)log->data;

    if (DB_NOT_READY(session) || (DB_IS_PRIMARY(&session->kernel->db)) || DB_IS_UPGRADE(session)) {
        if (*op_type != RD_CREATE_MK_BEGIN
            && *op_type != RD_CREATE_MK_END
            && *op_type != RD_CREATE_MK_DATA
            && *op_type != RD_UPDATE_SYSDATA_VERSION) {
            return;
        }
    }

    // replay logical log need update session query_scn
    session->query_scn = DB_CURR_SCN(session);

    for (uint32 id = 0; id < LOGIC_LMGR_COUNT; id++) {
        if (g_logic_lmgrs[id].type == *op_type) {
            g_logic_lmgrs[id].replay_proc(session, log);
            return;
        }
    }

    if (*op_type >= RD_SQL_LOG_BEGIN && *op_type < RD_SQL_LOG_END) {
        if (g_knl_callback.pl_logic_log_replay(session, *op_type - RD_SQL_LOG_BEGIN,
            (void *)(log->data + CM_ALIGN4(sizeof(logic_op_t)))) != GS_SUCCESS) {
            int32 error_code;
            const char *error_message = NULL;
            cm_get_error(&error_code, &error_message, NULL);
            GS_LOG_RUN_ERR("sql logic log replay fail, error code:%u, error message:%s",
                           error_code, error_message);
            cm_reset_error();
        }
    }
}

void print_replay_logic(log_entry_t *log)
{
    logic_op_t *op_type = (logic_op_t *)log->data;

    for (uint32 id = 0; id < LOGIC_LMGR_COUNT; id++) {
        if (g_logic_lmgrs[id].type == *op_type) {
            g_logic_lmgrs[id].desc_proc(log);
            return;
        }
    }
}

void gbp_aly_gbp_logic(knl_session_t *session, log_entry_t *log, uint64 lsn)
{
    logic_op_t *op_type = (logic_op_t *)log->data;

    if (DB_NOT_READY(session) || DB_IS_PRIMARY(&session->kernel->db)) {
        return;
    }

    switch (*op_type) {
        case RD_ADD_LOGFILE:
            rd_alter_add_logfile(session, log);
            break;
        case RD_DROP_LOGFILE:
            rd_alter_drop_logfile(session, log);
            break;
        default:
            gbp_aly_unsafe_entry(session, log, lsn);
            break;
    }
}