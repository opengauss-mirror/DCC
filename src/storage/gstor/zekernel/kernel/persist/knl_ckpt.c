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
 * knl_ckpt.c
 *    kernel checkpoint definitions
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/persist/knl_ckpt.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_ckpt.h"
#include "cm_log.h"
#include "cm_file.h"
#include "knl_buflatch.h"
#include "knl_ctrl_restore.h"
#include "zstd.h"

#define NEED_SYNC_LOG_INFO(ctx) ((ctx)->timed_task != CKPT_MODE_IDLE || (ctx)->trigger_task == CKPT_TRIGGER_FULL)

void ckpt_proc(thread_t *thread);
void dbwr_proc(thread_t *thread);
static status_t ckpt_perform(knl_session_t *session);
static void ckpt_page_clean(knl_session_t *session);

static inline void ckpt_param_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

    ctx->dbwr_count = kernel->attr.dbwr_processes;
    ctx->double_write = kernel->attr.enable_double_write;
}

static status_t dbwr_aio_init(knl_session_t *session, dbwr_context_t *dbwr)
{
    knl_instance_t *kernel = session->kernel;
    errno_t ret;

    if (!session->kernel->attr.enable_asynch) {
        return GS_SUCCESS;
    }

    ret = memset_sp(&dbwr->async_ctx.aio_ctx, sizeof(cm_io_context_t), 0, sizeof(cm_io_context_t));
    knl_securec_check(ret);

    if (cm_aio_setup(&kernel->aio_lib, GS_CKPT_GROUP_SIZE, &dbwr->async_ctx.aio_ctx) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[CKPT]: setup asynchronous I/O context failed, errno %d", errno);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t dbwr_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;
    dbwr_context_t *dbwr = NULL;
    errno_t ret;

    for (uint32 i = 0; i < ctx->dbwr_count; i++) {
        dbwr = &ctx->dbwr[i];
        dbwr->dbwr_trigger = GS_FALSE;
        dbwr->session = kernel->sessions[SESSION_ID_DBWR];
        ret = memset_sp(&dbwr->datafiles, GS_MAX_DATA_FILES * sizeof(int32), 0xFF, GS_MAX_DATA_FILES * sizeof(int32));
        knl_securec_check(ret);
#ifdef WIN32
        dbwr->sem = CreateSemaphore(NULL, 0, 1, NULL);
#else
        sem_init(&dbwr->sem, 0, 0);

        if (dbwr_aio_init(session, dbwr) != GS_SUCCESS) {
            return GS_ERROR;
        }
#endif  // WIN32
    }

    return GS_SUCCESS;
}

status_t ckpt_init(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;
    errno_t ret;

    ret = memset_sp(ctx, sizeof(ckpt_context_t), 0, sizeof(ckpt_context_t));
    knl_securec_check(ret);

    ckpt_param_init(session);

    cm_init_cond(&ctx->ckpt_cond);

    ctx->group.buf = kernel->attr.ckpt_buf;
    ctx->ckpt_enabled = GS_TRUE;
    ctx->trigger_task = CKPT_MODE_IDLE;
    ctx->timed_task = CKPT_MODE_IDLE;
    ctx->trigger_finish_num = 0;
    ctx->stat.proc_wait_cnt = 0;
    ctx->full_trigger_active_num = 0;
    ctx->dw_file = -1;
    ctx->batch_end = NULL;
    ctx->clean_end = NULL;

    if (dbwr_init(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (kernel->attr.enable_asynch) {
        ctx->group.iocbs_buf = (char *)malloc(GS_CKPT_GROUP_SIZE * CM_IOCB_LENTH);
        if (ctx->group.iocbs_buf == NULL) {
            GS_LOG_RUN_ERR("[CKPT] iocb malloc fail");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void ckpt_load(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

    ctx->lrp_point = session->kernel->db.ctrl.core.lrp_point;
}

void ckpt_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

#ifndef WIN32
    ctx->thread.closed = GS_TRUE;
#endif

    cm_close_thread(&ctx->thread);
    for (uint32 i = 0; i < ctx->dbwr_count; i++) {
#ifndef WIN32
        ctx->dbwr[i].thread.closed = GS_TRUE;
        ctx->dbwr[i].dbwr_trigger = GS_TRUE;
        (void)sem_post(&ctx->dbwr[i].sem);
#endif
        cm_close_thread(&ctx->dbwr[i].thread);
    }
    cm_close_file(ctx->dw_file);
    ctx->dw_file = GS_INVALID_HANDLE;
#ifndef WIN32
    if (ctx->group.iocbs_buf != NULL) {
        free(ctx->group.iocbs_buf);
        ctx->group.iocbs_buf = NULL;
    }
#endif
}

static void ckpt_update_log_point(knl_session_t *session)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    rcy_context_t *rcy = &session->kernel->rcy_ctx;
    log_point_t last_point = session->kernel->redo_ctx.curr_point;

    /*
     * when recovering file in mount status, ckpt can't update log point because there are only dirty pages
     * of the file to recover in queue.
     */
    if (IS_FILE_RECOVER(session)) {
        return;
    }

    if (ctx->queue.count != 0) {
        cm_spin_lock(&ctx->queue.lock, &session->stat_ckpt_queue);
        core->rcy_point = ctx->queue.first->trunc_point;
        cm_spin_unlock(&ctx->queue.lock);
        return;
    }

    /* 
     * We can not directly set rcy_point to lrp_point when ckpt queue is empty.
     * Because it doesn't mean all dirty pages have been flushed to disk.
     * Only after database has finished recovery job can we set rcy_point to lrp_point,
     * which means database status is ready or recover_for_restore has been set to true.
     */
    if (!DB_NOT_READY(session) || session->kernel->db.recover_for_restore) {
        if (RCY_IGNORE_CORRUPTED_LOG(rcy) && last_point.lfn < ctx->lrp_point.lfn) {
            core->rcy_point = last_point;
            return;
        }

        /*
         * Logical logs do not generate dirty pages, so lfn of lrp_point could be less than trunc_point_snapshot_lfn
         * probablely. In this scenario, we should set rcy_point to lrp_point still.
         */
        if (DB_IS_READONLY(session) && ctx->trunc_point_snapshot.lfn < ctx->lrp_point.lfn) {
            core->rcy_point = ctx->trunc_point_snapshot;
            return;
        }

        core->rcy_point = ctx->lrp_point;
        core->consistent_lfn = ctx->lrp_point.lfn;
    }
}

void ckpt_reset_point(knl_session_t *session, log_point_t *point)
{
    knl_instance_t *kernel = session->kernel;
    core_ctrl_t *core = &kernel->db.ctrl.core;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

    core->rcy_point = *point;
    ctx->lrp_point = *point;
    core->lrp_point = *point;

    core->consistent_lfn = point->lfn;
}

/*
 * trigger full checkpoint to promote rcy point to current point
 */
static void ckpt_full_checkpoint(knl_session_t *session)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    ctx->batch_end = NULL;
    
    for (;;) {
        if (ctx->thread.closed) {
            break;
        }

        buf_ctrl_t *ckpt_first = ctx->queue.first;
        if (ctx->batch_end == NULL) {
            ctx->batch_end = ctx->queue.last;
        }

        if (ckpt_perform(session) != GS_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: redo log task flush redo file failed.");
        }

        ckpt_update_log_point(session);
        log_recycle_file(session, &core->rcy_point);

        /* backup some core ctrl info on datafile head */        
        if (ctrl_backup_core_log_info(session) != GS_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
        }

        /* maybe someone has been blocked by full ckpt when alloc buffer ctrl */
        if (ckpt_first == ctx->queue.first) {
            ckpt_page_clean(session);
        }

        if (ctx->batch_end != NULL) {
            continue;
        }

        if (db_save_core_ctrl(session) != GS_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }

        break;
    }
}

/*
 * trigger inc checkpoint to flush page on ckpt-q as soon as possible
 */
static void ckpt_inc_checkpoint(knl_session_t *session)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    
    if (ckpt_perform(session) != GS_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: redo log task flush redo file failed.");
    }

    ckpt_update_log_point(session);
    log_recycle_file(session, &core->rcy_point);

    /* backup some core info on datafile head: only back up core log info for full ckpt and timed task */
    if (NEED_SYNC_LOG_INFO(ctx) && ctrl_backup_core_log_info(session) != GS_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
    }

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
    }
}

static void ckpt_pop_page(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *ctrl)
{
    cm_spin_lock(&ctx->queue.lock, &session->stat_ckpt_queue);
    ctx->queue.count--;

    if (ctx->queue.count == 0) {
        ctx->queue.first = NULL;
        ctx->queue.last = NULL;
    } else {
        if (ctrl->ckpt_prev != NULL) {
            ctrl->ckpt_prev->ckpt_next = ctrl->ckpt_next;
        }

        if (ctrl->ckpt_next != NULL) {
            ctrl->ckpt_next->ckpt_prev = ctrl->ckpt_prev;
        }

        if (ctx->queue.last == ctrl) {
            ctx->queue.last = ctrl->ckpt_prev;
        }

        if (ctx->queue.first == ctrl) {
            ctx->queue.first = ctrl->ckpt_next;
        }
    }

    knl_panic_log(ctrl->in_ckpt == GS_TRUE, "ctrl is not in ckpt, panic info: page %u-%u type %u", ctrl->page_id.file,
                  ctrl->page_id.page, ctrl->page->type);
    ctrl->ckpt_prev = NULL;
    ctrl->ckpt_next = NULL;
    ctrl->in_ckpt = GS_FALSE;

    cm_spin_unlock(&ctx->queue.lock);
}

static void ckpt_assign_trigger_task(knl_session_t *session, trigger_task_t *task_desc)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint64_t snap_num = 0;
    
    /* To ensure the trigger_task action is valid, we use white list for debugging */
    knl_panic (CKPT_IS_TRIGGER(task_desc->mode));

    for (;;) {
        cm_spin_lock(&ctx->lock, &session->stat_ckpt);
        if (ctx->trigger_task == CKPT_MODE_IDLE && ctx->ckpt_enabled) {
            /* We don not assign inc trigger if there is full_trigger running or waiting */
            if (task_desc->mode != CKPT_TRIGGER_INC || ctx->full_trigger_active_num == 0) {
                snap_num = ctx->trigger_finish_num;
                ctx->trigger_task = task_desc->mode;    
                cm_spin_unlock(&ctx->lock);
                break; // sucess
            }
        }
        cm_spin_unlock(&ctx->lock);

        if (!task_desc->guarantee) {
            return;
        }

        if (task_desc->join && task_desc->mode == ctx->trigger_task) {
             /* task with join should not be set with wait, so directly return. */
            return;
        }
        
        /* We will try again until sucess.
         * Doing the next try when contition satisfied to decrease lock competition.
         */
        while (ctx->trigger_task != CKPT_MODE_IDLE || !ctx->ckpt_enabled) {
            cm_sleep(1);
        }
    }

    cm_release_cond_signal(&ctx->ckpt_cond); /* send a signal whatever */

    /* Wait for task finished.
     * Note that this is only meaningful for inc and full ckpt task,
     * while clean task always comes with no wait.
     */
    while (task_desc->wait && snap_num == ctx->trigger_finish_num) {
        cm_release_cond_signal(&ctx->ckpt_cond);
        cm_sleep(1);
    }    
}

static inline status_t ckpt_assign_timed_task (knl_session_t *session, ckpt_context_t *ctx, ckpt_mode_t mode)
{  
    knl_panic (mode == CKPT_TIMED_CLEAN || mode == CKPT_TIMED_INC);

    cm_spin_lock(&ctx->lock, &session->stat_ckpt);
    /* Using lock to ensure corretness in case another 
     * thread doing somthing with ckpt_enabled flag.
     */
    if (SECUREC_UNLIKELY(!ctx->ckpt_enabled)) {
        cm_spin_unlock(&ctx->lock);
        return GS_ERROR; 
    }
    ctx->timed_task = mode;
    cm_spin_unlock(&ctx->lock);    
    return GS_SUCCESS;
}

void ckpt_trigger(knl_session_t *session, bool32 wait, ckpt_mode_t mode)
{
    if (!DB_TO_RECOVERY(session)) {
        return;
    }

    /*
     * The task flags are set to achieve the effects of legacy use.
     * With guarantee flag, we will keep trying until successfully assign the task.
     */
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    trigger_task_t task;
    task.guarantee = GS_FALSE;
    task.join = GS_TRUE;
    task.wait = wait;

    if (mode == CKPT_TRIGGER_FULL) {
        task.guarantee = GS_TRUE;
        task.join = GS_FALSE;
        (void)cm_atomic_inc(&ctx->full_trigger_active_num);
    } 
    
    task.mode = mode;
    ckpt_assign_trigger_task(session, &task);
}

static void ckpt_do_trigger_task(knl_session_t *session, ckpt_context_t *ctx, date_t *clean_time, date_t *ckpt_time)
{ 
    if (ctx->trigger_task == CKPT_MODE_IDLE) {
        return;
    }

    uint64 task_begin = KNL_NOW(session);

    knl_panic (CKPT_IS_TRIGGER(ctx->trigger_task));
    
    switch (ctx->trigger_task) {
        case CKPT_TRIGGER_FULL:
            ckpt_full_checkpoint(session);

            (void)cm_atomic_dec(&ctx->full_trigger_active_num);
            *ckpt_time = KNL_NOW(session);
            break;
        case CKPT_TRIGGER_INC:
            ckpt_inc_checkpoint(session);
            *ckpt_time = KNL_NOW(session);
            break;
        case CKPT_TRIGGER_CLEAN:
            ckpt_page_clean(session);
            *clean_time = KNL_NOW(session);
            break;
        default:
            /* Not possible, for grammar compliance with switch clause */
            break;
    }

    uint64 task_end = KNL_NOW(session);
    ctx->stat.task_count[ctx->trigger_task]++;
    ctx->stat.task_us[ctx->trigger_task] += task_end - task_begin;

    cm_spin_lock(&ctx->lock, &session->stat_ckpt);
    ctx->trigger_finish_num++;
    ctx->trigger_task = CKPT_MODE_IDLE;
    cm_spin_unlock(&ctx->lock);
}


static void ckpt_do_timed_task(knl_session_t *session, ckpt_context_t *ctx, date_t *clean_time, date_t *ckpt_time)
{
    knl_attr_t *attr = &session->kernel->attr;

    if (attr->page_clean_period != 0 &&
        KNL_NOW(session) - (*clean_time) >= (date_t)attr->page_clean_period * MICROSECS_PER_SECOND) {
        if (ckpt_assign_timed_task(session, ctx, CKPT_TIMED_CLEAN) == GS_SUCCESS) {
            date_t task_begin = KNL_NOW(session);

            ckpt_page_clean(session);
            *clean_time = KNL_NOW(session);
            ctx->timed_task = CKPT_MODE_IDLE;

            date_t task_end = KNL_NOW(session);
            ctx->stat.task_count[CKPT_TIMED_CLEAN]++;
            ctx->stat.task_us[CKPT_TIMED_CLEAN] += task_end - task_begin;
        }
    }

    if (ctx->queue.count >= attr->ckpt_interval ||
        KNL_NOW(session) - (*ckpt_time) >= (date_t)attr->ckpt_timeout * MICROSECS_PER_SECOND) {
        if (ckpt_assign_timed_task(session, ctx, CKPT_TIMED_INC) == GS_SUCCESS) {
            date_t task_begin = KNL_NOW(session);

            ckpt_inc_checkpoint(session);
            *ckpt_time = KNL_NOW(session);
            ctx->timed_task = CKPT_MODE_IDLE;

            date_t task_end = KNL_NOW(session);
            ctx->stat.task_count[CKPT_TIMED_INC]++;
            ctx->stat.task_us[CKPT_TIMED_INC] += task_end - task_begin;
        }
    }
}

/* 
 * ckpt thread handles buffer page clean and full/inc ckpt on following condition:
 * 1.trigger of page clean, inc/full ckpt. 
 * 2.page clean or inc ckpt timeout.
 * 3.count of dirty pages on ckpt queue is up to threshold. 
 */
void ckpt_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    knl_attr_t *attr = &session->kernel->attr;
    date_t ckpt_time = 0;
    date_t clean_time = 0;

    cm_set_thread_name("ckpt");
    GS_LOG_RUN_INF("ckpt thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    
    while (!thread->closed) {
        /* If the database has come to recovery stage, we will break and go to normal schedul once
         * a trigger task is received.
         */
        if (DB_TO_RECOVERY(session) && ctx->trigger_task != CKPT_MODE_IDLE) {
            break;
        }
        cm_sleep(CKPT_WAIT_MS);
    }

    while (!thread->closed) {
        ckpt_do_trigger_task(session, ctx, &clean_time, &ckpt_time);
        ckpt_do_timed_task(session, ctx, &clean_time, &ckpt_time);

        /* quickly go to the next schdule if there is trigger task */
        if (ctx->trigger_task != CKPT_MODE_IDLE) {
            continue;
        }

         /* For performance consideration,  we may don't want the timed task runing too frequently
          * in large-memory environment.
          * So we wait for a short time (default to 100ms with parameter), in which we can still
          * respond trigger task.
          * If one want the time task scheduled timely, he can set the parameter to 0.
          */
        uint32 timed_task_delay_ms = session->kernel->attr.ckpt_timed_task_delay;
        (void)cm_wait_cond(&ctx->ckpt_cond, timed_task_delay_ms);
        if (ctx->trigger_task != CKPT_MODE_IDLE) {
            continue;
        }

        /* Quicly go the next schedul if dirty queue satisfies timed schedule */
        if (ctx->queue.count >= attr->ckpt_interval && ctx->ckpt_enabled) {
            continue;
        }

        /*
         * Using condition wait may missing the singal, but can avoid stucking with
         * disordered system time and always return on time out.
         * Besides, we can keep on releasing signal after triggering to make sure
         * the signal is not missed.
         */
        (void)cm_wait_cond(&ctx->ckpt_cond, CKPT_WAIT_MS);
        ctx->stat.proc_wait_cnt++;
    }

    GS_LOG_RUN_INF("ckpt thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

static bool32 ckpt_try_latch_ctrl(knl_session_t *session, buf_ctrl_t *ctrl)
{
    uint32 times = 0;
    uint32 wait_ticks = 0;

    for (;;) {
        while (ctrl->is_readonly) {
            if (wait_ticks >= CKPT_LATCH_WAIT) {
                return GS_FALSE;
            }

            times++;
            if (times > GS_SPIN_COUNT) {
                cm_spin_sleep();
                times = 0;
                wait_ticks++;
                return GS_FALSE;
            }
        }

        // in checkpoint, we don't increase the ref_num.
        if (!buf_latch_timed_s(session, ctrl, CKPT_LATCH_TIMEOUT, GS_FALSE, GS_TRUE)) {
            return GS_FALSE;
        }

        if (!ctrl->is_readonly) {
            return GS_TRUE;
        }
        buf_unlatch(session, ctrl, GS_FALSE);
    }
}

static status_t ckpt_checksum(knl_session_t *session, ckpt_context_t *ctx)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    page_head_t *page = (page_head_t *)(ctx->group.buf + DEFAULT_PAGE_SIZE * ctx->group.count);

    if (cks_level == (uint32)CKS_FULL) {
        if (PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE) != GS_INVALID_CHECKSUM 
            && !page_verify_checksum(page, DEFAULT_PAGE_SIZE)) {
            GS_LOG_RUN_ERR("[CKPT] page corrupted(file %u, page %u).checksum level %s, page size %u, cks %u",
                AS_PAGID_PTR(page->id)->file, AS_PAGID_PTR(page->id)->page, knl_checksum_level(cks_level),
                PAGE_SIZE(*page), PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE));
            return GS_ERROR;
        }
    } else if (cks_level == (uint32)CKS_OFF) {
        PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE) = GS_INVALID_CHECKSUM;
    } else {
        page_calc_checksum(page, DEFAULT_PAGE_SIZE);
    }

    return GS_SUCCESS;
}

static uint32 ckpt_get_neighbors(knl_session_t *session, buf_ctrl_t *ctrl, page_id_t *first)
{
    knl_attr_t *attr = &session->kernel->attr;
    datafile_t *df = NULL;
    space_t *space = NULL;
    page_id_t page_id;
    uint32 start_id, load_count;

    *first = ctrl->page_id;

    if (!attr->ckpt_flush_neighbors) {
        return 1;
    }

    if (ctrl->page->type == PAGE_TYPE_UNDO) {
        return UNDO_PREFETCH_NUM;
    }

    page_id = ctrl->page_id;
    df = DATAFILE_GET(page_id.file);
    space = SPACE_GET(df->space_id);
    start_id = spc_first_extent_id(session, space, page_id);
    if (page_id.page >= start_id) {
        first->page = page_id.page - ((page_id.page - start_id) % space->ctrl->extent_size);
        first->aligned = 0;
        load_count = MAX(space->ctrl->extent_size, BUF_MAX_PREFETCH_NUM / 2);
    } else {
        load_count = 1;
    }

    return load_count;
}

static inline bool32 page_encrypt_enable(knl_session_t *session, space_t *space, page_head_t *page)
{
    if (page->type == PAGE_TYPE_UNDO) {
        return undo_valid_encrypt(session, page);
    }

    if (SPACE_IS_ENCRYPT(space) && page_type_suport_encrypt(page->type)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

static status_t ckpt_encrypt(knl_session_t *session, ckpt_context_t *ctx)
{
    page_head_t *page = (page_head_t *)(ctx->group.buf + DEFAULT_PAGE_SIZE * ctx->group.count);
    space_t *space = SPACE_GET(DATAFILE_GET(AS_PAGID_PTR(page->id)->file)->space_id);
    if (!page_encrypt_enable(session, space, page)) {
        return GS_SUCCESS;
    }

    if (page_encrypt(session, page, space->ctrl->encrypt_version, space->ctrl->cipher_reserve_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

#ifdef LOG_DIAG
static status_t ckpt_verify_decrypt(knl_session_t *session, ckpt_context_t *ctx)
{
    page_head_t *page = (page_head_t *)(ctx->group.buf + DEFAULT_PAGE_SIZE * ctx->group.count);
    page_id_t page_id = AS_PAGID(page->id);
    space_t *space = SPACE_GET(DATAFILE_GET(page_id.file)->space_id);

    char *copy_page = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE);
    errno_t ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE, page, DEFAULT_PAGE_SIZE);
    knl_securec_check(ret);

    if (((page_head_t *)copy_page)->encrypted) {
        if (page_decrypt(session, (page_head_t *)copy_page) != GS_SUCCESS) {
            knl_panic_log(0, "decrypt verify failed![AFTER ENCRYPT]AFTER CKPT CHECKSUM! ,DECRYPT IMMEDEATLY ERROR: "
                "page_info: page %u, file %u, page_type %u, encrypted %u,"
                "space->ctrl->cipher_reserve_size: %u ",
                page_id.page, page_id.file, page->type, page->encrypted, space->ctrl->cipher_reserve_size);
        }
    }
    cm_pop(session->stack);
    return GS_SUCCESS;
}
#endif

void ckpt_unlatch_group(knl_session_t *session, page_id_t first, uint32 start, uint32 end)
{
    page_id_t page_id;
    buf_ctrl_t *to_flush_ctrl = NULL;

    page_id.file = first.file;

    for (uint32 i = start; i < end; i++) {
        page_id.page = first.page + i;
        to_flush_ctrl = buf_find_by_pageid(session, page_id);
        knl_panic_log(to_flush_ctrl != NULL, "ctrl missed in buffer, panic info: group head %u-%u, missed %u-%u", 
            first.file, first.page, first.file, first.page + i);
        buf_unlatch(session, to_flush_ctrl, GS_FALSE);
    }
}

page_id_t page_first_group_id(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = DATAFILE_GET(page_id.file);
    space_t *space = SPACE_GET(df->space_id);
    page_id_t first;
    uint32 start_id;

    start_id = spc_first_extent_id(session, space, page_id);

    knl_panic_log(page_id.page >= start_id, "page %u-%u before space first extent %u-%u", page_id.file, page_id.page, 
        page_id.file, start_id);
    first.page = page_id.page - ((page_id.page - start_id) % PAGE_GROUP_COUNT);
    first.file = page_id.file;
    first.aligned = 0;

    return first;
}

bool32 buf_group_compressible(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_ctrl_t *to_compress_ctrl = NULL;
    page_id_t first, page_id;

    first = page_first_group_id(session, ctrl->page_id);
    if (!IS_SAME_PAGID(first, ctrl->page_id)) {
        GS_LOG_RUN_ERR("group incompressible, first: %d-%d != current: %d-%d", first.file, first.page,
            ctrl->page_id.file, ctrl->page_id.page);
        return GS_FALSE;
    }

    page_id.file = first.file;
    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        page_id.page = first.page + i;
        to_compress_ctrl = buf_find_by_pageid(session, page_id);
        /* as a page group is alloc and release as a whole, so we consider a page group
         * which members are not all in buffer is incompressible */
        if (to_compress_ctrl == NULL || !page_compress(session, to_compress_ctrl->page_id)) {
            GS_LOG_RUN_ERR("group incompressible, member: %d-0x%llx, current: %d-%d", i, (uint64)to_compress_ctrl,
                ctrl->page_id.file, ctrl->page_id.page);
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

bool32 ckpt_try_latch_group(knl_session_t *session, buf_ctrl_t *ctrl)
{
    buf_ctrl_t *to_compress_ctrl = NULL;
    page_id_t first, page_id;

    first = page_first_group_id(session, ctrl->page_id);
    page_id.file = first.file;

    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        page_id.page = first.page + i;
        to_compress_ctrl = buf_find_by_pageid(session, page_id);
        /* in the following scenario, ctrl may be null 
         * 1.for noread, PAGE_GROUP_COUNT's pages are added to segment in log_atomic_op
         * 2.page is reused, PAGE_GROUP_COUNT's pages are formatted in log_atomic_op 
         * so we consider group has NULL member as an exception */
        knl_panic_log(to_compress_ctrl != NULL, "ctrl missed in buffer, panic info: group head %u-%u, missed %u-%u",
            first.file, first.page, first.file, first.page + i);
        if (!ckpt_try_latch_ctrl(session, to_compress_ctrl)) {
            ckpt_unlatch_group(session, first, 0, i);
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}
 
static void ckpt_copy_item(knl_session_t *session, buf_ctrl_t *ctrl, buf_ctrl_t *to_flush_ctrl)
{
    gbp_context_t *gbp_ctx = &session->kernel->gbp_context;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 gbp_lock_id = GS_INVALID_ID32;
    errno_t ret;

    /* concurrent with knl_read_page_from_gbp when buf_enter_page with LATCH_S lock */
    if (SECUREC_UNLIKELY(KNL_RECOVERY_WITH_GBP(session->kernel))) {
        gbp_lock_id = ctrl->page_id.page % GS_GBP_RD_LOCK_COUNT;
        cm_spin_lock(&gbp_ctx->buf_read_lock[gbp_lock_id], NULL);
    }

    knl_panic_log(IS_SAME_PAGID(to_flush_ctrl->page_id, AS_PAGID(to_flush_ctrl->page->id)),
        "to_flush_ctrl's page_id and to_flush_ctrl page's id are not same, panic info: page_id %u-%u type %u, "
        "page id %u-%u type %u", to_flush_ctrl->page_id.file, to_flush_ctrl->page_id.page,
        to_flush_ctrl->page->type, AS_PAGID(to_flush_ctrl->page->id).file,
        AS_PAGID(to_flush_ctrl->page->id).page, to_flush_ctrl->page->type);
    knl_panic_log(CHECK_PAGE_PCN(to_flush_ctrl->page), "page pcn is abnormal, panic info: page %u-%u type %u",
        to_flush_ctrl->page_id.file, to_flush_ctrl->page_id.page, to_flush_ctrl->page->type);

    /* this is not accurate, does not matter */
    if (ctx->trunc_lsn < to_flush_ctrl->page->lsn) {
        ctx->trunc_lsn = to_flush_ctrl->page->lsn;
    }

    if (ctx->consistent_lfn < to_flush_ctrl->lastest_lfn) {
        ctx->consistent_lfn = to_flush_ctrl->lastest_lfn;
    }

    /* DEFAULT_PAGE_SIZE is 8192,  ctx->group.count <= GS_CKPT_GROUP_SIZE(4096), integers cannot cross bounds */
    ret = memcpy_sp(ctx->group.buf + DEFAULT_PAGE_SIZE * ctx->group.count, DEFAULT_PAGE_SIZE,
        to_flush_ctrl->page, DEFAULT_PAGE_SIZE);
    knl_securec_check(ret);

    if (SECUREC_UNLIKELY(gbp_lock_id != GS_INVALID_ID32)) {
        cm_spin_unlock(&gbp_ctx->buf_read_lock[gbp_lock_id]);
        gbp_lock_id = GS_INVALID_ID32;
    }

    if (to_flush_ctrl == ctx->batch_end) {
        ctx->batch_end = to_flush_ctrl->ckpt_prev;
    }

    if (to_flush_ctrl->in_ckpt) {
        ckpt_pop_page(session, ctx, to_flush_ctrl);
    }

    to_flush_ctrl->is_marked = 1;
    CM_MFENCE;
    to_flush_ctrl->is_dirty = 0;

    ctx->group.items[ctx->group.count].ctrl = to_flush_ctrl;
    ctx->group.items[ctx->group.count].buf_id = ctx->group.count;
    ctx->group.items[ctx->group.count].need_punch = GS_FALSE;
}

static status_t ckpt_ending_prepare(knl_session_t *session, ckpt_context_t *ctx)
{   
    /* must before checksum calc */
    if (ckpt_encrypt(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (ckpt_checksum(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }
#ifdef LOG_DIAG
    if (ckpt_verify_decrypt(session, ctx) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("ERROR: ckpt verify decrypt failed. ");
        return GS_ERROR;
    }
#endif

    return GS_SUCCESS;
}

static status_t ckpt_prepare_compress(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *curr_ctrl,
    buf_ctrl_t *ctrl_next, bool8 *ctrl_next_is_flushed, bool8 *need_exit)
{
    page_id_t first_page_id, to_flush_pageid;
    buf_ctrl_t *to_flush_ctrl = NULL;

    ctx->has_compressed = GS_TRUE;

    if (ctx->group.count + PAGE_GROUP_COUNT > GS_CKPT_GROUP_SIZE) {
        *need_exit = GS_TRUE;
        return GS_SUCCESS;
    }

    if (!ckpt_try_latch_group(session, curr_ctrl)) {
        return GS_SUCCESS;
    }

    first_page_id = page_first_group_id(session, curr_ctrl->page_id);
    to_flush_pageid = first_page_id;
    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        to_flush_pageid.page = first_page_id.page + i;

        /* get ctrl */
        if (IS_SAME_PAGID(to_flush_pageid, curr_ctrl->page_id)) {
            to_flush_ctrl = curr_ctrl;
        } else {
            to_flush_ctrl = buf_find_by_pageid(session, to_flush_pageid);
        }

        /* not a flushable page */
        if (to_flush_ctrl == NULL) {
            continue;
        }

        /* we should retain items for clean pages in page group, as a result, it may lead to lower io capacity */
        if (to_flush_ctrl->is_marked) {
            /* this ctrl has been added to ckpt group, so skip it */
            if (to_flush_ctrl->in_ckpt == GS_FALSE) {
                buf_unlatch(session, to_flush_ctrl, GS_FALSE);
                continue;
            }
            ckpt_unlatch_group(session, first_page_id, i, PAGE_GROUP_COUNT);
            *need_exit = GS_TRUE;
            return GS_SUCCESS;
        }

        ckpt_copy_item(session, curr_ctrl, to_flush_ctrl);

        if (to_flush_ctrl == ctrl_next) {
            *ctrl_next_is_flushed = GS_TRUE;
        }

        buf_unlatch(session, to_flush_ctrl, GS_FALSE);

        if (ckpt_ending_prepare(session, ctx) != GS_SUCCESS) {
            ckpt_unlatch_group(session, first_page_id, i + 1, PAGE_GROUP_COUNT);
            return GS_ERROR;
        }

        ctx->group.count++;

        if (ctx->group.count >= GS_CKPT_GROUP_SIZE) {
            *need_exit = GS_TRUE;
            return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

static status_t ckpt_prepare_normal(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *curr_ctrl,
    buf_ctrl_t *ctrl_next, bool8 *ctrl_next_is_flushed, bool8 *need_exit)
{
    page_id_t first_page_id, to_flush_pageid;
    buf_ctrl_t *to_flush_ctrl = NULL;
    uint32 count;

    ctx->stat.ckpt_total_neighbors_times++;
    ctx->stat.ckpt_curr_neighbors_times++;

    count = ckpt_get_neighbors(session, curr_ctrl, &first_page_id);
    to_flush_pageid = first_page_id;
    for (uint16 i = 0; i < count; i++) {
        to_flush_pageid.page = first_page_id.page + i;

        /* get ctrl */
        if (IS_SAME_PAGID(to_flush_pageid, curr_ctrl->page_id)) {
            to_flush_ctrl = curr_ctrl;
        } else {
            to_flush_ctrl = buf_find_by_pageid(session, to_flush_pageid);
        }

        /* not a flushable page */
        if (to_flush_ctrl == NULL || to_flush_ctrl->in_ckpt == GS_FALSE) {
            continue;
        }

        /* skip compress page when flush non-compress page's neighbors */
        if (page_compress(session, to_flush_ctrl->page_id)) {
            continue;
        }

        if (!ckpt_try_latch_ctrl(session, to_flush_ctrl)) {
            continue;
        }

        /*
        * added to ckpt->queue again during we flush it,
        * end this prepare, we can not handle two copies of same page
        */
        if (to_flush_ctrl->is_marked) {
            buf_unlatch(session, to_flush_ctrl, GS_FALSE);
            *need_exit = GS_TRUE;
            return GS_SUCCESS;
        }

        ckpt_copy_item(session, curr_ctrl, to_flush_ctrl);

        if (to_flush_ctrl == ctrl_next) {
            *ctrl_next_is_flushed = GS_TRUE;
        }

        buf_unlatch(session, to_flush_ctrl, GS_FALSE);

        if (ckpt_ending_prepare(session, ctx) != GS_SUCCESS) {
            return GS_ERROR;
        }

        ctx->stat.ckpt_total_neighbors_len++;
        ctx->stat.ckpt_curr_neighbors_len++;
        ctx->group.count++;

        if (ctx->group.count >= GS_CKPT_GROUP_SIZE) {
            *need_exit = GS_TRUE;
            return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

status_t ckpt_prepare_pages(knl_session_t *session, ckpt_context_t *ctx)
{
    buf_ctrl_t *ctrl_next = NULL;
    buf_ctrl_t *ctrl = ctx->queue.first;
    bool8 ctrl_next_is_flushed = GS_FALSE;
    bool8 need_exit = GS_FALSE;

    if (ctx->queue.count == 0) {
        return GS_SUCCESS;
    }

    ctx->trunc_lsn = 0;
    ctx->consistent_lfn = 0;
    ctx->has_compressed = GS_FALSE;
    ctx->stat.ckpt_curr_neighbors_times = 0;
    ctx->stat.ckpt_curr_neighbors_len = 0;

    while (ctrl != NULL) {
        ctrl_next = ctrl->ckpt_next;
        ctrl_next_is_flushed = GS_FALSE;
        if (page_compress(session, ctrl->page_id)) {
            if (ckpt_prepare_compress(session, ctx, ctrl, ctrl_next, &ctrl_next_is_flushed, &need_exit) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (ckpt_prepare_normal(session, ctx, ctrl, ctrl_next, &ctrl_next_is_flushed, &need_exit) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (need_exit) {
            break;
        }

        ctrl = ctrl_next_is_flushed ? ctx->queue.first : ctrl_next;
    }

    if (ctx->stat.ckpt_curr_neighbors_times != 0) {
        ctx->stat.ckpt_last_neighbors_len = (ctx->stat.ckpt_curr_neighbors_len / ctx->stat.ckpt_curr_neighbors_times);
    }

    return GS_SUCCESS;
}

static inline void ckpt_unlatch_datafiles(datafile_t **df, uint32 count)
{
    for (uint32 i = 0; i < count; i++) {
        cm_unlatch(&df[i]->block_latch, NULL);
    }
}

static void ckpt_latch_datafiles(datafile_t **df, uint64 *offset, int32 size, uint32 count)
{
    uint64 end_pos = 0;
    uint32 i = 0;
    for (;;) {
        for (i = 0; i < count; i++) {
            end_pos = offset[i] + (uint64)size;

            if (!cm_latch_timed_s(&df[i]->block_latch, 1, GS_FALSE, NULL)) {
                /* latch fail need release them and try again from first page */
                ckpt_unlatch_datafiles(df, i);
                cm_sleep(1);
                break;
            }
            if (spc_datafile_is_blocked(df[i], (uint64)offset[i], end_pos)) {
                /* one page is backing up, need try again from fisrt page */
                ckpt_unlatch_datafiles(df, i + 1);
                cm_sleep(1);
                break;
            }
        }
        if (i == count) {
            return;
        }
    }
}

void dbwr_compress_checksum(knl_session_t *session, page_head_t *page)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;

    if (cks_level == (uint32)CKS_OFF) {
        COMPRESS_PAGE_HEAD(page)->checksum = GS_INVALID_CHECKSUM;
    } else {
        page_compress_calc_checksum(page, DEFAULT_PAGE_SIZE);
    }
}

static void dbwr_construct_group(knl_session_t *session, dbwr_context_t *dbwr, uint32 begin, 
    uint32 compressed_size, const char *zbuf)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 remaining_size, actual_size, zsize;
    page_head_t *page = NULL;
    buf_ctrl_t *ctrl = NULL;
    uint32 buf_id;
    uint32 offset;
    uint32 slot;
    errno_t ret;

    remaining_size = compressed_size;
    
    /* +---------+----------+---------------------+
    *  |page_head|group_head| zip data            |
    *  +---------+----------+---------------------+
    *  */
    slot = begin;
    zsize = COMPRESS_PAGE_VALID_SIZE;
    offset = 0;
    do {
        if (remaining_size > zsize) {
            actual_size = zsize;
        } else {
            actual_size = remaining_size;
        }

        ctrl = ctx->group.items[slot].ctrl;
        buf_id = ctx->group.items[slot].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE);
        ret = memcpy_sp((char *)page + DEFAULT_PAGE_SIZE - zsize, actual_size, (char *)zbuf + offset, actual_size);
        knl_securec_check(ret);
        knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(page->id)), "the ctrl's page_id and page->id are not same, "
            "panic info: ctrl page %u-%u type %u curr page %u-%u", ctrl->page_id.file, ctrl->page_id.page, page->type,
            AS_PAGID(page->id).file, AS_PAGID(page->id).page);
        knl_panic_log(page_compress(session, AS_PAGID(page->id)), "the page is incompressible, panic info: "
            "type %u curr page %u-%u", page->type, AS_PAGID(page->id).file, AS_PAGID(page->id).page);
        COMPRESS_PAGE_HEAD(page)->compressed_size = compressed_size;
        COMPRESS_PAGE_HEAD(page)->compress_algo = COMPRESS_ZSTD;
        COMPRESS_PAGE_HEAD(page)->group_cnt = GROUP_COUNT_8;
        COMPRESS_PAGE_HEAD(page)->unused = 0;
        page->compressed = 1;
        dbwr_compress_checksum(session, page);
        remaining_size -= actual_size;
        offset += actual_size;
        slot++;
    } while (remaining_size != 0);

    while (slot <= begin + PAGE_GROUP_COUNT - 1) {
        ctx->group.items[slot].need_punch = GS_TRUE;
        ctrl = ctx->group.items[slot].ctrl;
        knl_panic_log(page_compress(session, ctrl->page_id), "the page is incompressible, panic info: "
            "curr page %u-%u", ctrl->page_id.file, ctrl->page_id.page);
        slot++;
    }
}

static status_t dbwr_compress_group(knl_session_t *session, dbwr_context_t *dbwr, uint32 begin, char *zbuf, char *src)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    page_head_t *page = NULL;
    uint32 buf_id;
    uint32 compressed_size;
    errno_t ret;

    for (uint16 i = 0; i < PAGE_GROUP_COUNT; i++) {
        buf_id = ctx->group.items[i + begin].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE);
        ret = memcpy_sp(src + DEFAULT_PAGE_SIZE * i, DEFAULT_PAGE_SIZE, page, DEFAULT_PAGE_SIZE);
        knl_securec_check(ret);
    }
    compressed_size = ZSTD_compress((char *)zbuf, DEFAULT_PAGE_SIZE * PAGE_GROUP_COUNT, src,
        DEFAULT_PAGE_SIZE * PAGE_GROUP_COUNT, ZSTD_DEFAULT_COMPRESS_LEVEL);
    if (ZSTD_isError(compressed_size)) {
        GS_THROW_ERROR(ERR_COMPRESS_ERROR, "zstd", compressed_size, ZSTD_getErrorName(compressed_size));
        return GS_ERROR;
    }

    if (SECUREC_LIKELY(compressed_size <= COMPRESS_GROUP_VALID_SIZE)) {
        dbwr_construct_group(session, dbwr, begin, compressed_size, zbuf);
    }

    return GS_SUCCESS;
}

/* we devide ckpt group into two groups,one is pages which would be punched,the other is pages wihch would be submit */
static status_t dbwr_compress_prepare(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    page_head_t *page = NULL;
    uint32 buf_id;
    uint32 skip_cnt;
    errno_t ret;
    pcb_assist_t src_pcb_assist;
    pcb_assist_t zbuf_pcb_assist;
    uint16 i;

    if (pcb_get_buf(session, &src_pcb_assist) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (pcb_get_buf(session, &zbuf_pcb_assist) != GS_SUCCESS) {
        pcb_release_buf(session, &src_pcb_assist);
        return GS_ERROR;
    }

    ret = memset_sp(zbuf_pcb_assist.aligned_buf, DEFAULT_PAGE_SIZE * PAGE_GROUP_COUNT, 0, 
        DEFAULT_PAGE_SIZE * PAGE_GROUP_COUNT);
    knl_securec_check(ret);

    for (i = dbwr->begin; i <= dbwr->end; i = i + skip_cnt) {
        buf_id = ctx->group.items[i].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE);
        skip_cnt = 1;
        if (!page_compress(session, AS_PAGID(page->id))) {
            continue;
        }
        knl_panic(AS_PAGID(page->id).page % PAGE_GROUP_COUNT == 0);
        if (dbwr_compress_group(session, dbwr, i, zbuf_pcb_assist.aligned_buf, 
            src_pcb_assist.aligned_buf) != GS_SUCCESS) {
            pcb_release_buf(session, &src_pcb_assist);
            pcb_release_buf(session, &zbuf_pcb_assist);
            return GS_ERROR;
        }
        skip_cnt = PAGE_GROUP_COUNT;
    }

    pcb_release_buf(session, &src_pcb_assist);
    pcb_release_buf(session, &zbuf_pcb_assist);
    return GS_SUCCESS;
}

static status_t dbwr_async_io_write(knl_session_t *session, cm_aio_iocbs_t *aio_cbs, ckpt_context_t *ctx,
                                    dbwr_context_t *dbwr, uint32 size)
{
    struct timespec timeout = { 0, 200 };
    int32 aio_ret;
    uint32 buf_id, cb_id;
    page_head_t *page = NULL;
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    cm_aio_lib_t *lib_ctx = &session->kernel->aio_lib;
    int32 event_num = (int32)dbwr->io_cnt;
    ckpt_sort_item *item = NULL;
    cb_id = 0;
    uint32 idx = 0;
    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        item = &ctx->group.items[i];
        if (item->need_punch) {
            if (cm_file_punch_hole(*asyncio_ctx->handles[idx], (int64)asyncio_ctx->offsets[idx], size) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[CKPT] failed to punch datafile %s", asyncio_ctx->datafiles[idx]->ctrl->name);
                return GS_ERROR;
            }
        } else {
            buf_id = ctx->group.items[i].buf_id;
            page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * size);
            knl_panic(item->ctrl != NULL);
            knl_panic(IS_SAME_PAGID(item->ctrl->page_id, AS_PAGID(page->id)));
            aio_cbs->iocb_ptrs[cb_id] = &aio_cbs->iocbs[cb_id];
            cm_aio_prep_write(aio_cbs->iocb_ptrs[cb_id], *asyncio_ctx->handles[idx], (void *)page, size, 
                              (int64)asyncio_ctx->offsets[idx]);
            knl_panic(asyncio_ctx->offsets[idx] == (uint64)item->ctrl->page_id.page * PAGE_SIZE(*page));
            cb_id++;
        }
        idx++;
    }
    knl_panic(cb_id == dbwr->io_cnt);
    aio_ret = lib_ctx->io_submit(dbwr->async_ctx.aio_ctx, (long)event_num, aio_cbs->iocb_ptrs);
    if (aio_ret != event_num) {
        return GS_ERROR;
    }

    while (event_num > 0) {
        aio_ret = lib_ctx->io_getevents(dbwr->async_ctx.aio_ctx, 1, event_num, aio_cbs->events, &timeout);
        if (aio_ret < 0) {
            if (errno == EINTR || aio_ret == -EINTR) {
                continue;
            }
            return GS_ERROR;
        }
        event_num = event_num - aio_ret;
    }
    return GS_SUCCESS;
}

static status_t dbwr_flush_async_io(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_asyncio_ctx_t *asyncio_ctx = &dbwr->async_ctx;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    page_id_t *page_id = NULL;
    page_head_t *page = NULL;
    uint32 buf_offset, buf_id;
    cm_aio_iocbs_t aio_cbs;
    ckpt_sort_item *item = NULL;

    if (ctx->has_compressed) {
        if (dbwr_compress_prepare(session, dbwr) != GS_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if (err_code != ERR_ALLOC_MEMORY) {
                return GS_ERROR;
            }
            /* if there is not enough memory, no compression is performed */
            cm_reset_error();
        }
    }

    dbwr->io_cnt = dbwr->end - dbwr->begin + 1; // page count need to io ,init by all page count first. 
    uint32 latch_cnt = 0; // to recode page count need to latch.
    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        buf_id = ctx->group.items[i].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE);
        item = &ctx->group.items[i];
        if (item->need_punch) {
            dbwr->io_cnt--; // remove punch hole page count from all page count.  
        }
        knl_panic(item->ctrl != NULL);
        knl_panic(IS_SAME_PAGID(item->ctrl->page_id, AS_PAGID(page->id)));

        page_id = AS_PAGID_PTR(page->id);
        asyncio_ctx->datafiles[latch_cnt] = DATAFILE_GET(page_id->file);
        asyncio_ctx->handles[latch_cnt] = &dbwr->datafiles[page_id->file];
        asyncio_ctx->offsets[latch_cnt] = (uint64)page_id->page * DEFAULT_PAGE_SIZE;
        knl_panic(page_compress(session, AS_PAGID(page)) || CHECK_PAGE_PCN(page));

        if (spc_open_datafile(session, asyncio_ctx->datafiles[latch_cnt], 
            asyncio_ctx->handles[latch_cnt]) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[CKPT] failed to open datafile %s", asyncio_ctx->datafiles[latch_cnt]->ctrl->name);
            return GS_ERROR;
        }
        latch_cnt++;
    }

    buf_offset = dbwr->begin * CM_IOCB_LENTH;
    aio_cbs.iocbs = (cm_iocb_t *)(ctx->group.iocbs_buf + buf_offset);
    buf_offset += sizeof(cm_iocb_t) * dbwr->io_cnt;
    aio_cbs.events = (cm_io_event_t*)(ctx->group.iocbs_buf + buf_offset);
    buf_offset += sizeof(cm_io_event_t) * dbwr->io_cnt;
    aio_cbs.iocb_ptrs = (cm_iocb_t**)(ctx->group.iocbs_buf + buf_offset);

    ckpt_latch_datafiles(asyncio_ctx->datafiles, asyncio_ctx->offsets, DEFAULT_PAGE_SIZE, latch_cnt);
    if (dbwr_async_io_write(session, &aio_cbs, ctx, dbwr, DEFAULT_PAGE_SIZE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[CKPT] failed to write datafile by async io");
        ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt);
        return GS_ERROR;
    }
    ckpt_unlatch_datafiles(asyncio_ctx->datafiles, latch_cnt);

    for (uint16 i = dbwr->begin; i <= dbwr->end; i++) {
        ctx->group.items[i].ctrl->is_marked = 0;
    }

    return GS_SUCCESS;
}

static status_t ckpt_double_write(knl_session_t *session, ckpt_context_t *ctx)
{
    database_t *db = &session->kernel->db;
    datafile_t *df = DATAFILE_GET(db->ctrl.core.dw_file_id);
    core_ctrl_t *core = &db->ctrl.core;
    timeval_t tv_begin, tv_end;
    int64 offset;

    (void)cm_gettimeofday(&tv_begin);

    if (ctx->dw_ckpt_start + ctx->group.count > DW_DISTRICT_END) {
        ctx->dw_ckpt_start = DW_DISTRICT_BEGIN;
    }

    ctx->dw_ckpt_end = ctx->dw_ckpt_start + ctx->group.count;
    knl_panic(ctx->dw_ckpt_start >= DW_DISTRICT_BEGIN);
    knl_panic(ctx->dw_ckpt_end <= DW_DISTRICT_END);
    knl_panic(df->file_no == 0);  // first sysaux file

    offset = (uint64)ctx->dw_ckpt_start * DEFAULT_PAGE_SIZE;
    /* DEFAULT_PAGE_SIZE is 8192, ctx->group.count <= GS_CKPT_GROUP_SIZE(4096), can not cross bounds */
    if (spc_write_datafile(session, df, &ctx->dw_file, offset, ctx->group.buf,
                           ctx->group.count * DEFAULT_PAGE_SIZE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
        return GS_ERROR;
    }

    if (db_fdatasync_file(session, ctx->dw_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[CKPT] failed to fdatasync datafile %s", (char *)DATAFILE_GET(0));
        return GS_ERROR;
    }

    cm_spin_lock(&db->ctrl_lock, NULL);
    core->dw_start = ctx->dw_ckpt_start;
    core->dw_end = ctx->dw_ckpt_end;
    cm_spin_unlock(&db->ctrl_lock);

    (void)cm_gettimeofday(&tv_end);
    ctx->stat.double_writes++;
    ctx->stat.double_write_time += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);

    return GS_SUCCESS;
}

static int32 ckpt_buforder_comparator(const void *pa, const void *pb)
{
    const ckpt_sort_item *a = (const ckpt_sort_item *) pa;
    const ckpt_sort_item *b = (const ckpt_sort_item *) pb;

    /* compare fileid */
    if (a->ctrl->page_id.file < b->ctrl->page_id.file) {
        return -1;
    } else if (a->ctrl->page_id.file > b->ctrl->page_id.file) {
        return 1;
    }

    /* compare page */
    if (a->ctrl->page_id.page < b->ctrl->page_id.page) {
        return -1;
    } else if (a->ctrl->page_id.page > b->ctrl->page_id.page) {
        return 1;
    }

    /* equal pageid is impossible */
    return 0;
}

static inline void ckpt_flush_sort(knl_session_t *session, ckpt_context_t *ctx)
{
    qsort(ctx->group.items, ctx->group.count, sizeof(ckpt_sort_item), ckpt_buforder_comparator);
}


static uint32 ckpt_adjust_dbwr(knl_session_t *session, buf_ctrl_t *ctrl)
{
    page_id_t first;

    first = page_first_group_id(session, ctrl->page_id);

    return (PAGE_GROUP_COUNT - (ctrl->page_id.page - first.page + 1));
}

/* flush [begin, end - 1] */
static inline status_t ckpt_flush(knl_session_t *session, ckpt_context_t *ctx, uint32 begin, uint32 end)
{
    uint32 pages_each_wr = (end - begin - 1) / ctx->dbwr_count + 1;
    uint32 curr_page = begin;
    uint32 i;
    uint32 trigger_count = 0;
    buf_ctrl_t *ctrl = NULL;
    uint32 cnt;

    for (i = 0; i < ctx->dbwr_count; i++) {
        ctx->dbwr[i].begin = curr_page;
        curr_page += pages_each_wr;
        if (curr_page >= end) {
            curr_page = end;
        }
        
        /* if the last page is compressed page, take all its grouped pages to this dbwr  */
        ctrl = ctx->group.items[curr_page - 1].ctrl;
        if (page_compress(session, ctrl->page_id)) {
            cnt = ckpt_adjust_dbwr(session, ctrl);
            curr_page += cnt;
            knl_panic(curr_page <= end);
        }

        ctx->dbwr[i].end = curr_page - 1;
        ctx->dbwr[i].dbwr_trigger = GS_TRUE;
        trigger_count++;
#ifdef WIN32
        ReleaseSemaphore(ctx->dbwr[i].sem, 1, NULL);
#else
        (void)sem_post(&ctx->dbwr[i].sem);
#endif  // WIN32

        if (curr_page >= end) {
            break;
        }
    }

    for (i = 0; i < trigger_count; i++) {
        while (ctx->dbwr[i].dbwr_trigger) {
            cm_sleep(1);
        }
    }
    return GS_SUCCESS;
}

static inline void ckpt_delay(knl_session_t *session, uint32 ckpt_io_capacity)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    /* max capacity, skip sleep */
    if (ctx->group.count == ckpt_io_capacity) {
        return;
    }

    cm_sleep(1000); /* 1000ms */
}

static uint32 ckpt_get_dirty_ratio(knl_session_t *session)
{
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    buf_set_t *set = NULL;
    uint64 total_pages;

    set = &buf_ctx->buf_set[0];
    total_pages = (uint64)set->capacity * buf_ctx->buf_set_count;

    return (uint32)ceil((double)ckpt_ctx->queue.count / ((double)total_pages) * GS_PERCENT);
}

static uint32 ckpt_adjust_io_capacity(knl_session_t *session)
{
    knl_attr_t *attr = &session->kernel->attr;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 ckpt_io_capacity = attr->ckpt_io_capacity;
    atomic_t curr_io_read = cm_atomic_get(&session->kernel->total_io_read);

    /* adjust io capacity */
    if (ctx->trigger_task != CKPT_MODE_IDLE) {
        /* triggered, max capacity */
        ckpt_io_capacity = ctx->group.count;
    } else if (ctx->prev_io_read == curr_io_read || /* no read, max capacity */
               ckpt_get_dirty_ratio(session) > GS_MAX_BUF_DIRTY_PCT) {
        ckpt_io_capacity = ctx->group.count;
    } else {
        /* normal case */
        ckpt_io_capacity = attr->ckpt_io_capacity;
    }

    ctx->prev_io_read = curr_io_read;

    return ckpt_io_capacity;
}

static status_t ckpt_flush_pages(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 ckpt_io_capacity;
    uint32 begin;
    uint32 end;
    timeval_t tv_begin, tv_end;
    buf_ctrl_t *ctrl_border = NULL; 

    ckpt_io_capacity = ckpt_adjust_io_capacity(session);
    ckpt_flush_sort(session, ctx); 

    begin = 0;
    while (begin < ctx->group.count) {
        end = MIN(begin + ckpt_io_capacity, ctx->group.count);
 
        ctrl_border = ctx->group.items[end - 1].ctrl; // if compressed, taking all the group
        if (page_compress(session, ctrl_border->page_id)) {
            end += ckpt_adjust_dbwr(session, ctrl_border);
            knl_panic(end <= ctx->group.count);
        }

        (void)cm_gettimeofday(&tv_begin);
        if (ckpt_flush(session, ctx, begin, end) != GS_SUCCESS) {
            return GS_ERROR;
        }

        (void)cm_gettimeofday(&tv_end);
        ctx->stat.disk_writes += end - begin;
        ctx->stat.disk_write_time += (uint64)TIMEVAL_DIFF_US(&tv_begin, &tv_end);
        ckpt_delay(session, ckpt_io_capacity);
        
        begin  = end;
    }

    /* check */
#ifdef LOG_DIAG
    buf_ctrl_t *ctrl = NULL;

    for (uint32 i = 0; i < ctx->group.count; i++) {
        ctrl = ctx->group.items[i].ctrl;
        knl_panic_log(ctrl->is_marked == 0, "ctrl is marked, panic info: page %u-%u type %u", ctrl->page_id.file,
                      ctrl->page_id.page, ctrl->page->type);
    }
#endif

    return GS_SUCCESS;
}

/*
 * we need to do following jobs before flushing pages:
 * 1.flush redo log to update lrp point.
 * 2.double write pages to be flushed if need.
 * 3.back up log info in core ctrl to log file.
 */
static status_t ckpt_flush_prepare(knl_session_t *session, ckpt_context_t *ctx)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;

    if (log_flush(session, &ctx->lrp_point, &ctx->lrp_scn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!DB_NOT_READY(session) && !DB_IS_READONLY(session)) {
        if (DB_IS_RAFT_ENABLED(session->kernel)) {
            raft_wait_for_log_flush(session, (uint64)ctx->lrp_point.lfn);
        } else if (session->kernel->lsnd_ctx.standby_num > 0) {
            lsnd_wait(session, (uint64)ctx->lrp_point.lfn, NULL);
        }
    }

    if (ctx->double_write) {
        if (ckpt_double_write(session, ctx) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    core->lrp_point = ctx->lrp_point;
    core->scn = ctx->lrp_scn;
    if (core->consistent_lfn < ctx->consistent_lfn) {
        core->consistent_lfn = ctx->consistent_lfn;
    }

    if (DB_IS_RAFT_ENABLED(session->kernel) && (session->kernel->raft_ctx.status >= RAFT_STATUS_INITED)) {
        raft_context_t *raft_ctx = &session->kernel->raft_ctx;
        cm_spin_lock(&raft_ctx->raft_write_disk_lock, NULL);
        core->raft_flush_point = raft_ctx->raft_flush_point;
        cm_spin_unlock(&raft_ctx->raft_write_disk_lock);

        if (db_save_core_ctrl(session) != GS_SUCCESS) {
            return GS_ERROR;
        }

        knl_panic(session->kernel->raft_ctx.saved_raft_flush_point.lfn <= core->raft_flush_point.lfn &&
                  session->kernel->raft_ctx.saved_raft_flush_point.raft_index <= core->raft_flush_point.raft_index);
        session->kernel->raft_ctx.saved_raft_flush_point = core->raft_flush_point;
    } else {
        if (db_save_core_ctrl(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    /* backup some core info on datafile head: only back up core log info for full ckpt & timed task */
    if (NEED_SYNC_LOG_INFO(ctx) && ctrl_backup_core_log_info(session) != GS_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: backup core control info failed when perform checkpoint");
    }
    
    return GS_SUCCESS;
}

/* 
 * steps to perform checkpoint:
 * 1.prepare dirty pages and copy to ckpt group.
 * 2.flush redo log and double write dirty pages.
 * 3.flush pages to disk.
 */
static status_t ckpt_perform(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    core_ctrl_t *core = &session->kernel->db.ctrl.core;

    if (ckpt_prepare_pages(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (ctx->timed_task == CKPT_MODE_IDLE) {
        ctx->stat.flush_pages[ctx->trigger_task] += ctx->group.count;
    } else {
        ctx->stat.flush_pages[ctx->timed_task] += ctx->group.count;
    }

    ckpt_get_trunc_point(session, &ctx->trunc_point_snapshot);

    if (ctx->group.count == 0) {
        return GS_SUCCESS;
    }

    if (ckpt_flush_prepare(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (ckpt_flush_pages(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ctx->group.count = 0;
    ctx->dw_ckpt_start = ctx->dw_ckpt_end;
    core->ckpt_id++;
    core->dw_start = ctx->dw_ckpt_end;

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        KNL_SESSION_CLEAR_THREADID(session);
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
    }

    return GS_SUCCESS;
}

void ckpt_enque_page(knl_session_t *session)
{
    ckpt_context_t *ckpt = &session->kernel->ckpt_ctx;
    ckpt_queue_t *queue = &ckpt->queue;
    uint32 i;

    cm_spin_lock(&queue->lock, &session->stat_ckpt_queue);

    if (queue->count == 0) {
        queue->first = session->dirty_pages[0];
        session->dirty_pages[0]->ckpt_prev = NULL;
    } else {
        queue->last->ckpt_next = session->dirty_pages[0];
        session->dirty_pages[0]->ckpt_prev = queue->last;
    }

    queue->last = session->dirty_pages[session->dirty_count - 1];
    queue->last->ckpt_next = NULL;
    queue->count += session->dirty_count;

    /** set log truncate point for every dirty page in current session */
    for (i = 0; i < session->dirty_count; i++) {
        knl_panic(session->dirty_pages[i]->in_ckpt == GS_FALSE);
        session->dirty_pages[i]->trunc_point = queue->trunc_point;
        session->dirty_pages[i]->in_ckpt = GS_TRUE;
    }

    cm_spin_unlock(&queue->lock);

    session->stat.disk_writes += session->dirty_count;
    session->dirty_count = 0;
}

void ckpt_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl)
{
    ckpt_context_t *ckpt = &session->kernel->ckpt_ctx;
    ckpt_queue_t *queue = &ckpt->queue;

    cm_spin_lock(&queue->lock, &session->stat_ckpt_queue);

    if (queue->count == 0) {
        queue->first = ctrl;
        ctrl->ckpt_prev = NULL;
    } else {
        queue->last->ckpt_next = ctrl;
        ctrl->ckpt_prev = queue->last;
    }

    queue->last = ctrl;
    queue->last->ckpt_next = NULL;
    queue->count++;

    ctrl->trunc_point = queue->trunc_point;
    ctrl->in_ckpt = GS_TRUE;
    cm_spin_unlock(&queue->lock);
}

bool32 ckpt_check(knl_session_t *session)
{
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;

    if (ckpt_ctx->trigger_task == CKPT_MODE_IDLE && ckpt_ctx->queue.count == 0) {
        return GS_TRUE;
    } else {
        return GS_FALSE;
    }
}

void ckpt_set_trunc_point(knl_session_t *session, log_point_t *point)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    /* do not move forward trunc point if GBP_RECOVERY is not completed */
    if (KNL_RECOVERY_WITH_GBP(session->kernel)) {
        return;
    }
    cm_spin_lock(&ctx->queue.lock, &session->stat_ckpt_queue);
    ctx->queue.trunc_point = *point;
    cm_spin_unlock(&ctx->queue.lock);
}

void ckpt_get_trunc_point(knl_session_t *session, log_point_t *point)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;

    cm_spin_lock(&ctx->queue.lock, &session->stat_ckpt_queue);
    *point = ctx->queue.trunc_point;
    cm_spin_unlock(&ctx->queue.lock);
}

status_t dbwr_save_page(knl_session_t *session, dbwr_context_t *dbwr, page_head_t *page)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(page_id->file);
    int32 *handle = &dbwr->datafiles[page_id->file];
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);

    knl_panic (!page_compress(session, *page_id));
    knl_panic (page->type != PAGE_TYPE_PUNCH_PAGE);
    knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
        page_id->page, page->type);

    if (spc_write_datafile(session, df, handle, offset, page, PAGE_SIZE(*page)) != GS_SUCCESS) {
        spc_close_datafile(df, handle);
        GS_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
        return GS_ERROR;
    }

    if (!dbwr->flags[page_id->file]) {
        dbwr->flags[page_id->file] = GS_TRUE;
    }

    return GS_SUCCESS;
}

status_t dbwr_fdatasync(knl_session_t *session, dbwr_context_t *dbwr)
{
    database_t *db = &session->kernel->db;

    if (!session->kernel->attr.enable_fdatasync) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < GS_MAX_DATA_FILES; i++) {
        if (dbwr->flags[i]) {
            if (cm_fdatasync_file(dbwr->datafiles[i]) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("failed to fdatasync datafile %s", db->datafiles[i].ctrl->name);
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t dbwr_write_or_punch(knl_session_t *session, ckpt_sort_item *item, int32 *handle, datafile_t *df,
    page_head_t *page)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);

    if (!page_compress(session, *page_id)) {
        knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
            page_id->page, page->type);
    }

    if (item->need_punch) {
        knl_panic(page_compress(session, *page_id));
        if (cm_file_punch_hole(*handle, (uint64)offset, PAGE_SIZE(*page)) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[CKPT] failed to punch datafile compress %s", df->ctrl->name);
            return GS_ERROR;
        }
    } else if (page->type == PAGE_TYPE_PUNCH_PAGE) {
        knl_panic(!page_compress(session, *page_id));
        if (cm_file_punch_hole(*handle, (uint64)offset, PAGE_SIZE(*page)) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[CKPT] failed to punch datafile normal %s", df->ctrl->name);
            return GS_ERROR;
        }
    } else {
        if (cm_write_device(df->ctrl->type, *handle, offset, page, PAGE_SIZE(*page)) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[CKPT] failed to write datafile %s", df->ctrl->name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
    
static status_t dbwr_save_page_by_id(knl_session_t *session, dbwr_context_t *dbwr, uint16 begin, uint16 *saved_cnt)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint32 buf_id = ctx->group.items[begin].buf_id;
    page_head_t *page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE);

    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(page_id->file);
    int32 *handle = &dbwr->datafiles[page_id->file];
    int64 offset = (int64)page_id->page * DEFAULT_PAGE_SIZE;
    uint16 sequent_cnt = page_compress(session, *page_id) ? PAGE_GROUP_COUNT : 1;
    uint64 end_pos = (uint64)offset + sequent_cnt * DEFAULT_PAGE_SIZE;
    *saved_cnt = 0;

    if (*handle == -1) {
        if (spc_open_datafile(session, df, handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[SPACE] failed to open datafile %s", df->ctrl->name);
            return GS_ERROR;
        }
    }

    for (;;) {
        cm_latch_s(&df->block_latch, GS_INVALID_ID32, GS_FALSE, NULL);
        if (!spc_datafile_is_blocked(df, (uint64)offset, end_pos)) {
            break;
        }
        cm_unlatch(&df->block_latch, NULL);
        cm_sleep(1);
    }

    for (uint16 i = begin; i < begin + sequent_cnt; i++) {
        buf_ctrl_t *ctrl = ctx->group.items[i].ctrl;
        uint32 buf_id = ctx->group.items[i].buf_id;
        page = (page_head_t *)(ctx->group.buf + ((uint64)buf_id) * DEFAULT_PAGE_SIZE);

        knl_panic_log(ctrl != NULL, "ctrl is NULL, panic info: page %u-%u type %u", AS_PAGID(page->id).file,
            AS_PAGID(page->id).page, page->type);
        knl_panic_log(IS_SAME_PAGID(ctrl->page_id, AS_PAGID(page->id)), "ctrl's page_id and page's id are not same, "
            "panic info: ctrl_page %u-%u type %u, page %u-%u type %u", ctrl->page_id.file,
            ctrl->page_id.page, ctrl->page->type, AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);

        if (dbwr_write_or_punch(session, &ctx->group.items[i], handle, df, page) != GS_SUCCESS) {
            cm_unlatch(&df->block_latch, NULL);
            spc_close_datafile(df, handle);
            return GS_ERROR;
        }

        ctrl->is_marked = 0;
    }

    if (!dbwr->flags[page_id->file]) {
        dbwr->flags[page_id->file] = GS_TRUE;
    }

    cm_unlatch(&df->block_latch, NULL);
    *saved_cnt = sequent_cnt;
    return GS_SUCCESS;
}

static status_t dbwr_flush_sync_io(knl_session_t *session, dbwr_context_t *dbwr)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    uint16 saved_cnt;

    errno_t ret = memset_sp(dbwr->flags, sizeof(dbwr->flags), 0, sizeof(dbwr->flags));
    knl_securec_check(ret);

    if (ctx->has_compressed) {
        if (dbwr_compress_prepare(session, dbwr) != GS_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if (err_code != ERR_ALLOC_MEMORY) {
                return GS_ERROR;
            }
            /* if there is not enough memory, no compression is performed */
            cm_reset_error();
        } 
    }

    for (uint16 i = dbwr->begin; i <= dbwr->end; i += saved_cnt) {
        if (dbwr_save_page_by_id(session, dbwr, i, &saved_cnt) != GS_SUCCESS) {
            return GS_ERROR;
        }
        knl_panic(saved_cnt == 1 || saved_cnt == PAGE_GROUP_COUNT);
    }

    return dbwr_fdatasync(session, dbwr);
}

static status_t dbwr_flush(knl_session_t *session, dbwr_context_t *dbwr)
{
#ifndef WIN32
    if (session->kernel->attr.enable_asynch) {
        if (dbwr_flush_async_io(session, dbwr) != GS_SUCCESS) {
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
#endif

    if (dbwr_flush_sync_io(session, dbwr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void dbwr_end(dbwr_context_t *dbwr)
{
    for (uint32 i = 0; i < GS_MAX_DATA_FILES; i++) {
        cm_close_file(dbwr->datafiles[i]);
        dbwr->datafiles[i] = GS_INVALID_HANDLE;
    }
}

static void dbwr_aio_destroy(knl_session_t *session, dbwr_context_t *dbwr)
{
#ifndef WIN32
    knl_instance_t *kernel = session->kernel;

    if (!session->kernel->attr.enable_asynch) {
        return;
    }

    (void)cm_aio_destroy(&kernel->aio_lib, dbwr->async_ctx.aio_ctx);
#endif
}

void dbwr_proc(thread_t *thread)
{
    dbwr_context_t *dbwr = (dbwr_context_t *)thread->argument;
    knl_session_t *session = dbwr->session;
    status_t status;

    cm_set_thread_name("dbwr");
    GS_LOG_RUN_INF("dbwr thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
#ifdef WIN32
        if (WaitForSingleObject(dbwr->sem, 5000) == WAIT_TIMEOUT) {
            continue;
        }
#else
        struct timespec wait_time;
        long nsecs;
        (void)clock_gettime(CLOCK_REALTIME, &wait_time);
        nsecs = wait_time.tv_nsec + 500 * NANOSECS_PER_MILLISEC; // 500ms
        wait_time.tv_sec += nsecs / (int32)NANOSECS_PER_SECOND;
        wait_time.tv_nsec = nsecs % (int32)NANOSECS_PER_SECOND;

        if (sem_timedwait(&dbwr->sem, &wait_time) == -1) {
            continue;
        }
#endif  // WIN32
        if (thread->closed) {
            break;
        }

        knl_panic(dbwr->end >= dbwr->begin);
        knl_panic(dbwr->dbwr_trigger);

        status = dbwr_flush(session, dbwr);
        if (status != GS_SUCCESS) {
            GS_LOG_ALARM(WARN_FLUSHBUFFER, "'instance-name':'%s'}", session->kernel->instance_name);
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: db flush fail");
        }
        dbwr->dbwr_trigger = GS_FALSE;
    }

    dbwr_end(dbwr);
    dbwr_aio_destroy(session, dbwr);
    GS_LOG_RUN_INF("dbwr thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

static status_t ckpt_read_doublewrite_pages(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    int64 offset;
    datafile_t *df;
    uint32 dw_file_id = knl_get_dbwrite_file_id(session);

    offset = (int64)ctx->dw_ckpt_start * DEFAULT_PAGE_SIZE;
    df = DATAFILE_GET(dw_file_id);

    knl_panic(ctx->dw_ckpt_start >= DW_DISTRICT_BEGIN);
    knl_panic(ctx->dw_ckpt_end <= DW_DISTRICT_END);
    knl_panic(df->ctrl->id == dw_file_id);  // first sysware file

    ctx->group.count = ctx->dw_ckpt_end - ctx->dw_ckpt_start;
    /* DEFAULT_PAGE_SIZE is 8192, ctx->group.count <= GS_CKPT_GROUP_SIZE(4096), can not cross bounds */
    if (spc_read_datafile(session, df, &ctx->dw_file, offset, ctx->group.buf,
        ctx->group.count * DEFAULT_PAGE_SIZE) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[CKPT] failed to open datafile %s", df->ctrl->name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t ckpt_recover_decompress(knl_session_t *session, int32 *handle, page_head_t *page, 
    const char *read_buf, char *org_group)
{
    const uint32 group_size = DEFAULT_PAGE_SIZE * PAGE_GROUP_COUNT;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(page_id->file);
    status_t status = GS_SUCCESS;
    page_head_t *org_page = NULL;
    uint32 size;
    errno_t ret;

    if (((page_head_t *)read_buf)->compressed) {
        if (buf_check_load_compress_group(session, *page_id, read_buf) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (buf_decompress_group(session, org_group, read_buf, &size) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (size != group_size) {
            return GS_ERROR;
        }
    } else {
        ret = memcpy_s(org_group, group_size, read_buf, group_size);
        knl_securec_check(ret);
    }

    for (uint32 i = 0; i < PAGE_GROUP_COUNT; i++) {
        org_page = (page_head_t *)((char *)org_group + i * DEFAULT_PAGE_SIZE);
        if (!CHECK_PAGE_PCN(org_page) || (PAGE_CHECKSUM(org_page, DEFAULT_PAGE_SIZE) == GS_INVALID_CHECKSUM) ||
            !page_verify_checksum(org_page, DEFAULT_PAGE_SIZE)) {
            GS_LOG_RUN_INF("[CKPT] datafile %s page corrupted(file %u, page %u), recover from doublewrite page",
                df->ctrl->name, page_id->file, page_id->page + i);
            status = GS_ERROR;
        }
    }

    return status;
}

static status_t ckpt_recover_one(knl_session_t *session, int32 *handle, page_head_t *page, page_head_t *org_page, 
    bool32 force_recover)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(page_id->file);
    space_t *space = SPACE_GET(df->space_id);
    status_t status;

    if (!force_recover) {
        if (CHECK_PAGE_PCN(org_page) && (PAGE_CHECKSUM(org_page, DEFAULT_PAGE_SIZE) != GS_INVALID_CHECKSUM) &&
            page_verify_checksum(org_page, DEFAULT_PAGE_SIZE)) {
            return GS_SUCCESS;
        }
        GS_LOG_RUN_INF("[CKPT] datafile %s page corrupted(file %u, page %u), recover from doublewrite page",
            df->ctrl->name, page_id->file, page_id->page);
    }

    knl_panic_log(CHECK_PAGE_PCN(page), "page pcn is abnormal, panic info: page %u-%u type %u", page_id->file,
        page_id->page, page->type);
    knl_panic_log((PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE) == GS_INVALID_CHECKSUM) ||
        page_verify_checksum(page, DEFAULT_PAGE_SIZE), "checksum is wrong, panic info: page %u-%u type %u",
        page_id->file, page_id->page, page->type);

    status = spc_write_datafile(session, df, handle, offset, page, DEFAULT_PAGE_SIZE);
    if (status != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[CKPT] failed to write datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);
    } else {
        status = db_fdatasync_file(session, *handle);
        if (status != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[CKPT] failed to fdatasync datafile %s", df->ctrl->name);
        }
    }

    if (status != GS_SUCCESS) {
        if (spc_auto_offline_space(session, space, df)) {
            status = GS_SUCCESS;
        }
    }

    return status;
}

static status_t ckpt_recover_compress_group(knl_session_t *session, ckpt_context_t *ctx, uint32 slot)
{
    rcy_sort_item_t *item = &ctx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(page_id->file);
    space_t *space = SPACE_GET(df->space_id);
    int32 handle = -1;
    char *read_buf = NULL;
    char *src = NULL;
    char *org_group = NULL;
    uint32 size;
    status_t status = GS_SUCCESS;

    knl_panic_log(page_id->page % PAGE_GROUP_COUNT == 0, "panic info: page %u-%u not the group head", page_id->file,
        page_id->page);
    size = DEFAULT_PAGE_SIZE * PAGE_GROUP_COUNT;
    src = (char *)malloc(size + GS_MAX_ALIGN_SIZE_4K);
    if (src == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, size + GS_MAX_ALIGN_SIZE_4K, "recover compress group");
        return GS_ERROR;
    }
    org_group = (char *)malloc(size);
    if (org_group == NULL) {
        free(src);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, size, "recover compress group");
        return GS_ERROR;
    }
    read_buf = (char *)cm_aligned_buf(src);
    if (spc_read_datafile(session, df, &handle, offset, read_buf, size) != GS_SUCCESS) {
        spc_close_datafile(df, &handle);
        GS_LOG_RUN_ERR("[CKPT] failed to read datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);

        if (spc_auto_offline_space(session, space, df)) {
            GS_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
            free(org_group);
            free(src);
            return GS_SUCCESS;
        }

        free(org_group);
        free(src);
        return GS_ERROR;
    }

    if (ckpt_recover_decompress(session, &handle, page, read_buf, org_group) != GS_SUCCESS) {
        GS_LOG_RUN_INF("[CKPT] datafile %s decompress group failed(file %u, page %u), recover from doublewrite",
            df->ctrl->name, page_id->file, page_id->page);
        /* we need to recover the compress group as a whole */
        for (uint32 i = 0; i < PAGE_GROUP_COUNT; i++) {
            if (ckpt_recover_one(session, &handle, ctx->rcy_items[slot + i].page,
                (page_head_t *)((char *)org_group + i * DEFAULT_PAGE_SIZE), GS_TRUE) != GS_SUCCESS) {
                status = GS_ERROR;
                break;
            }
        }
    }

    free(org_group);
    free(src);
    spc_close_datafile(df, &handle);
    return status;
}

static status_t ckpt_recover_normal(knl_session_t *session, ckpt_context_t *ctx, uint32 slot, page_head_t *org_page)
{
    rcy_sort_item_t *item = &ctx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    int64 offset = (int64)page_id->page * PAGE_SIZE(*page);
    datafile_t *df = DATAFILE_GET(page_id->file);
    space_t *space = SPACE_GET(df->space_id);
    int32 handle = -1;
    status_t status;

    if (spc_read_datafile(session, df, &handle, offset, org_page, DEFAULT_PAGE_SIZE) != GS_SUCCESS) {
        spc_close_datafile(df, &handle);
        GS_LOG_RUN_ERR("[CKPT] failed to read datafile %s, file %u, page %u", df->ctrl->name, page_id->file,
            page_id->page);

        if (spc_auto_offline_space(session, space, df)) {
            GS_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
            return GS_SUCCESS;
        }

        return GS_ERROR;
    }

    status = ckpt_recover_one(session, &handle, page, org_page, GS_FALSE);
    spc_close_datafile(df, &handle);
    return status;
}

status_t ckpt_recover_page(knl_session_t *session, ckpt_context_t *ctx, uint32 slot, page_head_t *org_page,
    uint32 *skip_cnt)
{
    rcy_sort_item_t *item = &ctx->rcy_items[slot];
    page_head_t *page = item->page;
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    datafile_t *df = DATAFILE_GET(page_id->file);
    space_t *space = SPACE_GET(df->space_id);
    status_t status;

    if (!SPACE_IS_ONLINE(space) || !DATAFILE_IS_ONLINE(df)) {
        GS_LOG_RUN_INF("[CKPT] skip recover offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
        return GS_SUCCESS;
    }

    if (page_compress(session, *page_id)) {
        *skip_cnt = PAGE_GROUP_COUNT;
        status = ckpt_recover_compress_group(session, ctx, slot);
    } else {
        *skip_cnt = 1;
        status = ckpt_recover_normal(session, ctx, slot, org_page);
    }

    return status;
}

static int32 ckpt_rcyorder_comparator(const void *pa, const void *pb)
{
    const rcy_sort_item_t *a = (const rcy_sort_item_t *)pa;
    const rcy_sort_item_t *b = (const rcy_sort_item_t *)pb;

    /* compare fileid */
    if (AS_PAGID(a->page->id).file < AS_PAGID(b->page->id).file) {
        return -1;
    } else if (AS_PAGID(a->page->id).file > AS_PAGID(b->page->id).file) {
        return 1;
    }

    /* compare page */
    if (AS_PAGID(a->page->id).page < AS_PAGID(b->page->id).page) {
        return -1;
    } else if (AS_PAGID(a->page->id).page > AS_PAGID(b->page->id).page) {
        return 1;
    }

    /* equal pageid is impossible */
    return 0;
}

static void ckpt_recover_prepare(knl_session_t *session, ckpt_context_t *ctx)
{
    page_head_t *page = NULL;

    for (uint32 i = 0; i < ctx->group.count; i++) {
        page = (page_head_t *)(ctx->group.buf + i * DEFAULT_PAGE_SIZE);
        ctx->rcy_items[i].page = page;
        ctx->rcy_items[i].buf_id = i;
    }
    qsort(ctx->rcy_items, ctx->group.count, sizeof(rcy_sort_item_t), ckpt_rcyorder_comparator);
}

static status_t ckpt_recover_pages(knl_session_t *session, ckpt_context_t *ctx)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    uint32 i;
    page_head_t *page = NULL;
    char *page_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE + GS_MAX_ALIGN_SIZE_4K);
    char *head = (char *)cm_aligned_buf(page_buf);
    uint16 swap_file_head = SPACE_GET(core->swap_space)->ctrl->files[0];
    uint32 skip_cnt;

    ckpt_recover_prepare(session, ctx);
    for (i = 0; i < ctx->group.count; i = i + skip_cnt) {
        page = ctx->rcy_items[i].page;
        page_id_t *page_id = AS_PAGID_PTR(page->id);
        skip_cnt = 1;

        if (page_id->file == swap_file_head) {
            GS_LOG_RUN_INF("[CKPT] skip recover swap datafile %s", DATAFILE_GET(swap_file_head)->ctrl->name);
            continue;
        }

        if (ckpt_recover_page(session, ctx, i, (page_head_t *)head, &skip_cnt) != GS_SUCCESS) {
            cm_pop(session->stack);
            return GS_ERROR;
        }
    }

    cm_pop(session->stack);
    ctx->group.count = 0;
    ctx->dw_ckpt_start = ctx->dw_ckpt_end;
    core->dw_start = ctx->dw_ckpt_end;

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when checkpoint recover pages");
    }

    return GS_SUCCESS;
}

status_t ckpt_recover_partial_write(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;

    ctx->dw_ckpt_start = ctrl->core.dw_start;
    ctx->dw_ckpt_end = ctrl->core.dw_end;

    if (ctx->dw_ckpt_start == ctx->dw_ckpt_end) {
        return GS_SUCCESS;
    }

    if (ckpt_read_doublewrite_pages(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (ckpt_recover_pages(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[CKPT] ckpt recover finish");
    return GS_SUCCESS;
}

/* Forbidden others to set new task, and then wait the running task to finish */
void ckpt_disable(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    cm_spin_lock(&ctx->lock, &session->stat_ckpt);
    ctx->ckpt_enabled = GS_FALSE;
    cm_spin_unlock(&ctx->lock);
    while (ctx->trigger_task != CKPT_MODE_IDLE || ctx->timed_task != CKPT_MODE_IDLE) {
        cm_sleep(10);
    }
}

void ckpt_enable(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    ctx->ckpt_enabled = GS_TRUE;
}

/* 
 * disable ckpt and remove page of df to be removed from ckpt queue
 */
void ckpt_remove_df_page(knl_session_t *session, datafile_t *df, bool32 need_disable)
{
    knl_instance_t *kernel = session->kernel;
    ckpt_context_t *ctx = &kernel->ckpt_ctx;

    if (need_disable) {
        ckpt_disable(session);
    }

    /* remove page from queue base on file id */
    cm_spin_lock(&ctx->queue.lock, &session->stat_ckpt_queue);
    buf_ctrl_t *curr = ctx->queue.first;
    buf_ctrl_t *last = ctx->queue.last;
    cm_spin_unlock(&ctx->queue.lock);

    buf_ctrl_t *next = NULL;
    while (ctx->queue.count != 0 && curr != NULL && curr != last->ckpt_next) {
        next = curr->ckpt_next;
        if (curr->page_id.file == df->ctrl->id) {
            ckpt_pop_page(session, ctx, curr);
            curr->is_dirty = 0;
            buf_expire_page(session, curr->page_id);
        }
        curr = next;
    }

    if (need_disable) {
        ckpt_enable(session);
    }
}

static status_t ckpt_clean_try_latch_group(knl_session_t *session, buf_ctrl_t *ctrl, buf_ctrl_t **ctrl_group)
{
    page_id_t page_id;
    uint32  i, j;
    buf_ctrl_t *cur_ctrl = NULL; 

    page_id = page_first_group_id(session, ctrl->page_id);
    
    for (i = 0; i < PAGE_GROUP_COUNT; i++, page_id.page++) {
        cur_ctrl = buf_find_by_pageid(session, page_id);
        knl_panic(cur_ctrl != NULL);
        if (!ckpt_try_latch_ctrl(session, cur_ctrl)) {
            for (j = 0; j < i; j++) {
                buf_unlatch(session, ctrl_group[j], GS_FALSE);
            }
            return GS_ERROR;
        }
        ctrl_group[i] = cur_ctrl;
    }

    return GS_SUCCESS;
}

status_t ckpt_clean_prepare_compress(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *head)
{
    buf_ctrl_t *ctrl_group[PAGE_GROUP_COUNT];
    int i, j;

    if (ctx->group.count + PAGE_GROUP_COUNT > GS_CKPT_GROUP_SIZE) {
        return GS_SUCCESS; // continue the next
    }

    if (ckpt_clean_try_latch_group(session, head, ctrl_group) != GS_SUCCESS) {
        return GS_SUCCESS; // continue the next
    }

    knl_panic(!head->is_marked);
    knl_panic(head->in_ckpt);

    /* Copy all the compression group pages to ckpt group.
     * If a page is dirty (in ckpt queue), we will pop it and update its flags.
     */
    for (i = 0; i < PAGE_GROUP_COUNT; i++) {
        errno_t ret = memcpy_sp(ctx->group.buf + DEFAULT_PAGE_SIZE * ctx->group.count,
            DEFAULT_PAGE_SIZE, ctrl_group[i]->page, DEFAULT_PAGE_SIZE);
        knl_securec_check(ret);        

        if (ctrl_group[i]->is_dirty) {
            knl_panic(ctrl_group[i]->in_ckpt);
            ckpt_pop_page(session, ctx, ctrl_group[i]);
            if (ctx->consistent_lfn < ctrl_group[i]->lastest_lfn) {
                ctx->consistent_lfn = ctrl_group[i]->lastest_lfn;
            }
            ctrl_group[i]->is_marked = 1;
            CM_MFENCE;
            ctrl_group[i]->is_dirty = 0;
        }

        buf_unlatch(session, ctrl_group[i], GS_FALSE);
        
        ctx->group.items[ctx->group.count].ctrl = ctrl_group[i];
        ctx->group.items[ctx->group.count].buf_id = ctx->group.count;
        ctx->group.items[ctx->group.count].need_punch = GS_FALSE;
        
        if (ckpt_encrypt(session, ctx) != GS_SUCCESS) {
            for (j = i + 1; j < PAGE_GROUP_COUNT; j++) {
                buf_unlatch(session, ctrl_group[j], GS_FALSE);
            }
            return GS_ERROR;
        }
        if (ckpt_checksum(session, ctx) != GS_SUCCESS) {
            for (j = i + 1; j < PAGE_GROUP_COUNT; j++) {
                buf_unlatch(session, ctrl_group[j], GS_FALSE);
            }
            return GS_ERROR;
        }

        ctx->group.count++;
    }

    return GS_SUCCESS;    
}

status_t ckpt_clean_prepare_normal(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *shift)
{       
    if (!ckpt_try_latch_ctrl(session, shift)) {
        return GS_SUCCESS; // continue the next
    }

    knl_panic(!shift->is_marked);
    knl_panic(shift->in_ckpt);
    
    /* copy page from buffer to ckpt group */
    errno_t ret = memcpy_sp(ctx->group.buf + DEFAULT_PAGE_SIZE * ctx->group.count,
        DEFAULT_PAGE_SIZE, shift->page, DEFAULT_PAGE_SIZE);
    knl_securec_check(ret);
    
    ckpt_pop_page(session, ctx, shift);
    
    if (ctx->consistent_lfn < shift->lastest_lfn) {
        ctx->consistent_lfn = shift->lastest_lfn;
    }
    
    shift->is_marked = 1;
    CM_MFENCE;
    shift->is_dirty = 0;
    buf_unlatch(session, shift, GS_FALSE);
    
    ctx->group.items[ctx->group.count].ctrl = shift;
    ctx->group.items[ctx->group.count].buf_id = ctx->group.count;
    ctx->group.items[ctx->group.count].need_punch = GS_FALSE;
            
    if (ckpt_encrypt(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (ckpt_checksum(session, ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ctx->group.count++;
    return GS_SUCCESS;
}

/*
 * prepare pages to be cleaned
 * 1.search dirty page from write list of buffer set and copy to ckpt group
 * 2.stash dirty pages for releasing after flushing.
 */
static status_t ckpt_clean_prepare_pages(knl_session_t *session, ckpt_context_t *ctx, buf_set_t *set, 
    buf_lru_list_t *page_list)
{
    buf_ctrl_t *ctrl = NULL;
    buf_ctrl_t *shift = NULL;

    if (ctx->clean_end != NULL) {
        ctrl = ctx->clean_end;
    } else {
        cm_spin_lock(&set->write_list.lock, NULL);
        ctrl = set->write_list.lru_last;
        cm_spin_unlock(&set->write_list.lock);
    }

    while (ctrl != NULL) {
        shift = ctrl;
        ctrl = ctrl->prev;
    
        /* page has been expired */
        if (shift->bucket_id == GS_INVALID_ID32) {
            buf_stash_marked_page(set, page_list, shift);
            continue;
        }

        /* page has already been flushed by checkpoint.
         * We need not hold lock to the ctrl when tesing dirty, since there is no harm
         * if it is set to dirty by others again after we get a not-dirty result.
         */
        if (!shift->is_dirty) {
            buf_stash_marked_page(set, page_list, shift); 
            continue;
        }
    
        status_t status;
        if (page_compress(session, shift->page_id)) {
            status = ckpt_clean_prepare_compress(session, ctx, shift);
        } else {
            status = ckpt_clean_prepare_normal(session, ctx, shift);
        }
        if (status != GS_SUCCESS) {
            return GS_ERROR;
        }

        buf_stash_marked_page(set, page_list, shift);
        
        if (ctx->group.count >= GS_CKPT_GROUP_SIZE) {
            ctx->clean_end = ctrl;
            return GS_SUCCESS;
        }
    }

    ctx->clean_end = NULL;
    return GS_SUCCESS;
}

/*
 * clean dirty page on write list of given buffer set. 
 * 1.only flush a part of dirty page to release clean page of other buffer set.
 * 2.need to flush one more time because of ckpt group size limitation.
 */
static status_t ckpt_clean_single_set(knl_session_t *session, ckpt_context_t *ckpt_ctx, buf_set_t *set)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    buf_lru_list_t page_list;
    int64 clean_cnt = (int64)(set->write_list.count * CKPT_PAGE_CLEAN_RATIO);
    ckpt_ctx->clean_end = NULL;

    for (;;) {
        page_list = g_init_list_t;
        if (ckpt_clean_prepare_pages(session, ckpt_ctx, set, &page_list) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (ckpt_ctx->timed_task == CKPT_MODE_IDLE) {
            ckpt_ctx->stat.flush_pages[CKPT_TRIGGER_CLEAN] += ckpt_ctx->group.count;
        } else {
            ckpt_ctx->stat.flush_pages[CKPT_TIMED_CLEAN] += ckpt_ctx->group.count;
        }

        if (ckpt_ctx->group.count == 0) {
            buf_reset_cleaned_pages(set, &page_list);
            return GS_SUCCESS;
        }

        if (ckpt_flush_prepare(session, ckpt_ctx) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (ckpt_flush_pages(session) != GS_SUCCESS) {
            CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean page.");
        }

        buf_reset_cleaned_pages(set, &page_list);

        clean_cnt -= ckpt_ctx->group.count;
        ckpt_ctx->group.count = 0;
        ckpt_ctx->dw_ckpt_start = ckpt_ctx->dw_ckpt_end;
        core->dw_start = ckpt_ctx->dw_ckpt_end;

        if (db_save_core_ctrl(session) != GS_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: save core control file failed when perform checkpoint");
        }

        /* only clean a part of pages when generate by trigger */
        if (clean_cnt <= 0 || ckpt_ctx->clean_end == NULL) {
            return GS_SUCCESS;
        }
    }
    return GS_SUCCESS;
}

/*
 * clean dirty page on buffer write list of each buffer set
 */
static void ckpt_page_clean(knl_session_t *session)
{
    buf_context_t *buf_ctx = &session->kernel->buf_ctx;
    ckpt_context_t *ckpt_ctx = &session->kernel->ckpt_ctx;

    for (uint32 i = 0; i < buf_ctx->buf_set_count; i++) {
        if (ckpt_clean_single_set(session, ckpt_ctx, &buf_ctx->buf_set[i]) != GS_SUCCESS) {
            KNL_SESSION_CLEAR_THREADID(session);
            CM_ABORT(0, "[CKPT] ABORT INFO: flush page failed when clean dirty page");
        }
    }
}
