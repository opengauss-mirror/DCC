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
 * knl_backup.c
 *    implement of backup
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/backup/knl_backup.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_backup.h"
#include "cm_file.h"
#include "bak_paral.h"
#include "cm_kmc.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BAK_NEED_LOAD_FILE(session) ((session)->kernel->db.status == DB_STATUS_MOUNT)
#define BAK_NEED_UNLOAD_FILE(session) ((session)->kernel->db.status == DB_STATUS_MOUNT)
#define BAK_DISTRIBUTED_PHASE_SECOND(bak) ((bak)->record.log_only && (bak)->target_info.target != TARGET_ARCHIVE)
#define BAK_DATAFILE_VERSION    DATAFILE_STRUCTURE_VERSION

void bak_read_proc(thread_t *thread); // backup process for read local file

void bak_record_new_file(bak_t *bak, bak_file_type_t file_type, uint32 file_id, uint32 sec_id)
{
    knl_panic(bak->file_count < BAK_MAX_FILE_NUM);
    bak_file_t *new_file = &bak->files[bak->file_count];

    errno_t ret = memset_sp(new_file, sizeof(bak_file_t), 0, sizeof(bak_file_t));
    knl_securec_check(ret);

    new_file->type = file_type;
    new_file->id = file_id;
    new_file->sec_id = sec_id;
    bak->file_count++;
}

static inline void bak_generate_default_backupset_tag(bak_t *bak, knl_scn_t scn)
{
    int32 ret = snprintf_s(bak->record.attr.tag, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1, DEFAULT_TAG_FORMAT,
        bak->record.start_time, scn);
    knl_securec_check_ss(ret);
}

static status_t bak_tag_exists(knl_session_t *session, const char *tag, bool32 *exists)
{
    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_BACKUP_SET_ID, 1);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)tag,
                     (uint16)strlen(tag), 0);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    *exists = !cursor->eof;
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

void bak_reset_fileinfo(bak_assignment_t *assign_ctrl)
{
    assign_ctrl->start = 0;
    assign_ctrl->end = 0;
    assign_ctrl->file_id = 0;
    assign_ctrl->is_section = GS_FALSE;
    assign_ctrl->sec_id = 0;
    assign_ctrl->section_start = 0;
    assign_ctrl->section_end = 0;
    assign_ctrl->type = BACKUP_HEAD_FILE;
}

status_t bak_local_write(bak_local_t *local, const void *buf, int32 size, bak_t *bak)
{
    bak_stat_t *stat = &bak->stat;

    if (size == 0) {
        return GS_SUCCESS;
    }

    if (cm_write_file(local->handle, buf, size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] failed to write %s", local->name);
        return GS_ERROR;
    }

    if (bak->kernel->attr.enable_fdatasync) {
        if (cm_fdatasync_file(local->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] failed to fdatasync datafile %s", local->name);
            return GS_ERROR;
        }
    }

    (void)cm_atomic_inc(&stat->writes);

    GS_LOG_DEBUG_INF("bakup write data size:%d", size);
    return GS_SUCCESS;
}

static status_t bak_read_data(bak_process_t *bak_proc, bak_ctrl_t *ctrl, void *buf, int32 size)
{
    date_t start = g_timer()->now;
    if (cm_read_device(ctrl->type, ctrl->handle, ctrl->offset, buf, size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] failed to read %s", ctrl->name);
        return GS_ERROR;
    }
    bak_proc->stat.read_size += size;
    bak_proc->stat.read_time += (g_timer()->now - start);
    ctrl->offset += size;
    return GS_SUCCESS;
}

static void bak_set_log_point(knl_session_t *session, bak_ctrlinfo_t *ctrlinfo, bool32 update)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    log_context_t *log = &session->kernel->redo_ctx;
    bak_t *bak = &session->kernel->backup_ctx.bak;

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_INC);
    if (!update) {
        ctrlinfo->rcy_point = ctrl->core.rcy_point;
        errno_t ret = memset_sp(&bak->arch_stat, sizeof(arch_bak_status_t), 0, sizeof(arch_bak_status_t));
        knl_securec_check(ret);
        bak->arch_stat.start_asn = ctrlinfo->rcy_point.asn;
        GS_LOG_RUN_INF("[BACKUP] backup rcy point, rst_id:[%llu], asn[%u], lfn[%llu]",
                       (uint64)ctrlinfo->rcy_point.rst_id, ctrlinfo->rcy_point.asn,
                       (uint64)ctrlinfo->rcy_point.lfn);
    }

    log_lock_logfile(session);
    ctrlinfo->lrp_point = ctrl->core.lrp_point;
    ctrlinfo->scn = DB_CURR_SCN(session);
    uint32 file_id = log_get_id_by_asn(session, (uint32)ctrlinfo->lrp_point.rst_id, ctrlinfo->lrp_point.asn, NULL);
    if (file_id != GS_INVALID_ID32) {
        log_unlatch_file(session, file_id);
        log_get_next_file(session, &file_id, GS_FALSE);
    } else if (log->files[log->curr_file].head.asn == ctrlinfo->lrp_point.asn + 1) {
        file_id = log->curr_file; // lrp online log is recycled, head asn is invalid
    } else {
        knl_panic_log(!DB_IS_RAFT_ENABLED(session->kernel), "[BACKUP] failed to get log slot, lrp asn %u, curr asn %u",
                      ctrlinfo->lrp_point.asn, log->files[log->curr_file].head.asn);
        file_id = 0;
    }
    bak->log_first_slot = file_id;
    GS_LOG_RUN_INF("[BACKUP] log first file id %u, log curr_file %u, lrp asn %u, lfn %llu",
                   file_id, log->curr_file, ctrlinfo->lrp_point.asn, (uint64)ctrlinfo->lrp_point.lfn);
    log_unlock_logfile(session);
}

status_t bak_load_log_batch(knl_session_t *session, log_point_t *point, uint32 *data_size, aligned_buf_t *buf,
    uint32 *block_size)
{
    int32 handle = GS_INVALID_HANDLE;
    arch_file_t arch_file = { .name = { 0 }, .handle = GS_INVALID_HANDLE };
    status_t status;

    log_lock_logfile(session);
    uint32 file_id = log_get_id_by_asn(session, (uint32)point->rst_id, point->asn, NULL);
    log_unlock_logfile(session);

    if (file_id != GS_INVALID_ID32) {
        status = rcy_load_from_online(session, file_id, point, data_size, &handle, buf);
        *block_size = session->kernel->redo_ctx.files[file_id].ctrl->block_size;
        cm_close_device(session->kernel->redo_ctx.files[file_id].ctrl->type, &handle);
    } else {
        status = rcy_load_from_arch(session, point, data_size, &arch_file, buf);
        *block_size = arch_file.head.block_size;
        cm_close_file(arch_file.handle);
    }

    return status;
}

static status_t bak_set_lsn(knl_session_t *session, bak_t *bak)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    log_point_t start_point = ctrlinfo->rcy_point;
    log_batch_t *batch = NULL;
    log_batch_tail_t *tail = NULL;
    uint32 data_size;
    uint32 block_size;
    database_t *db = &session->kernel->db;
    reset_log_t rst_log = db->ctrl.core.resetlogs;
    aligned_buf_t log_buf;

    if (bak->record.attr.backup_type == BACKUP_MODE_FULL) {
        return GS_SUCCESS;
    }

    if (ctrlinfo->lrp_point.lfn == ctrlinfo->rcy_point.lfn) {
        // make sure pages whose lsn is less than ctrlinfo->lsn flushed
        ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
        GS_LOG_RUN_INF("[BACKUP] current database base lsn: %llu, rcy lfn %llu, lrp lfn %llu", ctrlinfo->lsn,
                       (uint64)db->ctrl.core.rcy_point.lfn, (uint64)db->ctrl.core.lrp_point.lfn);
        return GS_SUCCESS;
    }
    knl_panic(log_cmp_point(&ctrlinfo->rcy_point, &ctrlinfo->lrp_point) < 0);
    GS_LOG_RUN_INF("[BACKUP] fetch incremental backup base lsn for point asn %u, lfn %llu, block id %u",
                   start_point.asn, (uint64)start_point.lfn, start_point.block_id);
    if (cm_aligned_malloc(GS_MAX_BATCH_SIZE, "backup log buffer", &log_buf) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (;;) {
        if (bak_load_log_batch(session, &start_point, &data_size, &log_buf, &block_size) != GS_SUCCESS) {
            cm_aligned_free(&log_buf);
            return GS_ERROR;
        }

        batch = (log_batch_t *)log_buf.aligned_buf;
        if (data_size >= sizeof(log_batch_t) && data_size >= batch->size) {
            tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
            if (rcy_validate_batch(batch, tail)) {
                break;
            }
        }

        start_point.asn++;
        start_point.rst_id = (start_point.asn <= rst_log.last_asn) ? (rst_log.rst_id - 1) : rst_log.rst_id;
        start_point.block_id = 0;
    }

    ctrlinfo->lsn = rcy_fetch_batch_lsn(session, batch);
    GS_LOG_RUN_INF("[BACKUP] fetch base lsn %llu from batch asn %u, lfn %llu, block id %u",
                   ctrlinfo->lsn, batch->head.point.asn, (uint64)batch->head.point.lfn, batch->head.point.block_id);
    cm_aligned_free(&log_buf);
    return GS_SUCCESS;
}

static status_t bak_write(bak_t *bak, bak_process_t *proc, char *buf, int32 size)
{
    status_t status;
    char *write_buf = buf;

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE && bak->files[bak->curr_file_index].type != BACKUP_HEAD_FILE
        && !bak->is_building) {
        if (bak_encrypt_data(proc, buf, size) != GS_SUCCESS) {
            return GS_ERROR;
        }
        write_buf = proc->encrypt_ctx.encrypt_buf.aligned_buf;
    }

    if (bak->is_building || bak->record.device == DEVICE_UDS) {
        status = bak_agent_write(bak, write_buf, size);
    } else {
        status = bak_local_write(&bak->local, write_buf, size, bak);
    }

    bak->backup_size += size;
    return status;
}

static status_t bak_compress_write(bak_t *bak, bak_process_t *proc, char *buf, int32 size, bool32 stream_end)
{
    knl_compress_set_input(bak->record.attr.compress, &bak->compress_ctx, buf, (uint32)size);
    for (;;) {
        if (knl_compress(bak->record.attr.compress, &bak->compress_ctx, stream_end, bak->compress_buf,
                         (uint32)GS_COMPRESS_BUFFER_SIZE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak_write(bak, proc, bak->compress_buf, bak->compress_ctx.write_len) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak->compress_ctx.finished) {
            break;
        }
    }

    return GS_SUCCESS;
}

static status_t bak_set_finish_info(bak_t *bak, knl_backup_t *param)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (!bak->record.data_only || !cm_str_equal(bak->record.attr.tag, param->tag)) {
        GS_THROW_ERROR(ERR_BACKUP_NOT_PREPARE, param->tag);
        return GS_ERROR;
    }

    if (ctrlinfo->scn > param->finish_scn) {
        GS_THROW_ERROR(ERR_INVALID_FINISH_SCN, ctrlinfo->scn);
        return GS_ERROR;
    }

    bak->record.log_only = GS_TRUE;
    bak->record.data_only = GS_FALSE;
    bak->record.finish_scn = param->finish_scn;
    GS_LOG_RUN_INF("[BACKUP] ctrl info scn %llu", ctrlinfo->scn);
    return GS_SUCCESS;
}

static status_t bak_set_tag(knl_session_t *session, bak_t *bak, const char *tag)
{
    bool32 exists = GS_FALSE;

    if (tag[0] == '\0') {
        bak_generate_default_backupset_tag(bak, DB_CURR_SCN(session));
    } else {
        if (DB_IS_OPEN(session) && bak_tag_exists(session, tag, &exists) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (exists) {
            GS_THROW_ERROR(ERR_BACKUP_TAG_EXISTS, tag);
            return GS_ERROR;
        }

        errno_t ret = strncpy_s(bak->record.attr.tag, GS_NAME_BUFFER_SIZE, tag, strlen(tag));
        knl_securec_check(ret);
    }

    return GS_SUCCESS;
}

static status_t bak_set_params(knl_session_t *session, knl_backup_t *param)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_attr_t *attr = &bak->record.attr;
    uchar salt[GS_KDF2SALTSIZE];
    uchar kdf2_key[GS_AES256KEYSIZE];
    uint32 cipher_len = GS_PASSWORD_BUFFER_SIZE;
    errno_t ret;

    bak->is_building = GS_FALSE;
    bak->is_first_link = GS_TRUE;
    bak->need_retry = GS_FALSE;
    bak->need_check = GS_FALSE;
    bak->failed = GS_FALSE;

    if (param->type == BACKUP_MODE_FINISH_LOG) {
        return bak_set_finish_info(bak, param);
    }

    bak->record.start_time = (uint64)cm_now();
    bak->record.log_only = GS_FALSE;
    bak->record.finish_scn = 0;
    bak->record.data_only = param->prepare;
    attr->backup_type = param->type;
    attr->level = param->level;
    bak->record.device = param->device;
    bak->cumulative = param->cumulative;
    attr->compress = param->compress_algo;
    bak->compress_ctx.compress_level = param->compress_level;
    bak->section_threshold = param->section_threshold;
    bak->proc_count = param->parallelism == 0 ? BAK_DEFAULT_PARALLELISM : param->parallelism;
    bak->encrypt_info.encrypt_alg = param->crypt_info.encrypt_alg;
    bak->target_info = param->target_info;

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (cm_rand(salt, GS_KDF2SALTSIZE) != GS_SUCCESS) {
            bak_replace_password(param->crypt_info.password);
            return GS_ERROR;
        }
        ret = memcpy_sp(bak->encrypt_info.salt, GS_KDF2SALTSIZE, salt, GS_KDF2SALTSIZE);
        knl_securec_check(ret);

        if (cm_encrypt_KDF2((uchar *)param->crypt_info.password, (uint32)strlen(param->crypt_info.password), salt,
            GS_KDF2SALTSIZE, GS_KDF2DEFITERATION, kdf2_key, GS_AES256KEYSIZE) != GS_SUCCESS) {
            bak_replace_password(param->crypt_info.password);
            return GS_ERROR;
        }

        if (cm_generate_scram_sha256(param->crypt_info.password, (uint32)strlen(param->crypt_info.password),
            GS_KDF2DEFITERATION, (uchar *)bak->sys_pwd, &cipher_len) != GS_SUCCESS) {
            bak_replace_password(param->crypt_info.password);
            return GS_ERROR;
        }
        ret = memcpy_sp(bak->key, GS_AES256KEYSIZE, kdf2_key, GS_AES256KEYSIZE);
        knl_securec_check(ret);
        bak_replace_password(param->crypt_info.password);
    }

    (void)cm_text2str(&param->policy, bak->record.policy, GS_BACKUP_PARAM_SIZE);
    if (bak_set_data_path(session, bak, &param->format) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_set_tag(session, bak, param->tag) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_set_exclude_space(session, bak, param->exclude_spcs) != GS_SUCCESS) {
        ret = memset_sp(bak->exclude_spcs, sizeof(bool32) * GS_MAX_SPACES, 0, sizeof(bool32) * GS_MAX_SPACES);
        knl_securec_check(ret);
        return GS_ERROR;
    }

    if (bak_set_include_space(session, bak, param->target_info.target_list) != GS_SUCCESS) {
        ret = memset_sp(bak->include_spcs, sizeof(bool32) * GS_MAX_SPACES, 0, sizeof(bool32) * GS_MAX_SPACES);
        knl_securec_check(ret);
        return GS_ERROR;
    }

    if (param->target_info.target == TARGET_ARCHIVE) {
        bak->record.log_only = GS_TRUE;
        bak->record.data_only = GS_FALSE;
    }

    return GS_SUCCESS;
}

static status_t bak_set_head(knl_session_t *session)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (bak_set_incr_info(session, bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak->record.log_only && bak->target_info.target != TARGET_ARCHIVE) {
        return GS_SUCCESS;
    }

    bak->file_count = 0;
    bak->curr_file_index = 0;
    ctrlinfo->lsn = DB_CURR_LSN(session);  // for incremental backup restore
    bak->send_buf.offset = GS_INVALID_ID32;
    bak->record.status = BACKUP_PROCESSING;
    bak_set_log_point(session, ctrlinfo, GS_FALSE);
    if (bak_set_lsn(session, bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t bak_alloc_resource(knl_session_t *session, bak_t *bak)
{
    char uds_path[GS_FILE_NAME_BUFFER_SIZE];

    /* malloc space for bak->backup_buf,bak->depends, so it is multiplied by 2
     * malloc space for bak->compress_buf
     */
    bak->backup_buf = (char *)malloc(GS_BACKUP_BUFFER_SIZE * 2 + GS_COMPRESS_BUFFER_SIZE);
    if (bak->backup_buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_BACKUP_BUFFER_SIZE * 2 + (uint64)GS_COMPRESS_BUFFER_SIZE, "backup");
        return GS_ERROR;
    }
    bak->depends = (bak_dependence_t *)(bak->backup_buf + GS_BACKUP_BUFFER_SIZE);
    /* 2 * GS_BACKUP_BUFFER_SIZE for size of bak->backup_buf and size of bak->depends */
    bak->compress_buf = bak->backup_buf + 2 * GS_BACKUP_BUFFER_SIZE;

    if (bak->record.device == DEVICE_UDS) {
        int32 ret = snprintf_s(&uds_path[0], GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, BAK_SUN_PATH_FORMAT,
            session->kernel->home, session->kernel->instance_name);
        knl_securec_check_ss(ret);
        if (bak_init_uds(&bak->remote.uds_link, uds_path) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    // send_stream buffers are released in bak_end
    if (cm_aligned_malloc(GS_BACKUP_BUFFER_SIZE, "bak stream buf0", &bak->send_stream.bufs[0]) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cm_aligned_malloc(GS_BACKUP_BUFFER_SIZE, "bak stream buf1", &bak->send_stream.bufs[1]) != GS_SUCCESS) {
        return GS_ERROR;
    }
    bak->send_stream.buf_size = GS_BACKUP_BUFFER_SIZE;

    return GS_SUCCESS;
}

static status_t bak_start_read_thread(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_process_t *proc = &ctx->process[BAK_COMMON_PROC];
    uint32 proc_count = ctx->bak.proc_count;

    proc->proc_id = BAK_COMMON_PROC;
    if (cm_aligned_malloc((int64)GS_BACKUP_BUFFER_SIZE, "backup process", &proc->backup_buf) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_BACKUP_BUFFER_SIZE, "backup process");
        return GS_ERROR;
    }

    if (cm_aligned_malloc((int64)GS_COMPRESS_BUFFER_SIZE, "backup process", &proc->encrypt_ctx.encrypt_buf) !=
        GS_SUCCESS) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_COMPRESS_BUFFER_SIZE, "backup process");
        return GS_ERROR;
    }

    if (cm_create_thread(bak_read_proc, 0, session, &proc->thread) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!bak_paral_task_enable(session)) {
        return GS_SUCCESS;
    }

    for (uint32 i = 1; i <= proc_count; i++) {
        proc = &ctx->process[i];
        proc->proc_id = i;
        proc->is_free = GS_FALSE;
        proc->compress_ctx.compress_level = ctx->bak.compress_ctx.compress_level;

        if (cm_aligned_malloc((int64)GS_BACKUP_BUFFER_SIZE, "backup process", &proc->backup_buf) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_BACKUP_BUFFER_SIZE, "backup process");
            return GS_ERROR;
        }

        if (cm_aligned_malloc((int64)GS_COMPRESS_BUFFER_SIZE, "backup process", &proc->encrypt_ctx.encrypt_buf) !=
            GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_COMPRESS_BUFFER_SIZE, "backup process");
            return GS_ERROR;
        }

        if (cm_aligned_malloc((int64)GS_COMPRESS_BUFFER_SIZE, "backup process", &proc->compress_ctx.compress_buf) !=
                              GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_COMPRESS_BUFFER_SIZE, "backup process");
            return GS_ERROR;
        }

        if (cm_create_thread(bak_paral_task_proc, 0, proc, &proc->thread) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    bak_wait_paral_proc(session);
    return GS_SUCCESS;
}

static status_t bak_start(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    bak_reset_process_ctrl(bak, GS_FALSE);
    bak_reset_stats(session);
    if (bak_alloc_resource(session, bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        GS_LOG_RUN_INF("[BUILD] ignore set head for break-point building");
    } else {
        if (bak_set_head(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (bak_alloc_compress_context(session, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_alloc_encrypt_context(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_start_read_thread(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t bak_set_log_ctrl(knl_session_t *session, bak_process_t *process, uint32 asn, uint32 *block_size)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    database_t *db = &session->kernel->db;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    bak_ctrl_t *ctrl = &process->ctrl;
    log_file_t *file = NULL;
    arch_ctrl_t *arch_ctrl = NULL;
    reset_log_t rst_log = db->ctrl.core.resetlogs;
    uint32 rst_id = (asn <= rst_log.last_asn) ? (rst_log.rst_id - 1) : rst_log.rst_id;
    errno_t ret;

    assign_ctrl->log_asn = asn;
    assign_ctrl->file_id = log_get_id_by_asn(session, rst_id, asn, NULL);
    assign_ctrl->file_size = 0;
    if (assign_ctrl->file_id == GS_INVALID_ID32) {
        ctrl->type = DEV_TYPE_FILE;
        arch_ctrl = arch_get_archived_log_info(session, rst_id, asn, ARCH_DEFAULT_DEST);
        if (arch_ctrl == NULL) {
            GS_LOG_RUN_ERR("[BACKUP] failed to get archived log for [%u-%u]", rst_id, asn);
            GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "archive log", "for backup");
            return GS_ERROR;
        }
        ret = strcpy_sp(ctrl->name, GS_FILE_NAME_BUFFER_SIZE, arch_ctrl->name);
        knl_securec_check(ret);
        GS_LOG_DEBUG_INF("[BACKUP] Get archived log %s for [%u-%u]", ctrl->name, rst_id, asn);
        *block_size = (uint32)arch_ctrl->block_size;
        bak_record_new_file(bak, BACKUP_ARCH_FILE, asn, 0);
    } else {
        file = &db->logfiles.items[assign_ctrl->file_id];
        ret = strcpy_sp(ctrl->name, GS_FILE_NAME_BUFFER_SIZE, file->ctrl->name);
        knl_securec_check(ret);
        ctrl->type = file->ctrl->type;
        *block_size = file->ctrl->block_size;
        GS_LOG_DEBUG_INF("[BACKUP] Get online log %s for [%u-%u] write pos %llu", ctrl->name, rst_id, asn,
                         file->head.write_pos);

        if (assign_ctrl->file_id == db->ctrl.core.log_last) {
            bak_record_new_file(bak, BACKUP_LOG_FILE, assign_ctrl->file_id, 0);
            assign_ctrl->file_size = file->head.write_pos;
        } else {
            bak_record_new_file(bak, BACKUP_ARCH_FILE, asn, 0);
        }
    }

    if (cm_open_device(ctrl->name, ctrl->type, knl_redo_io_flag(session), &ctrl->handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] failed to open %s", ctrl->name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void bak_unlatch_logfile(knl_session_t *session, bak_process_t *process)
{
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;

    if (assign_ctrl->file_id == GS_INVALID_ID32) {
        return;
    }
    log_unlatch_file(session, assign_ctrl->file_id);
}

static uint32 log_fetch_asn(knl_session_t *session, uint32 start_asn, uint64 scn)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    uint32 i;

    if (redo_ctx->files[redo_ctx->curr_file].head.first <= scn &&
        !log_is_empty(&redo_ctx->files[redo_ctx->curr_file].head)) {
        return redo_ctx->files[redo_ctx->curr_file].head.asn;
    }

    for (i = redo_ctx->active_file; i != redo_ctx->curr_file;) {
        if (redo_ctx->files[i].head.last > scn) {
            return redo_ctx->files[i].head.asn;
        }
        log_get_next_file(session, &i, GS_FALSE);
    }

    return redo_ctx->files[i].head.asn;
}

static status_t bak_switch_logfile(knl_session_t *session, uint32 last_asn, bool32 switch_log)
{
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    knl_panic(redo_ctx->files[redo_ctx->curr_file].head.asn >= last_asn);
    if (redo_ctx->files[redo_ctx->curr_file].head.asn != last_asn) {
        return GS_SUCCESS;
    }

    if (!switch_log) {
        return GS_SUCCESS;
    }
    ckpt_trigger(session, GS_FALSE, CKPT_TRIGGER_INC);

    if (DB_IS_RAFT_ENABLED(session->kernel) || DB_IS_PRIMARY(&session->kernel->db)) {
        return log_switch_logfile(session, GS_INVALID_FILEID, GS_INVALID_ASN, NULL);
    } else {
        return GS_SUCCESS;
    }
}

static status_t bak_fetch_last_log(knl_session_t *session, bak_t *bak, uint32 *last_asn)
{
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    if (BAK_DISTRIBUTED_PHASE_SECOND(bak)) {
        log_lock_logfile(session);
        *last_asn = log_fetch_asn(session, ctrlinfo->lrp_point.asn, bak->record.finish_scn);
        bak->record.ctrlinfo.scn = MIN(DB_CURR_SCN(session), bak->record.finish_scn);
        GS_LOG_RUN_INF("[BACKUP] fetch last log by scn %llu, new backup scn %llu",
                       bak->record.finish_scn, bak->record.ctrlinfo.scn);
        log_unlock_logfile(session);
    } else {
        *last_asn = ctrlinfo->lrp_point.asn;
    }

    if (BAK_IS_FULL_BUILDING(bak) && bak->progress.build_progress.stage == BACKUP_LOG_STAGE) {
        GS_LOG_RUN_INF("[BUILD] ignore switch logfile for break-point building");
        return GS_SUCCESS;
    }

    return bak_switch_logfile(session, *last_asn, GS_FALSE);
}

static status_t bak_notify_lrcv_record(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;

    if (DB_IS_RAFT_ENABLED(kernel)) {
        GS_LOG_RUN_WAR("do not record backupset info on raft mode");
        return GS_SUCCESS;
    }

    lrcv_trigger_backup_task(session);

    if (lrcv_wait_task_process(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* wait bak_read_proc read file data to send_buf */
static status_t bak_wait_write_data(bak_context_t *ctx, uint32 curr_file)
{
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;

    while (!bak->failed && bak->progress.stage != BACKUP_READ_FINISHED &&
           send_buf->offset != 0 && curr_file == bak->file_count) {
        cm_sleep(1);
        continue;
    }

    return bak->failed ? GS_ERROR : GS_SUCCESS;
}

static status_t bak_write_data(bak_context_t *ctx, char *buf, int32 size)
{
    bak_t *bak = &ctx->bak;
    bak_attr_t *attr = &bak->record.attr;
    bak_process_t proc = ctx->process[BAK_COMMON_PROC];

    if ((attr->compress == COMPRESS_NONE) || bak->progress.stage == BACKUP_HEAD_STAGE) {
        return bak_write(bak, &proc, buf, size);
    }

    return bak_compress_write(bak, &proc, buf, size, GS_FALSE);
}

static status_t bak_write_file(knl_session_t *session, uint32 curr_file)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;
    bak_attr_t *attr = &bak->record.attr;
    LZ4F_preferences_t ref = LZ4F_INIT_PREFERENCES;

    if (attr->compress == COMPRESS_LZ4 && bak->files[bak->curr_file_index].type != BACKUP_HEAD_FILE) {
        ref.compressionLevel = bak->compress_ctx.compress_level;
        size_t res = LZ4F_compressBegin(bak->compress_ctx.lz4f_cstream, bak->compress_buf,
            (uint32)GS_COMPRESS_BUFFER_SIZE, &ref);
        if (LZ4F_isError(res)) {
            GS_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
            return GS_ERROR;
        }
        if (bak_write(bak, &ctx->process[BAK_COMMON_PROC], bak->compress_buf, (int32)res) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    while (!bak->failed) {
        if (bak_check_session_status(session) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak_wait_write_data(ctx, curr_file) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (curr_file != bak->file_count || bak->progress.stage == BACKUP_READ_FINISHED) {
            break;
        }

        knl_panic(send_buf->offset == 0);
        knl_panic(send_buf->buf_size > 0);
        if (bak_write_data(ctx, send_buf->buf, send_buf->buf_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        bak_update_progress(bak, send_buf->buf_size);
        send_buf->offset = send_buf->buf_size;
    }

    if ((attr->compress != COMPRESS_NONE) && bak->files[bak->curr_file_index].type != BACKUP_HEAD_FILE) {
        if (bak_compress_write(bak, &ctx->process[BAK_COMMON_PROC], NULL, 0, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t bak_write_start(knl_session_t *session, uint32 file_index, uint32 sec_id)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    char *path = bak->record.path;

    bak->backup_size = 0;

    if (bak->is_building || bak->record.device == DEVICE_UDS) {
        uint32 start_type = bak_get_package_type(bak->files[file_index].type);
        if (bak_agent_file_start(bak, path, start_type, bak->files[file_index].id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        bak->remote.remain_data_size = 0;
    } else {
        bak_generate_bak_file(session, path, bak->files[file_index].type, file_index, bak->files[file_index].id, sec_id,
                              bak->local.name);
        if (cm_create_file(bak->local.name, O_BINARY | O_SYNC | O_RDWR | O_EXCL, &bak->local.handle) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (bak->files[file_index].type != BACKUP_HEAD_FILE && bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_init(bak, &ctx->process[BAK_COMMON_PROC].encrypt_ctx, &bak->files[file_index],
            GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (bak->files[file_index].type != BACKUP_HEAD_FILE && (bak->record.attr.compress != COMPRESS_NONE)) {
        if (knl_compress_init(bak->record.attr.compress, &bak->compress_ctx, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t bak_write_end(knl_session_t *session, bak_t *bak, bak_stage_t stage)
{
    bak_attr_t *attr = &bak->record.attr;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    errno_t ret;

    if (bak->is_building || bak->record.device == DEVICE_UDS) {
        if (bak_agent_send_pkg(bak, BAK_PKG_FILE_END) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak_agent_wait_pkg(bak, BAK_PKG_ACK) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak->is_building) {
            bak->curr_file_index++;
            if ((attr->compress != COMPRESS_NONE) && stage != BACKUP_HEAD_STAGE) {
                knl_compress_end(bak->record.attr.compress, &bak->compress_ctx, GS_TRUE);
            }
            return GS_SUCCESS;
        }
    } else {
        cm_close_file(bak->local.handle);
        bak->local.handle = GS_INVALID_HANDLE;
    }

    if ((attr->compress != COMPRESS_NONE) && stage != BACKUP_HEAD_STAGE) {
        knl_compress_end(bak->record.attr.compress, &bak->compress_ctx, GS_TRUE);
    }

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE && stage != BACKUP_HEAD_STAGE) {
        if (bak_encrypt_end(bak, &ctx->process[BAK_COMMON_PROC].encrypt_ctx) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (bak->files[bak->curr_file_index].type != BACKUP_HEAD_FILE) {
        knl_panic(bak->curr_file_index < BAK_MAX_FILE_NUM);
        bak->files[bak->curr_file_index].size = bak->backup_size;
        bak->files[bak->curr_file_index].sec_start = 0;
        bak->files[bak->curr_file_index].sec_end = 0;
        if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
            ret = memcpy_sp(bak->files[bak->curr_file_index].gcm_tag, EVP_GCM_TLS_TAG_LEN,
                ctx->process[BAK_COMMON_PROC].encrypt_ctx.encrypt_buf.aligned_buf, EVP_GCM_TLS_TAG_LEN);
            knl_securec_check(ret);
        }
        bak->curr_file_index++;
    }

    return GS_SUCCESS;
}

static status_t bak_write_files(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_stage_t stage = BACKUP_START;

    while (!bak->failed && bak->progress.stage != BACKUP_READ_FINISHED) {
        if (bak_check_session_status(session) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak->curr_file_index == bak->file_count) {
            cm_sleep(1);
            continue;
        }

        bak_file_type_t type = bak->files[bak->curr_file_index].type;
        if (type >= BACKUP_DATA_FILE && type <= BACKUP_ARCH_FILE) {
            bak->ctrlfile_completed = GS_TRUE;
            if (bak_paral_task_enable(session)) {
                cm_sleep(10);
                continue;
            }
        }

        stage = bak->progress.stage;
        if (bak_write_start(session, bak->curr_file_index, 0) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak_write_file(session, bak->curr_file_index + 1) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] bak_write_file write exit");
            return GS_ERROR;
        }

        if (bak_write_end(session, bak, stage) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return bak->failed ? GS_ERROR : GS_SUCCESS;
}

static status_t bak_record(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    if (bak->is_building) {
        return GS_SUCCESS;
    }

    if (session->kernel->db.status == DB_STATUS_MOUNT) {
        return GS_SUCCESS;
    }

    if (DB_IS_PRIMARY(&session->kernel->db)) {
        bak->record.status = (bak->failed) ? BACKUP_FAILED : BACKUP_SUCCESS;
        return bak_record_backup_set(session, &bak->record);
    }

    return bak_notify_lrcv_record(session);
}

static status_t bak_write_config_param(bak_context_t *ctx)
{
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;

    GS_LOG_RUN_INF("[BACKUP] start write config parameter");
    while (!bak->failed) {
        if (bak_wait_write_data(ctx, 0) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (bak->file_count != 0) {
            break;
        }

        knl_panic(send_buf->offset == 0);
        knl_panic(send_buf->buf_size > 0);

        if (bak_write(&ctx->bak, &ctx->process[BAK_COMMON_PROC], send_buf->buf,
            (int32)send_buf->buf_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        bak_update_progress(bak, send_buf->buf_size);
        send_buf->offset = send_buf->buf_size;
    }
    GS_LOG_RUN_INF("[BACKUP] write config parameter successfully");

    return GS_SUCCESS;
}

static status_t bak_wait_write_ctrl_file(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;

    if (send_buf->offset < send_buf->buf_size) {
        return GS_SUCCESS;
    }

    while ((!bak->failed && send_buf->offset != 0) || send_buf->buf_size == 0) {
        if (bak_check_session_status(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
        cm_sleep(1);
        continue;
    }

    return bak->failed ? GS_ERROR : GS_SUCCESS;
}

static status_t bak_write_ctrl_file(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;
    bak_agent_head_t head;

    if (!BAK_IS_FULL_BUILDING(bak)) {
        return GS_SUCCESS;
    }

    if (bak->is_first_link) {
        return GS_SUCCESS;
    }

    GS_LOG_RUN_INF("[BACKUP] start write ctrl file");
    for (uint32 i = 0; i < BAK_BUILD_CTRL_SEND_TIME; i++) {
        if (bak_wait_write_ctrl_file(session) != GS_SUCCESS) {
            return GS_ERROR;
        }

        knl_panic(send_buf->offset == 0);
        knl_panic(send_buf->buf_size > 0);

        head.ver = BAK_AGENT_PROTOCOL;
        head.cmd = BAK_PKG_DATA;
        head.len = sizeof(bak_agent_head_t) + send_buf->buf_size;
        head.flags = 0;
        head.serial_number = 0;
        head.reserved = 0;

        if (bak_agent_send(bak, (char *)&head, sizeof(bak_agent_head_t)) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (bak_agent_send(bak, send_buf->buf, send_buf->buf_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
        send_buf->offset += send_buf->buf_size;
        GS_LOG_RUN_INF("send_buf->offset : %u ", send_buf->offset);
        GS_LOG_RUN_INF("send_buf->buf_size : %u ", send_buf->buf_size);
    }

    if (bak_agent_wait_pkg(bak, BAK_PKG_ACK) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[BACKUP] write ctrl file successfully");

    return GS_SUCCESS;
}

static status_t bak_write_proc(knl_session_t *session, bak_context_t *ctx)
{
    bak_t *bak = &ctx->bak;

    // send param
    if (bak->is_building && bak->is_first_link && !bak->record.is_repair) {
        if (bak_write_config_param(ctx) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    if (bak_write_ctrl_file(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_agent_command(bak, BAK_PKG_SET_START) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_write_files(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_agent_command(bak, BAK_PKG_SET_END) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak->record.device == DEVICE_UDS) {
        cs_uds_disconnect(&bak->remote.uds_link);
    }

    return GS_SUCCESS;
}

status_t bak_load_tablespaces(knl_session_t *session)
{
    for (uint16 i = 0; i < GS_MAX_SPACES; i++) {
        space_t *space = SPACE_GET(i);
        if (space->ctrl->file_hwm == 0) {
            continue;
        }

        if (!SPACE_IS_ONLINE(space)) {
            continue;
        }

        if (spc_mount_space(session, space, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t bak_load_files(knl_session_t *session)
{
    if (bak_load_tablespaces(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (log_load(session) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] backup failed when load log in mount mode");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void bak_unload_tablespace(knl_session_t *session)
{
    for (uint16 i = 0; i < GS_MAX_SPACES; i++) {
        space_t *space = SPACE_GET(i);
        if (space->ctrl->file_hwm == 0) {
            continue;
        }

        if (!SPACE_IS_ONLINE(space)) {
            continue;
        }

        spc_umount_space(session, space);
    }
}

status_t bak_precheck(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;

    if (!session->kernel->db.ctrl.core.build_completed) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_COMPLETED);
        return GS_ERROR;
    }

    if (session->kernel->backup_ctx.bak.build_stopped) {
        GS_THROW_ERROR(ERR_BUILD_CANCELLED);
        return GS_ERROR;
    }

    if (!arch_ctx->is_archive) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_ARCHIVE, "can not execute backup prepare");
        return GS_ERROR;
    }

    if (session->kernel->switch_ctrl.request != SWITCH_REQ_NONE) {
        GS_THROW_ERROR(ERR_SESSION_CLOSED, "server is doing switch request");
        return GS_ERROR;
    }

    if (DB_IS_RAFT_ENABLED(session->kernel) && !DB_IS_PRIMARY(&session->kernel->db) && raft_is_primary_alive(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION,
                       "not allowed to backup on standby node when primary is alive in raft mode");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_backup_proc(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    status_t status;

    if (knl_ddl_latch_s(&session->kernel->db.ddl_latch, (knl_handle_t)session, NULL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_start(session) != GS_SUCCESS) {
        cm_unlatch(&session->kernel->db.ddl_latch, NULL);
        bak->failed = GS_TRUE;
        bak_end(session, GS_FALSE);
        return GS_ERROR;
    }
    if (bak_write_proc(session, ctx) != GS_SUCCESS) {
        cm_unlatch(&session->kernel->db.ddl_latch, NULL);
        bak->failed = GS_TRUE;
        bak_end(session, GS_FALSE);
        return GS_ERROR;
    }
    cm_unlatch(&session->kernel->db.ddl_latch, NULL);

    status = bak_record(session);
    bak_end(session, GS_FALSE);
    return status;
}

static status_t bak_backup_database_internal(knl_session_t *session, knl_backup_t *param)
{
    uint32 proc_count = param->parallelism == 0 ? BAK_DEFAULT_PARALLELISM : param->parallelism;
    bak_context_t *ctx = &session->kernel->backup_ctx;

    if (bak_precheck(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (bak_set_running(ctx) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_BACKUP_IN_PROGRESS, "backup or delete backupset");
        return GS_ERROR;
    }
    if (DB_IS_PRIMARY(&session->kernel->db) && DB_IS_READONLY(session) && param->type != BACKUP_MODE_FULL) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION,
                       ", only full backup is allowed when primary is read-only mode");
        bak_unset_running(&session->kernel->backup_ctx);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[BACKUP] backup start, type :%d, level:%d, path:%s, device:%d, "
                   "policy:%s, tag:%s, finish scn :%llu, prepare:%d, process count %u, compress type:%u level:%u",
                   param->type, param->level, T2S(&param->format), param->device, T2S_EX(&param->policy), param->tag,
                   param->finish_scn, param->prepare, proc_count, param->compress_algo, param->compress_level);
    if (bak_set_params(session, param) != GS_SUCCESS) {
        bak_unset_running(&session->kernel->backup_ctx);
        return GS_ERROR;
    }

    if (bak_backup_proc(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_backup_database(knl_session_t *session, knl_backup_t *param)
{
    status_t status = GS_SUCCESS;

    if (param->force_cancel) {
        session->kernel->backup_ctx.bak.failed = GS_TRUE;
        session->kernel->backup_ctx.bak.record.data_only = GS_FALSE;
        GS_LOG_RUN_WAR("[BACKUP] backup process is canceled by user");
        return GS_SUCCESS;
    }

    if (BAK_NEED_LOAD_FILE(session)) {
        if (bak_load_files(session) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] backup failed when load spaces in mount mode");
            return GS_ERROR;
        }
    }

    if (bak_backup_database_internal(session, param) != GS_SUCCESS) {
        status = GS_ERROR;
    }

    if (BAK_NEED_UNLOAD_FILE(session)) {
        bak_unload_tablespace(session);
    }

    return status;
}

static void bak_set_read_range(knl_session_t *session, bak_assignment_t *assign_ctrl, uint64 offset)
{
    datafile_t *df = DATAFILE_GET(assign_ctrl->file_id);
    uint32 sec_id = assign_ctrl->sec_id;

    bool32 contains_dw = bak_datafile_contains_dw(session, assign_ctrl);
    if (contains_dw && offset == 2 * DEFAULT_PAGE_SIZE) {      /* skip double write area */
        offset = DW_SPC_HWM_START * DEFAULT_PAGE_SIZE;
    }

    uint64 read_size = bak_set_datafile_read_size(session, offset, contains_dw,
        assign_ctrl->file_size, assign_ctrl->file_hwm_start);
    if (read_size > GS_BACKUP_BUFFER_SIZE) {
        read_size = GS_BACKUP_BUFFER_SIZE;
    }

    if (BAK_IS_UDS_DEVICE(&session->kernel->backup_ctx.bak) && read_size > GS_BACKUP_STREAM_BUFSIZE) {
        read_size = GS_BACKUP_STREAM_BUFSIZE;
    }

    assign_ctrl->start = offset;
    assign_ctrl->end = offset + read_size;
    spc_block_datafile(df, sec_id, assign_ctrl->start, assign_ctrl->end);
}

static bool32 bak_check_page_list(knl_session_t *session, page_head_t *page)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    page_id_t id = PAGE_GET_PAGEID(page);
    uint32 file_hash = id.file % BUILD_ALY_MAX_FILE;
    uint32 page_hash = id.page % BUILD_ALY_MAX_BUCKET_PER_FILE;
    build_analyse_bucket_t *bucket = &bak->build_aly_buckets[file_hash * BUILD_ALY_MAX_BUCKET_PER_FILE + page_hash];
    build_analyse_item_t *item = bucket->first;

    while (item != NULL) {
        if (IS_SAME_PAGID(id, *item->page_id)) {
            GS_LOG_DEBUG_INF("[REPAIR] find page %u-%u", id.file, id.page);
            return GS_TRUE;
        }
        item = item->next;
    }

    return GS_FALSE;
}

static void bak_filter_pages(knl_session_t *session, bak_process_t *ctx)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_attr_t *attr = &backup_ctx->bak.record.attr;
    uint64 base_lsn = attr->base_lsn;
    uint32 level = attr->level;
    int32 size;
    errno_t ret;

    if (level == 0) {
        ctx->write_size = ctx->read_size;
        return;
    }

    for (ctx->write_size = 0, size = 0; size < ctx->read_size; size += DEFAULT_PAGE_SIZE) {
        page_head_t *page = (page_head_t *)(ctx->backup_buf.aligned_buf + size);

        if (page->lsn >= base_lsn || (backup_ctx->bak.record.is_repair && bak_check_page_list(session, page))) {
            GS_LOG_DEBUG_INF("[BAK] incr backup get page_id %u-%u", AS_PAGID_PTR(page->id)->file, 
                AS_PAGID_PTR(page->id)->page);
            if (ctx->write_size < size) {
                ret = memcpy_sp(ctx->backup_buf.aligned_buf + ctx->write_size, 
                    GS_BACKUP_BUFFER_SIZE - (uint32)ctx->write_size, ctx->backup_buf.aligned_buf + size, 
                    DEFAULT_PAGE_SIZE);
                knl_securec_check(ret);
            }
            ctx->write_size += (int32)DEFAULT_PAGE_SIZE;
        }
    }
}

static void bak_fetch_read_range(knl_session_t *session, bak_process_t *bak_proc)
{
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bak_ctrl_t *ctrl = &bak_proc->ctrl;

    bak_proc->read_size = 0;
    knl_panic(ctrl->offset < assign_ctrl->file_size);

    bak_set_read_range(session, assign_ctrl, ctrl->offset);
    uint64 size = assign_ctrl->end - assign_ctrl->start;
    knl_panic(size <= GS_BACKUP_BUFFER_SIZE);
    bak_proc->read_size = (int32)size; // size <= 8M, can not overflow
    ctrl->offset = assign_ctrl->start;
}

status_t bak_read_datafile_pages(knl_session_t *session, bak_process_t *bak_proc)
{
    bak_ctrl_t *ctrl = &bak_proc->ctrl;
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_stat_t *stat = &bak_ctx->bak.stat;

    bak_fetch_read_range(session, bak_proc);
    if (cm_read_device(ctrl->type, ctrl->handle, ctrl->offset, bak_proc->backup_buf.aligned_buf,
                       bak_proc->read_size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] failed to read %s", ctrl->name);
        spc_unblock_datafile(DATAFILE_GET(assign_ctrl->file_id), assign_ctrl->sec_id);
        return GS_ERROR;
    }
    spc_unblock_datafile(DATAFILE_GET(assign_ctrl->file_id), assign_ctrl->sec_id);
#ifndef WIN32
    if (bak_need_decompress(session, bak_proc)) {
        if (bak_decompress_and_verify_datafile(session, bak_proc)) {
            return GS_ERROR;
        }
    } else {
        if (bak_verify_datafile_checksum(session, bak_proc, ctrl->offset, ctrl->name) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
#endif
    (void)cm_atomic_inc(&stat->reads);
    (void)cm_atomic_inc(&session->kernel->total_io_read);

    ctrl->offset += bak_proc->read_size;
    bak_filter_pages(session, bak_proc);
    return GS_SUCCESS;
}

void bak_close(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;

    bak->failed = GS_TRUE;
}

/* wait bak_write_proc write send_buf data to local disk */
static status_t bak_wait_write(bak_t *bak)
{
    bak_buf_t *send_buf = &bak->send_buf;

    while (!bak->failed && send_buf->offset != send_buf->buf_size) {
        cm_sleep(1);
        continue;
    }

    return bak->failed ? GS_ERROR : GS_SUCCESS;
}

static void bak_offline_space(knl_session_t *session, ctrl_page_t *pages, uint32 id)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;

    // pages from backup buffer, not the original database ctrl pages
    space_ctrl_t *space = (space_ctrl_t *)db_get_ctrl_item(pages, id, sizeof(space_ctrl_t), ctrl->space_segment);
    CM_CLEAN_FLAG(space->flag, SPACE_FLAG_ONLINE);
    GS_LOG_RUN_INF("[BAK] backup offline space %s", space->name);

    for (uint32 i = 0; i < space->file_hwm; i++) {
        uint32 file = space->files[i];
        if (file == GS_INVALID_ID32) {
            continue;
        }
        datafile_ctrl_t *datafile = (datafile_ctrl_t *)db_get_ctrl_item(pages, file, sizeof(datafile_ctrl_t),
            ctrl->datafile_segment);
        CM_CLEAN_FLAG(datafile->flag, DATAFILE_FLAG_ONLINE);
    }
}

static void bak_offline_exclude_spaces(knl_session_t *session, ctrl_page_t *pages, bak_t *bak)
{
    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        if (!bak->exclude_spcs[i]) {
            continue;
        }

        bak_offline_space(session, pages, i);
    }
}

static void bak_read_ctrl_pages(knl_session_t *session, bak_t *bak, ctrl_page_t *pages, uint32 page_count)
{
    bak_buf_t *send_buf = &bak->send_buf;
    uint32 size = page_count * GS_DFLT_CTRL_BLOCK_SIZE;

    knl_panic(size <= GS_BACKUP_BUFFER_SIZE);
    errno_t ret = memcpy_sp(bak->backup_buf, GS_BACKUP_BUFFER_SIZE, pages, size);
    knl_securec_check(ret);

    bak_offline_exclude_spaces(session, (ctrl_page_t *)bak->backup_buf, bak);
    bak_calc_ctrlfile_checksum(session, bak->backup_buf, page_count);

    send_buf->buf = bak->backup_buf;
    send_buf->buf_size = size;
    send_buf->offset = 0;
}

static void bak_read_arch_pages(knl_session_t *session, bak_t *bak, uint32 page_count)
{
    bak_buf_t *send_buf = &bak->send_buf;
    uint32 size = page_count * GS_DFLT_CTRL_BLOCK_SIZE;

    knl_panic(size <= GS_BACKUP_BUFFER_SIZE);
    errno_t ret = memset_sp(bak->backup_buf, GS_BACKUP_BUFFER_SIZE, 0, size);
    knl_securec_check(ret);

    send_buf->buf = bak->backup_buf;
    send_buf->buf_size = size;
    send_buf->offset = 0;
    GS_LOG_RUN_INF("[BACKUP] arch send_buf->buf_size : %u", send_buf->buf_size);
}

static status_t bak_read_ctrlfile(knl_session_t *session)
{
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    database_t *db = &session->kernel->db;
    uint32 page_count = db->ctrl.arch_segment;

    GS_LOG_RUN_INF("[BACKUP] start read ctrl files");
    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        GS_LOG_RUN_INF("[BUILD] ignore setting progress for break-point building");
    } else {
        bak->ctrlfile_completed = GS_FALSE;
        bak_set_progress(session, BACKUP_CTRL_STAGE, CTRL_MAX_PAGE * GS_DFLT_CTRL_BLOCK_SIZE);
        bak_record_new_file(bak, BACKUP_CTRL_FILE, 0, 0);
    }

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);
    bak_read_ctrl_pages(session, bak, db->ctrl.pages, page_count);
    cm_spin_unlock(&db->ctrl_lock);

    if (bak_wait_write(bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    page_count = CTRL_MAX_PAGE - db->ctrl.arch_segment;
    bak_read_arch_pages(session, bak, page_count);

    if (bak_wait_write(bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_DEBUG_INF("[BACKUP] prepare ctrl");

    return GS_SUCCESS;
}

static status_t bak_read_keyfile(knl_session_t *session, char *buf, uint64 buf_size)
{
    int32 handle = INVALID_FILE_HANDLE;
    char keyfile_name[GS_FILE_NAME_BUFFER_SIZE];
    int32 read_size = 0;
    int64 file_size = 0;

    if (!g_knl_callback.have_ssl()) {
        ((keyfile_ctrl_t *)buf)->size = file_size;
        GS_LOG_RUN_INF("HA don't have ssl, can't send keyfile when build standby");
        return GS_SUCCESS;
    }

    errno_t ret = snprintf_s(keyfile_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s.building.export",
                             session->kernel->attr.kmc_key_files[0].name);
    knl_securec_check_ss(ret);

    if (cm_file_exist(keyfile_name)) {
        if (cm_remove_file(keyfile_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("failed to remove building key file %s", keyfile_name);
            return GS_ERROR;
        }
    }

    if (cm_kmc_export_keyfile(keyfile_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_open_file(keyfile_name, O_RDONLY | O_BINARY, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    file_size = cm_file_size(handle);
    if (file_size <= 0) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("[BACKUP READ KEYFILE ERROR]seek file failed :%s.", keyfile_name);
        return GS_ERROR;
    }

    knl_panic((uint64)file_size + sizeof(keyfile_ctrl_t) <= buf_size);

    if (cm_seek_file(handle, 0, SEEK_SET) != 0) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("[BACKUP READ KEYFILE ERROR]seek file failed :%s.", keyfile_name);
        return GS_ERROR;
    }

    ((keyfile_ctrl_t *)buf)->size = file_size;
    if (cm_read_file(handle, buf + sizeof(keyfile_ctrl_t), (int32)(buf_size - sizeof(keyfile_ctrl_t)),
                     &read_size) != GS_SUCCESS) {
        cm_close_file(handle);
        GS_LOG_RUN_ERR("[BACKUP READ KEYFILE ERROR]read file failed :%s.", keyfile_name);
        return GS_ERROR;
    }
    cm_close_file(handle);

    if (read_size != file_size) {
        GS_LOG_RUN_ERR("[BACKUP READ KEYFILE ERROR]file %s, read size %d, file size %lld.",
            keyfile_name, read_size, file_size);
        return GS_ERROR;
    }

    if (cm_file_exist(keyfile_name)) {
        if (cm_remove_file(keyfile_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("failed to remove building key file %s", keyfile_name);
            return GS_ERROR;
        }
    }

    GS_LOG_DEBUG_INF("[BACKUP] prepare key file");
    return GS_SUCCESS;
}

static status_t bak_write_to_write_buf(bak_context_t *ctx, const void *buf, int32 size)
{
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;

    if (bak_wait_write(bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic(size > 0);
    errno_t ret = memcpy_sp(bak->backup_buf, GS_BACKUP_BUFFER_SIZE, buf, size);
    knl_securec_check(ret);
    send_buf->buf = bak->backup_buf;
    send_buf->buf_size = (uint32)size;
    CM_MFENCE;
    send_buf->offset = 0;
    GS_LOG_DEBUG_INF("[BACKUP] prepare data, size %u", size);
    return GS_SUCCESS;
}

void bak_read_prepare(knl_session_t *session, bak_process_t *process, datafile_t *datafile, uint32 sec_id)
{
    bak_context_t *bkup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bkup_ctx->bak;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    bak_ctrl_t *ctrl = &process->ctrl;
    build_progress_t *build_progress = &bak->progress.build_progress;

    errno_t ret = strcpy_sp(ctrl->name, GS_FILE_NAME_BUFFER_SIZE, datafile->ctrl->name);
    knl_securec_check(ret);
    ctrl->type = datafile->ctrl->type;

    if (BAK_IS_FULL_BUILDING(bak) && bak->need_check) {
        GS_LOG_RUN_INF("[BUILD] reset ctrl offset for break-point building");
        ctrl->offset = build_progress->data_offset;
        bak->need_check = GS_FALSE;
    } else {
        ctrl->offset = DEFAULT_PAGE_SIZE;
    }

    assign_ctrl->start = ctrl->offset;
    assign_ctrl->end = ctrl->offset;
    assign_ctrl->file_id = datafile->ctrl->id;
    assign_ctrl->sec_id = sec_id;
    assign_ctrl->type = ctrl->type;

    bak_record_new_file(bak, BACKUP_DATA_FILE, assign_ctrl->file_id, sec_id);
}

status_t bak_read_datafile(knl_session_t *session, bak_process_t *bak_proc, bool32 to_disk)
{
    bak_context_t *bak_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bak_ctx->bak;
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bak_ctrl_t *ctrl = &bak_proc->ctrl;
    uint64 curr_offset = ctrl->offset;
    status_t status;
    date_t start;

    /* open when backup datafiles, closed in this function */
    if (cm_open_device(ctrl->name, ctrl->type, knl_io_flag(session), &ctrl->handle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!bak->failed) {
        if (ctrl->offset == assign_ctrl->file_size) {
            break;
        }

        start = g_timer()->now;
        if (bak_read_datafile_pages(session, bak_proc) != GS_SUCCESS) {
            bak->failed = GS_TRUE;
            break;
        }
        bak_proc->stat.read_time += (g_timer()->now - start);
        bak_proc->stat.read_size += (ctrl->offset - curr_offset);
        curr_offset = ctrl->offset;

        if (bak_proc->write_size == 0) {
            continue;
        }

        if (to_disk) {
            status = bak_write_to_local_disk(bak_ctx, bak_proc, bak_proc->backup_buf.aligned_buf,
                                             bak_proc->write_size, GS_FALSE);
        } else {
            status = bak_write_to_write_buf(bak_ctx, bak_proc->backup_buf.aligned_buf, bak_proc->write_size);
        }

        if (status != GS_SUCCESS) {
            bak->failed = GS_TRUE;
            break;
        }
    }

    cm_close_device(ctrl->type, &ctrl->handle);

    if (!to_disk) {
        if (bak_wait_write(bak) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t bak_wait_ctrlfiles_ready(bak_t *bak)
{
    while (!bak->ctrlfile_completed) {
        if (bak->failed) {
            return GS_ERROR;
        }
        cm_sleep(1);
    }
    return GS_SUCCESS;
}

status_t bak_stream_read_datafile(knl_session_t *session, bak_process_t *process, datafile_ctrl_t *df_ctrl,
                                  uint64 data_size, uint32 hwm_start)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    bak_stream_buf_t *stream_buf = &bak->send_stream;
    char *path = bak->record.path;

    if (bak_wait_ctrlfiles_ready(bak) != GS_SUCCESS) {
        return GS_ERROR;
    }
    bak_init_send_stream(bak, DEFAULT_PAGE_SIZE, assign_ctrl->file_size, assign_ctrl->file_id);

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_rand_iv(&bak->files[bak->curr_file_index]) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    bak->backup_size = 0;
    uint32 start_type = bak_get_package_type(bak->files[bak->curr_file_index].type);
    if (bak_agent_file_start(bak, path, start_type, bak->files[bak->curr_file_index].id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    bak->remote.remain_data_size = 0;

    bak_assign_stream_backup_task(session, df_ctrl->type, df_ctrl->name, df_ctrl->id, data_size, hwm_start);
    if (bak_send_stream_data(session, bak, assign_ctrl) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bak_wait_paral_proc(session);
    if (bak_stream_send_end(bak, stream_buf) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t bak_read_datafiles(knl_session_t *session, bak_process_t *process)
{
    bak_context_t *bkup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &bkup_ctx->bak;
    bak_assignment_t *assign_ctrl = &process->assign_ctrl;
    build_progress_t *build_progress = &bak->progress.build_progress;
    bak_ctrl_t *ctrl = &process->ctrl;
    bak_stage_t *stage = &bak->progress.build_progress.stage;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_DATA_STAGE) {
        GS_LOG_RUN_INF("[BUILD] ignore read datafiles for break-point building");
        return GS_SUCCESS;
    }

    if (bak_check_datafiles_num(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint64 data_size = db_get_datafiles_used_size(session);
    bak_set_progress(session, BACKUP_DATA_STAGE, data_size);
    if (bak_paral_task_enable(session) && !BAK_IS_UDS_DEVICE(bak)) {
        if (bak_get_section_threshold(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (BAK_IS_FULL_BUILDING(bak) && !bak->is_first_link) {
        GS_LOG_RUN_INF("[BUILD] bak->is_first_link : %u", bak->is_first_link);
        assign_ctrl->file_id = build_progress->file_id;
        ctrl->offset = build_progress->data_offset;
    } else {
        assign_ctrl->file_id = 0;
    }

    while (!bak->failed) {
        datafile_t *datafile = db_get_next_datafile(session, assign_ctrl->file_id, &assign_ctrl->file_size,
            &assign_ctrl->file_hwm_start);
        if (datafile == NULL) {
            break;
        }

        if (bak->target_info.target == TARGET_ALL && bak->exclude_spcs[datafile->space_id]) {
            assign_ctrl->file_id = datafile->ctrl->id + 1;
            continue;
        }

        if (bak->target_info.target == TARGET_TABLESPACE && !bak->include_spcs[datafile->space_id]) {
            assign_ctrl->file_id = datafile->ctrl->id + 1;
            continue;
        }

        data_size = assign_ctrl->file_size;
        if (bak_paral_task_enable(session)) {
            if (BAK_IS_UDS_DEVICE(bak)) {
                bak_read_prepare(session, process, datafile, 0);
                if (bak_stream_read_datafile(session, process, datafile->ctrl, data_size, 
                    assign_ctrl->file_hwm_start) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            } else {
                if (bak_paral_backup_datafile(session, assign_ctrl, datafile, data_size) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
            bak_read_prepare(session, process, datafile, 0);
            GS_LOG_RUN_INF("[BACKUP] backup datafile %u, size %lluKB",
                           assign_ctrl->file_id, data_size / SIZE_K(1));
            if (bak_read_datafile(session, process, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        assign_ctrl->file_id = datafile->ctrl->id + 1;
    }

    bak_wait_paral_proc(session);
    return (bak->failed) ? GS_ERROR : GS_SUCCESS;
}

bool32 bak_logfile_not_backed(knl_session_t *session, uint32 asn)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_progress_t *progress = &bak->progress;
    bool32 bak_done = GS_FALSE;

    cm_spin_lock(&progress->lock, NULL);
    if (progress->stage == BACKUP_DATA_STAGE) {
        bak_done = (asn < bak->arch_stat.start_asn);
        cm_spin_unlock(&progress->lock);
        return !bak_done;
    }

    if (progress->stage != BACKUP_LOG_STAGE) {
        cm_spin_unlock(&progress->lock);
        return GS_TRUE;
    }
    if (asn >= bak->arch_stat.start_asn && (asn - bak->arch_stat.start_asn) < BAK_MAX_FILE_NUM) {
        bak_done = bak->arch_stat.bak_done[asn - bak->arch_stat.start_asn];
    } else if (asn < bak->arch_stat.start_asn) {
        bak_done = GS_TRUE;
    } else {
        bak_done = GS_FALSE;
    }
    cm_spin_unlock(&progress->lock);
    return !bak_done;
}

static void bak_set_logfile_backed(knl_session_t *session, uint32 asn)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;

    if (asn >= bak->arch_stat.start_asn && (asn - bak->arch_stat.start_asn) < BAK_MAX_FILE_NUM) {
        bak->arch_stat.bak_done[asn - bak->arch_stat.start_asn] = GS_TRUE;
    } else {
        GS_LOG_RUN_ERR("[BACKUP] failed to refresh logfile bakcup status for asn %u, start asn is %u",
                       asn, bak->arch_stat.start_asn);
    }
}

status_t bak_read_logfile(knl_session_t *session, bak_context_t *ctx, bak_process_t *bak_proc,
                          uint32 block_size, bool32 to_disk)
{
    bak_assignment_t *assign_ctrl = &bak_proc->assign_ctrl;
    bak_ctrl_t *ctrl = &bak_proc->ctrl;
    char *backup_buf = bak_proc->backup_buf.aligned_buf;
    log_file_head_t *head = (log_file_head_t *)backup_buf;
    bak_local_t *bak_file = &bak_proc->assign_ctrl.bak_file;
    bak_t *bak = &session->kernel->backup_ctx.bak;
    status_t status = GS_ERROR;

    ctrl->offset = 0;
    int32 read_size = CM_CALC_ALIGN(sizeof(log_file_head_t), block_size);
    if (bak_read_data(bak_proc, ctrl, head, read_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (log_verify_head_checksum(session, head, ctrl->name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (assign_ctrl->file_size > 0) {
        head->write_pos = assign_ctrl->file_size;
        log_calc_head_checksum(session, head);
    }
    
    uint64 file_size = (head->cmp_algorithm != COMPRESS_NONE) ? (uint64)cm_file_size(ctrl->handle) : head->write_pos;
    GS_LOG_RUN_INF("[BACKUP] prepare log, size %lluKB", file_size / SIZE_K(1));

    if (to_disk) {
        if (bak_local_write(bak_file, backup_buf, read_size, bak) != GS_SUCCESS) { // do not compress log head
            return GS_ERROR;
        }
        bak_file->size += read_size;
        bak_update_progress(bak, (uint64)read_size);
        if (bak_write_lz4_compress_head(bak, bak_proc, bak_file) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (bak_write_to_write_buf(ctx, backup_buf, read_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    knl_panic(file_size >= (uint32)read_size);
    uint64 data_size = file_size - read_size;
    while (data_size > 0) {
        /* when data_size > 8M, read_size = 8M, can not overflow */
        read_size = data_size > GS_BACKUP_BUFFER_SIZE ? (int32)GS_BACKUP_BUFFER_SIZE : (int32)data_size;
        if (bak_read_data(bak_proc, ctrl, backup_buf, read_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (to_disk) {
            status = bak_write_to_local_disk(ctx, bak_proc, backup_buf, read_size, GS_FALSE);
        } else {
            status = bak_write_to_write_buf(ctx, backup_buf, read_size);
        }

        if (status != GS_SUCCESS) {
            return GS_ERROR;
        }

        data_size -= read_size;
    }

    /* logfile backed flag used for determining to clean arch log when backup full database */
    if (bak->target_info.target != TARGET_ARCHIVE) {
        bak_set_logfile_backed(session, assign_ctrl->log_asn);
    }

    return GS_SUCCESS;
}

static status_t bak_get_start_asn(knl_session_t *session, uint32 *start_asn, uint32 last_asn)
{
    knl_instance_t *kernel = session->kernel;
    bak_t *bak = &kernel->backup_ctx.bak;
    arch_ctrl_t *start_ctrl = db_get_arch_ctrl(session, kernel->db.ctrl.core.archived_start);

    if (bak->target_info.backup_arch_mode == ARCHIVELOG_ALL) {
        *start_asn = start_ctrl->asn;
    } else {
        *start_asn = bak->target_info.backup_begin_asn;
    }

    if (*start_asn < start_ctrl->asn || *start_asn > last_asn) {
        GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
            " asn: '%d' is not in the range of archivelogs", *start_asn);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t bak_send_logfile_head(knl_session_t *session, bak_process_t *proc, uint32 block_size,
                               uint64 *file_size)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    char *backup_buf = proc->backup_buf.aligned_buf;
    log_file_head_t *head = (log_file_head_t *)backup_buf;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    int32 read_size = CM_CALC_ALIGN(sizeof(log_file_head_t), block_size);
    bak_ctrl_t *ctrl = &proc->ctrl;

    ctrl->offset = 0;
    if (bak_read_data(proc, ctrl, head, read_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (log_verify_head_checksum(session, head, ctrl->name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (assign_ctrl->file_size > 0) {
        head->write_pos = assign_ctrl->file_size;
        log_calc_head_checksum(session, head);
    }

    *file_size = head->write_pos;
    GS_LOG_RUN_INF("[BACKUP] prepare log, size %lluKB", *file_size / SIZE_K(1));

    if (bak_agent_write(bak, backup_buf, read_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bak_update_progress(bak, read_size);
    return GS_SUCCESS;
}

status_t bak_stream_read_logfile(knl_session_t *session, bak_process_t *proc, uint32 block_size)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    bak_stream_buf_t *stream = &bak->send_stream;
    bak_assignment_t *assign_ctrl = &proc->assign_ctrl;
    char *path = bak->record.path;
    uint64 file_size = 0;

    if (bak_wait_ctrlfiles_ready(bak) != GS_SUCCESS) {
        return GS_ERROR;
    }
    bak->backup_size = 0;

    if (bak->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        if (bak_encrypt_rand_iv(&bak->files[bak->curr_file_index]) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    uint32 start_type = bak_get_package_type(bak->files[bak->curr_file_index].type);
    if (bak_agent_file_start(bak, path, start_type, bak->files[bak->curr_file_index].id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    bak->remote.remain_data_size = 0;

    if (bak_send_logfile_head(session, proc, block_size, &file_size) != GS_SUCCESS) {
        return GS_ERROR;
    }
    assign_ctrl->file_size = file_size;

    bak_init_send_stream(bak, CM_CALC_ALIGN(sizeof(log_file_head_t), block_size), assign_ctrl->file_size,
                         assign_ctrl->file_id);

    bak_assign_stream_backup_task(session, proc->ctrl.type, proc->ctrl.name, assign_ctrl->file_id, file_size, 0);
    if (bak_send_stream_data(session, bak, assign_ctrl) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bak_wait_paral_proc(session);
    if (bak_stream_send_end(bak, stream) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t bak_get_logfiles_used_size(knl_session_t *session, uint32 curr_asn, uint32 last_asn, uint64 *data_size)
{
    database_t *db = &session->kernel->db;
    reset_log_t rst_log = db->ctrl.core.resetlogs;

    for (; curr_asn <= last_asn; curr_asn++) {
        uint32 rst_id = (curr_asn <= rst_log.last_asn) ? (rst_log.rst_id - 1) : rst_log.rst_id;
        uint32 file_id = log_get_id_by_asn(session, rst_id, curr_asn, NULL);
        if (file_id == GS_INVALID_ID32) {
            arch_ctrl_t *arch_ctrl = arch_get_archived_log_info(session, rst_id, curr_asn, ARCH_DEFAULT_DEST);
            if (arch_ctrl == NULL) {
                GS_LOG_RUN_ERR("[BACKUP] failed to get archived log for [%u-%u]", rst_id, curr_asn);
                GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "archive log", "for backup");
                return GS_ERROR;
            }
            *data_size += (uint64)arch_ctrl->blocks * arch_ctrl->block_size;
        } else {
            log_file_t *file = &db->logfiles.items[file_id];
            *data_size += file->head.write_pos;
            log_unlatch_file(session, file_id);
        }
    }
    return GS_SUCCESS;
}

static status_t bak_read_logfiles(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    bak_context_t *ctx = &kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    uint32 curr_asn = (uint32)ctrlinfo->rcy_point.asn;
    bak_process_t *proc = &ctx->process[BAK_COMMON_PROC];
    bak_stage_t *stage = &bak->progress.build_progress.stage;
    status_t status = GS_SUCCESS;
    uint32 last_asn;
    uint64 data_size = 0;
    uint32 block_size;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_LOG_STAGE) {
        GS_LOG_RUN_INF("[BUILD] ignore read logfiles for break-point building");
        return GS_SUCCESS;
    }

    if (bak_fetch_last_log(session, bak, &last_asn) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[BACKUP] fetch last log failed");
        return GS_ERROR;
    }

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) == BUILD_LOG_STAGE) {
        GS_LOG_RUN_INF("[BUILD] break-point condition, curr asn : %u", bak->progress.build_progress.asn);
        curr_asn = (uint32)bak->progress.build_progress.asn;
    }

    if (bak->target_info.target == TARGET_ARCHIVE) {
        if (bak_get_start_asn(session, &curr_asn, last_asn) != GS_SUCCESS) {
            return GS_ERROR;
        }

        ctrlinfo->rcy_point.asn = curr_asn;
        ctrlinfo->lrp_point.asn = last_asn;

        bak->send_buf.buf_size = GS_INVALID_ID32;
        bak->send_buf.offset = GS_INVALID_ID32;
    }
    knl_panic(last_asn >= curr_asn);

    if (bak_get_logfiles_used_size(session, curr_asn, last_asn, &data_size) != GS_SUCCESS) {
        return GS_ERROR;
    }
    bak_set_progress(session, BACKUP_LOG_STAGE, data_size);

    for (; curr_asn <= last_asn; curr_asn++) {
        if (curr_asn == last_asn) {
            if (bak_switch_logfile(session, last_asn, GS_TRUE) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (bak_paral_task_enable(session) && !BAK_IS_UDS_DEVICE(bak)) {
            if (bak_get_free_proc(session, &proc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (bak_set_log_ctrl(session, proc, curr_asn, &block_size) != GS_SUCCESS) {
            bak_unlatch_logfile(session, proc);
            return GS_ERROR;
        }

        proc->assign_ctrl.log_block_size = block_size;
        if (bak_paral_task_enable(session)) {
            if (BAK_IS_UDS_DEVICE(bak)) {
                status = bak_stream_read_logfile(session, proc, block_size);
                bak_unlatch_logfile(session, proc);
                cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
                if (status != GS_SUCCESS) {
                    return GS_ERROR;
                }
            } else {
                if (bak_assign_backup_task(session, proc, 0) != GS_SUCCESS) {
                    bak_unlatch_logfile(session, proc);
                    cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
                    return GS_ERROR;
                }
            }
        } else {
            status = bak_read_logfile(session, ctx, proc, block_size, GS_FALSE);
            bak_unlatch_logfile(session, proc);
            cm_close_device(proc->ctrl.type, &proc->ctrl.handle);
            if (status != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (bak_wait_write(bak) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    bak_wait_paral_proc(session);
    if (bak_paral_task_enable(session)) {
        /* parallel backup dose not enter bak_write_end, need update curr_file_index here */
        bak->curr_file_index = bak->file_count;
    }
    return GS_SUCCESS;
}

static void bak_set_config_param(knl_session_t *session, char *buf)
{
    errno_t ret = memset_sp(buf, GS_MAX_CONFIG_LINE_SIZE, 0, GS_MAX_CONFIG_LINE_SIZE);
    knl_securec_check(ret);
    char *param = cm_get_config_value(session->kernel->attr.config, "CONTROL_FILES");
    knl_panic(param != NULL);
    size_t param_len = strlen(param) + 1;
    ret = memcpy_sp(buf, GS_MAX_CONFIG_LINE_SIZE, param, param_len);
    knl_securec_check(ret);
}

status_t bak_read_param(knl_session_t *session)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;
    bak_t *bak = &backup_ctx->bak;
    bak_process_t *process = &backup_ctx->process[BAK_COMMON_PROC];
    bak_buf_t *send_buf = &bak->send_buf;

    GS_LOG_RUN_INF("[BUILD] read param for building of first link");

    bak_set_progress(session, BACKUP_PARAM_STAGE, GS_MAX_CONFIG_LINE_SIZE);
    bak_set_config_param(session, process->backup_buf.aligned_buf);

    send_buf->buf = process->backup_buf.aligned_buf;
    send_buf->buf_size = GS_MAX_CONFIG_LINE_SIZE;
    send_buf->offset = 0;

    if (bak_wait_write(bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void bak_build_head(knl_session_t *session, bak_head_t *head)
{
    bak_t *bak = &session->kernel->backup_ctx.bak;
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    bak_attr_t *attr = &bak->record.attr;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;

    head->version.major_ver = BAK_VERSION_MAJOR;
    head->version.min_ver = BAK_VERSION_MIN;
    head->version.magic = BAK_VERSION_MAGIC;

    head->attr.backup_type = attr->backup_type;
    errno_t ret = strcpy_sp(head->attr.tag, GS_NAME_BUFFER_SIZE, attr->tag);
    knl_securec_check(ret);

    head->attr.base_lsn = attr->base_lsn;
    ret = strcpy_sp(head->attr.base_tag, GS_NAME_BUFFER_SIZE, attr->base_tag);
    knl_securec_check(ret);

    head->attr.level = attr->level;
    head->attr.compress = attr->compress;
    head->file_count = bak->is_building ? 0 : bak->file_count - 1;

    head->ctrlinfo.rcy_point = ctrlinfo->rcy_point;
    head->ctrlinfo.lrp_point = ctrlinfo->lrp_point;
    head->ctrlinfo.scn = ctrlinfo->scn;
    head->ctrlinfo.lsn = ctrlinfo->lsn;

    head->depend_num = bak->depend_num;
    head->start_time = bak->record.start_time;
    head->completion_time = bak->record.completion_time;
    head->encrypt_info.encrypt_alg = bak->encrypt_info.encrypt_alg;
    head->log_fisrt_slot = bak->log_first_slot;

    if (head->encrypt_info.encrypt_alg != ENCRYPT_NONE) {
        ret = memcpy_sp(head->encrypt_info.salt, GS_KDF2SALTSIZE, bak->encrypt_info.salt, GS_KDF2SALTSIZE);
        knl_securec_check(ret);

        ret = strncpy_sp(head->sys_pwd, GS_PASSWORD_BUFFER_SIZE, bak->sys_pwd, strlen(bak->sys_pwd));
        knl_securec_check(ret);
    }

    head->db_id = core->dbid;
    head->db_role = core->db_role;
    head->db_init_time = core->init_time;
    ret = strcpy_s(head->db_name, GS_DB_NAME_LEN, core->name);
    knl_securec_check(ret);
    ret = strcpy_s(head->db_version, GS_DB_NAME_LEN, session->kernel->attr.db_version);
    knl_securec_check(ret);

    ret = memset_s(head->unused, BAK_HEAD_UNUSED_SIZE, 0, BAK_HEAD_UNUSED_SIZE);
    knl_securec_check(ret);
    head->df_struc_version = (uint32)BAK_DATAFILE_VERSION;
    bak_set_config_param(session, head->control_files);
}

static status_t bak_wait_write_finished(bak_t *bak)
{
    if (bak->is_building) {
        return GS_SUCCESS;
    }

    while (!bak->failed && bak->file_count != (bak->curr_file_index + 1)) {
        cm_sleep(1);
    }

    return bak->failed ? GS_ERROR : GS_SUCCESS;
}

static status_t bak_generate_backupset_head(knl_session_t *session, bak_context_t *ctx)
{
    bak_t *bak = &ctx->bak;
    bak_buf_t *send_buf = &bak->send_buf;
    bak_head_t *head = (bak_head_t *)ctx->process[BAK_COMMON_PROC].backup_buf.aligned_buf;
    uint64 data_size;
    bak_stage_t *stage = &bak->progress.build_progress.stage;
    uint32 buf_size = GS_BACKUP_BUFFER_SIZE;

    if (BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_HEAD_STAGE) {
        GS_LOG_RUN_INF("[BUILD] ignore gneerate backupset for break-point building");
        return GS_SUCCESS;
    }

    /* store keyfile befor bak_head */
    if (bak->is_building) {
        if (bak_read_keyfile(session, (char *)head, buf_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
        data_size = (uint64)sizeof(bak_head_t) + GS_KMC_MAX_KEY_SIZE;
        if (data_size > GS_BACKUP_BUFFER_SIZE) {
            GS_LOG_RUN_ERR("[BACKUP ERROR]store keyfile befor bak_head failed.");
            return GS_ERROR;
        }
        head = (bak_head_t *)((char *)head + GS_KMC_MAX_KEY_SIZE);
    } else {
        data_size = (uint64)sizeof(bak_head_t) + (uint64)bak->file_count * sizeof(bak_file_t) +
            (uint64)bak->depend_num * sizeof(bak_dependence_t);
    }

    bak_set_progress(session, BACKUP_HEAD_STAGE, data_size);
    bak_record_new_file(bak, BACKUP_HEAD_FILE, 0, 0); // will not save in backupset file

    if (bak_wait_write_finished(bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bak->record.completion_time = (uint64)cm_now();
    bak_build_head(session, head);
    GS_LOG_DEBUG_INF("[BACKUP] prepare head, size %u", (uint32)sizeof(bak_head_t));
    if (bak->is_building) {
        bak_calc_head_checksum(head, sizeof(bak_head_t));
        send_buf->buf = ctx->process[BAK_COMMON_PROC].backup_buf.aligned_buf;
        send_buf->buf_size = (uint32)(GS_KMC_MAX_KEY_SIZE + sizeof(bak_head_t));
        send_buf->offset = 0;

        GS_LOG_DEBUG_INF("[BACKUP] build is running, only send backup head, size %u",
            (uint32)(GS_KMC_MAX_KEY_SIZE + sizeof(bak_head_t)));
        if (bak_wait_write(bak) != GS_SUCCESS) {
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }

    uint32 offset = sizeof(bak_head_t);
    uint32 send_size = (bak->file_count - 1) * sizeof(bak_file_t); /* max bak->file_count is 2048, cannot overflow */
    errno_t ret = memcpy_sp((char *)head + offset, buf_size - offset, (char *)bak->files, send_size);
    knl_securec_check(ret);
    offset += send_size;
    GS_LOG_DEBUG_INF("[BACKUP] prepare file_info, size %u", send_size);

    if (bak->depend_num > 0) {
        if (bak->depend_num > BAK_MAX_DEPEND_NUM) {
            GS_LOG_RUN_ERR("[BACKUP] depend incremental backup number too large, size %u", bak->depend_num);
            return GS_ERROR;
        }

        send_size = bak->depend_num * sizeof(bak_dependence_t);
        ret = memcpy_sp((char *)head + offset, buf_size - offset, (char *)bak->depends, send_size);
        knl_securec_check(ret);
        offset += send_size;
        GS_LOG_DEBUG_INF("[BACKUP] prepare depend, size %u", send_size);
    }

    bak_calc_head_checksum(head, offset);
    send_buf->buf = (char *)head;
    send_buf->buf_size = offset;
    send_buf->offset = 0;

    if (bak_wait_write(bak) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void bak_read_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_t *bak = &ctx->bak;
    bak_ctrlinfo_t *ctrlinfo = &bak->record.ctrlinfo;
    bak_process_t *process = &ctx->process[BAK_COMMON_PROC];
    bak_stage_t *stage = &bak->progress.build_progress.stage;

    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed && !bak->failed) {
        if (bak->is_building && bak->is_first_link && !bak->record.is_repair) {
            if (bak_read_param(session) != GS_SUCCESS) {
                bak->failed = GS_TRUE;
                break;
            }
        }

        if (!bak->record.log_only) {
            if (bak_read_ctrlfile(session) != GS_SUCCESS) {
                bak->failed = GS_TRUE;
                break;
            }

            if (bak_read_datafiles(session, process) != GS_SUCCESS) {
                bak->failed = GS_TRUE;
                break;
            }

            if ((BAK_IS_FULL_BUILDING(bak) && bak_get_build_stage(stage) > BUILD_DATA_STAGE)) {
                GS_LOG_RUN_INF("[BACKUP] ignore set log point for break-porint building");
            } else {
                GS_LOG_RUN_INF("[BACKUP] set log point");
                bak_set_log_point(session, ctrlinfo, GS_TRUE);
            }
        }

        if (bak->record.data_only) {
            break;
        }

        if (bak_read_logfiles(session) != GS_SUCCESS) {
            bak->failed = GS_TRUE;
            break;
        }

        if (bak_generate_backupset_head(session, ctx) != GS_SUCCESS) {
            bak->failed = GS_TRUE;
            break;
        }
        break;
    }

    if (bak->failed) {
        bak_set_error(&bak->error_info);
    }

    bak_reset_fileinfo(&process->assign_ctrl);
    GS_LOG_RUN_INF("[BACKUP] backup to remote, read proc finished and exit");
    KNL_SESSION_CLEAR_THREADID(session);
    bak->progress.stage = BACKUP_READ_FINISHED;
}

#ifdef __cplusplus
}
#endif
