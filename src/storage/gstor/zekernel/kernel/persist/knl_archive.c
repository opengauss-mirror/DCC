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
 * knl_archive.c
 *    implement of archive 
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/persist/knl_archive.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_archive.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctrl_restore.h"

#define GS_MIN_FREE_LOGS 2
#define GS_HWM_ARCHIVE_FILES_SIZE(max_arch_size) ((uint64)((max_arch_size) * 0.85))
#define GS_OPT_ARCHIVE_FILES_SIZE(max_arch_size) ((uint64)((max_arch_size) * 0.15))

// LOG_ARCHIVE_FORMAT contains %s %r %t, need to reserve enough space for the integers
#define GS_ARCH_RESERVED_FORMAT_LEN (uint32)(GS_MAX_UINT32_PREC * 2 + GS_MAX_UINT64_PREC - 6)

typedef struct st_arch_file_attr {
    const char *src_name;
    const char *arch_file_name;
    int32 src_file;
    int32 dst_file;
} arch_file_attr_t;

void arch_reset_file_id(knl_session_t *session, uint32 dest_pos)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];

    proc_ctx->last_file_id = GS_INVALID_ID32;
    proc_ctx->next_file_id = GS_INVALID_ID32;
}

bool32 arch_need_archive(arch_proc_context_t *proc_ctx, log_context_t *redo_ctx)
{
    log_file_t *file = NULL;
    uint32 file_id = proc_ctx->last_file_id;
    uint32 ori_file_id = proc_ctx->last_file_id;

    proc_ctx->next_file_id = GS_INVALID_ID32;

    log_lock_logfile(proc_ctx->session);

    if (file_id == GS_INVALID_ID32) {
        file_id = redo_ctx->active_file;
    } else {
        log_get_next_file(proc_ctx->session, &file_id, GS_FALSE);
    }

    file = redo_ctx->files + file_id;

    /*
     * log file is current log file, no need to archive, and last_file_id = GS_INVALID_ID32 is needed.
     * Consider the scenario as follows: standby logfile is skipped and proc_ctx->last_file_id's next
     * is current file, will lead to active file can not be archived.
     *
     * 3 logfile, asn 7(file 0) is archived, asn 8~24 is skipped, asn 26(file 1) has been archived,
     * asn 27(file 2) is current file, asd asn 25(file 0) can not be archive, last_file_id is 1.
     */
    if (file_id == redo_ctx->curr_file) {
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = DB_IS_PRIMARY(&proc_ctx->session->kernel->db) ? ori_file_id : GS_INVALID_ID32;
        return GS_FALSE;
    }

    /*
     * log file is invalid, need to check the next one.
     * On standby or cascade standby, log switch skip and this routine could run concurrently. Skipped
     * file will set GS_INVALID_ASN, and last_file_id will be push backwards slowly. This will lead to
     * some active file can not be archived immediately.
     */
    if (file->head.asn == GS_INVALID_ASN) {
        // Just skip this log file
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = DB_IS_PRIMARY(&proc_ctx->session->kernel->db) ? file_id : GS_INVALID_ID32;
        return GS_FALSE;
    }

    // log file is valid, need to check whether it is archived
    if (((proc_ctx->last_archived_log.rst_id > file->head.rst_id ||
        (proc_ctx->last_archived_log.rst_id == file->head.rst_id && 
        proc_ctx->last_archived_log.asn >= file->head.asn)) &&
        DB_IS_PRIMARY(&proc_ctx->session->kernel->db)) || file->ctrl->archived) {
        // already archived, skip it
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->last_file_id = file_id;
        return GS_FALSE;
    } else {
        // need to archive this log file
        log_unlock_logfile(proc_ctx->session);
        proc_ctx->next_file_id = file_id;
        return GS_TRUE;
    }
}

void arch_set_archive_log_name(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos, char *buf,
                               uint32 buf_size)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];
    char *cur_pos = arch_ctx->arch_format;
    char *last_pos = cur_pos;
    size_t dest_len;
    size_t remain_buf_size = buf_size;
    size_t offset = 0;
    errno_t ret;

    dest_len = strlen(proc_ctx->arch_dest);
    ret = strncpy_s(buf, remain_buf_size, proc_ctx->arch_dest, dest_len);
    knl_securec_check(ret);
    offset += strlen(proc_ctx->arch_dest);
    buf[offset] = '/';
    offset++;

    while (*cur_pos != '\0') {
        int32 print_num = 0;
        while (*cur_pos != '%' && *cur_pos != '\0') {
            // literal char, just move to next char
            cur_pos++;
        }

        if (*cur_pos == '\0' && cur_pos == last_pos) {
            break;
        }

        remain_buf_size = buf_size - offset;
        dest_len = cur_pos - last_pos;
        ret = strncpy_s(buf + offset, remain_buf_size, last_pos, dest_len);
        knl_securec_check(ret);
        offset += (cur_pos - last_pos);
        last_pos = cur_pos;

        if (*cur_pos == '\0') {
            break;
        }
        cur_pos++;

        // here we got a valid option, process it
        switch (*cur_pos) {
            case 's':
            case 'S': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT32_PREC, "%u", asn);
                knl_securec_check_ss(print_num);
                break;
            }
            case 't':
            case 'T': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT64_PREC, "%lu", proc_ctx->thread.id);
                knl_securec_check_ss(print_num);
                break;
            }
            case 'r':
            case 'R': {
                print_num = snprintf_s(buf + offset, buf_size - offset, GS_MAX_UINT32_PREC, "%u", rst_id);
                knl_securec_check_ss(print_num);
                break;
            }
            default:
            {
                // Invalid format, just ignore.
                CM_ABORT(0, "[ARCH] ABORT INFO: ARCHIVE_FORMAT '%s' has wrong format '%c' for ARCHIVE_FORMAT",
                         arch_ctx->arch_format, *cur_pos);
                return;
            }
        }

        offset += print_num;
        cur_pos++;
        last_pos = cur_pos;
    }
}

static void arch_archive_delay(knl_session_t *session)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 log_generated = ctx->stat.flush_bytes - arch_ctx->begin_redo_bytes;

    if (arch_ctx->prev_redo_bytes == ctx->stat.flush_bytes) {
        /* no log generate during this archive copy, max speed */
        return;
    }

    arch_ctx->prev_redo_bytes = ctx->stat.flush_bytes;

    if (log_generated > arch_ctx->total_bytes) {
        /* log generate is fast than arch, max speed */
        return;
    }

    if (log_get_free_count(session) <= GS_MIN_FREE_LOGS) {
        /* when arch proc is bottleneck, we do not delay arch proc */
        return;
    }
    GS_LOG_DEBUG_INF("[ARCH] arch_delay log_generated:%llu log_archived:%llu", log_generated, arch_ctx->total_bytes);
    cm_sleep(100); /* 100ms */
}

status_t arch_flush_file(knl_session_t *session, char *buf, log_file_t *logfile, arch_file_attr_t *arch_files)
{
    log_context_t *ctx = &session->kernel->redo_ctx;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint64 left_size = logfile->head.write_pos;
    int32 read_size, data_size;
    logfile->arch_pos = 0;

    arch_ctx->begin_redo_bytes = ctx->stat.flush_bytes;
    arch_ctx->prev_redo_bytes = ctx->stat.flush_bytes;
    arch_ctx->total_bytes = 0;

    while (left_size > 0) {
        read_size = (int32)((left_size > GS_ARCHIVE_BUFFER_SIZE) ? GS_ARCHIVE_BUFFER_SIZE : left_size);
        if (cm_read_file(arch_files->src_file, buf, read_size, &data_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cm_write_file(arch_files->dst_file, buf, data_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        left_size -= (uint64)data_size;
        arch_ctx->total_bytes += data_size;
        logfile->arch_pos += data_size;

        if (DB_TO_RECOVERY(session)) {
            arch_archive_delay(session);
        }
    }
    return GS_SUCCESS;
}

status_t arch_archive_tmp_file(knl_session_t *session, char *buf, char *tmp_arch_file_name, log_file_t *logfile,
    const char *src_name, const char *arch_file_name)
{
    arch_file_attr_t arch_files;
    arch_files.arch_file_name = arch_file_name;
    arch_files.src_name = src_name;

    if (cm_file_exist(tmp_arch_file_name) && cm_remove_file(tmp_arch_file_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to remove remained temp archived log file %s", tmp_arch_file_name);
        return GS_ERROR;
    }

    arch_files.src_file = -1;
    if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, O_DSYNC, &arch_files.src_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to open archive log file %s", logfile->ctrl->name);
        return GS_ERROR;
    }

    arch_files.dst_file = -1;
    if (cm_build_device(tmp_arch_file_name, logfile->ctrl->type, session->kernel->attr.xpurpose_buf,
        GS_XPURPOSE_BUFFER_SIZE, CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size), O_DSYNC,
        GS_FALSE, &arch_files.dst_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to build %s ", logfile->ctrl->name);
        cm_close_device(logfile->ctrl->type, &arch_files.src_file);
        return GS_ERROR;
    }

    if (cm_open_device(tmp_arch_file_name, logfile->ctrl->type, O_DSYNC, &arch_files.dst_file) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to create temp archive log file %s", tmp_arch_file_name);
        cm_close_device(logfile->ctrl->type, &arch_files.src_file);
        return GS_ERROR;
    }

    status_t status = arch_flush_file(session, buf, logfile, &arch_files);

    cm_close_device(logfile->ctrl->type, &arch_files.src_file);
    cm_close_device(logfile->ctrl->type, &arch_files.dst_file);
    return status;
}

status_t arch_archive_file(knl_session_t *session, char *buf, const char *src_name, const char *arch_file_name,
    log_file_t *logfile)
{
    char tmp_arch_file_name[GS_FILE_NAME_BUFFER_SIZE + 4] = {0}; /* 4 bytes for ".tmp" */
    uint64 left_size = logfile->head.write_pos;    
    int32 ret;

    if (cm_file_exist(arch_file_name)) {
        GS_LOG_RUN_INF("[ARCH] Archived log file %s already exits", arch_file_name);
        return GS_SUCCESS;
    } else {
        knl_panic(left_size > CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size));
    }

    ret = sprintf_s(tmp_arch_file_name, GS_FILE_NAME_BUFFER_SIZE + 4, "%s.tmp", arch_file_name);
    knl_securec_check_ss(ret);
    if (arch_archive_tmp_file(session, buf, tmp_arch_file_name, logfile, src_name, arch_file_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_rename_file_durably(tmp_arch_file_name, arch_file_name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to rename temp archive log file %s to %s", tmp_arch_file_name, arch_file_name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void arch_record_arch_ctrl(arch_ctrl_t *arch_ctrl, knl_session_t *session, uint32 dest_id,
    const char *file_name, log_file_head_t *log_head)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_ctrl->recid = arch_ctx->archived_recid;
    arch_ctrl->dest_id = dest_id;
    arch_ctrl->stamp = session->kernel->attr.timer->now;
    size_t file_name_size = strlen(file_name) + 1;
    errno_t ret = memcpy_sp(arch_ctrl->name, GS_FILE_NAME_BUFFER_SIZE, file_name, file_name_size);
    knl_securec_check(ret);
    arch_ctrl->block_size = log_head->block_size;
    /* log_head->write_pos / log_head->block_size < max int32, cannont overflow */
    arch_ctrl->blocks = (int32)(log_head->write_pos / (uint32)log_head->block_size);
    arch_ctrl->first = log_head->first;
    arch_ctrl->last = log_head->last;
    arch_ctrl->rst_id = log_head->rst_id;
    arch_ctrl->asn = log_head->asn;
}

status_t arch_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name,
    log_file_head_t *log_head)
{
    arch_ctrl_t *arch_ctrl = NULL;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    uint32 dest_id = dest_pos - 1;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_id];
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 end_pos = (ctrl->core.archived_end + 1) % GS_MAX_ARCH_NUM;

    cm_spin_lock(&arch_ctx->record_lock, NULL);
    arch_ctx->archived_recid++;
    cm_spin_unlock(&arch_ctx->record_lock);

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    if (end_pos == ctrl->core.archived_start) {
        arch_ctrl = db_get_arch_ctrl(session, end_pos);
        arch_ctrl->recid = 0;
        ctrl->core.archived_start = (ctrl->core.archived_start + 1) % GS_MAX_ARCH_NUM;
        if (db_save_core_ctrl(session) != GS_SUCCESS) {
            cm_spin_unlock(&proc_ctx->record_lock);
            CM_ABORT(0, "[ARCH] ABORT INFO: save core control file failed when record archive info");
        }
    }

    uint32 id = ctrl->core.archived_end;
    arch_ctrl = db_get_arch_ctrl(session, id);
    arch_record_arch_ctrl(arch_ctrl, session, dest_id, file_name, log_head);

    proc_ctx->curr_arch_size += (int64)log_head->write_pos;
    ctrl->core.archived_end = end_pos;

    if (proc_ctx->last_archived_log.rst_id < log_head->rst_id ||
        (proc_ctx->last_archived_log.rst_id == log_head->rst_id && proc_ctx->last_archived_log.asn < log_head->asn)) {
        proc_ctx->last_archived_log.rst_id = log_head->rst_id;
        proc_ctx->last_archived_log.asn = log_head->asn;
        GS_LOG_DEBUG_INF("[ARCH] Set last_arch_log [%u-%u]",
                         proc_ctx->last_archived_log.rst_id, proc_ctx->last_archived_log.asn);
    }

    if (db_save_arch_ctrl(session, id) != GS_SUCCESS) {
        cm_spin_unlock(&proc_ctx->record_lock);
        CM_ABORT(0, "[ARCH] ABORT INFO: save control file failed when record archive info");
    }

    GS_LOG_RUN_INF("[ARCH] Record archive log file %s for log [%u-%u] start %u end %u",
                   arch_ctrl->name, log_head->rst_id, log_head->asn, 
                   ctrl->core.archived_start, ctrl->core.archived_end);
    cm_spin_unlock(&proc_ctx->record_lock);
    return GS_SUCCESS;
}

void arch_get_files_num(knl_session_t *session, uint32 dest_id, uint32 *arch_num)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;

    if (ctrl->core.archived_end >= ctrl->core.archived_start) {
        *arch_num = ctrl->core.archived_end - ctrl->core.archived_start;
    } else {
        *arch_num = GS_MAX_ARCH_NUM - (ctrl->core.archived_start - ctrl->core.archived_end);
    }
}

arch_ctrl_t *arch_get_archived_log_info(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 arch_num = 0;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 arch_locator = 0;

    arch_get_files_num(session, dest_pos - 1, &arch_num);
    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (ctrl->core.archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator);
        if (arch_ctrl->recid == 0) {
            continue;
        }

        if (arch_ctrl->asn == asn) {
            if (arch_ctrl->rst_id != rst_id) {
                GS_LOG_RUN_WAR("[ARCH] Archived log[%u-%u] found, but restlog id not equal, %u found but %u required",
                               arch_ctrl->rst_id, arch_ctrl->asn, arch_ctrl->rst_id, rst_id);
            }
            return arch_ctrl;
        }
    }

    return NULL;
}

arch_ctrl_t *arch_get_last_log(knl_session_t *session)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 arch_locator = 0;

    if (ctrl->core.archived_end == 0) {
        arch_locator = GS_MAX_ARCH_NUM - 1;
    } else {
        arch_locator = (ctrl->core.archived_end - 1) % GS_MAX_ARCH_NUM;
    }

    return db_get_arch_ctrl(session, arch_locator);
}

bool32 arch_archive_log_recorded(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos)
{
    arch_ctrl_t *arch_ctrl = arch_get_archived_log_info(session, rst_id, asn, dest_pos);
    if (arch_ctrl != NULL) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

static bool32 arch_need_print_error(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    if (proc_ctx->fail_time == 0) {
        proc_ctx->fail_time = KNL_NOW(session);
        return GS_TRUE;
    }

    if (KNL_NOW(session) - proc_ctx->fail_time >= ARCH_FAIL_PRINT_THRESHOLD) {
        proc_ctx->fail_time = KNL_NOW(session);
        return GS_TRUE;
    }

    return GS_FALSE;
}

void arch_do_archive(knl_session_t *session, arch_proc_context_t *proc_ctx)
{
    log_file_t *logfile = session->kernel->redo_ctx.files + proc_ctx->next_file_id;
    char arch_file_name[GS_FILE_NAME_BUFFER_SIZE] = {0};

    knl_panic_log(proc_ctx->next_file_id != GS_INVALID_ID32, "next_file_id is invalid.");

    if (logfile->head.asn == GS_INVALID_ASN) {
        GS_LOG_RUN_INF("[ARCH] Empty log file[%u], no need to archive. Skip to process next.", proc_ctx->next_file_id);

        // Try to recycle logfile
        log_recycle_file(session, &session->kernel->db.ctrl.core.rcy_point);

        // Update last archived log file id
        proc_ctx->last_file_id = proc_ctx->next_file_id;

        return;
    }

    arch_set_archive_log_name(session, logfile->head.rst_id, logfile->head.asn, proc_ctx->arch_id, arch_file_name,
                              GS_FILE_NAME_BUFFER_SIZE);

    if (arch_archive_file(session, proc_ctx->arch_buf, logfile->ctrl->name, arch_file_name, logfile) == GS_SUCCESS) {
        // Update last archived log file id
        proc_ctx->last_file_id = proc_ctx->next_file_id;
        GS_LOG_RUN_INF("[ARCH] Archive log file[%u], restlog id is %u, asn is %u to %s",
            proc_ctx->next_file_id, logfile->head.rst_id, logfile->head.asn, arch_file_name);

        if (!arch_archive_log_recorded(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST)) {
            // Update control file archive information
            if (arch_record_archinfo(session, proc_ctx->arch_id, arch_file_name, &logfile->head) != GS_SUCCESS) {
                return;
            }
        } else {
            if (proc_ctx->last_archived_log.rst_id < logfile->head.rst_id ||
                (proc_ctx->last_archived_log.rst_id == logfile->head.rst_id &&
                 proc_ctx->last_archived_log.asn < logfile->head.asn)) {
                arch_log_id_t id;
                id.rst_id = logfile->head.rst_id;
                id.asn = logfile->head.asn;
                proc_ctx->last_archived_log = id;
                GS_LOG_DEBUG_INF("[ARCH] Already archived %s, set last_arch_log [%u-%u]",
                    arch_file_name, proc_ctx->last_archived_log.rst_id, proc_ctx->last_archived_log.asn);
            }
        }
        logfile->ctrl->archived = GS_TRUE;
        if (db_save_log_ctrl(session, proc_ctx->next_file_id) != GS_SUCCESS) {
            CM_ABORT(0, "[ARCH] ABORT INFO: save control redo file failed when archive file");
        }

        // Try to recycle logfile
        log_recycle_file(session, &session->kernel->db.ctrl.core.rcy_point);
        if (proc_ctx->alarmed) {
            GS_LOG_ALARM_RECOVER(WARN_ARCHIVE, "'file-name':'%s'}", arch_file_name);
        }
        proc_ctx->alarmed = GS_FALSE;
        proc_ctx->fail_time = 0;
    } else {
        if (arch_need_print_error(session, proc_ctx)) {
            GS_LOG_RUN_ERR("[ARCH] Failed to archive log file[%u], restlog id is %u, asn is %u to %s",
                proc_ctx->next_file_id, logfile->head.rst_id, logfile->head.asn, arch_file_name);
        }
        cm_reset_error();
        if (!proc_ctx->alarmed) {
            GS_LOG_ALARM(WARN_ARCHIVE, "'file-name':'%s'}", arch_file_name);
            proc_ctx->alarmed = GS_TRUE;
        }
    }
}

bool32 arch_get_archived_log_name(knl_session_t *session, uint32 rst_id, uint32 asn, 
                                  uint32 dest_pos, char *buf, uint32 buf_size)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 arch_num = 0;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 arch_locator = 0;
    errno_t ret;

    arch_get_files_num(session, dest_pos - 1, &arch_num);
    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (ctrl->core.archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator);
        if (arch_ctrl->recid == 0) {
            continue;
        }

        if (arch_ctrl->asn == asn) {
            size_t dest_len;
            dest_len = strlen(arch_ctrl->name);
            ret = strncpy_s(buf, buf_size, arch_ctrl->name, dest_len);
            knl_securec_check(ret);
            if (arch_ctrl->rst_id != rst_id) {
                GS_LOG_RUN_WAR("[ARCH] Archived log[%u-%u] found, but restlog id not equal, %u found but %u required",
                               arch_ctrl->rst_id, arch_ctrl->asn, arch_ctrl->rst_id, rst_id);
            }
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static bool32 arch_can_be_cleaned(arch_ctrl_t *arch_ctrl, log_point_t *rcy_point, log_point_t *backup_rcy,
    knl_alterdb_archivelog_t *def)
{
    log_point_t curr_rcy_point;
    curr_rcy_point.asn = arch_ctrl->asn;
    curr_rcy_point.rst_id = arch_ctrl->rst_id;

    if (!def->all_delete) {
        if (arch_ctrl->stamp > def->until_time) {
            return GS_FALSE;
        }
    }

    if (!LOG_POINT_FILE_LT(curr_rcy_point, *rcy_point)) {
        return GS_FALSE;
    }

    if (!def->force_delete) {
        if (!LOG_POINT_FILE_LT(curr_rcy_point, *backup_rcy)) {
            return GS_FALSE;
        }
    }
    return GS_TRUE;
}

static bool32 arch_needed_by_backup(knl_session_t *session, uint32 asn)
{
    bak_context_t *backup_ctx = &session->kernel->backup_ctx;

    if (!BAK_NOT_WORK(backup_ctx) || BAK_IS_BUILDING(backup_ctx)) {
        return bak_logfile_not_backed(session, asn);
    }

    // in two stage backup, after backup datafiles(stage one), we need save archive log for stage two
    if (backup_ctx->bak.record.data_only) {
        return (asn >= backup_ctx->bak.arch_stat.start_asn);
    }
    return GS_FALSE;
}

static status_t arch_do_real_clean(knl_session_t *session, arch_proc_context_t *proc_ctx, log_point_t *rcy_point,
    log_point_t *backup_rcy, uint64 target_size, knl_alterdb_archivelog_t *def)
{
    status_t status = GS_SUCCESS;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 arch_num = 0;
    uint32 clean_num = 0;
    uint32 clean_locator = 0;
    bool32 clean_skip = GS_FALSE;
    arch_ctrl_t *arch_ctrl = NULL;

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    arch_get_files_num(session, proc_ctx->arch_id - 1, &arch_num);

    for (uint32 i = 0; i < arch_num; i++) {
        clean_locator = (ctrl->core.archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, clean_locator);
        if (arch_needed_by_backup(session, arch_ctrl->asn)) {
            break;
        }

        if (arch_ctrl->recid == 0) {
            if (!clean_skip) {
                clean_num++;
            }
            continue;
        }

        if (!arch_can_be_cleaned(arch_ctrl, rcy_point, backup_rcy, def)) {
            clean_skip = GS_TRUE;
            continue;
        }

        if (!cm_file_exist(arch_ctrl->name)) {
            GS_LOG_RUN_INF("archive file %s is not exist", arch_ctrl->name);
        } else {
            if (cm_remove_file(arch_ctrl->name) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("Failed to remove archive file %s", arch_ctrl->name);
                status = GS_ERROR;
                break;
            }
            GS_LOG_RUN_INF("archive file %s is cleaned, resetlog %u asn %u force %u start %u end %u",
                           arch_ctrl->name, arch_ctrl->rst_id, arch_ctrl->asn, def->force_delete, 
                           ctrl->core.archived_start, ctrl->core.archived_end);
        }

        arch_ctrl->recid = 0;
        if (!clean_skip) {
            clean_num++;
        }

        proc_ctx->curr_arch_size -= (int64)arch_ctrl->blocks * arch_ctrl->block_size;

        if (db_save_arch_ctrl(session, clean_locator) != GS_SUCCESS) {
            cm_spin_unlock(&proc_ctx->record_lock);
            return GS_ERROR;
        }

        if ((uint64)proc_ctx->curr_arch_size < target_size) {
            break;
        }
    }

    ctrl->core.archived_start = (ctrl->core.archived_start + clean_num) % GS_MAX_ARCH_NUM;
    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        status = GS_ERROR;
    }

    cm_spin_unlock(&proc_ctx->record_lock);
    return status;
}

static status_t arch_clean_arch_files(knl_session_t *session, arch_proc_context_t *proc_ctx,
    log_point_t *min_rcy_point, knl_alterdb_archivelog_t *def, uint64 max_arch_size)
{
    log_point_t local_rcy_point = session->kernel->db.ctrl.core.rcy_point;
    bool32 ignore_standby = session->kernel->attr.arch_ignore_standby;
    log_point_t backup_rcy_point;

    if (bak_get_last_rcy_point(session, &backup_rcy_point) != GS_SUCCESS) {
        return GS_SUCCESS;
    }

    if (arch_do_real_clean(session, proc_ctx, min_rcy_point, &backup_rcy_point,
        GS_OPT_ARCHIVE_FILES_SIZE(max_arch_size), def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (ignore_standby && !LOG_POINT_FILE_EQUAL(local_rcy_point, *min_rcy_point) &&
        (uint64)proc_ctx->curr_arch_size > GS_HWM_ARCHIVE_FILES_SIZE(max_arch_size)) {
        GS_LOG_DEBUG_INF("[ARCH] begin to clean archive logfile ignore standby");
        if (arch_do_real_clean(session, proc_ctx, &local_rcy_point, &backup_rcy_point,
            GS_HWM_ARCHIVE_FILES_SIZE(max_arch_size), def) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if ((uint64)proc_ctx->curr_arch_size > GS_HWM_ARCHIVE_FILES_SIZE(max_arch_size)) {
            GS_LOG_DEBUG_ERR("failed to clean archive logfile ignore standby, local rcy_point [%u-%u/%u/%llu], "
                             "total archive size %lld, archive hwm size %llu",
                             local_rcy_point.rst_id, local_rcy_point.asn, local_rcy_point.block_id, 
                             (uint64)local_rcy_point.lfn, proc_ctx->curr_arch_size, 
                             GS_HWM_ARCHIVE_FILES_SIZE(max_arch_size));
        }
    }

    return GS_SUCCESS;
}

void arch_auto_clean(arch_proc_context_t *proc_ctx)
{
    knl_session_t *session = proc_ctx->session;
    lsnd_context_t *lsnd_ctx = &session->kernel->lsnd_ctx;
    database_t *db = &session->kernel->db;
    log_point_t min_rcy_point = db->ctrl.core.rcy_point;
    uint64 max_arch_size = session->kernel->attr.max_arch_files_size;
    knl_alterdb_archivelog_t def;

    if (DB_STATUS(session) != DB_STATUS_OPEN ||
        session->kernel->attr.max_arch_files_size == 0 ||
        (uint64)proc_ctx->curr_arch_size < GS_HWM_ARCHIVE_FILES_SIZE(session->kernel->attr.max_arch_files_size)
        || DB_IS_MAINTENANCE(session)) {
        return;
    }

    bool32 exist_standby = (lsnd_ctx->standby_num != 0) && !DB_IS_RAFT_ENABLED(session->kernel);
    if (exist_standby && !DB_IS_CASCADED_PHYSICAL_STANDBY(db)) {
        lsnd_get_min_contflush_point(lsnd_ctx, &min_rcy_point);
    }

    def.all_delete = GS_FALSE;
    def.force_delete = session->kernel->attr.arch_ignore_backup;
    def.until_time = GS_INVALID_INT64;

    (void)arch_clean_arch_files(session, proc_ctx, &min_rcy_point, &def, max_arch_size);
}

status_t arch_force_clean(knl_session_t *session, knl_alterdb_archivelog_t *def)
{
    arch_context_t *ctx = &session->kernel->arch_ctx;
    lsnd_context_t *lsnd_ctx = &session->kernel->lsnd_ctx;
    database_t *db = &session->kernel->db;
    arch_proc_context_t *proc_ctx = NULL;
    bool32 exist_standby;
    log_point_t min_rcy_point = db->ctrl.core.rcy_point;
    uint32 i;

    exist_standby = (lsnd_ctx->standby_num != 0) && !DB_IS_RAFT_ENABLED(session->kernel);
    if (exist_standby && !DB_IS_CASCADED_PHYSICAL_STANDBY(db)) {
        lsnd_get_min_contflush_point(lsnd_ctx, &min_rcy_point);
    }

    for (i = 0; i < GS_MAX_ARCH_DEST; i++) {
        proc_ctx = &ctx->arch_proc[i];

        if (proc_ctx->arch_dest[0] == '\0') {
            continue;
        }

        if (arch_clean_arch_files(session, proc_ctx, &min_rcy_point, def, 0) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void arch_try_update_contflush_point(log_point_t *cont_point, uint32 rst_id, uint32 asn)
{
    if (cont_point->rst_id <= rst_id && cont_point->asn == (asn - 1)) {
        cont_point->rst_id = rst_id;
        cont_point->asn = asn;
    }
}

void arch_check_cont_archived_log(arch_proc_context_t *proc_ctx)
{
    knl_session_t *session = proc_ctx->session;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 arch_num = 0;
    arch_ctrl_t *arch_ctrl = NULL;
    uint32 arch_locator = 0;
    log_point_t rcy_point = session->kernel->db.ctrl.core.rcy_point;

    if (!DB_IS_OPEN(session) || DB_IS_PRIMARY(&session->kernel->db)) {
        return;
    }

    log_point_t *contflush_point = &session->kernel->lrcv_ctx.contflush_point;
    if (LOG_POINT_FILE_LT(*contflush_point, rcy_point)) {
        contflush_point->rst_id = rcy_point.rst_id;
        contflush_point->asn = rcy_point.asn;
    }

    if (!LOG_POINT_FILE_LT(*contflush_point, proc_ctx->last_archived_log)) {
        return;
    }

    arch_get_files_num(session, proc_ctx->arch_id - 1, &arch_num);
    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (ctrl->core.archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator);
        if (arch_ctrl->recid == 0) {
            continue;
        }
        arch_try_update_contflush_point(contflush_point, arch_ctrl->rst_id, arch_ctrl->asn);
    }
}

void arch_proc(thread_t *thread)
{
    arch_proc_context_t *proc_ctx = (arch_proc_context_t *)thread->argument;
    knl_session_t *session = proc_ctx->session;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;

    cm_set_thread_name("arch_proc");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    while (!thread->closed) {
        if (DB_NOT_READY(session) || !proc_ctx->enabled) {
            cm_sleep(200);
            continue;
        }

        if (arch_need_archive(proc_ctx, redo_ctx)) {
            // Try to archive log file
            arch_do_archive(session, proc_ctx);
        } else {
            // No work to do
            cm_sleep(1000);
        }

        // Try to record the max continuous received log in standby
        arch_check_cont_archived_log(proc_ctx);
        // Try to clean archived log file
        arch_auto_clean(proc_ctx);
    }

    GS_LOG_RUN_INF("[ARCH] Thread exit.");
    KNL_SESSION_CLEAR_THREADID(session);
}

status_t arch_check_dest(arch_context_t *arch_ctx, char *dest, uint32 cur_pos)
{
    arch_proc_context_t *proc_ctx = NULL;
    uint32 i;
    knl_attr_t *attr = &arch_ctx->arch_proc[0].session->kernel->attr;

    if (strlen(dest) == 0) {
        return GS_SUCCESS;
    }

    if (strlen(dest) >= GS_MAX_ARCH_NAME_LEN) {
        GS_THROW_ERROR(ERR_NAME_TOO_LONG, "arch dest path", strlen(dest), GS_MAX_ARCH_NAME_LEN);
        return GS_ERROR;
    }

    if (cm_check_exist_special_char(dest, (uint32)strlen(dest))) {
        GS_THROW_ERROR(ERR_INVALID_DIR, dest);
        return GS_ERROR;
    }

    if ((attr->arch_attr[cur_pos].dest_mode == LOG_ARCH_DEST_LOCATION) && !cm_dir_exist(dest)) {
        GS_THROW_ERROR(ERR_DIR_NOT_EXISTS, dest);
        return GS_ERROR;
    }

    for (i = 0; i < GS_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        if (i == cur_pos || strlen(proc_ctx->arch_dest) == 0) {
            continue;
        }

        if (strcmp(proc_ctx->arch_dest, dest) == 0) {
            GS_THROW_ERROR(ERR_DUPLICATE_LOG_ARCHIVE_DEST, cur_pos + 1, i + 1);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static void arch_init_arch_files_size(knl_session_t *session, uint32 dest_id)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 arch_num, arch_locator;
    arch_ctrl_t *arch_ctrl = NULL;
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_log_id_t *last_arch_log = NULL;

    arch_get_files_num(session, dest_id, &arch_num);

    for (uint32 i = 0; i < arch_num; i++) {
        arch_locator = (ctrl->core.archived_start + i) % GS_MAX_ARCH_NUM;
        arch_ctrl = db_get_arch_ctrl(session, arch_locator);
        if (arch_ctrl->recid == 0) {
            continue;
        }

        arch_ctx->arch_proc[dest_id].curr_arch_size += (int64)arch_ctrl->blocks * arch_ctrl->block_size;

        last_arch_log = &arch_ctx->arch_proc[dest_id].last_archived_log;
        if (arch_ctrl->rst_id > last_arch_log->rst_id ||
            (arch_ctrl->rst_id == last_arch_log->rst_id && arch_ctrl->asn > last_arch_log->asn)) {
            last_arch_log->rst_id = arch_ctrl->rst_id;
            last_arch_log->asn = arch_ctrl->asn;
        }
    }
}

static status_t arch_init_single_proc_ctx(arch_context_t *arch_ctx, uint32 dest_id, knl_session_t *session)
{
    const config_t *config = session->kernel->attr.config;
    const char *state_format = "ARCHIVE_DEST_STATE_%d";
    char param_name[GS_MAX_NAME_LEN];
    errno_t ret;

    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[dest_id];
    ret = memset_sp(proc_ctx, sizeof(arch_proc_context_t), 0, sizeof(arch_proc_context_t));
    knl_securec_check(ret);

    proc_ctx->arch_id = dest_id + 1;
    proc_ctx->session = session->kernel->sessions[SESSION_ID_ARCH];
    proc_ctx->last_file_id = GS_INVALID_ID32;
    proc_ctx->next_file_id = GS_INVALID_ID32;
    proc_ctx->enabled = GS_FALSE;
    proc_ctx->alarmed = GS_FALSE;

    arch_attr_t *arch_attr = &session->kernel->attr.arch_attr[dest_id];

    // Set log archive destination path
    char *value = arch_attr->local_path;
    if (arch_set_dest(arch_ctx, value, dest_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // Set log archive destination status
    ret = sprintf_s(param_name, GS_MAX_NAME_LEN, state_format, dest_id + 1); /* state_format length < 26 + 11 = 37 */
    knl_securec_check_ss(ret);
    value = cm_get_config_value(config, param_name);
    knl_panic_log(value != NULL, "the config value is NULL.");

    if (arch_set_dest_state(session, value, dest_id, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arch_init_arch_files_size(session, dest_id);

    if (proc_ctx->arch_dest[0] != '\0' && proc_ctx->dest_status == STATE_ENABLE) {
        if (proc_ctx->arch_id > ARCH_DEFAULT_DEST) {
            GS_LOG_RUN_ERR("[ARCH] Multiple ARCHIVE_DEST not supported. ARCHIVE_DEST_%u is set.",
                proc_ctx->arch_id);
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "Set multiple ARCHIVE_DEST",
                "the situation when ARCHIVE_DEST is set");
            return GS_ERROR;
        }
        arch_ctx->arch_dest_num++;
        proc_ctx->enabled = GS_TRUE;
    }
    return GS_SUCCESS;
}

static status_t arch_init_proc_ctx(arch_context_t *arch_ctx, knl_session_t *session)
{
    for (uint32 i = 0; i < GS_MAX_ARCH_DEST; i++) {
        if (arch_init_single_proc_ctx(arch_ctx, i, session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    // If no LOG_ARCHIVE_DEST_n is configured, set LOG_ARCHIVE_DEST_1 with default value.
    if (arch_ctx->arch_dest_num == 0) {
        arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[0];
        char *value = session->kernel->home;
        knl_panic_log(value != NULL, "the value is NULL.");

        int32 print_num = sprintf_s(proc_ctx->arch_dest, GS_FILE_NAME_BUFFER_SIZE, "%s/archive_log", value);
        knl_securec_check_ss(print_num);
        if (strlen(proc_ctx->arch_dest) >= GS_MAX_ARCH_NAME_LEN) {
            GS_THROW_ERROR(ERR_NAME_TOO_LONG, "dest path", strlen(proc_ctx->arch_dest), GS_MAX_ARCH_NAME_LEN);
            return GS_ERROR;
        }

        if (!cm_dir_exist(proc_ctx->arch_dest)) {
            if (cm_create_dir(proc_ctx->arch_dest) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[ARCH] failed to create dir %s", proc_ctx->arch_dest);
                return GS_ERROR;
            }
        }

        arch_ctx->arch_dest_num++;
        proc_ctx->enabled = GS_TRUE;
    }

    return GS_SUCCESS;
}

status_t arch_init(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    const config_t *config = session->kernel->attr.config;
    char *value = NULL;

    if (arch_ctx->initialized) {
        if (!arch_ctx->is_archive && ctrl->core.log_mode == ARCHIVE_LOG_ON) {
            arch_ctx->is_archive = GS_TRUE;
        }

        GS_LOG_RUN_INF("[ARCH] Already initialized");
        return GS_SUCCESS;
    }

    arch_ctx->is_archive = (ctrl->core.log_mode == ARCHIVE_LOG_ON);
    arch_ctx->rcy_point = &ctrl->core.rcy_point;
    arch_ctx->archived_recid = 0;

    // Set archived log file name format
    value = cm_get_config_value(config, "ARCHIVE_FORMAT");
    knl_panic_log(value != NULL, "the config value is NULL.");

    if (arch_set_format(arch_ctx, value)) {
        return GS_ERROR;
    }

    if (arch_init_proc_ctx(arch_ctx, session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arch_ctx->initialized = GS_TRUE;
    GS_LOG_RUN_INF("[ARCH] Initialization complete");
    return GS_SUCCESS;
}

void arch_last_archived_log(knl_session_t *session, uint32 dest_pos, arch_log_id_t *arch_log_out)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;

    if (dest_pos <= GS_MAX_ARCH_DEST && dest_pos >= ARCH_DEFAULT_DEST) {
        proc_ctx = &arch_ctx->arch_proc[dest_pos - 1];
        if (proc_ctx->arch_id == 0) {
            arch_log_out->arch_log = 0;
        } else {
            *arch_log_out = proc_ctx->last_archived_log;
        }
    } else {
        CM_ABORT(0, "[ARCH] ABORT INFO: invalid destination id %u for archive", dest_pos);
    }
}

void arch_get_last_rstid_asn(knl_session_t *session, uint32 *rst_id, uint32 *asn)
{
    arch_log_id_t last_arch_log;
    arch_last_archived_log(session, ARCH_DEFAULT_DEST, &last_arch_log);

    *rst_id = last_arch_log.rst_id;
    *asn = last_arch_log.asn;
}

status_t arch_start(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    uint32 i;

    arch_ctx->is_archive = (ctrl->core.log_mode == ARCHIVE_LOG_ON);

    if (!arch_ctx->is_archive) {
        return GS_SUCCESS;
    }

    for (i = 0; i < GS_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        if (proc_ctx != NULL && proc_ctx->arch_dest[0] != '\0' && proc_ctx->enabled) {
            proc_ctx->arch_buf = (char *)malloc(GS_ARCHIVE_BUFFER_SIZE);
            if (proc_ctx->arch_buf == NULL) {
                GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_ARCHIVE_BUFFER_SIZE, "copying archive log file");
                return GS_ERROR;
            }

            if (cm_create_thread(arch_proc, 0, proc_ctx, &proc_ctx->thread) != GS_SUCCESS) {
                CM_FREE_PTR(proc_ctx->arch_buf);
                return GS_ERROR;
            }
            GS_LOG_RUN_INF("[ARCH] Start ARCH thread for ARCHIVE_DEST_%d[%s]",
                           proc_ctx->arch_id, proc_ctx->arch_dest);
        }
    }

    return GS_SUCCESS;
}

void arch_close(knl_session_t *session)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = NULL;
    uint32 i;

    for (i = 0; i < GS_MAX_ARCH_DEST; i++) {
        proc_ctx = &arch_ctx->arch_proc[i];
        if (proc_ctx->arch_dest[0] != '\0' && proc_ctx->enabled) {
            cm_close_thread(&proc_ctx->thread);
            CM_FREE_PTR(proc_ctx->arch_buf);
            GS_LOG_RUN_INF("[ARCH] Close ARCH thread for ARCHIVE_DEST_%d[%s]",
                           proc_ctx->arch_id, proc_ctx->arch_dest);
        }
    }
}

status_t arch_set_dest(arch_context_t *arch_ctx, char *value, uint32 pos)
{
    knl_panic_log(pos < GS_MAX_ARCH_DEST, "the pos is abnormal, panic info: pos %u", pos);
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[pos];
    size_t value_len;
    errno_t ret;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    if (arch_check_dest(arch_ctx, value, pos) != GS_SUCCESS) {
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }

    value_len = strlen(value);
    ret = strncpy_s(proc_ctx->arch_dest, GS_FILE_NAME_BUFFER_SIZE, value, value_len);
    knl_securec_check(ret);

    cm_spin_unlock(&arch_ctx->dest_lock);
    return GS_SUCCESS;
}

status_t arch_set_dest_state(knl_session_t *session, const char *value, uint32 cur_pos, bool32 notify)
{
    arch_context_t *arch_ctx = &session->kernel->arch_ctx;
    arch_proc_context_t *proc_ctx = &arch_ctx->arch_proc[cur_pos];
    knl_attr_t *attr = &session->kernel->attr;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    if (cm_strcmpi(value, "DEFER") == 0) {
        proc_ctx->dest_status = STATE_DEFER;
    } else if (cm_strcmpi(value, "ALTERNATE") == 0) {
        proc_ctx->dest_status = STATE_ALTERNATE;
    } else if (cm_strcmpi(value, "ENABLE") == 0) {
        proc_ctx->dest_status = STATE_ENABLE;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "archive_dest_state_n");
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }

    if (!notify) {
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_SUCCESS;
    }

    bool32 enable_orig = attr->arch_attr[cur_pos].enable;
    attr->arch_attr[cur_pos].enable = (bool32)(proc_ctx->dest_status == STATE_ENABLE);
    if (arch_check_dest_service(attr, &attr->arch_attr[cur_pos], cur_pos) != GS_SUCCESS) {
        attr->arch_attr[cur_pos].enable = enable_orig;
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }

    arch_ctx->arch_dest_state_changed = GS_TRUE;
    GS_LOG_RUN_INF("ARCHIVE_DEST_STATE_%d is changed to %s", cur_pos + 1,
                   attr->arch_attr[cur_pos].enable ? "ENABLE" : "DISABLE");

    while (arch_ctx->arch_dest_state_changed) {
        cm_sleep(1);
        if (proc_ctx->thread.closed) {
            arch_ctx->arch_dest_state_changed = GS_FALSE;
            cm_spin_unlock(&arch_ctx->dest_lock);
            return GS_ERROR;
        }
    }

    cm_spin_unlock(&arch_ctx->dest_lock);
    return GS_SUCCESS;
}
static status_t arch_check_format(char *value, char *cur_pos, bool32 *has_asn,
    bool32 *has_thread_id, bool32 *has_rst_id)
{
    switch (*cur_pos) {
        case 's':
        case 'S': {
            if (*has_asn) {
                GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                    "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return GS_ERROR;
            }

            *has_asn = GS_TRUE;
            break;
        }
        case 't':
        case 'T': {
            if (*has_thread_id) {
                GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                    "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return GS_ERROR;
            }

            *has_thread_id = GS_TRUE;
            break;
        }
        case 'r':
        case 'R': {
            if (*has_rst_id) {
                GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                    "'%s' has repeated format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
                return GS_ERROR;
            }

            *has_rst_id = GS_TRUE;
            break;
        }
        default:
        {
            // Invalid format.
            GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                "'%s' has wrong format '%c' for ARCHIVE_FORMAT", value, *cur_pos);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t arch_set_format(arch_context_t *arch_ctx, char *value)
{
    char *cur_pos = value;
    bool32 has_asn = GS_FALSE;
    bool32 has_rst_id = GS_FALSE;
    bool32 has_thread_id = GS_FALSE;
    size_t value_len;
    errno_t ret;

    cm_spin_lock(&arch_ctx->dest_lock, NULL);
    if (strlen(value) > GS_MAX_ARCH_NAME_LEN - GS_ARCH_RESERVED_FORMAT_LEN) {
        GS_THROW_ERROR(ERR_NAME_TOO_LONG, "archive format", strlen(value),
                       GS_MAX_ARCH_NAME_LEN - GS_ARCH_RESERVED_FORMAT_LEN);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }

    while (*cur_pos != '\0') {
        while (*cur_pos != '%' && *cur_pos != '\0') {
            // literal char, just move to next.
            cur_pos++;
        }

        if (*cur_pos == '\0') {
            break;
        }

        cur_pos++;
        // here we got a valid option, process it
        if (arch_check_format(value, cur_pos, &has_asn, &has_thread_id, &has_rst_id) != GS_SUCCESS) {
            cm_spin_unlock(&arch_ctx->dest_lock);
            return GS_ERROR;
        }
        cur_pos++;
    }

    if (has_asn && has_rst_id) {
        value_len = strlen(value);
        ret = strncpy_s(arch_ctx->arch_format, GS_FILE_NAME_BUFFER_SIZE, value, value_len);
        knl_securec_check(ret);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_SUCCESS;
    } else {
        GS_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
                          "'%s' does not contains asn[s] or resetlog[r] option for ARCHIVE_FORMAT", value);
        cm_spin_unlock(&arch_ctx->dest_lock);
        return GS_ERROR;
    }
}

status_t arch_set_max_processes(knl_session_t *session, char *value)
{
    GS_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_MAX_THREADS");
    return GS_ERROR;
}

status_t arch_set_min_succeed(arch_context_t *ctx, char *value)
{
    GS_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_MIN_SUCCEED_DEST");
    return GS_ERROR;
}

status_t arch_set_trace(char *value, uint32 *arch_trace)
{
    GS_THROW_ERROR(ERR_NOT_COMPATIBLE, "ARCHIVE_TRACE");
    return GS_ERROR;
}

char *arch_get_dest_type(knl_session_t *session, uint32 id, arch_attr_t *attr, bool32 *is_primary)
{
    database_t *db = &session->kernel->db;
    uint16 port;
    char host[GS_HOST_NAME_BUFFER_SIZE];

    *is_primary = GS_FALSE;
    if (id == 0) {
        return "LOCAL";
    }

    if (DB_IS_PRIMARY(db)) {
        if (attr->role_valid != VALID_FOR_STANDBY_ROLE && attr->enable) {
            return "PHYSICAL STANDBY";
        }

        return "UNKNOWN";
    }

    if (attr->enable) {
        lrcv_context_t *lrcv = &session->kernel->lrcv_ctx;
        if (lrcv->status == LRCV_DISCONNECTED || lrcv->status == LRCV_NEED_REPAIR ||
            lrcv_get_primary_server(session, 0, host, GS_HOST_NAME_BUFFER_SIZE, &port) != GS_SUCCESS) {
            return "UNKNOWN";
        }

        if (!strcmp(host, attr->service.host) && port == attr->service.port) {
            if (DB_IS_PHYSICAL_STANDBY(db) && attr->role_valid != VALID_FOR_STANDBY_ROLE) {
                *is_primary = GS_TRUE;
                return "PRIMARY";
            }

            if (DB_IS_CASCADED_PHYSICAL_STANDBY(db) && attr->role_valid != VALID_FOR_PRIMARY_ROLE) {
                return "PHYSICAL STANDBY";
            }
        } else {
            if (DB_IS_PHYSICAL_STANDBY(db)) {
                if (attr->role_valid == VALID_FOR_STANDBY_ROLE) {
                    return "CASCADED PHYSICAL STANDBY";
                }
            }

            return "UNKNOWN";
        }
    }

    return "UNKNOWN";
}

void arch_get_dest_path(knl_session_t *session, uint32 id, arch_attr_t *arch_attr, char *path, uint32 path_size)
{
    arch_proc_context_t *proc_ctx = &session->kernel->arch_ctx.arch_proc[id];
    errno_t ret;
    int32 print_num;
    size_t arch_dest_len = strlen(proc_ctx->arch_dest);

    if (id == 0) {
        ret = strncpy_s(path, path_size, proc_ctx->arch_dest, arch_dest_len);
        knl_securec_check(ret);
    } else if (arch_attr->used) {
        print_num = sprintf_s(path, path_size, "[%s:%u] %s",
                              arch_attr->service.host, arch_attr->service.port, proc_ctx->arch_dest);
        knl_securec_check_ss(print_num);
    } else {
        path[0] = '\0';
    }
}

char *arch_get_sync_status(knl_session_t *session, uint32 id, arch_attr_t *arch_attr, arch_dest_sync_t *sync_type)
{
    uint32 i;
    database_t *db = &session->kernel->db;
    lsnd_context_t *lsnd_ctx = &session->kernel->lsnd_ctx;
    lsnd_t *proc = NULL;

    if (DB_IS_PRIMARY(db) || DB_IS_PHYSICAL_STANDBY(db)) {
        if (id == 0) {
            *sync_type = ARCH_DEST_SYNCHRONIZED;
            return "OK";
        }

        if (arch_attr->enable) {
            if (db->ctrl.core.protect_mode == MAXIMUM_PERFORMANCE ||
                (DB_IS_PRIMARY(db) && arch_attr->net_mode != LOG_NET_TRANS_MODE_SYNC)) {
                *sync_type = ARCH_DEST_UNKNOWN;
                return "CHECK CONFIGURATION";
            }

            for (i = 0; i < GS_MAX_PHYSICAL_STANDBY; i++) {
                proc = lsnd_ctx->lsnd[i];
                if (proc == NULL) {
                    continue;
                }

                if (!strcmp(proc->dest_info.peer_host, arch_attr->service.host)) {
                    if (proc->status >= LSND_LOG_SHIFTING) {
                        *sync_type = ARCH_DEST_SYNCHRONIZED;
                        return "OK";
                    } else if (DB_IS_PRIMARY(db)) {
                        *sync_type = ARCH_DEST_NO_SYNCHRONIZED;
                        return "CHECK NETWORK";
                    } else {
                        *sync_type = ARCH_DEST_UNKNOWN;
                        return "NOT AVAILABLE";
                    }
                }
            }
        }
    }

    *sync_type = ARCH_DEST_UNKNOWN;
    return "NOT AVAILABLE";
}

char *arch_get_dest_sync(const arch_dest_sync_t *sync_type)
{
    switch (*sync_type) {
        case ARCH_DEST_SYNCHRONIZED:
            return "YES";
        case ARCH_DEST_NO_SYNCHRONIZED:
            return "NO";
        default:
            return "UNKNOWN";
    }
}

bool32 arch_dest_state_match_role(knl_session_t *session, arch_attr_t *arch_attr)
{
    return (bool32)((DB_IS_PRIMARY(&session->kernel->db) && arch_attr->role_valid != VALID_FOR_STANDBY_ROLE) ||
        (DB_IS_PHYSICAL_STANDBY(&session->kernel->db) && arch_attr->role_valid != VALID_FOR_PRIMARY_ROLE));
}

bool32 arch_dest_state_disabled(knl_session_t *session, uint32 inx)
{
    knl_attr_t *attr = &session->kernel->attr;

    return !attr->arch_attr[inx].enable;
}

void arch_set_deststate_disabled(knl_session_t *session, uint32 inx)
{
    knl_attr_t *attr = &session->kernel->attr;

    knl_panic(attr->arch_attr[inx].enable);
    attr->arch_attr[inx].enable = GS_FALSE;
}

static inline bool32 arch_dest_both_valid(arch_attr_t *tmp_attr, arch_attr_t *arch_attr)
{
    if (tmp_attr->role_valid != arch_attr->role_valid &&
        tmp_attr->role_valid != VALID_FOR_ALL_ROLES &&
        arch_attr->role_valid != VALID_FOR_ALL_ROLES) {
        return GS_FALSE;
    }

    return (bool32)(tmp_attr->enable && arch_attr->enable);
}

status_t arch_check_dest_service(void *attr, arch_attr_t *arch_attr, uint32 slot)
{
    uint32 i;
    arch_attr_t *tmp_attr = NULL;

    for (i = 1; i < GS_MAX_ARCH_DEST; i++) {
        tmp_attr = &((knl_attr_t *)attr)->arch_attr[i];

        if (i == slot || tmp_attr->dest_mode != LOG_ARCH_DEST_SERVICE) {
            continue;
        }

        if (strcmp(tmp_attr->service.host, arch_attr->service.host) == 0 &&
            tmp_attr->service.port == arch_attr->service.port &&
            arch_dest_both_valid(tmp_attr, arch_attr)) {
            GS_THROW_ERROR(ERR_DUPLICATE_LOG_ARCHIVE_DEST, slot + 1, i + 1);
            GS_LOG_RUN_ERR("ARCHIVE_DEST_%d destination is the same as ARCHIVE_DEST_%d", slot + 1, i + 1);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

bool32 arch_has_valid_arch_dest(knl_session_t *session)
{
    uint32 i;
    knl_attr_t *attr = &session->kernel->attr;

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        return GS_TRUE;
    }

    for (i = 1; i < GS_MAX_ARCH_DEST; i++) {
        if (attr->arch_attr[i].dest_mode == LOG_ARCH_DEST_SERVICE) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

status_t arch_regist_archive(knl_session_t *session, const char *name)
{
    int32 handle = GS_INVALID_HANDLE;
    log_file_head_t head;

    if (cm_open_file(name, O_BINARY | O_SYNC | O_RDWR, &handle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_read_file(handle, &head, sizeof(log_file_head_t), NULL) != GS_SUCCESS) {
        cm_close_file(handle);
        return GS_ERROR;
    }

    if ((int64)head.write_pos != cm_file_size(handle)) {
        cm_close_file(handle);
        GS_THROW_ERROR(ERR_INVALID_ARCHIVE_LOG, name);
        return GS_ERROR;
    }

    cm_close_file(handle);
    if (arch_record_archinfo(session, ARCH_DEFAULT_DEST, name, &head) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t arch_try_regist_archive(knl_session_t *session, uint32 rst_id, uint32 *asn)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    for (;;) {
        arch_set_archive_log_name(session, rst_id, *asn, ARCH_DEFAULT_DEST, file_name, GS_FILE_NAME_BUFFER_SIZE);
        if (!cm_file_exist(file_name)) {
            break;
        }

        if (arch_regist_archive(session, file_name) != GS_SUCCESS) {
            return GS_ERROR;
        }

        (*asn)++;
    }

    return GS_SUCCESS;
}

void arch_reset_archfile(knl_session_t *session, uint32 replay_asn)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    arch_proc_context_t *proc_ctx = &session->kernel->arch_ctx.arch_proc[0];
    arch_ctrl_t *arch_ctrl = NULL;

    cm_spin_lock(&proc_ctx->record_lock, NULL);

    for (uint32 i = ctrl->core.archived_start; i != ctrl->core.archived_end;) {
        arch_ctrl = db_get_arch_ctrl(session, i);
        if (arch_ctrl->asn > replay_asn) {
            if (cm_file_exist(arch_ctrl->name)) {
                if (cm_remove_file(arch_ctrl->name) != GS_SUCCESS) {
                    GS_LOG_RUN_ERR("[ARCH] failed to remove archive logfile %s", arch_ctrl->name);
                } else {
                    proc_ctx->curr_arch_size -= (int64)arch_ctrl->blocks * arch_ctrl->block_size;
                    GS_LOG_RUN_INF("[ARCH] remove archive logfile %s", arch_ctrl->name);
                }
            }

            arch_ctrl->recid = 0;

            if (db_save_arch_ctrl(session, i) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[ARCH] failed to save archive control file");
            }
        }

        i = (i + 1) % GS_MAX_ARCH_NUM;
    }

    cm_spin_unlock(&proc_ctx->record_lock);

    if (proc_ctx->last_archived_log.asn > replay_asn) {
        proc_ctx->last_archived_log.asn = replay_asn - 1;
    }
}

bool32 arch_log_not_archived(knl_session_t *session, uint32 req_rstid, uint32 req_asn)
{
    arch_log_id_t last_arch_log;
    database_t *db = &session->kernel->db;
    log_point_t point = session->kernel->redo_ctx.curr_point;
    log_context_t *redo_ctx = &session->kernel->redo_ctx;
    log_file_t * active_file = &redo_ctx->files[redo_ctx->active_file];

    arch_last_archived_log(session, ARCH_DEFAULT_DEST, &last_arch_log);

    if (DB_IS_PRIMARY(db) && req_asn < active_file->head.asn) {
        return GS_FALSE;
    }

    if (req_rstid > last_arch_log.rst_id || (req_rstid == last_arch_log.rst_id && req_asn > last_arch_log.asn)) {
        return GS_TRUE;
    }

    if (!DB_IS_PHYSICAL_STANDBY(db)) {
        return GS_FALSE;
    }

    /*
     * The resetid and asn in last archived log is not necessarily increasing in ascending order on standby,
     * because it may receive online log and archive log concurrently, and it is unpredictable which one will
     * be recorded in archive firstly.
     *
     * So on the standby, it is need to compare the requested resetid/asn with the replay point further.
     * If the former is larger than the latter, we should consider the requested log has not been archived.
     */
    return (bool32)(req_rstid > point.rst_id || (req_rstid == point.rst_id && req_asn > point.asn));
}

void arch_get_bind_host(knl_session_t *session, const char *srv_host, char *bind_host, uint32 buf_size)
{
    knl_attr_t *attr = &session->kernel->attr;
    arch_attr_t *arch_attr = NULL;
    size_t host_len;
    errno_t err;

    for (uint32 i = 1; i < GS_MAX_ARCH_DEST; i++) {
        arch_attr = &attr->arch_attr[i];

        if (strcmp(srv_host, arch_attr->service.host) == 0 && arch_attr->local_host[0] != '\0') {
            host_len = strlen(arch_attr->local_host);
            err = strncpy_s(bind_host, buf_size, arch_attr->local_host, host_len);
            knl_securec_check(err);
            return;
        }
    }

    bind_host[0] = '\0';
}

static bool32 arch_is_same(const char *arch_name, log_file_head_t head)
{
    log_file_head_t arch_head;
    int32 handle = GS_INVALID_HANDLE;

    if (cm_open_device(arch_name, DEV_TYPE_FILE, 0, &handle) != GS_SUCCESS) {
        GS_LOG_RUN_INF("[ARCH] failed to open %s", arch_name);
        cm_reset_error();
        return GS_FALSE;
    }

    if (cm_read_device(DEV_TYPE_FILE, handle, 0, &arch_head, sizeof(log_file_head_t)) != GS_SUCCESS) {
        cm_close_device(DEV_TYPE_FILE, &handle);
        GS_LOG_RUN_INF("[ARCH] failed to read %s", arch_name);
        cm_reset_error();
        return GS_FALSE;
    }

    if (arch_head.cmp_algorithm == COMPRESS_NONE && cm_file_size(handle) != arch_head.write_pos) {
        cm_close_device(DEV_TYPE_FILE, &handle);
        GS_LOG_RUN_INF("[ARCH] archive file %s is invalid", arch_name);
        return GS_FALSE;
    }
    cm_close_device(DEV_TYPE_FILE, &handle);

    if (arch_head.first != head.first || arch_head.write_pos < head.write_pos) {
        GS_LOG_RUN_INF("[ARCH] archive file %s is not expected, arch info [%lld-%lld], expected log info [%lld-%lld]",
            arch_name, arch_head.write_pos, arch_head.first, head.write_pos, head.first);
        return GS_FALSE;
    }

    return GS_TRUE;
}

status_t arch_process_existed_archfile(knl_session_t * session, const char *arch_name,
    log_file_head_t head, bool32 *ignore_data)
{
    database_ctrl_t *ctrl = &session->kernel->db.ctrl;
    arch_proc_context_t *proc_ctx = &session->kernel->arch_ctx.arch_proc[0];
    arch_ctrl_t *arch_ctrl = NULL;
    *ignore_data = arch_is_same(arch_name, head);
    if (*ignore_data) {
        return GS_SUCCESS;
    }

    if (cm_remove_file(arch_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = ctrl->core.archived_start; i != ctrl->core.archived_end;) {
        arch_ctrl = db_get_arch_ctrl(session, i);
        if (arch_ctrl->asn == head.asn && arch_ctrl->rst_id == head.rst_id) {
            proc_ctx->curr_arch_size -= (int64)arch_ctrl->blocks * arch_ctrl->block_size;
            arch_ctrl->recid = 0;
            if (db_save_arch_ctrl(session, i) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[ARCH] failed to save archive control file");
            }
            break;
        }
        i = (i + 1) % GS_MAX_ARCH_NUM;
    }

    GS_LOG_RUN_INF("[ARCH] Remove archive log %s", arch_name);
    return GS_SUCCESS;
}

static status_t log_try_get_file_offset(knl_session_t *session, log_file_t *logfile, aligned_buf_t *buf)
{
    uint64 size = (uint64)logfile->ctrl->size - logfile->head.write_pos;
    size = (size > buf->buf_size) ? buf->buf_size : size;

    if (logfile->head.write_pos == logfile->ctrl->size) {
        return GS_SUCCESS;
    }
    knl_panic(logfile->head.write_pos < logfile->ctrl->size);

    if (cm_read_device(logfile->ctrl->type, logfile->handle, logfile->head.write_pos,
        buf->aligned_buf, size) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[LOG] failed to read %s ", logfile->ctrl->name);
        return GS_ERROR;
    }
    log_batch_t *batch = (log_batch_t *)(buf->aligned_buf);
    log_batch_tail_t *tail = (log_batch_tail_t *)((char *)batch + batch->size - sizeof(log_batch_tail_t));
    if (size < batch->space_size || !rcy_validate_batch(batch, tail) ||
        batch->head.point.rst_id != logfile->head.rst_id || batch->head.point.asn != logfile->head.asn) {
        return GS_SUCCESS;
    }

    uint64 latest_lfn;
    if (log_get_file_offset(session, logfile->ctrl->name, buf, (uint64 *)&logfile->head.write_pos,
        &latest_lfn, &logfile->head.last) != GS_SUCCESS) {
        return GS_ERROR;
    }
    log_flush_head(session, logfile);

    return GS_SUCCESS;
}

status_t arch_archive_redo(knl_session_t *session, log_file_t *logfile, char *arch_buf, aligned_buf_t log_buf,
    bool32 *is_continue)
{
    char arch_file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    bool32 ignore_data = GS_FALSE;

    if (log_init_file_head(session, logfile) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (logfile->head.write_pos <= CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size)) {
        GS_LOG_RUN_INF("[ARCH] Skip archive empty log file %s", logfile->ctrl->name);
        *is_continue = GS_TRUE;
        return GS_SUCCESS;
    }

    if (log_try_get_file_offset(session, logfile, &log_buf) != GS_SUCCESS) {
        return GS_ERROR;
    }

    arch_set_archive_log_name(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST, arch_file_name,
                              GS_FILE_NAME_BUFFER_SIZE);

    if (cm_file_exist(arch_file_name)) {
        if (arch_process_existed_archfile(session, arch_file_name, logfile->head, &ignore_data) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (ignore_data) {
            GS_LOG_RUN_INF("[ARCH] skip archive log file %s to %s which already exists",
                logfile->ctrl->name, arch_file_name);
            if (arch_archive_log_recorded(session, logfile->head.rst_id, logfile->head.asn, ARCH_DEFAULT_DEST)) {
                *is_continue = GS_TRUE;
                return GS_SUCCESS;
            }
            return (arch_regist_archive(session, arch_file_name));
        }
    }

    if (arch_archive_file(session, arch_buf, logfile->ctrl->name, arch_file_name, logfile) != GS_SUCCESS) {
        return GS_ERROR;
    }
    GS_LOG_RUN_INF("[ARCH] Archive log file %s to %s", logfile->ctrl->name, arch_file_name);

    if (arch_regist_archive(session, arch_file_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t arch_redo_alloc_resource(knl_session_t *session, aligned_buf_t *log_buf, char **arch_buf)
{
    uint32 buf_size = (uint32)LOG_LGWR_BUF_SIZE(session) + SIZE_K(4);
    if (cm_aligned_malloc((int64)buf_size, "log buffer", log_buf) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[ARCH] failed to alloc log buffer with size %u", buf_size);
        return GS_ERROR;
    }

    *arch_buf = (char *)malloc(GS_ARCHIVE_BUFFER_SIZE);
    if (*arch_buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_ARCHIVE_BUFFER_SIZE, "copying archive log file");
        cm_aligned_free(log_buf);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t arch_try_arch_redo(knl_session_t *session, uint32 *max_asn)
{
    log_file_t *logfile = NULL;
    database_t *db = &session->kernel->db;
    aligned_buf_t log_buf;
    char *arch_buf = NULL;

    if (arch_redo_alloc_resource(session, &log_buf, &arch_buf) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *max_asn = 0;
    for (uint32 i = 0; i < db->ctrl.core.log_hwm; i++) {
        logfile = &db->logfiles.items[i];
        if (LOG_IS_DROPPED(logfile->ctrl->flg)) {
            continue;
        }
        if (logfile->ctrl->status == LOG_FILE_ACTIVE || logfile->ctrl->status == LOG_FILE_CURRENT) {
            bool32 is_continue = GS_FALSE;
            if (arch_archive_redo(session, logfile, arch_buf, log_buf, &is_continue) != GS_SUCCESS) {
                cm_aligned_free(&log_buf);
                CM_FREE_PTR(arch_buf);
                return GS_ERROR;
            }

            if (is_continue) {
                continue;
            }

            if (logfile->head.asn >= *max_asn) {
                *max_asn = logfile->head.asn;
            }
        }
    }
    cm_aligned_free(&log_buf);
    CM_FREE_PTR(arch_buf);
    return GS_SUCCESS;
}

