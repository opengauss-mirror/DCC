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
 * knl_log_file.c
 *    Functions for constructing redo log file
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/persist/knl_log_file.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_log_file.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctrl_restore.h"

static uint32 log_check_logfile_exist(knl_session_t *session, uint32 hwl, const text_t *log_name,
                                      bool32 *exist)
{
    uint32 i;
    log_file_ctrl_t *ctrl = NULL;

    for (i = 0; i < hwl; i++) {
        ctrl = session->kernel->db.logfiles.items[i].ctrl;
        if (cm_filename_equal(log_name, ctrl->name)) {
            *exist = GS_TRUE;
            return i;
        }
    }

    *exist = GS_FALSE;
    return 0;
}

static bool32 log_check_filepath_exist(text_t *log_name)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    char file_path[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    (void)cm_text2str(log_name, file_name, GS_FILE_NAME_BUFFER_SIZE);
    cm_trim_filename(file_name, GS_FILE_NAME_BUFFER_SIZE, file_path);

    if (!cm_dir_exist(file_path)) {
        log_name->str[strlen(file_path)] = '\0';
        return GS_FALSE;
    }

    return GS_TRUE;
}


static status_t log_precheck(knl_session_t *session, knl_alterdb_def_t *def)
{
    bool32 is_exist = GS_FALSE;
    int64 min_size;
    knl_device_def_t *dev_def = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    log_file_ctrl_t *ctrl = NULL;

    for (uint32 i = 0; i < kernel->redo_ctx.logfile_hwm; i++) {
        ctrl = kernel->db.logfiles.items[i].ctrl;
        if (LOG_IS_DROPPED(ctrl->flg)) {
            continue;
        }
    }

    // log_count <= 256, count <= 256, so sum total value is smaller than max uint32 value
    if (db->ctrl.core.log_count + def->logfile.logfiles.count > GS_MAX_LOG_FILES) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_LOG_FILES, "logfile");
        return GS_ERROR;
    }

    min_size = (int64)LOG_MIN_SIZE(kernel);
    for (uint32 i = 0; i < def->logfile.logfiles.count; i++) {
        dev_def = (knl_device_def_t *)cm_galist_get(&def->logfile.logfiles, i);
        if (dev_def->size <= min_size) {
            GS_THROW_ERROR(ERR_LOG_FILE_SIZE_TOO_SMALL, min_size);
            return GS_ERROR;
        }

        if (DB_IS_RAFT_ENABLED(kernel) && dev_def->size != ctrl->size) {
            GS_THROW_ERROR(ERR_LOG_SIZE_NOT_MATCH);
            return GS_ERROR;      
        }

        if (dev_def->name.str[dev_def->name.len - 1] == '/' || (dev_def->name.str[dev_def->name.len - 1] == '\\')) {
            GS_THROW_ERROR(ERR_LOG_FILE_NAME_MISS);
            return GS_ERROR;
        }

        (void)log_check_logfile_exist(session, db->ctrl.core.log_hwm, &dev_def->name, &is_exist);
        if (is_exist) {
            dev_def->name.str[dev_def->name.len] = '\0';
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "file or directory", dev_def->name.str);
            return GS_ERROR;
        }

        if (!log_check_filepath_exist(&dev_def->name)) {
            GS_THROW_ERROR(ERR_DIR_NOT_EXISTS, dev_def->name.str);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static uint32 log_find_hole_idx(knl_session_t *session, uint32 hwm, bool32 *found)
{
    log_file_ctrl_t *ctrl = NULL;
    for (uint32 i = 0; i < hwm; i++) {
        ctrl = session->kernel->db.logfiles.items[i].ctrl;
        if (LOG_IS_DROPPED(ctrl->flg)) {
            *found = GS_TRUE;
            return i;
        }
    }

    *found = GS_FALSE;
    return GS_INVALID_ID32;
}

status_t db_alter_add_logfile(knl_session_t *session, knl_alterdb_def_t *def)
{
    uint32 slot, hole_inx;
    bool32 hole_found = GS_FALSE;
    knl_device_def_t *dev_def = NULL;
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;
    database_t *db = &kernel->db;
    log_context_t *ctx = &kernel->redo_ctx;
    rd_altdb_logfile_t rd;
    int64 block_num;
    errno_t err;

    if (log_precheck(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->logfile.logfiles.count; i++) {
        dev_def = (knl_device_def_t *)cm_galist_get(&def->logfile.logfiles, i);

        hole_inx = log_find_hole_idx(session, db->ctrl.core.log_hwm, &hole_found);
        if (hole_found) {
            knl_panic_log(db->ctrl.core.log_count < db->ctrl.core.log_hwm, "the log_count is more than log_hwm, "
                          "panic info: log_count %u log_hwm %u", db->ctrl.core.log_count, db->ctrl.core.log_hwm);
            slot = hole_inx;
        } else {
            knl_panic_log(db->ctrl.core.log_count == db->ctrl.core.log_hwm, "the log_count is not equal to log_hwm, "
                          "panic info: log_count %u log_hwm %u", db->ctrl.core.log_count, db->ctrl.core.log_hwm);
            slot = db->ctrl.core.log_count;
        }

        logfile = &db->logfiles.items[slot];
        logfile->ctrl->file_id = (int32)slot;
        logfile->ctrl->size = dev_def->size;
        logfile->ctrl->block_size = dev_def->block_size == 0 ? GS_DFLT_LOG_BLOCK_SIZE : (uint16)dev_def->block_size;
        block_num = logfile->ctrl->size / (int16)logfile->ctrl->block_size;
        INT32_OVERFLOW_CHECK(block_num);
        (void)cm_text2str(&dev_def->name, logfile->ctrl->name, GS_FILE_NAME_BUFFER_SIZE);
        logfile->ctrl->type = DEV_TYPE_FILE;
        logfile->ctrl->status = LOG_FILE_UNUSED;

        if (cm_build_device(logfile->ctrl->name, logfile->ctrl->type, kernel->attr.xpurpose_buf,
            GS_XPURPOSE_BUFFER_SIZE, logfile->ctrl->size, knl_redo_io_flag(session),
            GS_FALSE, &logfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to build %s ", logfile->ctrl->name);
            return GS_ERROR;
        }

        logfile->head.first = GS_INVALID_ID64;
        logfile->head.last = GS_INVALID_ID64;
        logfile->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
        logfile->head.asn = GS_INVALID_ASN;
        logfile->head.block_size = (int32)logfile->ctrl->block_size;
        logfile->head.rst_id = 0;
        logfile->head.cmp_algorithm = COMPRESS_NONE;

        if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
                           &logfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", logfile->ctrl->name);
            return GS_ERROR;
        }

        if (lsnd_open_specified_logfile(session, slot) != GS_SUCCESS) {
            cm_close_device(logfile->ctrl->type, &logfile->handle);
            return GS_ERROR;
        }

        log_lock_logfile(session);
        log_flush_head(session, logfile);
        log_unlock_logfile(session);

        db->ctrl.core.log_count += 1;
        db->ctrl.core.log_hwm += hole_found ? 0 : 1;
        db->logfiles.hwm = db->ctrl.core.log_hwm;
        LOG_SET_DROPPED(logfile->ctrl->flg);

        if (cm_add_file_watch(rmon_ctx->watch_fd, logfile->ctrl->name, &logfile->wd) != GS_SUCCESS) {
            GS_LOG_RUN_WAR("[RMON]: failed to add monitor of logfile %s", logfile->ctrl->name);
        }

        rd.op_type = RD_ADD_LOGFILE;
        rd.slot = slot;
        rd.size = logfile->ctrl->size;
        rd.block_size = (int32)logfile->ctrl->block_size;
        err = strcpy_sp(rd.name, GS_FILE_NAME_BUFFER_SIZE, logfile->ctrl->name);
        knl_securec_check(err);
        rd.hole_found = hole_found;
        log_put(session, RD_LOGIC_OPERATION, &rd, sizeof(rd_altdb_logfile_t), LOG_ENTRY_FLAG_NONE);

        knl_commit(session);

        log_lock_logfile(session);
        LOG_UNSET_DROPPED(logfile->ctrl->flg);
        ctx->logfile_hwm = db->logfiles.hwm;
        ctx->files = db->logfiles.items;
        log_add_freesize(session, slot);
        log_unlock_logfile(session);

        if (db_save_log_ctrl(session, slot) != GS_SUCCESS) {
            CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file when alter database");
        }
    }

    return GS_SUCCESS;
}

status_t db_alter_drop_logfile(knl_session_t *session, knl_alterdb_def_t *def)
{
    uint32 inx;
    uint32 log_count;
    bool32 is_exist = GS_FALSE;
    knl_device_def_t *dev_def;
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    log_context_t *ctx = &kernel->redo_ctx;
    rmon_t *rmon_ctx = &kernel->rmon_ctx;
    rd_altdb_logfile_t rd;
    errno_t err;

    dev_def = (knl_device_def_t *)cm_galist_get(&def->logfile.logfiles, 0);

    inx = log_check_logfile_exist(session, db->ctrl.core.log_hwm, &dev_def->name, &is_exist);
    if (!is_exist) {
        GS_THROW_ERROR(ERR_LOG_FILE_NOT_EXIST);
        return GS_ERROR;
    }

    logfile = &db->logfiles.items[inx];

    log_count = log_get_count(session);
    if (log_count <= GS_MIN_LOG_FILES) {
        GS_THROW_ERROR(ERR_LOG_FILE_NOT_ENOUGH);
        return GS_ERROR;
    }

    log_lock_logfile(session);
    if (!log_file_can_drop(ctx, inx) ||
        (ctx->free_size - log_file_freesize(logfile) < LOG_KEEP_SIZE(session->kernel))) {
        GS_THROW_ERROR(ERR_LOG_IN_USE);
        log_unlock_logfile(session);
        return GS_ERROR;
    }

    /* remove datafile from resource monitor */
    if (cm_file_exist(logfile->ctrl->name)) {
        if (cm_rm_file_watch(rmon_ctx->watch_fd, &logfile->wd) != GS_SUCCESS) {
            GS_LOG_RUN_WAR("[RMON]: failed to remove monitor of logfile %s", logfile->ctrl->name);
        }
    }

    cm_close_device(logfile->ctrl->type, &logfile->handle);
    if (cm_remove_device(logfile->ctrl->type, logfile->ctrl->name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to remove %s ", logfile->ctrl->name);
        log_unlock_logfile(session);
        return GS_ERROR;
    }

    rd.op_type = RD_DROP_LOGFILE;
    err = strcpy_sp(rd.name, GS_FILE_NAME_BUFFER_SIZE, logfile->ctrl->name);
    knl_securec_check(err);

    log_decrease_freesize(ctx, logfile);
    LOG_SET_DROPPED(logfile->ctrl->flg);
    err = memset_sp(logfile->ctrl->name, GS_FILE_NAME_BUFFER_SIZE, 0, GS_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    log_unlock_logfile(session);

    db->ctrl.core.log_count--;
    if (db_save_log_ctrl(session, inx) != GS_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file when alter database");
    }

    lsnd_close_specified_logfile(session, inx);
    log_put(session, RD_LOGIC_OPERATION, &rd, sizeof(rd_altdb_logfile_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);
    return GS_SUCCESS;
}

void rd_alter_add_logfile(knl_session_t *session, log_entry_t *log)
{
    rd_altdb_logfile_t *rd = (rd_altdb_logfile_t *)log->data;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    log_context_t *ctx = &kernel->redo_ctx;
    log_file_t *logfile = NULL;
    char dev_name_str[GS_FILE_NAME_BUFFER_SIZE];
    text_t dev_name;
    bool32 is_exist = GS_FALSE;
    errno_t err;
    int32 size;

    err = memset_sp(dev_name_str, GS_FILE_NAME_BUFFER_SIZE, 0, GS_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    if (db_change_storage_path(&kernel->attr.log_file_convert, rd->name, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
        return;
    }
    err = strcpy_sp(dev_name_str, GS_FILE_NAME_BUFFER_SIZE, rd->name);
    knl_securec_check(err);
    dev_name.str = dev_name_str;
    dev_name.len = (uint32)strlen(dev_name_str);
    (void)log_check_logfile_exist(session, db->ctrl.core.log_hwm, &dev_name, &is_exist);
    if (is_exist) {
        return;
    }

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_latch_x(&session->kernel->db.ddl_latch, session->id, NULL);
    }

    logfile = &db->logfiles.items[rd->slot];
    logfile->ctrl->size = rd->size;
    logfile->ctrl->file_id = (int32)rd->slot;
    logfile->ctrl->block_size = (uint16)rd->block_size;
    err = strcpy_sp(logfile->ctrl->name, GS_FILE_NAME_BUFFER_SIZE, rd->name);
    knl_securec_check(err);
    logfile->ctrl->type = DEV_TYPE_FILE;
    logfile->ctrl->status = LOG_FILE_UNUSED;

    if (cm_build_device(logfile->ctrl->name, logfile->ctrl->type, kernel->attr.xpurpose_buf, GS_XPURPOSE_BUFFER_SIZE,
        logfile->ctrl->size, knl_redo_io_flag(session), GS_FALSE, &logfile->handle) != GS_SUCCESS) {
#ifdef LOG_DIAG
        if (!session->log_diag) {
#else
        {
#endif
            cm_unlatch(&session->kernel->db.ddl_latch, NULL);
        }
        GS_LOG_RUN_ERR("[DB] failed to build file %s", logfile->ctrl->name);
        return;
    }

    logfile->head.first = GS_INVALID_ID64;
    logfile->head.last = GS_INVALID_ID64;
    logfile->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
    logfile->head.asn = GS_INVALID_ASN;
    logfile->head.block_size = (int32)logfile->ctrl->block_size;
    logfile->head.rst_id = 0;

    if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
        &logfile->handle) != GS_SUCCESS) {
#ifdef LOG_DIAG
        if (!session->log_diag) {
#else
        {
#endif
            cm_unlatch(&session->kernel->db.ddl_latch, NULL);
        }
        GS_LOG_RUN_ERR("[DB] failed to open %s ", logfile->ctrl->name);
        return;
    }

    log_calc_head_checksum(session, &logfile->head);

    err = memset_sp(ctx->logwr_head_buf, logfile->ctrl->block_size, 0, logfile->ctrl->block_size);
    knl_securec_check(err);
    *(log_file_head_t *)ctx->logwr_head_buf = logfile->head;
    size = CM_CALC_ALIGN(logfile->ctrl->block_size, sizeof(log_file_head_t));
    if (cm_write_device(logfile->ctrl->type, logfile->handle, 0, ctx->logwr_head_buf,
        size) != GS_SUCCESS) {
#ifdef LOG_DIAG
        if (!session->log_diag) {
#else
        {
#endif
            cm_unlatch(&session->kernel->db.ddl_latch, NULL);
        }
        GS_LOG_RUN_ERR("[DB] failed to write %s ", logfile->ctrl->name);
        GS_THROW_ERROR(ERR_FLUSH_REDO_FILE_FAILED, logfile->ctrl->name, 0, sizeof(log_file_head_t));
        cm_close_device(logfile->ctrl->type, &logfile->handle);
        return;
    }

    db->ctrl.core.log_count += 1;
    db->ctrl.core.log_hwm += rd->hole_found ? 0 : 1;
    db->logfiles.hwm = db->ctrl.core.log_hwm;
    LOG_SET_DROPPED(logfile->ctrl->flg);

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_unlatch(&session->kernel->db.ddl_latch, NULL);
    }
    log_lock_logfile(session);
    LOG_UNSET_DROPPED(logfile->ctrl->flg);
    ctx->logfile_hwm = db->logfiles.hwm;
    ctx->files = db->logfiles.items;
    log_add_freesize(session, rd->slot);
    log_unlock_logfile(session);

    if (db_save_log_ctrl(session, rd->slot) != GS_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file");
    }

    (void)lsnd_open_specified_logfile(session, rd->slot);
    (void)cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
                         &kernel->lrpl_ctx.log_handle[rd->slot]);
    if (KNL_GBP_ENABLE(session->kernel)) {
        (void)cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
                             &kernel->gbp_aly_ctx.log_handle[rd->slot]);
    }
}

void print_alter_add_logfile(log_entry_t *log)
{
    rd_altdb_logfile_t *rd = (rd_altdb_logfile_t *)log->data;
    (void)printf("alter add logfile slot:%d,size:%lld,block_size:%d,name:%s,hole_found:%d\n",
        rd->slot, rd->size, rd->block_size, rd->name, rd->hole_found);
}

void rd_alter_drop_logfile(knl_session_t *session, log_entry_t *log)
{
    rd_altdb_logfile_t *rd = (rd_altdb_logfile_t *)log->data;
    uint32 inx;
    uint32 log_count;
    bool32 is_exist = GS_FALSE;
    char dev_name_str[GS_FILE_NAME_BUFFER_SIZE];
    text_t dev_name;
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    log_context_t *ctx = &kernel->redo_ctx;
    rmon_t *rmon_ctx = &kernel->rmon_ctx;
    lrcv_context_t *lrcv = &kernel->lrcv_ctx;
    errno_t err;

    err = memset_sp(dev_name_str, GS_FILE_NAME_BUFFER_SIZE, 0, GS_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    if (db_change_storage_path(&kernel->attr.log_file_convert, rd->name, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
        return;
    }
    err = strcpy_sp(dev_name_str, GS_FILE_NAME_BUFFER_SIZE, rd->name);
    knl_securec_check(err);
    cm_str2text_safe(dev_name_str, (uint32)strlen(dev_name_str), &dev_name);
    inx = log_check_logfile_exist(session, db->ctrl.core.log_hwm, &dev_name, &is_exist);
    if (!is_exist) {
        GS_THROW_ERROR(ERR_LOG_FILE_NOT_EXIST);
        return;
    }

    logfile = &db->logfiles.items[inx];
    log_count = log_get_count(session);
    if (log_count <= GS_MIN_LOG_FILES) {
        GS_THROW_ERROR(ERR_LOG_FILE_NOT_ENOUGH);
        return;
    }

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_latch_x(&session->kernel->db.ddl_latch, session->id, NULL);
    }

    /* Wait until specified log file can be dropped. */
    for (;;) {
        log_lock_logfile(session);
        if (log_file_can_drop(ctx, inx) || lrcv->wait_info.waiting || session->killed) {
            break;
        }
        log_unlock_logfile(session);
        ckpt_trigger(session, GS_FALSE, CKPT_TRIGGER_INC);
        cm_sleep(10);
    }

    lsnd_close_specified_logfile(session, inx);
    cm_close_device(logfile->ctrl->type, &logfile->handle);
    cm_close_device(logfile->ctrl->type, &kernel->lrpl_ctx.log_handle[inx]);
    if (KNL_GBP_ENABLE(kernel)) {
        cm_close_device(logfile->ctrl->type, &kernel->gbp_aly_ctx.log_handle[inx]);
    }

    if (cm_file_exist(logfile->ctrl->name)) {
        if (cm_rm_file_watch(rmon_ctx->watch_fd, &logfile->wd) != GS_SUCCESS) {
            GS_LOG_RUN_WAR("[RMON]: failed to remove monitor of logfile %s", logfile->ctrl->name);
        }
    }

    if (cm_remove_device(logfile->ctrl->type, logfile->ctrl->name) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to remove %s ", logfile->ctrl->name);
        log_unlock_logfile(session);
#ifdef LOG_DIAG
        if (!session->log_diag) {
#else
        {
#endif
            cm_unlatch(&session->kernel->db.ddl_latch, NULL);
        }
        return;
    }

    log_decrease_freesize(ctx, logfile);
    LOG_SET_DROPPED(logfile->ctrl->flg);
    err = memset_sp(logfile->ctrl->name, GS_FILE_NAME_BUFFER_SIZE, 0, GS_FILE_NAME_BUFFER_SIZE);
    knl_securec_check(err);
    log_unlock_logfile(session);

    db->ctrl.core.log_count--;
    if (db_save_log_ctrl(session, inx) != GS_SUCCESS) {
        CM_ABORT(0, "[DB] ABORT INFO: failed to save whole control file");
    }
#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_unlatch(&session->kernel->db.ddl_latch, NULL);
    }
}

void print_alter_drop_logfile(log_entry_t *log)
{
    rd_altdb_logfile_t *rd = (rd_altdb_logfile_t *)log->data;
    (void)printf("alter drop logfile slot:%d,size:%lld,block_size:%d,name:%s,hole_found:%d\n",
        rd->slot, rd->size, rd->block_size, rd->name, rd->hole_found);
}

status_t db_alter_archive_logfile(knl_session_t *session, knl_alterdb_def_t *def)
{
    knl_device_def_t *device = NULL;
    log_file_t log;
    log_file_ctrl_t log_ctrl;
    log_file_t *logfile = &log;
    logfile->ctrl = &log_ctrl;
    aligned_buf_t log_buf;
    char* arch_buf = NULL;
    bool32 is_continue = GS_FALSE;

    if (DB_STATUS(session) != DB_STATUS_NOMOUNT) {
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", operation only supported in nomount mode");
        return GS_ERROR;
    }

    if (arch_init(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (arch_redo_alloc_resource(session, &log_buf, &arch_buf) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->logfile.logfiles.count; i++) {
        device = (knl_device_def_t *)cm_galist_get(&def->logfile.logfiles, i);
        (void)cm_text2str(&device->name, logfile->ctrl->name, GS_MAX_FILE_NAME_LEN);

        if (ctrl_init_logfile_ctrl(session, logfile) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to get logfile %s ctrl info", logfile->ctrl->name);
            cm_aligned_free(&log_buf);
            CM_FREE_PTR(arch_buf);
            return GS_ERROR;
        }

        if (arch_archive_redo(session, logfile, arch_buf, log_buf, &is_continue) != GS_SUCCESS) {
            cm_close_device(DEV_TYPE_FILE, &logfile->handle);
            cm_aligned_free(&log_buf);
            CM_FREE_PTR(arch_buf);
            return GS_ERROR;
        }

        cm_close_device(DEV_TYPE_FILE, &logfile->handle);
    }

    cm_aligned_free(&log_buf);
    CM_FREE_PTR(arch_buf);
    return GS_SUCCESS;
}

