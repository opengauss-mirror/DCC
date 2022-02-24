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
 * knl_db_ctrl.c
 *    implement of database
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/knl_db_ctrl.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_db_ctrl.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctrl_restore.h"

#ifdef __cplusplus
extern "C" {
#endif

void db_init_logfile_ctrl(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 i;

    for (i = 0; i < GS_MAX_LOG_FILES; i++) {
        db->logfiles.items[i].ctrl = (log_file_ctrl_t *)db_get_ctrl_item(db->ctrl.pages, i, sizeof(log_file_ctrl_t),
                                                                         *offset);
        db->logfiles.items[i].handle = GS_INVALID_HANDLE;
    }
    *offset = *offset + (GS_MAX_LOG_FILES - 1) / count + 1;
}

void db_init_space_ctrl(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t);
    uint32 i;
    errno_t err;

    for (i = 0; i < GS_MAX_SPACES; i++) {
        db->spaces[i].ctrl = (space_ctrl_t *)db_get_ctrl_item(db->ctrl.pages, i, sizeof(space_ctrl_t), *offset);
        db->spaces[i].ctrl->used = GS_FALSE;
        db->spaces[i].ctrl->id = i;
        err = memset_sp(db->spaces[i].ctrl->files, GS_MAX_SPACE_FILES * sizeof(uint32), 0xFF,
                        GS_MAX_SPACE_FILES * sizeof(uint32));
        knl_securec_check(err);
    }
    *offset = *offset + (GS_MAX_SPACES - 1) / count + 1;
}

void db_init_datafile_ctrl(knl_session_t *session, uint32 *offset)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    uint32 i;

    for (i = 0; i < GS_MAX_DATA_FILES; i++) {
        db->datafiles[i].ctrl = (datafile_ctrl_t *)db_get_ctrl_item(db->ctrl.pages, i, sizeof(datafile_ctrl_t),
                                                                    *offset);
        db->datafiles[i].ctrl->id = i;
        db->datafiles[i].ctrl->used = GS_FALSE;
        db->datafiles[i].file_no = GS_INVALID_ID32;
        db->datafiles[i].block_num = 0;
    }

    *offset = *offset + (GS_MAX_DATA_FILES - 1) / count + 1;
}

static inline void db_calc_ctrl_checksum(knl_session_t *session, ctrl_page_t *page, uint32 size)
{
    page->tail.checksum = GS_INVALID_CHECKSUM;
    if (size == 0 || DB_IS_CHECKSUM_OFF(session)) {
        return;
    }

    page_calc_checksum((page_head_t *)page, size);
}

static bool32 db_verify_ctrl_checksum(knl_session_t *session, ctrl_page_t *page, uint32 size, uint32 id)
{
    uint32 cks_level = session->kernel->attr.db_block_checksum;
    if (DB_IS_CHECKSUM_OFF(session) || page->tail.checksum == GS_INVALID_CHECKSUM) {
        return GS_TRUE;
    }

    if (size == 0 || !page_verify_checksum((page_head_t *)page, size)) {
        GS_LOG_RUN_ERR("the %d's ctrl page corrupted.size %u cks %u checksum level %s", id, size, page->tail.checksum,
                       knl_checksum_level(cks_level));
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t db_try_sync_ctrl_files(knl_session_t *session, uint32 main_file_id)
{
    uint32 i;
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        if (i == main_file_id) {
            continue;
        }

        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            return GS_ERROR;
        }

        if (cm_write_device(ctrlfile->type, ctrlfile->handle, 0, db->ctrl.pages,
                            (int32)ctrlfile->blocks * ctrlfile->block_size) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            return GS_ERROR;
        }

        if (db_fdatasync_file(session, ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to fdatasync datafile %s", ctrlfile->name);
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            return GS_ERROR;
        }

        cm_close_device(ctrlfile->type, &ctrlfile->handle);
    }

    return GS_SUCCESS;
}

/*
 * Description     : fetch ctrl file name from file name list
 * Input           : files: file name list seperated by \0
 * Output          : name: one ctrl file name
 * Return Value    : void
 * History         : 1.2017/4/26,  add description
 */
static void db_fetch_ctrlfile_name(text_t *files, text_t *name)
{
    if (!cm_fetch_text(files, ',', '\0', name)) {
        return;
    }

    cm_trim_text(name);
    if (name->str[0] == '\'') {
        name->str++;
        /* reduce the length of "\'XXX\'" */
        name->len -= (uint32)strlen("\'\'");

        cm_trim_text(name);
    }
}

static bool32 db_is_ctrl_size_valid(knl_session_t *session, ctrlfile_t *ctrlfile)
{
    int64 filesize, max_size;

    max_size = (int64)(ctrlfile->blocks * ctrlfile->block_size);
    cm_get_filesize(ctrlfile->name, &filesize);
    if (filesize != max_size) {
        GS_LOG_RUN_ERR("[DB] the size of ctrl file %s is abnormal, the expected size is: %lld, "
            "the actual size is: %lld",
            ctrlfile->name, max_size, filesize);
        return GS_FALSE;
    }

    return GS_TRUE;
}

static bool32 db_validate_ctrl(knl_session_t *session, ctrlfile_t *ctrlfile)
{
    uint32 i;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    ctrl_page_t *pages = kernel->db.ctrl.pages;

    for (i = 0; i < CTRL_MAX_PAGE; i++) {
        if (pages[i].head.pcn != pages[i].tail.pcn) {
            return GS_FALSE;
        }

        if (!db_verify_ctrl_checksum(session, &pages[i], (uint32)ctrlfile->block_size, i)) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

static status_t db_try_load_oldctrl(ctrlfile_t *ctrlfile, knl_instance_t *kernel, bool32 *updated)
{
    int32 error_code = cm_get_error_code();
    if (error_code == ERR_READ_DEVICE_INCOMPLETE) {
        GS_LOG_RUN_ERR("[DB] failed to read %s try read old version", ctrlfile->name);
        if (cm_read_device(ctrlfile->type, ctrlfile->handle, 0, kernel->db.ctrl.pages,
                           CTRL_OLD_MAX_PAGE * ctrlfile->block_size) == GS_SUCCESS) {
            cm_reset_error();
            *updated = GS_TRUE;
            return GS_SUCCESS;
        }
    }
    return GS_ERROR;
}

static status_t db_check_undo_space(knl_instance_t *kernel, database_t *db)
{
    uint32 undo_id = kernel->db.ctrl.core.undo_space;
    space_t *undo_space = &db->spaces[undo_id];
    text_t undo_name;
    char *param = cm_get_config_value(kernel->attr.config, "UNDO_TABLESPACE");
    uint32 len = (uint32)strlen(param);
    if (len == 0) {
        return cm_alter_config(kernel->attr.config, "UNDO_TABLESPACE", undo_space->ctrl->name, CONFIG_SCOPE_MEMORY,
                               GS_TRUE);
    }

    cm_str2text(param, &undo_name);
    if (!cm_text_str_equal_ins(&undo_name, undo_space->ctrl->name)) {
        GS_THROW_ERROR(ERR_UNDO_TABLESPACE_NOT_MATCH, undo_name.str, undo_space->ctrl->name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t db_check_ctrl_attr(knl_instance_t *kernel, database_t *db)
{
    if (!db->recover_for_restore && db->status != DB_STATUS_CREATING && !db->ctrl.core.build_completed) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_COMPLETED);
        return GS_ERROR;
    }

    if (kernel->attr.page_size != db->ctrl.core.page_size) {
        GS_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "PAGE_SIZE", kernel->attr.page_size, db->ctrl.core.page_size);
        return GS_ERROR;
    }

    if (kernel->attr.max_column_count < db->ctrl.core.max_column_count) {
        GS_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "MAX_COLUMN_COUNT", kernel->attr.max_column_count,
                       db->ctrl.core.max_column_count);
        return GS_ERROR;
    }

    if (kernel->attr.max_column_count > db->ctrl.core.max_column_count) {
        db->ctrl.core.max_column_count = kernel->attr.max_column_count;
    }

    if (kernel->attr.undo_segments != db->ctrl.core.undo_segments) {
        GS_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "UNDO_SEGMENTS", kernel->attr.undo_segments,
                       db->ctrl.core.undo_segments);
        return GS_ERROR;
    }

    if (db_check_undo_space(kernel, db) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_load_ctrlspace(knl_session_t *session, text_t *files)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    ctrlfile_t *ctrlfile = NULL;
    text_t file_name;
    uint32 main_file_id = GS_INVALID_ID32;
    uint32 id = 0;
    bool32 loaded = GS_FALSE;
    bool32 upgrade = GS_FALSE;

    cm_remove_brackets(files);

    db_fetch_ctrlfile_name(files, &file_name);
    while (file_name.len > 0) {
        CM_ABORT((id < GS_MAX_CTRL_FILES), "number of ctrl file exceeded the limit %d.", GS_MAX_CTRL_FILES);
        ctrlfile = &db->ctrlfiles.items[id];
        (void)cm_text2str(&file_name, ctrlfile->name, GS_FILE_NAME_BUFFER_SIZE);
        ctrlfile->type = DEV_TYPE_FILE;
        ctrlfile->block_size = GS_DFLT_CTRL_BLOCK_SIZE;
        ctrlfile->blocks = CTRL_MAX_PAGE;

        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            return GS_ERROR;
        }

        if (loaded) {
            id++;
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            db_fetch_ctrlfile_name(files, &file_name);
            continue;
        }

        if (cm_read_device(ctrlfile->type, ctrlfile->handle, 0, db->ctrl.pages,
                           (int32)ctrlfile->blocks * ctrlfile->block_size) != GS_SUCCESS) {
            /*
             * old version ctrl file size is 512*16k, new version change to 640*16k
             * need to adapte old version and read 512*16k again when read error!
             */
            if (db_try_load_oldctrl(ctrlfile, kernel, &upgrade) != GS_SUCCESS) {
                GS_LOG_RUN_ERR("[DB] failed to read %s ", ctrlfile->name);
                cm_close_device(ctrlfile->type, &ctrlfile->handle);
                return GS_ERROR;
            }
        }

        cm_close_device(ctrlfile->type, &ctrlfile->handle);

        if (!db_is_ctrl_size_valid(session, ctrlfile)) {
            GS_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "control file size is not correct");
            return GS_ERROR;
        }

        if (!db_validate_ctrl(session, ctrlfile)) {
            GS_LOG_RUN_WAR("control file %s is corrupted", ctrlfile->name);
        } else {
            main_file_id = id;
            loaded = GS_TRUE;
        }

        id++;
        db_fetch_ctrlfile_name(files, &file_name);
    }

    if (!loaded) {
        GS_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "no usable control file");
        return GS_ERROR;
    }

    db_load_core(db);
    if (db_check_ctrl_attr(kernel, db) != GS_SUCCESS) {
        return GS_ERROR;
    }

    db->ctrlfiles.count = id;
    kernel->scn = db->ctrl.core.scn;

    if (upgrade) {
        main_file_id = db->ctrlfiles.count;
    }
    return db_try_sync_ctrl_files(session, main_file_id);
}

status_t db_generate_ctrlitems(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    ctrlfile_t *ctrlfile = NULL;
    char *param;
    text_t files;
    text_t file_name;
    uint32 id = 0;

    param = cm_get_config_value(kernel->attr.config, "CONTROL_FILES");
    cm_str2text(param, &files);

    if (files.len == 0) {
        GS_THROW_ERROR(ERR_LOAD_CONTROL_FILE, "CONTROL_FILES is not set!");
        return GS_ERROR;
    }

    cm_remove_brackets(&files);
    db_fetch_ctrlfile_name(&files, &file_name);
    while (file_name.len > 0) {
        ctrlfile = &db->ctrlfiles.items[id];
        (void)cm_text2str(&file_name, ctrlfile->name, GS_FILE_NAME_BUFFER_SIZE);
        ctrlfile->type = DEV_TYPE_FILE;
        ctrlfile->block_size = GS_DFLT_CTRL_BLOCK_SIZE;
        id++;
        db_fetch_ctrlfile_name(&files, &file_name);
    }

    db->ctrlfiles.count = id;
    return GS_SUCCESS;
}

status_t db_create_ctrl_file(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    ctrlfile_t *ctrlfile = NULL;
    bak_context_t *ctx = &session->kernel->backup_ctx;
    bak_stat_t *stat = &ctx->bak.stat;
    uint32 id;

    for (id = 0; id < db->ctrlfiles.count; id++) {
        ctrlfile = &db->ctrlfiles.items[id];
        if (cm_create_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] failed to create %s ", ctrlfile->name);
            return GS_ERROR;
        }

        if (db_fsync_file(session, ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[BACKUP] failed to fsync datafile %s", ctrlfile->name);
            return GS_ERROR;
        }

        (void)cm_atomic_inc(&stat->writes);
    }

    return GS_SUCCESS;
}

static status_t db_save_ctrl_page(knl_session_t *session, ctrlfile_t *ctrlfile, uint32 page_id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    char *page_buf = (char *)cm_push(session->stack, (uint32)ctrlfile->block_size + (uint32)GS_MAX_ALIGN_SIZE_4K);
    ctrl_page_t *page = (ctrl_page_t *)cm_aligned_buf(page_buf);
    errno_t ret;

    knl_panic(page_id < CTRL_MAX_PAGE);
    CM_ABORT(page_id < CTRL_MAX_PAGE, "[DB] ABORT INFO: the count of control page has reached max control page %u",
             CTRL_MAX_PAGE);
    ret = memcpy_sp(page, ctrlfile->block_size, &db->ctrl.pages[page_id], ctrlfile->block_size);
    knl_securec_check(ret);

    page->head.pcn++;
    page->tail.pcn++;

    db_calc_ctrl_checksum(session, page, (uint32)ctrlfile->block_size);

    if (cm_write_device(ctrlfile->type, ctrlfile->handle, (int64)page_id * ctrlfile->block_size, (char *)page,
                        ctrlfile->block_size) != GS_SUCCESS) {
        cm_pop(session->stack);
        GS_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
        return GS_ERROR;
    }

    if (db_fdatasync_file(session, ctrlfile->handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[DB] failed to fdatasync datafile %s", ctrlfile->name);
        cm_pop(session->stack);
        return GS_ERROR;
    }

    cm_pop(session->stack);
    return GS_SUCCESS;
}

status_t db_save_core_ctrl(knl_session_t *session)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 i;

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        knl_panic((uint32)ctrlfile->block_size == GS_DFLT_CTRL_BLOCK_SIZE);

        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }
    }

    cm_spin_unlock(&db->ctrl_lock);
    return GS_SUCCESS;
}

status_t db_save_log_ctrl(knl_session_t *session, uint32 id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 i;
    uint32 page_id;

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        page_id = db->ctrl.log_segment + id / count;
        if (db_save_ctrl_page(session, ctrlfile, page_id) != GS_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != GS_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }
    }

    if (ctrl_backup_log_ctrl(session, id) != GS_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&db->ctrl_lock);
    return GS_SUCCESS;
}

status_t db_save_datafile_ctrl(knl_session_t *session, uint32 id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    uint32 i;
    uint32 page_id;

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        page_id = db->ctrl.datafile_segment + id / count;
        if (db_save_ctrl_page(session, ctrlfile, page_id) != GS_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != GS_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }
    }

    if (ctrl_backup_datafile_ctrl(session, id) != GS_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&db->ctrl_lock);
    return GS_SUCCESS;
}

status_t db_save_space_ctrl(knl_session_t *session, uint32 id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t);
    uint32 i;
    uint32 page_id;

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        page_id = db->ctrl.space_segment + id / count;
        if (db_save_ctrl_page(session, ctrlfile, page_id) != GS_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != GS_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }
    }

    if (ctrl_backup_space_ctrl(session, id) != GS_SUCCESS) {
        cm_spin_unlock(&db->ctrl_lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&db->ctrl_lock);
    return GS_SUCCESS;
}

status_t db_save_arch_ctrl(knl_session_t *session, uint32 id)
{
    ctrlfile_t *ctrlfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 i;
    uint32 page_id;

    cm_spin_lock(&db->ctrl_lock, NULL);
    db_store_core(db);

    for (i = 0; i < db->ctrlfiles.count; i++) {
        ctrlfile = &db->ctrlfiles.items[i];
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        page_id = db->ctrl.arch_segment + id / count;
        if (db_save_ctrl_page(session, ctrlfile, page_id) != GS_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }

        if (db_save_ctrl_page(session, ctrlfile, CORE_CTRL_PAGE_ID) != GS_SUCCESS) {
            cm_spin_unlock(&db->ctrl_lock);
            return GS_ERROR;
        }
    }

    cm_spin_unlock(&db->ctrl_lock);
    return GS_SUCCESS;
}

arch_ctrl_t *db_get_arch_ctrl(knl_session_t *session, uint32 id)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(arch_ctrl_t);
    uint32 page_id;
    uint32 slot;
    ctrl_page_t *page = NULL;

    page_id = db->ctrl.arch_segment + id / count;
    knl_panic(page_id < CTRL_MAX_PAGE);
    CM_ABORT(page_id < CTRL_MAX_PAGE, "[DB] ABORT INFO: the count of control page has reached max control page %u",
             CTRL_MAX_PAGE);
    slot = id % count;
    page = &db->ctrl.pages[page_id];
    return (arch_ctrl_t *)(page->buf + slot * sizeof(arch_ctrl_t));
}

/*
 * check if ctrl file readable
 */
status_t db_check(knl_session_t *session, text_t *ctrlfiles, bool32 *is_found)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    text_t file_name;
    text_t temp_ctrlfiles;
    int32 fp = GS_INVALID_HANDLE;
    char name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    char *param = cm_get_config_value(kernel->attr.config, "CONTROL_FILES");

    cm_str2text(param, ctrlfiles);
    cm_str2text(param, &temp_ctrlfiles);
    if (ctrlfiles->len == 0) {
        *is_found = GS_FALSE;
        return GS_SUCCESS;
    }

    cm_remove_brackets(&temp_ctrlfiles);
    db_fetch_ctrlfile_name(&temp_ctrlfiles, &file_name);
    (void)cm_text2str(&file_name, name, GS_FILE_NAME_BUFFER_SIZE);

    if (cm_open_device(name, DEV_TYPE_FILE, knl_io_flag(session), &fp) != GS_SUCCESS) {
        *is_found = GS_FALSE;
        GS_LOG_RUN_ERR("[DB] failed to open %s ", name);
        return GS_ERROR;
    }
    cm_close_device(DEV_TYPE_FILE, &fp);
    *is_found = GS_TRUE;

    return GS_SUCCESS;
}

void db_update_name_by_path(const char *path, char *name, uint32 len)
{
    text_t left;
    text_t right;
    text_t text;
    char right_str[GS_FILE_NAME_BUFFER_SIZE];
    errno_t err;

    cm_str2text(name, &text);
    (void)cm_split_rtext(&text, SLASH, '\0', &left, &right);
    (void)cm_text2str(&right, right_str, GS_FILE_NAME_BUFFER_SIZE);
    err = snprintf_s(name, len, len - 1, "%s/%s", path, right_str);
    knl_securec_check_ss(err);
}

status_t db_update_ctrl_filename(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    ctrlfile_set_t *ctrlfiles = &kernel->db.ctrlfiles;
    char *param = NULL;
    text_t local_ctrlfiles;
    text_t file_name;
    char path[GS_FILE_NAME_BUFFER_SIZE];
    char name[GS_FILE_NAME_BUFFER_SIZE];
    uint32 i;
    errno_t err;

    param = cm_get_config_value(kernel->attr.config, "CONTROL_FILES");
    cm_str2text(param, &local_ctrlfiles);
    if (local_ctrlfiles.len == 0) {
        GS_LOG_RUN_ERR("the value of CONTROL_FILES is invaild");
        return GS_ERROR;
    }
    if (cm_check_exist_special_char(param, (uint32)strlen(param))) {
        GS_THROW_ERROR(ERR_INVALID_DIR, param);
        return GS_ERROR;
    }

    err = snprintf_s(path, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", kernel->home, "data");
    knl_securec_check_ss(err);
    cm_remove_brackets(&local_ctrlfiles);
    for (i = 0; i < ctrlfiles->count; i++) {
        db_fetch_ctrlfile_name(&local_ctrlfiles, &file_name);
        if (file_name.len == 0) {
            GS_LOG_RUN_ERR("the value of CONTROL_FILES is invaild");
            return GS_ERROR;
        }
        (void)cm_text2str(&file_name, name, GS_FILE_NAME_BUFFER_SIZE);
        db_update_name_by_path(path, name, GS_FILE_NAME_BUFFER_SIZE);
        err = strcpy_sp(ctrlfiles->items[i].name, GS_FILE_NAME_BUFFER_SIZE, name);
        knl_securec_check(err);
    }

    return GS_SUCCESS;
}

status_t db_update_config_ctrl_name(knl_session_t *session)
{
    config_t *config = session->kernel->attr.config;
    knl_instance_t *kernel = session->kernel;
    ctrlfile_set_t *ctrlfiles = &kernel->db.ctrlfiles;
    char value[GS_MAX_CONFIG_LINE_SIZE] = { 0 };
    uint32 i;
    errno_t err;

    err = strcpy_sp(value, GS_MAX_CONFIG_LINE_SIZE, "(");
    knl_securec_check(err);
    if (ctrlfiles->count > 1) {
        for (i = 0; i < ctrlfiles->count - 1; i++) {
            err = strcat_sp(value, GS_MAX_CONFIG_LINE_SIZE, ctrlfiles->items[i].name);
            knl_securec_check(err);
            err = strcat_sp(value, GS_MAX_CONFIG_LINE_SIZE, ", ");
            knl_securec_check(err);
        }
    }
    err = strcat_sp(value, GS_MAX_CONFIG_LINE_SIZE, ctrlfiles->items[ctrlfiles->count - 1].name);
    knl_securec_check(err);
    err = strcat_sp(value, GS_MAX_CONFIG_LINE_SIZE, ")");
    knl_securec_check(err);

    if (cm_alter_config(config, "CONTROL_FILES", value, CONFIG_SCOPE_BOTH, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_update_ctrl_logfile_name(knl_session_t *session)
{
    knl_attr_t *attr = &session->kernel->attr;
    knl_instance_t *kernel = session->kernel;
    log_file_ctrl_t *logfile = NULL;
    uint32 i;

    if (!attr->log_file_convert.is_convert) {
        return GS_SUCCESS;
    }

    for (i = 0; i < kernel->db.ctrl.core.log_hwm; i++) {
        logfile = kernel->db.logfiles.items[i].ctrl;
        if (LOG_IS_DROPPED(logfile->flg)) {
            continue;
        }
        if (db_change_storage_path(&attr->log_file_convert, logfile->name, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_update_ctrl_datafile_name(knl_session_t *session)
{
    knl_attr_t *attr = &session->kernel->attr;
    knl_instance_t *kernel = session->kernel;
    datafile_ctrl_t *datafile = NULL;
    uint32 i;

    if (!attr->data_file_convert.is_convert) {
        return GS_SUCCESS;
    }

    for (i = 0; i < GS_MAX_DATA_FILES; i++) {
        datafile = kernel->db.datafiles[i].ctrl;
        if (!datafile->used) {
            continue;
        }
        if (db_change_storage_path(&attr->data_file_convert, datafile->name, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_update_storage_filename(knl_session_t *session)
{
    if (db_update_ctrl_logfile_name(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_ctrl_datafile_name(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void db_update_sysdata_version(knl_session_t *session)
{
    database_t *db = &session->kernel->db;
    rd_update_sysdata_t redo;

    redo.op_type = RD_UPDATE_SYSDATA_VERSION;
    redo.sysdata_version = CORE_SYSDATA_VERSION;

    GS_LOG_RUN_INF("[UPGRADE] system data version is update from %u to %u",
        db->ctrl.core.sysdata_version, CORE_SYSDATA_VERSION);
    db->ctrl.core.sysdata_version = CORE_SYSDATA_VERSION;
    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[UPGRADE] ABORT INFO: update system data version failed when perform upgrade");
    }

    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_update_sysdata_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);
}

void rd_update_sysdata_version(knl_session_t *session, log_entry_t *log)
{
    database_t *db = &session->kernel->db;
    rd_update_sysdata_t *redo = (rd_update_sysdata_t *)log->data;

    if (redo->sysdata_version != CORE_SYSDATA_VERSION) {
        CM_ABORT(0, "[UPGRADE] ABORT INFO: the system data's binary version is different between primary and standby");
    }
    GS_LOG_RUN_INF("[UPGRADE] system data version is update from %u to %u",
        db->ctrl.core.sysdata_version, CORE_SYSDATA_VERSION);
    db->ctrl.core.sysdata_version = CORE_SYSDATA_VERSION;
    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[UPGRADE] ABORT INFO: update system data version failed when perform upgrade");
    }
}

void print_update_sysdata_version(log_entry_t *log)
{
    rd_update_sysdata_t *redo = (rd_update_sysdata_t *)log->data;
    printf("update sysdata version:%u\n", redo->sysdata_version);
}

bool32 db_sysdata_version_is_equal(knl_session_t *session, bool32 is_upgrade)
{
    database_t *db = &session->kernel->db;
    knl_attr_t *attr = &session->kernel->attr;

    if (is_upgrade || !attr->check_sysdata_version) {
        return GS_TRUE;
    }
    if (db->ctrl.core.sysdata_version != CORE_SYSDATA_VERSION) {
        GS_LOG_RUN_ERR("[CTRL] the system data's version is different between binary and ctrl file");
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ": the system data's version is different between binary and ctrl file");
        return GS_FALSE;
    }

    return GS_TRUE;
}

#ifdef __cplusplus
}
#endif
