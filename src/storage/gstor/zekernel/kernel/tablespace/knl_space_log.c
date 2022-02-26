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
 * knl_space_log.c
 *    kernel space redo
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/tablespace/knl_space_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_space_log.h"
#include "cm_file.h"
#include "knl_context.h"
#include "knl_ctrl_restore.h"

#ifdef __cplusplus
extern "C" {
#endif


void rd_spc_create_space(knl_session_t *session, log_entry_t *log)
{
    rd_create_space_t *redo = (rd_create_space_t *)log->data;
    space_t *space = SPACE_GET(redo->space_id);
    database_t *db = &session->kernel->db;
    uint32 name_len = GS_NAME_BUFFER_SIZE - 1;
    errno_t ret;

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_latch_x(&session->kernel->db.ddl_latch, session->id, NULL);
    }
    if (space->ctrl->used) {
        knl_panic(db->ctrl.core.space_count > 0);
        GS_LOG_RUN_WAR("trying to redo create tablespace %s", redo->name);
        db->ctrl.core.space_count--;
    }

    // In standby or crash recovery, set the space to online status directly.
    space->lock = 0;
    space->ctrl->id = redo->space_id;
    space->ctrl->flag = redo->flags;
    space->ctrl->extent_size = redo->extent_size;
    space->ctrl->block_size = redo->block_size;
    space->ctrl->org_scn = redo->org_scn;
    space->ctrl->encrypt_version = redo->encrypt_version;
    space->ctrl->cipher_reserve_size = redo->cipher_reserve_size;
    space->is_empty = GS_FALSE;
    space->allow_extend = GS_TRUE;

    // to be compatible previous version which do not have 'type' in rd_create_space_t
    if (log->size == (uint16)(sizeof(rd_create_space_t) + LOG_ENTRY_SIZE)) {
        space->ctrl->type = redo->type;
    } else {
        space->ctrl->type = 0;
    }

    if (SPACE_IS_ENCRYPT(space)) {
        if (spc_active_undo_encrypt(session, DB_CORE_CTRL(session)->undo_space) != GS_SUCCESS) {
            knl_panic_log(GS_FALSE, "fail to active undo encrypt");
        }
        if (spc_active_undo_encrypt(session, DB_CORE_CTRL(session)->temp_undo_space) != GS_SUCCESS) {
            knl_panic_log(GS_FALSE, "fail to active undo encrypt");
        }
        if (spc_active_swap_encrypt(session) != GS_SUCCESS) {
            knl_panic_log(GS_FALSE, "fail to active swap encrypt");
        }
    }

    ret = strncpy_s(space->ctrl->name, GS_NAME_BUFFER_SIZE, redo->name, name_len);
    knl_securec_check(ret);
    space->ctrl->file_hwm = 0;

    ret = memset_s(space->ctrl->files, GS_MAX_SPACE_FILES * sizeof(uint32), 0xFF, GS_MAX_SPACE_FILES * sizeof(uint32));
    knl_securec_check(ret);

    space->ctrl->used = GS_TRUE;
    db->ctrl.core.space_count++;

    SPACE_SET_ONLINE(space);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when create tablespace");
    }
#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_unlatch(&session->kernel->db.ddl_latch, NULL);
    }
}

void print_spc_create_space(log_entry_t *log)
{
    rd_create_space_t *redo = (rd_create_space_t *)log->data;
    (void)printf("name %s, id %u, flag %u, extent_size %u, block_size %u",
           redo->name, redo->space_id, redo->flags, redo->extent_size, redo->block_size);
    if (log->size == (uint16)(sizeof(rd_create_space_t) + LOG_ENTRY_SIZE)) {
        (void)printf(", type 0x%x", log->type);
    }
    (void)printf("\n");
}

void print_spc_remove_space(log_entry_t *log)
{
    rd_remove_space_t *redo = (rd_remove_space_t *)log->data;
    (void)printf("id %u, options %u\n,", redo->space_id, redo->options);
}

void rd_spc_remove_space(knl_session_t *session, log_entry_t *log)
{
    rd_remove_space_t *redo = (rd_remove_space_t *)log->data;
    uint32 space_id = redo->space_id;
    space_t *space = SPACE_GET(space_id);
    database_t *db = &session->kernel->db;

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_latch_x(&session->kernel->db.ddl_latch, session->id, NULL);
    }
    if (!space->ctrl->used) {
        GS_LOG_RUN_WAR("trying to redo remove space.");
        db->ctrl.core.space_count++;
    }

    if (session->kernel->db.status == DB_STATUS_OPEN) {
        if (spc_check_object_exist(session, space) != GS_SUCCESS) {
#ifdef LOG_DIAG
            if (!session->log_diag) {
#else
            {
#endif
                cm_unlatch(&session->kernel->db.ddl_latch, NULL);
            }
            GS_LOG_RUN_ERR("[SPACE] failed to check if object exist");
            return;
        }
    }

    knl_panic(db->ctrl.core.space_count > 0);

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    spc_wait_data_buffer(session, space);

    (void)spc_remove_space(session, space, redo->options, GS_TRUE);

    (void)spc_try_inactive_swap_encrypt(session);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }
#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_unlatch(&session->kernel->db.ddl_latch, NULL);
    }
}

void rd_spc_create_datafile(knl_session_t *session, log_entry_t *log)
{
    rd_create_datafile_t *redo = (rd_create_datafile_t *)log->data;
    space_t *space = SPACE_GET(redo->space_id);
    datafile_t *df = DATAFILE_GET(redo->id);
    database_t *db = &session->kernel->db;
    knl_attr_t *attr = &session->kernel->attr;
    uint32 name_len = GS_FILE_NAME_BUFFER_SIZE - 1;
    page_id_t space_head;
    errno_t ret;
    bool32 need_rename = GS_FALSE;
    char old_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    /* Only replay one page when page is repairing, we need init page to zero and do not operate datafile */
    if (IS_BLOCK_RECOVER(session)) {
        abr_clear_page(session, redo->id);
        return;
    }

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_latch_x(&session->kernel->db.ddl_latch, session->id, NULL);
    }
    if (df->ctrl->used) {
        knl_panic(db->ctrl.core.device_count > 0);
        GS_LOG_RUN_WAR("trying to redo create datafile %s", redo->name);
        db->ctrl.core.device_count--;

        /* expire space head in buffer */
        if (redo->file_no == 0) {
            space_head.file = redo->id;
            space_head.page = SPACE_ENTRY_PAGE;
            space_head.aligned = 0;
            buf_expire_page(session, space_head);
        }

        /* expire map head of datafile in bitmap space */
        if (SPACE_IS_BITMAPMANAGED(space)) {
            buf_expire_page(session, df->map_head_entry);
        }
    }

    if (!space->ctrl->used) {
#ifdef LOG_DIAG
        if (!session->log_diag) {
#else
        {
#endif
            cm_unlatch(&session->kernel->db.ddl_latch, NULL);
        }
        return;
    }

    df->space_id = redo->space_id;
    df->file_no = redo->file_no;
    df->ctrl->size = (int64)redo->size;
    df->ctrl->block_size = space->ctrl->block_size;
    knl_panic(df->ctrl->block_size != 0);

    df->ctrl->id = redo->id;

    df->ctrl->auto_extend_size = redo->auto_extend_size;
    df->ctrl->auto_extend_maxsize = redo->auto_extend_maxsize;
    df->ctrl->type = redo->type;

    if (db_change_storage_path(&attr->data_file_convert, redo->name, GS_FILE_NAME_BUFFER_SIZE) != GS_SUCCESS) {
#ifdef LOG_DIAG
        if (!session->log_diag) {
#else
        {
#endif
            cm_unlatch(&session->kernel->db.ddl_latch, NULL);
        }
        return;
    }

    if (df->ctrl->used) {
        text_t ctrl_name_text;
        text_t redo_name_text;
        cm_str2text(redo->name, &redo_name_text);
        cm_str2text(df->ctrl->name, &ctrl_name_text);
        if (!cm_text_equal(&redo_name_text, &ctrl_name_text) && cm_file_exist(df->ctrl->name)) {
            need_rename = GS_TRUE;
            ret = strncpy_s(old_name, GS_FILE_NAME_BUFFER_SIZE, df->ctrl->name, name_len);
            knl_securec_check(ret);
        }
    }

    ret = strncpy_s(df->ctrl->name, GS_FILE_NAME_BUFFER_SIZE, redo->name, name_len);
    knl_securec_check(ret);

    if (cm_file_exist(df->ctrl->name) || cm_file_exist(old_name)) {
        if (need_rename) {
            knl_panic_log(!cm_file_exist(df->ctrl->name),
                "new file %s should not exist, old file %s already exists", df->ctrl->name, old_name);
            if (cm_rename_device(df->ctrl->type, old_name, df->ctrl->name) != GS_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to rename datafile from %s to %s", old_name, df->ctrl->name);
            }
            GS_LOG_RUN_INF("succeed to rename datafile from %s to %s", old_name, df->ctrl->name);
        }
        if (spc_open_datafile(session, df, DATAFILE_FD(df->ctrl->id)) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: datafile %s break down, try to offline it in MOUNT mode", df->ctrl->name);
        }

        if (cm_truncate_file(*(DATAFILE_FD(df->ctrl->id)), 0) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to truncate datafile %s", df->ctrl->name);
        }

        if (cm_extend_device(df->ctrl->type, *(DATAFILE_FD(df->ctrl->id)), session->kernel->attr.xpurpose_buf,
            GS_XPURPOSE_BUFFER_SIZE, (int64)redo->size, session->kernel->attr.build_datafile_prealloc) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to rebuild datafile %s", df->ctrl->name);
        }

        if (db_fsync_file(session, *(DATAFILE_FD(df->ctrl->id))) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to fsync datafile %s", df->ctrl->name);
        }
    } else {
        if (GS_SUCCESS != spc_build_datafile(session, df, DATAFILE_FD(df->ctrl->id))) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to build datafile %s", df->ctrl->name);
        }
        df->ctrl->create_version++;

        if (spc_open_datafile(session, df, DATAFILE_FD(df->ctrl->id)) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: datafile %s break down, try to offline it in MOUNT mode", df->ctrl->name);
        }
    }

    if (spc_init_datafile_head(session, df) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file for datafile %s", df->ctrl->name);
    }

    space->ctrl->files[df->file_no] = df->ctrl->id;
    if (df->file_no == 0) {
        space->entry.file = df->ctrl->id;
        space->entry.page = SPACE_ENTRY_PAGE;
    }

    if (df->file_no >= space->ctrl->file_hwm) {
        space->ctrl->file_hwm++;
    }

    df->ctrl->flag = redo->flags;
    df->ctrl->used = GS_TRUE;
    DATAFILE_SET_ONLINE(df);

    db->ctrl.core.device_count++;

    if (GS_SUCCESS != db_save_datafile_ctrl(session, df->ctrl->id)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }

    if (GS_SUCCESS != db_save_space_ctrl(session, space->ctrl->id)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }

    /* backup sapce ctrl info after datafile is created */
    if (db->ctrl.core.db_role != REPL_ROLE_PRIMARY) {
        if (ctrl_backup_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to backup space ctrl info");
        }
    }

    if (IS_SWAP_SPACE(space)) {
        space->head->datafile_count++;
        spc_init_swap_space(session, space);
    }

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_unlatch(&session->kernel->db.ddl_latch, NULL);
    }
}

void print_spc_create_datafile(log_entry_t *log)
{
    rd_create_datafile_t *redo = (rd_create_datafile_t *)log->data;
    (void)printf("name %s, id %u, space_id %u, file_no %u, size %llu, auto_extend %u, "
           "auto_extend_size %lld, max_extend_size %lld\n",
           redo->name, redo->id, redo->space_id, redo->file_no, redo->size,
           (redo->flags & DATAFILE_FLAG_AUTO_EXTEND), redo->auto_extend_size, redo->auto_extend_maxsize);
}

void rd_spc_extend_undo_segments(knl_session_t *session, log_entry_t *log)
{
    rd_extend_undo_segments_t *redo = (rd_extend_undo_segments_t *)log->data;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    char seg_count[GS_MAX_UINT32_STRLEN] = { 0 };
    errno_t ret;

    if (redo->undo_segments <= core_ctrl->undo_segments) {
        return;
    }

    if (!DB_IS_PRIMARY(&session->kernel->db)) {
        undo_init_impl(session, redo->old_undo_segments, redo->undo_segments);
        if (tx_area_init_impl(session, redo->old_undo_segments, redo->undo_segments, GS_TRUE) != GS_SUCCESS) {
            uint16 extend_cnt = redo->undo_segments - redo->old_undo_segments;
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to allocate memory for extend %u undo segments", extend_cnt);
        }
        tx_area_release_impl(session, redo->old_undo_segments, redo->undo_segments);
        ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    }

    core_ctrl->undo_segments = redo->undo_segments;
    core_ctrl->undo_segments_extended = GS_TRUE;

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }

    ret = sprintf_s(seg_count, GS_MAX_UINT32_STRLEN, "%d", redo->undo_segments);
    knl_securec_check_ss(ret);
    UNDO_SEGMENT_COUNT = redo->undo_segments;
    if (cm_alter_config(session->kernel->attr.config, "_UNDO_SEGMENTS", seg_count, CONFIG_SCOPE_BOTH, GS_TRUE) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save config");
    }

    GS_LOG_RUN_INF("[SPACE LOG] replay extend undo segments from %u to %u completed", redo->old_undo_segments, redo->undo_segments);
}

void print_spc_extend_undo_segments(log_entry_t *log)
{
    rd_extend_undo_segments_t *redo = (rd_extend_undo_segments_t *)log->data;
    (void)printf("extend undo segments from %u to %u\n", redo->old_undo_segments, redo->undo_segments);
}

void rd_ckpt_trigger(knl_session_t *session, bool32 wait, ckpt_mode_t mode)
{
    page_id_t page_id = session->curr_page_ctrl->page_id;
    uint8 options = session->curr_page_ctrl->is_resident ? ENTER_PAGE_RESIDENT : ENTER_PAGE_NORMAL;

    buf_leave_page(session, GS_FALSE);

    ckpt_trigger(session, wait, mode);

    buf_enter_page(session, page_id, LATCH_MODE_X, options);
}

void rd_spc_remove_datafile(knl_session_t *session, log_entry_t *log)
{
    rd_remove_datafile_t *redo = (rd_remove_datafile_t *)log->data;
    space_t *space = SPACE_GET(redo->space_id);
    space_head_t *head = SPACE_HEAD;
    datafile_t *df = DATAFILE_GET(redo->id);
    database_t *db = &session->kernel->db;

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        rd_ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    }

    /* Only replay one page when page is repairing, we need init page to zero and do not operate datafile */
    if (IS_BLOCK_RECOVER(session)) {
        abr_clear_page(session, redo->id);
        return;
    }

    if (IS_SWAP_SPACE(space)) {
        if (space->ctrl->files[redo->file_no] != GS_INVALID_ID32) {
            head->datafile_count--;
            head->hwms[redo->file_no] = 0;
        }
    } else {
        head->datafile_count--;
        head->hwms[redo->file_no] = 0;
    }

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        cm_latch_x(&session->kernel->db.ddl_latch, session->id, NULL);

        ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

        if (space->ctrl->files[redo->file_no] != GS_INVALID_ID32) {
            space->ctrl->files[redo->file_no] = GS_INVALID_ID32;
            db->ctrl.core.device_count--;
        }

        if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole space control file when rd_remove datafile");
        }

        DATAFILE_UNSET_ONLINE(df);
        df->ctrl->used = GS_FALSE;
        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save datafile control file when offline datafile");
        }

        spc_remove_datafile_device(session, df);

        df->space_id = GS_INVALID_ID32;
        df->ctrl->size = 0;
        df->ctrl->name[0] = '\0';
    }

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when rd_remove datafile");
        }

        cm_unlatch(&session->kernel->db.ddl_latch, NULL);
    }
}

void print_spc_remove_datafile(log_entry_t *log)
{
    rd_remove_datafile_t *redo = (rd_remove_datafile_t *)log->data;
    (void)printf("id %u, space_id %u, file_no %u\n", redo->id, redo->space_id, redo->file_no);
}

void rd_spc_update_head(knl_session_t *session, log_entry_t *log)
{
    rd_update_head_t *redo = (rd_update_head_t *)log->data;
    space_t *space = SPACE_GET(redo->space_id);
    space_head_t *head = (space_head_t *)(CURR_PAGE + PAGE_HEAD_SIZE);
    errno_t ret;

    if (0 == redo->file_no) {
#ifdef LOG_DIAG
        if (!session->log_diag) {
#else
        {
#endif
            session->curr_page_ctrl->is_resident = 1;
            space->head = head;
        }
        page_init(session, (page_head_t *)CURR_PAGE, redo->entry, PAGE_TYPE_SPACE_HEAD);
        ret = memset_sp(head, sizeof(space_head_t), 0, sizeof(space_head_t));
        knl_securec_check(ret);
        head->free_extents.first = INVALID_PAGID;
        head->free_extents.last = INVALID_PAGID;
        spc_try_init_punch_head(session, space);
    }

    head->hwms[redo->file_no] = spc_get_hwm_start(session, space, DATAFILE_GET(space->ctrl->files[redo->file_no]));
    head->datafile_count++;

    if (IS_BLOCK_RECOVER(session)) {
        return; // do not modify ctrl files when repair page use ztrst tool
    }

    if (GS_SUCCESS != db_save_space_ctrl(session, space->ctrl->id)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }
}

void print_spc_update_head(log_entry_t *log)
{
    rd_update_head_t *redo = (rd_update_head_t *)log->data;
    (void)printf("head %u-%u, space_id %u, file_no %u\n",
           (uint32)redo->entry.file, (uint32)redo->entry.page, (uint32)redo->space_id, (uint32)redo->file_no);
}

void rd_spc_change_segment(knl_session_t *session, log_entry_t *log)
{
    uint32 count = *(uint32 *)log->data;
    space_head_t *head = (space_head_t *)(CURR_PAGE + PAGE_HEAD_SIZE);
    head->segment_count = count;
}

void print_spc_change_segment(log_entry_t *log)
{
    uint32 count = *(uint32 *)log->data;
    (void)printf("count %u\n", count);
}

void rd_spc_update_hwm(knl_session_t *session, log_entry_t *log)
{
    rd_update_hwm_t *redo = (rd_update_hwm_t *)log->data;
    space_head_t *head = (space_head_t *)(CURR_PAGE + PAGE_HEAD_SIZE);
    head->hwms[redo->file_no] = redo->file_hwm;
}

void print_spc_update_hwm(log_entry_t *log)
{
    rd_update_hwm_t *redo = (rd_update_hwm_t *)log->data;
    (void)printf("file_no %u, file_hwm %u\n", redo->file_no, redo->file_hwm);
}

void rd_spc_alloc_extent(knl_session_t *session, log_entry_t *log)
{
    page_list_t *extents = (page_list_t *)log->data;
    space_head_t *head = (space_head_t *)(CURR_PAGE + PAGE_HEAD_SIZE);

    head->free_extents = *extents;
}

void print_spc_alloc_extent(log_entry_t *log)
{
    page_list_t *extents = (page_list_t *)log->data;
    (void)printf("count %u, first %u-%u, last %u-%u\n", extents->count,
           (uint32)extents->first.file, (uint32)extents->first.page,
           (uint32)extents->last.file, (uint32)extents->last.page);
}

void rd_spc_free_extent(knl_session_t *session, log_entry_t *log)
{
    page_list_t *extents = (page_list_t *)log->data;
    space_head_t *head = (space_head_t *)(CURR_PAGE + PAGE_HEAD_SIZE);

    head->free_extents = *extents;
}

void print_spc_free_extent(log_entry_t *log)
{
    page_list_t *extents = (page_list_t *)log->data;
    (void)printf("count %u, first %u-%u, last %u-%u\n", extents->count,
           (uint32)extents->first.file, (uint32)extents->first.page,
           (uint32)extents->last.file, (uint32)extents->last.page);
}

void rd_spc_set_autoextend(knl_session_t *session, log_entry_t *log)
{
    rd_set_space_autoextend_t *redo = (rd_set_space_autoextend_t *)log->data;
    space_t *space = SPACE_GET((uint32)redo->space_id);
    datafile_t *df = NULL;

    if (!space->ctrl->used) {
        return;
    }

    for (uint32 i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[i]);
        if (redo->auto_extend) {
            DATAFILE_SET_AUTO_EXTEND(df);
        } else {
            DATAFILE_UNSET_AUTO_EXTEND(df);
        }
        df->ctrl->auto_extend_size = redo->auto_extend_size;
        df->ctrl->auto_extend_maxsize = redo->auto_extend_maxsize;

        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole ctrl files");
        }
    }
}

void print_spc_set_autoextend(log_entry_t *log)
{
    rd_set_space_autoextend_t *rd = (rd_set_space_autoextend_t *)log->data;
    (void)printf("spc get autoextend space_id:%d,auto_extend:%d,next size:%llu,max size:%llu\n",
           rd->space_id, rd->auto_extend, rd->auto_extend_size, rd->auto_extend_maxsize);
}

void rd_spc_set_flag(knl_session_t *session, log_entry_t *log)
{
    rd_set_space_flag_t *redo = (rd_set_space_flag_t *)log->data;
    space_t *space = SPACE_GET((uint32)redo->space_id);

    if (!space->ctrl->used) {
        return;
    }

    space->ctrl->flag = redo->flags;

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole ctrl files");
    }
}

void print_spc_set_flag(log_entry_t *log)
{
    rd_set_space_flag_t *rd = (rd_set_space_flag_t *)log->data;
    (void)printf("spc set flag space_id:%u, flag %u\n", rd->space_id, (uint32)rd->flags);
}

void rd_spc_rename_space(knl_session_t *session, log_entry_t *log)
{
    rd_rename_space_t *redo = (rd_rename_space_t *)log->data;
    space_t *space = SPACE_GET(redo->space_id);
    uint32 name_len = GS_NAME_BUFFER_SIZE - 1;
    errno_t ret;

    if (!space->ctrl->used) {
        return;
    }

    ret = strncpy_s(space->ctrl->name, GS_NAME_BUFFER_SIZE, redo->name, name_len);
    knl_securec_check(ret);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole ctrl files");
    }
}

void rd_spc_shrink_ckpt(knl_session_t *session, log_entry_t *log)
{
    rd_shrink_space_t *redo = (rd_shrink_space_t *)log->data;
    space_t *space = SPACE_GET(redo->space_id);

    if (!space->ctrl->used) {
        return;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
}

void print_spc_rename_space(log_entry_t *log)
{
    rd_rename_space_t *rd = (rd_rename_space_t *)log->data;
    (void)printf("spc rename space space_id:%d,name:%s\n", rd->space_id, rd->name);
}

void print_spc_shrink_ckpt(log_entry_t *log)
{
    rd_shrink_space_t *rd = (rd_shrink_space_t *)log->data;
    (void)printf("spc shrink space space_id:%d checkpoint\n", rd->space_id);
}

void rd_spc_concat_extent(knl_session_t *session, log_entry_t *log)
{
    page_id_t page_id = *(page_id_t *)log->data;
    page_head_t *page_head = (page_head_t *)CURR_PAGE;
    TO_PAGID_DATA(page_id, page_head->next_ext);
}

void print_spc_concat_extent(log_entry_t *log)
{
    page_id_t page_id = *(page_id_t *)log->data;
    (void)printf("next %u-%u\n", (uint32)page_id.file, (uint32)page_id.page);
}

void rd_spc_free_page(knl_session_t *session, log_entry_t *log)
{
    page_head_t *page_head = (page_head_t *)CURR_PAGE;
    page_free(session, page_head);
    buf_unreside(session, session->curr_page_ctrl);
}

void print_spc_free_page(log_entry_t *log)
{
    page_id_t page_id = *(page_id_t *)log->data;
    (void)printf("page %u-%u\n", (uint32)page_id.file, (uint32)page_id.page);
}

void rd_spc_extend_datafile(knl_session_t *session, log_entry_t *log)
{
    rd_extend_datafile_t *redo = (rd_extend_datafile_t *)log->data;
    datafile_t *df = DATAFILE_GET(redo->id);
    int32 *handle = DATAFILE_FD(redo->id);
    bool32 need_lock = KNL_GBP_ENABLE(session->kernel);

    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        return;
    }

    if (need_lock) { // concurrency with gbp_aly_spc_extend_datafile in gbp_aly_proc
        cm_spin_lock(&session->kernel->gbp_aly_ctx.extend_lock, NULL);
    }

    if (df->ctrl->size < redo->size) {
        if (*handle == -1) {
            if (spc_open_datafile(session, df, handle) != GS_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to open file %s when extending datafile, error code is %d",
                    df->ctrl->name, errno);
            }
        }

        knl_attr_t *attr = &(session->kernel->attr);
        if (cm_extend_device(df->ctrl->type, *handle, attr->xpurpose_buf, GS_XPURPOSE_BUFFER_SIZE,
            redo->size - df->ctrl->size, attr->build_datafile_prealloc) != GS_SUCCESS) {
            CM_ABORT(0, "[REDO] ABORT INFO: failed to extend datafile %s, error code is %d", df->ctrl->name, errno);
        }

        if (db_fsync_file(session, *handle) != GS_SUCCESS) {
            CM_ABORT(0, "[REDO] ABORT INFO: failed to fsync datafile %s", df->ctrl->name);
        }

        df->ctrl->size = redo->size;

        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[REDO] ABORT INFO: failed to save whole ctrl files");
        }
    }

    if (need_lock) {
        cm_spin_unlock(&session->kernel->gbp_aly_ctx.extend_lock);
    }
}

void gbp_aly_spc_extend_datafile(knl_session_t *session, log_entry_t *log, uint64 lsn)
{
    if (KNL_GBP_SAFE(session->kernel)) {
        rd_spc_extend_datafile(session, log);
    } else {
        gbp_aly_unsafe_entry(session, log, lsn);
    }
}

void rd_spc_truncate_datafile(knl_session_t *session, log_entry_t *log)
{
    rd_truncate_datafile_t *redo = (rd_truncate_datafile_t *)log->data;
    datafile_t *df = DATAFILE_GET(redo->id);
    int32 *handle = DATAFILE_FD(redo->id);

    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        return;
    }

    if (df->ctrl->size > redo->size) {
        if (*handle == -1) {
            if (spc_open_datafile(session, df, handle) != GS_SUCCESS) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to open file %s when truncate datafile, error code is %d",
                    df->ctrl->name, errno);
            }
        }
        df->ctrl->size = redo->size;

        if (cm_truncate_device(df->ctrl->type, *handle, redo->size) != GS_SUCCESS) {
            CM_ABORT(0, "[REDO] ABORT INFO: failed to truncate datafile %s, error code is %d",
                df->ctrl->name, errno);
        }

        if (db_fsync_file(session, *handle) != GS_SUCCESS) {
            CM_ABORT(0, "[REDO] ABORT INFO: failed to fsync datafile %s", df->ctrl->name);
        }

        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[REDO] ABORT INFO: failed to save whole ctrl files");
        }
    }
}

void print_spc_extend_datafile(log_entry_t *log)
{
    rd_extend_datafile_t *redo = (rd_extend_datafile_t *)log->data;
    (void)printf("id %u, new_size %lld\n", redo->id, redo->size);
}

void print_spc_truncate_datafile(log_entry_t *log)
{
    rd_truncate_datafile_t *redo = (rd_truncate_datafile_t *)log->data;
    (void)printf("id %u, new_size %lld\n", redo->id, redo->size);
}

void rd_spc_change_autoextend(knl_session_t *session, log_entry_t *log)
{
    rd_set_df_autoextend_t *redo = (rd_set_df_autoextend_t *)log->data;
    datafile_t *df = DATAFILE_GET(redo->id);

    if (redo->auto_extend) {
        DATAFILE_SET_AUTO_EXTEND(df);
    } else {
        DATAFILE_UNSET_AUTO_EXTEND(df);
    }
    df->ctrl->auto_extend_size = redo->auto_extend_size;
    df->ctrl->auto_extend_maxsize = redo->auto_extend_maxsize;

    if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file");
    }
}

void rd_df_init_map_head(knl_session_t *session, log_entry_t *log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    datafile_t *df = DATAFILE_GET(page_id->file);
    space_t *space = SPACE_GET(df->space_id);
    df_map_head_t *bitmap_head = (df_map_head_t *)CURR_PAGE;

    page_init(session, (page_head_t *)CURR_PAGE, *page_id, PAGE_TYPE_DF_MAP_HEAD);
    bitmap_head->group_count = 0;
    bitmap_head->bit_unit = space->ctrl->extent_size;

#ifdef LOG_DIAG
    if (!session->log_diag) {
#else
    {
#endif
        session->curr_page_ctrl->is_resident = 1;
        df->map_head = bitmap_head;
        df->map_head_entry = *page_id;
    }
}

void rd_df_add_map_group(knl_session_t *session, log_entry_t *log)
{
    rd_df_add_map_group_t *redo = (rd_df_add_map_group_t *)log->data;
    df_map_head_t *bitmap_head = (df_map_head_t *)CURR_PAGE;
    df_map_group_t *bitmap_group;

    bitmap_group = &bitmap_head->groups[bitmap_head->group_count++];
    bitmap_group->first_map = redo->begin_page;
    bitmap_group->page_count = redo->page_count;
}

void rd_df_init_map_page(knl_session_t *session, log_entry_t *log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    df_map_page_t *bitmap_page = (df_map_page_t *)CURR_PAGE;

    page_init(session, (page_head_t *)CURR_PAGE, session->curr_page_ctrl->page_id, PAGE_TYPE_DF_MAP_DATA);
    bitmap_page->free_begin = 0;
    bitmap_page->free_bits = DF_MAP_BIT_CNT;
    bitmap_page->first_page = *page_id;
}

void rd_df_change_map(knl_session_t *session, log_entry_t *log)
{
    df_map_page_t *bitmap_page = (df_map_page_t *)CURR_PAGE;
    rd_df_change_map_t *redo = (rd_df_change_map_t *)log->data;

    if (redo->is_set == GS_TRUE) {
        df_set_bitmap(bitmap_page->bitmap, redo->start, redo->size);

        bitmap_page->free_bits -= redo->size;
        if (bitmap_page->free_begin == redo->start) {
            bitmap_page->free_begin += redo->size;
        }
    } else {
        df_unset_bitmap(bitmap_page->bitmap, redo->start, redo->size);
        bitmap_page->free_bits += redo->size;
        if (redo->start < bitmap_page->free_begin) {
            bitmap_page->free_begin = redo->start;
        }
    }
}

void print_df_init_map_head(log_entry_t * log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    (void)printf("page %u-%u\n", (uint32)page_id->file, (uint32)page_id->page);
}

void print_df_add_map_group(log_entry_t * log)
{
    rd_df_add_map_group_t *redo = (rd_df_add_map_group_t *)log->data;
    (void)printf("begin page %u-%u, page count %u\n", (uint32)redo->begin_page.file,
        (uint32)redo->begin_page.page, redo->page_count);
}

void print_df_init_map_page(log_entry_t * log)
{
    page_id_t *page_id = (page_id_t *)log->data;
    (void)printf("page %u-%u\n", (uint32)page_id->file, (uint32)page_id->page);
}

void print_df_change_map(log_entry_t * log)
{
    rd_df_change_map_t *redo = (rd_df_change_map_t *)log->data;
    (void)printf("start %u, size %u, is_set %u\n", redo->start, redo->size, redo->is_set);
}

void rd_spc_set_ext_size(knl_session_t *session, log_entry_t *log)
{
    page_head_t *page_head = (page_head_t *)CURR_PAGE;
    uint16 *extent_size = (uint16 *)log->data;

    page_head->ext_size = spc_ext_id_by_size(*extent_size);
}

void print_spc_change_autoextend(log_entry_t *log)
{
    rd_set_df_autoextend_t *redo = (rd_set_df_autoextend_t *)log->data;
    (void)printf("id %u, auto_extend %d, auto_extend_size %llu, auto_extend_maxsize %llu \n",
        redo->id, redo->auto_extend, redo->auto_extend_size, redo->auto_extend_maxsize);
}

void rd_spc_punch_format_page(knl_session_t *session, log_entry_t *log)
{
    rd_punch_page_t *id = (rd_punch_page_t *)log->data;
    page_head_t *page = (page_head_t *)CURR_PAGE;

    TO_PAGID_DATA(id->page_id, page->id);
    page->type = PAGE_TYPE_PUNCH_PAGE;
    page->size_units = page_size_units(DEFAULT_PAGE_SIZE);
    page->pcn = 0;
    page_tail_t *tail = PAGE_TAIL(page);
    tail->checksum = 0;
    tail->pcn = 0;

    spc_set_datafile_ctrl_punched(session, id->page_id.file);
}

void print_spc_punch_format_hole(log_entry_t *log)
{
    page_id_t *page = (page_id_t *)log->data;
    (void)printf("spc punch hole page:%u-%u, \n", page->file, page->page);
}

bool32 rd_log_is_format_page(uint8 type)
{
    switch (type) {
        case RD_HEAP_FORMAT_PAGE:
        case RD_HEAP_FORMAT_MAP:
        case RD_HEAP_FORMAT_ENTRY:
        case RD_BTREE_FORMAT_PAGE:
        case RD_BTREE_INIT_ENTRY:
        case RD_SPC_UPDATE_HEAD:
        case RD_SPC_INIT_MAP_HEAD:
        case RD_SPC_INIT_MAP_PAGE:
        case RD_SPC_CREATE_DATAFILE:
        case RD_UNDO_CREATE_SEGMENT:
        case RD_UNDO_FORMAT_TXN:
        case RD_UNDO_FORMAT_PAGE:
        case RD_LOB_PAGE_INIT:
        case RD_LOB_PAGE_EXT_INIT:
        case RD_LOGIC_OPERATION:
        case RD_PUNCH_FORMAT_PAGE:
            return GS_TRUE;
        default:
            return GS_FALSE;
    }

    return GS_FALSE;
}

/* some redo type is to format page, we need to verify format normally and punch page */
bool32 rd_check_punch_entry(knl_session_t *session, log_entry_t *log)
{
    database_t *db = &session->kernel->db;

    if (RD_TYPE_IS_ENTER_PAGE(log->type) || RD_TYPE_IS_LEAVE_PAGE(log->type) || session->page_stack.depth == 0) {
        return GS_FALSE;
    }

    if (SECUREC_UNLIKELY(db->ctrl.core.shutdown_consistency) && DB_IS_PRIMARY(db)) {
        return GS_FALSE;
    }

    page_id_t *page_id = NULL;
    if (session->kernel->backup_ctx.block_repairing) {
        page_id = session->kernel->rcy_ctx.abr_ctrl == NULL ? NULL : &session->kernel->rcy_ctx.abr_ctrl->page_id;
    } else {
        page_id = session->curr_page_ctrl == NULL ? NULL : &session->curr_page_ctrl->page_id;
    }
    
    if (page_id == NULL) {
        return GS_FALSE;
    }

    page_head_t *page = (page_head_t *)CURR_PAGE;
    datafile_t *df = DATAFILE_GET(page_id->file);
    
    if (!df->ctrl->punched || page->size_units != 0) {
        return GS_FALSE;
    }
    
    if (rd_log_is_format_page(log->type)) {
        return GS_FALSE;
    }

    session->page_stack.is_skip[session->page_stack.depth - 1] = GS_TRUE;
    return GS_TRUE;
}

void rd_spc_punch_extents(knl_session_t *session, log_entry_t *log)
{
    rd_punch_extents_t *rd = (rd_punch_extents_t*)log->data;
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD;

    punch_head->punching_exts = rd->punching_exts;
    punch_head->punched_exts = rd->punched_exts;

}

void print_spc_punch_extents(log_entry_t *log)
{
    rd_punch_extents_t *rd = (rd_punch_extents_t *)log->data;
    page_list_t *punching = &rd->punching_exts;
    page_list_t *punched = &rd->punched_exts;
    (void)printf("punching extent: count %u, first %u-%u, last %u-%u \n."
        " punched extent: count %u, first %u-%u, last %u-%u \n.",
        punching->count, (uint32)punching->first.file, (uint32)punching->first.page,
        (uint32)punching->last.file, (uint32)punching->last.page,
        punched->count, (uint32)punched->first.file, (uint32)punched->first.page,
        (uint32)punched->last.file, (uint32)punched->last.page);
}

#ifdef __cplusplus
}
#endif

