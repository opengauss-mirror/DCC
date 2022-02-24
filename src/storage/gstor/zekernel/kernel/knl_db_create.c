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
 * knl_db_create.c
 *    implement of database
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/knl_db_create.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_db_create.h"
#include "knl_database.h"
#include "knl_context.h"
#include "knl_user.h"
#include "knl_ctlg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dbname_time {
    char name[GS_DB_NAME_LEN];
    date_t time;
} dbname_time_t;

static void dbc_init_archivelog(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    db->ctrl.core.log_mode = def->arch_mode;
}

static void dbc_init_dbid(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    (void)cm_text2str(&def->name, db->ctrl.core.name, GS_DB_NAME_LEN);
    db->ctrl.core.dbid = dbc_generate_dbid(session);
}

static void dbc_init_scn(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    timeval_t now;

    (void)cm_gettimeofday(&now);
    db->ctrl.core.init_time = now.tv_sec;

    KNL_SET_SCN(&session->kernel->scn, 0);
}

static status_t dbc_save_sys_password(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    char *alg = kernel->attr.pwd_alg;
    char *sys_pwd = kernel->attr.sys_pwd;
    errno_t ret;

    if (strlen(def->sys_password) != 0) {
        if (user_encrypt_password(alg, kernel->attr.alg_iter, def->sys_password, (uint32)strlen(def->sys_password),
            sys_pwd, GS_PASSWORD_BUFFER_SIZE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        ret = memset_sp(def->sys_password, GS_PASSWORD_BUFFER_SIZE, 0, GS_PASSWORD_BUFFER_SIZE);
        knl_securec_check(ret);
        return GS_SUCCESS;
    }

    return GS_SUCCESS;
}

static status_t dbc_save_charset(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    uint16 charset_id;

    if (def->charset.len == 0) {
        kernel->db.ctrl.core.charset_id = CHARSET_UTF8; // default UTF8
        return GS_SUCCESS;
    }
    charset_id = cm_get_charset_id_ex(&def->charset);
    if (charset_id == GS_INVALID_ID16) {
        /* not check at 'sql_parse_dbca_charset' */
        GS_LOG_RUN_WAR("[DB] invaid charaset %s, reset to UTF8.", T2S(&def->charset));
        kernel->db.ctrl.core.charset_id = CHARSET_UTF8;
        return GS_SUCCESS;
    }

    kernel->db.ctrl.core.charset_id = (uint32)charset_id;

    return GS_SUCCESS;
}

static void dbc_ctrl_page_init(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    page_tail_t *tail = NULL;
    page_id_t page_id;
    uint32 i;
    page_head_t *page = NULL;

    for (i = 0; i < CTRL_MAX_PAGE; i++) {
        page_id.file = 0;
        page_id.page = 1;
        page = (page_head_t *)(db->ctrl.pages + i);

        TO_PAGID_DATA(page_id, page->id);
        TO_PAGID_DATA(INVALID_PAGID, page->next_ext);
        page->size_units = page_size_units(GS_DFLT_CTRL_BLOCK_SIZE);
        page->type = PAGE_TYPE_CTRL;
        tail = PAGE_TAIL(page);
        tail->pcn = 0;
    }
}

static status_t dbc_build_ctrlfiles(knl_session_t *session, knl_database_def_t *def)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;

    dbc_ctrl_page_init(session);
    db->ctrlfiles.count = def->ctrlfiles.count;
    db->ctrl.core.resetlogs.rst_id = 0;
    db->ctrl.core.undo_segments = kernel->attr.undo_segments;
    db->ctrl.core.undo_segments_extended = GS_FALSE;
    db->ctrl.core.page_size = kernel->attr.page_size;
    db->ctrl.core.max_column_count = kernel->attr.max_column_count;
    db->ctrl.core.version.main = CORE_VERSION_MAIN;
    db->ctrl.core.version.major = CORE_VERSION_MAJOR;
    db->ctrl.core.version.revision = CORE_VERSION_REVISION;
    db->ctrl.core.version.inner = CORE_VERSION_INNER;
    db->ctrl.core.sysdata_version = CORE_SYSDATA_VERSION;

    db_store_core(db);

    for (uint32 i = 0; i < def->ctrlfiles.count; i++) {
        ctrlfile_t *ctrlfile = &db->ctrlfiles.items[i];
        text_t *name = (text_t *)cm_galist_get(&def->ctrlfiles, i);

        (void)cm_text2str(name, ctrlfile->name, GS_FILE_NAME_BUFFER_SIZE);
        ctrlfile->type = DEV_TYPE_FILE;
        ctrlfile->blocks = CTRL_MAX_PAGE;
        ctrlfile->block_size = GS_DFLT_CTRL_BLOCK_SIZE;

        if (cm_build_device(ctrlfile->name, ctrlfile->type, kernel->attr.xpurpose_buf,
            GS_XPURPOSE_BUFFER_SIZE, (int64)ctrlfile->blocks * ctrlfile->block_size,
            knl_io_flag(session), GS_FALSE, &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to build %s ", ctrlfile->name);
            return GS_ERROR;
        }
        /* ctrlfile can be opened for a long time, closed in db_close_ctrl_files */
        if (cm_open_device(ctrlfile->name, ctrlfile->type, knl_io_flag(session), &ctrlfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", ctrlfile->name);
            return GS_ERROR;
        }

        if (cm_write_device(ctrlfile->type, ctrlfile->handle, 0, db->ctrl.pages,
            (int32)ctrlfile->blocks * ctrlfile->block_size) != GS_SUCCESS) {
            cm_close_device(ctrlfile->type, &ctrlfile->handle);
            GS_LOG_RUN_ERR("[DB] failed to write %s ", ctrlfile->name);
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

static status_t dbc_build_logfiles(knl_session_t *session, knl_database_def_t *def)
{
    uint32 i;
    int64 min_size;
    int64 block_num;
    knl_device_def_t *dev_def = NULL;
    log_file_t *logfile = NULL;
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    int64 temp_size = 0;

    db->ctrl.core.log_count = def->logfiles.count;
    db->ctrl.core.log_hwm = def->logfiles.count;
    db->ctrl.core.rcy_point.asn = GS_FIRST_ASN;
    db->ctrl.core.lrp_point.asn = GS_FIRST_ASN;
    db->logfiles.hwm = def->logfiles.count;

    min_size = (int64)LOG_MIN_SIZE(kernel);

    if (DB_IS_RAFT_ENABLED(kernel)) {
        for (i = 0; i < def->logfiles.count; i++) {
            dev_def = (knl_device_def_t *)cm_galist_get(&def->logfiles, i);
            temp_size = (temp_size == 0) ? dev_def->size : temp_size;
            if (dev_def->size != temp_size) {
                GS_THROW_ERROR(ERR_LOG_SIZE_NOT_MATCH);
                return GS_ERROR;
            }
        }
    }

    for (i = 0; i < def->logfiles.count; i++) {
        dev_def = (knl_device_def_t *)cm_galist_get(&def->logfiles, i);
        if (dev_def->size <= min_size) {
            GS_THROW_ERROR(ERR_LOG_FILE_SIZE_TOO_SMALL, min_size);
            return GS_ERROR;
        }

        logfile = &db->logfiles.items[i];
        logfile->ctrl->file_id = (int32)i;
        logfile->ctrl->size = dev_def->size;
        logfile->ctrl->block_size = dev_def->block_size == 0 ? GS_DFLT_LOG_BLOCK_SIZE : (uint16)dev_def->block_size;
        block_num = logfile->ctrl->size / logfile->ctrl->block_size;
        INT32_OVERFLOW_CHECK(block_num);
        (void)cm_text2str(&dev_def->name, logfile->ctrl->name, GS_FILE_NAME_BUFFER_SIZE);
        logfile->ctrl->type = DEV_TYPE_FILE;
        logfile->ctrl->flg = 0;
        logfile->ctrl->archived = GS_FALSE;

        if (cm_build_device(logfile->ctrl->name, logfile->ctrl->type, kernel->attr.xpurpose_buf, 
            GS_XPURPOSE_BUFFER_SIZE, logfile->ctrl->size, knl_redo_io_flag(session),
            GS_FALSE, &logfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to build %s ", logfile->ctrl->name);
            return GS_ERROR;
        }

        logfile->head.first = GS_INVALID_ID64;
        logfile->head.last = GS_INVALID_ID64;
        logfile->head.write_pos = CM_CALC_ALIGN(sizeof(log_file_head_t), logfile->ctrl->block_size);
        logfile->head.block_size = (int32)logfile->ctrl->block_size;
        logfile->head.rst_id = db->ctrl.core.resetlogs.rst_id;
        logfile->head.cmp_algorithm = COMPRESS_NONE;

        if (i == 0) {
            logfile->ctrl->status = LOG_FILE_CURRENT;
            logfile->head.asn = GS_FIRST_ASN;
            db->ctrl.core.rcy_point.block_id = 1;
            db->ctrl.core.lrp_point.block_id = 1;
        } else {
            logfile->head.asn = GS_INVALID_ASN;
            logfile->ctrl->status = LOG_FILE_INACTIVE;
        }

        if (cm_open_device(logfile->ctrl->name, logfile->ctrl->type, knl_redo_io_flag(session),
            &logfile->handle) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to open %s ", logfile->ctrl->name);
            return GS_ERROR;
        }

        log_flush_head(session, logfile);
        cm_close_device(logfile->ctrl->type, &logfile->handle);

        if (db_save_log_ctrl(session, i) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to save ctrl when create logfile : %s ", logfile->ctrl->name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t dbc_init_space(knl_session_t *session, knl_database_def_t *def)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    if (spc_create_space(session, &def->system_space, &core_ctrl->system_space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_create_space(session, &def->swap_space, &core_ctrl->swap_space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    def->undo_space.extent_size = UNDO_EXTENT_SIZE;
    if (spc_create_space(session, &def->undo_space, &core_ctrl->undo_space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (def->user_space.datafiles.count > 0) {
        if (spc_create_space(session, &def->user_space, &core_ctrl->user_space) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (spc_create_space(session, &def->temp_space, &core_ctrl->temp_space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    def->temp_undo_space.extent_size = UNDO_EXTENT_SIZE;
    if (spc_create_space(session, &def->temp_undo_space, &core_ctrl->temp_undo_space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_create_space(session, &def->sysaux_space, &core_ctrl->sysaux_space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void dbc_init_doublewrite(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    space_t *dw_space = &(db->spaces[core_ctrl->sysaux_space]);

    buf_enter_page(session, dw_space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
    db->ctrl.core.dw_file_id = dw_space->ctrl->files[0];
    db->ctrl.core.dw_area_pages = DOUBLE_WRITE_PAGES;

    db->ctrl.core.dw_start = DW_DISTRICT_BEGIN;
    db->ctrl.core.dw_end = DW_DISTRICT_BEGIN;

    dw_space->head->hwms[0] = SPACE_IS_BITMAPMANAGED(dw_space) ? DW_MAP_HWM_START : DW_SPC_HWM_START;
    buf_leave_page(session, GS_TRUE);
}

static status_t dbc_build_sys_table(knl_session_t *session, knl_cursor_t *cursor)
{
    uint32 i;
    table_t *table = NULL;

    for (i = 0; i <= CORE_SYS_TABLE_CEIL; i++) {
        table = db_sys_table(i);

        if (db_write_systable(session, cursor, &table->desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    knl_commit(session);

    return GS_SUCCESS;
}

static status_t dbc_create_sys_segment(knl_session_t *session, uint32 table_id, page_id_t *entry)
{
    table_t *table;

    table = db_sys_table(table_id);
    if (heap_create_segment(session, table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_enter_page(session, table->heap.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
    table->heap.segment = HEAP_SEG_HEAD;
    buf_leave_page(session, GS_FALSE);

    *entry = table->heap.entry;
    return GS_SUCCESS;
}

static status_t dbc_create_sys_segments(knl_session_t *session)
{
    database_t *db = &session->kernel->db;

    if (dbc_create_sys_segment(session, SYS_TABLE_ID, &db->ctrl.core.sys_table_entry) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_create_sys_segment(session, SYS_COLUMN_ID, &db->ctrl.core.sys_column_entry) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_create_sys_segment(session, SYS_INDEX_ID, &db->ctrl.core.sys_index_entry) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_create_sys_segment(session, SYS_USER_ID, &db->ctrl.core.sys_user_entry) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t dbc_build_systables(knl_session_t *session)
{
    knl_cursor_t *cursor = NULL;

    if (dbc_create_sys_segments(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    if (dbc_build_sys_table(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_build_sys_column(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_build_sys_index(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_build_sys_user(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t dbc_save_data_file(knl_session_t *session)
{
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    buf_ctrl_t *next = NULL;

    dbwr_context_t *dbwr = (dbwr_context_t *)cm_push(session->stack, sizeof(dbwr_context_t));
    for (uint32 i = 0; i < GS_MAX_DATA_FILES; i++) {
        dbwr->datafiles[i] = GS_INVALID_HANDLE;
        dbwr->flags[i] = GS_FALSE;
    }

    knl_panic(ctx->queue.count > 0);
    buf_ctrl_t *ctrl = ctx->queue.first;

    while (ctrl != NULL) {
        if (GS_SUCCESS != dbwr_save_page(session, dbwr, ctrl->page)) {
            dbwr_end(dbwr);
            cm_pop(session->stack);
            return GS_ERROR;
        }

        next = ctrl->ckpt_next;
        ctrl->ckpt_prev = NULL;
        ctrl->ckpt_next = NULL;
        ctrl->in_ckpt = GS_FALSE;
        ctrl->is_dirty = 0;
        ctrl = next;
    }

    if (dbwr_fdatasync(session, dbwr) != GS_SUCCESS) {
        dbwr_end(dbwr);
        cm_pop(session->stack);
        return GS_ERROR;
    }

    ctx->queue.count = 0;
    ctx->queue.first = NULL;
    ctx->queue.last = NULL;

    dbwr_end(dbwr);
    cm_pop(session->stack);
    return GS_SUCCESS;
}

/*
 * Description     : save database configuration
 * Input           : kernel: database kernel instance
 * Input           : def : database definition
 * Output          : NA
 * Return Value    : status
 * History         : 1.2017/4/26,  add description
 */
static status_t dbc_save_config(knl_instance_t *kernel, knl_database_def_t *def)
{
    char buf[GS_MAX_CONFIG_LINE_SIZE] = { 0 };
    text_t file_list = { .len = 0, .str = buf };
    
    if (cm_concat_string(&file_list, GS_MAX_CONFIG_LINE_SIZE, "(") != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->ctrlfiles.count; i++) {
        text_t *file_name = (text_t *)cm_galist_get(&def->ctrlfiles, i);
        cm_concat_text(&file_list, GS_MAX_CONFIG_LINE_SIZE, file_name);

        if (i != def->ctrlfiles.count - 1) {
            if (cm_concat_string(&file_list, GS_MAX_CONFIG_LINE_SIZE, ", ") != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    if (cm_concat_string(&file_list, GS_MAX_CONFIG_LINE_SIZE, ")\0") != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_alter_config(kernel->attr.config, "CONTROL_FILES", buf, CONFIG_SCOPE_BOTH, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_alter_config(kernel->attr.config, "UNDO_TABLESPACE", def->undo_space.name.str, 
                        CONFIG_SCOPE_MEMORY, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t dbc_wait_dc_completed(knl_session_t *session)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;

    while (!kernel->dc_ctx.completed) {
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        cm_sleep(100);
    }

    return GS_SUCCESS;
}

status_t dbc_create_database(knl_handle_t session, knl_database_def_t *def)
{
    knl_session_t *knl_session = (knl_session_t *)session;
    knl_instance_t *kernel = knl_session->kernel;

    kernel->db.status = DB_STATUS_CREATING;
    DB_CORE_CTRL(knl_session)->resetlogs.rst_id = 0;
    dbc_init_scn(knl_session);
    dbc_init_archivelog(knl_session, def);
    dbc_init_dbid(knl_session, def);

    if (dbc_save_sys_password(knl_session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_alter_config(kernel->attr.config, "_SYS_PASSWORD", kernel->attr.sys_pwd, CONFIG_SCOPE_DISK, GS_TRUE) !=
        GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_save_charset(knl_session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_build_ctrlfiles(knl_session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_build_logfiles(knl_session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // after build ctrl files and log files, we should launch the redo log
    // and checkpoint facility to keep database init consistency.
    if (db_load_logfiles(knl_session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_init_space(knl_session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dbc_init_doublewrite(knl_session);

    if (undo_create(knl_session, DB_CORE_CTRL(knl_session)->undo_space, 0, UNDO_SEGMENT_COUNT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_build_systables(knl_session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_save_data_file(knl_session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_save_core_ctrl(knl_session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_save_config(kernel, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_mount(knl_session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    db_open_opt_t open_options = {
        GS_TRUE, GS_FALSE, GS_FALSE, GS_FALSE, GS_TRUE, DB_OPEN_STATUS_NORMAL, GS_INVALID_LFN
    };
    if (db_open(knl_session, &open_options) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (undo_preload(knl_session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dbc_wait_dc_completed(knl_session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

uint32 dbc_generate_dbid(knl_session_t *session)
{
    database_t *db = &session->kernel->db;
    dbname_time_t dbname_time;

    errno_t ret = strcpy_s(dbname_time.name, GS_DB_NAME_LEN, db->ctrl.core.name);
    knl_securec_check(ret);
    dbname_time.time = cm_now();

    int32 name_len = (int32)strlen(dbname_time.name);
    int32 remain_size = GS_DB_NAME_LEN - name_len;

    /* Fill the remaining bytes of the name with random number. */
    for (int32 i = 0; i < remain_size; i++) {
        dbname_time.name[name_len + i] = cm_random(GS_MAX_UINT8);
    }

    return cm_hash_bytes((uint8 *)&dbname_time.name[0], GS_DB_NAME_LEN + sizeof(date_t), GS_MAX_INT32);
}

#ifdef __cplusplus
}
#endif
