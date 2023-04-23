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
 * knl_table.c
 *    implement of table operation
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/table/knl_table.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_table.h"
#include "dc_tbl.h"
#include "dc_part.h"
#include "knl_mtrl.h"
#include "knl_database.h"
#include "knl_context.h"
#include "temp_btree.h"
#include "pcr_heap.h"
#include "pcr_btree.h"
#include "index_common.h"
#include "rcr_btree_scan.h"
#include "knl_comment.h"
#include "knl_external.h"
#include "knl_ctlg.h"
#include "knl_sys_part_defs.h"

#ifdef Z_SHARDING
static status_t db_insert_distribute_strategy_inner(knl_session_t *session, knl_cursor_t *cursor,
                                                    knl_table_desc_t *desc);
status_t db_insert_distribute_strategy(knl_session_t *session, table_t *table);
status_t db_delete_distribute_strategy(knl_session_t *session, table_t *table);
#endif

#define COLUMN_SET_DELETED(col)        ((col)->flags |= KNL_COLUMN_FLAG_DELETED)
#define COLUMN_SET_HIDDEN(col)         ((col)->flags |= KNL_COLUMN_FLAG_HIDDEN)
#define COLUMN_SET_SERIAL(col)         ((col)->flags |= KNL_COLUMN_FLAG_SERIAL)
#define COLUMN_SET_UPDATE_DEFAULT(col) ((col)->flags |= KNL_COLUMN_FLAG_UPDATE_DEFAULT)
#define COLUMN_RESET_UPDATE_DEFAULT(col) ((col)->flags &= ~KNL_COLUMN_FLAG_UPDATE_DEFAULT)

#define COLUMN_SET_CHARACTER(col)      ((col)->flags |= KNL_COLUMN_FLAG_CHARACTER)
#define COLUMN_SET_QUOTE(col)          ((col)->flags |= KNL_COLUMN_FLAG_QUOTE)
#define COLUMN_SET_VIRTUAL(col)        ((col)->flags |= KNL_COLUMN_FLAG_VIRTUAL)
#define COLUMN_SET_DESCEND(col)        ((col)->flags |= KNL_COLUMN_FLAG_DESCEND)
#define COLUMN_SET_NOCHARACTER(col)    ((col)->flags &= ~KNL_COLUMN_FLAG_CHARACTER)
#define COLUMN_SET_DEFAULT_NULL(col)   ((col)->flags |= KNL_COLUMN_FLAG_DEFAULT_NULL)
#define COLUMN_SET_ARRAY(col)          ((col)->flags |= KNL_COLUMN_FLAG_ARRAY)
#define COLUMN_RESET_ARRAY(col)        ((col)->flags &= ~KNL_COLUMN_FLAG_ARRAY)
#define COLUMN_RESET_DEFAULT_NULL(col)  ((col)->flags &= ~KNL_COLUMN_FLAG_DEFAULT_NULL)
#define MAX_COLUMN_ID_STR_LEN 6 // sizeof("65535,")

typedef struct st_ptrans_match_cond {
    knl_session_t *session;
    knl_cursor_t *cursor;
    knl_xa_xid_t *xa_xid;
    uint64 *ltid;
    bool32 only_remained;
}ptrans_match_cond_t;

static status_t db_clean_shadow_index(knl_session_t *session, uint32 user_id, uint32 table_id, bool32 clean_segment);

status_t db_invalid_cursor_operation(knl_session_t *session, knl_cursor_t *cursor)
{
    GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "invalid operation on view or external table");
    return GS_ERROR;
}

status_t db_invalid_cursor_operation1(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "invalid operation on view or external table");
    return GS_ERROR;
}

/* heap table access method */
table_accessor_t g_heap_acsor = {
    (knl_cursor_operator_t)heap_fetch,
    (knl_cursor_operator_t)heap_rowid_fetch,
    (knl_cursor_operator_t)heap_fetch_by_rowid,
    (knl_cursor_operator1_t)heap_lock_row,
    (knl_cursor_operator_t)heap_insert,
    (knl_cursor_operator_t)heap_update,
    (knl_cursor_operator_t)heap_delete
};

/* PCR heap table access method */
table_accessor_t g_pcr_heap_acsor = {
    (knl_cursor_operator_t)pcrh_fetch,
    (knl_cursor_operator_t)pcrh_rowid_fetch,
    (knl_cursor_operator_t)pcrh_fetch_by_rowid,
    (knl_cursor_operator1_t)pcrh_lock_row,
    (knl_cursor_operator_t)pcrh_insert,
    (knl_cursor_operator_t)pcrh_update,
    (knl_cursor_operator_t)pcrh_delete
};

/* temp table access method */
table_accessor_t g_temp_heap_acsor = {
    (knl_cursor_operator_t)temp_heap_fetch,
    (knl_cursor_operator_t)temp_heap_rowid_fetch,
    (knl_cursor_operator_t)temp_heap_fetch_by_rowid,
    (knl_cursor_operator1_t)temp_heap_lock_row,
    (knl_cursor_operator_t)temp_heap_insert,
    (knl_cursor_operator_t)temp_heap_update,
    (knl_cursor_operator_t)temp_heap_delete
};

table_accessor_t g_external_table_acsor = {
    (knl_cursor_operator_t)external_heap_fetch,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator1_t)db_invalid_cursor_operation,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
};

table_accessor_t g_invalid_table_acsor = {
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator1_t)db_invalid_cursor_operation1,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
    (knl_cursor_operator_t)db_invalid_cursor_operation,
};

status_t db_generate_object_id(knl_session_t *session, uint32 *obj_id)
{
    uint64 oid;
    text_t name;
    text_t sys = { .str = SYS_USER_NAME, .len = (uint32)strlen(SYS_USER_NAME) };
    cm_str2text("OBJECT_ID$", &name);

    if (knl_seq_nextval(session, &sys, &name, (int64 *)&oid) != GS_SUCCESS) {
        return GS_ERROR;
    }
    *obj_id = (uint32)oid;
    return GS_SUCCESS;
}

static status_t db_get_table_spaceid(knl_session_t *session, knl_table_def_t *def, knl_table_desc_t *desc)
{
    if (def->space.str == NULL) {
        if (TABLE_IS_TEMP(def->type)) {
            if (dc_get_user_temp_spc(session, desc->uid, &desc->space_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else if (def->type != TABLE_TYPE_NOLOGGING) {
            if (dc_get_user_default_spc(session, desc->uid, &desc->space_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            desc->space_id = DB_CORE_CTRL(session)->temp_space;
        }
    } else {
        if (spc_get_space_id(session, &def->space, &desc->space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (spc_check_by_uid(session, &def->space, desc->space_id, desc->uid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_check_table_by_spc(space_t *space, knl_table_def_t *def)
{
    if (IS_UNDO_SPACE(space)) {
        GS_THROW_ERROR(ERR_MISUSE_UNDO_SPACE, T2S(&def->space));
        return GS_ERROR;
    }

    if (SPACE_IS_LOGGING(space) && def->type == TABLE_TYPE_NOLOGGING) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create nologging table", "logging tablespace");
        return GS_ERROR;
    }

    if (SPACE_IS_NOLOGGING(space) && !TABLE_IS_TEMP(def->type)) {
        def->type = TABLE_TYPE_NOLOGGING;
    }

    if (IS_SWAP_SPACE(space) && !TABLE_IS_TEMP(def->type)) {
        GS_THROW_ERROR(ERR_PERMANENTOBJ_IN_TEMPSPACE);
        return GS_ERROR;
    }

    if (!IS_SWAP_SPACE(space) && TABLE_IS_TEMP(def->type)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create temporary table", "non-swap tablespace");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_init_table_desc_spc(knl_session_t *session, knl_table_desc_t *desc, knl_table_def_t *def)
{
    if (db_get_table_spaceid(session, def, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    space_t *space = SPACE_GET(desc->space_id);

    /* check if we have privilege to create table in the space */
    if (TABLE_IS_TEMP(def->type) && def->parted) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create partition",
            IS_LTT_BY_NAME(def->name.str) ? "local temporary table" : "global temporary table");
        return GS_ERROR;
    }

    if (db_check_table_by_spc(space, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_init_table_desc_by_def(knl_session_t *session, knl_table_desc_t *desc, knl_table_def_t *def)
{
    desc->column_count = def->columns.count;
    (void)cm_text2str(&def->name, desc->name, GS_NAME_BUFFER_SIZE);
    desc->entry = INVALID_PAGID;
    desc->type = def->type;
    desc->cr_mode = (cr_mode_t)def->cr_mode;
    desc->initrans = def->initrans;
    desc->pctfree = def->pctfree;
    desc->appendonly = def->appendonly;
    desc->parted = def->parted;
    desc->external_desc = NULL;
    desc->serial_start = def->serial_start;
    desc->id = def->sysid;
    desc->version = TABLE_VERSION_NEW_HASH;
    desc->is_csf = def->csf;
    space_t *space = SPACE_GET(desc->space_id);
    desc->compress_algo = COMPRESS_NONE;
    if (def->compress_algo > COMPRESS_NONE) {
        desc->compress_algo = def->compress_algo;
    } 
    if (desc->compress_algo > COMPRESS_NONE) {
        if (!(def->type == TABLE_TYPE_HEAP && IS_SPACE_COMPRESSIBLE(space))) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress table",
                "non heap table and non user bitmap tablespace");
            return GS_ERROR;
        }
        if (def->part_def != NULL && def->part_def->is_composite) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress table",
                "subpart table");
            return GS_ERROR;
        }
    } else {
        if (session->kernel->attr.default_compress_algo > COMPRESS_NONE) {
            if ((def->type == TABLE_TYPE_HEAP && IS_SPACE_COMPRESSIBLE(space) && (def->part_def == NULL || 
                !def->part_def->is_composite))) {
                desc->compress_algo = session->kernel->attr.default_compress_algo;
            } 
        }
    }
    desc->compress = (desc->compress_algo > COMPRESS_NONE) ? GS_TRUE : GS_FALSE;

    if (TABLE_IS_TEMP(def->type)) {
        desc->cr_mode = CR_ROW;
    }

#ifdef Z_SHARDING
    desc->distribute_type = def->distribute_type;
    desc->distribute_data = def->distribute_data;
    desc->distribute_text = def->distribute_text;
    desc->distribute_buckets = def->distribute_buckets;
    desc->slice_count = def->slice_count;
    desc->group_count = def->distribute_groups.count;
#endif

    return GS_SUCCESS;
}

static inline status_t db_create_table_def_check(knl_table_def_t *def)
{
    if (def->storage_def.initial > 0) {
        if (def->type != TABLE_TYPE_HEAP && def->type != TABLE_TYPE_NOLOGGING) {
            GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "storage option without heap table");
            return GS_ERROR;
        }
    }

    if (def->storage_def.maxsize > 0) {
        if (def->type != TABLE_TYPE_HEAP && def->type != TABLE_TYPE_NOLOGGING) {
            GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "storage option without heap table");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t db_init_table_storage_desc(knl_session_t *session, knl_table_desc_t *desc, knl_table_def_t *def)
{
    space_t *space;
    space = SPACE_GET(desc->space_id);

    if (def->storage_def.initial > 0) {
        if (!dc_is_reserved_entry(desc->uid, desc->id)) {
            desc->storaged = GS_TRUE;
        }
        desc->storage_desc.initial = CM_CALC_ALIGN((uint64)def->storage_def.initial, space->ctrl->block_size) /
            space->ctrl->block_size;
    }

    // storage maxsize clause will not take effect to sys tables
    if (def->storage_def.maxsize > 0 && !dc_is_reserved_entry(desc->uid, desc->id)) {
        desc->storaged = GS_TRUE;
        desc->storage_desc.max_pages = CM_CALC_ALIGN((uint64)def->storage_def.maxsize, space->ctrl->block_size) /
            space->ctrl->block_size;
    }

    return GS_SUCCESS;
}

status_t db_init_table_desc(knl_session_t *session, knl_table_desc_t *desc, knl_table_def_t *def)
{
    if (!dc_get_user_id(session, &def->schema, &desc->uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&def->schema));
        return GS_ERROR;
    }

    if (def->columns.count > session->kernel->attr.max_column_count - 1) {
        GS_THROW_ERROR(ERR_MAX_COLUMN_SIZE, session->kernel->attr.max_column_count - 1);
        return GS_ERROR;
    }

    if (db_init_table_desc_spc(session, desc, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_LTT_BY_NAME(def->name.str)) {
        desc->oid = GS_INVALID_ID32;
    } else {
        if (!dc_is_reserved_entry(desc->uid, desc->id)) {
            if (db_generate_object_id(session, &desc->oid) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            desc->oid = def->sysid;
        }
    }

    desc->org_scn = db_inc_scn(session);
    desc->chg_scn = desc->org_scn;
    if (db_init_table_desc_by_def(session, desc, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_init_table_storage_desc(session, desc, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_init_view_desc(knl_session_t *session, knl_view_t *view, knl_view_def_t *def)
{
    if (!dc_get_user_id(session, &def->user, &view->uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&def->user));
        return GS_ERROR;
    }

    view->org_scn = db_inc_scn(session);
    view->chg_scn = view->org_scn;
    view->column_count = def->columns.count;
    (void)cm_text2str(&def->name, view->name, GS_NAME_BUFFER_SIZE);
    view->flags = def->status;
    view->sql_type = def->sql_tpye;
    view->id = GS_INVALID_ID32;

    return GS_SUCCESS;
}

static void db_init_column_flg(knl_column_def_t *def, knl_column_t *column)
{
    if (def->is_serial) {
        COLUMN_SET_SERIAL(column);
    }

    if (def->is_update_default) {
        COLUMN_SET_UPDATE_DEFAULT(column);
    } else {
        COLUMN_RESET_UPDATE_DEFAULT(column);
    }

    if (def->has_quote) {
        COLUMN_SET_QUOTE(column);
    }

    if (GS_IS_STRING_TYPE(column->datatype)) {
        if (def->typmod.is_char) {
            COLUMN_SET_CHARACTER(column);
        } else {
            // modify to char(BYTE) need reset KNL_COLUMN_FLAG_CHARACTER to 0;
            COLUMN_SET_NOCHARACTER(column);
        }
    }

    if (!def->is_default_null) {
        COLUMN_RESET_DEFAULT_NULL(column);
        column->default_text = def->default_text;
    } else {
        column->default_text.str = NULL;
        column->default_text.len = 0;
        COLUMN_SET_DEFAULT_NULL(column);
    }

    if (def->typmod.is_array == GS_TRUE) {
        COLUMN_SET_ARRAY(column);
    } else {
        COLUMN_RESET_ARRAY(column);
    }
}

/*
 * Description     : Initialize table description with table definition
 *                 : Note: memory of column->name should allocated outside
 * Input           : session
 * Input           : def: table definition
 * Output          : desc: table description
 * Return Value    : status_t
 * History         : 1. 2017/4/26,  add description
 */
void db_convert_column_def(knl_column_t *column, uint32 uid, uint32 obj_id, knl_column_def_t *def,
                           knl_column_t *old_column, uint32 id)
{
    column->id = id;
    column->uid = uid;
    column->table_id = obj_id;
    (void)cm_text2str(&def->name, column->name, GS_NAME_BUFFER_SIZE);

    column->nullable = old_column ? (def->has_null ? def->nullable : old_column->nullable) : def->nullable;
    column->flags = old_column ? old_column->flags : 0;

    column->datatype = def->typmod.datatype;
    column->size = def->typmod.size;

    switch (column->datatype) {
        case GS_TYPE_REAL:
        case GS_TYPE_FLOAT:
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
        case GS_TYPE_INTERVAL_DS:
        case GS_TYPE_INTERVAL_YM:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_TZ:
        case GS_TYPE_TIMESTAMP_LTZ:
            column->precision = def->typmod.precision;
            column->scale = def->typmod.scale;
            break;
        default:
            column->precision = 0;
            column->scale = 0;
            break;
    }

    db_init_column_flg(def, column);
}

status_t db_write_syslob(knl_session_t *session, knl_cursor_t *cursor, knl_lob_desc_t *desc)
{
    row_assist_t ra;
    table_t *table = NULL;
    space_t *space;
    status_t status;

    space = SPACE_GET(desc->space_id);

    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "space offline and write to syslob failed");
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_LOB_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, cursor->buf, GS_MAX_ROW_SIZE, table->desc.column_count);
    (void)row_put_int32(&ra, desc->uid);               // user id
    (void)row_put_int32(&ra, desc->table_id);          // base table id
    (void)row_put_int32(&ra, desc->column_id);         // column_id
    (void)row_put_int32(&ra, desc->space_id);          // tablespace id
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);  // scn when creating
    (void)row_put_int64(&ra, desc->org_scn);           // scn when creating
    (void)row_put_int64(&ra, desc->chg_scn);           // scn when last ddl
    (void)row_put_int32(&ra, desc->chunk);             // chunk size
    (void)row_put_int32(&ra, desc->pctversion);        // pctversion
    (void)row_put_int32(&ra, desc->retention);         // retention
    (void)row_put_int32(&ra, desc->flags);             // is in row storage

    status = knl_internal_insert(session, cursor);

    return status;
}
static status_t db_parse_lob_store(knl_session_t *session, knl_column_t *column, galist_t *lob_stores,
                                   knl_lob_desc_t *lob_desc)
{
    knl_lobstor_def_t *store = NULL;
    uint32 i = 0;

    for (i = 0; i < lob_stores->count; i++) {
        store = (knl_lobstor_def_t *)cm_galist_get(lob_stores, i);
        if (!cm_text_str_equal(&store->col_name, column->name)) {
            continue;
        }

        if (store->space.len != 0) {
            lob_desc->is_stored = GS_TRUE;
            if (spc_get_space_id(session, &store->space, &lob_desc->space_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
            if (spc_check_by_uid(session, &store->space, lob_desc->space_id, lob_desc->uid) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (IS_SWAP_SPACE(SPACE_GET(lob_desc->space_id))) {
                GS_THROW_ERROR(ERR_PERMANENTOBJ_IN_TEMPSPACE);
                return GS_ERROR;
            }
        }

        lob_desc->is_inrow = store->in_row;

        return GS_SUCCESS;
    }

    return GS_SUCCESS;
}

status_t db_check_lob_storage_mode(knl_session_t *session, knl_table_def_t *def)
{
    knl_column_def_t *column_def = NULL;
    knl_lobstor_def_t *store = NULL;
    bool32 is_found = GS_FALSE;
    char *name = NULL;

    if (def->lob_stores.count == 0) {
        return GS_SUCCESS;
    }

    name = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);

    for (uint32 i = 0; i < def->lob_stores.count; i++) {
        store = (knl_lobstor_def_t *)cm_galist_get(&def->lob_stores, i);
        is_found = GS_FALSE;

        for (uint32 j = 0; j < def->columns.count; j++) {
            column_def = (knl_column_def_t *)cm_galist_get(&def->columns, j);
            (void)cm_text2str(&column_def->name, name, GS_NAME_BUFFER_SIZE);

            if (cm_text_str_equal(&store->col_name, name)) {
                is_found = GS_TRUE;

                if (!GS_IS_LOB_TYPE(column_def->typmod.datatype) && !column_def->typmod.is_array) {
                    cm_pop(session->stack);
                    GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set no-lob column to mode of storage");
                    return GS_ERROR;
                }
            }
        }

        if (!is_found) {
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "column", T2S(&store->col_name));
            return GS_ERROR;
        }
    }

    cm_pop(session->stack);
    return GS_SUCCESS;
}

static void db_init_lob_desc(knl_session_t *session, table_t *table, knl_column_t *column, knl_lob_desc_t *lob_desc)
{
    lob_desc->uid = table->desc.uid;
    lob_desc->table_id = table->desc.id;
    lob_desc->column_id = column->id;
    lob_desc->space_id = table->desc.space_id;
    lob_desc->entry = INVALID_PAGID;
    lob_desc->org_scn = db_inc_scn(session);
    lob_desc->chg_scn = lob_desc->org_scn;
    lob_desc->chunk = DEFAULT_LOB_CHUNK_SIZE;
    lob_desc->retention = 0;
    lob_desc->pctversion = GS_LOB_PCTVISON;
    lob_desc->is_compressed = GS_FALSE;
    lob_desc->is_encrypted = GS_FALSE;
    lob_desc->is_stored = GS_FALSE;
    lob_desc->is_inrow = IS_SYS_TABLE(table) ? GS_FALSE : GS_TRUE;
}

status_t db_create_lob(knl_session_t *session, table_t *table, knl_column_t *column, knl_table_def_t *def)
{
    lob_t lob;
    knl_cursor_t *cursor = NULL;
    knl_lob_desc_t *lob_desc = &lob.desc;

    errno_t ret = memset_sp(&lob, sizeof(lob_t), 0, sizeof(lob_t));
    knl_securec_check(ret);

    db_init_lob_desc(session, table, column, lob_desc);

    if (def != NULL && def->lob_stores.count > 0) {
        if (def->type == TABLE_TYPE_NOLOGGING) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "lob store", "nologging table");
            return GS_ERROR;
        }

        if (db_parse_lob_store(session, column, &def->lob_stores, lob_desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (lob_check_space(session, table, lob_desc->space_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_SYS_TABLE(table)) {
        if (lob_create_segment(session, &lob) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    if (db_write_syslob(session, cursor, lob_desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (IS_PART_TABLE(table)) {
        if (db_create_part_lob(session, cursor, table, def, &lob) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static bool32 db_reference_cols_match(uint32 *cols, uint32 count, knl_index_desc_t *desc, uint32 *match_id)
{
    uint32 i, j;

    if (count != desc->column_count) {
        return GS_FALSE;
    }

    for (i = 0; i < count; i++) {
        for (j = 0; j < count; j++) {
            if (cols[j] == desc->columns[i]) {
                match_id[i] = j;
                break;
            }
        }
        if (j == count) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

status_t db_get_fk_part_no(knl_session_t *session, knl_cursor_t *cursor, index_t *index, knl_handle_t dc_entity,
    ref_cons_t *cons, uint32 *part_no)
{
    uint32 i, j;
    part_table_t *part_table;
    part_key_t *part_key;
    dc_entity_t *entity = (dc_entity_t*)dc_entity;
    char *data = NULL;
    uint32 len;

    part_table = entity->table.part_table;
    part_key = (part_key_t *)cm_push(session->stack, GS_MAX_COLUMN_SIZE);
    errno_t ret = memset_sp(part_key, GS_MAX_COLUMN_SIZE, 0, GS_MAX_COLUMN_SIZE);
    knl_securec_check(ret);
    part_key_init(part_key, part_table->desc.partkeys);

    for (i = 0; i < part_table->desc.partkeys; i++) {
        for (j = 0; j < index->desc.column_count; j++) {
            if (part_table->keycols[i].column_id == index->desc.columns[j]) {
                data = CURSOR_COLUMN_DATA(cursor, cons->cols[j]);
                len = CURSOR_COLUMN_SIZE(cursor, cons->cols[j]);
                if (len != GS_NULL_VALUE_LEN) {
                    gs_type_t type = part_table->keycols[i].datatype;
                    dec4_t dec4;
                    if (CSF_IS_DECIMAL_ZERO(cursor->row->is_csf, len, type)) {
                        dec4.head = 0;
                        data = (char *)&dec4;
                        len = cm_dec4_stor_sz(&dec4);
                    }

                    if (part_put_data(part_key, data, len, type) != GS_SUCCESS) {
                        cm_pop(session->stack);
                        return GS_ERROR;
                    }
                } else {
                    part_put_null(part_key);
                }
                break;
            }
        }

        if (j == index->desc.column_count) {
            break;
        }
    }

    *part_no = knl_locate_part_key(entity, part_key);
    cm_pop(session->stack);
    return GS_SUCCESS;
}

status_t db_get_fk_subpart_no(knl_session_t *session, knl_cursor_t *cursor, index_t *index, knl_handle_t dc_entity,
    ref_cons_t *cons, uint32 compart_no, uint32 *subpart_no)
{
    uint32 len, j;
    char *data = NULL;
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;

    CM_SAVE_STACK(session->stack);
    part_key_t *part_key = (part_key_t *)cm_push(session->stack, GS_MAX_COLUMN_SIZE);
    part_key_init(part_key, part_table->desc.subpartkeys);

    for (uint32 i = 0; i < part_table->desc.subpartkeys; i++) {
        for (j = 0; j < index->desc.column_count; j++) {
            if (index->desc.columns[j] != part_table->sub_keycols[i].column_id) {
                continue;
            }

            data = CURSOR_COLUMN_DATA(cursor, cons->cols[j]);
            len = CURSOR_COLUMN_SIZE(cursor, cons->cols[j]);
            if (len != GS_NULL_VALUE_LEN) {
                if (part_put_data(part_key, data, len, part_table->sub_keycols[i].datatype) != GS_SUCCESS) {
                    CM_RESTORE_STACK(session->stack);
                    return GS_ERROR;
                }
            } else {
                part_put_null(part_key);
            }
            break;
        }

        if (j == index->desc.column_count) {
            break;
        }
    }

    *subpart_no = knl_locate_subpart_key(entity, compart_no, part_key);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_verify_reference_data(knl_session_t *session, knl_dictionary_t *dc, knl_dictionary_t *ref_dc,
                                         ref_cons_t *ref_cons)
{
    index_t *index = NULL;
    bool32 parent_exist = GS_FALSE;
    bool32 has_null = GS_FALSE;
    dc_entity_t *ref_entity = NULL;
    uint32 i, col_id;
    knl_cursor_t *cursor = NULL;
    char *key = NULL;
    char *data = NULL;
    uint32 len, part_no;
    knl_column_t *column = NULL;
    table_t *table = NULL;
    index_part_t *index_part = NULL;
    btree_t *btree = NULL;
    status_t status = GS_SUCCESS;

    ref_entity = (dc_entity_t *)ref_dc->handle;
    table = &ref_entity->table;

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (index->desc.id == ref_cons->ref_ix) {
            break;
        }
    }

    if (index->desc.is_invalid) {
        GS_THROW_ERROR(ERR_INDEX_NOT_STABLE, index->desc.name);
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_SELECT;

    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    key = (char *)cm_push(session->stack, GS_KEY_BUF_SIZE);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        parent_exist = GS_FALSE;
        has_null = GS_FALSE;
        knl_init_key(&index->desc, key, NULL);
        for (i = 0; i < index->desc.column_count; i++) {
            column = dc_get_column(ref_entity, index->desc.columns[i]);
            col_id = ref_cons->cols[i];
            data = CURSOR_COLUMN_DATA(cursor, col_id);
            len = CURSOR_COLUMN_SIZE(cursor, col_id);
            if (len == GS_NULL_VALUE_LEN) {
                has_null = GS_TRUE;
                break;
            }
            // the len of column data is not greater than max value of uint16
            knl_put_key_data(INDEX_DESC(index), key, column->datatype, data, len, i);
        }

        if (IS_PART_INDEX(index)) {
            if (db_get_fk_part_no(session, cursor, index, ref_entity, ref_cons, &part_no) != GS_SUCCESS) {
                knl_close_cursor(session, cursor);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (part_no == GS_INVALID_ID32 || index->part_index->groups[part_no / PART_GROUP_SIZE] == NULL) {
                knl_close_cursor(session, cursor);
                CM_RESTORE_STACK(session->stack);
                GS_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_NO_FOUND, "parent key not found");
                return GS_ERROR;
            }

            index_part = PART_GET_ENTITY(index->part_index, part_no);
            if (index_part == NULL) {
                knl_close_cursor(session, cursor);
                CM_RESTORE_STACK(session->stack);
                GS_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_NO_FOUND, "parent key not found");
                return GS_ERROR;
            }
            
            if (index_part->desc.is_invalid) {
                knl_close_cursor(session, cursor);
                CM_RESTORE_STACK(session->stack);
                GS_THROW_ERROR(ERR_INDEX_PART_UNUSABLE, index_part->desc.name, index->desc.name);
                return GS_ERROR;
            }
        }

        if (index->desc.parted) {
            btree = &index_part->btree;
        } else {
            btree = &index->btree;
        }

        if (btree->segment != NULL && !has_null) { 
            if (index->desc.cr_mode == CR_PAGE) {
                if (pcrb_check_key_exist(session, btree, key, &parent_exist) != GS_SUCCESS) {
                    status = GS_ERROR;
                    break;
                }
            } else {
                if (btree_check_key_exist(session, btree, key, &parent_exist) != GS_SUCCESS) {
                    status = GS_ERROR;
                    break;
                }
            }
        } else {
            parent_exist = has_null ? GS_TRUE : GS_FALSE;
        }

        if (!parent_exist) {
            GS_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_NO_FOUND, "parent key not found");
            status = GS_ERROR;
            break;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }
    }

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t db_verify_reference_cols(knl_session_t *session, knl_dictionary_t *dc, knl_dictionary_t *ref_dc,
                                         knl_constraint_def_t *def, ref_cons_t *ref_cons)
{
    uint32 i;
    uint32 *col_id = NULL;
    uint32 *ref_col_id = NULL;
    uint32 *match_id = NULL;
    table_t *ref_table = NULL;
    text_t *col_name = NULL;
    text_t *ref_col_name = NULL;
    knl_column_t *column = NULL;
    knl_column_t *ref_column = NULL;
    knl_reference_def_t *ref = &def->ref;
    bool32 match_index = GS_FALSE;
    knl_index_desc_t *index = NULL;

    col_id = (uint32 *)cm_push(session->stack, sizeof(uint32) * GS_MAX_INDEX_COLUMNS * 3);
    ref_col_id = col_id + GS_MAX_INDEX_COLUMNS;
    match_id = ref_col_id + GS_MAX_INDEX_COLUMNS;

    knl_panic_log(def->columns.count == ref->ref_columns.count, "columns's count is not equal to ref_columns's count, "
                  "panic info: columns count %u ref_columns count %u", def->columns.count, ref->ref_columns.count);

    for (i = 0; i < def->columns.count; i++) {
        col_name = (text_t *)cm_galist_get(&def->columns, i);
        col_id[i] = knl_get_column_id(dc, col_name);
        ref_col_name = (text_t *)cm_galist_get(&ref->ref_columns, i);
        ref_col_id[i] = knl_get_column_id(ref_dc, ref_col_name);

        if (col_id[i] == GS_INVALID_ID16) {
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, DC_ENTRY_NAME(dc), T2S(col_name));
            return GS_ERROR;
        }

        if (ref_col_id[i] == GS_INVALID_ID16) {
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, DC_ENTRY_NAME(ref_dc), T2S(ref_col_name));
            return GS_ERROR;
        }

        column = knl_get_column(DC_ENTITY(dc), col_id[i]);
        if (KNL_COLUMN_IS_ARRAY(column)) {
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_REF_ON_ARRAY_COLUMN);
            return GS_ERROR;
        }
        ref_column = knl_get_column(DC_ENTITY(ref_dc), ref_col_id[i]);
        if (ref_column->datatype != column->datatype) {
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_COL_TYPE_MISMATCH);
            return GS_ERROR;
        }
    }

    ref_table = DC_TABLE(ref_dc);
    for (i = 0; i < ref_table->index_set.count; i++) {
        index = &ref_table->index_set.items[i]->desc;
        if (!index->is_enforced) {
            continue;
        }

        knl_panic_log(index->primary || index->unique,
            "index is neither primary nor unique, panic info: table %s index %s", ref_table->desc.name, index->name);

        if (db_reference_cols_match(ref_col_id, def->columns.count, index, match_id)) {
            match_index = GS_TRUE;
            ref_cons->ref_ix = index->id;
            break;
        }
    }

    if (!match_index) {
        cm_pop(session->stack);
        GS_THROW_ERROR(ERR_NO_MATCH_CONSTRAINT);
        return GS_ERROR;
    }

    ref_cons->col_count = def->columns.count;
    ref_cons->ref_uid = ref_dc->uid;
    ref_cons->ref_oid = ref_dc->oid;

    for (i = 0; i < ref_cons->col_count; i++) {
        ref_cons->cols[i] = col_id[match_id[i]];
    }
    ref_cons->refactor = ref->refactor;
    cm_pop(session->stack);

    return GS_SUCCESS;
}

static bool32 db_check_cons_exists(knl_session_t *session, knl_dictionary_t *dc, ref_cons_t *ref_cons)
{
    table_t *table;
    ref_cons_t *item = NULL;
    uint32 i, j;

    table = DC_TABLE(dc);

    for (i = 0; i < table->cons_set.ref_count; i++) {
        item = table->cons_set.ref_cons[i];
        if (item->ref_uid != ref_cons->ref_uid || item->ref_oid != ref_cons->ref_oid) {
            continue;
        }

        if (item->col_count != ref_cons->col_count) {
            continue;
        }

        for (j = 0; j < ref_cons->col_count; j++) {
            if (item->cols[j] != ref_cons->cols[j]) {
                break;
            }
        }

        if (j == ref_cons->col_count) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

static status_t db_check_ref_dc(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def,
    knl_dictionary_t *ref_dc, ref_cons_t *ref_cons, bool32 is_same)
{
    knl_reference_def_t *ref = &def->ref;

    if (ref_dc->type == DICT_TYPE_TEMP_TABLE_TRANS || ref_dc->type == DICT_TYPE_TEMP_TABLE_SESSION) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT,
            "attempt to reference in a referential integrity", "temporary table");
        return GS_ERROR;
    }

    if (!is_same) {
        uint32 timeout = session->kernel->attr.ddl_lock_timeout;
        if (lock_table_directly(session, ref_dc, timeout) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    table_t *ref_table = DC_TABLE(ref_dc);
    if (ref_table->desc.org_scn > ref_dc->org_scn) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&ref->ref_user), T2S_EX(&ref->ref_table));
        return GS_ERROR;
    }

    ref_cons->cols = (uint16 *)cm_push(session->stack, sizeof(uint16) * GS_MAX_INDEX_COLUMNS);
    if (db_verify_reference_cols(session, dc, ref_dc, def, ref_cons) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (def->cons_state.is_validate) {
        if (db_verify_reference_data(session, dc, ref_dc, ref_cons) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (db_check_cons_exists(session, dc, ref_cons)) {
        GS_THROW_ERROR(ERR_CONS_EXISTS);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t db_make_col_list(knl_constraint_def_t *def, ref_cons_t *ref_cons, text_t *txt_cols)
{
    for (uint32 i = 0; i < def->columns.count; i++) {
        cm_concat_int32(txt_cols, GS_MAX_INDEX_COLUMNS * MAX_COLUMN_ID_STR_LEN, ref_cons->cols[i]);
        if (i + 1 < def->columns.count) {
            if (cm_concat_string(txt_cols, GS_MAX_INDEX_COLUMNS * MAX_COLUMN_ID_STR_LEN, ",") != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t db_build_ref_desc(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def,
                                  row_assist_t *ra)
{
    knl_reference_def_t *ref = &def->ref;
    ref_cons_t ref_cons;
    knl_dictionary_t *ref_dc = &ref->ref_dc;
    char str_cols[GS_MAX_INDEX_COLUMNS * MAX_COLUMN_ID_STR_LEN];
    text_t txt_cols;
    bool32 is_same = GS_FALSE;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;

    if (dc->type == DICT_TYPE_TEMP_TABLE_TRANS || dc->type == DICT_TYPE_TEMP_TABLE_SESSION) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT,
                       "attempt to reference in a referential integrity", "temporary table");
        return GS_ERROR;
    }

    if (cm_text_str_equal(&ref->ref_user, dc_entity->entry->user->desc.name) &&
        cm_text_str_equal(&ref->ref_table, dc_entity->table.desc.name)) {
        errno_t ret = memcpy_sp(ref_dc, sizeof(knl_dictionary_t), dc, sizeof(knl_dictionary_t));
        knl_securec_check(ret);
        is_same = GS_TRUE;
    }

    if (!is_same) {
        if (dc_open(session, &ref->ref_user, &ref->ref_table, ref_dc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (SYNONYM_EXIST(ref_dc)) {
            dc_close(ref_dc);
            GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&ref->ref_user), T2S_EX(&ref->ref_table));
            return GS_ERROR;
        }
    }

    CM_SAVE_STACK(session->stack);

    if (db_check_ref_dc(session, dc, def, ref_dc, &ref_cons, is_same) == GS_ERROR) {
        if (!is_same) {  // it will close dc outside when status is GS_SUCCESS
            dc_close(ref_dc);
        }
        ref_dc->handle = NULL;
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (is_same) {
        ref_dc->handle = NULL;
    }

    txt_cols.str = str_cols;
    txt_cols.len = 0;

    if (db_make_col_list(def, &ref_cons, &txt_cols) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    (void)row_put_int32(ra, ref_cons.col_count);       /* < column count */
    (void)row_put_text(ra, &txt_cols);                 /* < column list  */
    row_put_null(ra);                                  /* < index id of pk/unique */
    (void)row_put_int32(ra, ref_cons.ref_uid);         /* < referenced table uid */
    (void)row_put_int32(ra, ref_cons.ref_oid);         /* < referenced table id */
    (void)row_put_int32(ra, ref_cons.ref_ix);          /* < referenced constraint name, the same as index name */
    row_put_null(ra);                                  /* < check condition text */
    row_put_null(ra);                                  /* < check condition data */
    (void)row_put_int32(ra, def->cons_state.option);   /* < constraint flags */
    (void)row_put_int32(ra, (int32)ref_cons.refactor); /* < referenced constraint delete option */
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_verify_check_data(knl_session_t *session, knl_dictionary_t *dc, text_t *cond)
{
    bool32 exist = GS_FALSE;
    status_t ret;
    text_t sql;
    dc_entry_t *entry = DC_ENTRY(dc);
    dc_user_t *user = entry->user;
    char *clause;
    uint32 len = 2 * GS_MAX_NAME_LEN + GS_MAX_CHECK_VALUE_LEN + GS_FIX_CHECK_SQL_LEN;
    errno_t err;

    clause = (char *)cm_push(session->stack, len);
    err = snprintf_s(clause, len, len - 1, GS_FIX_CHECK_SQL_FORMAT, user->desc.name, entry->name, T2S(cond));
    knl_securec_check_ss(err);

    sql.len = (uint32)strlen(clause);
    sql.str = clause;
    ret = g_knl_callback.exec_check((knl_handle_t)session, &sql, &exist);
    cm_pop(session->stack);

    if (ret != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (exist) {
        GS_THROW_ERROR(ERR_CONSTRAINT_VIOLATED_CHECK_FAILED);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t db_build_check_desc(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def,
                                    row_assist_t *ra)
{
    text_t col_list;
    char str_cols[GS_MAX_CHECK_COLUMNS * MAX_COLUMN_ID_STR_LEN];
    uint16 col_id;
    text_t *column_name = NULL;
    knl_check_def_t *check = &def->check;

    if (def->columns.count > GS_MAX_CHECK_COLUMNS) {
        GS_THROW_ERROR(ERR_TOO_MANY_COLUMNS, "check constraint columns");
        return GS_ERROR;
    }

    if (row_put_int32(ra, def->columns.count) != GS_SUCCESS) { /**< column count */
        return GS_ERROR;
    }

    col_list.str = str_cols;
    col_list.len = 0;
    for (uint32 i = 0; i < def->columns.count; i++) {
        column_name = cm_galist_get(&def->columns, i);
        col_id = knl_get_column_id(dc, column_name);
        cm_concat_int32(&col_list, GS_MAX_CHECK_COLUMNS * MAX_COLUMN_ID_STR_LEN, (uint32)col_id);
        if (i + 1 < def->columns.count) {
            if (cm_concat_string(&col_list, GS_MAX_CHECK_COLUMNS * MAX_COLUMN_ID_STR_LEN, ",") != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    if (row_put_text(ra, &col_list) != GS_SUCCESS) { /**< column list  */
        return GS_ERROR;
    }

    row_put_null(ra); /* < index id of pk/unique */
    row_put_null(ra); /* < referenced table uid */
    row_put_null(ra); /* < referenced table id */
    row_put_null(ra); /* < referenced constraint name, the same as index name */

    if (row_put_text(ra, &check->text) != GS_SUCCESS) {  // check cond text
        return GS_ERROR;
    }

    if (row_put_null(ra) != GS_SUCCESS) {  // check serial data blob
        return GS_ERROR;
    }

    if (row_put_int32(ra, def->cons_state.option) != GS_SUCCESS) { /* < flags */
        return GS_ERROR;
    }

    row_put_null(ra); /* < refactor */
    return GS_SUCCESS;
}

static status_t db_build_cons_desc(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def,
                                   row_assist_t *ra, knl_cursor_t *cursor)
{
    table_t *table = NULL;
    knl_table_desc_t *table_desc = NULL;
    knl_index_col_def_t *column = NULL;
    char str_cols[GS_MAX_INDEX_COLUMNS * MAX_COLUMN_ID_STR_LEN];
    text_t col_list;
    uint32 i;
    uint16 col_id;

    table = DC_TABLE(dc);
    table_desc = &table->desc;

    (void)row_put_int32(ra, table_desc->uid);
    (void)row_put_int32(ra, table_desc->id);
    (void)row_put_text(ra, &def->name);
    (void)row_put_int32(ra, def->type);

    if (def->type == CONS_TYPE_REFERENCE && table->cons_set.ref_count >= GS_MAX_CONSTRAINTS) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_CONSTRAINTS, "foreign key constraint");
        return GS_ERROR;
    }

    if (def->type == CONS_TYPE_CHECK && table->cons_set.check_count >= GS_MAX_CONSTRAINTS) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_CONSTRAINTS, "check constraint");
        return GS_ERROR;
    }

    if (def->type == CONS_TYPE_PRIMARY || def->type == CONS_TYPE_UNIQUE) {
        (void)row_put_int32(ra, def->columns.count); /* < column count */
        if (def->columns.count > GS_MAX_INDEX_COLUMNS) {
            GS_THROW_ERROR(ERR_TOO_MANY_COLUMNS, "unique/primary key columns");
            return GS_ERROR;
        }

        col_list.str = str_cols;
        col_list.len = 0;
        for (i = 0; i < def->columns.count; i++) {
            column = (knl_index_col_def_t *)cm_galist_get(&def->columns, i);
            col_id = knl_get_column_id(dc, &column->name);
            cm_concat_int32(&col_list, GS_MAX_INDEX_COLUMNS * MAX_COLUMN_ID_STR_LEN, (uint32)col_id);
            if (i + 1 < def->columns.count) {
                if (cm_concat_string(&col_list, GS_MAX_INDEX_COLUMNS * MAX_COLUMN_ID_STR_LEN, ",") != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        }
        (void)row_put_text(ra, &col_list);               /* < column list  */
        (void)row_put_int32(ra, (int32)GS_INVALID_ID32); /* < index id of pk/unique */
        row_put_null(ra);                                /* < referenced table uid */
        row_put_null(ra);                                /* < referenced table id */
        row_put_null(ra);                                /* < referenced constraint name, the same as index name */
        row_put_null(ra);                                /* < check condition text */
        row_put_null(ra);                                /* < check condition data */
        (void)row_put_int32(ra, def->cons_state.option); /* < flags */
    } else if (def->type == CONS_TYPE_REFERENCE) {
        if (db_build_ref_desc(session, dc, def, ra) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (db_build_check_desc(session, dc, def, ra) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_fetch_sysconsdef_by_name(knl_session_t *session, knl_cursor_t *cursor,
                                            knl_cursor_action_t cursor_action,
                                            uint32 uid, uint32 oid, text_t *name, bool32 *is_found)
{
    *is_found = GS_FALSE;
    knl_open_sys_cursor(session, cursor, cursor_action, SYS_CONSDEF_ID, IX_SYS_CONSDEF003_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_CONSDEF003_REF_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_VARCHAR, name->str,
                     name->len, IX_COL_SYS_CONSDEF003_REF_CONS_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->eof) {
        *is_found = GS_TRUE;
    }
    return GS_SUCCESS;
}

static status_t db_fetch_sysconsdef_by_table(knl_session_t *session, knl_cursor_t *cursor,
                                             knl_cursor_action_t cursor_action,
                                             uint32 uid, uint32 oid, text_t *def, bool32 *find_flag)
{
    knl_scan_key_t *l_key = NULL;
    text_t cons_name;

    *find_flag = GS_FALSE;
    knl_open_sys_cursor(session, cursor, cursor_action, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    l_key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
        IX_COL_SYS_CONSDEF001_TABLE_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        cons_name.len = CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_NAME);
        cons_name.str = CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_NAME);

        if (cm_text_equal(&cons_name, def)) {
            *find_flag = GS_TRUE;
            return GS_SUCCESS;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t db_check_sys_name_exists(knl_session_t *session, knl_cursor_t *cursor,
                                         knl_dictionary_t *dc, text_t *name)
{
    bool32 is_found = GS_TRUE;
    errno_t ret;
    uint32 id = 0; // duplicate sys name id
    char *new_name = NULL;
    text_t new_sys_name;

    if (db_fetch_sysconsdef_by_name(session, cursor, CURSOR_ACTION_SELECT,
                                    dc->uid, dc->oid, name, &is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    new_name = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);
    while (is_found) {
        ret = sprintf_s(new_name, GS_NAME_BUFFER_SIZE, "%s_%d", name->str, id);
        knl_securec_check_ss(ret);

        cm_str2text_safe(new_name, (uint32)strlen(new_name), &new_sys_name);
        if (db_fetch_sysconsdef_by_name(session, cursor, CURSOR_ACTION_SELECT, dc->uid, dc->oid,
                                        &new_sys_name, &is_found) != GS_SUCCESS) {
            cm_pop(session->stack);
            return GS_ERROR;
        }
        id++;
    }

    if (id != 0) {
        ret = memcpy_sp(name->str, GS_NAME_BUFFER_SIZE, new_name, GS_NAME_BUFFER_SIZE);
        knl_securec_check(ret);
        name->len = new_sys_name.len;
    }
    cm_pop(session->stack);
    return GS_SUCCESS;
}

static status_t db_write_cons_def(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    if (def->cons_state.is_anonymous) {
        if (db_check_sys_name_exists(session, cursor, dc, &def->name) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);

    row_init(&ra, cursor->buf, GS_MAX_ROW_SIZE, ((table_t *)cursor->table)->desc.column_count);

    if (db_build_cons_desc(session, dc, def, &ra, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        int32 code = cm_get_error_code();
        if (code == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "constraint", T2S(&def->name));
        }
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static status_t db_update_cons_index(knl_session_t *session, knl_dictionary_t *dc, text_t *cons_name,
                                     uint32 index_id)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_update_info_t *info = NULL;
    bool32 is_found;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    if (db_fetch_sysconsdef_by_name(session, cursor, CURSOR_ACTION_UPDATE, dc->uid, dc->oid,
        cons_name, &is_found) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
    info = &cursor->update_info;
    row_init(&ra, info->data, GS_MAX_ROW_SIZE, 1);
    info->count = 1;
    info->columns[0] = CONSDEF_COL_INDEX_ID;
    (void)row_put_int32(&ra, index_id);
    cm_decode_row(info->data, info->offsets, info->lens, NULL);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static bool32 db_constraint_columns_match(galist_t *cols1, galist_t *cols2)
{
    uint32 i;
    knl_index_col_def_t *col_def1 = NULL;
    knl_index_col_def_t *col_def2 = NULL;

    if (cols1->count != cols2->count) {
        return GS_FALSE;
    }

    for (i = 0; i < cols1->count; i++) {
        col_def1 = (knl_index_col_def_t *)cm_galist_get(cols1, i);
        col_def2 = (knl_index_col_def_t *)cm_galist_get(cols2, i);
        if (!cm_text_equal(&col_def1->name, &col_def2->name)) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

/*
 * index include partkeys
 * Check current index include all partkeys or not.
 * @param index description, partitioned table
 */
static bool32 db_index_include_partkeys(uint32 idx_col_count, uint16 *idx_cols, part_table_t *part_table)
{
    uint32 i, j;

    for (i = 0; i < part_table->desc.partkeys; i++) {
        for (j = 0; j < idx_col_count; j++) {
            if (part_table->keycols[i].column_id == (uint32)idx_cols[j]) {
                break;
            }
        }

        if (j == idx_col_count) {
            return GS_FALSE;
        }
    }

    for (i = 0; i < part_table->desc.subpartkeys; i++) {
        for (j = 0; j < idx_col_count; j++) {
            if (part_table->sub_keycols[i].column_id == (uint32)idx_cols[j]) {
                break;
            }
        }

        if (j == idx_col_count) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

/*
 * Description     : allocate id for index
 * Input           : entity : dc entity of table
 * Input           : def : index definition
 * Output          : id : index id
 * Return Value    : status_t
 * History         : 1. 2017/4/26,  add description
 */
static status_t db_alloc_index_id(dc_entity_t *entity, knl_index_def_t *def, uint32 *id)
{
    uint32 i;
    index_t *index = NULL;
    uint8 map[GS_MAX_TABLE_INDEXES];
    uint32 max_indexes;
    errno_t err;

    max_indexes = GS_MAX_TABLE_INDEXES;
    if (entity->table.index_set.total_count >= GS_MAX_TABLE_INDEXES) {
        GS_THROW_ERROR(ERR_TOO_MANY_INDEXES, T2S(&def->user), T2S_EX(&def->table));
        return GS_ERROR;
    }

    err = memset_sp(map, max_indexes, 0, max_indexes);
    knl_securec_check(err);

    for (i = 0; i < entity->table.index_set.total_count; i++) {
        index = entity->table.index_set.items[i];
        map[index->desc.id] = 1;
    }

    for (i = 0; i < GS_MAX_TABLE_INDEXES; i++) {
        if (map[i] == 0) {
            *id = i;
            break;
        }
    }

    return GS_SUCCESS;
}

/*
 * Description     : check if index columns of two index exactly match
 * Input           : desc1 : description of index1
 * Input           : desc1 : description of index2
 * Output          : NA
 * Return Value    : bool32 : GS_TRUE if matched
 * History         : 1. 2017/4/26,  add description
 */
bool32 db_index_columns_matched(knl_session_t *session, knl_index_desc_t *desc, dc_entity_t *entity,
                                knl_handle_t def_cols, uint32 col_count, uint16 *columns)
{
    uint32 i;
    knl_index_col_def_t *index_col = NULL;
    knl_column_t *index_col2 = NULL;
    galist_t *def_columns = NULL;

    if (desc->column_count != col_count) {
        return GS_FALSE;
    }

    for (i = 0; i < desc->column_count; i++) {
        if (desc->is_func && desc->columns[i] >= DC_VIRTUAL_COL_START) {
            knl_panic_log(def_cols != NULL, "def_cols is NULL, panic info: table %s index %s",
                          entity->table.desc.name, desc->name);
            def_columns = (galist_t *)def_cols;
            index_col = (knl_index_col_def_t *)cm_galist_get(def_columns, i);
            if (!index_col->is_func) {
                return GS_FALSE;
            }
            index_col2 = dc_get_column(entity, desc->columns[i]);

            /* compare 2 function index expression */
            if (g_knl_callback.compare_index_expr(session, &index_col->func_text,
                                                  &index_col2->default_text) == GS_FALSE) {
                return GS_FALSE;
            }
        } else {
            if (desc->columns[i] != columns[i]) {
                return GS_FALSE;
            }
        }
    }

    return GS_TRUE;
}

static status_t db_create_virtual_icol(knl_session_t *session, knl_dictionary_t *dc,
                                       knl_index_col_def_t *index_col, uint32 v_col_id, knl_column_t *arg_column)
{
    knl_cursor_t *cursor = NULL;
    char col_name[GS_NAME_BUFFER_SIZE];
    knl_column_t vcolumn;
    errno_t ret;

    vcolumn.name = col_name;
    vcolumn.datatype = index_col->datatype;
    vcolumn.uid = dc->uid;
    vcolumn.table_id = dc->oid;
    vcolumn.id = v_col_id;
    vcolumn.size = index_col->size;
    vcolumn.nullable = index_col->nullable;
    vcolumn.flags = (KNL_COLUMN_FLAG_HIDDEN | KNL_COLUMN_FLAG_VIRTUAL);
    if (KNL_COLUMN_IS_CHARACTER(arg_column)) {
        COLUMN_SET_CHARACTER(&vcolumn);
    }
    vcolumn.default_text = index_col->func_text;

    ret = snprintf_s(col_name, GS_NAME_BUFFER_SIZE, GS_MAX_NAME_LEN, "SYS_NC%u$_%u", v_col_id, arg_column->id);
    knl_securec_check_ss(ret);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    if (db_write_syscolumn(session, cursor, &vcolumn) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static void db_alloc_vcol_id(dc_entity_t *entity, uint32 *vcol_id)
{
    knl_column_t *column = NULL;

    while (*vcol_id < entity->max_virtual_cols + DC_VIRTUAL_COL_START) {
        column = dc_get_column(entity, *vcol_id);

        if (column == NULL) {
            return;
        }
        (*vcol_id)++;
    }
}

static status_t db_prepare_idx_cols(knl_session_t *session, knl_index_def_t *def, knl_dictionary_t *dc,
                                    knl_index_desc_t *desc)
{
    knl_column_t *column = NULL;
    knl_index_col_def_t *index_col = NULL;
    gs_type_t type;
    uint16 col_size;
    dc_entity_t *entity = DC_ENTITY(dc);
    uint32 vcol_id = DC_VIRTUAL_COL_START;
    bool32 is_pcr = (desc->cr_mode == CR_PAGE);
    uint32 key_size = is_pcr ? (sizeof(pcrb_key_t) + sizeof(pcrb_dir_t)) :
                      (sizeof(btree_key_t) + sizeof(btree_dir_t));
    uint16 key_size_limit;
    bool32 is_lob = GS_FALSE;

    db_alloc_vcol_id(entity, &vcol_id);

    for (uint32 i = 0; i < desc->column_count; i++) {
        index_col = (knl_index_col_def_t *)cm_galist_get(&def->columns, i);
        desc->columns[i] = knl_get_column_id(dc, &index_col->name);

        if (desc->columns[i] == GS_INVALID_ID16) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->user), T2S_EX(&index_col->name));
            return GS_ERROR;
        }
        column = dc_get_column(entity, desc->columns[i]);
        if (KNL_COLUMN_IS_ARRAY(column)) {
            GS_THROW_ERROR(ERR_INDEX_ON_ARRAY_FIELD, column->name);
            return GS_ERROR;
        }

        if (index_col->is_func) {
            desc->is_func = GS_TRUE;
            desc->columns[i] = vcol_id;
            type = index_col->datatype;
            col_size = index_col->size;
            index_col->nullable = column->nullable;

            if (db_create_virtual_icol(session, dc, index_col, vcol_id, column) != GS_SUCCESS) {
                return GS_ERROR;
            }
            vcol_id++;
            db_alloc_vcol_id(entity, &vcol_id);
            is_lob = GS_IS_LOB_TYPE(type);
        } else {
            desc->columns[i] = knl_get_column_id(dc, &index_col->name);

            if (desc->columns[i] == GS_INVALID_ID16) {
                GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->user), T2S_EX(&index_col->name));
                return GS_ERROR;
            }

            column = dc_get_column(entity, desc->columns[i]);

            type = column->datatype;
            col_size = column->size;
            is_lob = COLUMN_IS_LOB(column);
        }

        if (is_lob) {
            GS_THROW_ERROR(ERR_CREATE_INDEX_ON_TYPE, get_datatype_name_str(type));
            return GS_ERROR;
        }

        key_size += btree_max_column_size(type, col_size, is_pcr);
    }

    if (session->kernel->attr.enable_idx_key_len_check) {
        key_size_limit = btree_max_allowed_size(session, desc);
        if (key_size > key_size_limit) {
            GS_THROW_ERROR(ERR_MAX_KEYLEN_EXCEEDED, key_size_limit);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static inline bool32 part_check_index_encrypt_allowed(knl_session_t *session, uint32 table_space_id, space_t *space)
{
    bool32 is_encrypt_table = SPACE_IS_ENCRYPT(SPACE_GET(table_space_id));
    bool32 is_encrypt_index = SPACE_IS_ENCRYPT(space);
    if (is_encrypt_table != is_encrypt_index) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

static status_t db_check_spaces_compatable(knl_session_t *session, text_t *space_name,
    space_t *parent_space)
{
    uint32 space_id;
    if (spc_get_space_id(session, space_name, &space_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    space_t *space = SPACE_GET(space_id);

    if (!IS_SWAP_SPACE(parent_space) && IS_SWAP_SPACE(space)) {
        GS_THROW_ERROR(ERR_PERMANENTOBJ_IN_TEMPSPACE);
        return GS_ERROR;
    }

    if (IS_SWAP_SPACE(parent_space) && !IS_SWAP_SPACE(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create temporary object", "non-swap object");
        return GS_ERROR;
    }

    if (IS_UNDO_SPACE(space)) {
        GS_THROW_ERROR(ERR_MISUSE_UNDO_SPACE, T2S(space_name));
        return GS_ERROR;
    }

    if (SPACE_IS_NOLOGGING(parent_space)) {
        if (SPACE_IS_LOGGING(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create logging object", "nologging parent object");
            return GS_ERROR;
        }
    } else {
        if (SPACE_IS_NOLOGGING(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create nologging object", "logging parent object");
            return GS_ERROR;
        }
    }

    if (!part_check_index_encrypt_allowed(session, parent_space->ctrl->id, space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create encrypt object", "non-encrypt parent object \
or create non-encrypt object on encrypt parent object.");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_check_idxpart_space_compatable(knl_session_t *session, knl_index_def_t *def,
    knl_index_desc_t *index_desc)
{
    uint32 part_count = def->part_def->parts.count;
    space_t *index_space = SPACE_GET(index_desc->space_id);

    for (uint32 i = 0; i < part_count; i++) {
        knl_part_def_t *part_def = (knl_part_def_t *)cm_galist_get(&def->part_def->parts, i);
        if (part_def->space.len == 0) {
            continue;
        }

        if (db_check_spaces_compatable(session, &part_def->space, index_space) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!def->part_def->is_composite) {
            continue;
        }

        uint32 subpart_count = part_def->subparts.count;
        for (uint32 j = 0; j < subpart_count; j++) {
            knl_part_def_t *subpart_def = (knl_part_def_t *)cm_galist_get(&part_def->subparts, j);
            if (subpart_def->space.len == 0) {
                continue;
            }

            if (db_check_spaces_compatable(session, &subpart_def->space, index_space) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_check_index_space(knl_session_t *session, knl_dictionary_t *dc, table_t *table,
                                     knl_index_def_t *def, knl_index_desc_t *desc)
{
    // if the space name is null, then use the default space
    if (def->space.len == 0) {
        desc->space_id = table->desc.space_id;
        if (!def->parted || (def->part_def == NULL)) {
            return GS_SUCCESS;
        }

        if (db_check_idxpart_space_compatable(session, def, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        return GS_SUCCESS;
    }

    desc->is_stored = GS_TRUE;
    space_t *table_space = SPACE_GET(table->desc.space_id);
    if (db_check_spaces_compatable(session, &def->space, table_space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_get_space_id(session, &def->space, &desc->space_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_check_by_uid(session, &def->space, desc->space_id, table->desc.uid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (table->desc.parted) {
        if (!def->parted || (def->part_def == NULL)) {
            return GS_SUCCESS;
        }

        if (db_check_idxpart_space_compatable(session, def, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}
/*
 * Description     : check if index columns of two index exactly match
 * Input           : desc1 : description of index1
 * Input           : desc1 : description of index2
 * Output          : NA
 * Return Value    : bool32 : GS_TRUE if matched
 * History         : 1. 2017/4/26,  add description
 */
static status_t db_verify_index_def(knl_session_t *session, knl_dictionary_t *dc, knl_index_def_t *def,
                                    knl_index_desc_t *desc)
{
    index_t *index = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    (void)cm_text2str(&def->name, desc->name, GS_NAME_BUFFER_SIZE);

    if (db_check_index_space(session, dc, table, def, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!dc_get_user_id(session, &def->user, &desc->uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&def->user));
        return GS_ERROR;
    }

    if (def->columns.count > GS_MAX_INDEX_COLUMNS) {
        GS_THROW_ERROR(ERR_TOO_MANY_COLUMNS, "index columns");
        return GS_ERROR;
    }

    if (def->parted && !table->desc.parted) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "could not create partition index on no partitioned table");
        return GS_ERROR;
    }

    desc->table_id = entity->table.desc.id;
    desc->primary = def->primary;
    desc->unique = def->unique;
    desc->type = def->type;
    desc->column_count = def->columns.count;
    desc->initrans = def->initrans;
    desc->cr_mode = (def->cr_mode == GS_INVALID_ID8) ? table->desc.cr_mode : def->cr_mode;
    desc->org_scn = db_inc_scn(session);
    desc->entry = INVALID_PAGID;
    desc->parted = def->parted;
    desc->pctfree = (def->pctfree == GS_INVALID_ID32) ? table->desc.pctfree : def->pctfree;

    if (desc->initrans == 0) {
        desc->initrans = cm_text_str_equal_ins(&def->user, "SYS") ? GS_INI_TRANS : session->kernel->attr.initrans;
    }

    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        desc->cr_mode = CR_ROW;
    }

    if (db_prepare_idx_cols(session, def, dc, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (desc->parted && (desc->primary || desc->unique)) {
        if (!db_index_include_partkeys(desc->column_count, desc->columns, table->part_table)) {
            GS_THROW_ERROR(ERR_LOCAL_UNIQUE_INDEX);
            return GS_ERROR;
        }
    }

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];

        if (desc->primary && index->desc.primary) {
            GS_THROW_ERROR(ERR_PRIMRY_KEY_ALREADY_EXISTS);
            return GS_ERROR;
        }

        if (db_index_columns_matched(session, &index->desc, entity, &def->columns, desc->column_count, desc->columns)) {
            GS_THROW_ERROR(ERR_COLUMN_ALREADY_INDEXED, index->desc.name);
            return GS_ERROR;
        }
    }

    desc->max_key_size = btree_max_allowed_size(session, desc);
    return GS_SUCCESS;
}

static status_t db_check_null_in_idxcols(knl_session_t *session, knl_cursor_t *cursor, knl_index_desc_t desc)
{
    uint32 i;
    uint32 col_id;
    knl_column_t *column = NULL;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        idx_decode_row(session, cursor, cursor->offsets, cursor->lens, &cursor->data_size);
        for (i = 0; i < desc.column_count; i++) {
            col_id = desc.columns[i];
            if (CURSOR_COLUMN_SIZE(cursor, i) == GS_NULL_VALUE_LEN) {
                column = dc_get_column(entity, col_id);
                GS_THROW_ERROR(ERR_COLUMN_NOT_NULL, column->name);
                return GS_ERROR;
            }
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t parttable_check_null_in_index(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    knl_index_desc_t desc)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        cursor->part_loc.part_no = i;
        if (!IS_PARENT_TABPART(&table_part->desc)) {
            cursor->part_loc.subpart_no = GS_INVALID_ID32;
            if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                return GS_ERROR;
            }
            cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

            if (db_check_null_in_idxcols(session, cursor, desc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            cursor->part_loc.subpart_no = j;
            if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                return GS_ERROR;
            }
            cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

            if (db_check_null_in_idxcols(session, cursor, desc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_check_null_in_index(knl_session_t *session, knl_dictionary_t *dc, knl_index_desc_t desc)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_INDEX;
    cursor->index_slot = desc.slot;
    cursor->index_only = GS_TRUE;

    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    table_t *table = (table_t *)(cursor->table);
    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

    knl_init_index_scan(cursor, GS_FALSE);

    uint32 none_nullable_cnts = 0;
    for (uint32 i = 0; i < desc.column_count; i++) {
        uint16 col_id = desc.columns[i];
        knl_column_t *knl_col = knl_get_column(dc->handle, col_id);

        if (!knl_col->nullable) {
            none_nullable_cnts++;
        }

        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, i);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, i);
    }

    if (none_nullable_cnts == desc.column_count) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    if (!IS_PART_TABLE(table)) {
        if (db_check_null_in_idxcols(session, cursor, desc) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    } else {
        if (parttable_check_null_in_index(session, cursor, dc, desc) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_enforce_index(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def,
                                 index_t *index)
{
    knl_alindex_def_t rebuild_def;
    table_t *table = DC_TABLE(dc);

    if (index->desc.is_func) {
        GS_THROW_ERROR(ERR_ENFORCE_INDEX);
        return GS_ERROR;
    }

    if (index->desc.is_enforced) {
        GS_THROW_ERROR(ERR_COLUMN_ALREADY_INDEXED, index->desc.name);
        return GS_ERROR;
    }

    if (index->desc.parted) {
        if (!db_index_include_partkeys(index->desc.column_count, index->desc.columns, table->part_table)) {
            GS_THROW_ERROR(ERR_LOCAL_UNIQUE_INDEX);
            return GS_ERROR;
        }
    }

    if (index->desc.unique) {
        return db_check_null_in_index(session, dc, index->desc);
    }

    rebuild_def.type = ALINDEX_TYPE_REBUILD;
    cm_str2text(index->desc.name, &rebuild_def.name);
    rebuild_def.rebuild.is_online = GS_FALSE;
    rebuild_def.rebuild.parallelism = 0;
    rebuild_def.rebuild.specified_parts = 0;
    rebuild_def.rebuild.space.len = 0;
    rebuild_def.rebuild.space.str = NULL;
    rebuild_def.rebuild.pctfree = index->desc.pctfree;
    rebuild_def.rebuild.cr_mode = (def->index.cr_mode == GS_INVALID_ID8) ? index->desc.cr_mode : def->index.cr_mode;

    if (table->desc.type == TABLE_TYPE_TRANS_TEMP || table->desc.type == TABLE_TYPE_SESSION_TEMP) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "would cause rebuiding index, which", "temporary table");
        return GS_ERROR;
    }

    if (db_alter_index_rebuild(session, &rebuild_def, dc, index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_set_column_nullable(knl_session_t *session, uint32 uid, uint32 table_id, uint32 col_id,
                                       bool32 nullable)
{
    knl_cursor_t *cursor = NULL;
    knl_update_info_t *info = NULL;
    row_assist_t ra;
    bool32 col_nullable = GS_FALSE;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_COLUMN_ID, IX_SYS_COLUMN_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &col_id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
    col_nullable = *(bool32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_NULLABLE);
    if (col_nullable == nullable) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    info = &cursor->update_info;
    row_init(&ra, info->data, HEAP_MAX_ROW_SIZE, 1);
    info->count = 1;
    info->columns[0] = SYS_COLUMN_COL_NULLABLE;
    (void)row_put_int32(&ra, nullable);
    cm_decode_row(info->data, info->offsets, info->lens, NULL);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_find_matched_index(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def,
                                      uint16 *idx_cols, knl_index_def_t *idx_def, index_t **index_ptr, bool32 *matched)
{
    uint32 column_count = def->columns.count;
    table_t *table;
    index_t *index = *index_ptr;

    table = DC_TABLE(dc);
    if (def->index.use_existed) {
        index = dc_find_index_by_name(DC_ENTITY(dc), &idx_def->name);
        if (index == NULL) {
            GS_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&idx_def->user), T2S_EX(&idx_def->name));
            return GS_ERROR;
        }

        if (!db_index_columns_matched(session, &index->desc, DC_ENTITY(dc), &def->columns, column_count, idx_cols)) {
            GS_THROW_ERROR(ERR_INDEX_NOT_SUITABLE);
            return GS_ERROR;
        }

        *matched = GS_TRUE;
        *index_ptr = index;
    } else {
        for (uint32 i = 0; i < table->index_set.total_count; i++) {
            index = table->index_set.items[i];
            if (db_index_columns_matched(session, &index->desc, DC_ENTITY(dc),
                                         &def->columns, column_count, idx_cols)) {
                *matched = GS_TRUE;
                *index_ptr = index;
                break;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_create_index_in_clause(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def,
                                          uint16 *idx_cols, uint32 *index_id)
{
    uint32 i;
    table_t *table;
    uint32 column_count;
    knl_index_col_def_t *index_col = NULL;

    table = DC_TABLE(dc);
    column_count = def->columns.count;

    if (!cm_text_str_equal(&def->index.table, table->desc.name)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid table name.");
        return GS_ERROR;
    }

    for (i = 0; i < def->index.columns.count; i++) {
        index_col = (knl_index_col_def_t *)cm_galist_get(&def->index.columns, i);
        if (index_col->is_func) {
            GS_THROW_ERROR(ERR_ENFORCE_INDEX);
            return GS_ERROR;
        }
    }

    if (!db_constraint_columns_match(&def->index.columns, &def->columns)) {
        GS_THROW_ERROR(ERR_INDEX_NOT_SUITABLE);
        return GS_ERROR;
    }

    if (def->index.parted && IS_PART_TABLE(table)) {
        if (!db_index_include_partkeys(column_count, idx_cols, table->part_table)) {
            GS_THROW_ERROR(ERR_LOCAL_UNIQUE_INDEX);
            return GS_ERROR;
        }
    }

    return db_create_index(session, &def->index, dc, GS_FALSE, index_id);
}

static status_t db_create_cons_index(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def,
                                     uint32 *index_id)
{
    table_t *table = DC_TABLE(dc);
    uint32 i;
    knl_index_col_def_t *col_def = NULL;
    uint32 column_count;
    index_t *index = NULL;
    bool32 matched = GS_FALSE;
    knl_index_def_t idx_def;
    errno_t err;
    uint16 *idx_cols = NULL;
    knl_column_t *col_tmp = NULL;
    status_t ret;

    knl_panic_log(def->type == CONS_TYPE_PRIMARY || def->type == CONS_TYPE_UNIQUE,
                  "type record on def is neither primary nor unique, panic info: table %s", table->desc.name);
    if (def->index.online) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create constraint index online");
        return GS_ERROR;
    }

    column_count = def->columns.count;
    idx_cols = (uint16 *)cm_push(session->stack, column_count * sizeof(uint16));

    for (i = 0; i < column_count; i++) {
        col_def = (knl_index_col_def_t *)cm_galist_get(&def->columns, i);
        if (col_def->is_func) {
            GS_THROW_ERROR(ERR_ENFORCE_INDEX);
            cm_pop(session->stack);
            return GS_ERROR;
        }

        idx_cols[i] = knl_get_column_id(dc, &col_def->name);
        if (idx_cols[i] == GS_INVALID_ID16) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, table->desc.name, T2S(&col_def->name));
            cm_pop(session->stack);
            return GS_ERROR;
        }

        /* check datatype of this column */
        col_tmp = knl_get_column(dc->handle, idx_cols[i]);
        if (col_tmp->datatype == GS_TYPE_TIMESTAMP_TZ) {
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
                "column of datatype TIMESTAMP WITH TIME ZONE cannot be unique or a primary key");
            cm_pop(session->stack);
            return GS_ERROR;
        }
    }

    /* if index is primary key, set columns of index not nullable */
    if (def->type == CONS_TYPE_PRIMARY) {
        for (i = 0; i < column_count; i++) {
            if (GS_SUCCESS != db_set_column_nullable(session, table->desc.uid, table->desc.id,
                                                     (uint32)idx_cols[i], GS_FALSE)) {
                cm_pop(session->stack);
                return GS_ERROR;
            }
        }
    }

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];

        if (def->type == CONS_TYPE_PRIMARY && index->desc.primary) {
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_PRIMRY_KEY_ALREADY_EXISTS);
            return GS_ERROR;
        }
    }

    /* in case of constraint state clause containing a create index clause */
    if (def->index.columns.count > 0) {
        ret = db_create_index_in_clause(session, dc, def, idx_cols, index_id);
        cm_pop(session->stack);
        return ret;
    } else {
        err = memcpy_sp(&idx_def, sizeof(knl_index_def_t), &def->index, sizeof(knl_index_def_t));
        knl_securec_check(err);
        err = memcpy_sp(&idx_def.columns, sizeof(galist_t), &def->columns, sizeof(galist_t));
        knl_securec_check(err);
    }

    if (db_find_matched_index(session, dc, def, idx_cols, &idx_def, &index, &matched) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    if (matched) {
        *index_id = index->desc.id;
        cm_pop(session->stack);
        return db_enforce_index(session, dc, def, index);
    }
    cm_pop(session->stack);
    return db_create_index(session, &idx_def, dc, GS_TRUE, index_id);
}

static status_t db_create_cons(knl_session_t *session, knl_dictionary_t *dc, knl_constraint_def_t *def)
{
    knl_index_def_t *index = NULL;
    dc_user_t *user = NULL;
    table_t *table = DC_TABLE(dc);
    uint32 index_id = GS_INVALID_ID32;

    if (db_write_cons_def(session, dc, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (def->type == CONS_TYPE_PRIMARY || def->type == CONS_TYPE_UNIQUE) {
        if (dc_open_user_by_id(session, dc->uid, &user) != GS_SUCCESS) {
            return GS_ERROR;
        }

        index = &def->index;
        if (index->user.len == 0) {
            cm_str2text(user->desc.name, &index->user);
        }
        if (index->table.len == 0) {
            cm_str2text(table->desc.name, &index->table);
        }
        if (index->name.len == 0) {
            index->name = def->name;
        }

        if (db_create_cons_index(session, dc, def, &index_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return db_update_cons_index(session, dc, &def->name, index_id);
}

static status_t db_create_constraints(knl_session_t *session, knl_table_desc_t *desc, knl_table_def_t *def)
{
    uint32 i;
    knl_constraint_def_t *cons_def = NULL;
    knl_dictionary_t dc;

    for (i = 0; i < def->constraints.count; i++) {
        if (dc_open_table_private(session, desc->uid, desc->id, &dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
        cons_def = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        knl_panic_log(cons_def->name.len != 0,
                      "name's len record on cons_def is zero, panic info: table %s", desc->name);

        if (cons_def->type == CONS_TYPE_REFERENCE) {
            dc_close_table_private(&dc);
            continue;
        }

        if (db_create_cons(session, &dc, cons_def) != GS_SUCCESS) {
            dc_close_table_private(&dc);
            return GS_ERROR;
        }
        dc_close_table_private(&dc);
    }

    for (i = 0; i < def->constraints.count; i++) {
        if (dc_open_table_private(session, desc->uid, desc->id, &dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
        cons_def = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        knl_panic_log(cons_def->name.len != 0,
                      "name's len record on cons_def is zero, panic info: table %s", desc->name);

        if (cons_def->type != CONS_TYPE_REFERENCE) {
            dc_close_table_private(&dc);
            continue;
        }

        if (db_create_cons(session, &dc, cons_def) != GS_SUCCESS) {
            dc_close_table_private(&dc);
            return GS_ERROR;
        }
        dc_close_table_private(&dc);
    }

    return GS_SUCCESS;
}

static status_t db_load_sys_dc(knl_session_t *session, knl_table_def_t *def, table_t *table)
{
    knl_dictionary_t dc;

    dc_ready(session, table->desc.uid, table->desc.id);

    if (dc_open(session, &def->schema, &def->name, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (SYNONYM_EXIST(&dc)) {
        dc_close(&dc);
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->schema), T2S_EX(&def->name));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

#ifdef Z_SHARDING
status_t db_query_consis_hash_strategy(knl_session_t *session, uint32 *slice_count, uint32 *group_count,
    knl_cursor_t *cursor, bool32 *is_found)
{
    *is_found = GS_FALSE;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_CONSIS_HASH_STRATEGY_ID,
        IX_SYS_CONSISTENT_HASH_STRATEGY001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        slice_count, sizeof(uint32), IX_COL_SYS_CONSIS_HASH_STRATEGY001_SLICE_COUNT);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        group_count, sizeof(uint32), IX_COL_SYS_CONSIS_HASH_STRATEGY001_GROUP_COUNT);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    *is_found = !cursor->eof;
    return GS_SUCCESS;
}

status_t db_insert_consis_hash_strategy(knl_session_t *session, table_t *table)
{
    knl_table_desc_t *desc = &table->desc;
    status_t status;
    row_assist_t ra;
    knl_column_t *lob_column = NULL;

    bool32 is_found = GS_FALSE;

    if (IS_SYS_TABLE(table) || desc->slice_count == 0) {
        return GS_SUCCESS;
    }
    CM_SAVE_STACK(session->stack);
    do {
        knl_cursor_t *cursor = knl_push_cursor(session);
        status = db_query_consis_hash_strategy(session, &desc->slice_count, &desc->group_count, cursor, &is_found);
        GS_BREAK_IF_ERROR(status);
        GS_BREAK_IF_TRUE(is_found);
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_CONSIS_HASH_STRATEGY_ID,
            IX_SYS_CONSISTENT_HASH_STRATEGY001_ID);
        row_init(&ra, cursor->buf, KNL_MAX_ROW_SIZE, SYS_CONSIS_HASH_STRATEGY_COLUMN_COUNT);
        (void)row_put_int32(&ra, desc->slice_count);
        (void)row_put_int32(&ra, desc->group_count);
        lob_column = knl_get_column(cursor->dc_entity, SYS_CONSIS_HASH_STRATEGY_COL_BUCKETS);
        status = knl_row_put_lob(session, cursor, lob_column, &desc->distribute_buckets, &ra);
        GS_BREAK_IF_ERROR(status);
        status = knl_internal_insert(session, cursor);
    } while (0);

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t db_insert_distribute_strategy(knl_session_t *session, table_t *table)
{
    knl_cursor_t *cursor = NULL;
    status_t status;
    knl_table_desc_t *desc = &table->desc;

    if (IS_SYS_TABLE(table)) {
        return GS_SUCCESS;
    }

    if (desc->distribute_data.size == 0) {
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_DISTRIBUTE_STRATEGY_ID,
                        IX_SYS_DISTRIBUTE_STRATEGY001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->uid, sizeof(uint32), DISTRIBUTED_STRATEGY_COL_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->id, sizeof(uint32), DISTRIBUTED_STRATEGY_COL_TABLE);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        status = db_insert_distribute_strategy_inner(session, cursor, desc);
    } else {
        GS_LOG_DEBUG_WAR("distribute strategy table is not empty, user = %d, table_id = %d", desc->uid, desc->id);
        if (GS_SUCCESS != db_delete_distribute_strategy(session, table)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        status = db_insert_distribute_strategy_inner(session, cursor, desc);
    }

    CM_RESTORE_STACK(session->stack);

    return status;
}

status_t db_delete_distribute_strategy(knl_session_t *session, table_t *table)
{
    knl_cursor_t *cursor = NULL;
    knl_table_desc_t *desc = &table->desc;

    if (IS_SYS_TABLE(table)) {
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_DISTRIBUTE_STRATEGY_ID,
                        IX_SYS_DISTRIBUTE_STRATEGY001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->uid, sizeof(uint32), DISTRIBUTED_STRATEGY_COL_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &desc->id, sizeof(uint32), DISTRIBUTED_STRATEGY_COL_TABLE);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        GS_LOG_DEBUG_WAR("cannot find the distribute strategy, user = %d, table_id = %d", desc->uid, desc->id);
        return GS_ERROR;
    }

    if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_insert_distribute_strategy_inner(knl_session_t *session, knl_cursor_t *cursor,
                                                    knl_table_desc_t *desc)
{
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_DISTRIBUTE_STRATEGY_ID,
                        IX_SYS_DISTRIBUTE_STRATEGY001_ID);

    row_init(&ra, cursor->buf, KNL_MAX_ROW_SIZE, DISTRIBUTED_STRATEGY_COLUMN_COUNT);
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->id);
    (void)row_put_bin(&ra, &desc->distribute_data);
    if (desc->distribute_type == distribute_hash || desc->distribute_type == distribute_hash_basic) {
        // write blob
        knl_column_t *lob_column;

        lob_column = knl_get_column(cursor->dc_entity, DISTRIBUTED_STRATEGY_COL_BUCKETS);

        if (knl_row_put_lob(session, cursor, lob_column, &desc->distribute_buckets, &ra) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        (void)row_put_null(&ra);
    }
    (void)row_put_int32(&ra, desc->slice_count);
    (void)row_put_int32(&ra, 0);
    (void)row_put_text(&ra, &desc->distribute_text);
    return knl_internal_insert(session, cursor);
}
#endif

static status_t db_write_sys_external(knl_session_t *session, knl_cursor_t *cursor, uint32 uid,
                                      uint32 table_id, knl_table_def_t *def)
{
    row_assist_t ra;
    table_t *table = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_EXTERNAL_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    /* check string length */
    if (def->external_def.directory.len >= GS_FILE_NAME_BUFFER_SIZE) {
        GS_THROW_ERROR(ERR_BUFFER_OVERFLOW, def->external_def.directory.len, GS_FILE_NAME_BUFFER_SIZE - 1);
        return GS_ERROR;
    }

    if (def->external_def.location.len >= GS_MAX_NAME_LEN) {
        GS_THROW_ERROR(ERR_SQL_TOO_LONG, def->external_def.location.len, GS_MAX_NAME_LEN - 1);
        return GS_ERROR;
    }

    row_init(&ra, cursor->buf, GS_MAX_ROW_SIZE, table->desc.column_count);
    row_put_int32(&ra, table_id);                              // base table id
    row_put_int32(&ra, def->external_def.external_type);       // external type
    row_put_text(&ra, &def->external_def.directory);           // directory
    row_put_text(&ra, &def->external_def.location);            // location
    row_put_int32(&ra, def->external_def.records_delimiter);   // records delimeters
    row_put_int32(&ra, def->external_def.fields_terminator);   // fields seperator
    row_put_int32(&ra, uid);                                   // user id

    return knl_internal_insert(session, cursor);
}

static status_t db_construct_columns(knl_session_t *session, knl_cursor_t *cursor, knl_table_def_t *def, table_t *table)
{
    knl_column_def_t *column_def = NULL;
    knl_column_t column;
    space_t *space = SPACE_GET(table->desc.space_id);
    bool32 is_encrypt = SPACE_IS_ENCRYPT(space);

    column.name = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);

    for (uint32 i = 0; i < def->columns.count; i++) {
        column_def = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        if (is_encrypt && (!GS_IS_LOB_TYPE(column_def->typmod.datatype) && !column_def->typmod.is_array)) {
            if (column_def->typmod.size > GS_MAX_COLUMN_SIZE - GS_KMC_MAX_CIPHER_SIZE) {
                cm_pop(session->stack);
                GS_THROW_ERROR(ERR_ENCRYPTION_NOT_SUPPORT_DDL, "column size should less than",
                    GS_MAX_COLUMN_SIZE - GS_KMC_MAX_CIPHER_SIZE);
                return GS_ERROR;
            }
        }

        db_convert_column_def(&column, table->desc.uid, table->desc.id, column_def, NULL, i);
        if (def->type != TABLE_TYPE_HEAP && KNL_COLUMN_IS_ARRAY(&column)) {
            GS_THROW_ERROR(ERR_WRONG_TABLE_TYPE);
            cm_pop(session->stack);
            return GS_ERROR;
        }
        if (COLUMN_IS_LOB(&column)) {
            if (def->type == TABLE_TYPE_EXTERNAL) {
                GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "lob type", "external organized table");
                cm_pop(session->stack);
                return GS_ERROR;
            }

            if (def->type == TABLE_TYPE_SESSION_TEMP || def->type == TABLE_TYPE_TRANS_TEMP) {
                if (column.datatype == GS_TYPE_CLOB || column.datatype == GS_TYPE_IMAGE) {
                    column.datatype = GS_TYPE_VARCHAR;
                    column.size = TEMP_LOB_TO_CHAR_LENGTH;
                } else {
                    column.datatype = GS_TYPE_RAW;
                    column.size = TEMP_LOB_TO_CHAR_LENGTH;
                }
            } else {
                if (db_create_lob(session, table, &column, def) != GS_SUCCESS) {
                    cm_pop(session->stack);
                    return GS_ERROR;
                }
            }
        }

        if (db_write_syscolumn(session, cursor, &column) != GS_SUCCESS) {
            cm_pop(session->stack);
            return GS_ERROR;
        }

        if (column_def->is_comment) {
            knl_comment_def_t comment_def;
            comment_def.uid = column.uid;
            comment_def.id = column.table_id;
            comment_def.column_id = column.id;
            comment_def.comment = column_def->comment;
            comment_def.type = COMMENT_ON_COLUMN;
            if (GS_SUCCESS != db_comment_on(session, &comment_def)) {
                cm_pop(session->stack);
                return GS_ERROR;
            }
        }
    }

    cm_pop(session->stack);
    return GS_SUCCESS;
}

static status_t db_create_external_table(knl_session_t *session, knl_cursor_t *cursor, knl_table_def_t *def,
    table_t *table)
{
    bool32 dire_exists = GS_FALSE;

    if (db_fetch_directory_path(session, T2S(&def->external_def.directory), NULL, 0, &dire_exists) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!dire_exists) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "directory", T2S(&def->external_def.directory));
        return GS_ERROR;
    }

    return db_write_sys_external(session, cursor, table->desc.uid, table->desc.id, def);
}

status_t db_create_table(knl_session_t *session, knl_table_def_t *def, table_t *table)
{
    knl_cursor_t *cursor = NULL;
    dc_user_t *user = NULL;
    errno_t err;

    if (DB_NOT_READY(session)) {
        GS_THROW_ERROR(ERR_NO_DB_ACTIVE);
        return GS_ERROR;
    }

    err = memset_sp(table, sizeof(table_t), 0, sizeof(table_t));
    knl_securec_check(err);

    if (db_init_table_desc(session, &table->desc, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table->desc.id = (table->desc.uid == 0) ? def->sysid : GS_INVALID_ID32;

    if (dc_open_user_by_id(session, table->desc.uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_create_table_entry(session, user, &table->desc) != GS_SUCCESS) {  // table id get from dc
        return GS_ERROR;
    }

    if (def->type == TABLE_TYPE_HEAP) {
        if (IS_SYS_TABLE(table)) {
            if (heap_create_segment(session, table) != GS_SUCCESS) {
                dc_free_broken_entry(session, table->desc.uid, table->desc.id);
                return GS_ERROR;
            }
            /*
             * reset storage initial size to 0 for sys table
             * storage parameter will not save to sys_storage for sys tables
             */
            table->desc.storage_desc.initial = 0;
        }
    }

    CM_SAVE_STACK(session->stack);

    // for creating table bug fix: cursor->row is null
    cursor = knl_push_cursor(session);
    cursor->row = (row_head_t *)cursor->buf;
    cursor->table = db_sys_table(SYS_TABLE_ID);
    cursor->is_valid = GS_TRUE;

    if (db_write_systable(session, cursor, &table->desc) != GS_SUCCESS) {
        dc_free_broken_entry(session, table->desc.uid, table->desc.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (table->desc.storaged && db_write_sysstorage(session, cursor, table->desc.org_scn,
        &table->desc.storage_desc) != GS_SUCCESS) {
        dc_free_broken_entry(session, table->desc.uid, table->desc.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (table->desc.compress) {
        if (db_write_syscompress(session, cursor, table->desc.space_id, table->desc.org_scn, table->desc.compress_algo,
            COMPRESS_OBJ_TYPE_TABLE) != GS_SUCCESS) {
            dc_free_broken_entry(session, table->desc.uid, table->desc.id);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

#ifdef Z_SHARDING
    if (db_insert_consis_hash_strategy(session, table) != GS_SUCCESS ||
        db_insert_distribute_strategy(session, table) != GS_SUCCESS) {
        dc_free_broken_entry(session, table->desc.uid, table->desc.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
#endif

    if (db_check_lob_storage_mode(session, def) != GS_SUCCESS) {
        dc_free_broken_entry(session, table->desc.uid, table->desc.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor->table = db_sys_table(SYS_COLUMN_ID);

    if (db_construct_columns(session, cursor, def, table) != GS_SUCCESS) {
        dc_free_broken_entry(session, table->desc.uid, table->desc.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (def->parted) {
        if (db_create_part_table(session, cursor, table, def) != GS_SUCCESS) {
            dc_free_broken_entry(session, table->desc.uid, table->desc.id);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (def->type == TABLE_TYPE_EXTERNAL) {
        if (db_create_external_table(session, cursor, def, table) != GS_SUCCESS) {
            dc_free_broken_entry(session, table->desc.uid, table->desc.id);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (def->constraints.count > 0) {
        if (db_create_constraints(session, &table->desc, def) != GS_SUCCESS) {
            dc_free_broken_entry(session, table->desc.uid, table->desc.id);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    if (def->sysid != GS_INVALID_ID32) {
        if (db_load_sys_dc(session, def, table) != GS_SUCCESS) {
            dc_free_broken_entry(session, table->desc.uid, table->desc.id);
            return GS_ERROR;
        }
    }

    session->stat.table_creates++;
    return GS_SUCCESS;
}

static status_t db_init_ltt_column(knl_column_t *column, uint32 uid, uint32 oid, knl_column_def_t *column_def,
                                   int id)
{
    errno_t ret;
    ret = memset_sp(column, sizeof(knl_column_t), 0, sizeof(knl_column_t));
    knl_securec_check(ret);

    column->id = id;
    column->uid = uid;
    column->table_id = oid;
    column->nullable = column_def->nullable;
    column->datatype = column_def->typmod.datatype;
    column->size = column_def->typmod.size;
    column->precision = column_def->typmod.precision;
    column->scale = column_def->typmod.scale;
    column->flags = 0;

    if (column->datatype == GS_TYPE_CLOB || column->datatype == GS_TYPE_IMAGE) {
        column->datatype = GS_TYPE_VARCHAR;
        column->size = TEMP_LOB_TO_CHAR_LENGTH;
    } else if (column->datatype == GS_TYPE_BLOB) {
        column->datatype = GS_TYPE_RAW;
        column->size = TEMP_LOB_TO_CHAR_LENGTH;
    }

    if (column_def->is_serial) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "ltt auto_increment");
        return GS_ERROR;
    }

    if (column_def->is_update_default) {
        COLUMN_SET_UPDATE_DEFAULT(column);
    }

    if (GS_IS_STRING_TYPE(column->datatype) && column_def->typmod.is_char) {
        COLUMN_SET_CHARACTER(column);
    }

    return GS_SUCCESS;
}

/*
 * realloc memory from dc context
 */
static status_t db_convert_ltt_column_def(knl_session_t *session, dc_entity_t *entity, knl_column_t *column,
                                          uint32 uid, uint32 oid, knl_column_def_t *column_def, int id)
{
    errno_t ret;

    // column name
    if (dc_copy_text2str(session, entity->memory, &column_def->name, &column->name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // default_text
    if (column_def->default_text.len == 0) {
        column->default_text.len = 0;
        column->default_text.str = NULL;
    } else {
        column->default_text.len = column_def->default_text.len;
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, column->default_text.len,
                         (void **)&column->default_text.str) != GS_SUCCESS) {
            return GS_ERROR;
        }
        ret = memcpy_sp(column->default_text.str, column->default_text.len, column_def->default_text.str,
                        column->default_text.len);
        knl_securec_check(ret);
    }

    // decode expr
    if (column->default_text.len != 0) {
        if (g_knl_callback.parse_default_from_text((knl_handle_t)session,
            (knl_handle_t)entity, (knl_handle_t)column, entity->memory,
            &column->default_expr, &column->update_default_expr, column->default_text) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_create_ltt_columns(knl_session_t *session, dc_entity_t *entity, knl_table_def_t *def,
                                      uint32 uid, uint32 oid)
{
    knl_table_desc_t *desc = &entity->table.desc;
    errno_t ret;

    entity->column_count = desc->column_count;
    if (dc_prepare_load_columns(session, entity) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->columns.count; i++) {
        knl_column_def_t *column_def = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        knl_column_t *column = NULL;
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory,
                         sizeof(knl_column_t), (void **)&column) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return GS_ERROR;
        }

        ret = memset_sp(column, sizeof(knl_column_t), 0, sizeof(knl_column_t));
        knl_securec_check(ret);

        if (db_init_ltt_column(column, desc->uid, desc->id, column_def, i) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_convert_ltt_column_def(session, entity, column, desc->uid, desc->id, column_def, i) != GS_SUCCESS) {
            return GS_ERROR;
        }

        entity->column_groups[column->id / DC_COLUMN_GROUP_SIZE].columns[column->id % DC_COLUMN_GROUP_SIZE] = column;
        if (KNL_COLUMN_IS_UPDATE_DEFAULT(column)) {
            entity->has_udef_col = GS_TRUE;
        }

        estimate_row_len(&entity->table, column);
    }

    dc_create_column_index(entity);
    return GS_SUCCESS;
}

status_t db_create_ltt_index(knl_session_t *session, knl_index_def_t *def, knl_dictionary_t *dc,
                             bool32 need_fill_index)
{
    index_t *index = NULL;
    table_t *table;
    dc_entity_t *entity;
    knl_index_desc_t *desc = NULL;
    errno_t ret;
    knl_column_t *column = NULL;
    knl_cursor_t *cursor = NULL;

    entity = DC_ENTITY(dc);
    table = &entity->table;
    if (table->index_set.total_count >= GS_MAX_TABLE_INDEXES) {
        GS_THROW_ERROR(ERR_TOO_MANY_INDEXES, T2S(&def->user), T2S_EX(&def->table));
        return GS_ERROR;
    }

    index_t check_index;
    ret = memset_sp(&check_index, sizeof(index_t), 0, sizeof(index_t));
    knl_securec_check(ret);
    if (db_alloc_index_id(entity, def, &check_index.desc.id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (db_verify_index_def(session, dc, def, &check_index.desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (check_index.desc.is_func) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create function index", "local temp table");
        return GS_ERROR;
    }

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(index_t), (void **)&index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ret = memcpy_sp(index, sizeof(index_t), &check_index, sizeof(index_t));
    knl_securec_check(ret);
    index->entity = entity;
    desc = &index->desc;
    desc->is_cons = GS_FALSE;
    desc->is_enforced = GS_FALSE;
    desc->id = table->index_set.count;
    desc->slot = desc->id;
    dc_set_index_accessor(table, index);

    if (need_fill_index) {
        CM_SAVE_STACK(session->stack);

        cursor = knl_push_cursor(session);
        if (temp_db_fill_index(session, cursor, index, def->parallelism) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        CM_RESTORE_STACK(session->stack);
    }

    if (index->desc.primary) {
        for (uint32 i = 0; i < index->desc.column_count; i++) {
            uint16 id = index->desc.columns[i];
            column = dc_get_column(entity, id);
            column->nullable = GS_FALSE;
        }
    }

    table->index_set.count++;
    table->index_set.total_count++;
    table->index_set.items[index->desc.slot] = index;
    table->desc.index_count++;

    return GS_SUCCESS;
}

static status_t db_create_ltt_indexes(knl_session_t *session, knl_table_def_t *def, knl_dictionary_t *dc)
{
    errno_t ret;

    for (uint32 i = 0; i < def->constraints.count; i++) {
        knl_constraint_def_t *cons = (knl_constraint_def_t *)cm_galist_get(&def->constraints, i);
        knl_index_def_t *index_def = &cons->index;

        if (cons->type == CONS_TYPE_REFERENCE || cons->type == CONS_TYPE_CHECK) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                              "local temporary table don't support reference or check constraints");
            return GS_ERROR;
        }

        if (index_def->parted) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                              "could not create partition index on local temporary table");
            return GS_ERROR;
        }

        if (index_def->use_existed) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                              "local temporary table don't support use existed index");
            return GS_ERROR;
        }

        if (index_def->columns.count > 0) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                              "local temporary table don't support this constraint syntax");
            return GS_ERROR;
        }

        if (index_def->user.len == 0) {
            index_def->user = def->schema;
        }
        if (index_def->table.len == 0) {
            index_def->table = def->name;
        }
        if (index_def->name.len == 0) {
            index_def->name = cons->name;
        }

        ret = memcpy_sp(&index_def->columns, sizeof(galist_t), &cons->columns, sizeof(galist_t));
        knl_securec_check(ret);
        if (db_create_ltt_index(session, index_def, dc, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_create_ltt(knl_session_t *session, knl_table_def_t *def, dc_entity_t *entity)
{
    knl_table_desc_t *desc = &entity->table.desc;
    knl_dictionary_t dc;

    dc.is_sysnonym = GS_FALSE;
    dc.handle = (knl_handle_t)entity;
    dc.kernel = (knl_handle_t)session->kernel;
    dc.uid = desc->uid;
    dc.oid = desc->id;
    dc.org_scn = desc->org_scn;
    dc.chg_scn = desc->chg_scn;
    dc.type = desc->type;
    dc_set_table_accessor(&entity->table);

    if (db_create_ltt_columns(session, entity, def, desc->uid, desc->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_create_ltt_indexes(session, def, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_drop_ltt(knl_session_t *session, knl_dictionary_t *dc)
{
    table_t *table = DC_TABLE(dc);
    knl_temp_cache_t *temp_table = NULL;

    // release temp segments
    temp_table = knl_get_temp_cache(session, dc->uid, dc->oid);
    if (temp_table != NULL) {
        knl_panic_log(temp_table->org_scn == table->desc.org_scn, "temp_table's org_scn is not equal to "
                      "table's org_scn, panic info: table %s temp_table org_scn %llu table org_scn %llu",
                      table->desc.name, temp_table->org_scn, table->desc.org_scn);
        knl_free_temp_vm(session, temp_table);
    }

    // release dc memory
    uint32 slot = table->desc.id - GS_LTT_ID_OFFSET;
    dc_entity_t *entity = DC_ENTITY(dc);
    mctx_destroy(entity->memory);
    session->temp_dc->entries[slot] = NULL;

    return GS_SUCCESS;
}

static status_t db_delete_from_systable(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, const char *name)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_TABLE_001_USER_ID);
    // name len is not greater than 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)name,
                     (uint16)strlen(name), IX_COL_SYS_TABLE_001_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_delete_from_sysview(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, char *name)
{
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_VIEW_ID, IX_SYS_VIEW001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_VIEW001_USER);
    // name len is not greater than 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)name,
                     (uint16)strlen(name), IX_COL_SYS_VIEW001_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user->desc.name, name);
        return GS_ERROR;
    } else {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_from_sysstorage(knl_session_t *session, knl_cursor_t *cursor, uint64 orgscn)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_STORAGE_ID, IX_STORAGE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_BIGINT, (void *)&orgscn,
                     sizeof(uint64), IX_COL_SYS_STORAGE_ORGSCN);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        return GS_SUCCESS;
    }

    if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_delete_from_sysindex(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 tid,
                                        uint32 iid)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_INDEX_ID, IX_SYS_INDEX_001_ID);
    if (iid == GS_INVALID_ID32) {
        knl_init_index_scan(cursor, GS_FALSE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_SYS_INDEX_001_USER);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &tid, sizeof(uint32),
                         IX_COL_SYS_INDEX_001_TABLE);
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEX_001_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_SYS_INDEX_001_USER);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &tid, sizeof(uint32),
                         IX_COL_SYS_INDEX_001_TABLE);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEX_001_ID);
    } else {
        knl_init_index_scan(cursor, GS_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_SYS_INDEX_001_USER);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &tid, sizeof(uint32),
                         IX_COL_SYS_INDEX_001_TABLE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &iid, sizeof(uint32),
                         IX_COL_SYS_INDEX_001_ID);
    }

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_columns(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 oid)
{
    knl_scan_key_t *l_key = NULL;
    knl_scan_key_t *r_key = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_COLUMN_ID, IX_SYS_COLUMN_001_ID);
    l_key = &cursor->scan_range.l_key;
    r_key = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_COLUMN_001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_COLUMN_001_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    knl_panic_log(oid == *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COLUMN_COL_TABLE_ID),
                  "the oid is abnormal, panic info: page %u-%u type %u table %s index %s oid %u", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name,
                  ((index_t *)cursor->index)->desc.name, oid);

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_delete_viewcolumns(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 oid)
{
    knl_scan_key_t *l_key = NULL;
    knl_scan_key_t *r_key = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_VIEWCOL_ID, IX_SYS_VIEWCOL001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    l_key = &cursor->scan_range.l_key;
    r_key = &cursor->scan_range.r_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_VIEWCOL001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_VIEWCOL001_VIEW_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_VIEWCOL001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_VIEWCOL001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_VIEWCOL001_VIEW_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_VIEWCOL001_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_delete_from_syslob(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 oid,
                                      uint32 col_id)
{
    knl_scan_key_t *l_key = NULL;
    knl_scan_key_t *r_key = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_LOB_ID, IX_SYS_LOB001_ID);

    if (col_id == GS_INVALID_INT32) {
        knl_init_index_scan(cursor, GS_FALSE);
        l_key = &cursor->scan_range.l_key;
        r_key = &cursor->scan_range.r_key;

        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_SYS_LOB001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                         IX_COL_SYS_LOB001_TABLE_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LOB001_COLUMN_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_SYS_LOB001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), r_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                         IX_COL_SYS_LOB001_TABLE_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LOB001_COLUMN_ID);
    } else {
        knl_init_index_scan(cursor, GS_TRUE);
        l_key = &cursor->scan_range.l_key;
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_SYS_LOB001_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                         IX_COL_SYS_LOB001_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &col_id, sizeof(uint32),
                         IX_COL_SYS_LOB001_COLUMN_ID);
    }

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static bool32 db_check_cons_referenced(uint32 idx_id, dc_entity_t *entity, uint32 *type)
{
    index_t *index = NULL;

    if (*type == CONS_TYPE_PRIMARY || *type == CONS_TYPE_UNIQUE) {
        index = dc_find_index_by_id(entity, idx_id);

        if (index != NULL && index->dep_set.count != 0) {
            GS_THROW_ERROR(ERR_DROP_CONS, "some foreign keys");
            return GS_TRUE;
        }

        if ((entity->lrep_info.status == LOGICREP_STATUS_ON) && (entity->lrep_info.index_id == idx_id)) {
            GS_THROW_ERROR(ERR_REFERENCED_BY_LOGICAL_LOG);
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

status_t db_check_cons_auto_increment(dc_entity_t *entity, knl_cursor_t *cursor, uint32 type)
{
    text_t col_list;
    uint32 col_id;
    uint32 cols_num;
    knl_column_t *column = NULL;

    if (type != CONS_TYPE_PRIMARY && type != CONS_TYPE_UNIQUE) {
        return GS_SUCCESS;
    }

    cols_num = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_COUNT);
    if (cols_num != 1) {
        return GS_SUCCESS;
    }

    col_list.str = CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_LIST);
    col_list.len = CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_COLUMN_LIST);
    if (cm_text2int(&col_list, (int32 *)&col_id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    column = dc_get_column(entity, col_id);
    if (column != NULL && KNL_COLUMN_IS_SERIAL(column)) {
        GS_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_drop_cons(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 oid,
                      dc_entity_t *entity, knl_altable_def_t *def, bool32 *is_found)
{
    uint32 index_id;
    uint32 ref_uid;
    uint32 ref_tid;
    knl_dictionary_t ref_dc;
    uint32 type;

    if (db_fetch_sysconsdef_by_table(session, cursor, CURSOR_ACTION_DELETE,
                                     uid, oid, &def->cons_def.name, is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!*is_found) {
        return GS_SUCCESS;
    }

    if (CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_INDEX_ID) == GS_NULL_VALUE_LEN) {
        index_id = GS_INVALID_ID32;
    } else {
        index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_INDEX_ID);
    }

    type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_TYPE);
    if (db_check_cons_auto_increment(entity, cursor, type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (type == CONS_TYPE_REFERENCE) {
        ref_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_USER);
        ref_tid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_TABLE);
        if (knl_open_dc_by_id(session, ref_uid, ref_tid, &ref_dc, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        uint32 timeout = session->kernel->attr.ddl_lock_timeout;
        if (lock_table_directly(session, &ref_dc, timeout) != GS_SUCCESS) {
            dc_close(&ref_dc);
            return GS_ERROR;
        }

        dc_close(&ref_dc);
    } else if (db_check_cons_referenced(index_id, entity, &type)) { // for primary cons and unique cons
        return GS_ERROR;
    }

    if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_drop_cascade_cons(knl_session_t *session, uint32 uid, uint32 oid)
{
    knl_scan_key_t *l_key = NULL;
    knl_cursor_t *cursor = NULL;
    uint32 child_uid;
    uint32 child_oid;
    knl_dictionary_t child_dc;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_CONSDEF_ID, IX_SYS_CONSDEF002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    l_key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_CONSDEF002_REF_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_CONSDEF002_REF_TABLE_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    uint32 timeout = session->kernel->attr.ddl_lock_timeout;
    while (!cursor->eof) {
        child_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_USER);
        child_oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_TABLE);
        if (knl_open_dc_by_id(session, child_uid, child_oid, &child_dc, GS_TRUE) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (lock_table_directly(session, &child_dc, timeout) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            dc_close(&child_dc);
            return GS_ERROR;
        }

        dc_close(&child_dc);

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_drop_all_cons(knl_session_t *session, uint32 uid, uint32 oid, bool32 only_fk)
{
    knl_dictionary_t ref_dc;
    knl_cursor_t *cursor = NULL;
    uint32 ref_uid;
    uint32 ref_tid;
    uint32 type;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_CONSDEF001_TABLE_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    uint32 timeout = session->kernel->attr.ddl_lock_timeout;
    while (!cursor->eof) {
        type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_CONS_TYPE);
        if (type == CONS_TYPE_REFERENCE) {
            ref_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_USER);
            ref_tid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_TABLE);
            if (knl_open_dc_by_id(session, ref_uid, ref_tid, &ref_dc, GS_TRUE) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (lock_table_directly(session, &ref_dc, timeout) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                dc_close(&ref_dc);
                return GS_ERROR;
            }

            dc_close(&ref_dc);
        }

        if (type == CONS_TYPE_REFERENCE || !only_fk) {
            if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_delete_from_sys_user(knl_session_t *session, uint32 uid)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_USER_ID, IX_SYS_USER_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_USER_001_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, ppanic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_delete_from_sys_tenant(knl_session_t *session, uint32 tid)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_TENANTS_ID, IX_SYS_TENANTS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &tid, sizeof(uint32),
        IX_SYS_TENANTS_001_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_drop_ref_constraints(knl_session_t *session, uint32 uid, uint32 oid)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_CONSDEF_ID, IX_SYS_CONSDEF002_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_CONSDEF002_REF_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_CONSDEF002_REF_TABLE_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

bool32 db_table_is_referenced(knl_session_t *session, table_t *table, bool32 check_state)
{
    uint32 i;
    index_t *index = NULL;
    cons_dep_t *dep = NULL;

    if (table->index_set.total_count == 0 || !table->cons_set.referenced) {
        return GS_FALSE;
    }

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (index->dep_set.count == 0) {
            continue;
        }

        /* if table is referenced by another table */
        dep = index->dep_set.first;
        while (dep != NULL) {
            if (check_state && !dep->cons_state.is_enable) {
                dep = dep->next;
                continue;
            }

            if (dep->uid != table->desc.uid || dep->oid != table->desc.id) {
                return GS_TRUE;
            }
            dep = dep->next;
        }
    }

    return GS_FALSE;
}

/*
 * un-reside all table segments entry page
 * @param kernel session, kernel dictionary
 */
void db_unreside_table_segments(knl_session_t *session, knl_dictionary_t *dc)
{
    dc_entity_t *entity;
    table_t *table;
    index_t *index = NULL;
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    uint32 i;
    space_t *space;

    table = DC_TABLE(dc);
    entity = DC_ENTITY(dc);

    space = SPACE_GET(table->desc.space_id);

    if (SPACE_IS_ONLINE(space)) {
        buf_unreside_page(session, table->desc.entry);
    }

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        space = SPACE_GET(index->desc.space_id);

        if (SPACE_IS_ONLINE(space)) {
            buf_unreside_page(session, index->desc.entry);
        }
    }

    for (i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        if (SPACE_IS_ONLINE(space)) {
            lob = (lob_t *)column->lob;
            buf_unreside_page(session, lob->desc.entry);
        }
    }
}

bool32 db_table_has_segment(knl_session_t *session, knl_dictionary_t *dc)
{
    table_t *table = DC_TABLE(dc);

    if (IS_PART_TABLE(table)) {
        table_part_t *table_part = NULL;
        for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
            table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            if (!IS_PARENT_TABPART(&table_part->desc)) {
                if (table_part->heap.segment != NULL) {
                    return GS_TRUE;
                }

                continue;
            }

            table_part_t *subpart = NULL;
            for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
                subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
                if (subpart->heap.segment != NULL) {
                    return GS_TRUE;
                }
            }
        }

        return GS_FALSE;
    } else {
        return (table->heap.segment != NULL);
    }
}

static status_t db_drop_heap_part_segments(knl_session_t *session, dc_entity_t *entity, table_t *table)
{
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;
    stats_table_mon_t *table_stats = NULL;

    for (uint32 id = 0; id < TOTAL_PARTCNT(&table->part_table->desc); ++id) {
        table_part = TABLE_GET_PART(table, id);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
                table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
                if (table_subpart == NULL) {
                    continue;
                }

                if (heap_part_segment_prepare(session, (table_part_t *)table_subpart, GS_INVALID_ID32,
                    HEAP_DROP_PART_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (DB_IS_STATS_ENABLED(((knl_session_t *)session)->kernel)) {
                    table_stats = &entity->entry->appendix->table_smon;
                    table_stats->is_change = GS_TRUE;
                    table_stats->drop_segments++;
                    table_stats->timestamp = cm_now();
                }
            }
        } else {
            if (heap_part_segment_prepare(session, table_part, GS_INVALID_ID32, HEAP_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (DB_IS_STATS_ENABLED(((knl_session_t *)session)->kernel)) {
                table_stats = &entity->entry->appendix->table_smon;
                table_stats->is_change = GS_TRUE;
                table_stats->drop_segments++;
                table_stats->timestamp = cm_now();
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_drop_heap_segments(knl_session_t *session, dc_entity_t *entity, table_t *table)
{
    if (heap_segment_prepare(session, table, GS_INVALID_ID32, HEAP_DROP_SEGMENT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (table->desc.parted) {
        if (db_drop_heap_part_segments(session, entity, table) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t db_drop_index_part_segments(knl_session_t *session, index_t *index)
{
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    table_part_t *table_part = NULL;
    table_t *table = &index->entity->table;

    for (uint32 id = 0; id < TOTAL_PARTCNT(&index->part_index->desc); ++id) {
        index_part = INDEX_GET_PART(index, id);
        table_part = TABLE_GET_PART(table, id);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }

        if (IS_PARENT_IDXPART(&index_part->desc)) {
            for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
                index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[i]);
                if (index_subpart == NULL) {
                    continue;
                }

                if (btree_part_segment_prepare(session, index_subpart, GS_INVALID_ID32,
                    BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
            if (btree_part_segment_prepare(session, index_part, GS_INVALID_ID32,
                BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_drop_index_segments(knl_session_t *session, table_t* table)
{
    index_t *index = NULL;

    for (uint32 i = 0; i < table->index_set.total_count; ++i) {
        index = table->index_set.items[i];
        if (btree_segment_prepare(session, index, GS_INVALID_ID32, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (index->desc.parted) {
            if (db_drop_index_part_segments(session, index) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_drop_lob_part_segments(knl_session_t *session, lob_t *lob, table_t *table)
{
    lob_part_t *lob_part = NULL;
    lob_part_t *lob_subpart = NULL;
    table_part_t *table_part = NULL;

    for (uint32 id = 0; id < TOTAL_PARTCNT(&table->part_table->desc); ++id) {
        lob_part = LOB_GET_PART(lob, id);
        table_part = TABLE_GET_PART(table, id);
        if (!IS_READY_PART(table_part) || lob_part == NULL) {
            continue;
        }

        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            for (uint32 i = 0; i < lob_part->desc.subpart_cnt; i++) {
                lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[i]);
                if (lob_subpart == NULL) {
                    continue;
                }

                if (lob_part_segment_prepare(session, (lob_part_t *)lob_subpart, GS_INVALID_ID32,
                    LOB_DROP_PART_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
            if (lob_part_segment_prepare(session, lob_part, GS_INVALID_ID32, LOB_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_drop_lob_segments(knl_session_t *session, dc_entity_t *entity)
{
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    table_t *table = &entity->table;

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (lob_segment_prepare(session, lob, GS_INVALID_ID32, LOB_DROP_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (table->desc.parted) {
            if (db_drop_lob_part_segments(session, lob, table) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

/*
 * drop all table segments
 * @param kernel session, kernel dictionary
 * @note heap segment should be drop first to support
 * table segment detection after crash.
 */
status_t db_drop_table_segments(knl_session_t *session, knl_dictionary_t *dc)
{
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    dc_load_all_part_segments(session, entity);
    if (db_drop_heap_segments(session, entity, table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_drop_index_segments(session, table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_drop_lob_segments(session, entity) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * db_write_sysdep$
 *
 * This function is used to insert dependencies to dependency$.
 *
 */
status_t db_write_sysdep(knl_session_t *session, knl_cursor_t *cursor, object_address_t *depender,
                         object_address_t *ref_obj, uint32 order)
{
    uint32 max_size;
    row_assist_t ra;
    table_t *table = NULL;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_DEPENDENCY_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);

    if (row_put_int32(&ra, depender->uid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int64(&ra, depender->oid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int32(&ra, depender->tid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int64(&ra, depender->scn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int32(&ra, order) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int32(&ra, ref_obj->uid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int64(&ra, ref_obj->oid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int32(&ra, ref_obj->tid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int64(&ra, ref_obj->scn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_str(&ra, depender->name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_str(&ra, ref_obj->name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * db_write_sysdep$_list
 *
 * This function is used to insert dependencies list to dependency$.
 *
 */
status_t db_write_sysdep_list(knl_session_t *knl_session, object_address_t *depender, galist_t *referenced_list)
{
    object_address_t *ref_obj = NULL;
    knl_cursor_t *cursor = NULL;
    uint32 i, count;

    if (referenced_list == NULL || referenced_list->count == 0) {
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(knl_session->stack);

    cursor = knl_push_cursor(knl_session);

    for (i = 0, count = 0; i < referenced_list->count; i++) {
        ref_obj = (object_address_t *)cm_galist_get((galist_t *)referenced_list, i);
        if (depender->uid == ref_obj->uid && depender->oid == ref_obj->oid && depender->tid == ref_obj->tid) {
            continue;
        }

        if (GS_SUCCESS != db_write_sysdep(knl_session, cursor, depender, ref_obj, count)) {
            CM_RESTORE_STACK(knl_session->stack);
            return GS_ERROR;
        }

        count++;
    }

    for (i = referenced_list->count; i > 0; i--) {
        cm_galist_delete(referenced_list, i - 1);
    }

    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

status_t db_update_sysview(knl_session_t *session, knl_cursor_t *cursor, knl_view_t *view, knl_view_def_t *def,
                           bool32 *is_found)
{
    uint32 max_size;
    row_assist_t ra;
    knl_column_t *lob_column = NULL;
    uint16 size;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_VIEW_ID, IX_SYS_VIEW001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&view->uid,
        sizeof(uint32), IX_COL_SYS_VIEW001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)def->name.str,
        def->name.len, IX_COL_SYS_VIEW001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        *is_found = GS_FALSE;
        return GS_SUCCESS;
    }

    row_init(&ra, cursor->update_info.data, max_size, 7);
    cursor->update_info.count = 7;
    cursor->update_info.columns[0] = SYS_VIEW_COLS;
    cursor->update_info.columns[1] = SYS_VIEW_FLAG;
    cursor->update_info.columns[2] = SYS_VIEW_ORG_SCN;
    cursor->update_info.columns[3] = SYS_VIEW_CHG_SCN;
    cursor->update_info.columns[4] = SYS_VIEW_TEXT_LENGTH;
    cursor->update_info.columns[5] = SYS_VIEW_TEXT_COLUMN;
    cursor->update_info.columns[6] = SYS_VIEW_SQL_TYPE;

    lob_column = knl_get_column(cursor->dc_entity, SYS_VIEW_TEXT_COLUMN);
    (void)row_put_int32(&ra, (int32)view->column_count);
    (void)row_put_int32(&ra, (int32)view->flags);
    (void)row_put_int64(&ra, (int64)view->org_scn);
    (void)row_put_int64(&ra, (int64)view->chg_scn);
    (void)row_put_int32(&ra, (int32)def->sub_sql.len);

    if (knl_row_put_lob(session, cursor, lob_column, &def->sub_sql, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }

    (void)row_put_int32(&ra, view->sql_type);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_replace_view(knl_session_t *session, knl_view_def_t *def, knl_dictionary_t *dc)
{
    knl_column_t column;
    knl_column_def_t *column_def = NULL;
    knl_comment_def_t comment_def;
    knl_cursor_t *cursor = NULL;
    knl_view_t view;
    uint32 i;
    rd_table_t redo;
    object_address_t depender;
    errno_t err;
    bool32 is_found = GS_TRUE;

    if (DB_NOT_READY(session)) {
        GS_THROW_ERROR(ERR_NO_DB_ACTIVE);
        return GS_ERROR;
    }

    if (db_init_view_desc(session, &view, def) != GS_SUCCESS) {
        return GS_ERROR;
    }
    view.id = dc->oid;
    view.uid = dc->uid;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    // to update sys view
    if (db_update_sysview(session, cursor, &view, def, &is_found) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!is_found) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_delete_viewcolumns(session, cursor, dc->uid, dc->oid)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_delete_from_sysdep(session, cursor, dc->uid, (int64)dc->oid, OBJ_TYPE_VIEW)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    comment_def.type = COMMENT_ON_TABLE;
    comment_def.uid = dc->uid;
    comment_def.id = dc->oid;
    /* drop the table comment */
    if (GS_SUCCESS != db_delete_comment(session, &comment_def)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    column.name = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);
    for (i = 0; i < def->columns.count; i++) {
        column_def = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        db_convert_column_def(&column, dc->uid, dc->oid, column_def, NULL, i);

        if (db_write_sysview_column(session, cursor, &column) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    // insert into sys.dependency$
    depender.uid = view.uid;
    depender.oid = view.id;
    depender.tid = OBJ_TYPE_VIEW;
    depender.scn = view.chg_scn;
    err = strcpy_sp(depender.name, GS_NAME_BUFFER_SIZE, view.name);
    knl_securec_check(err);
    if (db_write_sysdep_list(session, &depender, def->ref_objects) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    redo.op_type = RD_ALTER_TABLE;
    redo.uid = view.uid;
    redo.oid = view.id;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);

    return GS_SUCCESS;
}

status_t db_create_view(knl_session_t *session, knl_view_def_t *def)
{
    knl_column_t column;
    knl_column_def_t *column_def = NULL;
    knl_cursor_t *cursor = NULL;
    knl_view_t view;
    uint32 i;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    rd_create_table_t redo;
    object_address_t depender;
    errno_t err;

    if (DB_NOT_READY(session)) {
        GS_THROW_ERROR(ERR_NO_DB_ACTIVE);
        return GS_ERROR;
    }

    if (db_init_view_desc(session, &view, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_open_user_by_id(session, view.uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_create_view_entry(session, user, &view) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    // for creating table bug fix: cursor->row is null
    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;

    if (db_write_sysview(session, cursor, &view, def) != GS_SUCCESS) {
        dc_free_broken_entry(session, view.uid, view.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    column.name = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);
    for (i = 0; i < def->columns.count; i++) {
        column_def = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        db_convert_column_def(&column, view.uid, view.id, column_def, NULL, i);

        if (db_write_sysview_column(session, cursor, &column) != GS_SUCCESS) {
            dc_free_broken_entry(session, view.uid, view.id);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    // insert into sys.dependency$
    depender.uid = view.uid;
    depender.oid = view.id;
    depender.tid = OBJ_TYPE_VIEW;
    depender.scn = view.chg_scn;
    err = strcpy_sp(depender.name, GS_NAME_BUFFER_SIZE, view.name);
    knl_securec_check(err);
    if (db_write_sysdep_list(session, &depender, def->ref_objects) != GS_SUCCESS) {
        dc_free_broken_entry(session, view.uid, view.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    entry = DC_GET_ENTRY(user, view.id);
    cm_spin_lock(&entry->lock, &session->stat_dc_entry);
    entry->ready = GS_TRUE;
    cm_spin_unlock(&entry->lock);

    redo.op_type = RD_CREATE_TABLE;
    redo.uid = view.uid;
    redo.oid = view.id;

    err = strcpy_sp(redo.obj_name, GS_NAME_BUFFER_SIZE, view.name);
    knl_securec_check(err);
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_create_table_t), LOG_ENTRY_FLAG_NONE);

    return GS_SUCCESS;
}

status_t db_create_or_replace_view(knl_session_t *session, knl_view_def_t *def)
{
    knl_dictionary_t dc;
    bool32 is_found = GS_FALSE;

    if (knl_open_dc_if_exists(session, &def->user, &def->name, &dc, &is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!is_found) {
        return db_create_view(session, def);
    }

    if (SYNONYM_EXIST(&dc) || dc.type != DICT_TYPE_VIEW) {
        dc_close(&dc);
        GS_THROW_ERROR(ERR_DUPLICATE_TABLE, T2S(&def->user), T2S_EX(&def->name));
        return GS_ERROR;
    }

    if (db_replace_view(session, def, &dc) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    knl_commit(session);
    dc_invalidate(session, (dc_entity_t *)dc.handle);
    dc_close(&dc);

    return GS_SUCCESS;
}

status_t db_check_policies_before_delete(knl_session_t *session, const char *table_name, uint32 uid)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_POLICY_ID, IX_SYS_POLICY_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&uid, sizeof(uint32), IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
        (void *)&uid, sizeof(uint32), IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)table_name, (uint16)strlen(table_name), IX_COL_SYS_POLICY_001_OBJ_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_STRING,
        (void *)table_name, (uint16)strlen(table_name), IX_COL_SYS_POLICY_001_OBJ_NAME);

    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_POLICY_001_PNAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_POLICY_001_PNAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof == GS_FALSE) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", the table has policy, please drop policy firstly.");
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/*
 * Description     : fetch row of column according to user name and column name
 * Input           : cursor : cursor->action should set by caller, either delete or select
 * Input           : user : user name of table owner
 * Input           : index_name : name of index
 * Input           : dc : dictionary of table
 * Output          : NA
 * Return Value    : status_t
 * History         : 1. 2017/4/26,  add description
 */
static status_t db_fetch_syscolumn_row(knl_session_t *session, knl_cursor_t *cursor, uint16 col_id,
    uint32 uid, uint32 oid, knl_cursor_action_t action)
{
    knl_scan_key_t *key = NULL;
    uint32 id;

    knl_open_sys_cursor(session, cursor, action, SYS_COLUMN_ID, IX_SYS_COLUMN_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    id = (uint32)col_id;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &id, sizeof(uint32), IX_COL_SYS_COLUMN_001_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    return GS_SUCCESS;
}

static status_t db_update_icol_from_syscolumn(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
                                              knl_index_desc_t *idesc)
{
    uint32 i, col_id;

    for (i = 0; i < idesc->column_count; i++) {
        col_id = idesc->columns[i];
        if (col_id < DC_VIRTUAL_COL_START) {
            continue;
        }

        if (db_fetch_syscolumn_row(session, cursor, col_id,
                                   idesc->uid, idesc->table_id, CURSOR_ACTION_UPDATE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_drop_external_table(knl_session_t *session, knl_cursor_t *cursor, table_t *table)
{
    knl_table_desc_t *desc = &table->desc;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_EXTERNAL_ID, IX_EXTERNALTABS_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->uid,
                     sizeof(uint32), IX_COL_EXTERNALTABS_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->id,
                     sizeof(uint32), IX_COL_EXTERNALTABS_001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, desc->name,
                  ((index_t *)cursor->index)->desc.name);

    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_drop_view(knl_session_t *session, knl_dictionary_t *dc)
{
    knl_cursor_t *cursor = NULL;
    knl_view_t *view;
    dc_entity_t *entity;
    knl_comment_def_t comment_def;
    rd_view_t redo;
    errno_t err;
    obj_info_t obj_addr;
    entity = DC_ENTITY(dc);
    view = &entity->view;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;

    if (GS_SUCCESS != db_delete_from_sysview(session, cursor, view->uid, view->name)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_delete_viewcolumns(session, cursor, view->uid, view->id)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_delete_from_sysdep(session, cursor, view->uid, view->id, OBJ_TYPE_VIEW)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    comment_def.type = COMMENT_ON_TABLE;
    comment_def.uid = view->uid;
    comment_def.id = view->id;
    /* drop the table comment */
    if (GS_SUCCESS != db_delete_comment(session, &comment_def)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* to avoid deadlock, need update status first, before delete trigger */
    obj_addr.oid = dc->oid;
    obj_addr.uid = dc->uid;
    obj_addr.tid = OBJ_TYPE_VIEW;
    if (g_knl_callback.update_depender(session, &obj_addr) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (g_knl_callback.pl_db_drop_triggers(session, (void *)dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_drop_object_privs(session, view->uid, view->name, OBJ_TYPE_VIEW)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    redo.op_type = RD_DROP_VIEW;
    redo.uid = view->uid;
    redo.oid = view->id;

    err = strcpy_sp(redo.obj_name, GS_NAME_BUFFER_SIZE, view->name);
    knl_securec_check(err);
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_view_t), LOG_ENTRY_FLAG_NONE);

    knl_commit(session);
    g_knl_callback.pl_drop_triggers_entry(session, dc);

    // Only after transaction committed, can dc be dropped.
    dc_drop_object_privs(&session->kernel->dc_ctx, view->uid, view->name, OBJ_TYPE_VIEW);
    dc_drop(session, DC_ENTITY(dc));
    dc_free_entry(session, DC_ENTRY(dc));

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

void print_drop_view(log_entry_t *log)
{
    rd_view_t *rd = (rd_view_t *)log->data;
    printf("drop view uid:%d,obj:%s\n", rd->uid, rd->obj_name);
}

static void db_fetch_view_by_uid(knl_session_t *session, uint32 uid, char *buf, uint32 size, bool32 *found)
{
    knl_cursor_t *cursor = NULL;
    char *viewname = NULL;
    uint32 len;
    errno_t err;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_VIEW_ID, IX_SYS_VIEW001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_VIEW001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_VIEW001_USER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_VIEW001_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_VIEW001_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        *found = GS_FALSE;
        return;
    }

    if (!cursor->eof) {
        viewname = CURSOR_COLUMN_DATA(cursor, SYS_VIEW_NAME);
        len = CURSOR_COLUMN_SIZE(cursor, SYS_VIEW_NAME);
        err = memcpy_sp(buf, size, viewname, len);
        knl_securec_check(err);
        buf[len] = '\0';
        *found = GS_TRUE;
    } else {
        *found = GS_FALSE;
    }

    CM_RESTORE_STACK(session->stack);
    return;
}

status_t db_drop_view_by_user(knl_session_t *session, text_t *username, uint32 uid)
{
    bool32 found = GS_FALSE;
    char viewname[GS_NAME_BUFFER_SIZE];
    knl_drop_def_t def;

    db_fetch_view_by_uid(session, uid, viewname, GS_NAME_BUFFER_SIZE, &found);
    while (found) {
        cm_str2text_safe(viewname, (uint32)strlen(viewname), &def.name);
        def.owner.str = username->str;
        def.owner.len = username->len;
        def.purge = 0;
        def.options = 0;

        /* do NOT care the result here, continue drop the next */
        (void)knl_drop_view(session, &def);

        knl_set_session_scn(session, GS_INVALID_ID64);
        db_fetch_view_by_uid(session, uid, viewname, GS_NAME_BUFFER_SIZE, &found);
    }

    return GS_SUCCESS;
}

static status_t part_truncate_lob_prepare(knl_session_t *session, lob_t *lob, lob_part_t *lob_part, bool32 reuse)
{
    if (!IS_PARENT_LOBPART(&lob_part->desc)) {
        if (lob_part_segment_prepare(session, lob_part, reuse, LOB_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }

        return GS_SUCCESS;
    }

    lob_part_t *lob_subpart = NULL;
    for (uint32 i = 0; i < lob_part->desc.subpart_cnt; i++) {
        for (uint32 j = 0; j < lob_part->desc.subpart_cnt; j++) {
            lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[j]);
            if (lob_subpart == NULL) {
                continue;
            }

            if (lob_part_segment_prepare(session, (lob_part_t *)lob_subpart, reuse,
                LOB_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_truncate_lobs_prepare(knl_session_t *session, knl_dictionary_t *dc, bool32 reuse)
{
    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    table_part_t *table_part = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (table->desc.parted) {
            for (uint32 id = 0; id < table->part_table->desc.partcnt; id++) {
                table_part = TABLE_GET_PART(table, id);
                lob_part = LOB_GET_PART(lob, id);
                if (!IS_READY_PART(table_part) || lob_part == NULL) {
                    continue;
                }

                if (part_truncate_lob_prepare(session, lob, lob_part, reuse) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
            if (lob_segment_prepare(session, lob, reuse, LOB_TRUNCATE_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_truncate_index_prepare(knl_session_t *session, table_t *table, index_t *index,
    bool32 reuse_storage, bool32 *is_changed)
{
    if (IS_PART_INDEX(index)) { // local index on partition table
        index_part_t *index_part = NULL;
        table_part_t *table_part = NULL;
        for (uint32 id = 0; id < index->part_index->desc.partcnt; id++) {
            index_part = INDEX_GET_PART(index, id);
            table_part = TABLE_GET_PART(table, id);
            if (!IS_READY_PART(table_part) || index_part == NULL) {
                continue;
            }

            if (!IS_PARENT_IDXPART(&index_part->desc)) {
                if (db_update_idxpart_status(session, index_part, GS_FALSE, is_changed) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (btree_part_segment_prepare(session, index_part, reuse_storage,
                    BTREE_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                continue;
            }

            /* parent index part */
            index_part_t *index_subpart = NULL;
            for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
                index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[i]);
                if (index_subpart == NULL) {
                    continue;
                }

                if (db_update_sub_idxpart_status(session, index_subpart, GS_FALSE, is_changed) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (btree_part_segment_prepare(session, (index_part_t *)index_subpart, reuse_storage,
                    BTREE_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        }
    } else { // global index on partition table
        if (db_update_index_status(session, index, GS_FALSE, is_changed) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (btree_segment_prepare(session, index, reuse_storage, BTREE_TRUNCATE_SEGMENT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_truncate_part_table_prepare(knl_session_t *session, table_t *table, bool32 reuse)
{
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            if (heap_part_segment_prepare(session, table_part, reuse, HEAP_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            if (table_subpart == NULL) {
                continue;
            }

            if (heap_part_segment_prepare(session, table_subpart, reuse, HEAP_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static void db_truncate_lobs(knl_session_t *session, knl_dictionary_t *dc, bool32 reuse)
{
    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    table_part_t *table_part = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        if (table->desc.parted) {
            for (uint32 id = 0; id < table->part_table->desc.partcnt; id++) {
                table_part = TABLE_GET_PART(table, id);
                lob_part = LOB_GET_PART(lob, id);
                if (!IS_READY_PART(table_part) || lob_part == NULL) {
                    continue;
                }

                lob_truncate_part_segment(session, &lob_part->desc, reuse);
            }
        } else {
            lob_truncate_segment(session, &lob->desc, reuse);
        }
    }
}

static void db_truncate_part_table(knl_session_t *session, table_t *table, bool32 reuse)
{
    table_part_t *table_part = NULL;
    table_part_t *table_subpart = NULL;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            heap_truncate_part_segment(session, &table_part->desc, reuse);
            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            if (table_subpart == NULL) {
                continue;
            }
            heap_truncate_part_segment(session, &table_subpart->desc, reuse);
        }
    }
}

static void db_truncate_index(knl_session_t *session, table_t *table, index_t *index, bool32 reuse_storage)
{
    if (IS_PART_INDEX(index)) { // local index on partition table
        index_part_t *index_part = NULL;
        table_part_t *table_part = NULL;
        for (uint32 id = 0; id < index->part_index->desc.partcnt; id++) {
            index_part = INDEX_GET_PART(index, id);
            table_part = TABLE_GET_PART(table, id);
            if (!IS_READY_PART(table_part) || index_part == NULL) {
                continue;
            }

            if (!IS_PARENT_IDXPART(&index_part->desc)) {
                btree_truncate_part_segment(session, &index_part->desc, reuse_storage);
                continue;
            }

            /* parent index part */
            index_part_t *index_subpart = NULL;
            for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
                index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[i]);
                if (index_subpart == NULL) {
                    continue;
                }

                btree_truncate_part_segment(session, &index_subpart->desc, reuse_storage);
            }
        }
    }
    btree_truncate_segment(session, &index->desc, reuse_storage);
}

/* 
 * force truncate table when garbage segment handle failed.
 * If db has been killed, the records are still stored in garbage segment, 
 * reopen db the rest segments can be truncated.
 */
void db_force_truncate_table(knl_session_t *session, knl_dictionary_t *dc, 
    bool32 reuse_storage, bool32 is_not_recyclebin)
{
    if (!is_not_recyclebin) {
        return;
    }

    index_t *index = NULL;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    if (entity->contain_lob) {
        db_truncate_lobs(session, dc, reuse_storage);
    }

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        db_truncate_index(session, table, index, reuse_storage);
    }

    if (IS_PART_TABLE(table)) {
        db_truncate_part_table(session, table, reuse_storage);
    }

    heap_truncate_segment(session, &table->desc, reuse_storage);
}

status_t db_truncate_table_prepare(knl_session_t *session, knl_dictionary_t *dc, bool32 reuse_storage,
                                   bool32 *is_changed)
{
    index_t *index = NULL;
    knl_temp_cache_t *temp_table = NULL;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    if (entity->contain_lob) {
        if (db_truncate_lobs_prepare(session, dc, reuse_storage) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (table->desc.type == TABLE_TYPE_TRANS_TEMP || table->desc.type == TABLE_TYPE_SESSION_TEMP) {
        temp_table = knl_get_temp_cache(session, dc->uid, dc->oid);
        if (temp_table != NULL) {
            knl_panic_log(temp_table->org_scn == table->desc.org_scn, "the temp_table's org_scn is not equal to "
                "table's org_scn, panic info: table: %s temp_table org_scn %llu table org_scn %llu",
                table->desc.name, temp_table->org_scn, table->desc.org_scn);
            knl_free_temp_vm(session, temp_table);
        }
    } else {
        for (uint32 i = 0; i < table->index_set.total_count; i++) {
            index = table->index_set.items[i];
            if (db_truncate_index_prepare(session, table, index, reuse_storage, is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (IS_PART_TABLE(table)) {
            if (db_truncate_part_table_prepare(session, table, reuse_storage) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (heap_segment_prepare(session, table, reuse_storage, HEAP_TRUNCATE_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_update_index_count(knl_session_t *session, knl_cursor_t *cursor, knl_table_desc_t *desc, bool32 is_add)
{
    knl_table_desc_t desc_convert;
    knl_scan_key_t *l_key = NULL;
    uint32 index_count;
    uint16 size;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    l_key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // index name len is not greater than 68
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_STRING, &desc->name, (uint16)strlen(desc->name),
                     IX_COL_SYS_TABLE_001_NAME);

    if (btree_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, desc->name,
                  ((index_t *)cursor->index)->desc.name);

    dc_convert_table_desc(cursor, &desc_convert);
    knl_panic_log(cm_str_equal_ins(desc->name, desc_convert.name), "the name record on desc and desc_convert are not "
                  "same, panic info: page %u-%u type %u table %s index %s desc name %s desc_convert name %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, desc->name,
                  ((index_t *)cursor->index)->desc.name, desc->name, desc_convert.name);

    index_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_INDEXES) + (is_add ? 1 : (-1));
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
    cursor->update_info.count = 2;
    cursor->update_info.columns[0] = SYS_TABLE_COL_CHG_SCN;
    cursor->update_info.columns[1] = SYS_TABLE_COL_INDEXES;
    (void)row_put_int64(&ra, db_inc_scn(session));
    (void)row_put_int32(&ra, index_count);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (heap_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_update_table_trig_flag(knl_session_t *session, knl_table_desc_t *desc, bool32 has_trig)
{
    knl_table_desc_t desc_convert;
    knl_scan_key_t *l_key = NULL;
    uint32 column_size;
    uint16 size;
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    l_key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
        IX_COL_SYS_TABLE_001_USER_ID);
    // index name len is not greater than 68
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, GS_TYPE_STRING, &desc->name, (uint16)strlen(desc->name),
        IX_COL_SYS_TABLE_001_NAME);

    if (btree_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "table", desc->name);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    column_size = CURSOR_COLUMN_SIZE(cursor, SYS_TABLE_COL_FLAG);
    if (column_size == GS_NULL_VALUE_LEN) {
        desc_convert.flags = 0;
    } else {
        desc_convert.flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_FLAG);
    }

    desc_convert.has_trig = has_trig;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
    cursor->update_info.count = 2;
    cursor->update_info.columns[0] = SYS_TABLE_COL_CHG_SCN;
    cursor->update_info.columns[1] = SYS_TABLE_COL_FLAG;
    (void)row_put_int64(&ra, db_inc_scn(session));
    (void)row_put_int32(&ra, desc_convert.flags);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (heap_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}


/*
 * Description     : fetch row of index$ according to user name and index_name
 * Input           : cursor : cursor->action should set by caller, either delete or select
 * Input           : user : user name of table owner
 * Input           : index_name : name of index
 * Input           : dc : dictionary of table
 * Output          : NA
 * Return Value    : status_t
 * History         : 1. 2017/4/26,  add description
 */
status_t db_fetch_sysindex_row(knl_session_t *session, knl_cursor_t *cursor, uint32 uid,
                               text_t *index_name, knl_cursor_action_t action, bool32 *is_found)
{
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    *is_found = GS_TRUE;
    knl_open_sys_cursor(session, cursor, action, SYS_INDEX_ID, IX_SYS_INDEX_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &uid, sizeof(uint32), IX_COL_SYS_INDEX_002_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, index_name->str, index_name->len,
                     IX_COL_SYS_INDEX_002_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        *is_found = GS_FALSE;
    }
    return GS_SUCCESS;
}

status_t db_fetch_shadow_index_row(knl_session_t *session, knl_handle_t dc_entity, knl_cursor_t *cursor)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    knl_table_desc_t *desc = &entity->table.desc;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEX_ID, IX_SYS_SHADOW_INDEX_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->uid,
        sizeof(uint32), IX_COL_SYS_SHADOW_INDEX_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->id, sizeof(uint32),
        IX_COL_SYS_SHADOW_INDEX_001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_fetch_shadow_indexpart_row(knl_session_t *session, knl_handle_t dc_entity, knl_cursor_t *cursor)
{
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    knl_table_desc_t *desc = &entity->table.desc;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &desc->uid,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &desc->id,
        sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_create_btree_segment(knl_session_t *session, index_t *index, index_part_t *index_part,
    btree_t *btree, bool32 need_redo)
{
    if (IS_PART_INDEX(index)) {
        if (btree_create_part_segment(session, index_part) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (IS_SUB_IDXPART(&index_part->desc)) {
            if (db_update_subidxpart_entry(session, &index_part->desc, index_part->desc.entry) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (db_update_index_part_entry(session, &index_part->desc, index_part->desc.entry) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        buf_enter_page(session, index_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        btree->segment = BTREE_GET_SEGMENT;
        buf_leave_page(session, GS_FALSE);

        if (btree_generate_create_undo(session, index_part->desc.entry, index_part->desc.space_id,
            need_redo) != GS_SUCCESS) {
            btree_drop_part_segment(session, index_part);
            return GS_ERROR;
        }
    } else {
        if (btree_create_segment(session, index) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_update_index_entry(session, &index->desc, index->desc.entry) != GS_SUCCESS) {
            return GS_ERROR;
        }

        buf_enter_page(session, index->desc.entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        btree->segment = BTREE_GET_SEGMENT;
        buf_leave_page(session, GS_FALSE);

        if (btree_generate_create_undo(session, index->desc.entry, index->desc.space_id,
            need_redo) != GS_SUCCESS) {
            btree_drop_segment(session, index);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_prepare_fill_index(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
                                      btree_mt_context_t *ctx, mtrl_sort_ctrl_t *sort_ctrl)
{
    btree_t *btree = NULL;
    index_part_t *index_part = NULL;

    if (IS_PART_INDEX(index)) {
        // for local partitioned index, it shared the part_no with table partition
        index_part = INDEX_GET_PART(index, cursor->part_loc.part_no);
        if (IS_PARENT_IDXPART(&index_part->desc)) {
            index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[cursor->part_loc.subpart_no]);
        }
        btree = &index_part->btree;
    } else {
        btree = &index->btree;
    }

    if (btree->segment == NULL) {
        if (db_create_btree_segment(session, index, index_part,
            btree, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (!ctx->initialized) {
        if (btree_constructor_init(session, ctx, btree) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (!sort_ctrl->initialized) {
        if (mtrl_sort_init(session, index, cursor->part_loc, sort_ctrl) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (sort_ctrl->use_parallel) {
            mtrl_set_sort_type(ctx->mtrl_ctx.segments[ctx->seg_id], MTRL_SORT_TYPE_QSORT);
        }
    }

    return GS_SUCCESS;
}

static status_t db_construct_index(btree_mt_context_t *ctx, mtrl_sort_ctrl_t *sort_ctrl)
{
    if (mtrl_sort_clean(sort_ctrl) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (mtrl_close_segment(&ctx->mtrl_ctx, ctx->seg_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (ctx->mtrl_ctx.segments[ctx->seg_id]->vm_list.count < MIN_MTRL_SORT_EXTENTS) {
        sort_ctrl->use_parallel = GS_FALSE;
    }

    if (sort_ctrl->use_parallel) {
        if (mtrl_sort_segment_parallel(sort_ctrl, &ctx->mtrl_ctx, ctx->seg_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (mtrl_sort_segment(&ctx->mtrl_ctx, ctx->seg_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (idx_construct(ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ctx->initialized = GS_FALSE;
    return GS_SUCCESS;
}

status_t db_fill_index_entity(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
    btree_mt_context_t *ctx, mtrl_sort_ctrl_t *sort_ctrl)
{
    mtrl_rowid_t rid;
    char *key = NULL;

    /*
     * set cursor isolation level to current committed, so even if txn of delay
     * committed row in heap page is overwritten, there will no "snapshot too old" error.
     */
    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        (void)mtrl_sort_clean(sort_ctrl);
        mtrl_release_context(&ctx->mtrl_ctx);
        return GS_ERROR;
    }

    if (cursor->eof) {
        return GS_SUCCESS;
    }

    if (db_prepare_fill_index(session, cursor, index, ctx, sort_ctrl) != GS_SUCCESS) {
        (void)mtrl_sort_clean(sort_ctrl);
        mtrl_release_context(&ctx->mtrl_ctx);
        return GS_ERROR;
    }

    key = (char *)cm_push(session->stack, GS_KEY_BUF_SIZE);

    do {
        if (session->canceled) {
            (void)mtrl_sort_clean(sort_ctrl);
            mtrl_release_context(&ctx->mtrl_ctx);
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            (void)mtrl_sort_clean(sort_ctrl);
            mtrl_release_context(&ctx->mtrl_ctx);
            cm_pop(session->stack);
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        if (knl_make_key(session, cursor, index, key) != GS_SUCCESS) {
            (void)mtrl_sort_clean(sort_ctrl);
            mtrl_release_context(&ctx->mtrl_ctx);
            cm_pop(session->stack);
            return GS_ERROR;
        }

        if (index->desc.cr_mode == CR_ROW) {
            ((btree_key_t *)key)->scn = cursor->scn;
        } else {
            ((pcrb_key_t *)key)->itl_id = GS_INVALID_ID8;
        }

        if (sort_ctrl->use_parallel) {
            if (GS_SUCCESS != mtrl_insert_row_parallel(&ctx->mtrl_ctx, 0, key, sort_ctrl, &rid)) {
                (void)mtrl_sort_clean(sort_ctrl);
                mtrl_release_context(&ctx->mtrl_ctx);
                cm_pop(session->stack);
                return GS_ERROR;
            }
        } else {
            if (GS_SUCCESS != mtrl_insert_row(&ctx->mtrl_ctx, 0, key, &rid)) {
                mtrl_release_context(&ctx->mtrl_ctx);
                cm_pop(session->stack);
                return GS_ERROR;
            }
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            (void)mtrl_sort_clean(sort_ctrl);
            mtrl_release_context(&ctx->mtrl_ctx);
            cm_pop(session->stack);
            return GS_ERROR;
        }
    } while (!cursor->eof);

    cm_pop(session->stack);

    if (IS_PART_INDEX(index)) {
        if (db_construct_index(ctx, sort_ctrl) != GS_SUCCESS) {
            mtrl_release_context(&ctx->mtrl_ctx);
            return GS_ERROR;
        }
        mtrl_release_context(&ctx->mtrl_ctx);
    }

    return GS_SUCCESS;
}

static status_t db_fill_part_index(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc, index_t *index,
    btree_mt_context_t *ctx, mtrl_sort_ctrl_t *sort_ctrl)
{
    part_table_t *part_table = ((table_t *)cursor->table)->part_table;
    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        compart = TABLE_GET_PART(cursor->table, i);
        if (!IS_READY_PART(compart)) {
            continue;
        }

        cursor->part_loc.part_no = i;
        if (IS_PARENT_TABPART(&compart->desc)) {
            for (uint32 j = 0; j < compart->desc.subpart_cnt; j++) {
                subpart = PART_GET_SUBENTITY(part_table, compart->subparts[j]);
                if (subpart == NULL) {
                    continue;
                }

                cursor->part_loc.subpart_no = j;
                if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                    mtrl_release_context(&ctx->mtrl_ctx);
                    return GS_ERROR;
                }

                if (db_fill_index_entity(session, cursor, index, ctx, sort_ctrl) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
            cursor->part_loc.subpart_no = GS_INVALID_ID32;
            if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                mtrl_release_context(&ctx->mtrl_ctx);
                return GS_ERROR;
            }

            if (db_fill_index_entity(session, cursor, index, ctx, sort_ctrl) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static inline void db_reset_mtr_ctx(mtrl_context_t *ctx)
{
    if (ctx->session != NULL) {
        knl_session_t *ctx_se = (knl_session_t *)ctx->session;
        ctx_se->thread_shared = GS_FALSE;
    }
}

static status_t db_create_all_btree_segments(knl_session_t *session, table_t *table, index_t *index, uint32 *seg_cnt)
{
    bool32 need_redo = !IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type);
    index_part_t *index_part = NULL;
    table_part_t *table_part = NULL;
    index_part_t *index_sub_part = NULL;
    table_part_t *table_sub_part = NULL;

    uint32 seg_count = 0;
    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        index_part = INDEX_GET_PART(index, i);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            if (table_part->heap.segment == NULL) {
                continue;
            }

            if (db_create_btree_segment(session, index, index_part, &index_part->btree, need_redo) != GS_SUCCESS) {
                return GS_ERROR;
            }
            seg_count++;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_sub_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            index_sub_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (table_sub_part == NULL || index_sub_part == NULL || table_sub_part->heap.segment == NULL) {
                continue;
            }

            if (db_create_btree_segment(session, index, index_sub_part,
                &index_sub_part->btree, need_redo) != GS_SUCCESS) {
                return GS_ERROR;
            }
            seg_count++;
        }
    }

    *seg_cnt = seg_count;
    return GS_SUCCESS;
}

#define OPTIMAL_PARAL_FETCH_COUNT 4
#define MIN_PARAL_FETCH_COUNT 2
#define OPTIMAL_PARAL_PART_COUNT 10
#define OPTIMAL_CPU_COUNT 64
#define OPTIMAL_PART_COUNT 64

static void db_prepare_part_ctx(knl_session_t *session, uint32 *paral_no, idxpart_paral_ctx_t *paral_ctx)
{
    uint32 cpu_count = session->kernel->attr.cpu_count;
    uint32 seg_count = paral_ctx->part_info.seg_count;
    uint32 temp_paral_no = *paral_no;

    // if there is few cpu count, too many threads have no advantage;
    temp_paral_no = seg_count < temp_paral_no ? seg_count : temp_paral_no;
    if (cpu_count <= OPTIMAL_CPU_COUNT) {
        paral_ctx->paral_count = seg_count < *paral_no ? OPTIMAL_PARAL_FETCH_COUNT : MIN_PARAL_FETCH_COUNT;
        *paral_no = temp_paral_no;
        return;
    }

    /*
     * if cpu count is enough, part count is huge, the parallelism give priority to part_parallel;
     * if there is few part count with large paral_no,
     * we suppose each partition is huge and give priority to fetch_parallel;
     */
    if (seg_count > OPTIMAL_PART_COUNT) {
        if (*paral_no < OPTIMAL_PARAL_PART_COUNT) {
            paral_ctx->paral_count = MIN_PARAL_FETCH_COUNT;
        } else {
            paral_ctx->paral_count = MAX((cpu_count - temp_paral_no) / temp_paral_no, OPTIMAL_PARAL_FETCH_COUNT);
        }
    } else {
        if (*paral_no < OPTIMAL_PARAL_PART_COUNT) {
            paral_ctx->paral_count = MIN((cpu_count - temp_paral_no) / temp_paral_no, OPTIMAL_PARAL_FETCH_COUNT);
        } else {
            paral_ctx->paral_count = MIN((cpu_count - temp_paral_no) / temp_paral_no, *paral_no);
        }
    }

    temp_paral_no = MIN(MAX_IDX_PARAL_THREADS, temp_paral_no);
    paral_ctx->paral_count = paral_ctx->paral_count < MIN_PARAL_FETCH_COUNT ? MIN_PARAL_FETCH_COUNT :
        MIN(MAX_IDX_PARAL_THREADS, paral_ctx->paral_count);
    *paral_no = temp_paral_no;
}

status_t db_fill_part_index_paral(knl_session_t *session, knl_dictionary_t *dc, index_t *index, uint32 paral_no)
{
    // create all index segment
    uint32 segment_cnt = 0;
    table_t *table = DC_TABLE(dc);
    idxpart_paral_ctx_t paral_ctx;
    errno_t err = memset_sp(&paral_ctx, sizeof(idxpart_paral_ctx_t), 0, sizeof(idxpart_paral_ctx_t));
    knl_securec_check(err);

    if (db_create_all_btree_segments(session, table, index, &segment_cnt) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (segment_cnt == 0) {
        return GS_SUCCESS;
    }

    // initializations, alloc sessions and create threads
    paral_ctx.private_dc = dc;
    paral_ctx.indexes = &index;
    paral_ctx.index_cnt = 1;
    paral_ctx.part_info.seg_count = segment_cnt;
    db_prepare_part_ctx(session, &paral_no, &paral_ctx);

    if (idxpart_alloc_resource(session, paral_no, &paral_ctx) != GS_SUCCESS) {
        idxpart_release_resource(paral_no, &paral_ctx);
        return GS_ERROR;
    }

    // waiting all threads ended
    uint32 i, count;
    for (;;) {
        count = paral_no;
        for (i = 0; i < paral_no; i++) {
            if (!paral_ctx.workers[i].is_working) {
                count--;
            }

            if (paral_ctx.workers[i].thread.result != GS_SUCCESS) {
                GS_THROW_ERROR(ERR_BUILD_INDEX_PARALLEL, paral_ctx.err_msg);
                idxpart_release_resource(paral_no, &paral_ctx);
                return GS_ERROR;
            }
        }
        if (count == 0) {
            break;
        }

        if (knl_check_session_status(session) != GS_SUCCESS) {
            idxpart_release_resource(paral_no, &paral_ctx);
            return GS_ERROR;
        }
        cm_sleep(100);
    }

    idxpart_release_resource(paral_no, &paral_ctx);
    return GS_SUCCESS;
}

static void db_init_paral_ctx(idx_paral_sort_ctx_t *paral_ctx, knl_dictionary_t *dc, index_t *index,
    knl_part_locate_t part_loc)
{
    table_t *table = DC_TABLE(dc);

    paral_ctx->private_dc = dc;
    paral_ctx->part_info.curr_part = part_loc;
    paral_ctx->btree[0] = &index->btree;
    paral_ctx->index_count = 1;

    if (IS_PART_INDEX(index)) {
        index_part_t *index_part = INDEX_GET_PART(index, part_loc.part_no);
        if (IS_PARENT_IDXPART(&index_part->desc)) {
            index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[part_loc.subpart_no]);
        }
        paral_ctx->btree[0] = &index_part->btree;
    } else if (IS_PART_TABLE(table)) {
        paral_ctx->is_global = GS_TRUE;
    }
}

static status_t db_prepare_paral_ctx(knl_session_t *session, knl_dictionary_t *dc,
    index_t *index, knl_part_locate_t part_loc, idx_paral_sort_ctx_t *paral_ctx)
{
    knl_paral_range_t paral_range;
    idx_sort_worker_t *worker = NULL;

    db_init_paral_ctx(paral_ctx, dc, index, part_loc);
    errno_t err = memset_sp(&paral_range, sizeof(knl_paral_range_t), 0, sizeof(knl_paral_range_t));
    knl_securec_check(err);
    if (!paral_ctx->is_global) {
        paral_range.workers = paral_ctx->paral_count;
        if (knl_get_paral_schedule(session, dc, paral_ctx->part_info.curr_part,
            paral_ctx->paral_count, &paral_range) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (paral_range.workers < paral_ctx->paral_count) {
            paral_ctx->paral_count = paral_range.workers;
        }
        if (paral_range.workers == 0) {
            return GS_SUCCESS;
        }
    }

    uint32 mem_size = sizeof(idx_sort_worker_t) * paral_ctx->paral_count;
    paral_ctx->workers = (idx_sort_worker_t*)cm_push(session->stack, mem_size);
    err = memset_sp(paral_ctx->workers, mem_size, 0, mem_size);
    knl_securec_check(err);

    uint32 main_pool_id = session->id % session->kernel->temp_ctx_count;
    for (uint32 i = 0; i < paral_ctx->paral_count; i++) {
        worker = &paral_ctx->workers[i];
        worker->id = i;
        worker->pool_id = (main_pool_id + i) % session->kernel->temp_ctx_count;
        if (!paral_ctx->is_global) {
            worker->scan_range.l_page = paral_range.l_page[i];
            worker->scan_range.r_page = paral_range.r_page[i];
        }

        if (paral_ctx->sort_info.count == 0) {
            paral_ctx->sort_info.first = i;
            paral_ctx->sort_info.last = i;
            paral_ctx->sort_info.count++;
        } else {
            paral_ctx->sort_info.last = i;
            paral_ctx->sort_info.count++;
            paral_ctx->workers[i - 1].next_id = i;
        }
    }
    paral_ctx->workers[paral_ctx->paral_count - 1].next_id = GS_INVALID_ID8;
    return GS_SUCCESS;
}

status_t db_manage_sub_workers(knl_session_t *session, idx_paral_sort_ctx_t *paral_ctx)
{
    idx_start_all_workers(paral_ctx, BUILD_SEGMENT_PHASE);
    if (idx_wait_all_workers(session, paral_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    idx_start_all_workers(paral_ctx, MERGE_SEGMENT_PHASE);
    if (idx_wait_all_workers(session, paral_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    paral_ctx->phase = COMPLETE_PHASE;
    return GS_SUCCESS;
}

status_t db_fill_index_entity_paral(knl_session_t *session, knl_dictionary_t *dc, index_t *index,
    knl_part_locate_t part_loc, uint32 paral_no)
{
    CM_SAVE_STACK(session->stack);
    idx_paral_sort_ctx_t *paral_ctx = (idx_paral_sort_ctx_t*)cm_push(session->stack, sizeof(idx_paral_sort_ctx_t));
    errno_t err = memset_sp(paral_ctx, sizeof(idx_paral_sort_ctx_t), 0, sizeof(idx_paral_sort_ctx_t));
    knl_securec_check(err);
    paral_ctx->paral_count = paral_no;

    // initial
    if (db_prepare_paral_ctx(session, dc, index, part_loc, paral_ctx) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (paral_ctx->paral_count == 0) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    GS_LOG_RUN_INF("[INDEX] session %d begin to fill index, paral_count %d", session->id, paral_ctx->paral_count);
    if (idx_fetch_alloc_resource(session, paral_ctx)) {
        idx_fetch_release_resource(paral_ctx);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    // waiting all threads ended
    if (db_manage_sub_workers(session, paral_ctx) != GS_SUCCESS) {
        idx_fetch_release_resource(paral_ctx);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cm_spin_lock(&paral_ctx->parl_lock, NULL);
    if (paral_ctx->sort_info.count == 0) {
        cm_spin_unlock(&paral_ctx->parl_lock);
        idx_fetch_release_resource(paral_ctx);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }
    uint32 id = paral_ctx->sort_info.first;
    uint32 id2 = paral_ctx->workers[id].next_id;
    cm_spin_unlock(&paral_ctx->parl_lock);

    // construct index segment
    GS_LOG_RUN_INF("[INDEX] session %d begin to construct index", session->id);
    btree_mt_context_t ctx;
    idx_init_construct_ctx(paral_ctx, id, id2, &ctx);
    if (idx_construct(&ctx) != GS_SUCCESS) {
        idx_fetch_release_resource(paral_ctx);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    idx_fetch_release_resource(paral_ctx);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static void db_init_multi_paral_ctx(idx_paral_sort_ctx_t *paral_ctx, knl_dictionary_t *dc, index_t **index,
    uint8 index_count, knl_part_locate_t part_loc)
{
    paral_ctx->private_dc = dc;
    paral_ctx->part_info.curr_part = part_loc;
    paral_ctx->index_count = index_count;

    if (!IS_PART_INDEX(index[0])) {
        paral_ctx->is_global = GS_TRUE;
    }

    for (uint8 i = 0; i < index_count; i++) {
        paral_ctx->btree[i] = &index[i]->btree;

        if (IS_PART_INDEX(index[i])) {
            index_part_t *index_part = INDEX_GET_PART(index[i], part_loc.part_no);
            if (IS_PARENT_IDXPART(&index_part->desc)) {
                index_part = PART_GET_SUBENTITY(index[i]->part_index, index_part->subparts[part_loc.subpart_no]);
            }
            paral_ctx->btree[i] = &index_part->btree;
        }
    }
}

static status_t db_prepare_multi_paral_ctx(knl_session_t *session, knl_dictionary_t *dc,
    index_t **index, uint8 index_count, knl_part_locate_t part_loc, idx_paral_sort_ctx_t *paral_ctx)
{
    knl_paral_range_t paral_range;
    idx_build_worker_t *build_worker = NULL;

    db_init_multi_paral_ctx(paral_ctx, dc, index, index_count, part_loc);
    errno_t err = memset_sp(&paral_range, sizeof(knl_paral_range_t), 0, sizeof(knl_paral_range_t));
    knl_securec_check(err);

    paral_range.workers = paral_ctx->build_count;
    if (!paral_ctx->is_global) {
        if (knl_get_paral_schedule(session, dc, paral_ctx->part_info.curr_part,
            paral_ctx->build_count, &paral_range) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (paral_range.workers < paral_ctx->build_count) {
            paral_ctx->build_count = paral_range.workers;
        }
        if (paral_range.workers == 0) {
            return GS_SUCCESS;
        }
    }

    paral_ctx->build_workers = (idx_build_worker_t*)cm_push(session->stack,
        sizeof(idx_build_worker_t) * paral_ctx->build_count);
    err = memset_sp(paral_ctx->build_workers, sizeof(idx_build_worker_t) * paral_ctx->build_count,
        0, sizeof(idx_build_worker_t) * paral_ctx->build_count);
    knl_securec_check(err);

    uint32 main_pool_id = session->id % session->kernel->temp_ctx_count;
    for (uint32 i = 0; i < paral_ctx->build_count; i++) {
        build_worker = &paral_ctx->build_workers[i];
        build_worker->pool_id = (main_pool_id + i) % session->kernel->temp_ctx_count;
        build_worker->index_count = paral_ctx->index_count;
        if (!paral_ctx->is_global) {
            build_worker->scan_range.l_page = paral_range.l_page[i];
            build_worker->scan_range.r_page = paral_range.r_page[i];
        }
    }
    return GS_SUCCESS;
}

status_t db_manage_multi_sub_workers(knl_session_t *session, idx_paral_sort_ctx_t *paral_ctx)
{
    // all workers begin to sort own segment
    idx_start_all_workers(paral_ctx, SORT_SEGMENT_PHASE);

    // check sort end and begin to merge segments in turns
    if (idx_switch_create_phase(session, paral_ctx, SORT_SEGMENT_PHASE, MERGE_SEGMENT_PHASE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // check merge end and choose one thread to construct index in turns
    if (idx_switch_create_phase(session, paral_ctx, MERGE_SEGMENT_PHASE, CONSTRUCT_INDEX_PHASE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (idx_wait_all_workers(session, paral_ctx) != GS_SUCCESS) {
        return GS_ERROR;
    }

    paral_ctx->phase = COMPLETE_PHASE;
    return GS_SUCCESS;
}

status_t db_fill_multi_indexes_paral(knl_session_t *session, knl_dictionary_t *dc, index_t **indexes,
    uint32 index_cnt, uint32 paral_cnt, knl_part_locate_t part_loc)
{
    CM_SAVE_STACK(session->stack);
    idx_paral_sort_ctx_t *paral_ctx = (idx_paral_sort_ctx_t*)cm_push(session->stack, sizeof(idx_paral_sort_ctx_t));
    errno_t err = memset_sp(paral_ctx, sizeof(idx_paral_sort_ctx_t), 0, sizeof(idx_paral_sort_ctx_t));
    knl_securec_check(err);
    paral_ctx->build_count = paral_cnt;

    // initial
    if (db_prepare_multi_paral_ctx(session, dc, indexes, index_cnt, part_loc, paral_ctx) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (paral_ctx->build_count == 0) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    if (idx_build_alloc_resource(session, paral_ctx)) {
        idx_build_release_resource(paral_ctx, GS_TRUE);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    // waiting build threads ended
    idx_start_build_workers(paral_ctx, BUILD_SEGMENT_PHASE);
    if (idx_wait_build_workers(session, paral_ctx) != GS_SUCCESS) {
        idx_build_release_resource(paral_ctx, GS_TRUE);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    idx_close_build_thread(paral_ctx);

    if (idx_construct_alloc_resource(session, paral_ctx)) {
        idx_construct_release_resource(paral_ctx);
        idx_build_release_resource(paral_ctx, GS_FALSE);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    // waiting merge and construct threads ended
    if (db_manage_multi_sub_workers(session, paral_ctx) != GS_SUCCESS) {
        idx_construct_release_resource(paral_ctx);
        idx_build_release_resource(paral_ctx, GS_FALSE);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    idx_construct_release_resource(paral_ctx);
    idx_build_release_resource(paral_ctx, GS_FALSE);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_fill_index_paral(knl_session_t *session, knl_dictionary_t *dc, index_t *index, uint32 paral_no)
{
    if (index->desc.is_func) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index parallel", "functional index");
        return GS_ERROR;
    }

    dc_load_all_part_segments(session, dc->handle);
    if (IS_PART_INDEX(index)) {
        return db_fill_part_index_paral(session, dc, index, paral_no);
    }

    btree_t *btree = &index->btree;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(dc->type);
    knl_part_locate_t part_loc = { 0, 0 };

    if (db_create_btree_segment(session, index, NULL, btree, need_redo) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_fill_index_entity_paral(session, dc, index, part_loc, paral_no) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

/*
 * Description     : generate index keys for index when creating index
 * Input           : dc : dictionary of table
 * Input           : index : the new created index
 * Output          : NA
 * Return Value    : status_t
 * History         : 1. 2017/4/26,  add description
 */
static status_t db_fill_index(knl_session_t *session, knl_cursor_t *cursor,
    knl_table_desc_t desc, uint32 iid, uint32 paral_no)
{
    btree_mt_context_t ctx;
    mtrl_sort_ctrl_t sort_ctrl;
    knl_dictionary_t dc;

    if (dc_open_table_private(session, desc.uid, desc.id, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    index_t *index = dc_find_index_by_id((dc_entity_t *)dc.handle, iid);
    if (index == NULL) {
        dc_close_table_private(&dc);
        GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "index", iid);
        return GS_ERROR;
    }

    if (paral_no != 0) {
        status_t status = db_fill_index_paral(session, &dc, index, paral_no);
        dc_close_table_private(&dc);
        return status;
    }

    uint32 size_context = sizeof(btree_mt_context_t);
    uint32 size_ctrl = sizeof(mtrl_sort_ctrl_t);
    errno_t err = memset_sp(&ctx, size_context, 0, size_context);
    knl_securec_check(err);
    err = memset_sp(&sort_ctrl, size_ctrl, 0, size_ctrl);
    knl_securec_check(err);

    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;

    if (knl_open_cursor(session, cursor, &dc) != GS_SUCCESS) {
        dc_close_table_private(&dc);
        return GS_ERROR;
    }

    if (IS_PART_TABLE(cursor->table)) {
        if (db_fill_part_index(session, cursor, &dc, index, &ctx, &sort_ctrl) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            dc_close_table_private(&dc);
            db_reset_mtr_ctx(&ctx.mtrl_ctx);
            return GS_ERROR;
        }
    } else {
        if (db_fill_index_entity(session, cursor, index, &ctx, &sort_ctrl) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            dc_close_table_private(&dc);
            db_reset_mtr_ctx(&ctx.mtrl_ctx);
            return GS_ERROR;
        }
    }

    knl_close_cursor(session, cursor);

    if (ctx.initialized) {
        if (db_construct_index(&ctx, &sort_ctrl) != GS_SUCCESS) {
            mtrl_release_context(&ctx.mtrl_ctx);
            dc_close_table_private(&dc);
            db_reset_mtr_ctx(&ctx.mtrl_ctx);
            return GS_ERROR;
        }
        mtrl_release_context(&ctx.mtrl_ctx);
    }

    dc_close_table_private(&dc);
    db_reset_mtr_ctx(&ctx.mtrl_ctx);

    return GS_SUCCESS;
}

static status_t db_write_shadow_sysindex(knl_session_t *session, knl_index_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    text_t column_list;
    char buf[COLUMN_LIST_BUF_LEN];
    uint32 i;
    space_t *space;
    status_t status;

    space = SPACE_GET(desc->space_id);

    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "write to shadow_index$ failed");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SHADOW_INDEX_ID, GS_INVALID_ID32);

    column_list.len = 0;
    column_list.str = buf;
    for (i = 0; i < desc->column_count; i++) {
        cm_concat_int32(&column_list, sizeof(buf), desc->columns[i]);
        if (i + 1 < desc->column_count) {
            if (cm_concat_string(&column_list, COLUMN_LIST_BUF_LEN, ",") != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    row_init(&ra, cursor->buf, KNL_MAX_ROW_SIZE, 17);
    (void)row_put_int32(&ra, desc->uid);       // user
    (void)row_put_int32(&ra, desc->table_id);  // table
    (void)row_put_int32(&ra, desc->id);        // id
    (void)row_put_str(&ra, desc->name);  // name

    (void)row_put_int32(&ra, desc->space_id);          // space
    (void)row_put_int64(&ra, desc->org_scn);           // sequence
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);  // entry
    (void)row_put_int32(&ra, desc->primary);           // primary key
    (void)row_put_int32(&ra, desc->unique);            // unique
    (void)row_put_int32(&ra, desc->type);              // type
    (void)row_put_int32(&ra, desc->column_count);      // column count
    (void)row_put_text(&ra, &column_list);             // columns
    (void)row_put_int32(&ra, desc->initrans);          // initrans
    (void)row_put_int32(&ra, desc->cr_mode);           // consistent read mode
    (void)row_put_int32(&ra, desc->flags);             // flags
    (void)row_put_int32(&ra, desc->parted);            // is parted index
    (void)row_put_int32(&ra, desc->pctfree);           // index pctfree

    status = knl_internal_insert(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t db_drop_shadow_index(knl_session_t *session, uint32 user_id, uint32 table_id, bool32 clean_segment)
{
    knl_cursor_t *cursor = NULL;
    index_t index;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SHADOW_INDEX_ID, IX_SYS_SHADOW_INDEX_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &user_id, sizeof(uint32),
                     IX_COL_SYS_SHADOW_INDEX_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id,
        sizeof(uint32), IX_COL_SYS_SHADOW_INDEX_001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        dc_convert_index(session, cursor, &index.desc);

        if (!clean_segment) {
            index.desc.entry = INVALID_PAGID;
            GS_LOG_RUN_WAR("db drop shadow indexes found nologging table ID(%u)", table_id);
        }
        btree_drop_segment(session, &index);

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (index.desc.parted) {
            if (db_drop_shadow_indexpart(session, user_id, table_id, clean_segment) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static status_t db_clean_shadow_index(knl_session_t *session, uint32 user_id, uint32 table_id, bool32 clean_segment)
{
    if (db_drop_shadow_index(session, user_id, table_id, clean_segment) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return db_drop_shadow_indexpart(session, user_id, table_id, clean_segment);
}

static status_t db_create_shadow_index(knl_session_t *session, knl_dictionary_t *dc, index_t *index,
    knl_index_def_t *def, rebuild_info_t rebuild_info)
{
    knl_part_obj_def_t *part_def = NULL;
    space_t *space = NULL;

    if (def == NULL) {
        part_def = NULL;
    } else {
        part_def = def->part_def;
    }

    space = SPACE_GET(index->desc.space_id);

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_clean_shadow_index(session, dc->uid, dc->oid, !SPACE_IS_NOLOGGING(space)) != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        return GS_ERROR;
    }

    knl_end_auton_rm(session, GS_SUCCESS);

    if ((def && def->space.len != 0) || (rebuild_info.spc_id != GS_INVALID_ID32)) {
        index->desc.is_stored = GS_TRUE;
    }

    if (IS_PART_INDEX(index)) {
        if (db_create_part_shadow_index(session, dc, index, part_def, rebuild_info) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_write_shadow_sysindex(session, &index->desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (btree_create_segment(session, index) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (btree_generate_create_undo(session, index->desc.entry, index->desc.space_id,
            IS_LOGGING_TABLE_BY_TYPE(dc->type)) != GS_SUCCESS) {
            btree_drop_segment(session, index);
            return GS_ERROR;
        }

        if (db_write_shadow_sysindex(session, &index->desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_delete_shadow_sysindex(knl_session_t *session, knl_cursor_t *cursor, index_t *index)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SHADOW_INDEX_ID, IX_SYS_SHADOW_INDEX_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.uid,
                     sizeof(uint32), IX_COL_SYS_SHADOW_INDEX_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &index->desc.table_id,
                     sizeof(uint32), IX_COL_SYS_SHADOW_INDEX_001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * Description     : Implementation of create index
 * Input           : def : definition of index
 * Output          : NA
 * Return Value    : status_t
 * History         : 1. 2017/4/26,  add description
 */
status_t db_create_index(knl_session_t *session, knl_index_def_t *def, knl_dictionary_t *dc, bool32 is_cons,
                         uint32 *index_id)
{
    index_t index;

    if (dc->type == DICT_TYPE_TABLE_EXTERNAL) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index or cons", "external organized table");
        return GS_ERROR;
    }

    uint32 size_index = sizeof(index_t);
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    if (db_check_table_nologging_attr(table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    errno_t err = memset_sp((void *)&index, size_index, 0, size_index);
    knl_securec_check(err);
    index.entity = entity;

    knl_index_desc_t *desc = &index.desc;
    index.desc.is_enforced = is_cons; /* << enforcement index is used by constraint, which cannot be dropped */
    index.desc.is_cons = is_cons;

    if (db_alloc_index_id(entity, def, &index.desc.id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (db_verify_index_def(session, dc, def, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    if (dc->type == DICT_TYPE_TABLE) {
        if (IS_SYS_TABLE(table)) {
            if (GS_SUCCESS != btree_create_segment(session, &index)) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }
    }

    if (GS_SUCCESS != db_write_sysindex(session, cursor, desc)) {
        int32 err_code = cm_get_error_code();
        if (err_code == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "index", index.desc.name);
        }
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_update_index_count(session, cursor, &table->desc, GS_TRUE)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (IS_PART_INDEX(&index)) {
        if (!IS_COMPART_TABLE(table->part_table) && def->part_def != NULL && def->part_def->is_composite) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create composite partition index",
                "non composite partition table");
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_create_part_index(session, cursor, &index, def->part_def) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    // reset the cursor to avoid the dirty data introduced from previous step
    cursor = knl_push_cursor(session);

    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        if (GS_SUCCESS != temp_db_fill_index(session, cursor, &index, def->parallelism)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    } else {
        if (GS_SUCCESS != db_fill_index(session, cursor, table->desc, index.desc.id, def->parallelism)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    if (index_id != NULL) {
        *index_id = index.desc.id;
    }

    return GS_SUCCESS;
}

#define SHADOW_INDEX_FILL_BATCH 100
static void db_fill_shwidx_get_part(index_t *index, shadow_index_t *shadow_index, knl_cursor_t *build_cursor,
    knl_cursor_t *scan_cursor, knl_part_locate_t part_loc)
{
    /* rebuild all part of part_index */
    if (IS_PART_INDEX(index)) {
        build_cursor->index_part = INDEX_GET_PART(build_cursor->index, scan_cursor->part_loc.part_no);
        if (scan_cursor->part_loc.subpart_no != GS_INVALID_ID32) {
            knl_panic_log(IS_PARENT_IDXPART(&((index_part_t *)build_cursor->index_part)->desc),
                "the index_part is not parent_idxpart, panic info: page %u-%u type %u table %s index %s index_part %s",
                build_cursor->rowid.file, build_cursor->rowid.page, ((page_head_t *)build_cursor->page_buf)->type,
                ((table_t *)build_cursor->table)->desc.name, ((index_t *)build_cursor->index)->desc.name,
                ((index_part_t *)build_cursor->index_part)->desc.name);
            uint32 subpart_no = scan_cursor->part_loc.subpart_no;
            index_part_t *index_part = (index_part_t *)build_cursor->index_part;
            build_cursor->index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
        }
    }

    /* only rebuild one part */
    if (IS_PART_INDEX(index) && part_loc.part_no != GS_INVALID_ID32) {
        if (SHADOW_INDEX_IS_PART(shadow_index)) {
            build_cursor->index_part = &shadow_index->index_part;
        } else {
            build_cursor->index_part =  INDEX_GET_PART(build_cursor->index, part_loc.part_no);
            if (part_loc.subpart_no != GS_INVALID_ID32) {
                uint32 subpart_no = part_loc.subpart_no;
                index_part_t *index_part = (index_part_t *)build_cursor->index_part;
                build_cursor->index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[subpart_no]);
            }
        }
    }
}
static status_t db_shadow_index_make_key(knl_session_t *session, knl_cursor_t *scan_cursor, index_t *index, char *key)
{
    errno_t ret;

    if (IS_INDEX_ONLY_SCAN(scan_cursor)) {
        idx_decode_row(session, scan_cursor, scan_cursor->offsets, scan_cursor->lens, NULL);
        if (scan_cursor->index_dsc) {
            ret = memcpy_sp(key, GS_KEY_BUF_SIZE, scan_cursor->scan_range.r_buf, GS_KEY_BUF_SIZE);
        } else {
            ret = memcpy_sp(key, GS_KEY_BUF_SIZE, scan_cursor->scan_range.l_buf, GS_KEY_BUF_SIZE);
        }

        knl_securec_check(ret);
        return GS_SUCCESS;
    }

    cm_decode_row((char *)scan_cursor->row, scan_cursor->offsets, scan_cursor->lens, NULL);
    return knl_make_key(session, scan_cursor, index, key);
}

static status_t db_fill_shadow_index_entity(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *scan_cursor,
    knl_cursor_t *build_cursor, knl_part_locate_t part_loc, index_build_mode_t build_mode)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    shadow_index_t *shadow_index = entity->table.shadow_index;
    index_t *index = SHADOW_INDEX_ENTITY(shadow_index);
    status_t status;
    uint16 count = 0;

    build_cursor->skip_lock = (bool8)(REBUILD_INDEX_PARALLEL == build_mode);
    build_cursor->action = CURSOR_ACTION_INSERT;
    if (knl_open_cursor(session, build_cursor, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_PART_TABLE(scan_cursor->table)) {
        scan_cursor->part_loc = part_loc;
        if (build_mode != REBUILD_INDEX_PARALLEL &&
            knl_reopen_cursor(session, scan_cursor, dc) != GS_SUCCESS) {
            knl_close_cursor(session, build_cursor);
            return GS_ERROR;
        }
    }

    build_cursor->index = index;

    db_fill_shwidx_get_part(index, shadow_index, build_cursor, scan_cursor, part_loc);
    build_cursor->part_loc = part_loc;
    for (;;) {
        if (knl_fetch(session, scan_cursor) != GS_SUCCESS) {
            knl_close_cursor(session, build_cursor);
            return GS_ERROR;
        }

        if (scan_cursor->eof) {
            knl_close_cursor(session, build_cursor);
            if (build_mode == CREATE_INDEX_ONLINE && IS_UNIQUE_PRIMARY_INDEX(index)) {
                knl_commit(session);
            }
            return GS_SUCCESS;
        }

        if (session->canceled) {
            knl_close_cursor(session, build_cursor);
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            knl_close_cursor(session, build_cursor);
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        if (db_shadow_index_make_key(session, scan_cursor, index, build_cursor->key) != GS_SUCCESS) {
            knl_close_cursor(session, build_cursor);
            return GS_ERROR;
        }

        if (index->desc.cr_mode == CR_PAGE) {
            status = pcrb_insert_into_shadow(session, build_cursor);
        } else {
            status = btree_insert_into_shadow(session, build_cursor);
        }

        if (status != GS_SUCCESS) {
            int32 err_code;
            const char *err_msg = NULL;
            cm_get_error(&err_code, &err_msg, NULL);

            if (err_code != ERR_DUPLICATE_KEY) {
                knl_close_cursor(session, build_cursor);
                return GS_ERROR;
            }

            /* build_cursor->rowid is not initialized, so we use scan_cursor->rowid to compare with
             * conflict_rid instead
             */
            if (build_mode == REBUILD_INDEX_ONLINE || IS_SAME_ROWID(scan_cursor->rowid, build_cursor->conflict_rid)) {
                cm_reset_error();
            } else {
                knl_close_cursor(session, build_cursor);
                return GS_ERROR;
            }
        }

        if (build_mode == CREATE_INDEX_ONLINE && IS_UNIQUE_PRIMARY_INDEX(index)) {
            count++;
            if (count == SHADOW_INDEX_FILL_BATCH) {
                knl_commit(session);
                count = 0;
            }
        }
    }
}

static status_t db_fill_shwidx_all_parts(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, index_build_mode_t build_mode)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_compart = NULL;
    part_table_t *part_table = table->part_table;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *build_cursor = knl_push_cursor(session);

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_compart = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_compart)) {
            continue;
        }

        part_loc.part_no = i;
        if (!IS_PARENT_TABPART(&table_compart->desc)) {
            part_loc.subpart_no = GS_INVALID_ID32;
            if (db_fill_shadow_index_entity(session, dc, cursor, build_cursor, part_loc,
                build_mode) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < table_compart->desc.subpart_cnt; j++) {
            part_loc.subpart_no = j;
            if (db_fill_shadow_index_entity(session, dc, cursor, build_cursor, part_loc,
                build_mode) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_fill_shadow_part_index(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, index_build_mode_t build_mode)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_compart = NULL;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *build_cursor = knl_push_cursor(session);

    if (part_loc.part_no == GS_INVALID_ID32) {    // rebuild all parts
        if (db_fill_shwidx_all_parts(session, cursor, dc, part_loc, build_mode) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    } else if (part_loc.subpart_no == GS_INVALID_ID32) {    // reduild all subparts of one compart
        table_compart = TABLE_GET_PART(table, part_loc.part_no);
        if (!IS_PARENT_TABPART(&table_compart->desc)) {
            if (db_fill_shadow_index_entity(session, dc, cursor, build_cursor, part_loc, build_mode) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            CM_RESTORE_STACK(session->stack);
            return GS_SUCCESS;
        }

        for (uint32 i = 0; i < table_compart->desc.subpart_cnt; i++) {
            part_loc.subpart_no = i;
            if (db_fill_shadow_index_entity(session, dc, cursor, build_cursor, part_loc, build_mode) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }
    } else {    // only rebuild one subpart
        if (db_fill_shadow_index_entity(session, dc, cursor, build_cursor, part_loc,
            build_mode) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_fill_shadow_index(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, index_build_mode_t build_mode)
{
    if (IS_PART_TABLE(cursor->table)) {
        if (db_fill_shadow_part_index(session, cursor, dc, part_loc, build_mode) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        CM_SAVE_STACK(session->stack);
        knl_cursor_t *build_cursor = knl_push_cursor(session);
        part_loc.part_no = GS_INVALID_ID32;
        part_loc.subpart_no = GS_INVALID_ID32;
        if (db_fill_shadow_index_entity(session, dc, cursor, build_cursor, part_loc, build_mode) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        CM_RESTORE_STACK(session->stack);
    }

    return GS_SUCCESS;
}

static status_t db_create_index_directly(knl_session_t *session, knl_index_def_t *def, index_t *index)
{
    table_t *table = &index->entity->table;
    knl_cursor_t *scan_cursor = NULL;

    CM_SAVE_STACK(session->stack);

    scan_cursor = knl_push_cursor(session);

    if (db_write_sysindex(session, scan_cursor, &index->desc) != GS_SUCCESS) {
        int32 err_code = cm_get_error_code();
        if (err_code == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "index", index->desc.name);
        }
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_update_index_count(session, scan_cursor, &table->desc, GS_TRUE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (IS_PART_INDEX(index)) {
        if (db_create_part_index(session, scan_cursor, index, def->part_def) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static bool32 db_judge_heap_segment_null(table_t *table)
{
    part_table_t *part_table = NULL;
    table_part_t *table_part = NULL;

    if (IS_PART_TABLE(table)) {
        part_table = table->part_table;
        for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
            table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            if (!IS_PARENT_TABPART(&table_part->desc)) {
                if (table_part->heap.segment != NULL) {
                    return GS_FALSE;
                }
                continue;
            }

            table_part_t *table_subpart = NULL;
            for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
                table_subpart = PART_GET_SUBENTITY(part_table, table_part->subparts[j]);
                if (table_subpart == NULL) {
                    continue;
                }

                if (table_subpart->heap.segment != NULL) {
                    return GS_FALSE;
                }
            }
        }
    } else {
        if (table->heap.segment != NULL) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

static bool32 db_part_table_has_segment(knl_session_t *session, knl_dictionary_t *new_dc)
{
    table_t *table = DC_TABLE(new_dc);
    table_part_t *table_part = NULL;
    bool32 is_null = GS_TRUE;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (db_tabpart_has_segment(table->part_table, table_part)) {
            is_null = GS_FALSE;
            break;
        }
    }
    return is_null;
}

static status_t db_drop_empty_idxpart_segment(knl_session_t *session, knl_dictionary_t *new_dc, index_t *new_index)
{
    table_t *table = DC_TABLE(new_dc);
    table_part_t *table_part = NULL;
    table_part_t *table_sub_part = NULL;
    index_part_t *index_part = NULL;
    index_part_t *index_sub_part = NULL;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        index_part = INDEX_GET_PART(new_index, i);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            if (table_part->heap.segment != NULL || index_part == NULL) {
                continue;
            }

            if (db_update_index_part_entry(session, &index_part->desc, INVALID_PAGID) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (btree_part_segment_prepare(session, index_part, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_sub_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            if (table_sub_part == NULL || table_sub_part->heap.segment != NULL) {
                continue;
            }

            index_sub_part = PART_GET_SUBENTITY(new_index->part_index, index_part->subparts[j]);
            if (db_update_subidxpart_entry(session, &index_sub_part->desc, INVALID_PAGID) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (btree_part_segment_prepare(session, index_sub_part, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t db_drop_empty_index_segment(knl_session_t *session, knl_table_desc_t desc, uint32 idx_slot)
{
    knl_dictionary_t new_dc;
    bool32 is_null = GS_TRUE;
    status_t status = GS_SUCCESS;

    if (dc_open_table_private(session, desc.uid, desc.id, &new_dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table_t *table = DC_TABLE(&new_dc);
    index_t *index = table->index_set.items[idx_slot];

    if (IS_PART_TABLE(table)) {
        dc_load_all_part_segments(session, new_dc.handle);
        if (IS_PART_INDEX(index)) {
            status = db_drop_empty_idxpart_segment(session, &new_dc, index);
            dc_close_table_private(&new_dc);
            return status;
        } else {
            is_null = db_part_table_has_segment(session, &new_dc);
        }
    }

    is_null = IS_PART_TABLE(table) ? is_null : (table->heap.segment == NULL);
    if (is_null) {
        if (db_update_index_entry(session, &index->desc, INVALID_PAGID) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            return GS_ERROR;
        }

        if (btree_segment_prepare(session, index, GS_FALSE, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            return GS_ERROR;
        }
    }

    dc_close_table_private(&new_dc);
    return GS_SUCCESS;
}

static status_t db_switch_shadow_index(knl_session_t *session, knl_cursor_t *cursor, table_t *table,
    index_t *new_index, knl_parts_locate_t parts_loc)
{
    index_t *old_index = table->index_set.items[new_index->desc.slot];
    index_t *sys_index = NULL;
    knl_scan_key_t *scan_key = NULL;
    knl_update_info_t *update_info = NULL;
    row_assist_t ra;
    rd_update_core_index_t redo_index_info;

    CM_SAVE_STACK(session->stack);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEX_ID, IX_SYS_INDEX_001_ID);
    sys_index = (index_t *)cursor->index;
    scan_key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(&sys_index->desc, scan_key, GS_TYPE_INTEGER, &old_index->desc.uid, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(&sys_index->desc, scan_key, GS_TYPE_INTEGER, &old_index->desc.table_id, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_TABLE);
    knl_set_scan_key(&sys_index->desc, scan_key, GS_TYPE_INTEGER, &old_index->desc.id, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  sys_index->desc.name);

    update_info = &cursor->update_info;
    update_info->count = 8;
    update_info->columns[0] = SYS_INDEX_COLUMN_ID_SPACE;
    update_info->columns[1] = SYS_INDEX_COLUMN_ID_SEQUENCE;
    update_info->columns[2] = SYS_INDEX_COLUMN_ID_ENTRY;
    update_info->columns[3] = SYS_INDEX_COLUMN_ID_INITRANS;
    update_info->columns[4] = SYS_INDEX_COLUMN_ID_CR_MODE;
    update_info->columns[5] = SYS_INDEX_COLUMN_ID_FLAGS;
    update_info->columns[6] = SYS_INDEX_COLUMN_ID_PARTITIONED;
    update_info->columns[7] = SYS_INDEX_COLUMN_ID_PCTFREE;

    update_info->data = (char *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    row_init(&ra, update_info->data, GS_MAX_ROW_SIZE, update_info->count);
    (void)row_put_int32(&ra, new_index->desc.space_id);
    (void)row_put_int64(&ra, new_index->desc.org_scn);
    (void)row_put_int64(&ra, *(int64 *)&new_index->desc.entry);
    (void)row_put_int32(&ra, new_index->desc.initrans);
    (void)row_put_int32(&ra, new_index->desc.cr_mode);
    (void)row_put_int32(&ra, new_index->desc.flags);
    (void)row_put_int32(&ra, new_index->desc.parted);
    (void)row_put_int32(&ra, new_index->desc.pctfree);

    cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_delete_shadow_sysindex(session, cursor, new_index) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (IS_PART_INDEX(new_index)) {
        if (db_switch_shadow_indexparts(session, cursor, new_index) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_drop_part_btree_segments(session, old_index, parts_loc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (btree_segment_prepare(session, old_index, GS_FALSE, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!IS_SYS_TABLE(table)) {
        if (db_drop_empty_index_segment(session, table->desc, new_index->desc.slot) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (IS_CORE_SYS_TABLE(new_index->desc.uid, new_index->desc.table_id)) {
        redo_index_info.op_type = RD_UPDATE_CORE_INDEX;
        redo_index_info.table_id = new_index->desc.table_id;
        redo_index_info.index_id = new_index->desc.id;
        redo_index_info.entry = new_index->desc.entry;

        db_update_core_index(session, &redo_index_info);
        log_put(session, RD_LOGIC_OPERATION, &redo_index_info, sizeof(rd_update_core_index_t), LOG_ENTRY_FLAG_NONE);
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_create_index_online(knl_session_t *session, knl_index_def_t *def, knl_dictionary_t *dc)
{
    index_t index;
    dc_entity_t *entity;
    knl_cursor_t *scan_cursor = NULL;
    knl_dictionary_t new_dc;
    table_t *table;
    uint32 size_index;
    status_t status = GS_SUCCESS;
    errno_t err;
    rebuild_info_t rebuild_info;

    table = DC_TABLE(dc);
    entity = DC_ENTITY(dc);
    if (entity->table.desc.type == TABLE_TYPE_EXTERNAL) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index", "external organized table");
        return GS_ERROR;
    }

    if (entity->table.desc.type == TABLE_TYPE_TRANS_TEMP || entity->table.desc.type == TABLE_TYPE_SESSION_TEMP) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create index online", "temporary table");
        return GS_ERROR;
    }

    size_index = sizeof(index_t);
    err = memset_sp((void *)&index, size_index, 0, size_index);
    knl_securec_check(err);
    index.entity = entity;

    if (db_alloc_index_id(entity, def, &index.desc.id) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (db_verify_index_def(session, dc, def, &index.desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_judge_heap_segment_null(table)) {
        status = db_create_index_directly(session, def, &index);
        return status;
    }

    err = memset_sp(&rebuild_info, sizeof(rebuild_info_t), 0, sizeof(rebuild_info_t));
    knl_securec_check(err);
    rebuild_info.spc_id = GS_INVALID_ID32;
    if (db_create_shadow_index(session, dc, &index, def, rebuild_info) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_commit(session);
    dc_invalidate(session, entity);

    CM_SAVE_STACK(session->stack);

    scan_cursor = knl_push_cursor(session);

    for (;;) {
        if (knl_open_dc_by_id(session, index.desc.uid, index.desc.table_id, &new_dc, GS_TRUE) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        /* close old version of dc */
        dc_close(dc);
        err = memcpy_sp(dc, sizeof(knl_dictionary_t), &new_dc, sizeof(knl_dictionary_t));
        knl_securec_check(err);

        if (dc_load_shadow_index(session, dc) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        entity = DC_ENTITY(dc);
        table = DC_TABLE(dc);

        // create unique index online need lock row while doing heap fetch
        scan_cursor->action = def->unique || def->primary ? CURSOR_ACTION_UPDATE : CURSOR_ACTION_SELECT;
        scan_cursor->scan_mode = SCAN_MODE_TABLE_FULL;

        if (knl_open_cursor(session, scan_cursor, dc) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        scan_cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
        lock_degrade_table_lock(session, entity);
        err = memcpy_sp(&index, sizeof(index_t), &table->shadow_index->index, sizeof(index_t));
        knl_securec_check(err);

        knl_part_locate_t part_loc = { .part_no = GS_INVALID_ID32,
            .subpart_no = GS_INVALID_ID32 };
        if (db_fill_shadow_index(session, scan_cursor, dc, part_loc, CREATE_INDEX_ONLINE) != GS_SUCCESS) {
            knl_close_cursor(session, scan_cursor);
            status = GS_ERROR;
            break;
        }

        knl_close_cursor(session, scan_cursor);
        if (lock_upgrade_table_lock(session, entity) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (db_write_sysindex(session, scan_cursor, &index.desc) != GS_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if (err_code == ERR_DUPLICATE_KEY) {
                cm_reset_error();
                GS_THROW_ERROR(ERR_OBJECT_EXISTS, "index", index.desc.name);
            }
            status = GS_ERROR;
            break;
        }

        if (db_update_index_count(session, scan_cursor, &entity->table.desc, GS_TRUE) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (IS_PART_INDEX(&index)) {
            if (db_write_partindex(session, scan_cursor, &index) != GS_SUCCESS) {
                status = GS_ERROR;
                break;
            }
        }

        if (db_delete_shadow_sysindex(session, scan_cursor, &index) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        // delete from shadowindexpart$
        if (IS_PART_INDEX(&index)) {
            if (db_delete_from_shadow_sysindexpart(session, scan_cursor, index.desc.uid, index.desc.table_id,
                                                   index.desc.id) != GS_SUCCESS) {
                status = GS_ERROR;
                break;
            }
        }
        break;
    }

    CM_RESTORE_STACK(session->stack);

    if (status != GS_SUCCESS) {
        knl_rollback(session, NULL);
        dc_invalidate_shadow_index(dc->handle);
        if (((dc_entity_t *)dc->handle)->valid) {
            if (lock_upgrade_table_lock(session, dc->handle) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (knl_begin_auton_rm(session) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_drop_shadow_index(session, dc->uid, dc->oid, GS_TRUE) != GS_SUCCESS) {
            knl_end_auton_rm(session, GS_ERROR);
            return GS_ERROR;
        }

        knl_end_auton_rm(session, GS_SUCCESS);
        dc_invalidate(session, (dc_entity_t *)dc->handle);
    }

    return status;
}

status_t db_fetch_index_desc(knl_session_t *session, uint32 uid, text_t *name,
                             knl_index_desc_t *desc)
{
    bool32 is_found;
    knl_dictionary_t dc;
    knl_cursor_t *cursor = NULL;
    dc_user_t *user = NULL;

    db_get_sys_dc(session, SYS_INDEX_ID, &dc);

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    if (GS_SUCCESS != db_fetch_sysindex_row(session, cursor, uid, name, CURSOR_ACTION_SELECT, &is_found)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!is_found) {
        if (dc_open_user_by_id(session, uid, &user) == GS_SUCCESS) {
            GS_THROW_ERROR(ERR_INDEX_NOT_EXIST, user->desc.name, T2S_EX(name));
        }
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    dc_convert_index(session, cursor, desc);

    return GS_SUCCESS;
}

static status_t db_drop_index_update_catalog(knl_session_t *session, index_t *index, dc_entity_t *entity)
{
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_index_desc_t *idesc = &index->desc;

    if (db_update_index_count(session, cursor, &entity->table.desc, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_delete_from_sysindex(session, cursor, idesc->uid, idesc->table_id, idesc->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // set virtual column as deleted
    if (db_update_icol_from_syscolumn(session, cursor, entity, idesc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (index->desc.parted) {
        if (db_delete_from_syspartobject(session, cursor, idesc->uid, idesc->table_id, idesc->id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (IS_COMPART_INDEX(&index->part_index->desc)) {
            if (db_delete_subidxparts_with_index(session, cursor, idesc->uid, idesc->table_id,
                idesc->id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (db_delete_from_sysindexpart(session, cursor, idesc->uid, idesc->table_id, idesc->id,
            GS_INVALID_ID32) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_verify_index_logical_info(index_t *index)
{
    dc_entity_t *entity = index->entity;

    if ((entity->lrep_info.status == LOGICREP_STATUS_ON) && (entity->lrep_info.index_id == index->desc.id)) {
        return GS_ERROR;
    }

    if (!IS_PART_TABLE(&entity->table)) {
        return GS_SUCCESS;
    }

    table_part_t *table_part = NULL;
    table_part_t *subpart = NULL;
    for (uint32 i = 0; i < entity->table.part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(&entity->table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            if ((table_part->desc.lrep_status == PART_LOGICREP_STATUS_ON) &&
                (entity->lrep_info.index_id == index->desc.id)) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            subpart = PART_GET_SUBENTITY(entity->table.part_table, table_part->subparts[j]);
            if (subpart == NULL) {
                continue;
            }

            if ((subpart->desc.lrep_status == PART_LOGICREP_STATUS_ON) &&
                (entity->lrep_info.index_id == index->desc.id)) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

/*
 * Description     : Implementation of drop index
 * Input           : uid : user id of index owner
 * Input           : index_name : name of index
 * Output          : NA
 * Return Value    : status_t
 * History         : 1. 2017/4/26,  add description
 */
status_t db_drop_index(knl_session_t *session, index_t *index, knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    knl_index_desc_t *idesc = &index->desc;

    if (index->dep_set.count > 0) {
        GS_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
        return GS_ERROR;
    }

    if (db_verify_index_logical_info(index) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_REFERENCED_BY_LOGICAL_LOG);
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    if (db_drop_index_update_catalog(session, index, entity) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        knl_temp_cache_t *temp_table = knl_get_temp_cache(session, idesc->uid, idesc->table_id);

        if (temp_table != NULL) {
            if (temp_table->index_segid != GS_INVALID_ID32) {
                temp_table->index_root[idesc->id].root_vmid = GS_INVALID_ID32;
            }
            temp_table->index_root[idesc->id].org_scn = GS_INVALID_ID64;
        }
    } else {
        if (btree_segment_prepare(session, index, GS_INVALID_ID32, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (index->desc.parted) {
            if (db_drop_index_part_segments(session, index) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

status_t db_update_index_status(knl_session_t *session, index_t *index, bool32 is_invalid, bool32 *is_changed)
{
    row_assist_t ra;
    knl_index_desc_t desc;

    if (is_invalid && db_verify_index_logical_info(index) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_REFERENCED_BY_LOGICAL_LOG);
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEX_ID, IX_SYS_INDEX_001_ID);

    knl_scan_key_t *scan_key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), scan_key, GS_TYPE_INTEGER, &index->desc.uid, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), scan_key, GS_TYPE_INTEGER, &index->desc.table_id, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_TABLE);
    knl_set_scan_key(INDEX_DESC(cursor->index), scan_key, GS_TYPE_INTEGER, &index->desc.id, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    dc_convert_index(session, cursor, &desc);
    // if the state(is_invalid) of global index is changed, we set is_changed to true,
    // and then force invalidate dc in function knl_truncate_table
    if (!(*is_changed)) {
        *is_changed = desc.is_invalid != is_invalid;
    }

    desc.is_invalid = is_invalid;
    if (is_invalid) {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
        cursor->update_info.count = 2;
        cursor->update_info.columns[0] = SYS_INDEX_COLUMN_ID_ENTRY;   // entry
        cursor->update_info.columns[1] = SYS_INDEX_COLUMN_ID_FLAGS;  // flags
        (void)row_put_int64(&ra, *(int64 *)&INVALID_PAGID);
        (void)row_put_int32(&ra, desc.flags);
    } else {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
        cursor->update_info.count = 1;
        cursor->update_info.columns[0] = SYS_INDEX_COLUMN_ID_FLAGS;  // flags
        (void)row_put_int32(&ra, desc.flags);
    }

    cm_decode_row(ra.buf, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_altable_drop_cons(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    index_t *index = NULL;
    table_t *table = NULL;
    uint32 i, j;
    bool32 is_found = GS_FALSE;
    uint32 cons_type, col_count;
    text_t def_cols;
    uint16 *idx_cols = NULL;
    uint16 *cons_cols = NULL;

    table = DC_TABLE(dc);
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (db_drop_cons(session, cursor, table->desc.uid, table->desc.id, (dc_entity_t *)dc->handle,
                     def, &is_found) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!is_found) {
        if (def->options & DROP_IF_EXISTS) {
            CM_RESTORE_STACK(session->stack);
            return GS_SUCCESS;
        } else {
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_CONS_NOT_EXIST, T2S(&def->cons_def.name));
            return GS_ERROR;
        }
    }

    cons_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_TYPE);
    if (cons_type != CONS_TYPE_PRIMARY && cons_type != CONS_TYPE_UNIQUE) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    def_cols.str = CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_LIST);
    def_cols.len = CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_COLUMN_LIST);
    col_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_COUNT);

    cons_cols = cm_push(session->stack, GS_MAX_INDEX_COLUMNS);
    dc_convert_column_list(col_count, &def_cols, cons_cols);

    for (i = 0; i < table->index_set.total_count; i++) {
        idx_cols = table->index_set.items[i]->desc.columns;

        if (table->index_set.items[i]->desc.column_count != col_count) {
            continue;
        }

        for (j = 0; j < col_count; j++) {
            if (idx_cols[j] != cons_cols[j]) {
                break;
            }
        }

        if (j == col_count) {
            index = table->index_set.items[i];
            break;
        }
    }
    cm_pop(session->stack);

    /* if index is created by constraint, drop it */
    if (index != NULL && index->desc.is_cons) {
        if (db_drop_index(session, index, dc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_set_serial_value(knl_session_t *session, void *stmt, row_assist_t *ra, dc_entity_t *entity,
                                    knl_cursor_t *cursor, knl_column_t *column)
{
    int64 value;
    if (knl_get_serial_value(session, entity, &value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    switch (column->datatype) {
        case GS_TYPE_UINT32:
            TO_UINT32_OVERFLOW_CHECK(value, int64);
            uint32 ui32 = (uint32)value;
            return row_put_uint32(ra, ui32);
        case GS_TYPE_INTEGER:
            INT32_OVERFLOW_CHECK(value);
            int32 i32 = (int32)value;  // INT32_OVERFLOW_CHECK will promise value in the range of int32
            return row_put_int32(ra, i32);
        case GS_TYPE_BIGINT:
            return row_put_int64(ra, value);
        default:
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "auto_increment column needs to be int or bigint");
            return GS_ERROR;
    }
}

static status_t db_set_default_value(knl_session_t *session, void *stmt, row_assist_t *ra, void *expr,
                                     knl_cursor_t *cursor, knl_column_t *column)
{
    variant_t value;
    lob_locator_t *locator = NULL;
    status_t status;
    uint32 size_locator;
    binary_t lob;
    errno_t err;

    if (g_knl_callback.exec_default(stmt, expr, &value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (value.is_null) {
        if (!column->nullable) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_NULL, column->name);
            return GS_ERROR;
        }

        row_put_null(ra);
        return GS_SUCCESS;
    }

    switch (column->datatype) {
        case GS_TYPE_BOOLEAN:
            return row_put_bool(ra, VALUE(bool32, &value));

        case GS_TYPE_UINT32:
            return row_put_uint32(ra, VALUE(uint32, &value));

        case GS_TYPE_INTEGER:
            return row_put_int32(ra, VALUE(int32, &value));

        case GS_TYPE_BIGINT:
            return row_put_int64(ra, VALUE(int64, &value));

        case GS_TYPE_REAL:
            return row_put_real(ra, VALUE(double, &value));

        case GS_TYPE_DATE:
            return row_put_date(ra, VALUE(date_t, &value));

        case GS_TYPE_INTERVAL_DS:
            return row_put_dsinterval(ra, value.v_itvl_ds);

        case GS_TYPE_INTERVAL_YM:
            return row_put_yminterval(ra, value.v_itvl_ym);

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            return row_put_date(ra, VALUE(date_t, &value));

        case GS_TYPE_TIMESTAMP_TZ:
            return row_put_timestamp_tz(ra, VALUE_PTR(timestamp_tz_t, &value));

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING: {
            /* save variant */
            CM_SAVE_STACK(session->stack);
            g_knl_callback.keep_stack_variant(stmt, &value);
            status = row_put_text(ra, VALUE_PTR(text_t, &value));
            CM_RESTORE_STACK(session->stack);
            return status;
        }
        case GS_TYPE_BLOB:
        case GS_TYPE_CLOB:
        case GS_TYPE_IMAGE: {
            /* save variant */
            CM_SAVE_STACK(session->stack);
            g_knl_callback.keep_stack_variant(stmt, &value);
            size_locator = sizeof(lob_locator_t);
            locator = (lob_locator_t *)cm_push(session->stack, GS_LOB_LOCATOR_BUF_SIZE);
            err = memset_sp(locator, size_locator, 0xFF, size_locator);
            knl_securec_check(err);
            if (lob_set_column_default(session, cursor, locator, &value, column, stmt) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            cursor->set_default = GS_TRUE;
            lob.size = knl_lob_locator_size(locator);
            lob.bytes = (uint8 *)locator;
            status = row_put_bin(ra, &lob);
            CM_RESTORE_STACK(session->stack);
            return status;
        }
        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            return row_put_dec8(ra, VALUE_PTR(dec8_t, &value));

        case GS_TYPE_BINARY:
        case GS_TYPE_RAW:
        default:
        {
            /* save variant */
            CM_SAVE_STACK(session->stack);
            g_knl_callback.keep_stack_variant(stmt, &value);
            status = row_put_bin(ra, VALUE_PTR(binary_t, &value));
            CM_RESTORE_STACK(session->stack);
            return status;
        }
    }
}

static status_t db_set_column_update_info(knl_session_t *session, void *stmt, uint32 old_col_count,
                                          uint32 deleted_cols, knl_cursor_t *cursor)
{
    uint32 new_col_count = knl_get_column_count(cursor->dc_entity);
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_column_t *column = NULL;
    row_assist_t ra;
    uint32 i;
    bool32 is_csf = knl_is_table_csf(entity, cursor->part_loc.part_no);

    cursor->update_info.count = new_col_count + deleted_cols - old_col_count;
    cm_row_init(&ra, cursor->update_info.data, GS_MAX_ROW_SIZE, new_col_count + deleted_cols - old_col_count, is_csf);

    for (i = 0; i < deleted_cols; i++) {
        row_put_null(&ra);
    }

    for (i = old_col_count; i < new_col_count; i++) {
        column = knl_get_column(cursor->dc_entity, i);
        cursor->update_info.columns[i + deleted_cols - old_col_count] = (uint16)i;

        if (KNL_COLUMN_IS_SERIAL(column)) {
            if (db_set_serial_value(session, stmt, &ra, entity, cursor, column) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else if (column->default_text.len > 0) {
            void *expr = column->default_expr;
            if (db_set_default_value(session, stmt, &ra, expr, cursor, column) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            row_put_null(&ra);
        }
    }
    row_end(&ra);

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    return GS_SUCCESS;
}

static status_t db_set_column_default_entity(knl_session_t *session, void *stmt, uint32 old_col_count,
                                             uint32 deleted_cols, knl_cursor_t *cursor)
{
    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            lob_clean_all_default_segments(session, cursor->dc_entity, old_col_count);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (db_set_column_update_info(session, stmt, old_col_count, deleted_cols, cursor) != GS_SUCCESS) {
            lob_clean_all_default_segments(session, cursor->dc_entity, old_col_count);
            return GS_ERROR;
        }

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            lob_clean_all_default_segments(session, cursor->dc_entity, old_col_count);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_try_set_column_default(knl_session_t *session, knl_dictionary_t *dc, void *stmt,
                                          uint32 old_col_count, uint32 deleted_cols, knl_cursor_t *cursor)
{
    table_part_t *table_part = NULL;
    table_t *table = (table_t *)cursor->table;

    if (!IS_PART_TABLE(table)) {
        if (db_set_column_default_entity(session, stmt, old_col_count, deleted_cols, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
            cursor->part_loc.part_no = i;
            table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            if (!IS_PARENT_TABPART(&table_part->desc)) {
                cursor->part_loc.subpart_no = GS_INVALID_ID32;
                if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (db_set_column_default_entity(session, stmt, old_col_count, deleted_cols, cursor) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                continue;
            }

            for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
                cursor->part_loc.subpart_no = j;
                if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (db_set_column_default_entity(session, stmt, old_col_count, deleted_cols,
                    cursor) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_set_column_default(knl_session_t *session, void *stmt, knl_dictionary_t *dc)
{
    knl_cursor_t *cursor = NULL;
    knl_dictionary_t new_dc;
    knl_column_t *column = NULL;
    uint32 deleted_cols = 0;
    uint32 old_col_count = knl_get_column_count(dc->handle);

    if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_UPDATE;

    if (knl_open_cursor(session, cursor, &new_dc) != GS_SUCCESS) {
        dc_close_table_private(&new_dc);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor->update_info.data = (char *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    dc_entity_t *entity = DC_ENTITY(&new_dc);

    for (uint32 i = 0; i < old_col_count; i++) {
        column = dc_get_column(entity, i);
        if (KNL_COLUMN_IS_DELETED(column)) {
            cursor->update_info.columns[deleted_cols++] = (uint16)i;
        }
    }

    if (db_try_set_column_default(session, &new_dc, stmt, old_col_count, deleted_cols, cursor) != GS_SUCCESS) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        dc_close_table_private(&new_dc);
        return GS_ERROR;
    }

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    dc_close_table_private(&new_dc);
    return GS_SUCCESS;
}

static status_t db_update_table_desc(knl_session_t *session, knl_table_desc_t *desc, bool32 change_column_count,
                                     bool32 is_add)
{
    knl_scan_key_t *key = NULL;
    uint32 column_count;
    uint16 size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, desc->name, (uint16)strlen(desc->name),
                     IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    column_count = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_COLS) +
                   (change_column_count ? (is_add ? 1 : (-1)) : 0);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
    (void)row_put_int64(&ra, db_inc_scn(session));
    (void)row_put_int32(&ra, column_count);
    cursor->update_info.count = 2;
    cursor->update_info.columns[0] = SYS_TABLE_COL_CHG_SCN;
    cursor->update_info.columns[1] = SYS_TABLE_COL_COLS;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_update_table_chgscn(knl_session_t *session, knl_table_desc_t *desc)
{
    knl_cursor_t *cursor = NULL;
    knl_scan_key_t *key = NULL;
    uint16 size;
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, desc->name, (uint16)strlen(desc->name),
                     IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_int64(&ra, db_inc_scn(session));
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_TABLE_COL_CHG_SCN;  // table chg scn
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_update_table_entry(knl_session_t *session, knl_table_desc_t *desc, page_id_t entry)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;
    knl_scan_key_t *key = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, (void *)desc->name, (uint16)strlen(desc->name),
                     IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_int64(&ra, *(int64 *)&entry);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_TABLE_COL_ENTRY;  // table entry
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_update_table_pctfree(knl_session_t *session, knl_table_desc_t *desc, uint32 pctfree)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, desc->name,
                     (uint16)strlen(desc->name), IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_int32(&ra, pctfree);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_TABLE_COL_PCTFREE;  // table pctfree
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_update_table_initrans(knl_session_t *session, knl_table_desc_t *desc, uint32 initrans)
{
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
        IX_COL_SYS_TABLE_001_USER_ID);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, desc->name,
        (uint16)strlen(desc->name), IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_int32(&ra, initrans);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_TABLE_COL_INITRANS;  // table initrans
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_table_flag(knl_session_t *session, uint32 user_id, uint32 table_id, table_flag_type_e flag_type)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &user_id, sizeof(uint32),
        IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_id, sizeof(uint32),
        IX_COL_SYS_TABLE_002_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
    row_assist_t ra;
    knl_table_desc_t desc;
    dc_convert_table_desc(cursor, &desc);

    switch (flag_type) {
        case TABLE_FLAG_TYPE_STORAGED:
            desc.storaged = GS_TRUE;
            break;
        case TABLE_FLAG_TYPE_ENABLE_NOLOGGING:
            desc.is_nologging = GS_TRUE;
            break;
        case TABLE_FLAG_TYPE_DISABLE_NOLOGGING:
            desc.is_nologging = GS_FALSE;
            break;
        default:
            knl_panic_log(0, "update table's flag to unsupport flag type");
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int32(&ra, (int32)desc.flags);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_TABLE_COL_FLAG;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_update_storage_maxsize(knl_session_t *session, knl_cursor_t *cursor, uint64 orgscn,
    uint32 max_pages)
{
    row_assist_t ra;
    uint16 size;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_STORAGE_ID, IX_STORAGE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_BIGINT, (void *)&orgscn,
                     sizeof(uint64), IX_COL_SYS_STORAGE_ORGSCN);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_int32(&ra, max_pages);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_STORAGE_COL_MAX_PAGES;  // table pctfree
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_update_table_appendonly(knl_session_t *session, knl_table_desc_t *desc, uint32 appendonly)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, desc->name,
                     (uint16)strlen(desc->name), IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, desc->name,
                  ((index_t *)cursor->index)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_int32(&ra, appendonly);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_TABLE_COL_APPENDONLY;  // table appendonly
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_index_part_space(knl_session_t *session, knl_index_part_desc_t *desc, uint32 spc_id)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->uid,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->table_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->index_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&desc->part_id,
                     sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, UPDATE_COLUMN_COUNT_TWO);
    (void)row_put_int32(&ra, spc_id);
    (void)row_put_int32(&ra, desc->flags);

    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
    cursor->update_info.columns[0] = SYS_INDEXPART_COL_SPACE_ID;   // index part space id
    cursor->update_info.columns[1] = SYS_INDEXPART_COL_FLAGS;   // index part flags

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}


status_t db_update_index_entry(knl_session_t *session, knl_index_desc_t *desc, page_id_t entry)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;
    knl_scan_key_t *key = NULL;
    char idx_name[GS_NAME_BUFFER_SIZE];

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEX_ID, IX_SYS_INDEX_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
                     IX_COL_SYS_INDEX_002_USER);
    knl_get_index_name(desc, idx_name, GS_NAME_BUFFER_SIZE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, idx_name, (uint16)strlen(idx_name),
        IX_COL_SYS_INDEX_002_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    cursor->update_info.count = UPDATE_COLUMN_COUNT_TWO;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, UPDATE_COLUMN_COUNT_TWO);
    cursor->update_info.columns[0] = SYS_INDEX_COLUMN_ID_ENTRY;
    cursor->update_info.columns[1] = SYS_INDEX_COLUMN_ID_SPACE;
    (void)row_put_int64(&ra, *(int64 *)&entry);
    (void)row_put_uint32(&ra, desc->space_id);

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_lob_entry(knl_session_t *session, knl_lob_desc_t *desc, page_id_t entry)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;
    knl_scan_key_t *key = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_LOB_ID, IX_SYS_LOB001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
                     IX_COL_SYS_LOB001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->table_id, sizeof(uint32),
                     IX_COL_SYS_LOB001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->column_id, sizeof(uint32),
                     IX_COL_SYS_LOB001_COLUMN_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
    (void)row_put_int64(&ra, *(int64 *)&entry);

    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_LOB_COL_ENTRY;  // lob entry
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_update_table_policy(knl_session_t *session, uint32 uid, const char *name, text_t *new_name)
{
    row_assist_t row;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_POLICY_ID, IX_SYS_POLICY_001_ID);

    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        (void *)&uid, sizeof(uint32), IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER,
        (void *)&uid, sizeof(uint32), IX_COL_SYS_POLICY_001_OBJ_SCHEMA_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)name, (uint16)strlen(name), IX_COL_SYS_POLICY_001_OBJ_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_STRING,
        (void *)name, (uint16)strlen(name), IX_COL_SYS_POLICY_001_OBJ_NAME);

    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_POLICY_001_PNAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_POLICY_001_PNAME);

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        row_init(&row, cursor->update_info.data, HEAP_MAX_ROW_SIZE, UPDATE_COLUMN_COUNT_ONE);
        if (row_put_text(&row, new_name) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        cursor->update_info.columns[0] = SYS_POLICIES_COL_OBJ_NAME;
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);
        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_shadow_index_entry(knl_session_t *session, knl_index_desc_t *desc, page_id_t entry)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;
    knl_scan_key_t *key = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SHADOW_INDEX_ID, IX_SYS_SHADOW_INDEX_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
        IX_COL_SYS_SHADOW_INDEX_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->table_id, sizeof(uint32),
        IX_COL_SYS_SHADOW_INDEX_001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, UPDATE_COLUMN_COUNT_ONE);
        cursor->update_info.columns[0] = SYS_SHADOW_INDEX_COL_ENTRY;
        (void)row_put_int64(&ra, *(int64 *)&entry);

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_table_name(knl_session_t *session, uint32 uid, const char *name, text_t *new_name,
                              bool32 recycled)
{
    knl_cursor_t *cursor = NULL;
    uint16 size;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, name, (uint16)strlen(name),
                     IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
    (void)row_put_text(&ra, new_name);
    (void)row_put_int32(&ra, recycled);
    cursor->update_info.count = 2;
    cursor->update_info.columns[0] = SYS_TABLE_COL_NAME;   // table name
    cursor->update_info.columns[1] = SYS_TABLE_COL_RECYCLED;  // recycled
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_update_index_name(knl_session_t *session, uint32 uid, const char *name, text_t *new_name)
{
    knl_cursor_t *cursor = NULL;
    uint16 size;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEX_ID, IX_SYS_INDEX_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_INDEX_002_USER);
    // index name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, name, (uint16)strlen(name),
                     IX_COL_SYS_INDEX_002_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, ((index_t *)cursor->index)->desc.name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_text(&ra, new_name);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_INDEX_COLUMN_ID_NAME;   // index name
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_update_index_initrans(knl_session_t *session, knl_index_desc_t *desc, uint32 initrans)
{
    uint16 size;
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEX_ID, IX_SYS_INDEX_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, &desc->uid, sizeof(uint32),
        IX_COL_SYS_INDEX_002_USER);
    // index name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, desc->name, (uint16)strlen(desc->name),
        IX_COL_SYS_INDEX_002_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name, desc->name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_int32(&ra, initrans);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_INDEX_COLUMN_ID_INITRANS;   // index initrans
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static status_t db_subpart_judge_null(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc, 
    bool32 *is_null)
{
    knl_panic(part_loc.part_no != GS_INVALID_ID32);
    knl_panic(part_loc.subpart_no != GS_INVALID_ID32);

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->part_loc = part_loc;

    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    *is_null = cursor->eof;
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_part_judge_null(knl_session_t *session, knl_dictionary_t *dc, knl_part_locate_t part_loc, 
    bool32 *is_null)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *compart = TABLE_GET_PART(table, part_loc.part_no);
    *is_null = GS_TRUE;

    if (!IS_PARENT_TABPART(&compart->desc)) {
        CM_SAVE_STACK(session->stack);
        knl_cursor_t *cursor = knl_push_cursor(session);
        cursor->scan_mode = SCAN_MODE_TABLE_FULL;
        cursor->action = CURSOR_ACTION_SELECT;
        cursor->part_loc = part_loc;
        knl_panic(part_loc.subpart_no == GS_INVALID_ID32);
        if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        *is_null = cursor->eof;
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    bool32 subpart_is_null = GS_FALSE;
    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        part_loc.subpart_no = i;
        if (db_subpart_judge_null(session, dc, part_loc, &subpart_is_null) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!subpart_is_null) {
            *is_null = GS_FALSE;
            break;
        }
    }

    return GS_SUCCESS;
}

static status_t db_part_table_judge_null(knl_session_t *session, knl_dictionary_t *dc, bool32 *all_null)
{
    knl_part_locate_t part_loc;
    bool32 is_null = GS_FALSE;
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;

    *all_null = GS_TRUE;
    part_loc.subpart_no = GS_INVALID_ID32;
    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        part_loc.part_no = i;
        if (db_part_judge_null(session, dc, part_loc, &is_null) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!is_null) {
            *all_null = GS_FALSE;
            break;
        }
    }

    return GS_SUCCESS;
}

static status_t db_table_judge_null(knl_session_t *session, knl_dictionary_t *dc, bool32 *all_null)
{
    table_t *table = DC_TABLE(dc);

    if (IS_PART_TABLE(table)) {
        return db_part_table_judge_null(session, dc, all_null);
    }

    *all_null = GS_TRUE;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_SELECT;

    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    *all_null = cursor->eof;
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/* judge if the part has data or not */
static status_t db_part_is_empty(knl_session_t *session, knl_dictionary_t *dc, table_t *table, table_part_t *table_part,
    bool32 *is_empty)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->is_found = GS_FALSE;

    if (IS_PARENT_TABPART(&table_part->desc)) {
        *is_empty = GS_TRUE;
        cursor->part_loc.part_no = table_part->part_no;
        for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
            cursor->part_loc.subpart_no = i;
            if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (knl_fetch(session, cursor) != GS_SUCCESS) {
                knl_close_cursor(session, cursor);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (cursor->is_found) {
                *is_empty = GS_FALSE;
                break;
            }
        }

        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    if (IS_SUB_TABPART(&table_part->desc)) {
        table_part_t *compart = PART_GET_ENTITY(table->part_table, table_part->parent_partno);
        knl_panic_log(compart != NULL,
            "current compart is NULL, panic info: page %u-%u type %u table %s table_part %s", cursor->rowid.file,
            cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name, table_part->desc.name);
        cursor->part_loc.part_no = compart->part_no;
        cursor->part_loc.subpart_no = table_part->part_no;
    } else {
        cursor->part_loc.part_no = table_part->part_no;
        cursor->part_loc.subpart_no = GS_INVALID_ID32;
    }

    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    *is_empty = cursor->eof;
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_need_invalidate_index(knl_session_t *session, knl_dictionary_t *dc, table_t *table,
                                  table_part_t *table_part, bool32 *is_need)
{
    index_t *index = NULL;
    uint32 i;

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!index->desc.parted && !index->desc.is_invalid) {
            break;
        }
    }

    if (i == table->index_set.total_count) {
        *is_need = GS_FALSE;
        return GS_SUCCESS;
    }

    bool32 is_empty = GS_TRUE;
    if (db_part_is_empty(session, dc, table, table_part, &is_empty) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *is_need = !is_empty;
    return GS_SUCCESS;
}

static status_t db_prepare_add_column(knl_session_t *session, knl_dictionary_t *dc, knl_column_def_t *def)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    bool32 is_table_null = GS_FALSE;
    char col_name[GS_NAME_BUFFER_SIZE];

    if (entity->column_count >= session->kernel->attr.max_column_count - 1) {
        GS_THROW_ERROR(ERR_MAX_COLUMN_SIZE, session->kernel->attr.max_column_count - 1);
        return GS_ERROR;
    }

    if (db_table_judge_null(session, dc, &is_table_null) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!def->is_serial && !def->nullable && !is_table_null && CM_IS_EMPTY(&def->default_text)) {
        (void)cm_text2str(&def->name, col_name, GS_NAME_BUFFER_SIZE);
        GS_THROW_ERROR(ERR_COLUMN_NOT_NULL, col_name);
        return GS_ERROR;
    }

    if (entity->has_serial_col && def->is_serial) {
        GS_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_table_data_judge_empty(knl_session_t *session, knl_dictionary_t *dc, bool32 *is_empty)
{
    knl_cursor_t *cursor = NULL;
    table_t *table = NULL;
    *is_empty = GS_TRUE;
    status_t status = GS_SUCCESS;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_SELECT;

    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
    do {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (!cursor->eof) {
            *is_empty = GS_FALSE;
            break;
        }

        table = (table_t *)(cursor->table);
        if (IS_PART_TABLE(table)) {
            for (uint32 i = 1; i < table->part_table->desc.partcnt; i++) {
                cursor->part_loc.part_no = i;
                if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                    status = GS_ERROR;
                    break;
                }
                cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
                if (knl_fetch(session, cursor) != GS_SUCCESS) {
                    status = GS_ERROR;
                    break;
                }
                if (!cursor->eof) {
                    *is_empty = GS_FALSE;
                    break;
                }
            }
        }
    } while (0);

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t db_altable_create_inline_constraints(knl_session_t *session, knl_dictionary_t *dc,
                                                     galist_t *column_list, bool32 is_modify)
{
    knl_alt_column_prop_t *col_prop = NULL;
    knl_dictionary_t new_dc;
    uint32 i, j;
    bool32 is_empty = GS_FALSE;
    knl_constraint_def_t *cons = NULL;

    for (i = 0; i < column_list->count; i++) {
        col_prop = (knl_alt_column_prop_t *)cm_galist_get(column_list, i);

        if (!col_prop->new_column.is_check && !col_prop->new_column.unique && !col_prop->new_column.primary) {
            continue;
        }

        if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        for (j = 0; j < col_prop->constraints.count; j++) {
            cons = (knl_constraint_def_t *)cm_galist_get(&col_prop->constraints, j);
            if (is_modify && col_prop->new_column.is_check && cons->cons_state.is_validate) {
                if (db_table_data_judge_empty(session, dc, &is_empty) != GS_SUCCESS) {
                    dc_close_table_private(&new_dc);
                    return GS_ERROR;
                }
                if (!is_empty && db_verify_check_data(session, &new_dc, &cons->check.text)
                    != GS_SUCCESS) {
                    dc_close_table_private(&new_dc);
                    return GS_ERROR;
                }
            }

            if (db_create_cons(session, &new_dc, cons) != GS_SUCCESS) {
                dc_close_table_private(&new_dc);
                return GS_ERROR;
            }
        }

        dc_close_table_private(&new_dc);
    }

    return GS_SUCCESS;
}

status_t db_altable_add_column(knl_session_t *session, knl_dictionary_t *dc, void *stmt, knl_altable_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    table_t *table = NULL;
    dc_entity_t *entity = NULL;
    knl_column_t column;
    knl_column_def_t *new_column = NULL;
    knl_alt_column_prop_t *column_def = NULL;
    uint32 i;
    knl_dictionary_t new_dc;
    bool32 update_default = GS_FALSE;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && LOGIC_REP_TABLE_ENABLED(session, DC_ENTITY(dc));
    uint32 op_type = RD_ALTER_TABLE;
    space_t *space = NULL;

    log_append_lrep_addcol(session, op_type, has_logic, (uint32 *)&def->action);

    for (i = 0; i < def->column_defs.count; i++) {
        column_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, i);
        new_column = &column_def->new_column;

        if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != GS_SUCCESS) {;
            return GS_ERROR;
        }

        if (knl_find_column(&new_column->name, &new_dc) != NULL) {
            dc_close_table_private(&new_dc);
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "column", T2S(&new_column->name));
            return GS_ERROR;
        }

        if (db_prepare_add_column(session, &new_dc, new_column) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            return GS_ERROR;
        }

        CM_SAVE_STACK(session->stack);
        table = DC_TABLE(&new_dc);
        entity = DC_ENTITY(&new_dc);
        cursor = knl_push_cursor(session);

        column.name = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);
        db_convert_column_def(&column, table->desc.uid, table->desc.id, new_column, NULL, entity->column_count);

        if (db_write_syscolumn(session, cursor, &column) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            dc_close_table_private(&new_dc);
            return GS_ERROR;
        }

        if (COLUMN_IS_LOB(&column) || KNL_COLUMN_IS_ARRAY(&column)) {
            if (db_create_lob(session, table, &column, NULL) != GS_SUCCESS) {
                dc_close_table_private(&new_dc);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        if (db_update_table_desc(session, &table->desc, GS_TRUE, GS_TRUE) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        space = SPACE_GET(table->desc.space_id);

        if (SPACE_IS_ENCRYPT(space) && (!COLUMN_IS_LOB(&column))) {
            if (new_column->typmod.size > GS_MAX_COLUMN_SIZE - GS_KMC_MAX_CIPHER_SIZE) {
                dc_close_table_private(&new_dc);
                CM_RESTORE_STACK(session->stack);
                GS_THROW_ERROR(ERR_ENCRYPTION_NOT_SUPPORT_DDL, "column size should less than",
                    GS_MAX_COLUMN_SIZE - GS_KMC_MAX_CIPHER_SIZE);
                return GS_ERROR;
            }
        }

        if (new_column->is_default || new_column->is_serial) {
            update_default = GS_TRUE;
        }

        if (new_column->is_comment) {
            knl_comment_def_t comment_def;
            comment_def.uid = column.uid;
            comment_def.id = column.table_id;
            comment_def.column_id = column.id;
            comment_def.comment = new_column->comment;
            comment_def.type = COMMENT_ON_COLUMN;
            if (GS_SUCCESS != db_comment_on(session, &comment_def)) {
                dc_close_table_private(&new_dc);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        dc_close_table_private(&new_dc);
        CM_RESTORE_STACK(session->stack);
    }

    if (update_default) {
        if (db_set_column_default(session, stmt, dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (db_altable_create_inline_constraints(session, dc, &def->column_defs, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_column_entity_judge_null(knl_session_t *session, knl_cursor_t *cursor, uint32 column_id,
                                            bool32 *all_null, bool32 *include_null)
{
    *include_null = GS_FALSE;
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (ROW_COLUMN_COUNT(cursor->row) > column_id) {
            cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
            if (CURSOR_COLUMN_SIZE(cursor, column_id) != GS_NULL_VALUE_LEN) {
                *all_null = GS_FALSE;
                return GS_SUCCESS;
            } else {
                *include_null = GS_TRUE;
            }
        } else {
            /* if this column is added with null, and no insert happened after add column, must has null */
            *include_null = GS_TRUE;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    *all_null = GS_TRUE;

    return GS_SUCCESS;
}

static status_t db_column_part_judge_null(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor, 
    uint32 column_id, bool32 *all_null, bool32 *include_null)
{
    table_t *table = (table_t *)cursor->table;
    table_part_t *compart = TABLE_GET_PART(table, cursor->part_loc.part_no);

    if (!IS_READY_PART(compart)) {
        return GS_SUCCESS;
    }
    
    if (!IS_PARENT_TABPART(&compart->desc)) {
        if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
        cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

        if (db_column_entity_judge_null(session, cursor, column_id, all_null, include_null) != GS_SUCCESS) {
            return GS_ERROR;
        }

        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        cursor->part_loc.subpart_no = i;
        if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
        cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

        if (db_column_entity_judge_null(session, cursor, column_id, all_null, include_null) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!(*all_null)) {
            return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

static status_t db_column_judge_null(knl_session_t *session, uint32 column_id, knl_dictionary_t *dc,
                                     bool32 *all_null, bool32 *include_null)
{
    knl_cursor_t *cursor = NULL;
    table_t *table = NULL;

    *all_null = GS_TRUE;
    *include_null = GS_FALSE;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_SELECT;

    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;
    table = (table_t *)(cursor->table);
    if (!IS_PART_TABLE(table)) {
        if (db_column_entity_judge_null(session, cursor, column_id, all_null, include_null)) {
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        cursor->part_loc.part_no = i;
        if (db_column_part_judge_null(session, dc, cursor, column_id, all_null, include_null) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (!(*all_null)) {
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return GS_SUCCESS;
        }
    }

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_modify_column_in_syscolumn(knl_session_t *session, knl_column_t *column, knl_table_desc_t *desc)
{
    uint16 size;
    row_assist_t ra;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_COLUMN_ID, IX_SYS_COLUMN_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->uid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&column->id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, desc->name);
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 8);
    (void)row_put_int32(&ra, column->datatype);                                       // data type
    (void)row_put_int32(&ra, column->size);                                           // size
    row_put_prec_and_scale(&ra, column->datatype, column->precision, column->scale);  // precision & scale
    (void)row_put_int32(&ra, column->nullable);                                       // nullable
    (void)row_put_int32(&ra, column->flags);                                          // flags
    if (KNL_COLUMN_IS_DEFAULT_NULL(column)) {
        (void)row_put_null(&ra);
    } else {
        (void)row_put_text(&ra, &column->default_text);  // text of default
    }
    cursor->update_info.count = 7;
    cursor->update_info.columns[0] = SYS_COLUMN_COL_DATATYPE;
    cursor->update_info.columns[1] = SYS_COLUMN_COL_BYTES;
    cursor->update_info.columns[2] = SYS_COLUMN_COL_PRECISION;
    cursor->update_info.columns[3] = SYS_COLUMN_COL_SCALE;
    cursor->update_info.columns[4] = SYS_COLUMN_COL_NULLABLE;
    cursor->update_info.columns[5] = SYS_COLUMN_COL_FLAGS;
    cursor->update_info.columns[6] = SYS_COLUMN_COL_DEFAULT_TEXT;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (GS_SUCCESS != knl_internal_update(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static status_t db_modify_vcolumn_in_syscolumn(knl_session_t *session, knl_dictionary_t *dc, index_t *index,
                                               knl_column_t *new_column)
{
    uint32 col_id;
    typmode_t typmode;
    knl_icol_info_t *icol = NULL;
    knl_column_t *vcolumn = NULL;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = index->entity;

    for (uint32 i = 0; i < index->desc.column_count; i++) {
        col_id = index->desc.columns[i];
        icol = &index->desc.columns_info[i];

        /* if the indexed column is not virtual column or not the changed column, skip */
        if (col_id < DC_VIRTUAL_COL_START || icol->arg_cols[0] != new_column->id) {
            continue;
        }

        vcolumn = dc_get_column(entity, col_id);
        typmode.datatype = new_column->datatype;
        typmode.size = new_column->size;
        if (g_knl_callback.get_func_index_size(session, &vcolumn->default_text, &typmode) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (typmode.size != vcolumn->size) {
            vcolumn->size = typmode.size;
            if (db_modify_column_in_syscolumn(session, vcolumn, &table->desc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_judge_modify_part_column(table_t *table, knl_column_t *old_column, knl_column_t *new_column)
{
    part_table_t *part_table = table->part_table;

    for (uint32 i = 0; i < part_table->desc.partkeys; i++) {
        if (part_table->keycols[i].column_id == old_column->id) {
            if (old_column->datatype != new_column->datatype || old_column->size != new_column->size) {
                GS_THROW_ERROR(ERR_MODIFY_PART_COLUMN);
                return GS_ERROR;
            }

            return GS_SUCCESS;
        }
    }

    for (uint32 i = 0; i < part_table->desc.subpartkeys; i++) {
        if (part_table->sub_keycols[i].column_id == old_column->id) {
            if (old_column->datatype != new_column->datatype || old_column->size != new_column->size) {
                GS_THROW_ERROR(ERR_MODIFY_PART_COLUMN);
                return GS_ERROR;
            }

            return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

static bool32 db_column_in_list(uint16 *col_list, uint32 col_count, knl_column_t *column)
{
    uint32 i;

    for (i = 0; i < col_count; i++) {
        if (column->id == col_list[i]) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static status_t db_drop_old_part_lob(knl_session_t *session, knl_cursor_t *cursor, table_t *table, knl_column_t *column)
{
    lob_part_t *lob_part = NULL;
    lob_part_t *lob_subpart = NULL;
    table_part_t *table_part = NULL;
    lob_t *lob = (lob_t *)column->lob;
    part_table_t *part_table = table->part_table;
    uint32 total_partcnt = part_table->desc.partcnt + part_table->desc.not_ready_partcnt;

    for (uint32 i = 0; i < total_partcnt; ++i) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        lob_part = LOB_GET_PART(lob, i);
        GS_LOG_DEBUG_INF("modify lob column: delete lob part, uid: %d, tid: %d, column id: %d, part_id: %d",
            lob_part->desc.uid, lob_part->desc.table_id, lob_part->desc.column_id, lob_part->desc.part_id);
        if (db_delete_from_syslobpart(session, cursor, lob_part->desc.uid, lob_part->desc.table_id,
            lob_part->desc.column_id, lob_part->desc.part_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!IS_PARENT_LOBPART(&lob_part->desc)) {
            if (lob_part_segment_prepare(session, lob_part, GS_FALSE, LOB_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[j]);
            if (lob_subpart == NULL) {
                continue;
            }

            GS_LOG_DEBUG_INF("modify lob column: delete lob subpart, parent_partid %d, part_id: %d",
                lob_part->desc.part_id, lob_subpart->desc.part_id);
            if (db_delete_sublobparts_with_compart(session, cursor, lob_subpart->desc.uid,
                lob_subpart->desc.table_id, lob_subpart->desc.column_id, lob_part->desc.part_id) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (lob_part_segment_prepare(session, lob_subpart, GS_FALSE, LOB_DROP_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_altable_modify_lob_column(knl_session_t *session, table_t *table, knl_column_t *old_column,
                                             knl_column_t *new_column)
{
    if (COLUMN_IS_LOB(old_column) && COLUMN_IS_LOB(new_column)) {
        // check modify lob column null<-->not null only,
        // handle sql such as: alter table a modify lob_col not null/null
        if (old_column->nullable != new_column->nullable || !CM_IS_EMPTY(&new_column->default_text)) {
            // if lob column of table is set not null,modify it to null
            // (eg:alter table a modify a lob_col null),we just change
            // nullable of column to true, same as to convert null to not null.
            return GS_SUCCESS;
        }

        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",invalid modification of columns");
        return GS_ERROR;
    }

    if (COLUMN_IS_LOB(old_column)) {
        CM_SAVE_STACK(session->stack);
        knl_cursor_t *cursor = knl_push_cursor(session);
        lob_t *lob = (lob_t *)old_column->lob;
        if (db_delete_from_syslob(session, cursor, table->desc.uid, table->desc.id, old_column->id) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (lob_segment_prepare(session, lob, GS_FALSE, LOB_DROP_SEGMENT) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (table->desc.parted) {
            if (db_drop_old_part_lob(session, cursor, table, old_column) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        CM_RESTORE_STACK(session->stack);
    }

    if (COLUMN_IS_LOB(new_column)) {
        if (db_create_lob(session, table, new_column, NULL) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static bool32 db_column_in_icol_list(index_t *index, knl_column_t *old_col)
{
    uint32 i;
    knl_icol_info_t *icol = NULL;

    if (!index->desc.is_func) {
        return GS_FALSE;
    }

    for (i = 0; i < index->desc.column_count; i++) {
        icol = &index->desc.columns_info[i];

        if (!icol->is_func) {
            continue;
        }

        // we have only one argument for func index
        if (old_col->id == icol->arg_cols[0]) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

static uint32 db_get_func_index_keysize(knl_session_t *session, index_t *index, knl_column_t *new_column,
                                        bool32 is_pcr, uint32 *key_size)
{
    uint32 id;
    typmode_t typmode;
    text_t *func_text = NULL;
    knl_column_t *column = NULL;
    dc_entity_t *entity = index->entity;
    knl_icol_info_t *columns_info = NULL;

    *key_size = is_pcr ? sizeof(pcrb_key_t) + sizeof(pcrb_dir_t) : sizeof(btree_key_t) + sizeof(btree_dir_t);

    for (id = 0; id < index->desc.column_count; id++) {
        column = dc_get_column(entity, index->desc.columns[id]);
        columns_info = &index->desc.columns_info[id];
        if (columns_info->is_func) {
            func_text = &column->default_text;
            if (new_column->id == columns_info->arg_cols[0]) {
                /* if the modified column is used by current virtual column,
                   virtual column size should be recalculated */
                typmode.datatype = new_column->datatype;
                typmode.size = new_column->size;
                if (g_knl_callback.get_func_index_size(session, func_text, &typmode) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                (*key_size) += btree_max_column_size(typmode.datatype, typmode.size, is_pcr);
            } else {
                /* modified column is not used by current virtual column, get the origin size */
                (*key_size) += btree_max_column_size(column->datatype, column->size, is_pcr);
            }
        } else {
            if (new_column->id == column->id) {
                (*key_size) += btree_max_column_size(new_column->datatype, new_column->size, is_pcr);
            } else {
                (*key_size) += btree_max_column_size(column->datatype, column->size, is_pcr);
            }
        }
    }

    return GS_SUCCESS;
}
static status_t db_verify_index_key_size(knl_session_t *session, index_t *index, knl_column_t *old_column,
                                         knl_column_t *new_column)
{
    uint32 key_size, max_key_size;
    uint16 old_col_size, new_col_size;

    bool32 is_pcr = (index->desc.cr_mode == CR_PAGE);
    if (index->desc.is_func) {
        if (db_get_func_index_keysize(session, index, new_column, is_pcr, &key_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        old_col_size = btree_max_column_size(old_column->datatype, old_column->size, is_pcr);
        new_col_size = btree_max_column_size(new_column->datatype, new_column->size, is_pcr);
        key_size = btree_max_key_size(index) + new_col_size - old_col_size;
    }

    max_key_size = btree_max_allowed_size(session, &index->desc);
    if (key_size > max_key_size) {
        GS_THROW_ERROR(ERR_MAX_KEYLEN_EXCEEDED, max_key_size);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_verify_index_column(knl_session_t *session, knl_dictionary_t *dc, knl_column_t *new_column,
                                       bool32 compatible, bool32 *need_rebuild, uint32 index_count)
{
    uint32 i;
    index_t *index = NULL;
    table_t *table = DC_TABLE(dc);
    knl_column_t *old_column = knl_get_column(dc->handle, new_column->id);
    bool32 type_changed = (old_column->datatype != new_column->datatype);
    bool32 need_rebuild_force = (new_column->datatype == GS_TYPE_BIGINT && old_column->datatype == GS_TYPE_INTEGER);

    for (i = 0; i < index_count; i++) {
        index = table->index_set.items[i];

        if (!db_column_in_list(index->desc.columns, index->desc.column_count, old_column)) {
            if (!db_column_in_icol_list(index, old_column)) {
                continue;
            }
        }

        if (index->desc.primary && new_column->nullable) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " primary key cannot be modified to null");
            return GS_ERROR;
        }

        if (COLUMN_IS_LOB(new_column)) {
            GS_THROW_ERROR(ERR_CREATE_INDEX_ON_TYPE, get_datatype_name_str(new_column->datatype));
            return GS_ERROR;
        }

        if (index->desc.is_func) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify column", "functional index");
            return GS_ERROR;
        }

        if (session->kernel->attr.enable_idx_key_len_check &&
            db_verify_index_key_size(session, index, old_column, new_column) != GS_SUCCESS) {
            return GS_ERROR;
        }

        /* index is referenced by foreign key, column type should not be changed */
        if (type_changed) {
            if (index->dep_set.count > 0) {
                GS_THROW_ERROR(ERR_COL_TYPE_MISMATCH);
                return GS_ERROR;
            }

            if (!compatible || need_rebuild_force) {
                need_rebuild[i] = GS_TRUE;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_modify_column_index(knl_session_t *session, knl_dictionary_t *dc, bool32 *rebuild_indexes,
                                       knl_column_t *new_column, uint32 index_count)
{
    table_t *table = DC_TABLE(dc);
    index_t *index = NULL;
    knl_alindex_def_t rebuild_def;

    for (uint32 i = 0; i < index_count; i++) {
        index = table->index_set.items[i];
        if (index->desc.is_func) {
            if (db_modify_vcolumn_in_syscolumn(session, dc, index, new_column) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (!rebuild_indexes[i]) {
            continue;
        }

        if (table->desc.type == TABLE_TYPE_TRANS_TEMP || table->desc.type == TABLE_TYPE_SESSION_TEMP) {
            if (index->desc.is_func) {
                GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW,
                    "functional join index is defined on the column in global temporary table to be modified");
                return GS_ERROR;
            }

            if (!knl_is_temp_table_empty(session, table->desc.uid, table->desc.id)) {
                GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT,
                               "would cause rebuiding index, which", "non-empty temporary table");
                return GS_ERROR;
            }
        }

        rebuild_def.type = ALINDEX_TYPE_REBUILD;
        cm_str2text(index->desc.name, &rebuild_def.name);
        rebuild_def.rebuild.is_online = GS_FALSE;
        rebuild_def.rebuild.parallelism = 0;
        rebuild_def.rebuild.specified_parts = 0;
        rebuild_def.rebuild.space.len = 0;
        rebuild_def.rebuild.space.str = NULL;
        rebuild_def.rebuild.pctfree = index->desc.pctfree;
        rebuild_def.rebuild.cr_mode = index->desc.cr_mode;
        if (db_alter_index_rebuild(session, &rebuild_def, dc, index) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static bool32 db_modify_column_null_only(knl_column_t *old_column, knl_column_t *new_column)
{
    if (old_column->id == new_column->id &&
        cm_str_equal(old_column->name, new_column->name) &&
        old_column->uid == new_column->uid &&
        old_column->table_id == new_column->table_id &&
        old_column->datatype == new_column->datatype &&
        old_column->size == new_column->size &&
        old_column->precision == new_column->precision &&
        old_column->scale == new_column->scale) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

static inline bool32 db_is_number_compatible(knl_column_t *old_column, knl_column_t *new_column)
{
    int32 old_int_scale;
    int32 new_int_scale;

    if (old_column->precision == GS_UNSPECIFIED_NUM_PREC) {
        return (new_column->precision == GS_UNSPECIFIED_NUM_PREC);
    }

    /* modify column precision to unlimited, which is always allowed */
    if (new_column->precision == GS_UNSPECIFIED_NUM_PREC) {
        return GS_TRUE;
    }

    if (old_column->scale > new_column->scale) {
        return GS_FALSE;
    }

    old_int_scale = old_column->precision - old_column->scale;
    new_int_scale = new_column->precision - new_column->scale;

    return (old_int_scale <= new_int_scale);
}

static bool32 db_is_column_compatible(knl_column_t *old_column, knl_column_t *new_column, bool32 *type_changed)
{
    *type_changed = (old_column->datatype != new_column->datatype);

    if (*type_changed) {
        if (GS_IS_STRING_TYPE2(old_column->datatype, new_column->datatype)) {
            return (old_column->size <= new_column->size);
        } else if (GS_IS_DECIMAL_TYPE(old_column->datatype) && GS_IS_DECIMAL_TYPE(new_column->datatype)) {
            return db_is_number_compatible(old_column, new_column);
        } else {
            return (new_column->datatype == GS_TYPE_BIGINT && old_column->datatype == GS_TYPE_INTEGER);
        }
    }

    if (old_column->datatype == GS_TYPE_BINARY || GS_IS_STRING_TYPE(old_column->datatype)) {
        return (old_column->size <= new_column->size);
    } else if (GS_IS_DECIMAL_TYPE(old_column->datatype) && GS_IS_DECIMAL_TYPE(new_column->datatype)) {
        return db_is_number_compatible(old_column, new_column);
    } else {
        return GS_FALSE;
    }
}

static status_t db_is_modify_array_column(knl_column_t *old_column, knl_column_t *new_column)
{
    if (KNL_COLUMN_IS_ARRAY(old_column) != KNL_COLUMN_IS_ARRAY(new_column)) {
        GS_THROW_ERROR(ERR_MODIFY_ARRAY_COLUMN, old_column->name, KNL_COLUMN_IS_ARRAY(old_column) ? "non-" : "");
        return GS_ERROR;
    }

    /* can not change datatype for array type column */
    if (KNL_COLUMN_IS_ARRAY(old_column) && old_column->datatype != new_column->datatype) {
        GS_THROW_ERROR(ERR_MODIFY_ARRAY_DATATYPE, old_column->name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}
status_t db_check_rule_exists_by_name(knl_session_t *session, knl_ddm_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DDM_ID, IX_SYS_DDM_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->uid,
        sizeof(uint32), IX_COL_SYS_DDM_002_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->oid,
        sizeof(uint32), IX_COL_SYS_DDM_002_OID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, def->rulename,
        (uint16)strlen(def->rulename), IX_COL_SYS_DDM_002_RULENAME);
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    if (cursor->eof == GS_FALSE) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }
    CM_RESTORE_STACK(session->stack);
    GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ",this object does not have this ddm rule.");
    return GS_ERROR;
}


status_t db_drop_ddm_rule_by_name(knl_session_t *session,  knl_ddm_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_DDM_ID, IX_SYS_DDM_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->uid,
        sizeof(uint32), IX_COL_SYS_DDM_002_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->oid,
        sizeof(uint32), IX_COL_SYS_DDM_002_OID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,  GS_TYPE_STRING, def->rulename,
        (uint16)strlen(def->rulename), IX_COL_SYS_DDM_002_RULENAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_check_ddm_rule_by_col(knl_session_t *session, uint32 uid, uint32 oid, uint32 colid)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DDM_ID, IX_SYS_DDM_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_DDM_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&oid,
        sizeof(uint32), IX_COL_SYS_DDM_001_OID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&colid,
        sizeof(uint32), IX_COL_SYS_DDM_001_COLID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", this col has rule , please drop rule firstly.");
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}
static status_t db_check_col_ddm_rule(knl_session_t *session, knl_dictionary_t *dc, knl_column_t *new_column)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    knl_column_t *old_column = dc_get_column(entity, new_column->id);
    bool32 type_changed = GS_FALSE;
    if (db_is_column_compatible(old_column, new_column, &type_changed) == GS_FALSE) {
        if (old_column->ddm_expr != NULL) {
            GS_THROW_ERROR(ERR_CANNOT_MODIFY_COLUMN);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}
static status_t db_prepare_modify_column(knl_session_t *session, knl_dictionary_t *dc, knl_column_t *new_column,
                                         bool32 *rebuild_indexes, uint32 index_count)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);
    bool32 compatible = GS_FALSE;
    knl_column_t *old_column = dc_get_column(entity, new_column->id);
    bool32 col_null = GS_FALSE;
    bool32 include_null = GS_FALSE;
    uint32 i;
    bool32 type_changed = GS_FALSE;
    ref_cons_t *ref = NULL;
    check_cons_t *check = NULL;

    if (db_is_modify_array_column(old_column, new_column) != GS_SUCCESS) {
        return GS_ERROR;
    }

    compatible = db_is_column_compatible(old_column, new_column, &type_changed);
    if (db_modify_column_null_only(old_column, new_column) || compatible) {
        if (old_column->nullable && !new_column->nullable) {
            if (db_column_judge_null(session, old_column->id, dc, &col_null, &include_null) != GS_SUCCESS) {
                return GS_ERROR;
            }
            if (include_null) {
                GS_THROW_ERROR(ERR_COLUMN_HAS_NULL);
                return GS_ERROR;
            }
        }
    } else {
        if (db_column_judge_null(session, old_column->id, dc, &col_null, &include_null) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!col_null) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_EMPTY, new_column->name, table->desc.name);
            return GS_ERROR;
        }
    }

    if (db_verify_index_column(session, dc, new_column, compatible, rebuild_indexes,
                               index_count) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_PART_TABLE(table)) {
        if (db_judge_modify_part_column(table, old_column, new_column) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (entity->has_serial_col) {
        if (KNL_COLUMN_IS_SERIAL(old_column)) {
            if ((new_column->datatype != GS_TYPE_BIGINT) && (new_column->datatype != GS_TYPE_INTEGER)) {
                GS_THROW_ERROR(ERR_INVALID_DATA_TYPE, "column");
                return GS_ERROR;
            }
        } else {
            if (KNL_COLUMN_IS_SERIAL(new_column)) {
                GS_THROW_ERROR(ERR_DUPLICATE_AUTO_COLUMN);
                return GS_ERROR;
            }
        }
    }
    if (!type_changed) {
        return GS_SUCCESS;
    }

    for (i = 0; i < table->cons_set.check_count; i++) {
        check = table->cons_set.check_cons[i];
        if (db_column_in_list(check->cols, check->col_count, new_column)) {
            GS_THROW_ERROR(ERR_CANNOT_MODIFY_COLUMN);
            return GS_ERROR;
        }
    }

    for (i = 0; i < table->cons_set.ref_count; i++) {
        ref = table->cons_set.ref_cons[i];

        if (db_column_in_list(ref->cols, ref->col_count, old_column)) {
            GS_THROW_ERROR(ERR_COL_TYPE_MISMATCH);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

knl_column_def_t *db_altable_find_column_def(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
                                             uint16 col_id)
{
    uint32 i;
    knl_column_t *column = NULL;
    knl_alt_column_prop_t *col_def = NULL;
    knl_column_def_t *def_column = NULL;

    for (i = 0; i < def->column_defs.count; i++) {
        col_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, i);
        def_column = &col_def->new_column;
        column = knl_find_column(&def_column->name, dc);
        if (column == NULL) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->name), T2S_EX(&def_column->name));
            return NULL;
        }

        if (column->id == col_id) {
            break;
        }
    }

    return def_column;
}

status_t db_altable_sort_column_def(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
                                    uint16 *sort_col)
{
    uint16 temp_col;
    uint32 i;
    int32 j;
    knl_column_t *old_column = NULL;
    knl_alt_column_prop_t *col_def = NULL;
    knl_column_def_t *def_column = NULL;

    for (i = 0; i < def->column_defs.count; i++) {
        col_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, i);
        def_column = &col_def->new_column;
        old_column = knl_find_column(&def_column->name, dc);

        if (old_column == NULL) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->name), T2S_EX(&def_column->name));
            return GS_ERROR;
        }

        sort_col[i] = old_column->id;
    }
    /*
     * analyze table will update all columns order by columns id asc, we must ensure
     * update columns order bu column id asc when modify many columns for preventing deadlock
     * eg:analyze update column 1 and column 2,modify update column 2 and column 1
     */
    for (i = 1; i < def->column_defs.count; i++) {
        temp_col = sort_col[i];

        for (j = i - 1; (j >= 0) && (sort_col[j] > temp_col); j--) {
            sort_col[j + 1] = sort_col[j];
        }

        sort_col[j + 1] = temp_col;
    }

    return GS_SUCCESS;
}

void tbl_append_lrep_modify(knl_session_t *session, uint32 op_type, bool32 has_logic,
    uint16 *sort_col, knl_altable_def_t *def, knl_dictionary_t *dc)
{
    knl_column_def_t *def_column = NULL;
    if (has_logic) {
        log_atomic_op_begin(session);
        log_put(session, RD_LOGIC_REP_DDL, &op_type, sizeof(uint32), LOG_ENTRY_FLAG_WITH_LOGIC_OID);
        log_append_data(session, (void *)(&def->action), sizeof(uint32));
        log_append_data(session, (void *)(&def->column_defs.count), sizeof(uint32));

        for (uint32 i = 0; i < def->column_defs.count; i++) {
            def_column = db_altable_find_column_def(session, dc, def, sort_col[i]);
            knl_column_t *old_column = knl_find_column(&def_column->name, dc);
            if (old_column == NULL) {
                GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->name), T2S_EX(&def_column->name));
                return;
            }
            log_append_data(session, (void *)(&old_column->id), sizeof(uint32));
        }
        log_atomic_op_end(session);
        session->rm->is_ddl_op = GS_TRUE;
    }
}

status_t db_altable_modify_column(knl_session_t *session, knl_dictionary_t *dc, void *stmt, knl_altable_def_t *def)
{
    table_t *table = NULL;
    knl_column_t *old_column = NULL;
    knl_column_t column;
    knl_column_def_t *def_column = NULL;
    knl_dictionary_t new_dc;
    uint32 i;
    uint16 *sort_col = NULL;
    bool32 *rebuild_indexes = NULL;
    uint32 index_count;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && LOGIC_REP_TABLE_ENABLED(session, DC_ENTITY(dc));
    uint32 op_type = RD_ALTER_TABLE;

    CM_SAVE_STACK(session->stack);

    table = DC_TABLE(dc);
    space_t *space = SPACE_GET(table->desc.space_id);
    bool32 is_encrypt = SPACE_IS_ENCRYPT(space);
    index_count = table->index_set.total_count;

    if (index_count > 0) {
        rebuild_indexes = (bool32 *)cm_push(session->stack, index_count * sizeof(bool32));

        for (i = 0; i < index_count; i++) {
            rebuild_indexes[i] = GS_FALSE;
        }
    }

    sort_col = (uint16 *)cm_push(session->stack, GS_MAX_COLUMNS * sizeof(uint16));

    if (db_altable_sort_column_def(session, dc, def, sort_col) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    tbl_append_lrep_modify(session, op_type, has_logic, sort_col, def, dc);

    for (i = 0; i < def->column_defs.count; i++) {
        if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        def_column = db_altable_find_column_def(session, dc, def, sort_col[i]);
        old_column = knl_find_column(&def_column->name, dc);
        if (old_column == NULL) {
            dc_close_table_private(&new_dc);
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->name), T2S_EX(&def_column->name));
            return GS_ERROR;
        }

        if (!def_column->is_option_set) {
            dc_close_table_private(&new_dc);
            continue;
        }

        if (is_encrypt && (!GS_IS_LOB_TYPE(def_column->typmod.datatype) && !def_column->typmod.is_array)) {
            if (def_column->typmod.size > GS_MAX_COLUMN_SIZE - GS_KMC_MAX_CIPHER_SIZE) {
                dc_close_table_private(&new_dc);
                CM_RESTORE_STACK(session->stack);
                GS_THROW_ERROR(ERR_ENCRYPTION_NOT_SUPPORT_DDL, "column size should less than",
                    GS_MAX_COLUMN_SIZE - GS_KMC_MAX_CIPHER_SIZE);
                return GS_ERROR;
            }
        }

        table = DC_TABLE(&new_dc);
        column.name = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);
        db_convert_column_def(&column, table->desc.uid, table->desc.id, def_column,
                              old_column, table->desc.column_count);
        column.id = old_column->id;

        if (db_prepare_modify_column(session, &new_dc, &column, rebuild_indexes, index_count) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_altable_modify_lob_column(session, table,
                                         old_column, &column) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_modify_column_in_syscolumn(session, &column, &table->desc) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_check_col_ddm_rule(session, &new_dc, &column) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_update_table_desc(session, &table->desc, GS_FALSE, GS_FALSE) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (def_column->is_comment) {
            knl_comment_def_t comment_def;
            comment_def.uid = column.uid;
            comment_def.id = column.table_id;
            comment_def.column_id = column.id;
            comment_def.comment = def_column->comment;
            comment_def.type = COMMENT_ON_COLUMN;
            if (GS_SUCCESS != db_comment_on(session, &comment_def)) {
                dc_close_table_private(&new_dc);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        cm_pop(session->stack);
        dc_close_table_private(&new_dc);
    }

    if (index_count > 0) {
        if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_modify_column_index(session, &new_dc, rebuild_indexes, &column, index_count) != GS_SUCCESS) {
            dc_close_table_private(&new_dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        dc_close_table_private(&new_dc);
    }

    CM_RESTORE_STACK(session->stack);

    return db_altable_create_inline_constraints(session, dc, &def->column_defs, GS_TRUE);
}

static status_t knl_judge_visual_column_number(knl_dictionary_t *dc)
{
    uint32 i, column_count, visual_count;
    knl_column_t *column = NULL;

    visual_count = 0;
    column_count = knl_get_column_count(dc->handle);

    for (i = 0; i < column_count; i++) {
        column = knl_get_column(dc->handle, i);
        if (!KNL_COLUMN_IS_DELETED(column)) {
            visual_count += 1;
        }
    }
    return visual_count;
}

static status_t db_judge_drop_part_column(table_t *table, uint32 column_id)
{
    part_table_t *part_table = table->part_table;

    for (uint32 i = 0; i < part_table->desc.partkeys; i++) {
        if (part_table->keycols[i].column_id == column_id) {
            GS_THROW_ERROR(ERR_DROP_PART_COLUMN);
            return GS_ERROR;
        }
    }

    for (uint32 i = 0; i < part_table->desc.subpartkeys; i++) {
        if (part_table->sub_keycols[i].column_id == column_id) {
            GS_THROW_ERROR(ERR_DROP_PART_COLUMN);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_prepare_drop_column(knl_session_t *session, knl_column_t *column, knl_dictionary_t *dc)
{
    uint32 i;
    table_t *table = NULL;
    knl_cursor_t *cursor = NULL;
    text_t col_list;
    uint32 cols;
    bool32 used = GS_FALSE;
    uint16 *col_id = NULL;

    CM_SAVE_STACK(session->stack);

    table = DC_TABLE(dc);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_TABLE_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        used = GS_FALSE;
        cols = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_COUNT);
        col_list.len = CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_COLUMN_LIST);
        col_list.str = CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COLUMN_LIST);
        col_id = (uint16 *)cm_push(session->stack, GS_MAX_INDEX_COLUMNS * sizeof(uint16));
        dc_convert_column_list(cols, &col_list, col_id);
        for (i = 0; i < cols; i++) {
            if (column->id == (uint32)col_id[i]) {
                used = GS_TRUE;
                break;
            }
        }
        cm_pop(session->stack);

        if (used) {
            if (cols > 1) {
                GS_THROW_ERROR(ERR_COLUMN_IN_CONSTRAINT);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            /* if column is used in a single column constraint, drop this constraint */
            if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

// drop indexes on the columns have been dropped
static status_t db_drop_related_index(knl_session_t *session, knl_dictionary_t *dc, knl_column_t *column)
{
    table_t *table = NULL;
    index_t *index = NULL;
    uint32 i, j;
    bool32 drop_index = GS_FALSE;
    knl_icol_info_t *icol = NULL;

    table = DC_TABLE(dc);

    for (i = 0; i < table->index_set.total_count; i++) {
        drop_index = GS_FALSE;
        index = table->index_set.items[i];
        for (j = 0; j < index->desc.column_count; j++) {
            if (index->desc.columns[j] < DC_VIRTUAL_COL_START) {
                if (column->id == (uint32)index->desc.columns[j]) {
                    drop_index = GS_TRUE;
                }
            } else {
                icol = &index->desc.columns_info[j];
                if (column->id == icol->arg_cols[0]) {
                    drop_index = GS_TRUE;
                }
            }
        }

        if (!drop_index) {
            continue;
        }

        knl_set_session_scn(session, GS_INVALID_ID64);

        if (db_drop_index(session, index, dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t db_altable_drop_column(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_update_info_t *ua = NULL;
    knl_column_t *column = NULL;
    table_t *table = NULL;
    uint32 visual_column_count;
    knl_comment_def_t comment_def;
    knl_alt_column_prop_t *col_def = NULL;
    uint32 col_flags;

    table = DC_TABLE(dc);

    knl_panic_log(def->column_defs.count == 1, "column count is abnormal, panic info: table %s column_defs's count %u",
                  table->desc.name, def->column_defs.count);
    col_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, 0);
    column = knl_find_column(&col_def->name, dc);
    if (column == NULL) {
        GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->name), T2S_EX(&col_def->name));
        return GS_ERROR;
    }

    if (IS_PART_TABLE(table)) {
        if (db_judge_drop_part_column(table, column->id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    visual_column_count = knl_judge_visual_column_number(dc);
    if (visual_column_count == 1) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",cannot drop all columns in a table");
        return GS_ERROR;
    }

    if (db_prepare_drop_column(session, column, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && LOGIC_REP_TABLE_ENABLED(session, DC_ENTITY(dc));
    uint32 op_type = RD_ALTER_TABLE;
    log_append_lrep_colname(session, op_type, has_logic, (uint32 *)&def->action, &col_def->name);

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    if (db_fetch_syscolumn_row(session, cursor, column->id, table->desc.uid, table->desc.id,
                               CURSOR_ACTION_UPDATE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    col_flags = (column->flags | KNL_COLUMN_FLAG_DELETED);
    ua = &cursor->update_info;
    ua->count = 1;
    ua->columns[0] = SYS_COLUMN_COL_FLAGS;
    ua->lens[0] = sizeof(uint32);
    row_init(&ra, ua->data, GS_MAX_ROW_SIZE, 1);
    (void)row_put_int32(&ra, col_flags);
    cm_decode_row(ua->data, ua->offsets, ua->lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    // if column has ddm policy, please drop policy first
    if (db_check_ddm_rule_by_col(session, table->desc.uid, table->desc.id, column->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_table_desc(session, &table->desc, GS_FALSE, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_drop_related_index(session, dc, column) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* drop the column comment */
    comment_def.type = COMMENT_ON_COLUMN;
    comment_def.uid = column->uid;
    comment_def.id = column->table_id;
    comment_def.column_id = column->id;

    return db_delete_comment(session, &comment_def);
}

static status_t db_rename_column_in_syscolumn(knl_session_t *session, uint16 col_id, text_t *new_name,
                                              knl_table_desc_t *desc)
{
    uint16 size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    if (db_fetch_syscolumn_row(session, cursor, col_id, desc->uid, desc->id, CURSOR_ACTION_UPDATE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, desc->name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    (void)row_put_text(&ra, new_name);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_COLUMN_COL_NAME;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (GS_SUCCESS != knl_internal_update(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t knl_find_column_in_consdef(table_t *table, knl_column_t *column)
{
    uint32 i;
    check_cons_t *check = NULL;

    for (i = 0; i < table->cons_set.check_count; i++) {
        check = table->cons_set.check_cons[i];
        if (db_column_in_list(check->cols, check->col_count, column)) {
            GS_THROW_ERROR(ERR_COLUMN_IN_CONSTRAINT);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_altable_rename_column(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = NULL;
    knl_column_t *column = NULL;
    text_t *old_name = NULL;
    text_t *new_name = NULL;
    knl_alt_column_prop_t *col_def = NULL;
    uint32 i;
    index_t *index = NULL;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && LOGIC_REP_TABLE_ENABLED(session, DC_ENTITY(dc));
    uint32 op_type = RD_ALTER_TABLE;

    knl_panic(def->column_defs.count == 1);
    col_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, 0);
    old_name = &col_def->name;
    new_name = &col_def->new_name;
    table = DC_TABLE(dc);
    column = knl_find_column(&col_def->name, dc);

    if (column == NULL) {
        GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->user), T2S_EX(old_name));
        return GS_ERROR;
    }

    log_append_lrep_colname(session, op_type, has_logic, (uint32 *)&def->action, &col_def->name);

    // if column is indexed by a func index, not support rename column by now;
    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (db_column_in_icol_list(index, column)) {
            GS_THROW_ERROR(ERR_RENAME_FUNC_INDEX, T2S(old_name));
            return GS_ERROR;
        }
    }

    // if column is included in constraints, not support rename column by now;
    if (knl_find_column_in_consdef(table, column) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (knl_find_column(&col_def->new_name, dc) != NULL) {
        GS_THROW_ERROR(ERR_OBJECT_EXISTS, "column", T2S(new_name));
        return GS_ERROR;
    }

    if (db_rename_column_in_syscolumn(session, column->id, new_name, &table->desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_table_desc(session, &table->desc, GS_FALSE, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_altable_rename_table(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
                                 void *trig_list)
{
    knl_dictionary_t new_dc;
    dc_user_t *user = NULL;
    dc_entry_t *entry = NULL;
    bool32 is_exist = GS_FALSE;

    if (dc_is_reserved_entry(dc->uid, dc->oid) && !DB_IS_MAINTENANCE(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION,
                       ",can not rename system table %s.%s", T2S(&def->user), T2S_EX(&def->name));
        return GS_ERROR;
    }

    if (knl_open_dc_if_exists(session, &def->user, &def->table_def.new_name, &new_dc, &is_exist) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (is_exist || SYNONYM_EXIST(&new_dc)) {
        dc_close(&new_dc);
        GS_THROW_ERROR(ERR_DUPLICATE_TABLE, T2S(&def->user), T2S_EX(&def->table_def.new_name));
        return GS_ERROR;
    }

    if (dc_open_user_by_id(session, dc->uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    entry = DC_GET_ENTRY(user, dc->oid);

    if (db_update_table_name(session, dc->uid, entry->name, &def->table_def.new_name, GS_FALSE) != GS_SUCCESS) {
        int32 err_code = cm_get_error_code();

        if (err_code == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_DUPLICATE_TABLE, T2S(&def->user), T2S_EX(&def->table_def.new_name));
        }

        return GS_ERROR;
    }

    if (db_update_table_policy(session, dc->uid, entry->name, &def->table_def.new_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_objname_for_priv(session, dc->uid, entry->name, &def->table_def.new_name,
                                   OBJ_TYPE_TABLE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (g_knl_callback.pl_update_tab_from_sysproc(session, dc, &def->name,
        &def->table_def.new_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return dc_rename_table(session, &def->table_def.new_name, dc);
}

status_t db_altable_add_cons(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    status_t status;
    table_t *table = NULL;
    char cons_name[GS_NAME_BUFFER_SIZE];
    knl_cursor_t *cursor = NULL;
    bool32 find_flag = GS_FALSE;
    bool32 is_empty = GS_FALSE;

    CM_SAVE_STACK(session->stack);
    table = DC_TABLE(dc);
    cursor = knl_push_cursor(session);
    if (db_fetch_sysconsdef_by_table(session, cursor, CURSOR_ACTION_SELECT, table->desc.uid, table->desc.id,
                                     &(def->cons_def.new_cons.name), &find_flag) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    if (find_flag) {
        if (def->options & CREATE_IF_NOT_EXISTS) {
            return GS_SUCCESS;
        } else {
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "constraint", T2S(&def->cons_def.new_cons.name));
            return GS_ERROR;
        }
    }

    if (def->cons_def.new_cons.name.len == 0) {
        knl_get_system_name(session, def->cons_def.new_cons.type, cons_name, GS_NAME_BUFFER_SIZE);
        def->cons_def.new_cons.name.len = (uint32)strlen(cons_name);
        def->cons_def.new_cons.name.str = cons_name;
        def->cons_def.new_cons.cons_state.is_anonymous = GS_TRUE;
    }

    switch (def->cons_def.new_cons.type) {
        case CONS_TYPE_PRIMARY:
        case CONS_TYPE_UNIQUE:
        case CONS_TYPE_REFERENCE:
            status = db_create_cons(session, dc, &def->cons_def.new_cons);
            break;
        case CONS_TYPE_CHECK:
            if (def->cons_def.new_cons.cons_state.is_validate) {
                if (db_table_data_judge_empty(session, dc, &is_empty) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                if (!is_empty && db_verify_check_data(session, dc, &def->cons_def.new_cons.check.text) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            status = db_create_cons(session, dc, &def->cons_def.new_cons);
            break;
        default:
            status = GS_ERROR;
            break;
    }

    if (status != GS_ERROR) {
        /* constraint_state clause (other than "USING INDEX") specified */
        if (IS_CONS_STATE_FLAG_SPECIFIED(&def->cons_def.new_cons)
            && (!(IS_USEINDEX_FLAG_SPECIFIED(&def->cons_def.new_cons)))) {
            GS_LOG_RUN_WAR("constraint_state clause specified but did not take effect.");
        }
    }

    return status;
}

/*
 * alter table pctfree
 * update table description, update segment list range if necessary.
 * @param kernel session, alter table definition
 */
status_t db_altable_pctfree(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = NULL;
    heap_segment_t *segment = NULL;

    table = DC_TABLE(dc);
    if (db_update_table_pctfree(session, &table->desc, def->table_def.pctfree) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (table->heap.segment != NULL) {
        log_atomic_op_begin(session);

        buf_enter_page(session, table->heap.entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        segment = HEAP_SEG_HEAD;
        heap_set_pctfree(session, segment, def->table_def.pctfree);

        if (SPC_IS_LOGGING_BY_PAGEID(table->heap.entry)) {
            log_put(session, RD_HEAP_CHANGE_SEG, segment, HEAP_SEG_SIZE, LOG_ENTRY_FLAG_NONE);
        }

        buf_leave_page(session, GS_TRUE);

        log_atomic_op_end(session);
    }

    return GS_SUCCESS;
}

static status_t db_alter_table_subpart_initrans(knl_session_t *session, table_t *table,
    table_part_t* table_part, uint32 initrans)
{
    table_part_t *table_subpart = NULL;

    if (!IS_PARENT_TABPART(&table_part->desc)) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }

        if (db_update_table_subpart_initrans(session, &table_subpart->desc, initrans) != GS_SUCCESS) {
            return GS_ERROR;
        }
        heap_set_initrans(session, &table_subpart->heap, initrans);
    }
    return GS_SUCCESS;
}

status_t db_altable_initrans(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;
    uint32 initrans = def->table_def.initrans;

    if (db_update_table_initrans(session, &table->desc, initrans) != GS_SUCCESS) {
        return GS_ERROR;
    }
    heap_set_initrans(session, &table->heap, initrans);

    if (!IS_PART_TABLE(table)) {
        return GS_SUCCESS;
    }

    for (uint32 id = 0; id < table->part_table->desc.partcnt; id++) {
        table_part = TABLE_GET_PART(table, id);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (db_update_table_part_initrans(session, &table_part->desc, initrans) != GS_SUCCESS) {
            return GS_ERROR;
        }
        heap_set_initrans(session, &table_part->heap, initrans);

        if (db_alter_table_subpart_initrans(session, table, table_part, initrans) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t db_altable_part_initrans(knl_session_t *session, knl_dictionary_t *dc, knl_alt_part_t *def)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;
    uint32 initrans = def->part_prop.initrans;

    if (!IS_PART_TABLE(table)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify part initrans", "non-partitioned table");
        return GS_ERROR;
    }

    if (!part_table_find_by_name(table->part_table, &def->name, &table_part)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->name));
        return GS_ERROR;
    }

    if (table_part->desc.not_ready) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "modify the initrans parameter of a not ready partition");
        return GS_ERROR;
    }
    
    if (db_update_table_part_initrans(session, &table_part->desc, initrans) != GS_SUCCESS) {
        return GS_ERROR;
    }
    heap_set_initrans(session, &table_part->heap, initrans);

    if (db_alter_table_subpart_initrans(session, table, table_part, initrans) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t db_altable_storage(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    space_t *space = SPACE_GET(table->desc.space_id);
    knl_storage_desc_t storage_desc;
    uint32 max_pages = CM_CALC_ALIGN((uint64)def->table_def.storage_def.maxsize, space->ctrl->block_size) /
        space->ctrl->block_size;

    if (table->desc.storaged && max_pages > 0 && table->desc.storage_desc.initial > 0 &&
        (table->desc.storage_desc.initial > max_pages)) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "initial large than maxsize");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    errno_t err = memset_sp(&storage_desc, sizeof(knl_storage_desc_t), 0, sizeof(knl_storage_desc_t));
    knl_securec_check(err);

    storage_desc.max_pages = max_pages;

    if (!table->desc.storaged) {
        if (db_update_table_flag(session, table->desc.uid, table->desc.id, TABLE_FLAG_TYPE_STORAGED) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_write_sysstorage(session, cursor, table->desc.org_scn, &storage_desc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    } else {
        if (db_update_storage_maxsize(session, cursor, table->desc.org_scn, max_pages) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_altable_part_storage(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    uint32 part_no;
    knl_storage_desc_t storage_desc;

    if (!IS_PART_TABLE(table)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify part storage", "non-partitioned table");
        return GS_ERROR;
    }

    if (knl_find_table_part_by_name(entity, &def->part_def.name, &part_no) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table_part_t *table_part = TABLE_GET_PART(&entity->table, part_no);
    if (table_part->desc.not_ready) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "modify the storage parameters of a not ready partition");
        return GS_ERROR;
    }
    
    part_table_t *part_table = table->part_table;
    space_t *space = SPACE_GET(table_part->desc.space_id);
    uint32 max_pages = CM_CALC_ALIGN((uint64)def->part_def.storage_def.maxsize, space->ctrl->block_size) /
        space->ctrl->block_size;

    if (table_part->desc.storage_desc.initial > 0 && max_pages > 0 &&
        (table_part->desc.storage_desc.initial > max_pages)) {
        GS_THROW_ERROR(ERR_EXCEED_SEGMENT_MAXSIZE);
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    errno_t err = memset_sp(&storage_desc, sizeof(knl_storage_desc_t), 0, sizeof(knl_storage_desc_t));
    knl_securec_check(err);

    storage_desc.max_pages = max_pages;

    if (!table_part->desc.storaged) {
        if (db_update_part_flag(session, dc, part_table, table_part->desc.part_id, PART_FLAG_TYPE_STORAGED)
            != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (db_write_sysstorage(session, cursor, table_part->desc.org_scn, &storage_desc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    } else {
        if (db_update_storage_maxsize(session, cursor, table_part->desc.org_scn, max_pages) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/*
 * alter table appendonly
 * update table description.
 * @param kernel session, alter table definition
 */
status_t db_altable_appendonly(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = NULL;

    table = DC_TABLE(dc);
    if (db_update_table_appendonly(session, &table->desc, def->table_def.appendonly) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_altable_drop_logical_log_inner(knl_session_t *session, knl_cursor_t *cursor,
                                           const uint32 uid, const uint32 tableid)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_LOGIC_REP_ID, IX_SYS_LOGICREP_001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
        IX_COL_SYS_LOGICREP_001_USERID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &tableid, sizeof(uint32),
        IX_COL_SYS_LOGICREP_001_TABLEID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t db_altable_update_logical_log(knl_session_t *session, knl_cursor_t *cursor,
                                       const uint32 uid, const uint32 tableid, text_t *text)
{
    row_assist_t ra;
    uint16 size;
    knl_column_t *lob_column = NULL;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_LOGIC_REP_ID,
        IX_SYS_LOGICREP_001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        &uid, sizeof(uint32), IX_COL_SYS_LOGICREP_001_USERID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        &tableid, sizeof(uint32), IX_COL_SYS_LOGICREP_001_TABLEID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cursor->eof) {
        return GS_ERROR;
    }

    lob_column = knl_get_column(cursor->dc_entity, SYS_LOGIC_REP_COLUMN_ID_PARTITIONIDS);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    if (knl_row_put_lob(session, cursor, lob_column, text, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_LOGIC_REP_COLUMN_ID_PARTITIONIDS;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets,
        cursor->update_info.lens, &size);
    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void db_drop_part_compare_logical(knl_session_t *session, dc_entity_t *entity,
    table_part_t *table_part, text_t *text)
{
    errno_t err;
    table_part_t *table_parts = NULL;
    text->len = 0;

    for (uint32 i = 0; i < entity->table.part_table->desc.partcnt; i++) {
        table_parts = TABLE_GET_PART(&entity->table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            if (table_parts->desc.lrep_status == PART_LOGICREP_STATUS_ON && table_part->part_no != i) {
                if (text->len > 0) {
                    err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, ",");
                    knl_securec_check_ss(err);
                    text->len += err;
                }
                err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, "%s", table_parts->desc.name);
                knl_securec_check_ss(err);
                text->len += err;
            }

            continue;
        }

        table_part_t *subpart = NULL;
        for (uint32 j = 0; i < table_parts->desc.subpart_cnt; j++) {
            subpart = PART_GET_SUBENTITY(entity->table.part_table, table_parts->subparts[j]);
            if (subpart == NULL) {
                continue;
            }

            if (subpart->desc.lrep_status == PART_LOGICREP_STATUS_ON && table_part->part_no != i) {
                if (text->len > 0) {
                    err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, ",");
                    knl_securec_check_ss(err);
                    text->len += err;
                }

                err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, "%s",
                    table_parts->desc.name);
                knl_securec_check_ss(err);
                text->len += err;
            }
        }
    }
}

status_t db_drop_part_logical(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
                              table_part_t *table_part)
{
    text_t text;
    table_t *table = &entity->table;
    uint32 uid = table->desc.uid;
    uint32 tableid = table->desc.id;
    status_t status = GS_SUCCESS;

    if (entity->lrep_info.status == LOGICREP_STATUS_ON || entity->lrep_info.parts_count == 0
        || table_part->desc.lrep_status != PART_LOGICREP_STATUS_ON) {
        return GS_SUCCESS;
    }

    if (entity->lrep_info.parts_count == 1) {
        status = db_altable_drop_logical_log_inner(session, cursor, uid, tableid);
        if (status == GS_SUCCESS) {
            table_part->desc.lrep_status = PART_LOGICREP_STATUS_OFF;
            entity->lrep_info.parts_count = 0;
        }
        return status;
    }
    text.str = (char *)cm_push(session->stack, entity->lrep_info.parts_count * (GS_NAME_BUFFER_SIZE + 1));
    if (text.str == NULL) {
        GS_THROW_ERROR(ERR_STACK_OVERFLOW);
        return GS_ERROR;
    }

    db_drop_part_compare_logical(session, entity, table_part, &text);
    status = db_altable_update_logical_log(session, cursor, uid, tableid, &text);
    if (status == GS_SUCCESS) {
        table_part->desc.lrep_status = PART_LOGICREP_STATUS_OFF;
        entity->lrep_info.parts_count--;
    }
    cm_pop(session->stack);
    return status;
}

status_t db_drop_part_prepare(knl_session_t *session, table_t *table, knl_altable_def_t *def,
                              table_part_t **table_part, bool32 *part_not_exists)
{
    if (!table->desc.parted) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "drop partition", table->desc.name);
        return GS_ERROR;
    }

    if (!part_table_find_by_name(table->part_table, &def->part_def.name, table_part)) {
        *part_not_exists = GS_TRUE;
        if (!(def->options & DROP_IF_EXISTS)) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
        }
        return GS_ERROR;
    }

    // if partcnt < 2 , drop table partition is not allowed
    if (!((*table_part)->desc.flags & PARTITON_NOT_READY)) {
        if (table->part_table->desc.partcnt < 2 && def->action != ALTABLE_SPLIT_PARTITION) {
            GS_THROW_ERROR(ERR_DROP_ONLY_PART);
            return GS_ERROR;
        }
    }

    if (PART_CONTAIN_INTERVAL(table->part_table) && (*table_part)->part_no == table->part_table->desc.transition_no) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "drop transition partition", "interval partitioned table");
        return GS_ERROR;
    }

    if (db_table_is_referenced(session, table, GS_TRUE)) {
        GS_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_drop_part_handle_index(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    table_part_t *table_part, bool32 is_part_add_or_coalesce)
{
    table_t *table = DC_TABLE(dc);
    bool32 is_changed = GS_FALSE;
    bool32 need_invalidate_index = GS_FALSE;
    knl_part_desc_t *desc = &table->part_table->desc;

    if (db_need_invalidate_index(session, dc, table, table_part, &need_invalidate_index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index_t *index = table->index_set.items[i];
        if (index->desc.parted) {
            index_part_t *index_part = INDEX_GET_PART(index, table_part->part_no);
            if (index_part == NULL) {
                continue;
            }

            if (db_delete_from_sysindexpart(session, cursor, desc->uid, desc->table_id, index->desc.id,
                                            table_part->desc.part_id) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (PART_CONTAIN_INTERVAL(table->part_table)) {
                if (part_update_interval_part_count(session, table, table_part->part_no,
                                                    index->desc.id, GS_FALSE) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            } else {
                if (db_update_part_count(session, desc->uid, desc->table_id, index->desc.id, GS_FALSE) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            if (!IS_PARENT_TABPART(&table_part->desc)) {
                continue;
            }

            if (db_delete_subidxparts_with_compart(session, cursor, desc->uid, desc->table_id, index->desc.id,
                table_part->desc.part_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else if (!is_part_add_or_coalesce) {
            // is_part_add_or_coalesce = true means partition redistribution is ongoing, no need to invalidate index
            if (need_invalidate_index) {
                if (db_update_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                if (btree_segment_prepare(session, index, GS_INVALID_ID32, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
        }
    }

    return GS_SUCCESS;
}

static status_t db_delete_part_stats(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part)
{
    dc_entity_t *entity = DC_ENTITY(dc);

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (stats_delete_histgram_by_part(session, cursor, dc, table_part->desc.part_id) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    if (stats_delete_histhead_by_part(session, dc, table_part->desc.part_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (DB_IS_STATS_ENABLED(((knl_session_t *)session)->kernel)) {
        stats_table_mon_t *table_stats = &entity->entry->appendix->table_smon;
        table_stats->is_change = GS_TRUE;
        table_stats->drop_segments++;
        table_stats->timestamp = cm_now();
    }

    return GS_SUCCESS;
}

static status_t db_drop_part_handle_lob(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    table_part_t *table_part)
{
    knl_column_t *column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = DC_TABLE(dc);
    lob_part_t *lob_part = NULL;
    knl_part_desc_t *desc = &table->part_table->desc;

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        GS_LOG_DEBUG_INF("drop part: begin to delete from lob part$, uid: %d, tid: %d, column id: %d, part_id: %d",
            desc->uid, desc->table_id, column->id, table_part->desc.part_id);

        lob_part = LOB_GET_PART((lob_t *)column->lob, table_part->part_no);
        if (lob_part == NULL) {
            continue;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (db_delete_sublobparts_with_compart(session, cursor, desc->uid, desc->table_id, column->id,
                table_part->desc.part_id) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (db_delete_from_syslobpart(session, cursor, desc->uid, desc->table_id, column->id,
            table_part->desc.part_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static inline status_t db_drop_part_precheck(table_t *table, knl_altable_def_t *def, bool32 is_part_add_or_coalesce)
{
    if (!is_part_add_or_coalesce && !def->part_def.is_garbage_clean) {
        if (table->part_table == NULL) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
            return GS_ERROR;
        }
        if (table->part_table->desc.parttype == PART_TYPE_HASH) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table drop partition", "hash partition");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t db_drop_part_handle_interval(knl_session_t *session, table_t *table,  table_part_t *table_part,
    knl_part_desc_t *desc)
{
    if (PART_CONTAIN_INTERVAL(table->part_table)) {
        if (part_update_interval_part_count(session, table, table_part->part_no, GS_INVALID_ID32,
            GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (db_update_part_count(session, desc->uid, desc->table_id, desc->index_id, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t db_drop_part_handle_objects(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    table_part_t *table_part, bool32 is_part_add_or_coalesce)
{
    table_t *table = DC_TABLE(dc);
    knl_part_desc_t *desc = &table->part_table->desc;

    if (db_drop_part_handle_interval(session, table, table_part, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (DC_ENTITY(dc)->contain_lob) {
        if (db_drop_part_handle_lob(session, cursor, dc, table_part) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (db_drop_part_handle_index(session, cursor, dc, table_part, is_part_add_or_coalesce) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t db_drop_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    bool32 add_or_coalesce)
{
    table_t *table = DC_TABLE(dc);

    if (db_delete_part_stats(session, dc, table_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_part_desc_t *desc = &table->part_table->desc;

    if (IS_PARENT_TABPART(&table_part->desc)) {
        if (db_delete_subtabparts_of_compart(session, cursor, desc->uid, desc->table_id,
            table_part->desc.part_id) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (db_delete_from_systablepart(session, cursor, desc->uid, desc->table_id,
        table_part->desc.part_id) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (table_part->desc.storaged && db_delete_from_sysstorage(session, cursor,
        table_part->desc.org_scn) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_drop_part_handle_objects(session, dc, cursor, table_part, add_or_coalesce) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_update_table_chgscn(session, &table->desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_drop_part_segments(session, dc, table_part->part_no) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_drop_part_logical(session, cursor, DC_ENTITY(dc), table_part) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (table_part->desc.compress) {
        if (db_delete_from_syscompress(session, cursor, table_part->desc.org_scn) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    if (stats_update_global_tablestats(session, dc, table_part->part_no) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_delete_mon_sysmods(session, dc->uid, dc->oid, table_part->desc.part_id, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    session->stat.table_part_drops++;
    return GS_SUCCESS;
}

/*
 * is_force=true means do not check whether it is hash/xx partition
 */
status_t db_altable_drop_part(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    bool32 is_part_add_or_coalesce)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;

    if (db_drop_part_precheck(table, def, is_part_add_or_coalesce) != GS_SUCCESS) {
        return GS_ERROR;
    }

    bool32 part_not_exists = GS_FALSE;
    if (db_drop_part_prepare(session, table, def, &table_part, &part_not_exists) != GS_SUCCESS) {
        if (part_not_exists && (def->options & DROP_IF_EXISTS)) {
            return GS_SUCCESS;
        }
        return GS_ERROR;
    }

    if (db_drop_part(session, dc, table_part, is_part_add_or_coalesce) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t part_truncate_table_compart(knl_session_t *session, table_t *table, table_part_t *table_part,
    bool32 reuse)
{
    table_part_t *part = NULL;
    table_part_t *subpart = NULL;

    for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
        subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
        if (subpart == NULL || subpart->heap.segment == NULL) {
            continue;
        }

        part = (table_part_t *)subpart;
        if (heap_part_segment_prepare(session, part, reuse, HEAP_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t part_truncate_index_compart(knl_session_t *session, table_t *table, table_part_t *table_part,
    bool32 reuse, bool32 invalidate_index)
{
    index_t *index = NULL;
    bool32 is_changed = GS_FALSE;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (!index->desc.parted) {
            if (invalidate_index) {
                if (db_update_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                if (btree_segment_prepare(session, index, GS_FALSE, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            continue;
        }

        index_part_t *index_part = NULL;
        index_part_t *index_subpart = NULL;
        index_part = INDEX_GET_PART(index, table_part->part_no);
        knl_panic_log(IS_PARENT_IDXPART(&index_part->desc),
            "current index_part is not parent_idxpart, panic info: table %s table_part %s index %s index_part %s",
            table->desc.name, table_part->desc.name, index->desc.name, index_part->desc.name);
        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (index_subpart == NULL || index_subpart->btree.segment == NULL) {
                continue;
            }

            if (db_update_sub_idxpart_status(session, index_subpart, GS_FALSE, &is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (btree_part_segment_prepare(session, index_subpart, reuse, BTREE_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t part_truncate_lob_compart(knl_session_t *session, dc_entity_t *entity, table_part_t *table_part,
    bool32 reuse)
{
    if (!entity->contain_lob) {
        return GS_SUCCESS;
    }

    knl_column_t *column = NULL;
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    lob_part_t *lob_subpart = NULL;

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = column->lob;
        lob_part = LOB_GET_PART(lob, table_part->part_no);
        knl_panic_log(IS_PARENT_LOBPART(&lob_part->desc),
                      "current lob_part is not parent_lobpart, panic info: table %s table_part %s",
                      entity->table.desc.name, table_part->desc.name);
        for (uint32 j = 0; j < lob_part->desc.subpart_cnt; j++) {
            lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[j]);
            if (lob_subpart == NULL || lob_subpart->lob_entity.segment == NULL) {
                continue;
            }

            if (lob_part_segment_prepare(session, (lob_part_t *)lob_subpart, reuse,
                LOB_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_truncate_table_compart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    bool32 reuse_storage, bool32 need_invalidate_index)
{
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    knl_panic_log(IS_PARENT_TABPART(&table_part->desc), "current part is not parent_tabpart, panic info: table %s",
                  table->desc.name);
    if (part_truncate_table_compart(session, table, table_part, reuse_storage) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (part_truncate_index_compart(session, table, table_part, reuse_storage, need_invalidate_index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (part_truncate_lob_compart(session, entity, table_part, reuse_storage) != GS_SUCCESS) {
        return GS_ERROR;
    }

    stats_table_mon_t *table_stats = &entity->entry->appendix->table_smon;
    table_stats->is_change = GS_TRUE;
    table_stats->drop_segments++;
    table_stats->timestamp = cm_now();
    return GS_SUCCESS;
}

static status_t db_truncate_table_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
                                       bool32 reuse_storage)
{
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    lob_part_t *lob_part = NULL;
    lob_t *lob = NULL;
    knl_column_t *column = NULL;
    stats_table_mon_t *table_stats = NULL;
    bool32 is_changed = GS_FALSE;
    bool32 need_invalidate_index = GS_FALSE;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    if (db_need_invalidate_index(session, dc, table, table_part, &need_invalidate_index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_PARENT_TABPART(&table_part->desc)) {
        return db_truncate_table_compart(session, dc, table_part, reuse_storage, need_invalidate_index);
    }

    if (heap_part_segment_prepare(session, table_part, reuse_storage, HEAP_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (entity->contain_lob) {
        for (uint32 i = 0; i < entity->column_count; i++) {
            column = dc_get_column(entity, i);
            if (!COLUMN_IS_LOB(column)) {
                continue;
            }

            lob = (lob_t *)column->lob;
            lob_part = LOB_GET_PART(lob, table_part->part_no);
            if (lob_part_segment_prepare(session, lob_part, reuse_storage, LOB_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (index->desc.parted) {
            index_part = INDEX_GET_PART(index, table_part->part_no);
            if (btree_part_segment_prepare(session, index_part, reuse_storage,
                BTREE_TRUNCATE_PART_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        } else {
            if (need_invalidate_index) {
                if (db_update_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                if (btree_segment_prepare(session, index, GS_INVALID_ID32, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        }
    }

    table_stats = &entity->entry->appendix->table_smon;
    table_stats->is_change = GS_TRUE;
    table_stats->drop_segments++;
    table_stats->timestamp = cm_now();
    return GS_SUCCESS;
}

status_t db_altable_truncate_part(knl_session_t *session, knl_dictionary_t *dc, knl_alt_part_t *def)
{
    table_t *table;
    table_part_t *table_part = NULL;
    knl_session_t *se = (knl_session_t *)session;

    table = DC_TABLE(dc);

    if (!table->desc.parted) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table truncate partition", table->desc.name);
        return GS_ERROR;
    }

    if (!part_table_find_by_name(table->part_table, &def->name, &table_part)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->name));
        return GS_ERROR;
    }

    if (table_part->desc.not_ready) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "truncate a not ready partition");
        return GS_ERROR;
    }
    
    if (db_table_is_referenced(session, table, GS_TRUE)) {
        GS_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
        return GS_ERROR;
    }

    if (!db_tabpart_has_segment(table->part_table, table_part)) {
        return GS_SUCCESS;
    }

    if (dc->type != DICT_TYPE_TABLE || table_part->desc.space_id == SYS_SPACE_ID ||
        def->option != TRUNC_RECYCLE_STORAGE || !se->kernel->attr.recyclebin) {
        return db_truncate_table_part(session, dc, table_part, def->option & TRUNC_REUSE_STORAGE);
    } else {
        return rb_truncate_table_part(session, dc, table_part);
    }
}

bool32 db_fetch_systable_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    /* find the tuple by uid only */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uid),
                     IX_COL_SYS_TABLE_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uid),
                     IX_COL_SYS_TABLE_001_USER_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLE_001_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLE_001_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

bool32 db_fetch_sysindex_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INDEX_ID, IX_SYS_INDEX_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    /* find the tuple by uid only */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_USER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEX_001_TABLE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEX_001_TABLE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEX_001_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEX_001_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

bool32 db_fetch_sysconsdef_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    /* find the tuple by uid only */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_CONSDEF001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_CONSDEF001_TABLE_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

bool32 db_fetch_syssequence_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SEQ_ID, SYS_SEQ001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    /* get all sequences by uid */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_SEQ001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_SEQ001_UID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SEQ001_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SEQ001_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

bool32 db_fetch_sysview_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_VIEW_ID, IX_SYS_VIEW001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    /* find the tuple by uid only */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_VIEW001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_VIEW001_USER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_VIEW001_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_VIEW001_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

bool32 db_fetch_sysrecyclebin_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RB_ID, IX_SYS_RB004_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    /* find the tuple by uid only */
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_RB004_USER_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

bool32 db_fetch_sysproc_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, IX_PROC_003_ID);

    /* find the tuple by uid only */
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uid),
                     IX_COL_PROC_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uid),
                     IX_COL_PROC_003_USER_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_PROC_003_OBJ_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_PROC_003_OBJ_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

bool32 db_fetch_sysjob_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor, text_t *user_name)
{
    text_t job_user;
    dc_user_t *sys_user = NULL;

    /* check job$ exist or not */
    if (!(dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) == GS_SUCCESS &&
          DC_GET_ENTRY(sys_user, SYS_JOB_ID) != NULL)) {
        cm_reset_error();
        return GS_FALSE;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_JOB_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_FALSE;
    }

    while (!cursor->eof) {
        job_user.str = CURSOR_COLUMN_DATA(cursor, SYS_JOB_LOWNER);
        job_user.len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_LOWNER);

        if (cm_compare_text_ins(user_name, &job_user) == 0) {
            return GS_TRUE;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_FALSE;
        }
    }

    return GS_FALSE;
}

bool32 db_fetch_syslibrary_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_LIBRARY_ID, IDX_LIBRARY_001_ID);

    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uid),
                     IX_COL_SYS_LIBRARY001_OWNER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uid),
                     IX_COL_SYS_LIBRARY001_OWNER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_LIBRARY001_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_LIBRARY001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_FALSE;
    }

    if (!cursor->eof) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 db_fetch_sql_map_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SQL_MAP_ID, IDX_SQL_MAP_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SQL_MAP_002_SRC_USER_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

bool32 db_fetch_dist_rules_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DISTRIBUTE_RULE_ID, IX_SYS_DISTRIBUTE_RULE003_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_DISTRIBUTE_RULE003_UID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_FALSE;
    }

    return (bool32)(!cursor->eof);
}

/*
 * scan if the user need dropped has any objects not deleted yet.
 * @param
 * - session: kernel session
 * - uid : user id
 * - hasObj : scan result
 * @return
 * - GS_SUCCESS
 * - GS_ERROR
 * @note null
 * @see null
 */
bool32 db_user_has_objects(knl_session_t *session, uint32 uid, text_t *uname)
{
    bool32 hasObj = GS_FALSE;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    cursor->row = (row_head_t *)cursor->buf;

    do {
        if (db_fetch_systable_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_sysindex_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_sysconsdef_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_sysview_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_sysproc_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_syssequence_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_syssynonym_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_sysrecyclebin_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_sysjob_by_user(session, uid, cursor, uname)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_syslibrary_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_sql_map_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }

        if (db_fetch_dist_rules_by_user(session, uid, cursor)) {
            hasObj = GS_TRUE;
            break;
        }
    } while (0);

    CM_RESTORE_STACK(session->stack);
    return hasObj;
}

/*
 * drop tables owned by the user, include:
 * - TABLE$ tuples
 * - COLUMN$ tuples
 * - constraints
 * - indexes
 * - childrens' refrences constraints and indexes.
 * - syslob if exists.
 * @param
 * - session: kernel session
 * - dc : dictionary cache of the table need dropped.
 * @return
 * - GS_SUCCESS
 * - GS_ERROR
 * @note null
 * @see null
 */
status_t db_drop_table_cascade(knl_session_t *session, text_t *user, knl_table_desc_t *desc)
{
    knl_dictionary_t dc;
    table_t *table = NULL;
    text_t table_name;
    bool32 is_found = GS_FALSE;
    dc_entry_t *entry = NULL;
    errno_t ret;

    cm_str2text(desc->name, &table_name);
    if (knl_open_dc_if_exists(session, user, &table_name, &dc, &is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!is_found || SYNONYM_EXIST(&dc)) {
        if (is_found) {
            dc_close(&dc);
        }
        return GS_SUCCESS;
    }

    table = DC_TABLE(&dc);

    /* delete all the reference constraints for the childrens */
    if (db_drop_ref_constraints(session, table->desc.uid, table->desc.id) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (db_drop_table(session, &dc) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (db_altable_drop_logical_log(session, &dc, NULL) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (db_delete_mon_sysmods(session, table->desc.uid, table->desc.id, GS_INVALID_ID32, GS_FALSE) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    entry = DC_ENTRY(&dc);

    ret = memset_sp(&entry->appendix->table_smon, sizeof(stats_table_mon_t), 0, sizeof(stats_table_mon_t));
    knl_securec_check(ret);

    dc_close(&dc);
    return GS_SUCCESS;
}

status_t db_fetch_table_by_uid(knl_session_t *session, uint32 uid, knl_table_desc_t *desc, bool32 *found)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uid),
                     IX_COL_SYS_TABLE_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uid),
                     IX_COL_SYS_TABLE_001_USER_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_TABLE_001_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_TABLE_001_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        *found = GS_FALSE;
        return GS_ERROR;
    }

    while (!cursor->eof) {
        dc_convert_table_desc(cursor, desc);
        if (desc->recycled == 0) {
            *found = GS_TRUE;
            CM_RESTORE_STACK(session->stack);
            return GS_SUCCESS;
        } else {
            GS_BREAK_IF_ERROR(knl_fetch(session, cursor));
        }
    }

    CM_RESTORE_STACK(session->stack);
    *found = GS_FALSE;
    return GS_SUCCESS;
}

/*
 * drop tables owned by the user, include:
 * - TABLE$ tuples
 * - COLUMN$ tuples
 * - constraints
 * - indexes
 * - childrens' refrences constraints and indexes.
 * - syslob if exists.
 * @param
 * - session: kernel session
 * - uid : user id
 * @return
 * - GS_SUCCESS
 * - GS_ERROR
 * @note null
 * @see null
 */
status_t db_drop_table_by_user(knl_session_t *session, text_t *user)
{
    uint32 uid;
    bool32 found = GS_FALSE;
    knl_table_desc_t desc;

    if (!dc_get_user_id(session, user, &uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(user));
        return GS_ERROR;
    }

    knl_set_session_scn(session, GS_INVALID_ID64);
    if (db_fetch_table_by_uid(session, uid, &desc, &found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    while (found) {
        if (db_drop_table_cascade(session, user, &desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        knl_set_session_scn(session, GS_INVALID_ID64);

        if (db_fetch_table_by_uid(session, uid, &desc, &found) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_delete_job_by_user(knl_session_t *session, text_t *user)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = (knl_session_t *)session;
    dc_user_t *sys_user = NULL;
    text_t powner;

    /* check job$ exist or not */
    if (!(dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) == GS_SUCCESS &&
          DC_GET_ENTRY(sys_user, SYS_JOB_ID) != NULL)) {
        cm_reset_error();
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    knl_set_session_scn(session, GS_INVALID_ID64);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(knl_session, cursor, CURSOR_ACTION_DELETE, SYS_JOB_ID, GS_INVALID_ID32);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        /* check user name equal */
        powner.str = CURSOR_COLUMN_DATA(cursor, SYS_JOB_POWNER);
        powner.len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_POWNER);

        if (cm_text_equal_ins(&powner, user) && knl_internal_delete(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_insert_ptrans(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 ltid, binary_t *tlocklob, rowid_t *rowid)
{
    knl_cursor_t *cursor = NULL;
    knl_column_t *lob_column = NULL;
    row_assist_t ra;
    text_t global_id;
    text_t branch_id;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_PENDING_TRANS_ID, GS_INVALID_ID32);

    row_init(&ra, cursor->buf, GS_MAX_ROW_SIZE, SYS_PENDING_TRANS_COLUMN_COUNT);
    cm_str2text_safe(xa_xid->gtrid, xa_xid->gtrid_len, &global_id);
    (void)row_put_text(&ra, &global_id);
    (void)row_put_int64(&ra, (int64)ltid);

    if (tlocklob->size < GS_TLOCKLOB_BUFFER_SIZE) {
        (void)row_put_bin(&ra, tlocklob);
        row_put_null(&ra);
    } else {
        row_put_null(&ra);
        lob_column = knl_get_column(cursor->dc_entity, SYS_PENDING_TRANS_COL_TLOCK_LOBS_EXT);
        if (knl_row_put_lob(session, cursor, lob_column, tlocklob, &ra) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    (void)row_put_int64(&ra, (int64)xa_xid->fmt_id);

    if (xa_xid->bqual_len == 0) {
        row_put_null(&ra);
    } else {
        cm_str2text_safe(xa_xid->bqual, xa_xid->bqual_len, &branch_id);
        (void)row_put_text(&ra, &branch_id);
    }

    (void)row_put_int32(&ra, (int32)session->uid);

    (void)row_put_int64(&ra, session->xa_scn);
    (void)row_put_int64(&ra, GS_INVALID_ID64);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    ROWID_COPY((*rowid), cursor->rowid);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_decode_ptrans_result(knl_session_t *session, knl_cursor_t *cursor, knl_xa_xid_t *xa_xid,
                                        uint64 *ltid, binary_t *tlocklob, uint32 *uid)
{
    lob_locator_t *lob_locator = NULL;
    text_t rel_varchar;
    binary_t rel_tlocklob;
    errno_t ret;

    if (xa_xid != NULL) {
        rel_varchar.str = CURSOR_COLUMN_DATA(cursor, SYS_PENDING_TRANS_COL_GLOBAL_TRAN_ID);
        rel_varchar.len = CURSOR_COLUMN_SIZE(cursor, SYS_PENDING_TRANS_COL_GLOBAL_TRAN_ID);
        xa_xid->gtrid_len = rel_varchar.len;
        ret = memcpy_sp(xa_xid->gtrid, GS_MAX_XA_BASE16_GTRID_LEN, rel_varchar.str, rel_varchar.len);
        knl_securec_check(ret);

        xa_xid->fmt_id = *(uint64 *)(CURSOR_COLUMN_DATA(cursor, SYS_PENDING_TRANS_COL_FORMAT_ID));

        rel_varchar.str = CURSOR_COLUMN_DATA(cursor, SYS_PENDING_TRANS_COL_BRANCH_ID);
        rel_varchar.len = CURSOR_COLUMN_SIZE(cursor, SYS_PENDING_TRANS_COL_BRANCH_ID);

        if (rel_varchar.len == (uint32)GS_NULL_VALUE_LEN) {
            xa_xid->bqual_len = 0;
        } else {
            xa_xid->bqual_len = rel_varchar.len;
            ret = memcpy_sp(xa_xid->bqual, GS_MAX_XA_BASE16_BQUAL_LEN, rel_varchar.str, rel_varchar.len);
            knl_securec_check(ret);
        }
    }

    if (ltid != NULL) {
        *ltid = *(uint64 *)(CURSOR_COLUMN_DATA(cursor, SYS_PENDING_TRANS_COL_LOCAL_TRAN_ID));
    }

    if (uid != NULL) {
        *uid = *(uint32 *)(CURSOR_COLUMN_DATA(cursor, SYS_PENDING_TRANS_COL_OWNER));
    }

    if (tlocklob == NULL) {
        return GS_SUCCESS;
    }

    if (CURSOR_COLUMN_SIZE(cursor, SYS_PENDING_TRANS_COL_TLOCK_LOBS_EXT) != GS_NULL_VALUE_LEN) {
        lob_locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, SYS_PENDING_TRANS_COL_TLOCK_LOBS_EXT);
        if (lob_locator->head.size > 0) {
            tlocklob->size = knl_lob_size(lob_locator);
            if (knl_read_lob(session, lob_locator, 0, tlocklob->bytes,
                GS_XA_EXTEND_BUFFER_SIZE, NULL) != GS_SUCCESS) {
                return GS_ERROR;
            }
            return GS_SUCCESS;
        }
    }

    rel_tlocklob.bytes = (uint8 *)CURSOR_COLUMN_DATA(cursor, SYS_PENDING_TRANS_COL_TLOCK_LOBS);
    rel_tlocklob.size = CURSOR_COLUMN_SIZE(cursor, SYS_PENDING_TRANS_COL_TLOCK_LOBS);
    tlocklob->size = 0;

    if (rel_tlocklob.size == (uint32)GS_NULL_VALUE_LEN) {
        return GS_SUCCESS;
    }

    if (cm_concat_bin(tlocklob, GS_XA_EXTEND_BUFFER_SIZE, &rel_tlocklob) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_match_ptrans(void *handle, bool32 *match)
{
    ptrans_match_cond_t *cond = (ptrans_match_cond_t *)handle;
    knl_session_t *session = cond->session;
    knl_cursor_t *cursor = cond->cursor;
    knl_xa_xid_t ret_xa_xid;
    xid_t ret_ltid;
    txn_snapshot_t snapshot;

    *match = GS_FALSE;

    if (db_decode_ptrans_result(session, cursor, &ret_xa_xid, &ret_ltid.value, NULL, NULL) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cond->xa_xid != NULL) {
        if (!knl_xa_xid_equal(cond->xa_xid, &ret_xa_xid)) {
            return GS_SUCCESS;
        }
    }

    if (cond->only_remained) {
        /* this rm still in global hash bucket,not a remain XA transaction */
        if (g_knl_callback.get_xa_xid(&ret_xa_xid) != GS_INVALID_ID16) {
            return GS_SUCCESS;
        }

        tx_get_snapshot(session, ret_ltid.xmap, &snapshot);
        if (snapshot.xnum == ret_ltid.xnum && snapshot.status != (uint8)XACT_END) {
            return GS_SUCCESS;
        }
    }

    if (cond->ltid != NULL) {
        *match = (bool32)((*cond->ltid) == ret_ltid.value);
        return GS_SUCCESS;
    }

    *match = GS_TRUE;
    return GS_SUCCESS;
}

status_t db_fetch_ptrans_by_gtid(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 *ltid,
                                 bool32 *is_found, rowid_t *rowid)
{
    knl_match_cond_t org_match_cond = session->match_cond;
    knl_cursor_t *cursor = NULL;
    ptrans_match_cond_t cond;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PENDING_TRANS_ID, GS_INVALID_ID32);
    cursor->stmt = (void *)&cond;
    session->match_cond = db_match_ptrans;
    cond.session = session;
    cond.cursor = cursor;
    cond.xa_xid = xa_xid;
    cond.ltid = NULL;
    cond.only_remained = GS_FALSE;

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        session->match_cond = org_match_cond;
        return GS_ERROR;
    }
    session->match_cond = org_match_cond;

    if (cursor->eof) {
        *is_found = GS_FALSE;
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    if (db_decode_ptrans_result(session, cursor, NULL, ltid, NULL, NULL) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    ROWID_COPY((*rowid), cursor->rowid);
    CM_RESTORE_STACK(session->stack);
    *is_found = GS_TRUE;
    return GS_SUCCESS;
}


status_t db_fetch_ptrans_by_ltid(knl_session_t *session, uint64 ltid, knl_xa_xid_t *xa_xid,
                                 binary_t *tlocklob, bool32 *is_found, knl_rm_t *rm)
{
    knl_match_cond_t org_match_cond = session->match_cond;
    knl_cursor_t *cursor = NULL;
    ptrans_match_cond_t cond;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PENDING_TRANS_ID, GS_INVALID_ID32);
    cursor->stmt = (void *)&cond;
    session->match_cond = db_match_ptrans;
    cond.session = session;
    cond.cursor = cursor;
    cond.xa_xid = NULL;
    cond.ltid = &ltid;
    cond.only_remained = GS_FALSE;

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        session->match_cond = org_match_cond;
        return GS_ERROR;
    }
    session->match_cond = org_match_cond;

    if (cursor->eof) {
        *is_found = GS_FALSE;
        GS_LOG_DEBUG_WAR("fetch from pending_trans$ by ltid[%llu] failed.", ltid);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    if (db_decode_ptrans_result(session, cursor, xa_xid, NULL, tlocklob, &rm->uid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    ROWID_COPY(rm->xa_rowid, cursor->rowid);
    CM_RESTORE_STACK(session->stack);
    *is_found = GS_TRUE;
    return GS_SUCCESS;
}

status_t db_delete_ptrans_by_rowid(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 ltid, rowid_t rowid)
{
    knl_match_cond_t org_match_cond = session->match_cond;
    knl_cursor_t *cursor = NULL;
    ptrans_match_cond_t cond;
    bool32 is_found = GS_FALSE;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_PENDING_TRANS_ID, GS_INVALID_ID32);
    cursor->stmt = (void *)&cond;
    knl_panic_log(!IS_INVALID_ROWID(rowid), "the rowid is invalid, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);
    ROWID_COPY(cursor->rowid, rowid);
    session->match_cond = db_match_ptrans;
    cond.session = session;
    cond.cursor = cursor;
    cond.xa_xid = xa_xid;
    cond.ltid = &ltid;
    cond.only_remained = GS_FALSE;

    if (knl_fetch_by_rowid(session, cursor, &is_found) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        session->match_cond = org_match_cond;
        return GS_ERROR;
    }
    session->match_cond = org_match_cond;

    if (!is_found) {
        GS_LOG_DEBUG_INF("not found xa_xid[%llu] in pending_trans$.", xa_xid->fmt_id);
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_delete_ptrans_remained(knl_session_t *session, knl_xa_xid_t *xa_xid, uint64 *ltid, bool32 *is_found)
{
    knl_match_cond_t org_match_cond = session->match_cond;
    knl_cursor_t *cursor = NULL;
    ptrans_match_cond_t cond;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_PENDING_TRANS_ID, GS_INVALID_ID32);
    cursor->stmt = (void *)&cond;
    session->match_cond = db_match_ptrans;
    cond.session = session;
    cond.cursor = cursor;
    cond.xa_xid = xa_xid;
    cond.ltid = ltid;
    cond.only_remained = GS_TRUE;
    *is_found = GS_FALSE;

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        session->match_cond = org_match_cond;
        knl_rollback(session, NULL);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            session->match_cond = org_match_cond;
            knl_rollback(session, NULL);
            return GS_ERROR;
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            session->match_cond = org_match_cond;
            knl_rollback(session, NULL);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    session->match_cond = org_match_cond;
    knl_commit(session);
    return GS_SUCCESS;
}

status_t db_write_syssyn(knl_session_t *session, knl_cursor_t *cursor, knl_synonym_t *synonym)
{
    uint32 max_size;
    row_assist_t ra;
    table_t *table = NULL;

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SYN_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);

    if (row_put_int32(&ra, synonym->uid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int32(&ra, synonym->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int64(&ra, synonym->org_scn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int64(&ra, synonym->chg_scn) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_str(&ra, synonym->name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_str(&ra, synonym->table_owner) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_str(&ra, synonym->table_name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int32(&ra, synonym->flags) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (row_put_int32(&ra, synonym->type) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_init_synonmy_desc(knl_session_t *session, knl_synonym_t *synonym, knl_synonym_def_t *def)
{
    if (!dc_get_user_id(session, &def->owner, &synonym->uid)) {
        GS_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&def->owner));
        return GS_ERROR;
    }

    synonym->id = GS_INVALID_ID32;
    synonym->org_scn = db_inc_scn(session);
    synonym->chg_scn = synonym->org_scn;
    (void)cm_text2str(&def->name, synonym->name, GS_NAME_BUFFER_SIZE);
    (void)cm_text2str(&def->table_owner, synonym->table_owner, GS_NAME_BUFFER_SIZE);
    (void)cm_text2str(&def->table_name, synonym->table_name, GS_NAME_BUFFER_SIZE);
    synonym->flags = OBJ_STATUS_VALID;
    synonym->type = knl_get_object_type(def->ref_dc_type);

    return GS_SUCCESS;
}

status_t db_create_synonym(knl_session_t *session, knl_synonym_def_t *def)
{
    knl_synonym_t synonym;
    knl_cursor_t *cursor = NULL;
    rd_synonym_t redo;
    object_address_t depender, referer;
    dc_user_t *user = NULL;
    errno_t err;

    if (DB_NOT_READY(session)) {
        GS_THROW_ERROR(ERR_NO_DB_ACTIVE);
        return GS_ERROR;
    }

    if (db_init_synonmy_desc(session, &synonym, def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_open_user_by_id(session, synonym.uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_create_synonym_entry(session, user, &synonym) != GS_SUCCESS) {
        return GS_ERROR;
    }

    // for creating table bug fix: cursor->row is null
    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;

    if (db_write_syssyn(session, cursor, &synonym) != GS_SUCCESS) {
        dc_free_broken_entry(session, synonym.uid, synonym.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    // insert into sys.dependency$
    depender.uid = synonym.uid;
    depender.oid = synonym.id;
    depender.tid = OBJ_TYPE_SYNONYM;
    depender.scn = synonym.chg_scn;
    err = strncpy_s(depender.name, GS_NAME_BUFFER_SIZE, def->name.str, def->name.len);
    knl_securec_check(err);
    referer.uid = def->ref_uid;
    referer.oid = def->ref_oid;
    referer.tid = knl_get_object_type(def->ref_dc_type);
    referer.scn = def->ref_chg_scn;
    err = strncpy_s(referer.name, GS_NAME_BUFFER_SIZE, def->table_name.str, def->table_name.len);
    knl_securec_check(err);
    if (db_write_sysdep(session, cursor, &depender, &referer, 0) != GS_SUCCESS) {
        dc_free_broken_entry(session, synonym.uid, synonym.id);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    dc_ready(session, synonym.uid, synonym.id);

    redo.op_type = RD_CREATE_SYNONYM;
    redo.uid = synonym.uid;
    redo.id = synonym.id;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_synonym_t), LOG_ENTRY_FLAG_NONE);
    knl_commit(session);

    return GS_SUCCESS;
}

static status_t db_delete_from_syssyn(knl_session_t *session, knl_cursor_t *cursor, dc_entry_t *syn_entry)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SYN_ID, IX_SYS_SYNONYM001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&syn_entry->uid,
                     sizeof(uint32), IX_COL_SYS_SYNONYM001_USER);
    // object name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)syn_entry->name,
                     (uint16)strlen(syn_entry->name), IX_COL_SYS_SYNONYM001_SYNONYM_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_THROW_ERROR(ERR_SYNONYM_NOT_EXIST, syn_entry->user->desc.name, syn_entry->name);
        return GS_ERROR;
    }

    if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_delete_from_sysdep(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, int64 oid, uint32 tid)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_DEPENDENCY_ID, IX_DEPENDENCY1_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_DEPENDENCY1_D_OWNER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_BIGINT, &oid, sizeof(int64),
                     IX_COL_DEPENDENCY1_D_OBJ_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &tid, sizeof(uint32),
                     IX_COL_DEPENDENCY1_D_TYPE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_DEPENDENCY1_ORDER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_DEPENDENCY1_D_OWNER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_BIGINT, &oid, sizeof(int64),
                     IX_COL_DEPENDENCY1_D_OBJ_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &tid, sizeof(uint32),
                     IX_COL_DEPENDENCY1_D_TYPE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_DEPENDENCY1_ORDER_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
 * db_delete_dependency
 *
 * This function is used to delete the referenced object info of the input object.
 */
status_t db_delete_dependency(knl_session_t *session, uint32 uid, int64 oid, uint32 tid)
{
    knl_cursor_t *cursor = NULL;
    status_t status;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    status = db_delete_from_sysdep(session, cursor, uid, oid, tid);

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t db_drop_synonym(knl_session_t *session, knl_dictionary_t *dc)
{
    rd_synonym_t redo;
    knl_cursor_t *cursor = NULL;
    dc_entry_t *syn_entry = (dc_entry_t *)dc->syn_handle;
    obj_info_t obj_addr;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;

    if (GS_SUCCESS != db_delete_from_syssyn(session, cursor, syn_entry)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_delete_from_sysdep(session, cursor, syn_entry->uid, syn_entry->id, OBJ_TYPE_SYNONYM)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    redo.op_type = RD_DROP_SYNONYM;
    redo.uid = syn_entry->uid;
    redo.id = syn_entry->id;
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_synonym_t), LOG_ENTRY_FLAG_NONE);

    obj_addr.oid = syn_entry->id;
    obj_addr.uid = syn_entry->uid;
    obj_addr.tid = OBJ_TYPE_SYNONYM;
    if (g_knl_callback.update_depender(session, &obj_addr) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    knl_commit(session);

    // Only after transaction committed, can dc be dropped.
    dc_free_broken_entry(session, syn_entry->uid, syn_entry->id);
    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

status_t db_fetch_syssynonym_by_user(knl_session_t *session, uint32 uid, knl_cursor_t *cursor)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SYN_ID, IX_SYS_SYNONYM001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_SYNONYM001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_SYNONYM001_USER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SYNONYM001_SYNONYM_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SYNONYM001_SYNONYM_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        return GS_ERROR;
    }

    return (bool32)(!cursor->eof);
}

status_t db_drop_synonym_by_user(knl_session_t *session, uint32 uid)
{
    knl_cursor_t *cursor = NULL;
    uint32 syn_id;
    object_type_t syn_type;
    object_type_t depend_type;
    text_t syn_name;
    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SYN_ID, IX_SYS_SYNONYM001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_SYNONYM001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_SYNONYM001_USER);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SYNONYM001_SYNONYM_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SYNONYM001_SYNONYM_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        syn_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_OBJID);
        syn_type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SYN_TYPE);
        if (IS_PL_SYN(syn_type)) {
            syn_name.len = (uint32)CURSOR_COLUMN_SIZE(cursor, SYS_SYN_SYNONYM_NAME);
            syn_name.str = (char*)CURSOR_COLUMN_DATA(cursor, SYS_SYN_SYNONYM_NAME);
            if (g_knl_callback.pl_drop_synonym_by_user(session, uid, &syn_name) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        } else {
            depend_type = OBJ_TYPE_SYNONYM;
            if (GS_SUCCESS != db_delete_dependency(session, uid, syn_id, depend_type)) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_delete_from_sys_roles(knl_session_t *session, uint32 rid)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_ROLES_ID, IX_SYS_ROLES_001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&rid, sizeof(rid),
                     IX_COL_SYS_ROLES_001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, (void *)&rid, sizeof(rid),
                     IX_COL_SYS_ROLES_001_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_ROLES_001_NAME);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_ROLES_001_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_analyze_check_sample(double sample_ratio, stats_sample_level_t sample_level)
{
    if (sample_ratio < 0 || sample_ratio > 1) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "sample_ratio");
        return GS_ERROR;
    }

    if (sample_level != BLOCK_SAMPLE && sample_level != ROW_SAMPLE) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "sample level", sample_level);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

bool32 db_check_analyze_wsr_table(text_t *name)
{
    char *str = "WSR";
    text_t wsr_name;
    text_t split_name;

    wsr_name.len = (uint32)strlen(str);
    wsr_name.str = str;

    if (name->len <= wsr_name.len) {
        return GS_FALSE;
    }

    split_name.len = (uint32)strlen(str);
    split_name.str = name->str;

    if (cm_text_equal_ins(&wsr_name, &split_name)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

static status_t db_analyze_check_dc(knl_dictionary_t *dc, text_t *user, text_t *name, bool32 *unsupport_type)
{
    dc_entity_t *entity = DC_ENTITY(dc);

    if (STATS_INVALID_TABLE(entity->type)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "analyze table", dc_type2name(entity->type));
        return GS_ERROR;
    }

    if (SYNONYM_EXIST(dc)) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(user), T2S_EX(name));
        return GS_ERROR;
    }

    if (IS_SYS_DC(dc)) {
        *unsupport_type = GS_TRUE;
        return GS_SUCCESS;
    }

    if (dc->uid == DB_SYS_USER_ID) {
        if (db_check_analyze_wsr_table(name)) {
            *unsupport_type = GS_TRUE;
            return GS_SUCCESS;
        }
    }

    if (entity->stats_locked) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "analyze table", "statistics locked table");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_analyze_table_part(knl_session_t *session, knl_analyze_tab_def_t *def, bool32 is_dynamic)
{
    text_t user = def->owner;
    text_t name = def->name;
    stats_option_t stats_option;
    knl_dictionary_t dc;
    bool32 sys_table = GS_FALSE;
    stats_load_info_t load_info;

    stats_init_stats_option(&stats_option, def);

    if (db_analyze_check_sample(stats_option.sample_ratio, stats_option.sample_level) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_open(session, &user, &name, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_analyze_check_dc(&dc, &user, &name, &sys_table) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (sys_table) {
        dc_close(&dc);
        return GS_SUCCESS;
    }

    table_t *table = DC_TABLE(&dc);
    if (!IS_PART_TABLE(table)) {
        dc_close(&dc);
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "analyze partition", table->desc.name);
        return GS_ERROR;
    }

    if (stats_analyze_single_table_part(session, &dc, def, stats_option, is_dynamic) != GS_SUCCESS) {
        stats_rollback(session, is_dynamic);
        stats_set_analyzed(session, &dc, def->need_analyzed);
        dc_close(&dc);
        return GS_ERROR;
    }

    stats_commit(session, is_dynamic);
    stats_set_analyzed(session, &dc, def->need_analyzed);
    table_part_t *table_part = (table_part_t*)def->table_part;
    stats_disable_table_part_mon(&dc, table_part, def->need_analyzed);
    stats_set_load_info(&load_info, DC_ENTITY(&dc), GS_TRUE, table_part->desc.part_id);

    if (lock_table_shared_directly(session, &dc) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (stats_refresh_dc(session, &dc, load_info) != GS_SUCCESS) {
        unlock_tables_directly(session);
        stats_dc_invalidate(session, &dc);
        dc_close(&dc);
        return GS_ERROR;
    }

    unlock_tables_directly(session);
    dc_close(&dc);
    return GS_SUCCESS;
}

status_t db_analyze_temp_table(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                               bool32 is_dynamic, bool32 *need_invalidate)
{
    bool32 need_lock = !IS_LTT_BY_ID(dc->oid);

    if (need_lock) {
        if (lock_table_shared_directly(session, dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (STATS_MANUAL_SESSION_GTT(dc->type, dc->oid, is_dynamic)) {
        if (knl_begin_auton_rm(session) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (stats_gather_temp_table(session, dc, stats_option, is_dynamic) != GS_SUCCESS) {
        if (STATS_MANUAL_SESSION_GTT(dc->type, dc->oid, is_dynamic)) {
            knl_end_auton_rm(session, GS_ERROR);
        }
        return GS_ERROR;
    }

    stats_disable_table_mon(session, dc, GS_TRUE);
    /*
     * only manual collection stats for session gtt will be saved in system table.
     * And if manual collection stats exists, CBO will only use it for gtt.
     */
    dc_entity_t *entity = DC_ENTITY(dc);
    stats_load_info_t load_info;
    stats_set_load_info(&load_info, entity, GS_TRUE, GS_INVALID_ID32);

    if (STATS_MANUAL_SESSION_GTT(dc->type, dc->oid, is_dynamic)) {
        if (stats_refresh_dc(session, dc, load_info) != GS_SUCCESS) {
            if (need_lock) {
                unlock_tables_directly(session);
            }
            *need_invalidate = GS_TRUE;
            knl_end_auton_rm(session, GS_ERROR);
            return GS_ERROR;
        }

        knl_end_auton_rm(session, GS_SUCCESS);
    }

    if (entity->stat_exists) {
        entity->stats_version++;
    } else {
        entity->stat_exists = GS_TRUE;
        entity->stats_version = 0;
    }

    if (need_lock) {
        unlock_tables_directly(session);
    }

    return GS_SUCCESS;
}

status_t db_analyze_normal_table(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                                 bool32 is_dynamic, bool32 *need_invalidate)
{
    bool32 analyzed = GS_FALSE;
    stats_load_info_t  load_info;

    if (stats_analyze_normal_table(session, dc, stats_option, is_dynamic, &analyzed) != GS_SUCCESS) {
        stats_rollback(session, is_dynamic);
        stats_set_analyzed(session, dc, analyzed);
        return GS_ERROR;
    }

    stats_commit(session, is_dynamic);
    stats_set_analyzed(session, dc, analyzed);
    stats_disable_table_mon(session, dc, analyzed);
    stats_set_load_info(&load_info, DC_ENTITY(dc), GS_TRUE, GS_INVALID_ID32);

    if (lock_table_shared_directly(session, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (stats_refresh_dc(session, dc, load_info) != GS_SUCCESS) {
        stats_rollback(session, is_dynamic);
        unlock_tables_directly(session);
        *need_invalidate = GS_TRUE;
        return GS_ERROR;
    }
    // because we will begin a transaction when locking table,we must call
    // commit or rollback for ending this transaction
    stats_commit(session, is_dynamic);
    unlock_tables_directly(session);
    return GS_SUCCESS;
}

status_t db_analyze_table(knl_session_t *session, knl_analyze_tab_def_t *def, bool32 is_dynamic)
{
    text_t user = def->owner;
    text_t name = def->name;
    stats_option_t stats_option;
    knl_dictionary_t dc;
    bool32 unsupport_type = GS_FALSE;
    bool32 need_invalidate = GS_FALSE;
    status_t status = GS_SUCCESS;

    stats_init_stats_option(&stats_option, def);

    if (db_analyze_check_sample(stats_option.sample_ratio, stats_option.sample_level) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_open(session, &user, &name, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_analyze_check_dc(&dc, &user, &name, &unsupport_type) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (unsupport_type) {
        dc_close(&dc);
        return GS_SUCCESS;
    }

    if (IS_TEMP_TABLE_BY_DC((&dc))) {
        status = db_analyze_temp_table(session, &dc, stats_option, is_dynamic, &need_invalidate);
    } else {
        status = db_analyze_normal_table(session, &dc, stats_option, is_dynamic, &need_invalidate);
    }

    dc_close(&dc);
    if (need_invalidate) {
        stats_dc_invalidate(session, &dc);
    }

    return status;
}

status_t db_analyze_index(knl_session_t *session, knl_analyze_index_def_t *def, bool32 is_dynamic)
{
    text_t user = def->owner;
    text_t idx_name = def->name;
    knl_dictionary_t dc;
    bool32 unsupport_type = GS_FALSE;
    stats_load_info_t load_info;

    if (db_analyze_check_sample(def->sample_ratio, def->sample_level) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (knl_find_dc_by_tmpidx(session, &user, &idx_name)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "analyze index", "temp table's index");
        return GS_ERROR;
    }

    if (knl_open_dc_by_index(session, &user, NULL, &idx_name, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_analyze_check_dc(&dc, &user, &idx_name, &unsupport_type) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (unsupport_type) {
        dc_close(&dc);
        return GS_SUCCESS;
    }

    if (IS_TEMP_TABLE_BY_DC(&dc)) {
        dc_close(&dc);
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "analyze index", "temp table's index");
        return GS_ERROR;
    }

    if (lock_table_shared_directly(session, &dc) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (stats_analyze_index(session, &dc, def, is_dynamic) != GS_SUCCESS) {
        stats_rollback(session, is_dynamic);
        stats_set_analyzed(session, &dc, def->need_analyzed);
        unlock_tables_directly(session);
        dc_close(&dc);
        return GS_ERROR;
    }

    // dynamic statistics use autonomous transaction to commit modification of system table
    stats_commit(session, is_dynamic);
    stats_set_analyzed(session, &dc, def->need_analyzed);
    stats_disable_table_mon(session, &dc, def->need_analyzed);
    stats_set_load_info(&load_info, DC_ENTITY(&dc), GS_TRUE, GS_INVALID_ID32);

    if (stats_refresh_dc(session, &dc, load_info) != GS_SUCCESS) {
        unlock_tables_directly(session);
        stats_dc_invalidate(session, &dc);
        dc_close(&dc);
        return GS_ERROR;
    }

    unlock_tables_directly(session);
    dc_close(&dc);
    return GS_SUCCESS;
}

/*
 * db_delete_table_stats
 *
 * This function is used to delete table-related statistics.
 *
 */
status_t db_delete_table_stats(knl_session_t *session, text_t *ownname, text_t *tabname, text_t *partname)
{
    knl_dictionary_t dc;
    uint32 part_no;
    status_t status;

    if (dc_open(session, ownname, tabname, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (SYNONYM_EXIST(&dc)) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(ownname), T2S_EX(tabname));
        dc_close(&dc);
        return GS_ERROR;
    }

    dc_entity_t *entity = DC_ENTITY(&dc);

    if (STATS_INVALID_TABLE(entity->type)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "delete statistics of ", dc_type2name(entity->type));
        dc_close(&dc);
        return GS_ERROR;
    }

    if (IS_LTT_BY_ID(dc.oid)) {
        dc_close(&dc);
        return GS_SUCCESS;
    }

    if (lock_table_shared_directly(session, &dc) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    if (partname != NULL) {
        if (!IS_PART_TABLE(&entity->table)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "delete partition statistics ", entity->table.desc.name);
            unlock_tables_directly(session);
            dc_close(&dc);
            return GS_ERROR;
        }

        status = knl_find_table_part_by_name(entity, partname, &part_no);

        if (status == GS_SUCCESS) {
            table_part_t *table_part = TABLE_GET_PART(&entity->table, part_no);
            status = stats_delete_part_stats(session, dc.uid, dc.oid, table_part->desc.part_id);
        }
    }  else {
        status = stats_delete_table_stats(session, dc.uid, dc.oid, GS_FALSE);
    }

    if (status == GS_SUCCESS) {
        knl_commit(session);
    } else {
        knl_rollback(session, NULL);
    }

    unlock_tables_directly(session);
    dc_close(&dc);
    return status;
}
/*
 * Determine if current part exists in parts_loc
 */
bool32 is_idx_part_existed(knl_part_locate_t *current_part_loc, knl_parts_locate_t parts_loc, bool32 is_sub)
{
    if (parts_loc.specified_parts == 0) {
        return GS_TRUE;
    }

    if (parts_loc.specified_parts == 1 && parts_loc.part[0].subpart_no == GS_INVALID_ID32) {
        return current_part_loc->part_no == parts_loc.part[0].part_no;
    }

    for (uint32 i = 0; i < parts_loc.specified_parts; i++) {
        if (!is_sub && parts_loc.part[i].part_no != GS_INVALID_ID32 &&
            current_part_loc->part_no == parts_loc.part[i].part_no) {
            return GS_TRUE;
        }

        if (is_sub && parts_loc.part[i].subpart_no != GS_INVALID_ID32 &&
            current_part_loc->part_no == parts_loc.part[i].part_no &&
            current_part_loc->subpart_no == parts_loc.part[i].subpart_no) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

status_t db_fill_shadow_index_parallel(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    knl_part_locate_t part_loc, index_build_mode_t build_mode)
{
    return db_fill_shadow_index(session, cursor, dc, part_loc, build_mode);
}

/*
 * parallel rebuild index from heap or btree, The priorities are as follows
 * 1.active worker for all segments
 * 2.active worker for balance worker load
 */
static status_t db_parallel_rebuild_index(knl_session_t *session, knl_dictionary_t *dc,
    knl_parts_locate_t parts_loc, knl_alindex_def_t *def)
{
    knl_dictionary_t new_dc;
    status_t status;
    index_t *old_index = NULL;
    idx_paral_rebuild_ctx_t *ctx = NULL;
    rebuild_index_def_t *rebuild_def = &def->rebuild;
    uint32 paral_count = rebuild_def->parallelism;
    uint32 split_cnt = (parts_loc.specified_parts == 0) ? MAX_SPLIT_RANGE_CNT : 1;

    if (IS_SYS_DC(dc)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "rebuild index parallel", "system table");
        return GS_ERROR;
    }

    if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc_load_shadow_index(session, &new_dc) != GS_SUCCESS) {
        dc_close_table_private(&new_dc);
        return GS_ERROR;
    }
    old_index = idx_get_index_by_shadow(&new_dc);
    if (old_index->desc.is_func) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "rebuild index parallel", "functional index");
        dc_close_table_private(&new_dc);
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    do {
        paral_count = MIN(paral_count, session->kernel->attr.cpu_count);
        paral_count = MIN(paral_count, GS_MAX_REBUILD_INDEX_PARALLELISM);
        status = idx_alloc_parallel_rebuild_rsc(session, &new_dc, paral_count, &ctx);
        if (status == GS_ERROR) {
            break;
        }

        ctx->current_part = parts_loc.part[0];

        if (idx_is_multi_segments(ctx, parts_loc, rebuild_def)) {
            status = idx_start_rebuild_workers(session, ctx, parts_loc);
        } else {
            status = idx_start_rebuild_worker(session, ctx, split_cnt) ? GS_SUCCESS : GS_ERROR;
        }

        if (status == GS_SUCCESS) {
            status = idx_wait_rebuild_workers(session, ctx);
        }
    }while (0);

    idx_release_parallel_rebuild_rsc(session, ctx, paral_count);
    dc_close_table_private(&new_dc);
    CM_RESTORE_STACK(session->stack);
    GS_LOG_DEBUG_INF("db_rebuild_index_parallel finished, paral_count:%d,cpu_count:%d", paral_count,
        session->kernel->attr.cpu_count);
    return status;
}

static status_t db_rebuild_index(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    knl_part_locate_t part_loc)
{
    knl_dictionary_t new_dc;
    status_t status = GS_SUCCESS;
    errno_t ret;

    if (!IS_SYS_DC(dc)) {
        if (dc_open_table_private(session, dc->uid, dc->oid, &new_dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        ret = memcpy_sp(&new_dc, sizeof(knl_dictionary_t), dc, sizeof(knl_dictionary_t));
        knl_securec_check(ret);
    }

    do {
        if (dc_load_shadow_index(session, &new_dc) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        cursor->action = CURSOR_ACTION_SELECT;
        cursor->scan_mode = SCAN_MODE_TABLE_FULL;
        if (part_loc.part_no == GS_INVALID_ID32) {
            cursor->part_loc.part_no = 0;
            cursor->part_loc.subpart_no = 0;
        } else {
            cursor->part_loc = part_loc;
        }

        if (knl_open_cursor(session, cursor, &new_dc) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

        if (db_fill_shadow_index(session, cursor, &new_dc, part_loc, REBUILD_INDEX) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            status = GS_ERROR;
            break;
        }

        knl_close_cursor(session, cursor);
    } while (0);

    if (!IS_SYS_DC(dc)) {
        dc_close_table_private(&new_dc);
    }

    return status;
}

static status_t db_rebuild_index_online(knl_session_t *session, knl_cursor_t *cursor,
    knl_dictionary_t *dc, knl_part_locate_t part_loc)
{
    dc_entity_t *entity = NULL;
    knl_dictionary_t new_dc;
    errno_t err;

    knl_commit(session);
    dc_invalidate(session, (dc_entity_t *)dc->handle);

    if (knl_open_dc_by_id(session, dc->uid, dc->oid, &new_dc, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* close old version of dc */
    dc_close(dc);
    err = memcpy_sp(dc, sizeof(knl_dictionary_t), &new_dc, sizeof(knl_dictionary_t));
    knl_securec_check(err);

    if (dc_load_shadow_index(session, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    entity = DC_ENTITY(dc);
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->part_loc.part_no = (part_loc.part_no == GS_INVALID_ID32 ? 0 : part_loc.part_no);
    cursor->part_loc.subpart_no = (part_loc.subpart_no == GS_INVALID_ID32 ? 0 : part_loc.subpart_no);
    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cursor->isolevel = (uint8)ISOLATION_CURR_COMMITTED;

    if (tx_begin(session) != GS_SUCCESS) {
        knl_close_cursor(session, cursor);
        return GS_ERROR;
    }

    lock_degrade_table_lock(session, entity);

    if (db_fill_shadow_index(session, cursor, dc, part_loc, REBUILD_INDEX_ONLINE) != GS_SUCCESS) {
        knl_close_cursor(session, cursor);
        return GS_ERROR;
    }

    if (lock_upgrade_table_lock(session, entity) != GS_SUCCESS) {
        knl_close_cursor(session, cursor);
        return GS_ERROR;
    }

    knl_close_cursor(session, cursor);
    return GS_SUCCESS;
}

static status_t db_init_shadow_index(knl_session_t *session, rebuild_index_def_t *def, knl_dictionary_t *dc,
                                     index_t *old_index, index_t *shadow_index)
{
    knl_index_desc_t desc;
    uint32 spc_id;
    text_t idx_name;
    space_t *space = NULL;
    errno_t err;

    if (CM_IS_EMPTY(&def->space) || def->specified_parts > 0) {
        spc_id = old_index->desc.space_id;
    } else {
        if (spc_get_space_id(session, &def->space, &spc_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (spc_check_by_uid(session, &def->space, spc_id, old_index->desc.uid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        space = SPACE_GET(spc_id);
        if (!spc_valid_space_object(session, space->ctrl->id)) {
            GS_THROW_ERROR(ERR_SPACE_HAS_REPLACED, space->ctrl->name, space->ctrl->name);
            return GS_ERROR;
        }
    }

    cm_str2text(old_index->desc.name, &idx_name);

    if (db_fetch_index_desc(session, old_index->desc.uid, &idx_name, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    err = memset_sp(shadow_index, sizeof(index_t), 0, sizeof(index_t));
    knl_securec_check(err);
    desc.slot = old_index->desc.slot;
    desc.space_id = spc_id;
    desc.is_invalid = GS_FALSE;
    desc.entry = INVALID_PAGID;
    desc.cr_mode = (def->cr_mode == GS_INVALID_ID8) ? old_index->desc.cr_mode : def->cr_mode;
    desc.pctfree = (def->pctfree == GS_INVALID_ID32) ? old_index->desc.pctfree : def->pctfree;
    desc.columns_info = old_index->desc.columns_info;
    shadow_index->btree.is_shadow = GS_TRUE;
    shadow_index->btree.index = shadow_index;
    shadow_index->entity = DC_ENTITY(dc);
    shadow_index->part_index = old_index->part_index;

    err = memcpy_sp(&shadow_index->desc, sizeof(knl_index_desc_t), &desc, sizeof(knl_index_desc_t));
    knl_securec_check(err);

    return GS_SUCCESS;
}

status_t db_alter_temp_table_index(knl_session_t *session, table_t *table, index_t *old_index, index_t *index)
{
    knl_cursor_t *cursor = NULL;
    if (!knl_is_temp_table_empty(session, table->desc.uid, table->desc.id)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "rebuild index", "non-empty temporary table");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    if (db_delete_from_sysindex(session, cursor, old_index->desc.uid, old_index->desc.table_id,
                                old_index->desc.id) != GS_SUCCESS) {
        session->rm->is_ddl_op = GS_FALSE;
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_write_sysindex(session, cursor, &index->desc) != GS_SUCCESS) {
        session->rm->is_ddl_op = GS_FALSE;
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    session->rm->is_ddl_op = GS_FALSE;
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static bool32 db_allow_index_rebuild(knl_session_t *session, knl_dictionary_t *dc, index_t *old_index,
    index_t *index, bool32 is_online)
{
    if (IS_SYS_DC(dc)) {
        if (is_online) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "rebuild index online", "system table");
            return GS_FALSE;
        }

        if (index->desc.space_id != old_index->desc.space_id || index->desc.cr_mode != old_index->desc.cr_mode) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify index properties", "system index");
            return GS_FALSE;
        }
    }

    space_t *dest_space = SPACE_GET(index->desc.space_id);
    space_t *old_space = SPACE_GET(old_index->desc.space_id);
    if (SPACE_IS_LOGGING(dest_space) != SPACE_IS_LOGGING(old_space) ||
        SPACE_IS_NOLOGGING(dest_space) != SPACE_IS_NOLOGGING(old_space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify index properties",
            "index rebuild in different type space");
        return GS_FALSE;
    }

    if ((IS_SWAP_SPACE(old_space) && !IS_SWAP_SPACE(dest_space)) ||
        (!IS_SWAP_SPACE(old_space) && IS_SWAP_SPACE(dest_space))) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify index properties",
            "index rebuild in different type space");
        return GS_FALSE;
    }

    if (IS_UNDO_SPACE(dest_space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify index properties",
            "index rebuild in undo space");
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t db_delete_remain_shadow_index(knl_session_t *session, knl_dictionary_t *dc)
{
    if (((dc_entity_t *)dc->handle)->valid) {
        if (lock_upgrade_table_lock(session, dc->handle) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_drop_shadow_index(session, dc->uid, dc->oid, GS_TRUE) != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        return GS_ERROR;
    }

    knl_end_auton_rm(session, GS_SUCCESS);

    return GS_SUCCESS;
}

static bool32 db_get_index_part(knl_alindex_def_t *def, index_t *index, index_part_t **old_part, uint32 part_index)
{
    index_part_t *index_subpart = NULL;

    if (!IS_PART_INDEX(index)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ": index is not part index");
        return GS_FALSE;
    }

    if (!part_index_find_by_name(index->part_index, &def->rebuild.part_name[part_index], old_part)) {
        if (!subpart_index_find_by_name(index->part_index, &def->rebuild.part_name[part_index], &index_subpart)) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->rebuild.part_name[part_index]));
            return GS_FALSE;
        }

        *old_part = index_subpart;
    }

    if (def->type == ALINDEX_TYPE_REBUILD_PART && IS_SUB_IDXPART(&(*old_part)->desc)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->rebuild.part_name[part_index]));
        return GS_FALSE;
    }

    if (def->type == ALINDEX_TYPE_REBUILD_SUBPART && !IS_SUB_IDXPART(&(*old_part)->desc)) {
        if (!IS_COMPART_INDEX(index->part_index)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "rebuild one sub index partition on one non-subpartitioned index");
            return GS_FALSE;
        }

        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->rebuild.part_name[part_index]));
        return GS_FALSE;
    }

    return GS_TRUE;
}

static void db_rebuild_init_parts_loc(knl_parts_locate_t *parts_loc, knl_alindex_def_t *def)
{
    rebuild_index_def_t *rebuild_def = &def->rebuild;

    for (uint32 i = 0; i < MAX_REBUILD_PARTS; i++) {
        parts_loc->part[i].part_no = GS_INVALID_ID32;
        parts_loc->part[i].subpart_no = GS_INVALID_ID32;
    }

    parts_loc->specified_parts = rebuild_def->specified_parts;
}

static void db_parts_loc_asc_sort(knl_alindex_def_t *def, knl_parts_locate_t *parts_loc)
{
    knl_part_locate_t temp_part_loc;

    for (uint32 i = 0; i < def->rebuild.specified_parts; i++) {
        for (uint32 j = i + 1; j < def->rebuild.specified_parts; j++) {
            if (parts_loc->part[i].part_no > parts_loc->part[j].part_no ||
                (parts_loc->part[i].part_no == parts_loc->part[j].part_no && 
                parts_loc->part[i].subpart_no > parts_loc->part[j].subpart_no)) {
                temp_part_loc = parts_loc->part[i];
                parts_loc->part[i] = parts_loc->part[j];
                parts_loc->part[j] = temp_part_loc;
            }
        }
    }
}

static status_t db_get_index_parts_loc(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *index, rebuild_info_t* rebuild_info)
{
    index_part_t *old_part = NULL;
    index_part_t *compart = NULL;
    rebuild_index_def_t *rebuild_def = &def->rebuild;

    db_rebuild_init_parts_loc(&rebuild_info->parts_loc, def);

    if (!rebuild_def->specified_parts) {
        return GS_SUCCESS;
    }

    if (db_alter_indexpart_rebuild_verify(session, def, &rebuild_info->spc_id, index, 0) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < def->rebuild.specified_parts; i++) {
        if (!db_get_index_part(def, index, &old_part, i)) {
            return GS_ERROR;
        }

        if (!IS_PARENT_IDXPART(&old_part->desc)) {
            if (IS_SUB_IDXPART(&old_part->desc)) {
                compart = subpart_get_parent_idxpart(index, old_part->desc.parent_partid);
                knl_panic_log(compart != NULL, "the index_compart is NULL, panic info: index name %s parent part name %s",
                              index->desc.name, old_part->desc.name);
                rebuild_info->parts_loc.part[i].part_no = compart->part_no;
                rebuild_info->parts_loc.part[i].subpart_no = old_part->part_no;
            } else {
                rebuild_info->parts_loc.part[i].part_no = old_part->part_no;
                rebuild_info->parts_loc.part[i].subpart_no = GS_INVALID_ID32;
            }
        } else {
            rebuild_info->parts_loc.part[i].part_no = old_part->part_no;
            rebuild_info->parts_loc.part[i].subpart_no = GS_INVALID_ID32;

            if (rebuild_def->specified_parts > 1) {
                GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "rebuild multiple parent partition indexes");
                return GS_ERROR;
            }
        }
    }

    db_parts_loc_asc_sort(def, &rebuild_info->parts_loc);

    return GS_SUCCESS;
}

static status_t db_alter_index_rebuild_verify(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *old_index, index_t *index)
{
    rebuild_index_def_t *rebuild_def = &def->rebuild;
    table_t *table = DC_TABLE(dc);

    knl_panic_log(old_index != NULL, "invalid index:%s of table:%s", T2S_EX(&def->name), table->desc.name);

    if (db_init_shadow_index(session, rebuild_def, dc, old_index, index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!db_allow_index_rebuild(session, dc, old_index, index, rebuild_def->is_online)) {
        return GS_ERROR;
    }

    if (table->desc.type == TABLE_TYPE_TRANS_TEMP || table->desc.type == TABLE_TYPE_SESSION_TEMP) {
        if (rebuild_def->is_online) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "rebuild index online", "temporary table");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_alter_index_rebuild(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *old_index)
{
    index_t index;
    status_t status;
    rebuild_info_t rebuild_info;
    table_t *table = DC_TABLE(dc);

    if (db_alter_index_rebuild_verify(session, def, dc, old_index, &index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (table->desc.type == TABLE_TYPE_TRANS_TEMP || table->desc.type == TABLE_TYPE_SESSION_TEMP) {
        return db_alter_temp_table_index(session, table, old_index, &index);
    }

    rebuild_info.is_alter = GS_TRUE;
    rebuild_info.spc_id = index.desc.space_id;
    rebuild_info.alter_index_type = def->type;
    if (db_get_index_parts_loc(session, def, dc, old_index, &rebuild_info) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (CM_IS_EMPTY(&def->rebuild.space)) {
        rebuild_info.spc_id = GS_INVALID_ID32;
    }

    if (db_create_shadow_index(session, dc, &index, NULL, rebuild_info) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    uint32 part_index = 0;
    do {
        if (def->rebuild.is_online) {
            status = db_rebuild_index_online(session, cursor, dc, rebuild_info.parts_loc.part[part_index]);
        } else if (def->rebuild.parallelism == 0) {
            status = db_rebuild_index(session, cursor, dc, rebuild_info.parts_loc.part[part_index]);
        } else {
            status = db_parallel_rebuild_index(session, dc, rebuild_info.parts_loc, def);
            break;
        }
        part_index++;
    } while (status == GS_SUCCESS && part_index < def->rebuild.specified_parts);
    
    table = DC_TABLE(dc);
    if (status == GS_SUCCESS) {
        status = db_switch_shadow_index(session, cursor, table, &index, rebuild_info.parts_loc);
    }

    CM_RESTORE_STACK(session->stack);

    if (status != GS_SUCCESS) {
        if (def->rebuild.is_online) {
            knl_rollback(session, NULL);

            /*
             * in case session is killed, maybe there is no chance to clean shadow index,
             * we mark it as invalid, as a result, concurrency DML need not to mantain shadow index any more.
             */
            dc_invalidate_shadow_index(dc->handle);

            if (db_delete_remain_shadow_index(session, dc) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return status;
}

static status_t db_clean_shwidx_subpart(knl_session_t *session, index_part_t *subpart, bool32 clean_segment)
{
    index_part_t part;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SHADOW_INDEXPART_ID, IX_SYS_SHW_INDEXPART001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        &subpart->desc.uid, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        &subpart->desc.table_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        &subpart->desc.index_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        &subpart->desc.part_id, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
        &subpart->desc.parent_partid, sizeof(uint32), IX_COL_SYS_SHW_INDEXPART001_PARENTPART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    errno_t ret = memset_sp(&part, sizeof(index_part_t), 0, sizeof(index_part_t));
    knl_securec_check(ret);

    dc_convert_index_part_desc(cursor, &part.desc);
    part.desc.subpart_cnt = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SHADOW_INDEXPART_COL_SUBPART_CNT);

    if (clean_segment && spc_valid_space_object(session, part.desc.space_id) && !IS_INVALID_PAGID(part.desc.entry)) {
        btree_drop_part_segment(session, &part);
    }

    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_create_shadow_indexpart(knl_session_t *session, knl_cursor_t *cursor, index_part_t *shadow_part)
{
    row_assist_t ra;
    knl_index_part_desc_t *desc = &shadow_part->desc;
    space_t *space = SPACE_GET(desc->space_id);

    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "write to shadow_indexpart$ failed");
        return GS_ERROR;
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_SUB_IDXPART(&shadow_part->desc)) {
        if (db_clean_shwidx_subpart(session, shadow_part, !SPACE_IS_NOLOGGING(space)) != GS_SUCCESS) {
            knl_end_auton_rm(session, GS_ERROR);
            return GS_ERROR;
        }

        if (db_drop_shadow_index(session, desc->uid, desc->table_id, !SPACE_IS_NOLOGGING(space)) != GS_SUCCESS) {
            knl_end_auton_rm(session, GS_ERROR);
            return GS_ERROR;
        }
    } else {
        if (db_clean_shadow_index(session, desc->uid, desc->table_id, !SPACE_IS_NOLOGGING(space)) != GS_SUCCESS) {
            knl_end_auton_rm(session, GS_ERROR);
            return GS_ERROR;
        }
    }

    knl_end_auton_rm(session, GS_SUCCESS);

    if (btree_create_part_segment(session, shadow_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SHADOW_INDEXPART_ID, GS_INVALID_ID32);
    table_t *table = (table_t *)cursor->table;

    row_init(&ra, cursor->buf, HEAP_MAX_ROW_SIZE, table->desc.column_count);

    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->table_id);
    (void)row_put_int32(&ra, desc->index_id);
    (void)row_put_int32(&ra, desc->part_id);
    (void)row_put_str(&ra, desc->name);
    (void)row_put_int32(&ra, desc->hiboundval.len);
    (void)row_put_text(&ra, &desc->hiboundval);
    (void)row_put_int32(&ra, desc->space_id);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int64(&ra, *(int64 *)&desc->entry);
    (void)row_put_int32(&ra, desc->initrans);
    (void)row_put_int32(&ra, desc->pctfree);
    (void)row_put_int32(&ra, desc->flags);
    (void)row_put_bin(&ra, &desc->bhiboundval);
    (void)row_put_int32(&ra, desc->subpart_cnt);
    return knl_internal_insert(session, cursor);
}

static bool32 db_rebuild_get_part(knl_alindex_def_t *def, index_t *index, index_part_t **old_part, int part_i)
{
    index_part_t *index_subpart = NULL;

    if (!IS_PART_INDEX(index)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ": index is not part index");
        return GS_FALSE;
    }

    if (!part_index_find_by_name(index->part_index, &def->rebuild.part_name[part_i], old_part)) {
        if (!subpart_index_find_by_name(index->part_index, &def->rebuild.part_name[part_i], &index_subpart)) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->rebuild.part_name[part_i]));
            return GS_FALSE;
        }

        *old_part = index_subpart;
    }

    if (def->type == ALINDEX_TYPE_REBUILD_PART && IS_SUB_IDXPART(&(*old_part)->desc)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->rebuild.part_name[part_i]));
        return GS_FALSE;
    }

    if (def->type == ALINDEX_TYPE_REBUILD_SUBPART && !IS_SUB_IDXPART(&(*old_part)->desc)) {
        if (!IS_COMPART_INDEX(index->part_index)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "rebuild one sub index partition on one non-subpartitioned index");
            return GS_FALSE;
        }

        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->rebuild.part_name[part_i]));
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t db_delete_remain_shadow_indexpart(knl_session_t *session, knl_cursor_t *cursor,
    knl_dictionary_t *dc, index_t *index, index_part_t *new_part)
{
    if (((dc_entity_t *)dc->handle)->valid) {
        if (lock_upgrade_table_lock(session, dc->handle) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (knl_begin_auton_rm(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_delete_from_shadow_sysindexpart(session, cursor, index->desc.uid, index->desc.table_id,
        index->desc.id) != GS_SUCCESS) {
        knl_end_auton_rm(session, GS_ERROR);
        return GS_ERROR;
    }

    btree_drop_part_segment(session, new_part);

    knl_end_auton_rm(session, GS_SUCCESS);

    return GS_SUCCESS;
}

static status_t db_rebuild_index_part_entity(knl_session_t *session, knl_dictionary_t *dc, index_t *index,
    index_part_t *shadow_part, knl_part_locate_t part_loc, knl_alindex_def_t *def)
{
    status_t status;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_parts_locate_t parts_loc;

    if (db_create_shadow_indexpart(session, cursor, shadow_part) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    index_part_t *old_compart = INDEX_GET_PART(index, part_loc.part_no);
    index_part_t *old_part = (part_loc.subpart_no != GS_INVALID_ID32) ?
        PART_GET_SUBENTITY(index->part_index, old_compart->subparts[part_loc.subpart_no]) : old_compart;

    db_rebuild_init_parts_loc(&parts_loc, def);

    parts_loc.part[0] = part_loc;
    uint32 index_id = index->desc.id;
    for (;;) {
        if (def->rebuild.is_online) {
            status = db_rebuild_index_online(session, cursor, dc, part_loc);
        } else {
            status = db_rebuild_index(session, cursor, dc, part_loc);
        }

        index = dc_find_index_by_id((dc_entity_t *)dc->handle, index_id);
        if (index == NULL) {
            GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "index", index_id);
            status = GS_ERROR;
            break;
        }
        old_compart = INDEX_GET_PART(index, part_loc.part_no);
        old_part = (part_loc.subpart_no != GS_INVALID_ID32) ?
            PART_GET_SUBENTITY(index->part_index, old_compart->subparts[part_loc.subpart_no]) : old_compart;

        if (status != GS_SUCCESS) {
            break;
        }

        if (db_switch_shadow_indexparts(session, cursor, index) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        status = btree_part_segment_prepare(session, old_part, GS_FALSE, BTREE_DROP_PART_SEGMENT);
        break;
    }

    if (status != GS_SUCCESS) {
        if (def->rebuild.is_online) {
            knl_rollback(session, NULL);
            dc_invalidate_shadow_index(dc->handle);
            (void)db_delete_remain_shadow_indexpart(session, cursor, dc, index, shadow_part);
        }
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

static void db_init_new_part_desc(index_part_t *new_part, index_part_t *old_part, uint32 spc_id)
{
    errno_t err = memset_sp(new_part, sizeof(index_part_t), 0, sizeof(index_part_t));
    knl_securec_check(err);
    err = memcpy_sp(&new_part->desc, sizeof(knl_index_part_desc_t), &old_part->desc, sizeof(knl_index_part_desc_t));
    knl_securec_check(err);
    if (spc_id != GS_INVALID_ID32) {
        new_part->desc.space_id = spc_id;
        new_part->desc.is_stored = GS_TRUE;
    }
    new_part->desc.is_invalid = GS_FALSE;
}

status_t db_allow_indexpart_rebuild(knl_session_t *session, uint32 spc_id,
    index_part_t *old_part)
{
    space_t *space = SPACE_GET(spc_id);
    space_t *old_space = SPACE_GET(old_part->desc.space_id);

    if (!part_check_index_encrypt_allowed(session, old_part->desc.space_id, space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "rebuild part index", "cases: rebuild encrypt part index on \
non-encrypt part table or rebuild non-encrypt part index on encrypt part table.");
        return GS_ERROR;
    }

    if (SPACE_IS_LOGGING(space) != SPACE_IS_LOGGING(old_space) ||
        SPACE_IS_NOLOGGING(space) != SPACE_IS_NOLOGGING(old_space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify part index properties",
                       "part index rebuild in different type space");
        return GS_ERROR;
    }

    if ((IS_SWAP_SPACE(space) && !IS_SWAP_SPACE(old_space)) ||
        (!IS_SWAP_SPACE(space) && IS_SWAP_SPACE(old_space))) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify part index properties",
            "part index rebuild in different type space");
        return GS_ERROR;
    }

    if (IS_UNDO_SPACE(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify part index properties", "part index rebuild in undo space");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_alter_indexpart_rebuild_verify(knl_session_t *session, knl_alindex_def_t *def, uint32 *spc_id,
    index_t *index, int32 index_i)
{
    index_part_t *old_part = NULL;
    rebuild_index_def_t *rebuild = &def->rebuild;

    if (!db_get_index_part(def, index, &old_part, index_i)) {
        return GS_ERROR;
    }

    if (CM_IS_EMPTY(&rebuild->space)) {
        *spc_id = old_part->desc.space_id;
    } else {
        if (spc_get_space_id(session, &rebuild->space, spc_id) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (spc_check_by_uid(session, &rebuild->space, *spc_id, old_part->desc.uid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return db_allow_indexpart_rebuild(session, *spc_id, old_part);
}


status_t db_alter_index_rebuild_part(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *index)
{
    uint32 spc_id;
    index_part_t new_part;
    knl_part_locate_t part_loc;
    index_part_t *old_part = NULL;

    if (db_alter_indexpart_rebuild_verify(session, def, &spc_id, index, 0) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!db_rebuild_get_part(def, index, &old_part, 0)) {
        return GS_ERROR;
    }

    if (CM_IS_EMPTY(&def->rebuild.space)) {
        spc_id = GS_INVALID_ID32;
    }

    if (!IS_PARENT_IDXPART(&old_part->desc)) {
        if (IS_SUB_IDXPART(&old_part->desc)) {
            index_part_t *compart = subpart_get_parent_idxpart(index, old_part->desc.parent_partid);
            knl_panic_log(compart != NULL, "the index_compart is NULL, panic info: index name %s parent part name %s",
                          index->desc.name, old_part->desc.name);
            part_loc.part_no = compart->part_no;
            part_loc.subpart_no = old_part->part_no;
        } else {
            part_loc.part_no = old_part->part_no;
            part_loc.subpart_no = GS_INVALID_ID32;
        }

        db_init_new_part_desc(&new_part, old_part, spc_id);
        return db_rebuild_index_part_entity(session, dc, index, &new_part, part_loc, def);
    } else {
        part_loc.part_no = old_part->part_no;
        index_part_t *subpart = NULL;
        for (uint32 i = 0; i < old_part->desc.subpart_cnt; i++) {
            part_loc.subpart_no = i;
            subpart = PART_GET_SUBENTITY(index->part_index, old_part->subparts[i]);
            if (subpart == NULL) {
                continue;
            }

            db_init_new_part_desc(&new_part, subpart, spc_id);
            if (db_rebuild_index_part_entity(session, dc, index, &new_part, part_loc,
                def) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (spc_id != GS_INVALID_ID32) {
            old_part->desc.is_stored = GS_TRUE;
            return db_update_index_part_space(session, &old_part->desc, spc_id);
        }
    }

    return GS_SUCCESS;
}

static status_t db_alter_compart_index_coalesce(knl_session_t *session, knl_handle_t entity, index_t *index,
    index_part_t *compart, knl_part_locate_t *part_loc)
{
    idx_recycle_stats_t stats = { 0 };
    index_part_t *subpart = NULL;

    for (uint32 i = 0; i < compart->desc.subpart_cnt; i++) {
        part_loc->subpart_no = i;
        subpart = PART_GET_SUBENTITY(index->part_index, compart->subparts[i]);
        if (subpart == NULL) {
            continue;
        }

        if (subpart->btree.segment == NULL && !IS_INVALID_PAGID(subpart->btree.entry)) {
            if (dc_load_index_part_segment(session, entity, (index_part_t *)subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (subpart->btree.segment == NULL) {
            return GS_SUCCESS;
        }

        if (btree_coalesce(session, &subpart->btree, &stats, *part_loc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_alter_part_index_coalesce(knl_session_t *session, knl_dictionary_t *dc, knl_alindex_def_t *def,
    index_t *index)
{
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    idx_recycle_stats_t stats = { 0 };

    table_t *table = DC_TABLE(dc);
    if (!IS_PART_TABLE(table) || !IS_PART_INDEX(index)) {
        GS_THROW_ERROR(ERR_MODIFY_PART_INDEX);
        return GS_ERROR;
    }

    if (!part_index_find_by_name(index->part_index, &def->mod_idxpart.part_name, &index_part)) {
        if (!subpart_index_find_by_name(index->part_index, &def->mod_idxpart.part_name, &index_subpart)) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->mod_idxpart.part_name));
            return GS_ERROR;
        }

        index_part = index_subpart;
    }

    if (IS_SUB_IDXPART(&index_part->desc)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S_EX(&def->mod_idxpart.part_name));
        return GS_ERROR;
    }

    knl_part_locate_t part_loc;
    part_loc.part_no = index_part->part_no;
    if (!IS_PARENT_IDXPART(&index_part->desc)) {
        knl_panic_log(!IS_PARENT_IDXPART(&index_part->desc),
            "the index_part is parent_idxpart, panic info: table %s index %s", table->desc.name, index->desc.name);
        part_loc.subpart_no = GS_INVALID_ID32;
        if (index_part->btree.segment == NULL && !IS_INVALID_PAGID(index_part->btree.entry)) {
            if (dc_load_index_part_segment(session, dc->handle, index_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (index_part->btree.segment == NULL) {
            return GS_SUCCESS;
        }

        return btree_coalesce(session, &index_part->btree, &stats, part_loc);
    }

    return db_alter_compart_index_coalesce(session, dc->handle, index, index_part, &part_loc);
}

status_t db_alter_subpart_index_coalesce(knl_session_t *session, knl_dictionary_t *dc, knl_alindex_def_t *def,
    index_t *index)
{
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    idx_recycle_stats_t stats = { 0 };
    table_t *table = DC_TABLE(dc);

    if (!IS_PART_TABLE(table) || !IS_COMPART_TABLE(table->part_table) || !IS_PART_INDEX(index)) {
        GS_THROW_ERROR(ERR_MODIFY_PART_INDEX);
        return GS_ERROR;
    }

    if (!part_index_find_by_name(index->part_index, &def->mod_idxpart.part_name, &index_part)) {
        if (!subpart_index_find_by_name(index->part_index, &def->mod_idxpart.part_name, &index_subpart)) {
            GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->mod_idxpart.part_name));
            return GS_ERROR;
        }

        index_part = index_subpart;
    }

    if (!IS_SUB_IDXPART(&index_part->desc)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S_EX(&def->mod_idxpart.part_name));
        return GS_ERROR;
    }

    knl_part_locate_t part_loc;
    index_part_t *index_compart = subpart_get_parent_idxpart(index, index_part->desc.parent_partid);
    knl_panic_log(index_compart != NULL, "index_compart is NULL, panic info: table %s index %s", table->desc.name,
                  index->desc.name);
    part_loc.part_no = index_compart->part_no;
    part_loc.subpart_no = index_part->part_no;

    if (index_part->btree.segment == NULL && !IS_INVALID_PAGID(index_part->btree.entry)) {
        if (dc_load_index_part_segment(session, dc->handle, index_part) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (index_part->btree.segment == NULL) {
        return GS_SUCCESS;
    }

    return btree_coalesce(session, &index_part->btree, &stats, part_loc);
}


status_t db_alter_index_coalesce(knl_session_t *session, knl_dictionary_t *dc, index_t *index)
{
    idx_recycle_stats_t stats = { 0 };

    if (IS_PART_INDEX(index)) {
        GS_THROW_ERROR(ERR_PART_INDEX_COALESCE);
        return GS_ERROR;
    }

    if (index->btree.segment == NULL) {
        return GS_SUCCESS;
    }

    knl_part_locate_t part_loc;
    part_loc.part_no = GS_INVALID_ID32;
    part_loc.subpart_no = GS_INVALID_ID32;
    return btree_coalesce(session, &index->btree, &stats, part_loc);
}

status_t heap_segment_prepare(knl_session_t *session, table_t *table, bool32 reuse, seg_op_t op_type)
{
    knl_seg_desc_t seg;
    space_t *space = SPACE_GET(table->desc.space_id);

    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(table->heap.entry)) {
        return GS_SUCCESS;
    }

    seg.uid = table->desc.uid;
    seg.oid = table->desc.id;
    seg.index_id = GS_INVALID_ID32;
    seg.column_id = GS_INVALID_ID32;
    seg.space_id = table->desc.space_id;
    seg.entry = table->heap.entry;
    seg.org_scn = table->desc.org_scn;
    seg.seg_scn = table->desc.seg_scn;
    seg.initrans = table->desc.initrans;
    seg.pctfree = table->desc.pctfree;
    seg.op_type = op_type;
    seg.reuse = reuse;
    seg.serial = table->desc.serial_start;

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t heap_part_segment_prepare(knl_session_t *session, table_part_t *table_part, bool32 reuse,
                                   seg_op_t op_type)
{
    knl_seg_desc_t seg;
    space_t *space = SPACE_GET(table_part->desc.space_id);

    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(table_part->heap.entry)) {
        return GS_SUCCESS;
    }

    seg.uid = table_part->desc.uid;
    seg.oid = table_part->desc.table_id;
    seg.index_id = GS_INVALID_ID32;
    seg.column_id = GS_INVALID_ID32;
    seg.space_id = table_part->desc.space_id;
    seg.entry = table_part->heap.entry;
    seg.org_scn = table_part->desc.org_scn;
    seg.seg_scn = table_part->desc.seg_scn;
    seg.initrans = table_part->desc.initrans;
    seg.pctfree = table_part->desc.pctfree;
    seg.op_type = op_type;
    seg.reuse = reuse;
    seg.serial = GS_INVALID_INT64;

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t btree_segment_prepare(knl_session_t *session, index_t *index, bool32 reuse, seg_op_t op_type)
{
    knl_seg_desc_t seg;
    space_t *space = SPACE_GET(index->desc.space_id);

    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(index->btree.entry)) {
        return GS_SUCCESS;
    }

    seg.uid = index->desc.uid;
    seg.oid = index->desc.table_id;
    seg.index_id = index->desc.id;
    seg.column_id = GS_INVALID_ID32;
    seg.space_id = index->desc.space_id;
    seg.entry = index->btree.entry;
    seg.org_scn = index->desc.org_scn;
    seg.seg_scn = index->desc.seg_scn;
    seg.initrans = index->desc.initrans;
    seg.pctfree = GS_INVALID_ID32;
    seg.op_type = op_type;
    seg.reuse = reuse;
    seg.serial = GS_INVALID_INT64;

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t btree_part_segment_prepare(knl_session_t *session, index_part_t *index_part, bool32 reuse,
                                    seg_op_t op_type)
{
    knl_seg_desc_t seg;
    space_t *space = SPACE_GET(index_part->desc.space_id);

    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(index_part->btree.entry)) {
        return GS_SUCCESS;
    }

    seg.uid = index_part->desc.uid;
    seg.oid = index_part->desc.table_id;
    seg.index_id = index_part->desc.index_id;
    seg.column_id = GS_INVALID_ID32;
    seg.space_id = index_part->desc.space_id;
    seg.entry = index_part->btree.entry;
    seg.org_scn = index_part->desc.org_scn;
    seg.seg_scn = index_part->desc.seg_scn;
    seg.initrans = index_part->desc.initrans;
    seg.pctfree = GS_INVALID_ID32;
    seg.op_type = op_type;
    seg.reuse = reuse;
    seg.serial = GS_INVALID_INT64;

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t lob_segment_prepare(knl_session_t *session, lob_t *lob, bool32 reuse, seg_op_t op_type)
{
    knl_seg_desc_t seg;
    space_t *space = SPACE_GET(lob->desc.space_id);

    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(lob->lob_entity.entry)) {
        return GS_SUCCESS;
    }

    seg.uid = lob->desc.uid;
    seg.oid = lob->desc.table_id;
    seg.index_id = GS_INVALID_ID32;
    seg.column_id = lob->desc.column_id;
    seg.space_id = lob->desc.space_id;
    seg.entry = lob->lob_entity.entry;
    seg.org_scn = lob->desc.org_scn;
    seg.seg_scn = lob->desc.seg_scn;
    seg.initrans = GS_INVALID_ID32;
    seg.pctfree = GS_INVALID_ID32;
    seg.op_type = op_type;
    seg.reuse = reuse;
    seg.serial = GS_INVALID_INT64;

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t lob_part_segment_prepare(knl_session_t *session, lob_part_t *lob_part, bool32 reuse, seg_op_t op_type)
{
    knl_seg_desc_t seg;
    space_t *space = SPACE_GET(lob_part->desc.space_id);

    if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
        return GS_SUCCESS;
    }

    if (IS_INVALID_PAGID(lob_part->lob_entity.entry)) {
        return GS_SUCCESS;
    }

    seg.uid = lob_part->desc.uid;
    seg.oid = lob_part->desc.table_id;
    seg.index_id = GS_INVALID_ID32;
    seg.column_id = lob_part->desc.column_id;
    seg.space_id = lob_part->desc.space_id;
    seg.entry = lob_part->lob_entity.entry;
    seg.org_scn = lob_part->desc.org_scn;
    seg.seg_scn = lob_part->desc.seg_scn;
    seg.initrans = GS_INVALID_ID32;
    seg.pctfree = GS_INVALID_ID32;
    seg.op_type = op_type;
    seg.reuse = reuse;
    seg.serial = GS_INVALID_INT64;

    if (db_write_garbage_segment(session, &seg) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_update_table_increment_start(knl_session_t *session, knl_table_desc_t *desc, int64 serial_start)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_INTEGER, (void *)&desc->uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // object name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, GS_TYPE_STRING, (void *)desc->name, (uint16)strlen(desc->name),
                     IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
    (void)row_put_int64(&ra, db_inc_scn(session));
    (void)row_put_int64(&ra, serial_start);

    cursor->update_info.count = 2;
    cursor->update_info.columns[0] = SYS_TABLE_COL_CHG_SCN;                    // table chg scn
    cursor->update_info.columns[1] = SYS_TABLE_SERIAL_START;  // SERIAL_START
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

static status_t db_update_systrig_set_status(knl_session_t *session, knl_dictionary_t *dc, bool32 enable)
{
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    row_assist_t ra;
    knl_update_info_t *ui = NULL;
    knl_cursor_t *cursor = NULL;
    status_t status = GS_ERROR;
    uint32 table_uid = entity->table.desc.uid;
    uint64 table_oid = entity->table.desc.id;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TRIGGER_ID, IX_SYS_TRIGGERS_002_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table_uid,
        (uint16)sizeof(table_uid), IX_SYS_TRIGGERS_002_ID_OBJUID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table_uid,
        (uint16)sizeof(table_uid), IX_SYS_TRIGGERS_002_ID_OBJUID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_BIGINT, &table_oid,
        (uint16)sizeof(table_oid), IX_SYS_TRIGGERS_002_ID_BASEOBJ);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_BIGINT, &table_oid,
        (uint16)sizeof(table_oid), IX_SYS_TRIGGERS_002_ID_BASEOBJ);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_SYS_TRIGGER_002_ID_OBJ);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_SYS_TRIGGER_002_ID_OBJ);

    for (;;) {
        GS_BREAK_IF_ERROR(knl_fetch(session, cursor));

        if (cursor->eof) {
            status = GS_SUCCESS;
            break;
        }

        ui = &cursor->update_info;
        row_init(&ra, ui->data, GS_MAX_ROW_SIZE, 1);
        (void)row_put_int32(&ra, enable);
        ui->count = 1;
        ui->columns[0] = SYS_TRIGGER_COL_ENABLE;
        cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);
        GS_BREAK_IF_ERROR(knl_internal_update(session, cursor));
        status = GS_SUCCESS;
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t db_update_sysproc_set_trig(knl_session_t *session, knl_dictionary_t *dc, bool32 enable)
{
    dc_entity_t *entity = (dc_entity_t *)dc->handle;
    row_assist_t ra;
    knl_update_info_t *ui = NULL;
    knl_cursor_t *cursor = NULL;
    status_t status = GS_ERROR;
    text_t user;

    if (knl_get_user_name(session, entity->table.desc.uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_PROC_ID, IX_PROC_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    // table name len is not greater 68
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, entity->table.desc.name,
        (uint16)strlen(entity->table.desc.name), IX_COL_PROC_002_TRIG_TABLE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, user.str, (uint16)user.len,
        IX_COL_PROC_002_TRIG_TABLE_USER);

    for (;;) {
        GS_BREAK_IF_ERROR(knl_fetch(session, cursor));

        if (cursor->eof) {
            status = GS_SUCCESS;
            break;
        }

        ui = &cursor->update_info;
        row_init(&ra, ui->data, GS_MAX_ROW_SIZE, 1);
        if (enable) {
            (void)row_put_str(&ra, "ENABLED");
        } else {
            (void)row_put_str(&ra, "DISABLED");
        }
        
        ui->count = 1;
        ui->columns[0] = SYS_PROC_TRIG_STATUS_COL;
        cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);
        GS_BREAK_IF_ERROR(knl_internal_update(session, cursor));
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t db_altable_set_all_trig_status(knl_session_t *session, knl_dictionary_t *dc, bool32 enable)
{
    if (db_update_systrig_set_status(session, dc, enable) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_sysproc_set_trig(session, dc, enable) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_write_instance_info(knl_session_t *session, knl_cursor_t *cursor)
{
    table_t *table = NULL;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_INSTANCE_INFO_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    char name[] = "NOLOGOBJECT_CNT";
    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE, table->desc.column_count);
    (void)row_put_str(&ra, name);
    (void)row_put_int64(&ra, 1);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_update_nologobj_cnt(knl_session_t *session, bool32 is_add)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INSTANCE_INFO_ID, IX_SYS_INSTANCE_INFO_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    char name[] = "NOLOGOBJECT_CNT";
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, name, (uint16)strlen(name),
        IX_COL_SYS_INSTANCE_INFO_001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        if (db_write_instance_info(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    row_assist_t ra;
    uint64 nolog_cnt = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_INSTANCE_INFO_COL_VALUE);
    if (is_add) {
        nolog_cnt++;
    } else {
        nolog_cnt--;
    }
    
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, UPDATE_COLUMN_COUNT_ONE);
    (void)row_put_int64(&ra, (int64)nolog_cnt);
    cursor->update_info.count = UPDATE_COLUMN_COUNT_ONE;
    cursor->update_info.columns[0] = SYS_INSTANCE_INFO_COL_VALUE;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_enable_nologging_precheck(knl_session_t *session, knl_dictionary_t *dc)
{
    if (DB_IS_RCY_CHECK_PCN(session)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set nologging attribute when _RCY_CHECK_PCN is TRUE");
        return GS_ERROR;
    }

    if (!DB_IS_SINGLE(session)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set nologging attribute when database in HA mode");
        return GS_ERROR;
    }

    if (dc->type == DICT_TYPE_TEMP_TABLE_TRANS || dc->type == DICT_TYPE_TEMP_TABLE_SESSION) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set nologging attribute to temporaty table");
        return GS_ERROR;
    }

    if (dc->type == DICT_TYPE_TABLE_NOLOGGING) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", nologging table already has the nologging attribute");
        return GS_ERROR;
    }

    if (LOGIC_REP_DB_ENABLED(session)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set nologging attribute when logic replay is enabled");
        return GS_ERROR;
    }
    
    return GS_SUCCESS;
}

status_t db_altable_enable_nologging(knl_session_t *session, knl_dictionary_t *dc)
{
    if (db_enable_nologging_precheck(session, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    bool32 is_null = GS_FALSE;
    if (db_table_judge_null(session, dc, &is_null) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!is_null) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set nologging attribute when the table is not empty");
        return GS_ERROR;
    }
    
    knl_table_desc_t *desc = &table->desc;
    if (table->desc.is_nologging) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", the table already has the nologging attribute");
        return GS_ERROR;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    if (db_update_table_flag(session, desc->uid, desc->id, TABLE_FLAG_TYPE_ENABLE_NOLOGGING) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_nologobj_cnt(session, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_altable_disable_nologging(knl_session_t *session, knl_dictionary_t *dc)
{
    if (dc->type == DICT_TYPE_TEMP_TABLE_TRANS || dc->type == DICT_TYPE_TEMP_TABLE_SESSION) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "unset nologging attribute to temporaty table");
        return GS_ERROR;
    }

    if (dc->type == DICT_TYPE_TABLE_NOLOGGING) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", cannot change the nologging attribute of nologging table");
        return GS_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    knl_table_desc_t *desc = &table->desc;
    if (!desc->is_nologging) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", the table does not have the nologging attribute");
        return GS_ERROR;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    if (db_update_table_flag(session, desc->uid, desc->id, TABLE_FLAG_TYPE_DISABLE_NOLOGGING) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    return GS_SUCCESS;
}

static status_t db_enable_part_nologging_precheck(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def,
    table_part_t **table_part)
{
    if (db_enable_nologging_precheck(session, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    if (!IS_PART_TABLE(table)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
        return GS_ERROR;
    }

    table_part_t *part = NULL;
    if (!part_table_find_by_name(table->part_table, &def->part_def.name, &part)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
        return GS_ERROR;
    }

    bool32 is_null = GS_FALSE;
    knl_part_locate_t part_loc;
    part_loc.part_no = part->part_no;
    part_loc.subpart_no = GS_INVALID_ID32;
    if (db_part_judge_null(session, dc, part_loc, &is_null) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!is_null) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set nologging attribute when the table part is not empty");
        return GS_ERROR;
    }
    
    if (part->desc.is_nologging) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", the table partition already has the nologging attribute");
        return GS_ERROR;
    }

    *table_part = part;
    return GS_SUCCESS;
}

status_t db_altable_enable_part_nologging(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = NULL;

    if (db_enable_part_nologging_precheck(session, dc, def, &table_part) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    if (db_update_part_flag(session, dc, table->part_table, table_part->desc.part_id, 
        PART_FLAG_TYPE_ENABLE_NOLOGGING) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_nologobj_cnt(session, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (!IS_PARENT_TABPART(&table_part->desc)) {
        return GS_SUCCESS;
    }

    table_part_t *subpart = NULL;
    for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
        subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
        if (subpart == NULL || subpart->desc.is_nologging) {
            continue;
        }
    
        if (db_update_subpart_flag(session, dc, table_part, subpart->desc.part_id, 
            PART_FLAG_TYPE_ENABLE_NOLOGGING) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_update_nologobj_cnt(session, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_altable_disable_part_nologging(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    if (dc->type == DICT_TYPE_TABLE_NOLOGGING) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", cannot change the nologging attribute of nologging table");
        return GS_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    if (!IS_PART_TABLE(table)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
        return GS_ERROR;
    }

    table_part_t *table_part = NULL;
    if (!part_table_find_by_name(table->part_table, &def->part_def.name, &table_part)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
        return GS_ERROR;
    }

    if (!table_part->desc.is_nologging) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", the table part does not have the nologging attribute");
        return GS_ERROR;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    if (db_update_part_flag(session, dc, table->part_table, table_part->desc.part_id, 
        PART_FLAG_TYPE_DISABLE_NOLOGGING) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!IS_PARENT_TABPART(&table_part->desc)) {
        return GS_SUCCESS;
    }

    table_part_t *subpart = NULL;
    for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
        subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
        if (subpart == NULL || !subpart->desc.is_nologging) {
            continue;
        }
    
        if (db_update_subpart_flag(session, dc, table_part, subpart->desc.part_id, 
            PART_FLAG_TYPE_DISABLE_NOLOGGING) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_altable_enable_subpart_nologging(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    if (db_enable_nologging_precheck(session, dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    if (!IS_PART_TABLE(table)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
        return GS_ERROR;
    }

    if (!IS_COMPART_TABLE(table->part_table)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not composite partition table", T2S(&def->name));
        return GS_ERROR;
    }
    
    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    if (!subpart_table_find_by_name(table->part_table, &def->part_def.name, &compart, &subpart)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
        return GS_ERROR;
    }

    bool32 is_null = GS_FALSE;
    knl_part_locate_t part_loc;
    part_loc.part_no = compart->part_no;
    part_loc.subpart_no = subpart->part_no;
    if (db_subpart_judge_null(session, dc, part_loc, &is_null) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!is_null) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "set nologging attribute when the table part is not empty");
        return GS_ERROR;
    }
    if (subpart->desc.is_nologging) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", the table subpartition already has the nologging attribute");
        return GS_ERROR;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    if (db_update_subpart_flag(session, dc, compart, subpart->desc.part_id, 
        PART_FLAG_TYPE_ENABLE_NOLOGGING) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_nologobj_cnt(session, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_altable_disable_subpart_nologging(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    if (dc->type == DICT_TYPE_TABLE_NOLOGGING) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", cannot change the nologging attribute of nologging table");
        return GS_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;

    if (!IS_PART_TABLE(table)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not partition table", T2S(&def->name));
        return GS_ERROR;
    }

    if (!IS_COMPART_TABLE(part_table)) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, " %s not composite partition table", T2S(&def->name));
        return GS_ERROR;
    }
    
    table_part_t *compart = NULL;
    table_part_t *subpart = NULL;
    if (!subpart_table_find_by_name(part_table, &def->part_def.name, &compart, &subpart)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_def.name));
        return GS_ERROR;
    }

    if (!subpart->desc.is_nologging) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ", the table part does not have the nologging attribute");
        return GS_ERROR;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    if (db_update_subpart_flag(session, dc, compart, subpart->desc.part_id, 
        PART_FLAG_TYPE_DISABLE_NOLOGGING) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_alter_tmptable_auto_increment(knl_session_t *session, knl_dictionary_t *dc, int64 serial_start)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    dc_entry_t *entry = entity->entry;
    knl_temp_cache_t *temp_table = NULL;

    if (knl_ensure_temp_cache(session, entity, &temp_table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (serial_start <= temp_table->serial) {
        return GS_SUCCESS;
    }

    if (temp_table->serial == 0) {
        temp_table->serial++;
    }

    cm_spin_lock(&entry->serial_lock, NULL);
    if (db_update_table_increment_start(session, &entity->table.desc, serial_start) != GS_SUCCESS) {
        cm_spin_unlock(&entry->serial_lock);
        return GS_ERROR;
    }

    entity->table.desc.serial_start = serial_start;
    temp_table->serial = serial_start;
    cm_spin_unlock(&entry->serial_lock);

    return GS_SUCCESS;
}

static void db_altable_update_heap_serial(knl_session_t *session, int64 serial_start, dc_entity_t *entity)
{
    if (serial_start >= GS_INVALID_INT64 - GS_SERIAL_CACHE_COUNT) {
        if (GS_INVALID_INT64 != entity->table.heap.segment->serial) {
            heap_update_serial(session, &entity->table.heap, GS_INVALID_INT64);
        }
    } else if (serial_start < (entity->table.heap.segment->serial - entity->table.desc.serial_start + serial_start)) {
        heap_update_serial(session, &entity->table.heap,
            entity->table.heap.segment->serial - entity->table.desc.serial_start + serial_start);
    } else {
        heap_update_serial(session, &entity->table.heap, serial_start + GS_SERIAL_CACHE_COUNT);
    }
}

status_t db_altable_auto_increment(knl_session_t *session, knl_dictionary_t *dc, int64 serial_start)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    dc_entry_t *entry = entity->entry;

    if (entity->type == DICT_TYPE_TEMP_TABLE_SESSION || entity->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        return db_alter_tmptable_auto_increment(session, dc, serial_start);
    }

    if (entity->table.heap.segment == NULL) {
        if (heap_create_entry(session, &entity->table.heap) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    cm_spin_lock(&entry->serial_lock, NULL);

    // scenario: 1,create table without any insert,no need load dc, entry'serial_value is 0,here table desc can be set
    // scenario: 2,restart entry'serial_value is 0, need to know is there any insert, need verify init stat
    if ((HEAP_SEGMENT(entity->table.heap.entry, entity->table.heap.segment)->serial !=
         entity->table.desc.serial_start) && (entry->serial_value == 0)) {
        entry->serial_value = entity->table.heap.segment->serial;
    }

    if (serial_start <= entry->serial_value) {
        cm_spin_unlock(&entry->serial_lock);
        return GS_SUCCESS;
    }

    if (entry->serial_value == 0) {
        entry->serial_value = HEAP_SEGMENT(entity->table.heap.entry, entity->table.heap.segment)->serial;

        if (entry->serial_value == 0) {
            entry->serial_value = 1;
        }
    }

    if (db_update_table_increment_start(session, &entity->table.desc, serial_start) != GS_SUCCESS) {
        cm_spin_unlock(&entry->serial_lock);
        return GS_ERROR;
    }

    db_altable_update_heap_serial(session, serial_start, entity);

    entity->table.desc.serial_start = serial_start;
    entry->serial_value = serial_start;

    cm_spin_unlock(&entry->serial_lock);
    return GS_SUCCESS;
}

static status_t db_validate_old_data(knl_session_t *session, knl_dictionary_t *dc, knl_dictionary_t *ref_dc,
                                     knl_cursor_t *cursor, uint32 type)
{
    text_t cond;
    uint32 i;
    dc_entity_t *entity = DC_ENTITY(dc);
    ref_cons_t *ref_cons = NULL;

    if (type == CONS_TYPE_CHECK) {
        cond.len = CURSOR_COLUMN_SIZE(cursor, CONSDEF_COL_COND_TEXT);
        cond.str = CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_COND_TEXT);
        if (db_verify_check_data(session, dc, &cond) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        for (i = 0; i < entity->table.cons_set.ref_count; i++) {
            ref_cons = entity->table.cons_set.ref_cons[i];
            if (ref_cons->ref_uid == ref_dc->uid && ref_cons->ref_oid == ref_dc->oid) {
                break;
            }
        }

        if (i == entity->table.cons_set.ref_count) {
            GS_LOG_RUN_ERR("[TABLE] failed to validate old cons");
            return GS_ERROR;
        }

        if (GS_SUCCESS != db_verify_reference_data(session, dc, ref_dc, ref_cons)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_altable_apply_constraint(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    bool32 exist = GS_TRUE;
    knl_dictionary_t ref_dc;
    uint32 type, ref_uid, ref_tid;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    knl_update_info_t *ua = NULL;
    knl_constraint_def_t *cons = &def->cons_def.new_cons;
    knl_constraint_state_t cons_state;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    if (db_fetch_sysconsdef_by_table(session, cursor, CURSOR_ACTION_UPDATE, dc->uid, dc->oid,
        &cons->name, &exist) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!exist) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_CONS_NOT_EXIST, T2S(&cons->name));
        return GS_ERROR;
    }

    type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_TYPE);
    if (type == CONS_TYPE_PRIMARY || type == CONS_TYPE_UNIQUE) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Cannot apply constaint state to primary/uniuqe constraint now.");
        return GS_ERROR;
    }
    ref_dc.handle = NULL;
    if (type == CONS_TYPE_REFERENCE) {
        ref_uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_USER);
        ref_tid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_REF_TABLE);
        if (knl_open_dc_by_id(session, ref_uid, ref_tid, &ref_dc, GS_TRUE) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        uint32 timeout = session->kernel->attr.ddl_lock_timeout;
        if (lock_table_directly(session, &ref_dc, timeout) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            dc_close(&ref_dc);
            return GS_ERROR;
        }
    }

    if (cons->cons_state.is_validate) {
        if (GS_SUCCESS != db_validate_old_data(session, dc, &ref_dc, cursor, type)) {
            if (ref_dc.handle != NULL) {
                dc_close(&ref_dc);
            }
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (ref_dc.handle != NULL) {
        dc_close(&ref_dc);
    }
    cons_state.option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_FLAGS);
    cons_state.is_enable = cons->cons_state.is_enable;
    cons_state.is_validate = cons->cons_state.is_validate;
    ua = &cursor->update_info;
    row_init(&ra, ua->data, HEAP_MAX_ROW_SIZE, 1);
    if (GS_SUCCESS != row_put_int32(&ra, cons_state.option)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    ua->count = 1;
    ua->columns[0] = CONSDEF_COL_FLAGS;
    cm_decode_row(ua->data, ua->offsets, ua->lens, NULL);
    if (GS_SUCCESS != knl_internal_update(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_altable_rename_constraint(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    knl_constraint_def_t *new_cons = &def->cons_def.new_cons;
    knl_alt_cstr_prop_t *old_cons_def = &def->cons_def;
    knl_constraint_state_t cons_state;
    row_assist_t ra;
    bool32 exist = GS_TRUE;
    char new_name[GS_NAME_BUFFER_SIZE];

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (db_fetch_sysconsdef_by_name(session, cursor, CURSOR_ACTION_SELECT, dc->uid, dc->oid,
        &new_cons->name, &exist) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (exist) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_OBJECT_EXISTS, "constraint", T2S(&new_cons->name));
        return GS_ERROR;
    }

    if (db_fetch_sysconsdef_by_table(session, cursor, CURSOR_ACTION_UPDATE, dc->uid, dc->oid,
        &old_cons_def->name, &exist) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!exist) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_CONS_NOT_EXIST, T2S(&old_cons_def->name));
        return GS_ERROR;
    }

    (void)cm_text2str(&(new_cons->name), new_name, new_cons->name.len + 1);
    new_name[new_cons->name.len] = '\0';


    cons_state.option = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_FLAGS);
    cons_state.is_anonymous = GS_FALSE;

    knl_update_info_t *ua = &cursor->update_info;
    // update 2 rows
    row_init(&ra, ua->data, HEAP_MAX_ROW_SIZE, 2);
    (void)row_put_str(&ra, new_name);
    (void)row_put_uint32(&ra, cons_state.option);

    ua->count = 2;
    ua->columns[0] = CONSDEF_COL_NAME;
    ua->columns[1] = CONSDEF_COL_FLAGS;
    cm_decode_row(ua->data, ua->offsets, ua->lens, NULL);
    if (GS_SUCCESS != knl_internal_update(session, cursor)) {
        int32 err_code = cm_get_error_code();

        if (err_code == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "constraint", T2S(&new_cons->name));
        }

        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_get_pk_idx_id(knl_session_t *session, table_t *table,
    knl_altable_def_t *def, uint32 *index_id)
{
    knl_cursor_t *cursor = NULL;
    status_t ret;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    knl_init_index_scan(cursor, GS_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table->desc.id,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_TABLE_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    ret = GS_ERROR;
    while (!cursor->eof) {
        if (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_CONS_TYPE) == CONS_TYPE_PRIMARY) {
            *index_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_IND_ID);
            ret = GS_SUCCESS;
            break;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            break;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return ret;
}

static status_t db_used_by_uni_cons(knl_session_t *session, uint32 uid, uint32 tid, uint32 idx_id, bool32 *used)
{
    knl_cursor_t *cursor = NULL;
    status_t ret;
    *used = GS_FALSE;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &uid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &tid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &uid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_STRING, &tid,
                     sizeof(uint32), IX_COL_SYS_CONSDEF001_TABLE_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    ret = GS_ERROR;
    while (!cursor->eof) {
        if ((*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_CONS_TYPE) == CONS_TYPE_UNIQUE)
            && (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_CONSDEF_COL_IND_ID) == idx_id)) {
            *used = GS_TRUE;
            ret = GS_SUCCESS;
            break;
        }

        if (GS_SUCCESS != knl_fetch(session, cursor)) {
            break;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return ret;
}

static status_t db_get_unique_idx_id(knl_session_t *session, table_t *table,
    knl_altable_def_t *def, uint32 *index_id)
{
    knl_cursor_t *cursor = NULL;
    uint32 idx_id;
    bool32 used = GS_FALSE;
    status_t ret;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INDEX_ID, IX_SYS_INDEX_002_ID);
    knl_init_index_scan(cursor, GS_FALSE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEX_002_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, (void *)def->logical_log_def.idx_name.str,
                     def->logical_log_def.idx_name.len, IX_COL_SYS_INDEX_002_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_INTEGER, &table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEX_002_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, GS_TYPE_STRING, (void *)def->logical_log_def.idx_name.str,
                     def->logical_log_def.idx_name.len, IX_COL_SYS_INDEX_002_NAME);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    ret = GS_ERROR;
    if (!cursor->eof) {
        idx_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_ID);

        if (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_IS_UNIQUE) != 0) {
            *index_id = idx_id;
            ret = GS_SUCCESS;
        } else {
            // is_unique==0, this idx can still be unique if it is used by a unique constraint on the table
            ret = db_used_by_uni_cons(session, table->desc.uid, table->desc.id, idx_id, &used);
            if ((ret == GS_SUCCESS) && (used)) {
                *index_id = idx_id;
            } else if (!used) {
                ret = GS_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return ret;
}

static status_t db_check_index_is_valid(knl_session_t *session, table_t *table,
    knl_altable_def_t *def, uint32 *index_id)
{
    knl_cursor_t *cursor = NULL;
    uint32 flags;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INDEX_ID, IX_SYS_INDEX_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, &table->desc.id,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_TABLE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, index_id,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_ID);

    if (GS_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_FLAGS);
        if (!KNL_INDEX_FLAG_IS_INVALID(flags)) {
            CM_RESTORE_STACK(session->stack);
            return GS_SUCCESS;
        }
    }

    CM_RESTORE_STACK(session->stack);
    GS_THROW_ERROR(ERR_INVALID_LOGICAL_INDEX);
    return GS_ERROR;
}

static status_t db_get_table_index_id(knl_session_t *session, table_t *table,
    knl_altable_def_t *def, uint32 *index_id)
{
    status_t status;
    if (def->logical_log_def.key_type == LOGICREP_KEY_TYPE_PRIMARY_KEY) {
        status = db_get_pk_idx_id(session, table, def, index_id);
    } else if (def->logical_log_def.key_type == LOGICREP_KEY_TYPE_UNIQUE) {
        status = db_get_unique_idx_id(session, table, def, index_id);
    } else {
        GS_LOG_RUN_ERR("unsupported logical log type(%u)", def->logical_log_def.key_type);
        return GS_ERROR;
    }

    if (status != GS_SUCCESS) {
        return status;
    }

    // check whether the index is valid
    return db_check_index_is_valid(session, table, def, index_id);
}

status_t db_logical_log_get_parts(knl_session_t *session, knl_altable_def_t *def, text_t *text)
{
    uint32 i;
    uint32 max_size;
    errno_t err;
    knl_part_def_t *part_def = NULL;

    max_size = def->logical_log_def.parts.count * (GS_NAME_BUFFER_SIZE + 1);
    text->str = (char *)cm_push(session->stack, max_size);
    text->len = 0;

    for (i = 0; i < def->logical_log_def.parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->logical_log_def.parts, i);

        if (i > 0) {
            err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, ",");
            knl_securec_check_ss(err);
            text->len += err;
        }
        err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, "%s", T2S(&part_def->name));
        knl_securec_check_ss(err);
        text->len += err;
    }

    return GS_SUCCESS;
}

void db_logical_log_get_oldparts(dc_entity_t *entity, text_t *text)
{
    table_part_t *table_part = NULL;
    errno_t err;

    for (uint32 i = 0; i < entity->table.part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(&entity->table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (IS_PARENT_TABPART(&table_part->desc)) {
            table_part_t *subpart = NULL;
            for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
                subpart = PART_GET_SUBENTITY(entity->table.part_table, table_part->subparts[j]);
                if (subpart == NULL) {
                    continue;
                }

                if (subpart->desc.lrep_status == PART_LOGICREP_STATUS_ON) {
                    err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, ",");
                    knl_securec_check_ss(err);
                    text->len += err;

                    err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, "%s",
                        subpart->desc.name);
                    knl_securec_check_ss(err);
                    text->len += err;
                }
            }
        } else {
            if (table_part->desc.lrep_status == PART_LOGICREP_STATUS_ON) {
                err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, ",");
                knl_securec_check_ss(err);
                text->len += err;

                err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, "%s", table_part->desc.name);
                knl_securec_check_ss(err);
                text->len += err;
            }
        }
    }
}

status_t db_logical_log_compare_parts(knl_session_t *session, dc_entity_t *entity, knl_altable_def_t *def, text_t *text)
{
    uint32 i;
    errno_t err;
    knl_part_def_t *part_def = NULL;
    table_part_t *table_part = NULL;
    uint32 part_no = GS_INVALID_ID32;
    uint32 subpart_no = GS_INVALID_ID32;
    text->len = 0;

    for (i = 0; i < def->logical_log_def.parts.count; i++) {
        part_def = (knl_part_def_t *)cm_galist_get(&def->logical_log_def.parts, i);
        if (knl_find_table_part_by_name(entity, &part_def->name, &part_no) != GS_SUCCESS) {
            cm_reset_error();
            if (knl_find_subpart_by_name(entity, &part_def->name, &part_no, &subpart_no) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        table_part = TABLE_GET_PART(&entity->table, part_no);
        if (subpart_no != GS_INVALID_ID32) {
            table_part = PART_GET_SUBENTITY(entity->table.part_table, table_part->subparts[subpart_no]);
        }
        if (table_part->desc.lrep_status == PART_LOGICREP_STATUS_ON) {
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "partition logical log", T2S(&part_def->name));
            return GS_ERROR;
        }

        if (text->len > 0) {
            err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, ",");
            knl_securec_check_ss(err);
            text->len += err;
        }
        err = snprintf_s(text->str + text->len, GS_NAME_BUFFER_SIZE + 1, GS_NAME_BUFFER_SIZE, "%s", T2S(&part_def->name));
        knl_securec_check_ss(err);
        text->len += err;
    }

    db_logical_log_get_oldparts(entity, text);
    return GS_SUCCESS;
}

status_t db_altable_add_logical_log_inner(knl_session_t *session, knl_cursor_t *cursor,
                                          knl_dictionary_t *dc, knl_altable_def_t *def,
                                          const uint32 index_id)
{
    row_assist_t ra;
    table_t *table = NULL;
    uint32 uid;
    uint32 tableid;
    text_t text;
    knl_column_t *lob_column = NULL;

    table = DC_TABLE(dc);
    uid = table->desc.uid;
    tableid = table->desc.id;

    if (def->logical_log_def.is_parts_logical == GS_TRUE) {
        if (db_logical_log_get_parts(session, def, &text) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        text.len = 0;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_LOGIC_REP_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, cursor->buf, GS_MAX_ROW_SIZE, table->desc.column_count);
    (void)row_put_int32(&ra, uid);
    (void)row_put_int32(&ra, tableid);
    if (text.len > 0) {
        (void)row_put_int32(&ra, LOGICREP_STATUS_OFF);
    } else {
        (void)row_put_int32(&ra, LOGICREP_STATUS_ON);
    }
    (void)row_put_int32(&ra, index_id);
    lob_column = knl_get_column(cursor->dc_entity, SYS_LOGIC_REP_COLUMN_ID_PARTITIONIDS);
    if (knl_row_put_lob(session, cursor, lob_column, &text, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        int32 code = cm_get_error_code();
        if (code == ERR_DUPLICATE_KEY) {
            table = DC_TABLE(dc);
            cm_reset_error();
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "logical log", table->desc.name);
        }
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t db_altable_add_logical_log(knl_session_t *session, knl_dictionary_t *dc,
                                    knl_altable_def_t *def)
{
    uint32 uid, tableid, index_id;
    uint32 maxsize, src_maxsize;
    text_t text;
    status_t status;
    table_t *table = NULL;
    knl_cursor_t *cursor = NULL;
    dc_entity_t *entity = NULL;

    table = DC_TABLE(dc);
    uid = table->desc.uid;
    tableid = table->desc.id;
    entity = DC_ENTITY(dc);

    if (db_get_table_index_id(session, table, def, &index_id) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "primary key or unique index on table",
            table->desc.name);
        return GS_ERROR;
    }
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    do {
        if (entity->lrep_info.status == LOGICREP_STATUS_OFF && entity->lrep_info.parts_count == 0) {
            status = db_altable_add_logical_log_inner(session, cursor, dc, def, index_id);
            break;
        }
        if (entity->lrep_info.parts_count > 0 && def->logical_log_def.is_parts_logical == GS_TRUE) {
            maxsize = def->logical_log_def.parts.count * (GS_NAME_BUFFER_SIZE + 1);
            src_maxsize = entity->lrep_info.parts_count * (GS_NAME_BUFFER_SIZE + 1);
            text.str = (char *)cm_push(session->stack, (src_maxsize + maxsize));
            if (text.str == NULL) {
                GS_THROW_ERROR(ERR_STACK_OVERFLOW);
                status = GS_ERROR;
                break;
            }
            status = db_logical_log_compare_parts(session, entity, def, &text);
            GS_BREAK_IF_ERROR(status);
        } else {
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "logical log", table->desc.name);
            status = GS_ERROR;
            break;
        }
        status = db_altable_update_logical_log(session, cursor, uid, tableid, &text);
    } while (0);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t db_altable_drop_logical_log(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def)
{
    table_t *table;
    uint32 uid;
    uint32 tableid;
    status_t status;
    knl_cursor_t *cursor = NULL;

    table = DC_TABLE(dc);
    tableid = table->desc.id;
    uid = table->desc.uid;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    status = db_altable_drop_logical_log_inner(session, cursor, uid, tableid);

    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t db_shrink_lob_parts(knl_session_t *session, knl_dictionary_t *dc, knl_cursor_t *cursor,
    knl_column_t *column)
{
    table_part_t *table_part = NULL;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        cursor->part_loc.part_no = i;
        table_part = PART_GET_ENTITY(table->part_table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            cursor->part_loc.subpart_no = GS_INVALID_ID32;
            /* ensure table is locked by current session in exclusive mode */
            if (!SCH_LOCKED_EXCLUSIVE(entity)) {
                if (lock_upgrade_table_lock(session, entity) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (lob_shrink_space(session, cursor, column) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            cursor->part_loc.subpart_no = j;
            /* ensure table is locked by current session in exclusive mode */
            if (!SCH_LOCKED_EXCLUSIVE(entity)) {
                if (lock_upgrade_table_lock(session, entity) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            if (knl_reopen_cursor(session, cursor, dc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (lob_shrink_space(session, cursor, column) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t db_shrink_lob(knl_session_t *session, knl_dictionary_t *dc, knl_column_t *column)
{
    table_t *table = DC_TABLE(dc);

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->part_loc.part_no = 0;
    cursor->part_loc.subpart_no = 0;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->action = CURSOR_ACTION_UPDATE;

    if (knl_open_cursor(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cursor->isolevel = ISOLATION_CURR_COMMITTED;
    cursor->update_info.data = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE);
    cursor->update_info.columns[0] = column->id;
    cursor->update_info.count = 1;

    if (IS_PART_TABLE(table)) {
        if (db_shrink_lob_parts(session, dc, cursor, column) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    } else {
        if (lob_shrink_space(session, cursor, column) != GS_SUCCESS) {
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_altable_modify_lob(knl_session_t *session, knl_altable_def_t *def)
{
    knl_dictionary_t dc;
    knl_modify_lob_def_t *lob_def = &def->modify_lob_def;
    knl_column_t *column = NULL;

    if (dc_open(session, &def->user, &def->name, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dc.type < DICT_TYPE_TABLE || dc.type > DICT_TYPE_TABLE_NOLOGGING) {
        dc_close(&dc);
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter table", "view, external organized table or system table");
        return GS_ERROR;
    }

    if (SYNONYM_EXIST(&dc)) {
        dc_close(&dc);
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, T2S(&def->user), T2S_EX(&def->name));
        return GS_ERROR;
    }

    if (lock_table_directly(session, &dc, LOCK_INF_WAIT) != GS_SUCCESS) {
        dc_close(&dc);
        return GS_ERROR;
    }

    column = knl_find_column(&lob_def->name, &dc);

    if (column == NULL) {
        unlock_tables_directly(session);
        dc_close(&dc);
        GS_THROW_ERROR(ERR_COLUMN_NOT_EXIST, T2S(&def->user), T2S_EX(&lob_def->name));
        return GS_ERROR;
    }

    if (!COLUMN_IS_LOB(column)) {
        unlock_tables_directly(session);
        dc_close(&dc);
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "modify lob", "nonlob column");
        return GS_ERROR;
    }
    dc_entity_t *entity = DC_ENTITY(&dc);
    if (db_shrink_lob(session, &dc, column) != GS_SUCCESS) {
        if (SCH_LOCKED_EXCLUSIVE(dc.handle)) {
            dc_invalidate(session, entity);
        }
        unlock_tables_directly(session);
        dc_close(&dc);
        return GS_ERROR;
    }

    dc_invalidate(session, entity);
    unlock_tables_directly(session);
    dc_close(&dc);

    session->stat.table_alters++;
    return GS_SUCCESS;
}

status_t db_ddm_check_double_rule(knl_session_t *session, knl_ddm_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DDM_ID, IX_SYS_DDM_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->uid,
        sizeof(uint32), IX_COL_SYS_DDM_001_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->oid,
        sizeof(uint32), IX_COL_SYS_DDM_001_OID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->column_id,
        sizeof(uint32), IX_COL_SYS_DDM_001_COLID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    if (cursor->eof == GS_FALSE) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", col has rule already.");
        return GS_ERROR;
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_DDM_ID, IX_SYS_DDM_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->uid,
        sizeof(uint32), IX_COL_SYS_DDM_002_UID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&def->oid,
        sizeof(uint32), IX_COL_SYS_DDM_002_OID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, def->rulename,
        (uint16)strlen(def->rulename), IX_COL_SYS_DDM_002_RULENAME);
    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    if (cursor->eof == GS_FALSE) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", rule name already exists.");
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}
status_t db_write_ddm_core(knl_session_t *session, knl_ddm_def_t *def)
{
    uint32 max_size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    table_t *table = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_DDM_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);
    (void)row_put_int32(&ra, def->uid);                // user id
    (void)row_put_int32(&ra, def->oid);                // id
    (void)row_put_int32(&ra, def->column_id);          // col_id
    (void)row_put_str(&ra, def->rulename);             // name
    (void)row_put_str(&ra, def->ddmtype);              // type
    (void)row_put_str(&ra, def->param);                // param

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}
status_t db_ddm_invalid_dc(knl_session_t *session, knl_ddm_def_t *def)
{
    knl_dictionary_t dc;

    if (knl_open_dc_by_id(session, def->uid, def->oid, &dc, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    dc_invalidate(session, (dc_entity_t *)dc.handle);
    dc_close(&dc);
    return GS_SUCCESS;
}
status_t db_write_sysddm(knl_session_t *session, knl_ddm_def_t *def)
{
    if (db_ddm_check_double_rule(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (db_write_ddm_core(session, def) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}


status_t db_write_sysjob(knl_session_t *session, knl_job_def_t *def)
{
    uint32 max_size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    table_t *table = NULL;
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_JOB_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "JOB$");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_JOB_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);
    (void)row_put_int64(&ra, def->job_id);        // JOB
    (void)row_put_str(&ra, T2S(&def->lowner));    // LOWNER
    (void)row_put_str(&ra, T2S(&def->lowner));    // POWNER
    (void)row_put_str(&ra, T2S(&def->lowner));    // COWNER
    row_put_null(&ra);                            // LAST_DATE
    row_put_null(&ra);                            // THIS_DATE
    (void)row_put_int64(&ra, def->next_date);     // NEXT_DATE
    (void)row_put_int32(&ra, 0);                  // TOTAL DEFAULT 0
    (void)row_put_str(&ra, T2S(&def->interval));  // INTERVAL#
    (void)row_put_int32(&ra, 0);                  // FAILURES
    (void)row_put_int32(&ra, 0);                  // FLAG DEFAULT 0
    (void)row_put_str(&ra, T2S(&def->what));      // WHAT
    (void)row_put_int64(&ra, cm_now());           // CREATE_DATE
    (void)row_put_int32(&ra, def->instance);      // INSTANCE

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

bool32 db_check_job_priv(knl_session_t *session, text_t *user, text_t *powner)
{
    if (user->len == SYS_USER_NAME_LEN && cm_strcmpni(user->str, SYS_USER_NAME, user->len) == 0) {
        return GS_TRUE;
    } else {
        if (user->len == powner->len && cm_strcmpni(user->str, powner->str, user->len) == 0) {
            return GS_TRUE;
        } else {
            return GS_FALSE;
        }
    }
}

static status_t db_set_job_update_info(knl_session_t *session, knl_cursor_t *cursor, knl_job_node_t *job)
{
    row_assist_t ra;

    switch (job->node_type) {
        case JOB_TYPE_BROKEN:
            if (job->is_broken == GS_TRUE) {
                /* broken */
                row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
                (void)row_put_int32(&ra, GS_TRUE);
                cursor->update_info.count = 1;
                cursor->update_info.columns[0] = SYS_JOB_FLAG;
            } else {
                /* run */
                row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
                (void)row_put_int64(&ra, job->next_date);
                (void)row_put_int32(&ra, GS_FALSE);
                cursor->update_info.count = 2;
                cursor->update_info.columns[0] = SYS_JOB_NEXT_DATE;
                cursor->update_info.columns[1] = SYS_JOB_FLAG;
            }
            return GS_SUCCESS;

        case JOB_TYPE_RUN:
            row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 2);
            (void)row_put_int64(&ra, job->next_date);
            (void)row_put_int32(&ra, GS_FALSE);
            cursor->update_info.count = 2;
            cursor->update_info.columns[0] = SYS_JOB_NEXT_DATE;
            cursor->update_info.columns[1] = SYS_JOB_FLAG;
            return GS_SUCCESS;

        case JOB_TYPE_START:
            row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
            (void)row_put_int64(&ra, job->this_date);
            cursor->update_info.count = 1;
            cursor->update_info.columns[0] = SYS_JOB_THIS_DATE;
            return GS_SUCCESS;

        case JOB_TYPE_FINISH:
            if (job->is_success) {
                row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 4);
                (void)row_put_int64(&ra, job->this_date);
                row_put_null(&ra);
                (void)row_put_int64(&ra, job->next_date);
                (void)row_put_int32(&ra, job->failures);
                cursor->update_info.count = 4;
                cursor->update_info.columns[0] = SYS_JOB_LAST_DATE;
                cursor->update_info.columns[1] = SYS_JOB_THIS_DATE;
                cursor->update_info.columns[2] = SYS_JOB_NEXT_DATE;
                cursor->update_info.columns[3] = SYS_JOB_FAILURES;
            } else {
                row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
                (void)row_put_int32(&ra, job->failures);
                cursor->update_info.count = 1;
                cursor->update_info.columns[0] = SYS_JOB_FAILURES;
            }
            return GS_SUCCESS;

        default:
            GS_THROW_ERROR(ERR_UNSUPPORT_OPER_TYPE, "job operate", job->node_type);
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * db_update_job$
 */
status_t db_update_sysjob(knl_session_t *session, text_t *user, knl_job_node_t *job, bool32 should_exist)
{
    uint16 size;
    text_t powner;
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_JOB_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "JOB$");
        return GS_ERROR;
    }

    knl_set_session_scn(session, GS_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_JOB_ID, I_JOB_1_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_BIGINT, &job->job_id, sizeof(int64),
        IX_COL_JOB_1_JOB);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    text_t job_txt;
    char num_txt[GS_MAX_NUMBER_LEN];

    job_txt.str = num_txt;
    job_txt.len = 0;

    if (cursor->eof) {
        if (should_exist == GS_TRUE) {
            cm_bigint2text(job->job_id, &job_txt);
            GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "job", T2S(&job_txt));
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    powner.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_POWNER);
    powner.len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_POWNER);

    if (!db_check_job_priv(session, user, &powner)) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return GS_ERROR;
    }

    if (db_set_job_update_info(session, cursor, job) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        knl_rollback(session, NULL);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/*
 * db_delete_job$
 *
 * This function is used to delete a job record from job$.
 */
status_t db_delete_sysjob(knl_session_t *session, text_t *user, int64 jobno, bool32 should_exist)
{
    knl_cursor_t *cursor = NULL;
    text_t text;
    text_t powner;
    char num_txt[GS_MAX_NUMBER_LEN];
    dc_user_t *sys_user = NULL;

    text.str = num_txt;
    text.len = 0;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_JOB_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "JOB$");
        return GS_ERROR;
    }

    knl_set_session_scn(session, GS_INVALID_ID64);

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_JOB_ID, I_JOB_1_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_BIGINT, &jobno, sizeof(int64),
                     IX_COL_JOB_1_JOB);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (!cursor->eof) {
        powner.str = (char *)CURSOR_COLUMN_DATA(cursor, SYS_JOB_POWNER);
        powner.len = CURSOR_COLUMN_SIZE(cursor, SYS_JOB_POWNER);

        if (!db_check_job_priv(session, user, &powner)) {
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return GS_ERROR;
        }

        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            knl_rollback(session, NULL);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    } else {
        if (should_exist == GS_TRUE) {
            cm_bigint2text(jobno, &text);
            GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "job", T2S(&text));
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_sql_map_hash(knl_session_t *session, knl_cursor_t *cursor, uint32 hash_value)
{
    row_assist_t ra;
    knl_update_info_t *update_info = &cursor->update_info;

    row_init(&ra, update_info->data, GS_MAX_ROW_SIZE, 1);
    update_info->count = 1;
    update_info->columns[0] = 0;
    (void)row_put_int32(&ra, hash_value);
    cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);
    return knl_internal_update(session, cursor);
}

static status_t db_update_sql_map(knl_session_t *session, knl_cursor_t *cursor, knl_sql_map_t *sql_map)
{
    row_assist_t ra;
    knl_update_info_t *update_info = &cursor->update_info;
    knl_column_t *dst_lob_column = NULL;

    row_init(&ra, update_info->data, GS_MAX_ROW_SIZE, 1);
    update_info->count = 1;
    update_info->columns[0] = SYS_SQL_MAP_COL_DST_TEXT;
    dst_lob_column = knl_get_column(cursor->dc_entity, SYS_SQL_MAP_COL_DST_TEXT);

    if (knl_row_put_lob(session, cursor, dst_lob_column, &sql_map->dst_text.text, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_decode_row(update_info->data, update_info->offsets, update_info->lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t db_insert_sql_map(knl_session_t *session, knl_cursor_t *cursor, knl_sql_map_t *sql_map)
{
    row_assist_t ra;
    knl_column_t *src_lob_column = NULL;
    knl_column_t *dst_lob_column = NULL;

    cursor->action = CURSOR_ACTION_INSERT;
    row_init(&ra, cursor->buf, GS_MAX_ROW_SIZE, 4);
    (void)row_put_int32(&ra, sql_map->src_hash_code);

    src_lob_column = knl_get_column(cursor->dc_entity, 1);

    if (knl_row_put_lob(session, cursor, src_lob_column, &sql_map->src_text.text, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dst_lob_column = knl_get_column(cursor->dc_entity, SYS_SQL_MAP_COL_DST_TEXT);

    if (knl_row_put_lob(session, cursor, dst_lob_column, &sql_map->dst_text.text, &ra) != GS_SUCCESS) {
        return GS_ERROR;
    }

    (void)(row_put_int32(&ra, sql_map->user_id));

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_alter_sql_sysmap(knl_session_t *session, knl_sql_map_t *sql_map)
{
    knl_cursor_t *cursor = NULL;
    lob_locator_t *src_lob = NULL;
    text_t src_sql;
    bool8 found = GS_FALSE;

    knl_set_session_scn(session, GS_INVALID_ID64);
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SQL_MAP_ID, IDX_SQL_MAP_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&sql_map->src_hash_code, sizeof(uint32), IX_COL_SQL_MAP_001_SRC_HASHCODE);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    while (!cursor->eof) {
        if (sql_map->user_id != *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SQL_MAP_COL_USER_ID)) {
            if (knl_fetch(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            continue;
        }
        src_lob = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, SYS_SQL_MAP_COL_SRC_TEXT);
        src_sql.len = knl_lob_size(src_lob);
        src_sql.str = (char *)cm_push(session->stack, src_sql.len);
        if (src_sql.str == NULL) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        if (knl_read_lob(session, src_lob, 0, src_sql.str, src_sql.len + 1, NULL) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        if (cm_text_equal(&src_sql, &sql_map->src_text.text)) {
            if (db_update_sql_map(session, cursor, sql_map) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            found = GS_TRUE;
            break;
        }
        cm_pop(session->stack);
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }
    if (!found) {
        if (db_insert_sql_map(session, cursor, sql_map) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_delete_sql_sysmap(knl_session_t *session, knl_sql_map_t *sql_map, bool8 *is_exist)
{
    knl_cursor_t *cursor = NULL;
    lob_locator_t *src_lob = NULL;
    text_t src_sql;

    knl_set_session_scn(session, GS_INVALID_ID64);
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SQL_MAP_ID, IDX_SQL_MAP_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&sql_map->src_hash_code, sizeof(uint32), IX_COL_SQL_MAP_001_SRC_HASHCODE);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    while (!cursor->eof) {
        if (sql_map->user_id != *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_SQL_MAP_COL_USER_ID)) {
            if (knl_fetch(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            continue;
        }
        src_lob = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, SYS_SQL_MAP_COL_SRC_TEXT);
        src_sql.len = knl_lob_size(src_lob);
        src_sql.str = (char *)cm_push(session->stack, src_sql.len);
        if (src_sql.str == NULL) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        if (knl_read_lob(session, src_lob, 0, src_sql.str, src_sql.len + 1, NULL) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        if (cm_text_equal(&src_sql, &sql_map->src_text.text)) {
            if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            *is_exist = GS_TRUE;
        }
        cm_pop(session->stack);
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_delete_sql_map_by_user(knl_session_t *session, uint32 uid)
{
    knl_set_session_scn((knl_handle_t)session, GS_INVALID_ID64);
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SQL_MAP_ID, IDX_SQL_MAP_002_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SQL_MAP_002_SRC_USER_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    while (!cursor->eof) {
        if (GS_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/* db implementation for resource manager */
status_t db_create_control_group(knl_session_t *session, knl_rsrc_group_t *group)
{
    uint32 max_size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;
    table_t *table = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_GROUP_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_CONTROL_GROUPS");
        return GS_ERROR;
    }
    if (db_generate_object_id(session, &group->oid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_RSRC_GROUP_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);
    (void)row_put_int32(&ra, (int32)group->oid); // oid
    (void)row_put_str(&ra, group->name);         // name
    (void)row_put_str(&ra, group->description);  // description

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        if (GS_ERRNO == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "control group", group->name);
        }
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_delete_rules_by_col(knl_session_t *session, knl_cursor_t *cursor, text_t *name, uint32 col_id)
{
    text_t text;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RSRC_PLAN_RULE_ID, GS_INVALID_ID32);

    do {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cursor->eof) {
            break;
        }

        /* plan or group */
        text.str = CURSOR_COLUMN_DATA(cursor, col_id);
        text.len = CURSOR_COLUMN_SIZE(cursor, col_id);

        if (text.str != NULL && text.len != GS_NULL_VALUE_LEN && cm_text_equal(&text, name)) {
            if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } while (GS_TRUE);

    return GS_SUCCESS;
}

status_t db_update_rsrc_plan_num_rules_by_plan_name(knl_session_t *session, knl_cursor_t *cursor, text_t *plan_name, bool8 inc_flag)
{
    uint32 num_rules;
    row_assist_t ra;
    uint16 size;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_RSRC_PLAN_ID, IX_RSRC_PLAN_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)plan_name->str, (uint16)plan_name->len, IX_COL_SYS_RSRC_PLAN001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "resource plan", T2S(plan_name));
        return GS_ERROR;
    }

    num_rules = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_COL_RULES);
    if (inc_flag) {
        num_rules++;
    } else {
        num_rules--;
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_RSRC_PLAN_COL_RULES;
    row_put_int32(&ra, num_rules);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_dec_rsrc_plan_num_rules_by_group_name(knl_session_t *session, knl_cursor_t *cursor, text_t *group_name)
{
    text_t text;
    text_t plan_name;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RSRC_PLAN_RULE_ID, GS_INVALID_ID32);

    do {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cursor->eof) {
            break;
        }

        /* get plan name by group name */
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_GROUP);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_GROUP);

        if (text.str != NULL && text.len != GS_NULL_VALUE_LEN && cm_text_equal(&text, group_name)) {
            plan_name.str = CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_PLAN);
            plan_name.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_PLAN);

            return db_update_rsrc_plan_num_rules_by_plan_name(session, cursor, &plan_name, GS_FALSE);
        }
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static status_t db_delete_group_mapping(knl_session_t *session, knl_cursor_t *cursor, text_t *group_name)
{
    text_t text;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RSRC_GROUP_MAPPING_ID, GS_INVALID_ID32);

    do {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (cursor->eof) {
            break;
        }
        /* control_group */
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_RSRC_GROUP_MAPPING_COL_GROUP);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_GROUP_MAPPING_COL_GROUP);
        if (text.len != GS_NULL_VALUE_LEN && text.str != NULL && cm_text_equal(&text, group_name)) {
            if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } while (GS_TRUE);

    return GS_SUCCESS;
}

status_t db_delete_control_group(knl_session_t *session, text_t *group_name)
{
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_GROUP_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_CONTROL_GROUPS");
        return GS_ERROR;
    }

    if (cm_text_str_equal(group_name, GS_DEFAULT_GROUP_NAME)) {
        GS_THROW_ERROR(ERR_CANNOT_MODIFY_CGROUP);
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RSRC_GROUP_ID, IX_RSRC_GROUP_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)group_name->str, (uint16)group_name->len, IX_COL_SYS_RSRC_GROUP001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "control group", T2S(group_name));
        return GS_ERROR;
    }

    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* dec plan rules num by group */
    if (db_dec_rsrc_plan_num_rules_by_group_name(session, cursor, group_name) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* delete plan rules by group */
    if (db_delete_rules_by_col(session, cursor, group_name, SYS_RSRC_PLAN_RULE_COL_GROUP) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* delete group mappings */
    if (db_delete_group_mapping(session, cursor, group_name) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_control_group(knl_session_t *session, knl_rsrc_group_t *group)
{
    text_t text;
    uint16 size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_GROUP_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_CONTROL_GROUPS");
        return GS_ERROR;
    }

    if (cm_str_equal(group->name, GS_DEFAULT_GROUP_NAME)) {
        GS_THROW_ERROR(ERR_CANNOT_MODIFY_CGROUP);
        return GS_ERROR;
    }
    cm_str2text(group->name, &text);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_RSRC_GROUP_ID, IX_RSRC_GROUP_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)text.str, (uint16)text.len, IX_COL_SYS_RSRC_GROUP001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "control group", group->name);
        return GS_ERROR;
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_RSRC_GROUP_COL_COMMENT;
    if (group->description[0] != '\0') {
        (void)row_put_str(&ra, group->description);
    } else {
        (void)row_put_null(&ra);
    }
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_insert_default_plan_rule(knl_session_t *session, const char *plan_name)
{
    errno_t errcode;
    knl_rsrc_plan_rule_def_t def = { 0 };
    const char *default_rule_comment = "Plan rule for all other operations";

    errcode = strcpy_s(def.rule.plan_name, GS_NAME_BUFFER_SIZE, plan_name);
    knl_securec_check(errcode);
    errcode = strcpy_s(def.rule.group_name, GS_NAME_BUFFER_SIZE, GS_DEFAULT_GROUP_NAME);
    knl_securec_check(errcode);
    errcode = strcpy_s(def.rule.description, GS_COMMENT_BUFFER_SIZE, default_rule_comment);
    knl_securec_check(errcode);
    def.is_comment_set = GS_TRUE;

    return db_create_rsrc_plan_rule(session, &def);
}

status_t db_create_rsrc_plan(knl_session_t *session, knl_rsrc_plan_t *plan)
{
    uint32 max_size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;
    table_t *table = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_PLAN_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_PLANS");
        return GS_ERROR;
    }
    if (db_generate_object_id(session, &plan->oid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_RSRC_PLAN_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);
    (void)row_put_int32(&ra, (int32)plan->oid); // oid
    (void)row_put_str(&ra, plan->name);         // name
    (void)row_put_int32(&ra, 0);                // num_rules
    (void)row_put_str(&ra, plan->description);  // description
    (void)row_put_int32(&ra, plan->type);       // type

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        if (GS_ERRNO == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "resource plan", plan->name);
        }
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    // insert default group rule
    if (db_insert_default_plan_rule(session, plan->name) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t db_delete_rsrc_plan(knl_session_t *session, text_t *plan_name)
{
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_PLAN_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_PLANS");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RSRC_PLAN_ID, IX_RSRC_PLAN_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)plan_name->str, (uint16)plan_name->len, IX_COL_SYS_RSRC_PLAN001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "resource plan", T2S(plan_name));
        return GS_ERROR;
    }

    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* delete plan rules by plan */
    if (db_delete_rules_by_col(session, cursor, plan_name, SYS_RSRC_PLAN_RULE_COL_PLAN) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_rsrc_plan(knl_session_t *session, knl_rsrc_plan_t *plan)
{
    text_t text;
    uint16 size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_PLAN_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_PLANS");
        return GS_ERROR;
    }
    cm_str2text(plan->name, &text);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_RSRC_PLAN_ID, IX_RSRC_PLAN_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)text.str, (uint16)text.len, IX_COL_SYS_RSRC_PLAN001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "resource plan", plan->name);
        return GS_ERROR;
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_RSRC_PLAN_COL_COMMENT;
    if (plan->description[0] != '\0') {
        (void)row_put_str(&ra, plan->description);
    } else {
        (void)row_put_null(&ra);
    }
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static void db_fill_rsrc_plan_rule_row(row_assist_t *ra, knl_rsrc_plan_rule_def_t *def)
{
    /* cpu */
    if (def->is_cpu_set) {
        (void)row_put_int32(ra, def->rule.max_cpu_limit);
    } else {
        (void)row_put_int32(ra, 0);
    }
    /* sessions */
    if (def->is_sessions_set) {
        (void)row_put_int32(ra, def->rule.max_sessions);
    } else {
        row_put_null(ra);
    }
    /* active session */
    if (def->is_active_sess_set) {
        (void)row_put_int32(ra, def->rule.max_active_sess);
    } else {
        row_put_null(ra);
    }
    /* queue time */
    if (def->is_queue_time_set) {
        (void)row_put_int32(ra, def->rule.max_queue_time);
    } else {
        row_put_null(ra);
    }
    /* max estimate exec time */
    if (def->is_exec_time_set) {
        (void)row_put_int32(ra, def->rule.max_exec_time);
    } else {
        row_put_null(ra);
    }
    /* temp pool */
    if (def->is_temp_pool_set) {
        (void)row_put_int32(ra, def->rule.max_temp_pool);
    } else {
        row_put_null(ra);
    }
    /* iops */
    if (def->is_iops_set) {
        (void)row_put_int32(ra, def->rule.max_iops);
    } else {
        row_put_null(ra);
    }
    /* commits */
    if (def->is_commits_set) {
        (void)row_put_int32(ra, def->rule.max_commits);
    } else {
        row_put_null(ra);
    }
    /* description */
    if (def->is_comment_set) {
        (void)row_put_str(ra, def->rule.description);
    } else {
        row_put_null(ra);
    }
}

static status_t db_query_rsrc_plan_by_name(knl_session_t *session, knl_cursor_t *cursor, text_t *name,
    bool32 *is_exist)
{
    knl_set_session_scn(session, GS_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RSRC_PLAN_ID, IX_RSRC_PLAN_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)name->str, (uint16)name->len, IX_COL_SYS_RSRC_PLAN001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    *is_exist = !cursor->eof;
    return GS_SUCCESS;
}

static status_t db_query_control_group_by_name(knl_session_t *session, knl_cursor_t *cursor, text_t *name,
    bool32 *is_exist)
{
    knl_set_session_scn(session, GS_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_RSRC_GROUP_ID, IX_RSRC_GROUP_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)name->str, (uint16)name->len, IX_COL_SYS_RSRC_GROUP001_NAME);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    *is_exist = !cursor->eof;
    return GS_SUCCESS;
}

static knl_rsrc_group_t g_default_group = {
    .oid = 0,
    .name = GS_DEFAULT_GROUP_NAME,
    .description = "Control group for users or tenants not assigned to any control group",
};

status_t db_create_rsrc_plan_rule(knl_session_t *session, knl_rsrc_plan_rule_def_t *def)
{
    uint32 max_size;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;
    table_t *table = NULL;
    text_t name;
    bool32 is_exist = GS_FALSE;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_PLAN_RULE_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_PLAN_RULES");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    /* check if plan exists */
    cm_str2text(def->rule.plan_name, &name);
    if (db_query_rsrc_plan_by_name(session, cursor, &name, &is_exist) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    if (!is_exist) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "resource plan", def->rule.plan_name);
        return GS_ERROR;
    }

    /* check if control group exists */
    cm_str2text(def->rule.group_name, &name);
    if (db_query_control_group_by_name(session, cursor, &name, &is_exist) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    if (!is_exist) {
        if (!cm_str_equal(def->rule.group_name, GS_DEFAULT_GROUP_NAME)) {
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "control group", def->rule.group_name);
            return GS_ERROR;
        }
        /* create default group if not exists */
        if (db_create_control_group(session, &g_default_group) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    max_size = session->kernel->attr.max_row_size;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_RSRC_PLAN_RULE_ID, GS_INVALID_ID32);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);
    (void)row_put_str(&ra, def->rule.plan_name);      // plan
    (void)row_put_str(&ra, def->rule.group_name);     // control_group

    db_fill_rsrc_plan_rule_row(&ra, def);

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        if (GS_ERRNO == ERR_DUPLICATE_KEY) {
            cm_reset_error();
            char buf[GS_T2S_BUFFER_SIZE];
            errno_t errcode = snprintf_s(buf, GS_T2S_BUFFER_SIZE, GS_T2S_BUFFER_SIZE - 1, "%s, %s",
                def->rule.plan_name, def->rule.group_name);
            knl_securec_check_ss(errcode);
            GS_THROW_ERROR(ERR_OBJECT_EXISTS, "plan rule", buf);
        }
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* inc plan rules num by plan name */
    cm_str2text(def->rule.plan_name, &name);
    if (db_update_rsrc_plan_num_rules_by_plan_name(session, cursor, &name, GS_TRUE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_delete_rsrc_plan_rule(knl_session_t *session, text_t *plan_name, text_t *group_name)
{
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_PLAN_RULE_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_PLAN_RULES");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RSRC_PLAN_RULE_ID, IX_RSRC_PLAN_RULE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)plan_name->str, (uint16)plan_name->len, IX_COL_SYS_RSRC_RULE001_PLAN);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)group_name->str, (uint16)group_name->len, IX_COL_SYS_RSRC_RULE001_GROUP);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        char buf[GS_T2S_BUFFER_SIZE];
        errno_t errcode = snprintf_s(buf, GS_T2S_BUFFER_SIZE, GS_T2S_BUFFER_SIZE - 1, "%s, %s",
            T2S(plan_name), T2S_EX(group_name));
        knl_securec_check_ss(errcode);
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "plan rule", buf);
        return GS_ERROR;
    }

    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* delete plan rules by group */
    if (db_delete_rules_by_col(session, cursor, group_name, SYS_RSRC_PLAN_RULE_COL_GROUP) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* dec plan rules num by plan name */
    if (db_update_rsrc_plan_num_rules_by_plan_name(session, cursor, plan_name, GS_FALSE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_prepare_update_rsrc_plan_rule(knl_cursor_t *cursor, knl_rsrc_plan_rule_def_t *def)
{
    uint32 size;
    text_t text;

    /* cpu */
    if (!def->is_cpu_set) {
        size = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_CPU);
        if (size != GS_NULL_VALUE_LEN) {
            def->rule.max_cpu_limit = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_CPU);
            def->is_cpu_set = GS_TRUE;
        } else {
            def->rule.max_cpu_limit = GS_DEFAULT_NULL_VALUE;
        }
    }
    if (def->rule.max_cpu_limit == GS_DEFAULT_NULL_VALUE) {
        def->is_cpu_set = GS_FALSE;
    }

    /* sessions */
    if (!def->is_sessions_set) {
        size = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_SESSIONS);
        if (size != GS_NULL_VALUE_LEN) {
            def->rule.max_sessions = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_SESSIONS);
            def->is_sessions_set = GS_TRUE;
        } else {
            def->rule.max_sessions = GS_DEFAULT_NULL_VALUE;
        }
    }
    if (def->rule.max_sessions == GS_DEFAULT_NULL_VALUE) {
        def->is_sessions_set = GS_FALSE;
    }

    /* active sessions */
    if (!def->is_active_sess_set) {
        size = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_ACTIVE_SESS);
        if (size != GS_NULL_VALUE_LEN) {
            def->rule.max_active_sess = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_ACTIVE_SESS);
            def->is_active_sess_set = GS_TRUE;
        } else {
            def->rule.max_active_sess = GS_DEFAULT_NULL_VALUE;
        }
    }
    if (def->rule.max_active_sess == GS_DEFAULT_NULL_VALUE) {
        def->is_active_sess_set = GS_FALSE;
    }

    /* queue time */
    if (!def->is_queue_time_set) {
        size = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_QUEUE_TIME);
        if (size != GS_NULL_VALUE_LEN) {
            def->rule.max_queue_time = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_QUEUE_TIME);
            def->is_queue_time_set = GS_TRUE;
        } else {
            def->rule.max_queue_time = GS_DEFAULT_NULL_VALUE;
        }
    }
    if (def->rule.max_queue_time == GS_DEFAULT_NULL_VALUE) {
        def->is_queue_time_set = GS_FALSE;
    }

    /* estimate exec time */
    if (!def->is_exec_time_set) {
        size = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_EXEC_TIME);
        if (size != GS_NULL_VALUE_LEN) {
            def->rule.max_exec_time = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_EXEC_TIME);
            def->is_exec_time_set = GS_TRUE;
        } else {
            def->rule.max_exec_time = GS_DEFAULT_NULL_VALUE;
        }
    }
    if (def->rule.max_exec_time == GS_DEFAULT_NULL_VALUE) {
        def->is_exec_time_set = GS_FALSE;
    }

    /* temp pool */
    if (!def->is_temp_pool_set) {
        size = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_TEMP_POOL);
        if (size != GS_NULL_VALUE_LEN) {
            def->rule.max_temp_pool = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_TEMP_POOL);
            def->is_temp_pool_set = GS_TRUE;
        } else {
            def->rule.max_temp_pool = GS_DEFAULT_NULL_VALUE;
        }
    }
    if (def->rule.max_temp_pool == GS_DEFAULT_NULL_VALUE) {
        def->is_temp_pool_set = GS_FALSE;
    }

    /* iops */
    if (!def->is_iops_set) {
        size = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_IOPS);
        if (size != GS_NULL_VALUE_LEN) {
            def->rule.max_iops = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_IOPS);
            def->is_iops_set = GS_TRUE;
        } else {
            def->rule.max_iops = GS_DEFAULT_NULL_VALUE;
        }
    }
    if (def->rule.max_iops == GS_DEFAULT_NULL_VALUE) {
        def->is_iops_set = GS_FALSE;
    }

    /* commits */
    if (!def->is_commits_set) {
        size = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_COMMITS);
        if (size != GS_NULL_VALUE_LEN) {
            def->rule.max_commits = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_MAX_COMMITS);
            def->is_commits_set = GS_TRUE;
        } else {
            def->rule.max_commits = GS_DEFAULT_NULL_VALUE;
        }
    }
    if (def->rule.max_commits == GS_DEFAULT_NULL_VALUE) {
        def->is_commits_set = GS_FALSE;
    }

    /* description */
    if (!def->is_comment_set) {
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RSRC_PLAN_RULE_COL_COMMENT);
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_RSRC_PLAN_RULE_COL_COMMENT);
        if (text.len != GS_NULL_VALUE_LEN && text.str != NULL) {
            if (cm_text2str(&text, def->rule.description, GS_COMMENT_SIZE + 1) != GS_SUCCESS) {
                return GS_ERROR;
            }
            def->is_comment_set = GS_TRUE;
        } else {
            def->rule.description[0] = '\0';
        }
    }
    return GS_SUCCESS;
}

status_t db_update_rsrc_plan_rule(knl_session_t *session, knl_rsrc_plan_rule_def_t *def)
{
    text_t plan_name, group_name;
    uint32 col_count;
    row_assist_t ra;
    knl_cursor_t *cursor = NULL;
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_PLAN_RULE_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_PLAN_RULES");
        return GS_ERROR;
    }
    cm_str2text(def->rule.plan_name, &plan_name);
    cm_str2text(def->rule.group_name, &group_name);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_RSRC_PLAN_RULE_ID, IX_RSRC_PLAN_RULE_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)plan_name.str, (uint16)plan_name.len, IX_COL_SYS_RSRC_RULE001_PLAN);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)group_name.str, (uint16)group_name.len, IX_COL_SYS_RSRC_RULE001_GROUP);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        cm_reset_error();
        char buf[GS_T2S_BUFFER_SIZE];
        errno_t errcode = snprintf_s(buf, GS_T2S_BUFFER_SIZE, GS_T2S_BUFFER_SIZE - 1, "%s, %s",
            def->rule.plan_name, def->rule.group_name);
        knl_securec_check_ss(errcode);
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "plan rule", buf);
        return GS_ERROR;
    }

    if (db_prepare_update_rsrc_plan_rule(cursor, def) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* update all other columns except plan & control_group */
    col_count = SYS_RSRC_PLAN_RULE_COL_COUNT - 2;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, col_count);
    cursor->update_info.count = col_count;
    for (uint32 i = 0; i < col_count; i++) {
        cursor->update_info.columns[i] = (uint16)(i + 2);
    }

    db_fill_rsrc_plan_rule_row(&ra, def);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t db_insert_cgroup_mapping(knl_session_t *session, knl_cursor_t *cursor,
    knl_rsrc_group_mapping_t *mapping)
{
    row_assist_t ra;
    table_t *table = NULL;
    uint32 max_size;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_RSRC_GROUP_MAPPING_ID, GS_INVALID_ID32);
    max_size = session->kernel->attr.max_row_size;
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);
    (void)row_put_str(&ra, mapping->attribute);  // attribute
    (void)row_put_str(&ra, mapping->value);      // value
    (void)row_put_str(&ra, mapping->group_name); // control_group

    if (knl_internal_insert(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t db_delete_cgroup_mapping(knl_session_t *session, knl_cursor_t *cursor,
                                         knl_rsrc_group_mapping_t *mapping)
{
    text_t key, value;
    cm_str2text(mapping->attribute, &key);
    cm_str2text(mapping->value, &value);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_RSRC_GROUP_MAPPING_ID, IX_RSRC_GROUP_MAPPING_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)key.str, (uint16)key.len, IX_COL_SYS_RSRC_MAPPING001_ATTRIBUTE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)value.str, (uint16)value.len, IX_COL_SYS_RSRC_MAPPING001_VALUE);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (cursor->eof) {
        return GS_SUCCESS;
    }
    if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t db_update_cgroup_mapping(knl_session_t *session, knl_cursor_t *cursor, const char *value)
{
    row_assist_t ra;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE, 1);
    cursor->update_info.count = 1;
    cursor->update_info.columns[0] = SYS_RSRC_GROUP_MAPPING_COL_GROUP;
    (void)row_put_str(&ra, value);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

    if (knl_internal_update(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t db_set_cgroup_mapping_core(knl_session_t *session, knl_rsrc_group_mapping_t *mapping)
{
    text_t key, value, group_name;
    knl_cursor_t *cursor = NULL;
    bool32 is_exist;

    cm_str2text(mapping->attribute, &key);
    cm_str2text(mapping->value, &value);

    /* check if control group exists when group name is not null */
    if (mapping->group_name[0] != '\0') {
        cm_str2text(mapping->group_name, &group_name);
        cursor = knl_push_cursor(session);
        if (db_query_control_group_by_name(session, cursor, &group_name, &is_exist) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (!is_exist) {
            if (!cm_str_equal(mapping->group_name, GS_DEFAULT_GROUP_NAME)) {
                GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "control group", mapping->group_name);
                return GS_ERROR;
            }
        }
    }

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_RSRC_GROUP_MAPPING_ID, IX_RSRC_GROUP_MAPPING_001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)key.str, (uint16)key.len, IX_COL_SYS_RSRC_MAPPING001_ATTRIBUTE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING,
        (void *)value.str, (uint16)value.len, IX_COL_SYS_RSRC_MAPPING001_VALUE);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->eof) {
        if (mapping->group_name[0] != '\0') {
            return db_insert_cgroup_mapping(session, cursor, mapping);
        }
    } else {
        if (mapping->group_name[0] != '\0') {
            return db_update_cgroup_mapping(session, cursor, mapping->group_name);
        } else {
            return db_delete_cgroup_mapping(session, cursor, mapping);
        }
    }

    return GS_SUCCESS;
}

status_t db_set_cgroup_mapping(knl_session_t *session, knl_rsrc_group_mapping_t *mapping)
{
    dc_user_t *sys_user = NULL;

    if (dc_open_user_by_id(session, DB_SYS_USER_ID, &sys_user) != GS_SUCCESS ||
        DC_GET_ENTRY(sys_user, SYS_RSRC_GROUP_MAPPING_ID) == NULL) {
        GS_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, "SYS", "SYS_RSRC_GROUP_MAPPINGS");
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    status_t status = db_set_cgroup_mapping_core(session, mapping);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t db_clean_all_shadow_indexes(knl_session_t *session)
{
    core_ctrl_t *core = &session->kernel->db.ctrl.core;
    knl_cursor_t *cursor = NULL;
    index_t index;
    status_t status;
    dc_entry_t *entry = NULL;
    dc_user_t *user = NULL;
    space_t *space = NULL;
    bool32 is_nologging_table = GS_FALSE;
    errno_t err;

    if (DB_IS_READONLY(session) || !core->build_completed) {
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    knl_set_session_scn(session, GS_INVALID_ID64);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SHADOW_INDEX_ID, GS_INVALID_ID32);

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (cursor->eof) {
            status = GS_SUCCESS;
            break;
        }

        err = memset_sp(&index, sizeof(index_t), 0, sizeof(index_t));
        knl_securec_check(err);
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);
        dc_convert_index(session, cursor, &index.desc);
        dc_set_index_accessor((table_t *)cursor->table, &index);

        if (dc_open_user_by_id(session, index.desc.uid, &user) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        entry = DC_GET_ENTRY(user, index.desc.table_id);

        if (dc_locked_by_xa(session, entry)) {
            GS_LOG_RUN_WAR("skip dc clean shadow indexes for table ID(%u)", index.desc.table_id);
            continue;
        }

        space = SPACE_GET(index.desc.space_id);
        is_nologging_table = SPACE_IS_NOLOGGING(space) ? GS_TRUE : GS_FALSE;
        if (is_nologging_table) {
            index.desc.entry = INVALID_PAGID;
            GS_LOG_RUN_WAR("dc clean shadow indexes found nologging table ID(%u)", index.desc.table_id);
        }

        btree_drop_segment(session, &index);
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            status = GS_SUCCESS;
            break;
        }

        if (index.desc.parted) {
            if (db_drop_shadow_indexpart(session, index.desc.uid, index.desc.table_id,
                                         !is_nologging_table) != GS_SUCCESS) {
                status = GS_SUCCESS;
                break;
            }
        }
    }

    knl_commit(session);

    if (db_clean_all_shadow_indexparts(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return status;
}

static status_t db_delete_table_segments(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    table_t *table = DC_TABLE(dc);

    if (dc->type == DICT_TYPE_TEMP_TABLE_SESSION || dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        knl_temp_cache_t *temp_table = knl_get_temp_cache(session, dc->uid, dc->oid);
        if (temp_table != NULL) {
            knl_free_temp_vm(session, temp_table);
        }
    } else if (dc->type == DICT_TYPE_TABLE_EXTERNAL) {
        if (db_drop_external_table(session, cursor, table) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (db_drop_table_segments(session, dc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_drop_table(knl_session_t *session, knl_dictionary_t *dc)
{
    knl_comment_def_t comment_def;
    rd_drop_table_t redo;
    obj_info_t obj_addr;

    if (rb_purge_drop_related(session, dc->uid, dc->oid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;

    if (GS_SUCCESS != db_delete_from_systable(session, cursor, table->desc.uid, table->desc.name)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (table->desc.is_nologging) {
        if (db_update_nologobj_cnt(session, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (table->desc.storaged && db_delete_from_sysstorage(session, cursor, table->desc.org_scn) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_delete_columns(session, cursor, table->desc.uid, table->desc.id)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (table->desc.parted) {
        if (GS_SUCCESS != db_drop_part_table(session, cursor, table->part_table)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (table->desc.compress) {
        if (db_delete_from_syscompress(session, cursor, table->desc.org_scn) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (entity->contain_lob) {
        if (GS_SUCCESS != db_delete_from_syslob(session, cursor, entity->table.desc.uid,
            entity->table.desc.id, GS_INVALID_INT32)) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (GS_SUCCESS != db_delete_from_sysindex(session, cursor, table->desc.uid, table->desc.id, GS_INVALID_ID32)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_drop_all_cons(session, table->desc.uid, table->desc.id, GS_FALSE)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

#ifdef Z_SHARDING
    (void)db_delete_distribute_strategy(session, table);
#endif

    comment_def.type = COMMENT_ON_TABLE;
    comment_def.uid = table->desc.uid;
    comment_def.id = table->desc.id;

    if (GS_SUCCESS != db_delete_comment(session, &comment_def)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != stats_drop_hists(session, table->desc.uid, table->desc.id, 
        IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type))) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != db_delete_mon_sysmods(session, table->desc.uid, table->desc.id, GS_INVALID_ID32, GS_FALSE)) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_delete_table_segments(session, cursor, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_check_policies_before_delete(session, table->desc.name, table->desc.uid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* drop all the table privilege granted to users and roles */
    if (db_drop_object_privs(session, table->desc.uid, table->desc.name, OBJ_TYPE_TABLE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_clean_shadow_index(session, dc->uid, dc->oid, GS_TRUE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* to avoid deadlock, need update status first, before delete trigger */
    obj_addr.oid = dc->oid;
    obj_addr.uid = dc->uid;
    obj_addr.tid = OBJ_TYPE_TABLE;
    if (g_knl_callback.update_depender(session, &obj_addr) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (g_knl_callback.pl_db_drop_triggers(session, (void *)dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && LOGIC_REP_TABLE_ENABLED(session, entity);
    redo.op_type = RD_DROP_TABLE;
    redo.purge = GS_TRUE;
    redo.uid = table->desc.uid;
    redo.oid = table->desc.id;
    errno_t err = strcpy_sp(redo.name, GS_NAME_BUFFER_SIZE, table->desc.name);
    knl_securec_check(err);
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_drop_table_t),
            has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE);

    SYNC_POINT(session, "SP_B1_DROP_TABLE");

    knl_commit(session);

    if (db_garbage_segment_handle(session, dc->uid, dc->oid, GS_FALSE) != GS_SUCCESS) {
        cm_spin_lock(&session->kernel->rmon_ctx.mark_mutex, NULL);
        session->kernel->rmon_ctx.delay_clean_segments = GS_TRUE;
        cm_spin_unlock(&session->kernel->rmon_ctx.mark_mutex);
        GS_LOG_RUN_ERR("failed to handle garbage segment");
    }

    // Send rd log to drop trigger
    g_knl_callback.pl_drop_triggers_entry(session, dc);

    // Only after transaction committed, can dc be dropped.
    dc_drop_object_privs(&session->kernel->dc_ctx, table->desc.uid, table->desc.name, OBJ_TYPE_TABLE);
    dc_drop(session, DC_ENTITY(dc));
    CM_RESTORE_STACK(session->stack);

    session->stat.table_drops++;
    return GS_SUCCESS;
}

status_t db_delete_dist_rules_by_user(knl_session_t *session, uint32 uid)
{
    uint32 oid;
    knl_set_session_scn((knl_handle_t)session, GS_INVALID_ID64);
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_cursor_t *sub_cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_DISTRIBUTE_RULE_ID, IX_SYS_DISTRIBUTE_RULE003_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_SYS_DISTRIBUTE_RULE003_UID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    while (!cursor->eof) {
        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        oid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_DISTRIBUTE_RULE_COL_ID);
        if (db_delete_columns((knl_session_t *)session, sub_cursor, uid, oid) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_get_storage_desc(knl_session_t *session, knl_storage_desc_t *storage_desc, knl_scn_t org_scn)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_STORAGE_ID, IX_STORAGE_001_ID);

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_BIGINT, (void *)&org_scn,
        sizeof(uint64), IX_COL_SYS_STORAGE_ORGSCN);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    storage_desc->initial = (CURSOR_COLUMN_SIZE(cursor, SYS_STORAGE_COL_INITIAL_PAGES) != GS_NULL_VALUE_LEN) ?
        (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_STORAGE_COL_INITIAL_PAGES)) : 0;

    storage_desc->max_pages = (CURSOR_COLUMN_SIZE(cursor, SYS_STORAGE_COL_MAX_PAGES) != GS_NULL_VALUE_LEN) ?
        (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_STORAGE_COL_MAX_PAGES)) : 0;

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_update_part_index_status(knl_session_t *session, index_t *index, bool32 is_invalid, bool32 *is_changed)
{
    if (!IS_PART_INDEX(index)) {
        return GS_SUCCESS;
    }

    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    table_part_t *table_part = NULL;
    table_t *table = &index->entity->table;

    // local index on partition table
    for (uint32 id = 0; id < index->part_index->desc.partcnt; id++) {
        index_part = INDEX_GET_PART(index, id);
        table_part = TABLE_GET_PART(table, id);
        // in case of whole if partition is extended: [p1][p1][0x00][0x00][sys-400]
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }

        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            if (is_invalid) {
                if (btree_part_segment_prepare(session, index_part, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            if (db_update_idxpart_status(session, index_part, is_invalid, is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }
            continue;
        }
        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            if (is_invalid) {
                if (btree_part_segment_prepare(session, index_subpart,
                    GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }

            if (db_update_sub_idxpart_status(session, index_subpart, is_invalid, is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t db_do_index_subpart_unusable(knl_session_t *session, index_part_t *index_subpart)
{
    bool32 is_changed = GS_FALSE;

    if (btree_part_segment_prepare(session, index_subpart, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_sub_idxpart_status(session, index_subpart, GS_TRUE, &is_changed) != GS_SUCCESS) {
        return GS_ERROR;
    }
 
    return GS_SUCCESS;
}

static status_t db_do_index_part_unusable(knl_session_t *session, index_t *index, index_part_t *index_part)
{
    index_part_t *index_subpart = NULL;
    bool32 is_changed = GS_FALSE;

    if (IS_PARENT_IDXPART(&index_part->desc)) {
        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            if (db_do_index_subpart_unusable(session, index_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        return GS_SUCCESS;
    }

    if (btree_part_segment_prepare(session, index_part, GS_FALSE, BTREE_DROP_PART_SEGMENT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_idxpart_status(session, index_part, GS_TRUE, &is_changed) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t db_alter_index_unusable(knl_session_t *session, index_t *index)
{
    bool32 is_changed = GS_FALSE;

    if (IS_PART_INDEX(index)) {
        if (db_update_part_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (btree_segment_prepare(session, index, GS_FALSE, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_update_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_alter_index_part_unusable(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc, 
    index_t *index, bool32 is_subpart)
{   
    if (!IS_PART_INDEX(index)) {
        GS_THROW_ERROR(ERR_MODIFY_PART_INDEX);
        return GS_ERROR;
    }
    index_part_t *index_part = NULL;

    if (is_subpart) {
        if (subpart_index_find_by_name(index->part_index, &def->mod_idxpart.part_name, &index_part)) {
            return db_do_index_subpart_unusable(session, index_part);
        }
    } else {
        if (part_index_find_by_name(index->part_index, &def->mod_idxpart.part_name, &index_part)) {
            return db_do_index_part_unusable(session, index, index_part);
        }
    }

    GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->mod_idxpart.part_name));
    return GS_ERROR;
}

static status_t db_alter_index_subpart_initrans(knl_session_t *session, index_t *index,
    index_part_t *index_part, uint32 initrans)
{
    index_part_t *index_subpart = NULL;

    if (!IS_PARENT_IDXPART(&index_part->desc)) {
        return GS_SUCCESS;
    }

    for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
        index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[i]);
        if (index_subpart == NULL) {
            continue;
        }
        if (db_update_index_subpart_initrans(session, &index_subpart->desc, initrans) != GS_SUCCESS) {
            return GS_ERROR;
        }
        btree_set_initrans(session, &index_subpart->btree, initrans);
    }

    return GS_SUCCESS;
}

status_t db_alter_index_initrans(knl_session_t *session, knl_alindex_def_t *def, index_t *index)
{
    uint32 initrans = def->idx_def.initrans;
    table_part_t *table_part = NULL;
    index_part_t *index_part = NULL;

    if (db_update_index_initrans(session, &index->desc, initrans) != GS_SUCCESS) {
        return GS_ERROR;
    }
    btree_set_initrans(session, &index->btree, initrans);

    if (!IS_PART_INDEX(index)) {
        return GS_SUCCESS;
    }

    for (uint32 id = 0; id < index->part_index->desc.partcnt; ++id) {
        table_part = TABLE_GET_PART(&index->entity->table, id);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        index_part = INDEX_GET_PART(index, id);
        if (db_update_index_part_initrans(session, &index_part->desc, initrans) != GS_SUCCESS) {
            return GS_ERROR;
        }
        btree_set_initrans(session, &index_part->btree, initrans);

        if (db_alter_index_subpart_initrans(session, index, index_part, initrans) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t db_alter_index_part_initrans(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *index)
{
    table_t *table = DC_TABLE(dc);
    index_part_t *index_part = NULL;
    uint32 initrans = def->mod_idxpart.initrans;

    if (!IS_PART_TABLE(table) || !IS_PART_INDEX(index)) {
        GS_THROW_ERROR(ERR_MODIFY_PART_INDEX);
        return GS_ERROR;
    }

    if (!part_index_find_by_name(index->part_index, &def->mod_idxpart.part_name, &index_part)) {
        GS_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "index", T2S(&def->mod_idxpart.part_name));
        return GS_ERROR;
    }

    if (db_update_index_part_initrans(session, &index_part->desc, initrans) != GS_SUCCESS) {
        return GS_ERROR;
    }
    btree_set_initrans(session, &index_part->btree, initrans);

    if (db_alter_index_subpart_initrans(session, index, index_part, initrans) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t db_alter_index_partition(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *index)
{
    status_t status;

    switch (def->mod_idxpart.type) {
        case MODIFY_IDXPART_INITRANS:
            status = db_alter_index_part_initrans(session, def, dc, index);
            break;
        case MODIFY_IDXPART_UNUSABLE:
            status = db_alter_index_part_unusable(session, def, dc, index, GS_FALSE);
            break;
        default:
            GS_THROW_ERROR(ERR_INVALID_OPERATION, ",unsupported alter index operation");
            status = GS_ERROR;
    }
    return status;
}

status_t db_alter_index_subpartition(knl_session_t *session, knl_alindex_def_t *def, knl_dictionary_t *dc,
    index_t *index)
{
    status_t status;

    switch (def->mod_idxpart.type) {
        case MODIFY_IDXSUBPART_UNUSABLE:
            status = db_alter_index_part_unusable(session, def, dc, index, GS_TRUE);
            break;
        default:
            GS_THROW_ERROR(ERR_INVALID_OPERATION, ",unsupported alter index operation");
            status = GS_ERROR;
    }

    return status;
}

status_t db_check_table_nologging_attr(table_t *table)
{
    if (SECUREC_UNLIKELY(table->desc.is_nologging) && !IS_PART_TABLE(table)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "update, delete or others DDL on the table with nologging insert \
attribute");
        return GS_ERROR;
    }

    if (!IS_PART_TABLE(table)) {
        return GS_SUCCESS;
    }

    table_part_t *table_part = NULL;
    table_part_t *subpart = NULL;
    part_table_t *part_table = table->part_table;
    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (SECUREC_UNLIKELY(table_part->desc.is_nologging)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "update, delete or others DDL on the table with nologging insert \
attribute");
            return GS_ERROR;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            continue;
        }

        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            subpart = PART_GET_SUBENTITY(part_table, table_part->subparts[j]);
            if (subpart == NULL) {
                continue;
            }

            if (SECUREC_UNLIKELY(subpart->desc.is_nologging)) {
                GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "update, delete or others DDL on the table with nologging \
insert attribute");
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

status_t db_write_syscompress(knl_session_t *session, knl_cursor_t *cursor, uint32 space_id, uint64 org_scn, 
    uint32 compress_mode, compress_object_type_t obj_type)
{
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_COMPRESS_ID, GS_INVALID_ID32);

    row_init(&ra, (char *)cursor->row, session->kernel->attr.max_row_size, SYS_COMPRESS_COLUMN_COUNT);
    (void)row_put_int64(&ra, org_scn);
    (void)row_put_int32(&ra, (int32)compress_mode);
    (void)row_put_int32(&ra, (int32)obj_type);

    return knl_internal_insert(session, cursor);
}

status_t db_delete_from_syscompress(knl_session_t *session, knl_cursor_t *cursor, uint64 org_scn)
{
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_COMPRESS_ID, IX_SYSCOMPRESS001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER, (void *)&org_scn, 
        sizeof(uint64), IX_COL_SYSCOMPRESS001_ORGSCN);

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (knl_internal_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t db_get_compress_algo(knl_session_t *session, uint8 *compress_mode, uint64 org_scn)
{
    if (!DB_IS_OPEN(session)) {
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_COMPRESS_ID, IX_SYSCOMPRESS001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_BIGINT, (void *)&org_scn,
                     sizeof(uint64), IX_COL_SYSCOMPRESS001_ORGSCN);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return GS_SUCCESS;
    }

    *compress_mode = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_COMPRESS_COL_ALGO);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t db_truncate_sys_table(knl_session_t *session, uint32 table_id)
{
    knl_dictionary_t dc;
    table_t *table = NULL;
    status_t status;
    rd_table_t redo;
    bool32 is_changed = GS_FALSE;

    db_get_sys_dc(session, table_id, &dc);

    if (GS_SUCCESS != lock_table_directly(session, &dc, session->kernel->attr.ddl_lock_timeout)) {
        return GS_ERROR;
    }

    table = DC_TABLE(&dc);
    if (db_table_is_referenced(session, table, GS_TRUE)) {
        unlock_tables_directly(session);
        GS_THROW_ERROR(ERR_TABLE_IS_REFERENCED);
        return GS_ERROR;
    }

    /* reset serial value */
    if (knl_reset_serial_value(session, dc.handle) != GS_SUCCESS) {
        unlock_tables_directly(session);
        return GS_ERROR;
    }

    if (dc.type == DICT_TYPE_TABLE || dc.type == DICT_TYPE_TABLE_NOLOGGING) {
        if (!db_table_has_segment(session, &dc)) {
            unlock_tables_directly(session);
            return GS_SUCCESS;
        }
    }

    // when the state(is_invalid) of global index is changed, the flag is_changed will be set to GS_TRUE
    status = db_truncate_table_prepare(session, &dc, GS_FALSE, &is_changed);

    if (status == GS_SUCCESS) {
        SYNC_POINT(session, "SP_B1_TRUNCATE_TABLE");
        knl_commit(session);
        if (db_garbage_segment_handle(session, dc.uid, dc.oid, GS_FALSE) != GS_SUCCESS) {
            GS_LOG_DEBUG_ERR("failed to handle garbage segment");
        }
        SYNC_POINT(session, "SP_B2_TRUNCATE_TABLE");

        log_atomic_op_begin(session);
        redo.op_type = RD_ALTER_TABLE;
        redo.uid = dc.uid;
        redo.oid = dc.oid;
        if (IS_LOGGING_TABLE_BY_TYPE(dc.type)) {
            log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_table_t), LOG_ENTRY_FLAG_NONE);
        }
        log_atomic_op_end(session);
        knl_commit(session);
    } else {
        knl_rollback(session, NULL);
    }

    db_update_seg_scn(session, &dc);
    unlock_tables_directly(session);
    return status;
}

static status_t db_write_index_sysinfo(knl_session_t *session, knl_index_def_t *def, index_t *index, 
    knl_cursor_t *cursor, knl_dictionary_t *dc)
{
    table_t *table = DC_TABLE(dc);
    knl_index_desc_t *desc = &index->desc;
    desc->is_cons = GS_FALSE;
    desc->is_enforced = GS_FALSE;
    desc->is_func = GS_FALSE;

    if (db_verify_index_def(session, dc, def, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_write_sysindex(session, cursor, desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_update_index_count(session, cursor, &table->desc, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_PART_INDEX(index)) {
        if (!IS_COMPART_TABLE(table->part_table) && def->part_def != NULL && def->part_def->is_composite) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create composite partition index",
                           "non composite partition table");
            return GS_ERROR;
        }

        if (db_create_part_index(session, cursor, index, def->part_def) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t db_fill_indexes_paral(knl_session_t *session, knl_dictionary_t *dc, idxpart_paral_ctx_t *paral_ctx,
    uint32 paral_num)
{
    db_prepare_part_ctx(session, &paral_num, paral_ctx);
    if (paral_ctx->paral_count * paral_ctx->index_cnt > MAX_IDX_PARAL_THREADS) {
        paral_ctx->paral_count = MAX_IDX_PARAL_THREADS / paral_ctx->index_cnt;
    }

    /* alloc parallelism resource */
    if (idxpart_alloc_resource(session, paral_num, paral_ctx) != GS_SUCCESS) {
        idxpart_release_resource(paral_num, paral_ctx);
        return GS_ERROR;
    }

    /* waiting all threads ended */
    uint32 working_cnt;
    for (;;) {
        working_cnt = paral_num;
        for (uint32 i = 0; i < paral_num; i++) {
            if (!paral_ctx->workers[i].is_working) {
                working_cnt--;
            }

            if (paral_ctx->workers[i].thread.result != GS_SUCCESS) {
                GS_THROW_ERROR(ERR_BUILD_INDEX_PARALLEL, paral_ctx->err_msg);
                idxpart_release_resource(paral_num, paral_ctx);
                return GS_ERROR;
            }
        }

        if (working_cnt == 0) {
            break;
        }

        if (knl_check_session_status(session) != GS_SUCCESS) {
            idxpart_release_resource(paral_num, paral_ctx);
            return GS_ERROR;
        }
        
        cm_sleep(100);
    }

    idxpart_release_resource(paral_num, paral_ctx);
    return GS_SUCCESS;
}

static status_t db_fill_part_indexes(knl_session_t *session, knl_dictionary_t *dc, knl_indexes_def_t *def, 
    index_t **indexes, uint32 index_cnt)
{
    table_t *table = DC_TABLE(dc);
    uint32 segment_cnt;

    for (uint32 i = 0; i < index_cnt; i++) {
        segment_cnt = 0;
        if (db_create_all_btree_segments(session, table, indexes[i], &segment_cnt) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (segment_cnt == 0) {
        return GS_SUCCESS;
    }

    idxpart_paral_ctx_t paral_ctx;
    errno_t err = memset_sp(&paral_ctx, sizeof(idxpart_paral_ctx_t), 0, sizeof(idxpart_paral_ctx_t));
    knl_securec_check(err);

    paral_ctx.private_dc = dc;
    paral_ctx.indexes = indexes;
    paral_ctx.index_cnt = index_cnt;
    paral_ctx.part_info.seg_count = segment_cnt;
    uint32 paral_num = def->indexes_def[0].parallelism;
    if (db_fill_indexes_paral(session, dc, &paral_ctx, paral_num) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t db_fill_indexes(knl_session_t *session, knl_table_desc_t *desc, uint32 *index_ids, uint32 index_cnt,
    knl_indexes_def_t *def)
{
    knl_dictionary_t dc;

    if (dc_open_table_private(session, desc->uid, desc->id, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    index_t **indexes = (index_t **)cm_push(session->stack, sizeof(index_t *) * index_cnt);
    for (uint32 i = 0; i < index_cnt; i++) {
        indexes[i] = dc_find_index_by_id((dc_entity_t *)dc.handle, index_ids[i]);
        if (indexes[i] == NULL) {
            dc_close_table_private(&dc);
            GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "index", index_ids[i]);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    dc_load_all_part_segments(session, dc.handle);
    if (IS_PART_INDEX(indexes[0])) {
        if (db_fill_part_indexes(session, &dc, def, indexes, index_cnt) != GS_SUCCESS) {
            dc_close_table_private(&dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    } else {
        bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(dc.type);
        knl_part_locate_t part_loc = { 0, 0 };
        for (uint32 i = 0; i < index_cnt; i++) {
            if (db_create_btree_segment(session, indexes[i], NULL, &indexes[i]->btree, need_redo) != GS_SUCCESS) {
                dc_close_table_private(&dc);
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        if (db_fill_multi_indexes_paral(session, &dc, indexes, index_cnt, def->indexes_def[0].parallelism, 
            part_loc) != GS_SUCCESS) {
            dc_close_table_private(&dc);
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }


    dc_close_table_private(&dc);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static void db_alloc_index_ids(dc_entity_t *entity, uint32 *ids, uint32 index_cnt)
{
    index_t *index = NULL;
    uint8 map[GS_MAX_TABLE_INDEXES];

    errno_t err = memset_sp(map, GS_MAX_TABLE_INDEXES, 0, GS_MAX_TABLE_INDEXES);
    knl_securec_check(err);

    for (uint32 i = 0; i < entity->table.index_set.total_count; i++) {
        index = entity->table.index_set.items[i];
        map[index->desc.id] = 1;
    }

    uint32 redy_cnt = 0;
    for (uint32 i = 0; i < GS_MAX_TABLE_INDEXES; i++) {
        if (map[i] == 0) {
            ids[redy_cnt++] = i;
        }

        if (redy_cnt >= index_cnt) {
            break;
        }
    }
}

status_t db_create_indexes(knl_session_t *session, knl_indexes_def_t *def, knl_dictionary_t *dc)
{
    index_t index;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);
    
    CM_SAVE_STACK(session->stack);
    uint32 *index_ids = cm_push(session->stack, sizeof(uint32) * def->index_count);
    knl_cursor_t *cursor = knl_push_cursor(session);
    db_alloc_index_ids(entity, index_ids, def->index_count);
    for (uint32 i = 0; i < def->index_count; i++) {
        errno_t ret = memset_sp(&index, sizeof(index_t), 0, sizeof(index_t));
        knl_securec_check(ret);
        index.entity = entity;
        index.desc.id = index_ids[i];
        if (db_write_index_sysinfo(session, &def->indexes_def[i], &index, cursor, dc) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    if (db_fill_indexes(session, &table->desc, index_ids, def->index_count, def) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

