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
 * knl_space.c
 *    kernel space manager
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/tablespace/knl_space.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_space.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_kmc.h"
#include "knl_table.h"
#include "knl_context.h"
#include "dc_user.h"
#include "knl_sys_part_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPC_OBJ_TYPE_COUNT (uint32)(sizeof(g_spc_obj_fetch_list) / sizeof(spc_obj_fetch_t))
#define SPC_CLEAN_OPTION (TABALESPACE_INCLUDE | TABALESPACE_DFS_AND | TABALESPACE_CASCADE)
#define SPACE_FILE_PER_LINE (uint32)(80)

#define SPACE_VIEW_WAIT_INTERVAL    100
#define SPACE_DDL_WAIT_INTERVAL     5

#define SPC_PUNCH_EXTENT_ONCE 16       // punch 16 extents once
#define SPACE_PUNCH_CKPT_INTERVAL 4096

typedef status_t (*spc_check_func)(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
typedef struct st_spc_obj_fetch {
    uint16 sys_tbl_id;  // relevant system table id
    uint16 spc_col_id;  // column id in system table of space id
    spc_check_func check_func;  // check objects relation in space
} spc_obj_fetch_t;

status_t spc_check_systable_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sysindex_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_syslob_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sys_tablepart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sys_indexpart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sys_lobpart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_shadow_index_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_shadow_index_part_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sys_partstore_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
bool32 spc_try_free_extent_list(knl_session_t *session, space_t *space);

static spc_obj_fetch_t g_spc_obj_fetch_list[] = {
    { SYS_TABLE_ID,            SYS_TABLE_COL_SPACE_ID, spc_check_systable_objects},
    { SYS_INDEX_ID,            SYS_INDEX_COLUMN_ID_SPACE, spc_check_sysindex_objects},
    { SYS_LOB_ID,              SYS_LOB_COL_SPACE_ID, spc_check_syslob_objects},
    { SYS_TABLEPART_ID,        SYS_TABLEPART_COL_SPACE_ID, spc_check_sys_tablepart_objects},
    { SYS_INDEXPART_ID,        SYS_INDEXPART_COL_SPACE_ID, spc_check_sys_indexpart_objects},
    { SYS_LOBPART_ID,          SYS_LOBPART_COL_SPACE_ID, spc_check_sys_lobpart_objects},
    { SYS_SHADOW_INDEX_ID,     SYS_SHADOW_INDEX_COL_SPACE_ID, spc_check_shadow_index_objects},
    { SYS_SHADOW_INDEXPART_ID, SYS_SHADOW_INDEXPART_COL_SPACE_ID, spc_check_shadow_index_part_objects},
    { SYS_PARTSTORE_ID,        SYS_PARTSTORE_COL_SPACE_ID, spc_check_sys_partstore_objects},
    { SYS_RB_ID,               SYS_RECYCLEBIN_COL_SPACE_ID, NULL},
    { SYS_SUB_TABLE_PARTS_ID,  SYS_TABLESUBPART_COL_SPACE_ID, spc_check_sys_tablepart_objects},
    { SYS_SUB_INDEX_PARTS_ID,  SYS_INDEXSUBPART_COL_SPACE_ID, spc_check_sys_indexpart_objects},
    { SYS_SUB_LOB_PARTS_ID,    SYS_LOBSUBPART_COL_SPACE_ID,   spc_check_sys_lobpart_objects}
};

static status_t spc_create_memory_space(knl_session_t *session, space_t *space)
{
    return GS_ERROR;
}

static inline void spc_init_page_list(page_list_t *page_list)
{
    page_list->count = 0;
    page_list->first = INVALID_PAGID;
    page_list->last = INVALID_PAGID;
}

void spc_unlock_space(space_t *space)
{
    cm_spin_unlock(&space->lock);
}

bool32 spc_try_lock_space(knl_session_t *session, space_t *space, uint32 wait_time, const char *operation)
{
    for (;;) {
        if (SECUREC_UNLIKELY(session->canceled)) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_FALSE;
        }

        if (SECUREC_UNLIKELY(session->killed)) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_FALSE;
        }

        if (SECUREC_UNLIKELY(!SPACE_IS_ONLINE(space))) {
            GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, operation);
            return GS_FALSE;
        }

        if (cm_spin_try_lock(&space->lock)) {
            break;
        }
        cm_sleep(wait_time);
    }
    return GS_TRUE;
}

bool32 spc_view_try_lock_space(knl_session_t *session, space_t *space, const char *operation)
{
    return spc_try_lock_space(session, space, SPACE_VIEW_WAIT_INTERVAL, operation);
}

/*
 * check whether exists objects in space or not when dropping space online
 * see spc_fetch_obj_list to obtain all object types to be checked
 */
status_t spc_check_object_exist(knl_session_t *session, space_t *space)
{
    uint32 space_id = 0;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    for (uint32 i = 0; i < SPC_OBJ_TYPE_COUNT; i++) {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, g_spc_obj_fetch_list[i].sys_tbl_id, GS_INVALID_ID32);
        cursor->isolevel = ISOLATION_CURR_COMMITTED;

        for (;;) {
            if (knl_fetch(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (cursor->eof) {
                break;
            }

            space_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, g_spc_obj_fetch_list[i].spc_col_id));
            if (space_id == space->ctrl->id) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }
        
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/*
 * get space id of given user id and object id
 * @param kernel session, user id , object id , space id (return)
 */
status_t spc_get_table_space_id(knl_session_t *session, uint32 uid, uint32 oid, uint32 *space_id)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&uid, sizeof(uint32), 0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&oid, sizeof(uint32), 1);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    *space_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_SPACE_ID));
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/*
 * get space id of given compart
 * @param kernel session, user id , table id , part id, space id (return)
 */
status_t spc_get_compart_space_id(knl_session_t *session, uint32 uid, uint32 table_id, uint32 part_id,
    uint32 *space_id)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&uid, sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&table_id, sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&part_id, sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    *space_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_SPACE_ID));
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/*
 * check whether space to be dropped is user's default tablespace or tenant's usable tablespace
 */
status_t spc_check_default_tablespace(knl_session_t *session, space_t *space)
{
    knl_cursor_t *cursor = NULL;
    knl_user_desc_t desc;
    knl_tenant_desc_t tenant_desc;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_ID, GS_INVALID_ID32);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        dc_convert_user_desc(cursor, &desc);
        if (desc.data_space_id == space->ctrl->id) {
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name, "it's the default tablespace for user");
            return GS_ERROR;
        }
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TENANTS_ID, GS_INVALID_ID32);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    CM_MAGIC_SET(&tenant_desc, knl_tenant_desc_t);
    while (!cursor->eof) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        dc_convert_tenant_desc(cursor, &tenant_desc);
        if (tenant_desc.id != SYS_TENANTROOT_ID) {
            if (dc_get_tenant_tablespace_bitmap(&tenant_desc, space->ctrl->id)) {
                CM_RESTORE_STACK(session->stack);
                GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name, "it's the usable tablespace for tenant");
                return GS_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t spc_check_systable_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_table_desc_t desc;
    knl_dictionary_t dc;
    table_t *table = NULL;
    bool32 is_referenced = GS_FALSE;
    knl_drop_def_t def;
    bool32 is_found = GS_FALSE;
    errno_t ret;

    dc_convert_table_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        ret = memset_sp(&def, sizeof(knl_drop_def_t), 0, sizeof(knl_drop_def_t));
        knl_securec_check(ret);
        knl_get_user_name(session, desc.uid, &def.owner);
        cm_str2text(desc.name, &def.name);
        if (knl_open_dc_if_exists(session, &def.owner, &def.name, &dc, &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (is_found) {
            table = DC_TABLE(&dc);
            is_referenced = db_table_is_referenced(session, table, GS_FALSE);
            if (is_referenced && !SPC_DROP_CASCADE(options)) {
                GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name, "table in the space is referenced");
                knl_close_dc(&dc);
                return GS_ERROR;
            }
            knl_close_dc(&dc);
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_sysindex_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    uint32 table_space_id;
    knl_index_desc_t desc;

    dc_convert_index(session, cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "index of table in the space was created in other space");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_syslob_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_lob_desc_t desc;
    uint32 table_space_id;

    dc_convert_lob_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of lob column is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_sys_tablepart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_table_part_desc_t desc;
    uint32 table_space_id;

    dc_convert_table_part_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of (sub)partition is not in the same tablespace");
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

status_t spc_check_sys_indexpart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_index_part_desc_t desc;
    uint32 table_space_id;

    dc_convert_index_part_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of index (sub)partition is not in the same tablespace");
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

status_t spc_check_sys_lobpart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_lob_part_desc_t desc;
    uint32 table_space_id;

    dc_convert_lob_part_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of lob column is not in the same tablespace");
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

status_t spc_check_sys_partstore_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_part_store_desc_t desc;
    uint32 table_space_id;

    dc_convert_part_store_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of pos id is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_shadow_index_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_index_desc_t desc;
    uint32 table_space_id;

    dc_convert_index(session, cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of shadow index is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_shadow_index_part_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_index_part_desc_t desc;
    uint32 table_space_id;

    dc_convert_index_part_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of shadow index (sub)part is not in the same tablespace");
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

status_t spc_drop_sys_table_objects(knl_session_t *session, space_t *space, uint32 options)
{
    knl_cursor_t *cursor = NULL;
    uint32 space_id;
    knl_drop_def_t def;
    knl_table_desc_t desc;
    errno_t ret;

    knl_set_session_scn(session, GS_INVALID_ID64);
    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, GS_INVALID_ID32);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        space_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_SPACE_ID));
        if (space_id == space->ctrl->id) {
            ret = memset_sp(&def, sizeof(knl_drop_def_t), 0, sizeof(knl_drop_def_t));
            knl_securec_check(ret);
            dc_convert_table_desc(cursor, &desc);
            def.purge = GS_TRUE;

            if (SPC_DROP_CASCADE(options)) {
                def.options |= DROP_CASCADE_CONS;
            }

            if (knl_get_user_name(session, desc.uid, &def.owner) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            cm_str2text(desc.name, &def.name);
            if (knl_internal_drop_table(session, &def) != GS_SUCCESS) {
                int code = cm_get_error_code();
                if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
                    cm_reset_error();  // table dropped by other session, continue drop table space
                } else {
                    CM_RESTORE_STACK(session->stack);
                    GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name, "failed to drop object");
                    return GS_ERROR;
                }
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t spc_drop_sys_rb_objects(knl_session_t *session, space_t *space)
{
    return rb_purge_space(session, space->ctrl->id);
}

// record and set in memory, do not record redo
static inline void spc_try_set_swap_bitmap(knl_session_t *session, space_t *space)
{
    space->swap_bitmap = (IS_SWAP_SPACE(space) && SPACE_ATTR_SWAP_BITMAP);
}

// if change this func, plz change func spc_punch_check_normalspc_invaild
status_t spc_punch_check_space_invaild(knl_session_t *session, space_t *space)
{
    if (SPACE_IS_DEFAULT(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "punch tablespace", "default tablespace");
        return GS_ERROR;
    }

    if (SPACE_IS_ENCRYPT(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "punch tablespace", "ENCRYPT tablespace");
        return GS_ERROR;
    }

    if (IS_UNDO_SPACE(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "punch tablespace", "undo tablespace");
        return GS_ERROR;
    }

    if (IS_TEMP_SPACE(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "punch tablespace", "temp tablespace");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void spc_update_head(knl_session_t *session, space_t *space, datafile_t *df)
{
    bool32 need_init_punch = GS_FALSE;

    /* if this is the first datafile in space , we need to initialize space head */
    if (df->file_no == 0) {
        buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT | ENTER_PAGE_NO_READ);
        knl_panic(space->ctrl->file_hwm == 1);
        space->head = SPACE_HEAD;
        page_init(session, (page_head_t *)CURR_PAGE, space->entry, PAGE_TYPE_SPACE_HEAD);
        errno_t ret = memset_sp(space->head, sizeof(space_head_t), 0, sizeof(space_head_t));
        knl_securec_check(ret);
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
        need_init_punch = spc_try_init_punch_head(session, space);
    } else {
        buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    }
    /* double write will init dbc_init_doublewrite() */
    space->head->hwms[df->file_no] = spc_get_hwm_start(session, space, df);

    space->head->datafile_count++;

    spc_try_set_swap_bitmap(session, space);

    if (!IS_SWAP_SPACE(space)) {
        rd_update_head_t redo;
        redo.entry = space->entry;
        redo.space_id = (uint16)df->space_id;  // max space_id is 1023
        redo.file_no = (uint16)df->file_no;    // max file_no is 1022
        log_put(session, RD_SPC_UPDATE_HEAD, &redo, sizeof(rd_update_head_t), LOG_ENTRY_FLAG_NONE);
        if (need_init_punch) {
            log_put(session, RD_SPC_PUNCH_EXTENTS, &SPACE_PUNCH_HEAD_PTR(space)->punching_exts,
                sizeof(rd_punch_extents_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    buf_leave_page(session, GS_TRUE);
}

status_t spc_create_datafile_precheck(knl_session_t *session, space_t *space, knl_device_def_t *def)
{
    uint32 i = 0;
    uint32 used_count = 0;
    datafile_t *df = NULL;
    datafile_t *new_df = NULL;
    char buf[GS_MAX_FILE_NAME_LEN];

    (void)cm_text2str(&def->name, buf, GS_MAX_FILE_NAME_LEN - 1);

    if (cm_file_exist(buf)) {
        GS_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, buf);
        return GS_ERROR;
    }

    for (i = 0; i < GS_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(i);
        if (df->ctrl->used) {
            if (cm_text_str_equal(&def->name, df->ctrl->name)) {
                GS_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, df->ctrl->name);
                return GS_ERROR;
            }
            used_count++;
            continue;
        } 

        if (new_df == NULL) {
            new_df = df;
        }
    }

    if (used_count >= GS_MAX_DATA_FILES) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_DATA_FILES, "datafiles");
        return GS_ERROR;
    }

    for (i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            break;
        }
    }

    if (i >= GS_MAX_SPACE_FILES || new_df == NULL) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_SPACE_FILES, "space");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline status_t spc_precheck_create_parameter(knl_session_t *session, space_t *space,
                                                     knl_device_def_t *def, int64 max_file_size)
{
    if (def->compress) {
        if (!IS_USER_SPACE(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "non user tablespace");
            return GS_ERROR;
        }

        if (!SPACE_IS_BITMAPMANAGED(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "normal tablespace");
            return GS_ERROR;
        }

        if (IS_TEMP_SPACE(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "temp tablespace");
            return GS_ERROR;
        }

        if (SPACE_IS_NOLOGGING(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "nologging tablespace");
            return GS_ERROR;
        }

        if (SPACE_IS_ENCRYPT(space)) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "create compress datafile", "encrypt tablespace");
            return GS_ERROR;
        }
    }

    if (def->size > max_file_size) {
        GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "SIZE", T2S(&(def->name)));
        return GS_ERROR;
    }

    if (!def->autoextend.enabled) {
        return GS_SUCCESS;
    }

    if (def->autoextend.nextsize > max_file_size) {
        GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "NEXT SIZE", T2S(&(def->name)));
        return GS_ERROR;
    }

    if (def->autoextend.maxsize > max_file_size) {
        GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "MAXSIZE", T2S(&(def->name)));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline void spc_clean_untraced_datafile(knl_session_t *session, char *file_name)
{
    if (cm_file_exist(file_name)) {
        if (cm_remove_file(file_name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[SPACE] failed to remove datafile %s", file_name);
        }
    }
}

void spc_set_datafile_autoextend(knl_session_t *session, datafile_t *df, knl_autoextend_def_t *def)
{
    if (def->enabled) {
        DATAFILE_SET_AUTO_EXTEND(df);
        // If user does not gei next size, parse ddl will set it to 0
        if (def->nextsize == 0) {
            // If df's auto_extend_size is also 0, set DEFAULD AUTOEXTEND SIZE, otherwise, do nothing
            if (df->ctrl->auto_extend_size == 0) {
                df->ctrl->auto_extend_size = DF_DEFAULD_AUTOEXTEND_SIZE;
            }
        } else {
            df->ctrl->auto_extend_size = def->nextsize;
        }
    } else {
        DATAFILE_UNSET_AUTO_EXTEND(df);
        // if set auto extend off, set size to 0
        df->ctrl->auto_extend_size = 0;
    }

    if (def->maxsize == 0) {
        // If df's auto_extend_maxsize is also 0, set MAX SIZE, otherwise, do nothing
        if (df->ctrl->auto_extend_maxsize == 0) {
            // max file size is not more than 8T
            space_t *space = SPACE_GET(df->space_id);
            df->ctrl->auto_extend_maxsize = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE;
        }
    } else {
        df->ctrl->auto_extend_maxsize = def->maxsize;
    }
}

status_t spc_create_datafile(knl_session_t *session, space_t *space, knl_device_def_t *def, uint32 *file_no)
{
    rd_create_datafile_t *redo = NULL;
    uint32 i = 0;
    uint32 used_count = 0;
    datafile_t *new_df = NULL;
    database_t *db = &session->kernel->db;
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;
    uint64 min_file_size;

    min_file_size = spc_get_datafile_minsize_byspace(session, space);

    if ((uint64)def->size < min_file_size) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "size value is smaller than minimum(%llu) required", min_file_size);
        return GS_ERROR;
    }

    // Acquire a free slot in database datafile list.
    for (i = 0; i < GS_MAX_DATA_FILES; i++) {
        datafile_t *df = DATAFILE_GET(i);
        if (df->ctrl->used) {
            if (cm_text_str_equal(&def->name, df->ctrl->name)) {
                GS_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, df->ctrl->name);
                return GS_ERROR;
            }
            used_count++;
            continue;
        }

        if (new_df == NULL) {
            new_df = df;
            new_df->ctrl->id = i;
        }
    }

    if (used_count >= GS_MAX_DATA_FILES) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_DATA_FILES, "datafiles");
        return GS_ERROR;
    }

    // Acquire a free slot in current space datafile list.
    for (i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            break;
        }
    }

    if (i >= GS_MAX_SPACE_FILES || new_df == NULL) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_SPACE_FILES, "space");
        return GS_ERROR;
    }

    // max_file_size is less than 2^30 * 2^13
    uint64 max_file_size = (uint64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE;
    if (spc_precheck_create_parameter(session, space, def, (int64)max_file_size) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (i >= space->ctrl->file_hwm) {
        space->ctrl->file_hwm++;
    }

    log_atomic_op_begin(session);

    new_df->ctrl->block_size = space->ctrl->block_size;
    knl_panic(new_df->ctrl->block_size != 0);
    new_df->ctrl->size = def->size;
    (void)cm_text2str(&def->name, new_df->ctrl->name, GS_FILE_NAME_BUFFER_SIZE);
    new_df->space_id = space->ctrl->id;

    // reset df autoextend and max size to avoid get deleted info
    new_df->ctrl->auto_extend_size = 0;
    new_df->ctrl->auto_extend_maxsize = 0;
    spc_set_datafile_autoextend(session, new_df, &def->autoextend);

    if (cm_file_exist(new_df->ctrl->name)) {
        log_atomic_op_end(session);
        GS_THROW_ERROR(ERR_FILE_HAS_EXIST, new_df->ctrl->name);
        GS_LOG_RUN_ERR("[SPACE] failed to build datafile %s, file is already existed.", new_df->ctrl->name);
        return GS_ERROR;
    }

    if (spc_build_datafile(session, new_df, DATAFILE_FD(new_df->ctrl->id)) != GS_SUCCESS) {
        log_atomic_op_end(session);
        spc_clean_untraced_datafile(session, new_df->ctrl->name);
        GS_LOG_RUN_ERR("[SPACE] failed to build datafile %s", new_df->ctrl->name);
        return GS_ERROR;
    }

    if (spc_open_datafile(session, new_df, DATAFILE_FD(new_df->ctrl->id)) != GS_SUCCESS) {
        log_atomic_op_end(session);
        spc_clean_untraced_datafile(session, new_df->ctrl->name);
        GS_LOG_RUN_ERR("[SPACE] datafile %s break down, try to offline it in MOUNT mode", new_df->ctrl->name);
        return GS_ERROR;
    }

    if (spc_init_datafile_head(session, new_df) != GS_SUCCESS) {
        log_atomic_op_end(session);
        spc_clean_untraced_datafile(session, new_df->ctrl->name);
        cm_close_device(new_df->ctrl->type, DATAFILE_FD(new_df->ctrl->id));
        return GS_ERROR;
    }

    if (session->kernel->db.status >= DB_STATUS_MOUNT) {
        if (cm_add_file_watch(rmon_ctx->watch_fd, new_df->ctrl->name, &new_df->wd) != GS_SUCCESS) {
            GS_LOG_RUN_WAR("[RMON]: failed to add monitor of datafile %s", new_df->ctrl->name);
        }
    }

    new_df->file_no = i;
    new_df->ctrl->used = GS_TRUE;
    new_df->ctrl->create_version++;
    new_df->ctrl->punched = GS_FALSE;
    new_df->ctrl->unused = 0;
    if (def->compress) {
        DATAFILE_SET_COMPRESS(new_df);
    } else {
        DATAFILE_UNSET_COMPRESS(new_df);
    }
    DATAFILE_SET_ONLINE(new_df);

    space->ctrl->files[i] = new_df->ctrl->id;
    *file_no = new_df->ctrl->id;
    if (i == 0) {
        space->entry.file = space->ctrl->files[0];
        space->entry.page = SPACE_ENTRY_PAGE;
    }
    db->ctrl.core.device_count++;

    redo = (rd_create_datafile_t *)cm_push(session->stack, sizeof(rd_create_datafile_t));
    redo->id = new_df->ctrl->id;
    redo->space_id = new_df->space_id;
    redo->file_no = new_df->file_no;
    redo->size = (uint64)new_df->ctrl->size;
    redo->auto_extend_size = new_df->ctrl->auto_extend_size;
    errno_t ret = strcpy_sp(redo->name, GS_FILE_NAME_BUFFER_SIZE, new_df->ctrl->name);
    knl_securec_check(ret);
    redo->auto_extend_maxsize = new_df->ctrl->auto_extend_maxsize;
    redo->flags = new_df->ctrl->flag;
    redo->type = new_df->ctrl->type;
    redo->reserve = 0;

    log_put(session, RD_SPC_CREATE_DATAFILE, redo, sizeof(rd_create_datafile_t), LOG_ENTRY_FLAG_NONE);

    cm_pop(session->stack);

    if (SECUREC_UNLIKELY(IS_SWAP_SPACE(space))) {
        if (SPACE_ATTR_SWAP_BITMAP) {
            df_init_swap_map_head(session, new_df);
        }
    } else if (SPACE_CTRL_IS_BITMAPMANAGED(space)) {
        df_init_map_head(session, new_df);
    }

    spc_update_head(session, space, new_df);
    log_atomic_op_end(session);

    if (db_save_datafile_ctrl(session, new_df->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file when space create datafiles");
    }

    return GS_SUCCESS;
}

static inline bool32 spc_contain_datafile(space_ctrl_t *ctrl, uint32 file_id)
{
    for (uint32 i = 0; i < ctrl->file_hwm; ++i) {
        if (file_id == ctrl->files[i]) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

status_t spc_drop_datafile(knl_session_t *session, space_t *space, knl_device_def_t *def)
{
    datafile_t *df = NULL;
    uint32 i = 0;
    uint32 empty_hwm;

    for (i = 0; i < GS_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(i);
        if (df->ctrl->used && cm_text_str_equal(&def->name, df->ctrl->name) &&
            spc_contain_datafile(space->ctrl, i)) {
            break;
        }
    }

    if (i == GS_MAX_DATA_FILES || df == NULL) {
        GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "data", T2S(&def->name));
        return GS_ERROR;
    }

    if (!DATAFILE_IS_ONLINE(df)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "remove datafile failed");
        return GS_ERROR;
    }

    empty_hwm = SPACE_IS_BITMAPMANAGED(space) ? DF_MAP_HWM_START : DF_HWM_START;
    if (df->file_no != 0 && SPACE_HEAD_RESIDENT(space)->hwms[df->file_no] == empty_hwm) {
        if (spc_remove_datafile(session, space, df->ctrl->id, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_DATAFILE_HAS_BEEN_USED, T2S(&def->name), space->ctrl->name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

bool32 spc_valid_space_object(knl_session_t *session, uint32 space_id)
{
    space_t *space = SPACE_GET(space_id);

    if (SPACE_IS_DEFAULT(space)) {
        return GS_TRUE;
    }

    if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t spc_alter_precheck_datafile_autoextend(knl_session_t *session, space_t *space,
                                                       knl_autoextend_def_t *autoextend)
{
    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "set space autoextend");
        return GS_ERROR;
    }

    if (!autoextend->enabled) {
        return GS_SUCCESS;
    }

    // max_file_size is less than 2^30 * 2^13
    int64 max_file_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE;
    for (uint32 i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        datafile_t *df = DATAFILE_GET(space->ctrl->files[i]);

        if (autoextend->maxsize > max_file_size) {
            GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "MAXSIZE", space->ctrl->name);
            return GS_ERROR;
        }

        if (autoextend->maxsize != 0 && autoextend->maxsize < df->ctrl->size) {
            GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "MAXSIZE", space->ctrl->name);
            return GS_ERROR;
        }

        if (autoextend->nextsize > max_file_size) {
            GS_THROW_ERROR(ERR_DATAFILE_SIZE_NOT_ALLOWED, "NEXTSIZE", space->ctrl->name);
            return GS_ERROR;
        }

        if (df_alter_datafile_precheck_autoextend(session, df, autoextend)) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t spc_set_autoextend(knl_session_t *session, space_t *space, knl_autoextend_def_t *autoextend)
{
    datafile_t *df = NULL;
    rd_set_space_autoextend_t redo;

    cm_spin_lock(&space->lock, &session->stat_space);

    if (spc_alter_precheck_datafile_autoextend(session, space, autoextend) != GS_SUCCESS) {
        cm_spin_unlock(&space->lock);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);

    for (uint32 i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[i]);
        spc_set_datafile_autoextend(session, df, autoextend);

        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space set autoextend");
        }
    }

    redo.op_type = RD_SPC_SET_AUTOEXTEND;
    redo.space_id = (uint16)space->ctrl->id;  // space id is less than 1023
    redo.auto_extend = DATAFILE_IS_AUTO_EXTEND(df);
    redo.auto_extend_size = df->ctrl->auto_extend_size;
    redo.auto_extend_maxsize = df->ctrl->auto_extend_maxsize;

    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_set_space_autoextend_t), LOG_ENTRY_FLAG_NONE);

    log_atomic_op_end(session);

    cm_spin_unlock(&space->lock);
    return GS_SUCCESS;
}

status_t spc_set_autooffline(knl_session_t *session, space_t *space, bool32 auto_offline)
{
    rd_set_space_flag_t redo;

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "set tablespace autooffline");
        return GS_ERROR;
    }

    cm_spin_lock(&space->lock, &session->stat_space);

    if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        cm_spin_unlock(&space->lock);
        GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tablespace", space->ctrl->id);
        return GS_ERROR;
    }

    if (SPACE_IS_DEFAULT(space)) {
        cm_spin_unlock(&space->lock);
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",forbid to set system space auto offline");
        return GS_ERROR;
    }

    log_atomic_op_begin(session);

    if (!auto_offline) {
        SPACE_UNSET_AUTOOFFLINE(space);
    } else {
        SPACE_SET_AUTOOFFLINE(space);
    }

    redo.op_type = RD_SPC_SET_FLAG;
    redo.space_id = (uint16)space->ctrl->id;  // the maximum space id is 1023
    redo.flags = space->ctrl->flag;

    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_set_space_flag_t), LOG_ENTRY_FLAG_NONE);

    log_atomic_op_end(session);
    cm_spin_unlock(&space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space set autooffline");
    }

    return GS_SUCCESS;
}

void spc_offline_space_files(knl_session_t *session, uint32 *files, uint32 file_hwm)
{
    datafile_t *df = NULL;
    uint32 i;

    for (i = 0; i < file_hwm; i++) {
        if (files[i] == GS_INVALID_ID32) {
            continue;
        }
        df = DATAFILE_GET(files[i]);
        GS_LOG_RUN_INF("[SPACE] set datafile %s offline", df->ctrl->name);
        DATAFILE_UNSET_ONLINE(df);
    }
}

status_t spc_offline_datafile(knl_session_t *session, space_t *space, knl_device_def_t *def)
{
    datafile_t *df = NULL;
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;
    uint32 file_id;
    uint32 i;

    for (i = 0; i < space->ctrl->file_hwm; i++) {
        file_id = space->ctrl->files[i];
        if (GS_INVALID_ID32 == file_id) {
            continue;
        }

        df = DATAFILE_GET(file_id);
        if (!cm_text_str_equal(&def->name, df->ctrl->name)) {
            continue;
        }
        GS_LOG_RUN_INF("[SPACE] set datafile %s offline, space is %s ", df->ctrl->name, space->ctrl->name);
        DATAFILE_UNSET_ONLINE(df);
        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space offline datafiles");
        }

        /* remove datafile from resource monitor */
        if (cm_file_exist(df->ctrl->name)) {
            if (cm_rm_file_watch(rmon_ctx->watch_fd, &df->wd) != GS_SUCCESS) {
                GS_LOG_RUN_WAR("[RMON]: failed to remove monitor of datafile %s", df->ctrl->name);
            }
        }

        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_OFFLINE_DATAFILE_NOT_EXIST, T2S(&def->name), space->ctrl->name);
    return GS_ERROR;
}

status_t spc_offline_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles)
{
    knl_device_def_t *file = NULL;

    if (!cm_spin_try_lock(&session->kernel->lock)) {
        GS_THROW_ERROR(ERR_DB_START_IN_PROGRESS);
        return GS_ERROR;
    }

    if (session->kernel->db.status != DB_STATUS_MOUNT) {
        cm_spin_unlock(&session->kernel->lock);
        GS_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "offline datafile");
        return GS_ERROR;
    }

    if (SPACE_IS_DEFAULT(space)) {
        cm_spin_unlock(&session->kernel->lock);
        GS_THROW_ERROR(ERR_OFFLINE_WRONG_SPACE, space->ctrl->name);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < datafiles->count; i++) {
        file = (knl_device_def_t *)cm_galist_get(datafiles, i);
        if (spc_offline_datafile(session, space, file) != GS_SUCCESS) {
            cm_spin_unlock(&session->kernel->lock);
            return GS_ERROR;
        }
    }

    cm_spin_unlock(&session->kernel->lock);
    return GS_SUCCESS;
}

status_t spc_create_datafiles(knl_session_t *session, space_t *space, knl_altspace_def_t *def)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    galist_t *datafiles = &def->datafiles;
    knl_device_def_t *file = NULL;
    uint32 file_no;
    bool32 need_extend_undo = GS_FALSE;

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "create datafile");
        return GS_ERROR;
    }

    if (def->undo_segments > 0) {
        if (!DB_IS_RESTRICT(session)) {
            GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
            return GS_ERROR;
        }
        if (space->ctrl->id != core_ctrl->undo_space) {
            GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in current undo space");
            return GS_ERROR;
        }

        need_extend_undo = GS_TRUE;
    }  

    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "add datafile failed");
        return GS_ERROR;
    }

    cm_spin_lock(&space->lock, &session->stat_space);
    for (uint32 i = 0; i < datafiles->count; i++) {
        file = (knl_device_def_t *)cm_galist_get(datafiles, i);
        if (spc_create_datafile(session, space, file, &file_no) != GS_SUCCESS) {
            cm_spin_unlock(&space->lock);
            return GS_ERROR;
        }
    }
    cm_spin_unlock(&space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (DB_TO_RECOVERY(session) && IS_USER_SPACE(space)) {
        ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    }

    if (need_extend_undo) {
        datafile_t *new_df = DATAFILE_GET(file_no);

        knl_panic(datafiles->count == 1);

        if (spc_extend_undo_segments(session, def->undo_segments, new_df) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t spc_extend_undo_segments(knl_session_t *session, uint32 count, datafile_t *df)
{
    uint32 space_id = DB_CORE_CTRL(session)->undo_space;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);
    uint32 undo_segments = core_ctrl->undo_segments;
    char seg_count[GS_MAX_UINT32_STRLEN] = { 0 };
    rd_extend_undo_segments_t rd;
    errno_t ret;

    if (undo_df_create(session, space_id, undo_segments, undo_segments + count, df) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    rd.old_undo_segments = undo_segments;
    rd.undo_segments = undo_segments + count;
    core_ctrl->undo_segments = rd.undo_segments;
    core_ctrl->undo_segments_extended = GS_TRUE;

    log_atomic_op_begin(session);
    log_put(session, RD_SPC_EXTEND_UNDO_SEGMENTS, &rd, sizeof(rd_extend_undo_segments_t), LOG_ENTRY_FLAG_NONE);
    log_atomic_op_end(session);
    log_commit(session);

    if (db_save_core_ctrl(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ret = sprintf_s(seg_count, GS_MAX_UINT32_STRLEN, "%d", core_ctrl->undo_segments);
    knl_securec_check_ss(ret);
    if (cm_alter_config(session->kernel->attr.config, "_UNDO_SEGMENTS", seg_count, CONFIG_SCOPE_BOTH, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[SPACE] extend undo segments from %u to %u completed", rd.old_undo_segments, rd.undo_segments);

    return GS_SUCCESS;
}

status_t spc_drop_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles)
{
    knl_device_def_t *file = NULL;

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "drop datafile");
        return GS_ERROR;
    }

    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "drop datafile failed");
        return GS_ERROR;
    }

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    cm_spin_lock(&space->lock, &session->stat_space);

    for (uint32 i = 0; i < datafiles->count; i++) {
        file = (knl_device_def_t *)cm_galist_get(datafiles, i);
        if (spc_drop_datafile(session, space, file) != GS_SUCCESS) {
            cm_spin_unlock(&space->lock);
            return GS_ERROR;
        }
    }

    cm_spin_unlock(&space->lock);

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    return GS_SUCCESS;
}

bool32 spc_check_space_exists(knl_session_t *session, const text_t *name)
{
    space_t *space = NULL;
    uint32 i = 0;

    for (i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(i);
        if (!space->ctrl->used) {
            continue;
        }

        if (cm_text_str_equal(name, space->ctrl->name)) {
            break;
        }
    }

    return i >= GS_MAX_SPACES ? GS_FALSE : GS_TRUE;
}

status_t spc_rename_space(knl_session_t *session, space_t *space, text_t *rename_space)
{
    char buf[GS_NAME_BUFFER_SIZE];
    rd_rename_space_t redo;
    uint32 name_len = GS_NAME_BUFFER_SIZE - 1;
    errno_t ret;
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "rename space");
        return GS_ERROR;
    }

    if (space->ctrl->id == core_ctrl->temp_undo_space ||
        space->ctrl->id == core_ctrl->sysaux_space ||
        space->ctrl->id == core_ctrl->system_space ||
        space->ctrl->id == core_ctrl->undo_space) {
        GS_THROW_ERROR_EX(ERR_INVALID_OPERATION, ", can't rename %s tablespace.", space->ctrl->name);
        return GS_ERROR;
    }

    (void)cm_text2str(rename_space, buf, GS_NAME_BUFFER_SIZE);
    if (spc_check_space_exists(session, rename_space)) {
        GS_THROW_ERROR(ERR_SPACE_ALREADY_EXIST, T2S(rename_space));
        return GS_ERROR;
    }

    log_atomic_op_begin(session);
    cm_spin_lock(&space->lock, &session->stat_space);

    ret = strncpy_s(space->ctrl->name, GS_NAME_BUFFER_SIZE, buf, name_len);
    knl_securec_check(ret);
    space->ctrl->name[rename_space->len] = 0;

    redo.op_type = RD_SPC_RENAME_SPACE;
    redo.space_id = space->ctrl->id;
    ret = strcpy_sp(redo.name, GS_NAME_BUFFER_SIZE, space->ctrl->name);
    knl_securec_check(ret);

    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_rename_space_t), LOG_ENTRY_FLAG_NONE);

    cm_spin_unlock(&space->lock);
    log_atomic_op_end(session);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when rename space");
    }

    return GS_SUCCESS;
}

/*
 * rename a space datafile
 */
status_t spc_rename_datafile(knl_session_t *session, space_t *space, text_t *name, text_t *new_name)
{
    datafile_t *tmp_df = NULL;
    datafile_t *df = NULL;
    uint32 i;
    uint32 id = GS_INVALID_ID32;
    uint32 file_name_len = GS_MAX_FILE_NAME_LEN - 1;
    char buf[GS_MAX_FILE_NAME_LEN];
    errno_t ret;

    for (i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[i]);
        if (df->ctrl->used) {
            if (cm_text_str_equal_ins(new_name, df->ctrl->name)) {
                GS_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, T2S(new_name));
                return GS_ERROR;
            }
            if (cm_text_str_equal_ins(name, df->ctrl->name)) {
                tmp_df = df;
                id = space->ctrl->files[i];
            }
        }
    }

    if (tmp_df == NULL) {
        GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "data", T2S(name));
        return GS_ERROR;
    }

    spc_close_datafile(tmp_df, DATAFILE_FD(id));
    (void)cm_text2str(new_name, buf, GS_MAX_FILE_NAME_LEN);

    if (cm_file_exist(buf)) {
        GS_THROW_ERROR(ERR_FILE_ALREADY_EXIST, buf, "failed to rename datafile");
        return GS_ERROR;
    }

    if (cm_rename_file(tmp_df->ctrl->name, buf) != 0) {
        GS_THROW_ERROR(ERR_RENAME_FILE, tmp_df->ctrl->name, buf, errno);
        return GS_ERROR;
    }

    ret = strncpy_s(tmp_df->ctrl->name, GS_FILE_NAME_BUFFER_SIZE, buf, file_name_len);
    knl_securec_check(ret);

    if (db_save_datafile_ctrl(session, tmp_df->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file when space rename datafiles");
    }

    return GS_SUCCESS;
}

status_t spc_rename_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles, galist_t *new_datafiles)
{
    knl_device_def_t *file = NULL;
    knl_device_def_t *new_file = NULL;

    if (!cm_spin_try_lock(&session->kernel->lock)) {
        GS_THROW_ERROR(ERR_DB_START_IN_PROGRESS);
        return GS_ERROR;
    }

    if (session->kernel->db.status != DB_STATUS_MOUNT) {
        cm_spin_unlock(&session->kernel->lock);
        GS_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "rename datafiles");
        return GS_ERROR;
    }

    if (!SPACE_IS_ONLINE(space)) {
        cm_spin_unlock(&session->kernel->lock);
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "rename datafiles failed");
        return GS_ERROR;
    }

    if (spc_mount_space(session, space, GS_FALSE) != GS_SUCCESS) {
        cm_spin_unlock(&session->kernel->lock);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < datafiles->count; i++) {
        file = (knl_device_def_t *)cm_galist_get(datafiles, i);
        new_file = (knl_device_def_t *)cm_galist_get(new_datafiles, i);
        if (cm_text_equal_ins(&file->name, &new_file->name)) {
            continue;
        }

        if (spc_rename_datafile(session, space, &file->name, &new_file->name) != GS_SUCCESS) {
            cm_spin_unlock(&session->kernel->lock);
            return GS_ERROR;
        }
    }

    spc_umount_space(session, space);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space rename datafiles");
    }

    cm_spin_unlock(&session->kernel->lock);

    return GS_SUCCESS;
}

static inline bool32 spc_datafile_exist(space_t *space, datafile_t *df, uint32 id)
{
    if (!DATAFILE_IS_ONLINE(df)) {
        return GS_TRUE;
    }

    if (!df->ctrl->used) {
        return GS_FALSE;
    }

    if (space->ctrl->file_hwm == 0 || (!DF_FILENO_IS_INVAILD(df) && space->ctrl->files[df->file_no] != id)) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

status_t spc_remove_mount_datafile(knl_session_t *session, space_t *space, uint32 id, uint32 options)
{
    datafile_t *df = NULL;

    df = DATAFILE_GET(id);
    if (!spc_datafile_exist(space, df, id)) {
        GS_THROW_ERROR(ERR_DATAFILE_NUMBER_NOT_EXIST, id);
        return GS_ERROR;
    }

    if (!DF_FILENO_IS_INVAILD(df)) {
        space->ctrl->files[df->file_no] = GS_INVALID_ID32;
    }

    if (DATAFILE_IS_ONLINE(df)) {
        spc_invalidate_datafile(session, df, GS_TRUE);

        if (SPC_DROP_DATAFILE(options)) {
            if (cm_remove_device(df->ctrl->type, df->ctrl->name) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else {
        if (SPC_DROP_DATAFILE(options)) {
            GS_LOG_RUN_INF("[SPACE] datafile %s is offline, skip drop the file in disk", df->ctrl->name);
        }
    }

    DATAFILE_UNSET_ONLINE(df);
    df->space_id = GS_INVALID_ID32;
    df->ctrl->size = 0;
    df->ctrl->name[0] = '\0';
    df->ctrl->used = GS_FALSE;
    df->file_no = GS_INVALID_ID32;
    df->ctrl->flag = 0;

    if (db_save_datafile_ctrl(session, id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file when remove datafiles");
    }

    GS_LOG_RUN_INF("[SPACE] space %s remove mount datafile %s success", space->ctrl->name, df->ctrl->name);
    return GS_SUCCESS;
}

status_t spc_remove_datafile(knl_session_t *session, space_t *space, uint32 id, bool32 drop_datafile)
{
    database_t *db = &session->kernel->db;
    datafile_t *df = DATAFILE_GET(id);

    if (DATAFILE_IS_ONLINE(df) &&
        (space->ctrl->file_hwm == 0 || !df->ctrl->used || space->ctrl->files[df->file_no] != id)) {
        GS_THROW_ERROR(ERR_DATAFILE_NUMBER_NOT_EXIST, id);
        return GS_ERROR;
    }

    ckpt_disable(session);

    rd_remove_datafile_t *redo = (rd_remove_datafile_t *)cm_push(session->stack, sizeof(rd_remove_datafile_t));
    redo->id = id;
    redo->file_no = df->file_no;
    redo->space_id = df->space_id;

    log_atomic_op_begin(session);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    space->head->datafile_count--;
    space->head->hwms[df->file_no] = 0;
    log_put(session, RD_SPC_REMOVE_DATAFILE, redo, sizeof(rd_remove_datafile_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
    log_commit(session);
    cm_pop(session->stack);

    space->ctrl->files[df->file_no] = GS_INVALID_ID32;
    db->ctrl.core.device_count--;

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control space ctrl when remove datafile");
    }

    DATAFILE_UNSET_ONLINE(df);
    df->ctrl->used = GS_FALSE;

    if (db_save_datafile_ctrl(session, id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save the part of control datafile ctrl when remove datafile");
    }

    spc_invalidate_datafile(session, df, GS_FALSE);

    if (drop_datafile) {
        if (cm_remove_device(df->ctrl->type, df->ctrl->name) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("[DB] failed to remove datafile %s from space %s", df->ctrl->name, space->ctrl->name);
            return GS_ERROR;
        }
    }

    spc_remove_datafile_info(session, df, id);

    ckpt_enable(session);
    
    GS_LOG_RUN_INF("[SPACE] space %s remove datafile %s success", space->ctrl->name, df->ctrl->name);
    return GS_SUCCESS;
}

void spc_remove_datafile_info(knl_session_t *session, datafile_t *df, uint32 id)
{
    df->space_id = GS_INVALID_ID32;
    df->ctrl->size = 0;
    df->ctrl->name[0] = '\0';
    df->file_no = GS_INVALID_ID32;

    if (db_save_datafile_ctrl(session, id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control datafile ctrl when remove datafile");
    }
}

void spc_remove_datafile_device(knl_session_t *session, datafile_t *df)
{
    errno_t ret;
    if (cm_file_exist(df->ctrl->name)) {
        spc_invalidate_datafile(session, df, GS_TRUE);
        if (GS_SUCCESS != cm_remove_device(df->ctrl->type, df->ctrl->name)) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to remove device when remove datafile");
        }
    } else {
        ret = sprintf_s(df->ctrl->name, GS_FILE_NAME_BUFFER_SIZE, "%s.delete", df->ctrl->name);
        knl_securec_check_ss(ret);
        if (cm_file_exist(df->ctrl->name)) {
            if (GS_SUCCESS != cm_remove_device(df->ctrl->type, df->ctrl->name)) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to remove device when remove datafile");
            }
        }
    }
}

static void spc_wait_buffer_loaded(knl_session_t *session, space_t *space, buf_ctrl_t *ctrl)
{
    datafile_t *df = NULL;
    uint32 times = 0;

    df = DATAFILE_GET(ctrl->page_id.file);
    if (df->space_id == space->ctrl->id) {
        /* wait for page to be released */
        while (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
            knl_try_begin_session_wait(session, READ_BY_OTHER_SESSION, GS_TRUE);
            times++;
            if (times > GS_SPIN_COUNT) {
                times = 0;
                SPIN_STAT_INC(&session->stat_page, r_sleeps);
                cm_spin_sleep();
            }
        }
        knl_try_end_session_wait(session, READ_BY_OTHER_SESSION);
    }
}

/*
 * wait for loading of space page in data buffer
 * so that we can close fd correctly in the following
 * @note caller must guarantee the space has been offlined.
 * @param kernel session , space to be removed
 */
void spc_wait_data_buffer(knl_session_t *session, space_t *space)
{
    buf_context_t *ctx = &session->kernel->buf_ctx;
    buf_set_t *buf_set = NULL;
    buf_ctrl_t *buf_ctrl = NULL;
    uint32 i, j;

    for (i = 0; i < ctx->buf_set_count; i++) {
        buf_set = &ctx->buf_set[i];
        for (j = 0; j < buf_set->hwm; j++) {
            buf_ctrl = &buf_set->ctrls[j];
            spc_wait_buffer_loaded(session, space, buf_ctrl);
        }
    }
}

/*
 * space remove space
 * 1.wait for completion of visit of space page in data buffer
 * 2.remove datafiles and reset relevant info in space
 * 3.reset relevant space info
 */
status_t spc_remove_space(knl_session_t *session, space_t *space, uint32 options, bool32 ignore_error)
{
    database_t *db = &session->kernel->db;
    uint32 i;
    errno_t ret;

    for (i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        if (spc_remove_mount_datafile(session, space, space->ctrl->files[i], options) != GS_SUCCESS) {
            if (!ignore_error) {
                return GS_ERROR;
            }
        }
    }

    buf_expire_page(session, space->entry);
    space->is_empty = GS_FALSE;
    space->alarm_enabled = GS_FALSE;
    space->allow_extend = GS_FALSE;
    space->entry = INVALID_PAGID;
    space->swap_bitmap = GS_FALSE;
    space->head = NULL;
    space->ctrl->file_hwm = 0;
    space->ctrl->name[0] = '\0';
    space->ctrl->used = GS_FALSE;
    space->ctrl->org_scn = GS_INVALID_ID64;
    space->ctrl->flag = 0;
    space->ctrl->encrypt_version = NO_ENCRYPT;
    space->ctrl->cipher_reserve_size = 0;
    ret = memset_sp(space->ctrl->files, GS_MAX_SPACE_FILES * sizeof(uint32), 0xFF, GS_MAX_SPACE_FILES * sizeof(uint32));
    knl_securec_check(ret);

    /* if ignore_error == true, means it's remove garbage space, so the space_count has not been added */
    if (!ignore_error) { 
        db->ctrl.core.space_count--;
    }

    return GS_SUCCESS;
}

status_t spc_remove_space_online(knl_session_t *session, space_t *space, uint32 options)
{
    rd_remove_space_t *redo = NULL;

    space->is_empty = GS_TRUE;

    log_atomic_op_begin(session);

    redo = (rd_remove_space_t *)cm_push(session->stack, sizeof(rd_remove_space_t));
    redo->space_id = space->ctrl->id;
    redo->options = options;

    log_put(session, RD_SPC_REMOVE_SPACE, redo, sizeof(rd_remove_space_t), LOG_ENTRY_FLAG_NONE);
    cm_pop(session->stack);

    log_atomic_op_end(session);

    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);

    spc_wait_data_buffer(session, space);

    return spc_remove_space(session, space, options, GS_FALSE);
}

status_t spc_active_undo_encrypt(knl_session_t *session, uint32 space_id)
{
    space_t *space = SPACE_GET(space_id);

    cm_spin_lock(&space->lock, &session->stat_space);

    if (space->ctrl->encrypt_version == NO_ENCRYPT) {
        space->ctrl->encrypt_version = KMC_DEFAULT_ENCRYPT;
        if (page_cipher_reserve_size(session, space->ctrl->encrypt_version, 
                                     &space->ctrl->cipher_reserve_size) != GS_SUCCESS) {
            cm_spin_unlock(&space->lock);
            return GS_ERROR;
        }

        cm_spin_unlock(&space->lock);

        if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when create tablespace");
        }
        return GS_SUCCESS;
    }

    cm_spin_unlock(&space->lock);
    return GS_SUCCESS;
}

static status_t spc_prepare_swap_encrypt(knl_session_t *session, space_t *space)
{
    uint32 max_cipher_len = 0;
    encrypt_context_t *encrypt_ctx = &session->kernel->encrypt_ctx;

    encrypt_ctx->swap_encrypt_flg = GS_FALSE;
    encrypt_ctx->swap_encrypt_version = KMC_DEFAULT_ENCRYPT;

    if (cm_get_cipher_len(GS_VMEM_PAGE_SIZE, &max_cipher_len) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("swap sapce get cipher len error");
        return GS_ERROR;
    }

    max_cipher_len = CM_ALIGN4(max_cipher_len - GS_VMEM_PAGE_SIZE);
    TO_UINT8_OVERFLOW_CHECK(max_cipher_len, uint32);
    encrypt_ctx->swap_cipher_reserve_size = max_cipher_len;
    space->ctrl->extent_size = MAX((GS_VMEM_PAGE_SIZE + max_cipher_len) / DEFAULT_PAGE_SIZE + 1,
        GS_SWAP_EXTENT_SIZE);
    knl_panic(space->ctrl->extent_size * DEFAULT_PAGE_SIZE >= GS_VMEM_PAGE_SIZE + max_cipher_len);
    
    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when create tablespace");
    }
    return GS_SUCCESS;
}

status_t spc_active_swap_encrypt(knl_session_t *session)
{
    encrypt_context_t *encrypt_ctx = &session->kernel->encrypt_ctx;
    if (encrypt_ctx->swap_encrypt_flg) {
        return GS_SUCCESS;
    }

    knl_panic(encrypt_ctx->swap_encrypt_version > NO_ENCRYPT);
    knl_panic(encrypt_ctx->swap_cipher_reserve_size > 0);

    encrypt_ctx->swap_encrypt_flg = GS_TRUE;
    return GS_SUCCESS;
}

uint32 spc_get_encrypt_space_count(knl_session_t *session)
{
    uint32 count = 0;
    space_t *space = NULL;

    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(i);

        if (space->ctrl->used
            && SPACE_IS_ONLINE(space)
            && SPACE_IS_ENCRYPT(space)) {
            count++;
        }
    }

    return count;
}

status_t spc_try_inactive_swap_encrypt(knl_session_t *session)
{
    encrypt_context_t *encrypt_ctx = &session->kernel->encrypt_ctx;
    if (!encrypt_ctx->swap_encrypt_flg) {
        return GS_SUCCESS;
    }

    // has other encryption space except swap space
    if (spc_get_encrypt_space_count(session) > 0) {
        return GS_SUCCESS;
    }

    session->kernel->encrypt_ctx.swap_encrypt_flg = GS_FALSE;
    return GS_SUCCESS;
}

static status_t spc_init_flag(knl_session_t *session, knl_space_def_t *def, space_t *space)
{
    if (def->autooffline) {
        if (SPACE_IS_DEFAULT(space)) {
            GS_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to auto offline system space");
            return GS_ERROR;
        }
        SPACE_SET_AUTOOFFLINE(space);
    }

    // setting fellow previous version
    if (IS_USER_SPACE(space)) {
        SPACE_SET_AUTOPURGE(space);
    }

    if (def->in_memory) {
        SPACE_SET_INMEMORY(space);
    }

    if (IS_SWAP_SPACE(space)) {
        space->ctrl->extent_size = MAX(def->extent_size, GS_SWAP_EXTENT_SIZE);
        if (spc_prepare_swap_encrypt(session, space) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (def->autoallocate) {
        SPACE_SET_AUTOALLOCATE(space);
        space->ctrl->extent_size = GS_MIN_EXTENT_SIZE;
    }

    if (def->bitmapmanaged) {
        SPACE_SET_BITMAPMANAGED(space);
    }

    if (def->encrypt) {
        if (SPACE_IS_DEFAULT(space)) {
            GS_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to encrypt system space");
            return GS_ERROR;
        }

        if (session->kernel->lsnd_ctx.standby_num > 0 
            && !DB_IS_RAFT_ENABLED(session->kernel)) {
            GS_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to create encrypt space when database in HA mode");
            return GS_ERROR;
        }

        space->ctrl->encrypt_version = KMC_DEFAULT_ENCRYPT;
        if (page_cipher_reserve_size(session, space->ctrl->encrypt_version, &space->ctrl->cipher_reserve_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (spc_active_undo_encrypt(session, DB_CORE_CTRL(session)->undo_space) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (spc_active_undo_encrypt(session, DB_CORE_CTRL(session)->temp_undo_space) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (spc_active_swap_encrypt(session) != GS_SUCCESS) {
            return GS_ERROR;
        }

        SPACE_SET_ENCRYPT(space);
    }

    return GS_SUCCESS;
}

static status_t spc_init_space_ctrl(knl_session_t *session, knl_space_def_t *def, space_t *space)
{
    knl_device_def_t *file = NULL;

    for (uint32 i = 0; i < def->datafiles.count; i++) {
        file = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
        if (spc_create_datafile_precheck(session, space, file) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    space->lock = 0;
    space->alarm_enabled = GS_TRUE;
    space->purging = GS_FALSE;
    space->swap_bitmap = GS_FALSE;

    space->ctrl->flag = 0;
    space->ctrl->used = GS_TRUE;
    space->ctrl->file_hwm = 0;
    space->ctrl->org_scn = db_inc_scn(session);
    space->ctrl->block_size = DEFAULT_PAGE_SIZE;
    space->ctrl->extent_size = (def->extent_size == 0) ? session->kernel->attr.default_extents : def->extent_size;
    space->ctrl->type = def->type;

    cm_text2str(&def->name, space->ctrl->name, GS_NAME_BUFFER_SIZE);

    if (spc_init_flag(session, def, space) != GS_SUCCESS) {
        (void)spc_remove_space(session, space, (uint32)SPC_CLEAN_OPTION, GS_TRUE);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void spc_put_create_redo(knl_session_t *session, space_t *space)
{
    log_atomic_op_begin(session);
    rd_create_space_t *redo = (rd_create_space_t *)cm_push(session->stack, sizeof(rd_create_space_t));

    redo->space_id = space->ctrl->id;
    redo->flags = space->ctrl->flag;
    redo->extent_size = space->ctrl->extent_size;
    redo->block_size = space->ctrl->block_size;
    redo->org_scn = space->ctrl->org_scn;
    redo->type = space->ctrl->type;
    redo->encrypt_version = space->ctrl->encrypt_version;
    redo->cipher_reserve_size = space->ctrl->cipher_reserve_size;
    redo->reserved2 = 0;

    errno_t ret = memcpy_sp(redo->name, GS_NAME_BUFFER_SIZE, space->ctrl->name, GS_NAME_BUFFER_SIZE);
    knl_securec_check(ret);
    if (SPACE_IS_ENCRYPT(space)) {
        log_encrypt_prepare(session, GS_INVALID_ID8, GS_TRUE);
    }
    log_put(session, RD_SPC_CREATE_SPACE, redo, sizeof(rd_create_space_t), LOG_ENTRY_FLAG_NONE);

    cm_pop(session->stack); 
    log_atomic_op_end(session);
}


status_t spc_build_space(knl_session_t *session, knl_space_def_t *def, space_t *space)
{
    knl_instance_t *kernel = session->kernel;
    knl_device_def_t *file = NULL;
    uint32 file_no;
    
    for (uint32 i = 0; i < def->datafiles.count; i++) {
        file = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
        if (spc_create_datafile_precheck(session, space, file) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (spc_init_space_ctrl(session, def, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    space->lock = 0;
    space->alarm_enabled = GS_TRUE;
    space->allow_extend = GS_TRUE;
    space->purging = GS_FALSE;
    space->swap_bitmap = GS_FALSE;
    space->punching = GS_FALSE;

    kernel->db.ctrl.core.space_count++;
    spc_put_create_redo(session, space);

    if (DB_TO_RECOVERY(session)) {
        ckpt_trigger(session, GS_FALSE, CKPT_TRIGGER_FULL);
    }

    for (uint32 i = 0; i < def->datafiles.count; i++) {
        file = (knl_device_def_t *)cm_galist_get(&def->datafiles, i);
        if (spc_create_datafile(session, space, file, &file_no) != GS_SUCCESS) {
            (void)spc_remove_space_online(session, space, (uint32)SPC_CLEAN_OPTION);
            return GS_ERROR;
        }
    }

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        (void)spc_remove_space_online(session, space, (uint32)SPC_CLEAN_OPTION);
        return GS_ERROR;
    }

    if (DB_TO_RECOVERY(session) && IS_USER_SPACE(space)) {
        ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    }

    log_commit(session);
    return GS_SUCCESS;
}

/* Set df->space_id without mount datafiles. This function is used when DB is started as mount mode */
void spc_set_space_id(knl_session_t *session)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    uint32 file_id;

    for (uint32 spc_id = 0; spc_id < GS_MAX_SPACES; spc_id++) {
        space = SPACE_GET(spc_id);
        if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
            continue;
        }

        for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
            file_id = space->ctrl->files[i];
            if (file_id == GS_INVALID_ID32) {
                continue;
            }

            df = DATAFILE_GET(file_id);
            df->file_no = i;
            df->space_id = space->ctrl->id;
        }
    }
}

static status_t spc_rebuild_datafile(knl_session_t *session, space_t *space, uint32 fileno)
{
    datafile_t *rb_df = DATAFILE_GET(space->ctrl->files[fileno]);
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;

    if (spc_build_datafile(session, rb_df, DATAFILE_FD(rb_df->ctrl->id)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[SPACE] failed to build datafile %s", rb_df->ctrl->name);
        return GS_ERROR;
    }

    if (spc_open_datafile(session, rb_df, DATAFILE_FD(rb_df->ctrl->id)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[SPACE] failed to open datafile %s", rb_df->ctrl->name);
        return GS_ERROR;
    }

    if (cm_add_file_watch(rmon_ctx->watch_fd, rb_df->ctrl->name, &rb_df->wd) != GS_SUCCESS) {
        GS_LOG_RUN_WAR("[RMON]: failed to add monitor of datafile %s", rb_df->ctrl->name);
    }

    if (fileno == 0) {
        return spc_rebuild_space(session, space);
    }
    return GS_SUCCESS;
}

status_t spc_mount_space(knl_session_t *session, space_t *space, bool32 auto_offline)
{
    if (SPACE_IS_INMEMORY(space)) {
        if (spc_create_memory_space(session, space) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create space in memory");
            return GS_ERROR;
        }
    }

    space->swap_bitmap = GS_FALSE;

    /* mount datafile in space */
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        uint32 file_id = space->ctrl->files[i];
        if (GS_INVALID_ID32 == file_id) {
            continue;
        }

        datafile_t *df = DATAFILE_GET(file_id);
        df->file_no = i;
        df->space_id = space->ctrl->id;

        if (!DATAFILE_IS_ONLINE(df)) {
            GS_LOG_RUN_INF("[SPACE] offline space %s, cause datafile %s is offline",
                space->ctrl->name, df->ctrl->name);
            SPACE_UNSET_ONLINE(space);
            return GS_SUCCESS;
        }

        if (spc_open_datafile(session, df, DATAFILE_FD(file_id)) != GS_SUCCESS) {
            if (IS_SWAP_SPACE(space) && !cm_file_exist(df->ctrl->name)) {
                if (spc_rebuild_datafile(session, space, i) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                GS_LOG_RUN_INF("sucessfully rebuild datafile %s", df->ctrl->name);
            } else {
                if (auto_offline && spc_auto_offline_space(session, space, df)) {
                    return GS_SUCCESS;
                }

                GS_THROW_ERROR(ERR_DATAFILE_BREAKDOWN, df->ctrl->name, "try to offline it in MOUNT mode");
                return GS_ERROR;
            }
        }

        /* if the database shutdown abnormally when it's doing resize a datafile, the datafile's size in oper system 
         * is bigger than it in database after restart, we should truncate it to avoid space waste, and if the 
         * datafile's size in oper system is smaller than it in database after restart, we should extend it.
         */
        int64 actual_size = cm_seek_device(df->ctrl->type, session->datafiles[file_id], 0, SEEK_END);
        knl_panic(actual_size != -1);
        knl_instance_t *kernel = (knl_instance_t *)session->kernel;
        if (actual_size > df->ctrl->size && !kernel->lrcv_ctx.is_building && !kernel->db.recover_for_restore) {
            if (cm_truncate_device(df->ctrl->type, session->datafiles[file_id], df->ctrl->size) != GS_SUCCESS) {
                return GS_ERROR;
            }

            GS_LOG_RUN_INF("abnormal power failure occurred during the last resize operation on %s ", df->ctrl->name);
        }

        if (actual_size < df->ctrl->size && !kernel->lrcv_ctx.is_building && !kernel->db.recover_for_restore) {
            int64 extend_size = df->ctrl->size - actual_size;
            cm_spin_lock(&session->kernel->db.ctrl_lock, NULL);
            df->ctrl->size = actual_size;
            cm_spin_unlock(&session->kernel->db.ctrl_lock);
            if (spc_extend_datafile(session, df, &session->datafiles[file_id], extend_size, GS_FALSE) != GS_SUCCESS) {
                return GS_ERROR;
            }

            GS_LOG_RUN_INF("abnormal power failure occurred during the last resize operation on %s ", df->ctrl->name);
        }
        
        /* if is the first datafile in space, we need to mount the space head */
        if (i == 0) {
            space->entry.page = SPACE_ENTRY_PAGE;
            space->entry.file = space->ctrl->files[i];

            if (buf_read_page(session, space->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != GS_SUCCESS) {
                if (auto_offline && spc_auto_offline_space(session, space, df)) {
                    return GS_SUCCESS;
                }
                return GS_ERROR;
            }

            space->head = SPACE_HEAD;
            buf_leave_page(session, GS_FALSE);
            spc_try_set_swap_bitmap(session, space);
        }

        /* mount the bitmap head of datafile, here NOT init SWAP space */
        if (SPACE_CTRL_IS_BITMAPMANAGED(space)) {
            df->map_head_entry.file = df->ctrl->id;
            df->map_head_entry.page = df->ctrl->id == 0 ? DW_MAP_HEAD_PAGE : DF_MAP_HEAD_PAGE;

            if (buf_read_page(session, df->map_head_entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT) != GS_SUCCESS) {
                if (auto_offline && spc_auto_offline_space(session, space, df)) {
                    return GS_SUCCESS;
                }
                return GS_ERROR;
            }
            df->map_head = (df_map_head_t *)CURR_PAGE;
            buf_leave_page(session, GS_FALSE);
        }
    }

    if (IS_SWAP_SPACE(space)) {
        if (spc_prepare_swap_encrypt(session, space) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    space->purging = GS_FALSE;
    space->is_empty = GS_FALSE;
    space->allow_extend = GS_TRUE;
    space->alarm_enabled = GS_TRUE;

    SPACE_SET_ONLINE(space);

    return GS_SUCCESS;
}

void spc_umount_space(knl_session_t *session, space_t *space)
{
    datafile_t *df = NULL;
    uint32 file_id;
    uint32 i;

    for (i = 0; i < space->ctrl->file_hwm; i++) {
        file_id = space->ctrl->files[i];
        if (GS_INVALID_ID32 == file_id) {
            continue;
        }

        df = DATAFILE_GET(file_id);
        spc_close_datafile(df, DATAFILE_FD(file_id));
        df->file_no = GS_INVALID_ID32;
        df->space_id = GS_INVALID_ID32;
    }

    space->entry = INVALID_PAGID;
    space->head = NULL;
}

/*
 * reset nologging tablespace's head when db restart, no matter start as primary or standby
 *
 * Notes:
 *  caller should gurantee there's no one would change spc head concurrently.
 */
static void spc_nologging_reset_head(knl_session_t *session, space_t *space)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 dw_file_id = db->ctrl.core.dw_file_id;
    datafile_t *df = DATAFILE_GET(space->ctrl->files[0]);

    /* must be a nologging tablespace */
    knl_panic(SPACE_IS_LOGGING(space) == GS_FALSE);

    /*
     * space->head is already loaded during db_load_tablespaces and it's resident, so change it directly,
     * because we do this no matter it's master or standby, so buf_xxx interface can not be used.
     */
    knl_panic(space->head != NULL);

    SPC_UNPROTECT_HEAD(space);
    space->head->segment_count = 0;
    space->head->free_extents.count = 0;
    space->head->free_extents.first = INVALID_PAGID;
    space->head->free_extents.last = INVALID_PAGID;

    /* hwm of the first datafile starts with 2 because of including space head */
    space->head->hwms[0] = (DATAFILE_CONTAINS_DW(df, dw_file_id)) ? DW_SPC_HWM_START : DF_FIRST_HWM_START;

    for (uint32 i = 1; i < space->ctrl->file_hwm; i++) {
        space->head->hwms[i] = 1;
    }

    SPC_PROTECT_HEAD(space);
}

bool32 spc_need_clean(space_t *space)
{
    if (space->ctrl->file_hwm == 0) {
        return GS_FALSE;
    }

    if (SPACE_IS_LOGGING(space)) {
        return GS_FALSE;
    }

    if (IS_SWAP_SPACE(space)) {
        return GS_FALSE;
    }

    if (!SPACE_IS_ONLINE(space)) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

/*
 * 1. drop tables in it if needed;
 */
status_t spc_drop_nologging_table(knl_session_t *session)
{
    space_t *space = NULL;

    if (DB_IS_READONLY(session) || DB_IS_MAINTENANCE(session)) {
        return GS_SUCCESS;
    }

    /* drop table after undo complete, otherwise we cannot lock_table_directly when knl_internal_drop_table */
    while (DB_IN_BG_ROLLBACK(session)) {
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

    /* skip built-in tablespace */
    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(i);
        if (!spc_need_clean(space)) {
            continue;
        }

        /* set bootstrap flag to pass dc_is_ready_for_access check */
        session->bootstrap = GS_TRUE;
        if (spc_drop_space_remove_objects(session, space, TABALESPACE_CASCADE) != GS_SUCCESS) {
            session->bootstrap = GS_FALSE;
            GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name, "failed to drop object");
            return GS_ERROR;
        }

        session->bootstrap = GS_FALSE;
    }

    return GS_SUCCESS;
}

/* only called when db restart, no matter restart as primary or standby */
void spc_clean_nologging_data(knl_session_t *session)
{
    space_t *space = NULL;

    /* skip built-in tablespace */
    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(i);
        if (!spc_need_clean(space)) {
            continue;
        }

        spc_nologging_reset_head(session, space);
    }
}

space_t *spc_get_temp_undo(knl_session_t *session)
{
    core_ctrl_t *core_ctrl = DB_CORE_CTRL(session);

    if (core_ctrl->temp_undo_space == 0) {
        return NULL;
    }

    return SPACE_GET(core_ctrl->temp_undo_space);
}

status_t spc_create_space_precheck(knl_session_t *session, knl_space_def_t *def)
{
    /* check db status */
    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "create tablespace");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t spc_check_undo_space(knl_session_t *session, knl_space_def_t *def)
{
    if (def->type == (SPACE_TYPE_UNDO | SPACE_TYPE_TEMP)) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create UNDO tablespace with nologging");
        return GS_ERROR;
    }

    if (def->autoallocate) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create UNDO tablespace with extent autoallocate");
        return GS_ERROR;
    }

    if (def->encrypt) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create UNDO tablespace using encrypt");
        return GS_ERROR;
    }

    def->bitmapmanaged = GS_FALSE;
    def->extent_size = UNDO_EXTENT_SIZE;
    return GS_SUCCESS;
}

static status_t spc_create_space_prepare(knl_session_t *session, knl_space_def_t *def, space_t **new_space)
{
    space_t *space = NULL;

    /* autoallocate extent is not support on nologging space */
    if ((def->type & SPACE_TYPE_TEMP) && def->autoallocate) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "create nologging tablespace with extent autoallocate");
        return GS_ERROR;
    }

    if (def->type & SPACE_TYPE_UNDO) {
        if (spc_check_undo_space(session, def) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    uint32 used_count = 0;
    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(i);
        if (space->ctrl->used) {
            if (cm_text_str_equal(&def->name, space->ctrl->name)) {
                GS_THROW_ERROR(ERR_SPACE_ALREADY_EXIST, space->ctrl->name);
                return GS_ERROR;
            }
            used_count++;
            continue;
        }

        if (*new_space == NULL) {
            *new_space = space;
            (*new_space)->ctrl->id = i;
        }
    }

    if (used_count >= GS_MAX_SPACES || new_space == NULL) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_SPACES, "spaces");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * create a new tablespace and return space id
 */
status_t spc_create_space(knl_session_t *session, knl_space_def_t *def, uint32 *id)
{
    space_t *space = NULL;

    if (spc_create_space_prepare(session, def, &space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_build_space(session, def, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_mount_space(session, space, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when create tablespace");
    }

    *id = space->ctrl->id;
    GS_LOG_RUN_INF("[SPACE] succeed to create tablespace %s", space->ctrl->name);
    return GS_SUCCESS;
}

status_t spc_drop_offlined_space(knl_session_t *session, space_t *space, uint32 options)
{
    char spc_name[GS_NAME_BUFFER_SIZE];
    uint32 name_len = GS_NAME_BUFFER_SIZE - 1;
    errno_t ret;

    ret = strncpy_s(spc_name, GS_NAME_BUFFER_SIZE, space->ctrl->name, name_len);
    knl_securec_check(ret);

    cm_spin_lock(&space->lock, &session->stat_space);

    if (spc_check_object_exist(session, space) != GS_SUCCESS) {
        cm_spin_unlock(&space->lock);
        GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name,
                       "failed to check if object exists for offlined tablespace.");
        return GS_ERROR;
    }

    if (spc_remove_space_online(session, space, options) != GS_SUCCESS) {
        cm_spin_unlock(&space->lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when drop offlined space");
    }

    GS_LOG_RUN_INF("[SPACE] succeed to drop offlined tablespace %s", spc_name);
    return GS_SUCCESS;
}

#ifdef DB_DEBUG_VERSION
void spc_validate_extents(knl_session_t *session, page_list_t *extents)
{
    page_id_t page_id;
    uint32 count;

    knl_panic_log(extents->count != 0, "extents's count is zero.");

    count = 0;
    page_id = extents->first;

    while (!IS_INVALID_PAGID(page_id)) {
        count++;

        knl_panic_log(!(page_id.file == 0 && page_id.page == 0), "page_id is abnormal, panic info: page %u-%u",
                      page_id.file, page_id.page);

        if (IS_SAME_PAGID(page_id, extents->last)) {
            break;
        }

        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page_id = AS_PAGID(((page_head_t *)CURR_PAGE)->next_ext);
        buf_leave_page(session, GS_FALSE);
    }

    knl_panic_log(count == extents->count, "The current record extents count is not as expected, panic info: "
                  "count %u extents count %u", count, extents->count);
}

void spc_validate_undo_extents(knl_session_t *session, undo_page_list_t *extents)
{
    page_id_t page_id, pageid_last;
    uint32 count;

    knl_panic_log(extents->count != 0, "extents's count is zero.");

    count = 0;
    page_id = PAGID_U2N(extents->first);

    while (!IS_INVALID_PAGID(page_id)) {
        count++;
        knl_panic_log(!(page_id.file == 0 && page_id.page == 0), "page_id is abnormal, panic info: page %u-%u",
                      page_id.file, page_id.page);

        pageid_last = PAGID_U2N(extents->last);
        if (IS_SAME_PAGID(page_id, pageid_last)) {
            break;
        }

        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page_id = AS_PAGID(((page_head_t *)CURR_PAGE)->next_ext);
        buf_leave_page(session, GS_FALSE);
    }

    knl_panic_log(count == extents->count, "The current record extents count is not as expected, panic info: "
                  "current count %u extents count %u", count, extents->count);
}

#endif

/*
 * check objects in space when dropping with including options
 * see spc_fetch_obj_list to obtain all object types to be checked
 * @param kernel session, space to be dropped, options
 */
bool32 spc_check_object_relation(knl_session_t *session, space_t *space, uint32 options)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    for (uint32 i = 0; i < SPC_OBJ_TYPE_COUNT; i++) {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, g_spc_obj_fetch_list[i].sys_tbl_id, GS_INVALID_ID32);
        cursor->isolevel = ISOLATION_CURR_COMMITTED;

        for (;;) {
            if (knl_fetch(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_FALSE;
            }

            if (cursor->eof) {
                break;
            }

            if (g_spc_obj_fetch_list[i].check_func == NULL) {
                continue;
            }

            if (g_spc_obj_fetch_list[i].check_func(session, cursor, space, options) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_FALSE;
            }
        }
    }
    
    CM_RESTORE_STACK(session->stack);
    return GS_TRUE;
}

status_t spc_drop_space_remove_objects(knl_session_t *session, space_t *space, uint32 options)
{
    if (spc_drop_sys_table_objects(session, space, options) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_drop_sys_rb_objects(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

// fisrt lock then verify
static inline bool32 spc_is_punching(knl_session_t *session, space_t *space, const char *info)
{
    if (space->punching) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "%s when space %s is punching",
            info, space->ctrl->name);
        return GS_TRUE;
    }
    return GS_FALSE;
}

status_t spc_drop_online_space(knl_session_t *session, space_t *space, uint32 options)
{
    char spc_name[GS_NAME_BUFFER_SIZE];
    errno_t ret;

    ret = strncpy_s(spc_name, GS_NAME_BUFFER_SIZE, space->ctrl->name, strlen(space->ctrl->name) + 1);
    knl_securec_check(ret);

    if (spc_check_default_tablespace(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* if with drop contents option, we need to check objects in space and remove them if possible */
    if (SPC_DROP_CONTENTS(options)) {
        if (!spc_check_object_relation(session, space, options)) {
            return GS_ERROR;
        }

        if (spc_drop_space_remove_objects(session, space, options) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name, "failed to drop object");
            return GS_ERROR;
        }
    }

    /* after dropping objects in space or without drop contents option, we must guaratee space to be dropped is empty */
    if (spc_check_object_exist(session, space) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name, "exists object");
        return GS_ERROR;
    }

    cm_spin_lock(&space->lock, &session->stat_space);

    if (spc_is_punching(session, space, "drop space")) {
        cm_spin_unlock(&space->lock);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[SPACE] drop online space, set space %s offline", space->ctrl->name);
    SPACE_UNSET_ONLINE(space);

    /* everything is ready up to now, remove it */
    if (spc_remove_space_online(session, space, options) != GS_SUCCESS) {
        cm_spin_unlock(&space->lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when drop tablespace");
    }

    GS_LOG_RUN_INF("[SPACE] succeed to drop tablespace %s", spc_name);
    return GS_SUCCESS;
}

void spc_concat_extent(knl_session_t *session, page_id_t last_ext, page_id_t ext)
{
    page_head_t *head = NULL;

    buf_enter_page(session, last_ext, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE;
    TO_PAGID_DATA(ext, head->next_ext);

    bool32 need_redo = SPC_IS_LOGGING_BY_PAGEID(last_ext);
    if (need_redo) {
        log_put(session, RD_SPC_CONCAT_EXTENT, &ext, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}

void spc_concat_extents(knl_session_t *session, page_list_t *extents, const page_list_t *next_exts)
{
    spc_concat_extent(session, extents->last, next_exts->first);
    extents->count += next_exts->count;
    extents->last = next_exts->last;
}

static void spc_update_datafile_hwm(knl_session_t *session, space_t *space, uint32 id, uint32 hwm)
{
    rd_update_hwm_t *redo = NULL;
    bool32 need_redo = SPACE_IS_LOGGING(space);

    log_atomic_op_begin(session);
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    space->head->hwms[id] = hwm;

    redo = (rd_update_hwm_t *)cm_push(session->stack, sizeof(rd_update_hwm_t));
    redo->file_no = id;
    redo->file_hwm = space->head->hwms[id];

    if (need_redo) {
        log_put(session, RD_SPC_UPDATE_HWM, redo, sizeof(rd_update_hwm_t), LOG_ENTRY_FLAG_NONE);
    }

    cm_pop(session->stack);

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
}

static void spc_update_hwms(knl_session_t *session, space_t *space, uint32 *hwms)
{
    uint32 id;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (GS_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        if (hwms[id] == SPACE_HEAD_RESIDENT(space)->hwms[id]) {
            continue;
        }

        spc_update_datafile_hwm(session, space, id, hwms[id]);
        GS_LOG_RUN_INF("update hwm of file %u from %u to %u",
                       space->ctrl->files[id], SPACE_HEAD_RESIDENT(space)->hwms[id], hwms[id]);
    }
}

void spc_alloc_datafile_hwm_extent(knl_session_t *session, space_t *space,
    uint32 id, page_id_t *extent, uint32 extent_size)
{
    rd_update_hwm_t *redo = NULL;
    bool32 need_redo = SPACE_IS_LOGGING(space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    extent->page = space->head->hwms[id];
    extent->file = space->ctrl->files[id];
    extent->aligned = 0;
    space->head->hwms[id] += extent_size;  // the max page high water mark of a datafile is 2^30

    redo = (rd_update_hwm_t *)cm_push(session->stack, sizeof(rd_update_hwm_t));
    redo->file_no = id;
    redo->file_hwm = space->head->hwms[id];

    if (need_redo) {
        log_put(session, RD_SPC_UPDATE_HWM, redo, sizeof(rd_update_hwm_t), LOG_ENTRY_FLAG_NONE);
    }

    cm_pop(session->stack);

    buf_leave_page(session, GS_TRUE);
}

static inline void spc_alloc_free_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
        "the first of free_extents is invalid, panic info: first page of extents %u-%u type %u",
        space->head->free_extents.first.file, space->head->free_extents.first.page, ((page_head_t *)CURR_PAGE)->type);
    knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
        "the last of free_extents is invalid, panic info: last page of extents %u-%u type %u",
        space->head->free_extents.last.file, space->head->free_extents.last.page, ((page_head_t *)CURR_PAGE)->type);
    *extent = space->head->free_extents.first;
    space->head->free_extents.count--;
    
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    } else {
        space->head->free_extents.first = spc_get_next_ext(session, *extent);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
    }
    
    if (need_redo) {
        log_put(session, RD_SPC_ALLOC_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}

static bool32 spc_alloc_hwm_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    datafile_t *df = NULL;
    uint32 hwm;
    uint32 id;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (GS_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[id]);
        hwm = SPACE_HEAD_RESIDENT(space)->hwms[id];

        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        if (df->ctrl->size < (int64)(hwm + space->ctrl->extent_size) * space->ctrl->block_size) {
            continue;
        }

        if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
            continue;
        }

        spc_alloc_datafile_hwm_extent(session, space, id, extent, space->ctrl->extent_size);

        return GS_TRUE;
    }

    return GS_FALSE;
}

/*
 * Extend current space we use two strategies to handle this
 * step 1: try to allocate extent from the hwm in any space files.
 * step 2: in the worst case, try to extend file in device level.
 */
static status_t spc_extend_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 size, extent_size, unused_size, max_size;
    uint32 file_no, id, hwm;

    size = 0;
    file_no = GS_INVALID_ID32;
    extent_size = (int64)space->ctrl->extent_size * DEFAULT_PAGE_SIZE;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (space->ctrl->files[id] == GS_INVALID_ID32) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[id]);
        hwm = SPACE_HEAD_RESIDENT(space)->hwms[id];

        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE;
        if (unused_size < extent_size) {
            if (DATAFILE_IS_AUTO_EXTEND(df) && (df->ctrl->size < size || size == 0)) {
                if (df->ctrl->auto_extend_maxsize == 0 ||
                    df->ctrl->auto_extend_maxsize > (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE) {
                    max_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE;
                } else {
                    max_size = df->ctrl->auto_extend_maxsize;
                }

                /* guarantee that can alloc an extent at lease after extend */
                if (df->ctrl->size + extent_size - unused_size > max_size) {
                    continue;
                }
                file_no = id;
                size = df->ctrl->size;
            }
            continue;
        }

        if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
            continue;
        }

        spc_alloc_datafile_hwm_extent(session, space, id, extent, space->ctrl->extent_size);

        return GS_SUCCESS;
    }

    if (GS_INVALID_ID32 == file_no) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        return GS_ERROR;
    }

    hwm = SPACE_HEAD_RESIDENT(space)->hwms[file_no];
    if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
        GS_THROW_ERROR(ERR_MAX_DATAFILE_PAGES, hwm, MAX_FILE_PAGES(space->ctrl->type), space->ctrl->name);
        return GS_ERROR;
    }

    df = DATAFILE_GET(space->ctrl->files[file_no]);
    handle = DATAFILE_FD(space->ctrl->files[file_no]);
    unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE;

    if (df->ctrl->size + df->ctrl->auto_extend_size > df->ctrl->auto_extend_maxsize) {
        size = df->ctrl->auto_extend_maxsize - df->ctrl->size;
    } else {
        size = df->ctrl->auto_extend_size;
    }

    if (size + unused_size < extent_size) {
        size = extent_size - unused_size;
    }

    if (spc_extend_datafile(session, df, handle, size, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    spc_alloc_datafile_hwm_extent(session, space, file_no, extent, space->ctrl->extent_size);

    return GS_SUCCESS;
}

status_t spc_set_autopurge(knl_session_t *session, space_t *space, bool32 auto_purge)
{
    rd_set_space_flag_t redo;

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "set tablespace autopurge");
        return GS_ERROR;
    }

    cm_spin_lock(&space->lock, &session->stat_space);

    if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        cm_spin_unlock(&space->lock);
        GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tablespace", space->ctrl->id);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);

    if (!auto_purge) {
        SPACE_UNSET_AUTOPURGE(space);
    } else {
        SPACE_SET_AUTOPURGE(space);
    }

    redo.op_type = RD_SPC_SET_FLAG;
    redo.space_id = (uint16)space->ctrl->id;  // the maximum space id is 1023
    redo.flags = space->ctrl->flag;

    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_set_space_flag_t), LOG_ENTRY_FLAG_NONE);

    log_atomic_op_end(session);
    cm_spin_unlock(&space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space set autopurge");
    }

    return GS_SUCCESS;
}

/*
 * space auto purge
 * Check recycle bin to see if there are any objects that we can purge using current scn.
 * If object founded, we should release space spin lock we hold and end the atomic process
 * so that we can start an autonomous session to purge the object we found.
 * @param kernel session, space
 */
static bool32 spc_auto_purge(knl_session_t *session, space_t *space)
{
    knl_rb_desc_t desc;
    bool32 found = GS_FALSE;
    int32 code;
    const char *msg = NULL;
    bool32 is_free = GS_FALSE;

    if (!SPACE_IS_AUTOPURGE(space) || DB_IN_BG_ROLLBACK(session)) {
        return GS_FALSE;
    }

    if (rb_purge_fetch_space(session, space->ctrl->id, &desc, &found) != GS_SUCCESS) {
        cm_get_error(&code, &msg, NULL);
        GS_LOG_RUN_ERR("[SPACE] failed to fetch space autopurge: GS-%05d: %s", code, msg);
        cm_reset_error();
        return GS_FALSE;
    }

    if (found) {
        space->purging = GS_TRUE;
        cm_spin_unlock(&space->lock);

        log_atomic_op_end(session);

        if (rb_purge(session, &desc) != GS_SUCCESS) {
            code = cm_get_error_code();
            if (code != ERR_RECYCLE_OBJ_NOT_EXIST && code != ERR_RESOURCE_BUSY && code != ERR_DC_INVALIDATED) {
                GS_LOG_RUN_ERR("[SPACE] failed to purge space autopurge: GS-%05d: %s", code, msg);
            }
            cm_reset_error();
        }

        log_atomic_op_begin(session);

        cm_spin_lock(&space->lock, &session->stat_space);
        space->purging = GS_FALSE;
        GS_LOG_RUN_INF("[SPACE] auto purge space %s", space->ctrl->name);
        return GS_TRUE;
    } else {
        if (!SPACE_IS_BITMAPMANAGED(space)) {
            return GS_FALSE;
        }

        if (SPACE_HEAD_RESIDENT(space)->free_extents.count == 0) {
            return GS_FALSE;
        }

        log_atomic_op_end(session);
        is_free = spc_try_free_extent_list(session, space);
        log_atomic_op_begin(session);
    }
    return is_free;
}

static void spc_clean_free_list(knl_session_t *session, space_t *space)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    log_atomic_op_begin(session);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (space->head->free_extents.count == 0) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    space->head->free_extents.first = INVALID_PAGID;
    space->head->free_extents.last = INVALID_PAGID;
    space->head->free_extents.count = 0;

    if (need_redo) {
        log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);
}

static void spc_shrink_checkpoint(knl_session_t *session, space_t *space)
{
    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    if (SPACE_IS_LOGGING(space)) {
        log_atomic_op_begin(session);
        rd_shrink_space_t redo;
        redo.op_type = RD_SPC_SHRINK_CKPT;
        redo.space_id = space->ctrl->id;
        redo.flags = 0;
        log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_shrink_space_t), LOG_ENTRY_FLAG_NONE);
        log_atomic_op_end(session);
        log_commit(session);
    }
}

static void spc_shrink_files_prepare(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink,
    uint64 *spc_shrink_size, bool32 *need_shrink)
{
    uint64 spc_total_size = 0;
    uint64 spc_used_size = 0;
    *need_shrink = GS_TRUE;
    uint64 min_file_size;

    min_file_size = spc_get_datafile_minsize_byspace(session, space);

    spc_shrink_checkpoint(session, space);

    cm_spin_lock(&space->lock, &session->stat_space);

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        datafile_t *df = DATAFILE_GET(space->ctrl->files[i]);
        if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
            cm_spin_unlock(&space->lock);
            GS_LOG_RUN_WAR("space %s file %u is offline,can not shrink", space->ctrl->name, space->ctrl->files[i]);
            *need_shrink = GS_FALSE;
            return;
        }

        uint64 df_used_size = (uint64)SPACE_HEAD_RESIDENT(space)->hwms[i] * DEFAULT_PAGE_SIZE;
        spc_used_size += (df_used_size > min_file_size ? df_used_size : min_file_size);
        spc_total_size += (uint64)DATAFILE_GET(space->ctrl->files[i])->ctrl->size;
    }
    cm_spin_unlock(&space->lock);

    if (spc_total_size <= (uint64)shrink->keep_size || spc_total_size <= spc_used_size) {
        GS_LOG_RUN_INF("no need shrink to keep size %llu because space total size %llu, space non-shrinkable size %llu",
            (uint64)shrink->keep_size, spc_total_size, spc_used_size);
        *need_shrink = GS_FALSE;
        return;
    }

    *spc_shrink_size = spc_total_size - shrink->keep_size;

    if (spc_used_size > (uint64)shrink->keep_size) {
        GS_LOG_RUN_INF("can not shrink to keep size %llu because space non-shrinkable size %llu",
            (uint64)shrink->keep_size, spc_used_size);
    }
}

static status_t spc_shrink_files_check(knl_session_t *session, space_t *space, datafile_t *df)
{
    if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "shrink space found datafile offline");
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

static status_t spc_shrink_files(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    uint64 spc_shrink_size;
    bool32 need_shrink = GS_TRUE;
    uint64 min_file_size;

    min_file_size = spc_get_datafile_minsize_byspace(session, space);
    spc_shrink_files_prepare(session, space, shrink, &spc_shrink_size, &need_shrink);
    if (!need_shrink) {
        return GS_SUCCESS;
    }

    cm_spin_lock(&space->lock, &session->stat_space);
    for (uint32 i = 0 ; i < space->ctrl->file_hwm ; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        if (spc_shrink_size <= 0) {
            break;
        }

        datafile_t *df = DATAFILE_GET(space->ctrl->files[i]);
        if (spc_shrink_files_check(session, space, df) != GS_SUCCESS) {
            cm_spin_unlock(&space->lock);
            return GS_ERROR;
        }

        uint64 df_size = (uint64)DATAFILE_GET(space->ctrl->files[i])->ctrl->size;
        uint64 df_keep_size = (uint64)SPACE_HEAD_RESIDENT(space)->hwms[i] * DEFAULT_PAGE_SIZE;
        df_keep_size = df_keep_size > min_file_size ? df_keep_size : min_file_size;
        uint64 df_shrink_size = df_size > df_keep_size ? df_size - df_keep_size : 0;
        df_shrink_size = spc_shrink_size > df_shrink_size ? df_shrink_size : spc_shrink_size;
        df_keep_size = df_size - df_shrink_size;
        spc_shrink_size = spc_shrink_size > df_shrink_size ? spc_shrink_size - df_shrink_size : 0;

        if (df_keep_size >= df_size) {
            continue;
        }

        log_atomic_op_begin(session);
        if (spc_truncate_datafile(session, df, DATAFILE_FD(space->ctrl->files[i]), df_keep_size, GS_TRUE) != GS_SUCCESS) {
            log_atomic_op_end(session);
            cm_spin_unlock(&space->lock);
            return GS_ERROR;
        }
        log_atomic_op_end(session);
        GS_LOG_RUN_INF("shrink file size of file %u from %llu to %llu", space->ctrl->files[i], df_size, df_keep_size);
    }

    cm_spin_unlock(&space->lock);
    GS_LOG_RUN_INF("finish shrink space %s files", space->ctrl->name);
    return GS_SUCCESS;
}

status_t spc_rebuild_undo_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    uint32 *hwms = NULL;
    errno_t err;

    if (!DB_IS_RESTRICT(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return GS_ERROR;
    }

    /*
     * There must has no active transaction
     * for undo data will be cleaned for undo shrink
     */
    if (undo_check_active_transaction(session)) {
        GS_THROW_ERROR(ERR_TXN_IN_PROGRESS, "end all transaction before action");
        return GS_ERROR;
    }

    hwms = (uint32 *)cm_push(session->stack, sizeof(uint32) * GS_MAX_SPACE_FILES);
    knl_panic_log(hwms != NULL, "hwms is NULL.");
    err = memset_sp(hwms, sizeof(uint32) * GS_MAX_SPACE_FILES, 0, sizeof(uint32) * GS_MAX_SPACE_FILES);
    knl_securec_check(err);

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }
        hwms[i] = (i == 0) ? DF_FIRST_HWM_START : DF_HWM_START;
    }

    /*
     * get max page id of txn page for each datafile
     */
    undo_get_txn_hwms(session, space, hwms);
    spc_shrink_checkpoint(session, space);

    cm_spin_lock(&space->lock, &session->stat_space);
    /*
     * clean undo segment page list
     * clean undo space free list
     */
    undo_clean_segment_pagelist(session, space);
    GS_LOG_RUN_INF("finish clean undo segments");
    spc_clean_free_list(session, space);
    GS_LOG_RUN_INF("finish clean undo free list");

    /*
     * update datafile hwmjust keep txn area
     */
    spc_update_hwms(session, space, hwms);
    GS_LOG_RUN_INF("finish update undo hwms");

    cm_pop(session->stack);
    cm_spin_unlock(&space->lock);

    if (spc_shrink_files(session, space, shrink) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (undo_preload(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void spc_release_mpool_pages(knl_session_t *session, uint32 *mpool_pages, uint32 total_pages)
{
    for (uint32 i = 0; i < total_pages; i++) {
        if (mpool_pages[i] == GS_INVALID_ID32) {
            continue;
        }
        mpool_free_page(session->kernel->attr.large_pool, mpool_pages[i]);
        mpool_pages[i] = GS_INVALID_ID32;
    }
}

static status_t spc_alloc_mpool_pages(knl_session_t *session, uint32 total_pages, uint32 *mpool_pages, uint8 **page_bufs)
{
    for (uint32 i = 0; i < total_pages; i++) {
        mpool_pages[i] = GS_INVALID_ID32;
        if (!mpool_try_alloc_page(session->kernel->attr.large_pool, &mpool_pages[i])) {
            spc_release_mpool_pages(session, mpool_pages, i);
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, i, "mpool try alloc page");
            return GS_ERROR;
        }

        if (session->canceled) {
            spc_release_mpool_pages(session, mpool_pages, i);
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            spc_release_mpool_pages(session, mpool_pages, i);
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        page_bufs[i] = (uint8 *)mpool_page_addr(session->kernel->attr.large_pool, mpool_pages[i]);
        errno_t ret = memset_sp(page_bufs[i], GS_LARGE_PAGE_SIZE, 0, GS_LARGE_PAGE_SIZE);
        knl_securec_check(ret);
    }

    return GS_SUCCESS;
}

static void spc_try_remove_invalid_extent(knl_session_t *session, space_t *space, uint32 *hwms, page_id_t *prev_ext, page_id_t *curr_ext)
{
    page_id_t next;
    if (curr_ext->page < hwms[DATAFILE_GET(curr_ext->file)->file_no]) {
        next = spc_get_next_ext(session, *curr_ext);
        *prev_ext = *curr_ext;
        *curr_ext = next;
        return;
    }

    page_list_t *free_extents = &(SPACE_HEAD_RESIDENT(space)->free_extents);
    if (IS_SAME_PAGID(*curr_ext, free_extents->first)) {
        knl_panic_log(!IS_INVALID_PAGID(*curr_ext), "curr_ext is invalid, panic info: page %u-%u", curr_ext->file,
                      curr_ext->page);
        log_atomic_op_begin(session);
        page_id_t tmp;
        spc_alloc_free_extent(session, space, &tmp);
        log_atomic_op_end(session);
        *curr_ext = free_extents->first;
        *prev_ext = *curr_ext;
        return;
    }

    next = spc_get_next_ext(session, *curr_ext);
    log_atomic_op_begin(session);
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    space->head->free_extents.count--;
    if (SPACE_IS_LOGGING(space)) {
        log_put(session, RD_SPC_ALLOC_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
    spc_concat_extent(session, *prev_ext, next);
    log_atomic_op_end(session);

    *curr_ext = next;
}

static status_t spc_filter_free_lists(knl_session_t *session, space_t *space, uint32 *start_hwms, uint32 *new_hwms)
{
    uint32 i;
    for (i = 0; i < space->ctrl->file_hwm; i++) {
        if (start_hwms[i] != new_hwms[i]) {
            break;
        }
    }

    /* all file hwms are start hwms */
    if (i == space->ctrl->file_hwm) {
        spc_clean_free_list(session, space);
        return GS_SUCCESS;
    }

    page_list_t *free_extents = &(SPACE_HEAD_RESIDENT(space)->free_extents);
    page_id_t curr = free_extents->first;
    page_id_t prev = curr;
    uint32 count = free_extents->count;

    while (count > 0) {
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        spc_try_remove_invalid_extent(session, space, new_hwms, &prev, &curr);
        count--;
    }

    return GS_SUCCESS;
}

static status_t spc_shrink_hwms_prepare(knl_session_t *session, space_t *space, uint32 *new_hwms, uint32 *start_hwms, uint64 *prev_extents)
{
    prev_extents[0] = 0;
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            start_hwms[i] = GS_INVALID_ID32;
            new_hwms[i] = start_hwms[i];
            prev_extents[i + 1] = prev_extents[i];
            continue;
        }

        datafile_t *df  = DATAFILE_GET(space->ctrl->files[i]);
        if (!df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
            GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "shrink space found datafile offline");
            return GS_ERROR;
        }

        start_hwms[i] = spc_get_hwm_start(session, space, df);
        new_hwms[i] = start_hwms[i];
        uint32 extents = (SPACE_HEAD_RESIDENT(space)->hwms[i] - start_hwms[i]) / space->ctrl->extent_size;
        prev_extents[i + 1] = prev_extents[i] + extents;
    }

    uint64 spc_total_extents = prev_extents[space->ctrl->file_hwm];
    if (spc_total_extents > 0) {
        return GS_SUCCESS;
    }

    /* space total extents is zero, all files are start hwms, free extents list should be empty */
    if (!SPACE_IS_BITMAPMANAGED(space)) {
        spc_clean_free_list(session, space);
    }

    return GS_SUCCESS;
}

static status_t spc_set_free_extents_bits(knl_session_t *session, space_t *space, uint32 *start_hwms, uint64 *prev_extents, uint8 **page_bufs)
{
    uint64 page_idx, map_id;
    uint8 *bitmap = NULL;
    page_list_t *free_extents = &(SPACE_HEAD_RESIDENT(space)->free_extents);
    page_id_t curr = free_extents->first;
    uint64 begin_time = KNL_NOW(session);

    for (uint32 i = 0; i < free_extents->count; i++) {
        knl_panic_log(!IS_INVALID_PAGID(curr), "curr page is invalid, panic info: page %u-%u", curr.file, curr.page);
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        uint32 file_idx = DATAFILE_GET(curr.file)->file_no;
        /* ignore invalid extent */
        if (curr.page >= SPACE_HEAD_RESIDENT(space)->hwms[file_idx]) {
            continue;
        }

        uint64 extents = (curr.page - start_hwms[file_idx]) / space->ctrl->extent_size + 1;
        extents += prev_extents[file_idx];
        page_idx = extents / UINT8_BITS / GS_LARGE_PAGE_SIZE;
        bitmap = page_bufs[page_idx];
        map_id = extents / UINT8_BITS % GS_LARGE_PAGE_SIZE;

        bitmap[map_id] |= (0x01 << (extents % UINT8_BITS));
        curr = spc_get_next_ext(session, curr);

        session->kernel->stat.spc_free_exts++;
        session->kernel->stat.spc_shrink_times += (KNL_NOW(session) - begin_time);
    }

    return GS_SUCCESS;
}

static uint32 spc_free_extents_from_bits(uint8 **page_bufs, uint64 start, uint64 end)
{
    uint64 page_idx, map_id;
    uint8 *bitmap = NULL;

    for (uint64 i = end; i > start; i--) {
        page_idx = i / UINT8_BITS / GS_LARGE_PAGE_SIZE;
        bitmap = page_bufs[page_idx];
        map_id = i / UINT8_BITS % GS_LARGE_PAGE_SIZE;
        bool8 free = (bool8)(bitmap[map_id] >> (i % UINT8_BITS)) & (bool8)0x01;
        if (!free) {
            return (uint32)(end - i);
        }
    }

    return (uint32)(end - start);
}

static status_t spc_get_shrink_hwms(knl_session_t *session, space_t *space, uint32 *new_hwms)
{
    uint32 curr_hwm;
    datafile_t *df = NULL;
    database_t *db = &session->kernel->db;

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        df = &db->datafiles[space->ctrl->files[i]];
        if (!df->ctrl->used) {
            continue;
        }

        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        curr_hwm = df_get_shrink_hwm(session, df);
        if (new_hwms[i] < curr_hwm) {
            new_hwms[i] = curr_hwm;
        }
    }

    return GS_SUCCESS;
}


static status_t spc_get_new_hwms(knl_session_t *session, space_t *space, uint32 *start_hwms, uint64 *prev_extents, 
    uint32 *new_hwms)
{
    if (SPACE_IS_BITMAPMANAGED(space)) {
        return spc_get_shrink_hwms(session, space, new_hwms);
    }

    CM_SAVE_STACK(session->stack);

    uint32 total_pages = (uint32)(prev_extents[space->ctrl->file_hwm] / UINT8_BITS / GS_LARGE_PAGE_SIZE + 1);
    uint32 *mpool_pages = (uint32 *)cm_push(session->stack, sizeof(uint32) * total_pages);
    uint8 **page_bufs = (uint8 **)cm_push(session->stack, sizeof(uint8 *) * total_pages);

    if (spc_alloc_mpool_pages(session, total_pages, mpool_pages, page_bufs) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (spc_set_free_extents_bits(session, space, start_hwms, prev_extents, page_bufs) != GS_SUCCESS) {
        spc_release_mpool_pages(session, mpool_pages, total_pages);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    status_t status = GS_SUCCESS;

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        if (session->canceled) {
            status = GS_ERROR;
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            break;
        }

        if (session->killed) {
            status = GS_ERROR;
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            break;
        }

        uint32 curr_hwm = SPACE_HEAD_RESIDENT(space)->hwms[i];
        uint32 free_extents = spc_free_extents_from_bits(page_bufs, prev_extents[i], prev_extents[i + 1]);
        uint32 free_pages = free_extents * space->ctrl->extent_size;
        uint32 new_hwm = curr_hwm - free_pages;

        if (new_hwm > new_hwms[i]) {
            new_hwms[i] = new_hwm;
        }
    }

    spc_release_mpool_pages(session, mpool_pages, total_pages);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static bool32 spc_shrink_hwms_anable(knl_session_t *session, space_t *space, uint64 spc_total_extents)
{
    if (!SPACE_IS_BITMAPMANAGED(space)) {
        if (SPACE_HEAD_RESIDENT(space)->free_extents.count == 0) {
            return GS_FALSE;
        }
    }

    if (spc_total_extents == 0) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t spc_shrink_hwms(knl_session_t *session, space_t *space)
{
    spc_shrink_checkpoint(session, space);

    cm_spin_lock(&space->lock, &session->stat_space);
    CM_SAVE_STACK(session->stack);

    uint32 file_hwm = space->ctrl->file_hwm;
    uint32 *new_hwms = (uint32 *)cm_push(session->stack, sizeof(uint32) * file_hwm);
    uint32 *start_hwms = (uint32 *)cm_push(session->stack, sizeof(uint32) * file_hwm);
    uint64 *prev_extents = (uint64 *)cm_push(session->stack, sizeof(uint64) * (file_hwm + 1));

    if (spc_shrink_hwms_prepare(session, space, new_hwms, start_hwms, prev_extents) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_spin_unlock(&space->lock);
        return GS_ERROR;
    }

    if (!spc_shrink_hwms_anable(session, space, prev_extents[space->ctrl->file_hwm])) {
        CM_RESTORE_STACK(session->stack);
        cm_spin_unlock(&space->lock);
        return GS_SUCCESS;
    }

    if (spc_get_new_hwms(session, space, start_hwms, prev_extents, new_hwms) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        cm_spin_unlock(&space->lock);
        return GS_ERROR;
    }

    spc_update_hwms(session, space, new_hwms);

    if (!SPACE_IS_BITMAPMANAGED(space)) {
        if (spc_filter_free_lists(session, space, start_hwms, new_hwms) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_spin_unlock(&space->lock);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    cm_spin_unlock(&space->lock);

    GS_LOG_RUN_INF("finish shrink space %s hwms", space->ctrl->name);
    return GS_SUCCESS;
}

static status_t spc_shrink_space_prepare(knl_session_t *session, space_t *space)
{
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "shrink space");
        return GS_ERROR;
    }

    if (!DB_IS_OPEN(session)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "space shrink on non-open mode");
        return GS_ERROR;
    }

    if (space->ctrl->id == DB_CORE_CTRL(session)->undo_space) {
        undo_shrink_segments(session);
    }

    if (SPACE_IS_BITMAPMANAGED(space)) {
        while (SPACE_HEAD_RESIDENT(space)->free_extents.count != 0) {
            if (spc_free_extent_from_list(session, space, "shink space") != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    if (rb_purge_space(session, space->ctrl->id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t spc_shrink_temp_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    if (!DB_IS_RESTRICT(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return GS_ERROR;
    }

    return spc_shrink_files(session, space, shrink);
}

status_t spc_verify_shrink_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    uint64 min_file_size;
    uint64 min_space_size;
    uint32 file_count = 0;
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }
        file_count += 1;
    }

    min_file_size = spc_get_datafile_minsize_byspace(session, space);
    min_space_size = min_file_size * file_count;

    if ((uint64)shrink->keep_size < min_space_size) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "size value is smaller than minimum(%llu) required", min_space_size);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * shrink space
 * Only shrink temporary space
 * @param session, space, shrink_def
 */
status_t spc_shrink_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink)
{
    if (spc_is_punching(session, space, "shrink space")) {
        return GS_ERROR;
    }

    if (spc_verify_shrink_space(session, space, shrink) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (DB_IS_RESTRICT(session)) {
        if (space->ctrl->id == DB_CORE_CTRL(session)->undo_space) {
            return spc_rebuild_undo_space(session, space, shrink);
        }
    }

    if (IS_SWAP_SPACE(space)) {
        if (spc_shrink_temp_space(session, space, shrink) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (spc_shrink_space_prepare(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_shrink_hwms(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_shrink_files(session, space, shrink) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline void spc_print_punch_log(knl_session_t *session, space_t *space, const char *info)
{
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    page_list_t *p_ing = &punch_head->punching_exts;
    page_list_t *p_ed = &punch_head->punched_exts;
    page_list_t *free = &space->head->free_extents;
    GS_LOG_DEBUG_INF("[SPC PUNCH] %s: free extents count %u first %u-%u last %u-%u, punching extents count %u "
        "first %u-%u last %u-%u, punched extents count %u first %u-%u last %u-%u.", info,
        free->count, (uint32)free->first.file, free->first.page, (uint32)free->last.file, free->last.page,
        p_ing->count, (uint32)p_ing->first.file, p_ing->first.page, (uint32)p_ing->last.file, p_ing->last.page,
        p_ed->count, (uint32)p_ed->first.file, p_ed->first.page, (uint32)p_ed->last.file, p_ed->last.page);
}

/*
 * strategies to allocate extent from space whose extent is managed by hwm and free list:
 *
 * 1.alloc extent from space free extent lists.
 * 2.alloc extent from high water mark.
 * 3.try recycle space object from recycle bin.
 * 4.try extend space datafile when auto-extend is allowed.
 *
 * @note Causing autonomous session maybe called, so do not call
 * this interface when entered some pages or generated redo logs.
 */
status_t spc_alloc_extent_normal(knl_session_t *session, space_t *space, page_id_t *extent)
{
    CM_POINTER3(session, space, extent);

    for (;;) {
        // incase: drop space-> drop table, and table expand when insert concurrently
        if (cm_spin_try_lock(&space->lock)) {
            break;
        }

        if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
            return GS_ERROR;
        }

        cm_sleep(2);
    }

    for (;;) {
        if (SPACE_HEAD_RESIDENT(space)->free_extents.count > 0) {
            spc_alloc_free_extent(session, space, extent);
            if (extent->page >= space->head->hwms[DATAFILE_GET(extent->file)->file_no]) {
                GS_LOG_RUN_INF("ignore invalid extent(%u-%d), space %s, file no %u", 
                               extent->file, extent->page, space->ctrl->name, DATAFILE_GET(extent->file)->file_no);
                continue;
            }
            extent->aligned = 0;
            cm_spin_unlock(&space->lock);
            // page 0 is datafile head, allow can not be 0. verified when alloc success. same as below
            knl_panic_log((extent->page != 0), "alloce normal extent (%u-%u) assert, 0 should be datafile head page.",
                extent->file, extent->page);
            return GS_SUCCESS;
        }

        if (spc_alloc_hwm_extent(session, space, extent)) {
            cm_spin_unlock(&space->lock);
            knl_panic_log((extent->page != 0), "alloce normal extent (%u-%u) assert, 0 should be datafile head page.",
                extent->file, extent->page);
            return GS_SUCCESS;
        }

        // other sessions come here and find space->purging is true, do not wait for purging completed
        if (space->purging) {
            break;
        }

        if (!spc_auto_purge(session, space)) {
            break;
        }
    }

    if (spc_extend_extent(session, space, extent) != GS_SUCCESS) {
        cm_spin_unlock(&space->lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&space->lock);
    knl_panic_log((extent->page != 0), "alloce normal extent (%u-%u) assert, 0 should be datafile head page.",
        extent->file, extent->page);
    return GS_SUCCESS;
}

/*
 * judge whether need to add a new bitmap group after datafile extended.
 * the max pages that managed by current bitmap group including:
 * 1.file head page, space head page, bitmap head page
 * 2.total bitmap pages of each bitmap group
 * 3.data pages managed by each bitmap group
 */
static bool32 spc_need_more_map_group(knl_session_t *session, datafile_t *df)
{
    uint32 i;
    int64 total_pages, total_size;
    df_map_group_t group;

    total_pages = 0;
    for (i = 0; i < df->map_head->group_count; i++) {
        group = df->map_head->groups[i];
        total_pages += group.page_count;
    }

    total_pages += total_pages * DF_MAP_BIT_CNT * df->map_head->bit_unit; // add up data pages
    total_pages += DF_MAP_HEAD_PAGE + 1;  // add up three head pages
    total_size = total_pages * DEFAULT_PAGE_SIZE;

    return total_size < df->ctrl->size;
}

/*
 * update file hwm on space head if needed after alloc extent from map
 */
static void spc_try_update_hwm(knl_session_t *session, space_t *space, uint32 file_no, uint32 hwm)
{
    rd_update_hwm_t redo;

    /* update file hwm in space head */
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (hwm > space->head->hwms[file_no]) {
        space->head->hwms[file_no] = hwm;
        redo.file_no = file_no;
        redo.file_hwm = space->head->hwms[file_no];
        log_put(session, RD_SPC_UPDATE_HWM, &redo, sizeof(rd_update_hwm_t), LOG_ENTRY_FLAG_NONE);
        buf_leave_page(session, GS_TRUE);
    } else {
        buf_leave_page(session, GS_FALSE);
    }
}

static void spc_try_update_swap_hwm(knl_session_t *session, space_t *space, uint32 file_no, uint32 hwm)
{
    /* update file hwm in space head */
    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (hwm > space->head->hwms[file_no]) {
        space->head->hwms[file_no] = hwm;
    }
    buf_leave_temp_page(session);
}


/*
 * find the smallest file that fulfil the requirment to extend
 */
status_t spc_find_extend_file(knl_session_t *session, space_t *space, uint32 extent_size, uint32 *file_no, 
    bool32 is_compress)
{
    datafile_t *df = NULL;
    uint32 id;
    int64 size = 0;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (GS_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[id]);
        if (!is_compress != !DATAFILE_IS_COMPRESS(df)) {
            continue;
        }
        if (DATAFILE_IS_AUTO_EXTEND(df) && (df->ctrl->size < size || size == 0)) {
            /* guarantee that can alloc an extent at lease after extend */
            if (df->ctrl->size + extent_size * DEFAULT_PAGE_SIZE > df->ctrl->auto_extend_maxsize) {
                continue;
            }

            *file_no = id;
            size = df->ctrl->size;
        }
    }

    if (*file_no == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static int64 spc_get_extend_size(knl_session_t *session, datafile_t *df, uint32 extent_size, bool32 *need_group)
{
    int64 size;

    if (df->ctrl->size + df->ctrl->auto_extend_size > df->ctrl->auto_extend_maxsize) {
        size = df->ctrl->auto_extend_maxsize - df->ctrl->size;
    } else {
        size = df->ctrl->auto_extend_size;
    }

    if (size < extent_size * DEFAULT_PAGE_SIZE) {
        size = extent_size * DEFAULT_PAGE_SIZE;
    }

    /* if need to add new bitmap group, extend bitmap space additionally */
    *need_group = spc_need_more_map_group(session, df);
    if (*need_group) {
        size += DF_MAP_GROUP_SIZE * DEFAULT_PAGE_SIZE;
    }

    return size;
}

/*
 * extend datafile and add a new bitmap group if needed
 * 1.extend a extent at least, including bitmap group additional if needed.
 * 2.extend to maxsize if exceed maxsize after extend auto_extend_size.
 * 3.alloc extent maybe failed after extending because of bit aligned.
 */
status_t spc_extend_datafile_map(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent, 
    bool32 is_compress)
{
    datafile_t *df = NULL;
    int64 size;
    uint32 file_no = GS_INVALID_ID32;
    page_id_t page_id;
    bool32 new_group;

    for (;;) {
        if (spc_find_extend_file(session, space, extent_size, &file_no, is_compress) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            return GS_ERROR;
        }

        df = DATAFILE_GET(space->ctrl->files[file_no]);
        size = spc_get_extend_size(session, df, extent_size, &new_group);
        if (spc_extend_datafile(session, df, DATAFILE_FD(df->ctrl->id), size, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (new_group) {
            page_id.file = df->ctrl->id;
            page_id.page = space->head->hwms[file_no];
            page_id.aligned = 0;
            df_add_map_group(session, df, page_id, DF_MAP_GROUP_SIZE);
        }

        if (df_alloc_extent(session, df, extent_size, extent) != GS_SUCCESS) {
            continue;
        }

        spc_try_update_hwm(session, space, file_no, extent->page + extent_size);
        return GS_SUCCESS;
    }
}

status_t spc_extend_swap_datafile_map(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent)
{
    datafile_t *df = NULL;
    int64 size;
    uint32 file_no = GS_INVALID_ID32;
    page_id_t page_id;
    bool32 new_group = GS_FALSE;

    for (;;) {
        if (spc_find_extend_file(session, space, extent_size, &file_no, GS_FALSE) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
            return GS_ERROR;
        }

        df = DATAFILE_GET(space->ctrl->files[file_no]);
        size = spc_get_extend_size(session, df, extent_size, &new_group);
        if (spc_extend_datafile(session, df, DATAFILE_FD(df->ctrl->id), size, GS_FALSE) != GS_SUCCESS) {
            // will print log inside
            return GS_ERROR;
        }

        if (new_group) {
            page_id.file = df->ctrl->id;
            page_id.page = space->head->hwms[file_no];
            page_id.aligned = 0;
            df_add_map_group_swap(session, df, page_id, DF_MAP_GROUP_SIZE);
        }

        if (df_alloc_swap_map_extent(session, df, extent) != GS_SUCCESS) {
            continue;
        }

        spc_try_update_swap_hwm(session, space, file_no, extent->page + extent_size);
        return GS_SUCCESS;
    }
}

/*
 * search bitmap of datafile one by one for extent
 */
status_t spc_alloc_datafile_map_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent, 
    bool32 is_compress)
{
    datafile_t *df = NULL;
    uint32 id;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (space->ctrl->files[id] == GS_INVALID_ID32) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[id]);
        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        if (!is_compress != !DATAFILE_IS_COMPRESS(df)) {
            continue;
        }

        if (df_alloc_extent(session, df, extent_size, extent) != GS_SUCCESS) {
            continue;
        }

        spc_try_update_hwm(session, space, id, extent->page + extent_size);
        return GS_SUCCESS;
    }
    return GS_ERROR;
}

status_t spc_alloc_swap_map_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent)
{
    datafile_t *df = NULL;
    uint32 id;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (space->ctrl->files[id] == GS_INVALID_ID32) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[id]);
        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        if (df_alloc_swap_map_extent(session, df, extent) != GS_SUCCESS) {
            continue;
        }

        spc_try_update_swap_hwm(session, space, id, extent->page + extent_size);

        return GS_SUCCESS;
    }
    // caller will print error log
    return GS_ERROR;
}

/**
 * atomic operation and space lock need to be done
 *  ->atomic_op
 *  ---> space->lock
 **/
void spc_do_free_extent_list(knl_session_t *session, space_t *space)
{
    page_id_t page_id = SPACE_HEAD_RESIDENT(space)->free_extents.first;
    df_free_extent(session, DATAFILE_GET(page_id.file), page_id);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    space->head->free_extents.count--;

    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    } else {
        space->head->free_extents.first = spc_get_next_ext(session, page_id);
    }

    log_put(session, RD_SPC_ALLOC_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, GS_TRUE);
}


/*
 * strategy to allocate extent in space with map:
 * 1.alloc extent from datafile bitmap.
 * 2.try free extent list to bitmap pages and re-allocate from bitmap
 * 3.try recycle space object from recycle bin and re-allocate from bitmap.
 * 4.try extend space datafile when auto-extend is allowed and allocate from bitmap.
 * after purging recyclebin, we also need to extend datafile because extents may not free to bitmap immediately.
 */
status_t spc_alloc_extent_with_map(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent, 
    bool32 is_compress)
{
    cm_spin_lock(&space->lock, &session->stat_space);

    for (;;) {
        if (spc_alloc_datafile_map_extent(session, space, extent_size, extent, is_compress) == GS_SUCCESS) {
            cm_spin_unlock(&space->lock);
            knl_panic_log(!IS_INVALID_PAGID(*extent), "alloce bitmap extent (%u-%u) assert, "
                "datafile id is out of range.", extent->file, extent->page);
            // page 0 is datafile head, allow can not be 0. verified when alloc success. same as below
            knl_panic_log((extent->page != 0), "alloce bitmap extent (%u-%u) assert, 0 should be datafile head page.",
                extent->file, extent->page);
            return GS_SUCCESS;
        }

        // other sessions come here and find space->purging is true, do not wait for purging completed
        if (space->purging) {
            break;
        }

        if (!spc_auto_purge(session, space)) {
            break;
        }
    }

    if (spc_extend_datafile_map(session, space, extent_size, extent, is_compress) != GS_SUCCESS) {
        cm_spin_unlock(&space->lock);
        return GS_ERROR;
    }

    cm_spin_unlock(&space->lock);
    knl_panic_log(!IS_INVALID_PAGID(*extent), "alloce bitmap extent (%u-%u) assert, datafile id is out of range.",
        extent->file, extent->page);
    knl_panic_log((extent->page != 0), "alloce bitmap extent (%u-%u) assert, 0 should be datafile head page.",
        extent->file, extent->page);
    return GS_SUCCESS;
}

/*
 * we maintain two types tablespace with different extent management method:
 * 1.manage extent with hwm and free list, which only supports uniformed extent size
 * 2.manage extent with datafile bitmap, which can support dynamic extent size
 */
status_t spc_alloc_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent, 
    bool32 is_compress)
{
    if (SPACE_IS_BITMAPMANAGED(space)) {
        return spc_alloc_extent_with_map(session, space, extent_size, extent, is_compress);
    } else {
        if (is_compress) {
            GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "allocate compress extent from normal tablespace");
        }
        return spc_alloc_extent_normal(session, space, extent);
    }
}

// try to alloc extent with bitmap, if cant, degrade and try again
status_t spc_try_alloc_extent(knl_session_t *session, space_t *space, page_id_t *extent,
    uint32 *extent_size, bool32 *is_degrade, bool32 is_compress)
{
    uint32 size = *extent_size;
    status_t status = GS_ERROR;

    while (size != 0) {
        status = spc_alloc_extent(session, space, size, extent, is_compress);
        if (status == GS_SUCCESS) {
            break;
        }

        if (cm_get_error_code() != ERR_ALLOC_EXTENT) {
            break;
        }

        size = spc_degrade_extent_size(space, size);
        *is_degrade = GS_TRUE;
    }

    if (status == GS_SUCCESS && size != *extent_size) {
        cm_reset_error();
        GS_LOG_DEBUG_INF("alloc extent degrades, expect size: %u, degrade size: %u", *extent_size, size);
    }

    *extent_size = size;
    return status;
}

status_t spc_df_alloc_extent_normal(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    datafile_t *df)
{
    bool32 need_extend = GS_FALSE;
    int64 size, extent_bytes, unused_size, max_size;
    int32 *handle = NULL;
    uint32 hwm;

    extent_bytes = (int64)space->ctrl->extent_size * DEFAULT_PAGE_SIZE;

    for (;;) {
        if (need_extend) {
            if (!DATAFILE_IS_AUTO_EXTEND(df)) {
                GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
                return GS_ERROR;
            }

            if (df->ctrl->auto_extend_maxsize == 0 ||
                df->ctrl->auto_extend_maxsize > (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE) {
                max_size = (int64)MAX_FILE_PAGES(space->ctrl->type) * DEFAULT_PAGE_SIZE;
            } else {
                max_size = df->ctrl->auto_extend_maxsize;
            }

            unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE;

            if (df->ctrl->size - unused_size + extent_bytes > max_size) {
                GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
                return GS_ERROR;
            }

            if (df->ctrl->size + df->ctrl->auto_extend_size > max_size) {
                size = max_size - df->ctrl->size;
            } else {
                size = df->ctrl->auto_extend_size;
            }

            if (size + unused_size < extent_bytes) {
                size = extent_bytes - unused_size;
            }

            handle = DATAFILE_FD(space->ctrl->files[df->file_no]);
            if (spc_extend_datafile(session, df, handle, size, GS_TRUE) != GS_SUCCESS) {
                return GS_ERROR;
            }

            need_extend = GS_FALSE;
        }

        hwm = SPACE_HEAD_RESIDENT(space)->hwms[df->file_no];
        if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
            GS_THROW_ERROR(ERR_MAX_DATAFILE_PAGES, hwm, MAX_FILE_PAGES(space->ctrl->type), space->ctrl->name);
            return GS_ERROR;
        }

        if (df->ctrl->size < (int64)(hwm + space->ctrl->extent_size) * space->ctrl->block_size) {
            need_extend = GS_TRUE;
            continue;
        }

        spc_alloc_datafile_hwm_extent(session, space, df->file_no, extent, extent_size);     

        break;
    }

    return GS_SUCCESS;
}

/* This function only used in restrict now!! So we don't consider concurrency here. */
status_t spc_df_alloc_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    datafile_t *df)
{
    if (!DATAFILE_IS_ONLINE(df)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "extend undo segments failed");
        return GS_ERROR;
    }

    if (!DB_IS_RESTRICT(session)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in restrict mode");
        return GS_ERROR;
    }

    if (SPACE_IS_BITMAPMANAGED(space)) {
        GS_THROW_ERROR(ERR_INVALID_OPERATION, ",operation only supported in normal space");
        return GS_ERROR;
    }

    return spc_df_alloc_extent_normal(session, space, extent_size, extent, df);
}

/*
 * Try to extend undo extent like space extend extent, but without errmsg.
 */
static bool32 spc_extend_undo_extent(knl_session_t *session, space_t *space, uint32 extents, page_id_t *extent)
{
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 size, extent_size, unused_size;
    uint32 file_no, id, hwm;

    size = 0;
    file_no = GS_INVALID_ID32;
    extent_size = (int64)extents * DEFAULT_PAGE_SIZE;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (GS_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[id]);
        hwm = SPACE_HEAD_RESIDENT(space)->hwms[id];

        if (!DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE;
        if (unused_size  < extent_size) {
            if (DATAFILE_IS_AUTO_EXTEND(df) && (df->ctrl->size < size || size == 0)) {
                /* guarantee that can alloc an extent at lease after extend */
                if (df->ctrl->size + extent_size - unused_size > df->ctrl->auto_extend_maxsize) {
                    continue;
                }
                file_no = id;
                size = df->ctrl->size;
            }
            continue;
        }

        if (hwm + GS_EXTENT_SIZE > MAX_FILE_PAGES(space->ctrl->type)) {
            continue;
        }

        spc_alloc_datafile_hwm_extent(session, space, id, extent, GS_EXTENT_SIZE);

        return GS_TRUE;
    }

    if (GS_INVALID_ID32 == file_no) {
        space->allow_extend = GS_FALSE;
        GS_LOG_RUN_INF("invalid undo file number,disable undo space extend.");
        return GS_FALSE;
    }

    hwm = SPACE_HEAD_RESIDENT(space)->hwms[file_no];
    if (hwm + GS_EXTENT_SIZE > MAX_FILE_PAGES(space->ctrl->type)) {
        space->allow_extend = GS_FALSE;
        GS_LOG_RUN_INF("undo file[%u] no free space,disable undo space extend.", file_no);
        return GS_FALSE;
    }

    df = DATAFILE_GET(space->ctrl->files[file_no]);
    handle = DATAFILE_FD(space->ctrl->files[file_no]);
    unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE;

    if (df->ctrl->size + df->ctrl->auto_extend_size > df->ctrl->auto_extend_maxsize) {
        size = df->ctrl->auto_extend_maxsize - df->ctrl->size;
    } else {
        size = df->ctrl->auto_extend_size;
    }

    if (size + unused_size < extent_size) {
        size = extent_size - unused_size;
    }

    if (spc_extend_datafile(session, df, handle, size, GS_TRUE) != GS_SUCCESS) {
        return GS_FALSE;
    }

    spc_alloc_datafile_hwm_extent(session, space, file_no, extent, GS_EXTENT_SIZE);

    return GS_TRUE;
}

static void spc_alloc_undo_from_space(knl_session_t *session, space_t *space, page_id_t *extent, bool32 need_redo)
{
    *extent = space->head->free_extents.first;
    space->head->free_extents.count--;
    
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    } else {
        space->head->free_extents.first = spc_get_next_undo_ext_prefetch(session, *extent);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
    }
    
    if (need_redo) {
        log_put(session, RD_SPC_ALLOC_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    return;
}

/*
 * Used for undo alloc pages for txn, pages are linked on space head free extent.
 * When try to extend extent, alloc extent in GS_EXTENT_SIZE steps as normal
 * space without error msg.
 */
bool32 spc_alloc_undo_extent(knl_session_t *session, space_t *space, page_id_t *extent, uint32 *extent_size)
{
    bool32 result = GS_FALSE;
    bool32 need_redo = SPACE_IS_LOGGING(space);

    CM_POINTER4(session, space, extent, extent_size);

    // take a quick glance at undo space with optimistic lock.
    if (!space->allow_extend && SPACE_HEAD_RESIDENT(space)->free_extents.count == 0) {
        *extent_size = 0;
        return GS_FALSE;
    }

    cm_spin_lock(&space->lock, &session->stat_space);
    if (!space->allow_extend && SPACE_HEAD_RESIDENT(space)->free_extents.count == 0) {
        *extent_size = 0;
        cm_spin_unlock(&space->lock);
        return GS_FALSE;
    }

    for (;;) {
        if (SPACE_HEAD_RESIDENT(space)->free_extents.count == 0) {
            *extent_size = GS_EXTENT_SIZE;
            result = spc_extend_undo_extent(session, space, *extent_size, extent);
            cm_spin_unlock(&space->lock);
            return result;
        }

        buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        spc_alloc_undo_from_space(session, space, extent, need_redo);
        buf_leave_page(session, GS_TRUE);

        if (extent->page >= space->head->hwms[DATAFILE_GET(extent->file)->file_no]) {
            GS_LOG_RUN_INF("ignore invalid extent(%u-%d), space %s, file no %u", 
                           extent->file, extent->page, space->ctrl->name, DATAFILE_GET(extent->file)->file_no);
            continue;
        }
        break;
    }

    *extent_size = space->ctrl->extent_size;
    cm_spin_unlock(&space->lock);

    return GS_TRUE;
}

void spc_free_extent(knl_session_t *session, space_t *space, page_id_t extent)
{
    knl_panic_log(!IS_INVALID_PAGID(extent), "extent is invalid page, panic info: page %u-%u", extent.file,
                  extent.page);
    CM_POINTER2(session, space);

    bool32 need_redo = SPACE_IS_LOGGING(space);

    cm_spin_lock(&space->lock, &session->stat_space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = extent;
        space->head->free_extents.last = extent;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
        spc_concat_extent(session, extent, space->head->free_extents.first);
        space->head->free_extents.first = extent;
    }
    space->head->free_extents.count++;

    if (need_redo) {
        log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    cm_spin_unlock(&space->lock);
}

void spc_free_extents(knl_session_t *session, space_t *space, page_list_t *extents)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    knl_panic_log(!IS_INVALID_PAGID(extents->first),
                  "the first of extents is invalid page, panic info: first page of extents %u-%u",
                  space->head->free_extents.first.file, space->head->free_extents.first.page);
    knl_panic_log(!IS_INVALID_PAGID(extents->last),
                  "the last of extents is invalid page, panic info: last page of extents %u-%u",
                  space->head->free_extents.last.file, space->head->free_extents.last.page);
    CM_POINTER3(session, space, extents);

    cm_spin_lock(&space->lock, &session->stat_space);

#ifdef DB_DEBUG_VERSION
    spc_validate_extents(session, extents);
#endif

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (space->head->free_extents.count == 0) {
        space->head->free_extents = *extents;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
        spc_concat_extent(session, extents->last, space->head->free_extents.first);
        space->head->free_extents.first = extents->first;
        space->head->free_extents.count += extents->count;
    }

    if (need_redo) {
        log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    cm_spin_unlock(&space->lock);
}

/*
 * free extents on space free list back to bitmap
 */
status_t spc_free_extent_from_list(knl_session_t *session, space_t *space, const char *oper)
{
    log_atomic_op_begin(session);

    if (!cm_spin_try_lock(&space->lock)) {
        if (oper != NULL) {
            GS_THROW_ERROR_EX(ERR_OPERATIONS_NOT_ALLOW, "%s when space %s is being locked",
                oper, space->ctrl->name);
        }
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    /* space has been dropped or no free page when been reused */
    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "bitmap space free extents failed");
        cm_spin_unlock(&space->lock);
        log_atomic_op_end(session);
        return GS_ERROR;
    }

    if (SPACE_HEAD_RESIDENT(space)->free_extents.count == 0) {
        cm_spin_unlock(&space->lock);
        log_atomic_op_end(session);
        return GS_SUCCESS;
    }

    spc_do_free_extent_list(session, space);

    cm_spin_unlock(&space->lock);
    log_atomic_op_end(session);
    return GS_SUCCESS;
}

// the function need to be done under SPACE -> LOCK
bool32 spc_try_free_extent_list(knl_session_t *session, space_t *space)
{
    log_atomic_op_begin(session);

    if (SPACE_HEAD_RESIDENT(space)->free_extents.count == 0) {
        cm_spin_unlock(&space->lock);
        log_atomic_op_end(session);
        return GS_FALSE;
    }

    spc_do_free_extent_list(session, space);

    log_atomic_op_end(session);
    return GS_TRUE;
}

void spc_free_undo_extents(knl_session_t *session, space_t *space, undo_page_list_t *extents)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    knl_panic_log(!IS_INVALID_PAGID(extents->first),
                  "the first of extents is invalid page, panic info: first page of extents %u-%u",
                  space->head->free_extents.first.file, space->head->free_extents.first.page);
    knl_panic_log(!IS_INVALID_PAGID(extents->last),
                  "the last of extents is invalid page, panic info: last page of extents %u-%u",
                  space->head->free_extents.last.file, space->head->free_extents.last.page);
    CM_POINTER3(session, space, extents);

    cm_spin_lock(&space->lock, &session->stat_space);

#ifdef DB_DEBUG_VERSION
    spc_validate_undo_extents(session, extents);
#endif

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = PAGID_U2N(extents->first);
        space->head->free_extents.last = PAGID_U2N(extents->last);
        space->head->free_extents.count = extents->count;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
        spc_concat_extent(session, PAGID_U2N(extents->last), space->head->free_extents.first);
        space->head->free_extents.first = PAGID_U2N(extents->first);
        space->head->free_extents.count += extents->count;
    }

    if (need_redo) {
        log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);

    cm_spin_unlock(&space->lock);
}

void spc_create_segment(knl_session_t *session, space_t *space)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    space->head->segment_count++;
    if (need_redo) {
        log_put(session, RD_SPC_CHANGE_SEGMENT, &space->head->segment_count, sizeof(uint32), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
}

void spc_drop_segment(knl_session_t *session, space_t *space)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    knl_panic_log(space->head->segment_count > 0,
                  "segment_count abnormal, panic info: page %u-%u type %u segment_count %u", space->entry.file,
                  space->entry.page, ((page_head_t *)CURR_PAGE)->type, space->head->segment_count);
    space->head->segment_count--;
    if (need_redo) {
        log_put(session, RD_SPC_CHANGE_SEGMENT, &space->head->segment_count, sizeof(uint32), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
}

/*
 * db crash when creating space may bring out space that is not completed after recovery,
 * so we need to clean those garbage spaces after recovery or before standby is becoming primary.
 */
status_t spc_clean_garbage_space(knl_session_t *session)
{
    space_t *space = NULL;
    char spc_name[GS_NAME_BUFFER_SIZE];
    uint32 i;
    errno_t ret;

    GS_LOG_RUN_INF("[SPACE] Clean garbage tablespace start");
    for (i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(i);
        if (!space->ctrl->used || space->ctrl->file_hwm != 0) {
            continue;
        }

        ret = strncpy_s(spc_name, GS_NAME_BUFFER_SIZE, space->ctrl->name, sizeof(space->ctrl->name) - 1);
        knl_securec_check(ret);

        if (spc_remove_space(session, space, TABALESPACE_INCLUDE || TABALESPACE_DFS_AND, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when drop tablespace");
        }

        GS_LOG_RUN_INF("[SPACE] succeed to clean garbage tablespace %s", spc_name);
    }

    GS_LOG_RUN_INF("[SPACE] Clean garbage tablespace end");

    return GS_SUCCESS;
}

page_id_t spc_get_next_ext(knl_session_t *session, page_id_t extent)
{
    buf_enter_page(session, extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *last_page = (page_head_t *)session->curr_page;
    extent = AS_PAGID(last_page->next_ext);
    buf_leave_page(session, GS_FALSE);
    return extent;
}

// get current extent size and next extent
page_id_t spc_get_size_next_ext(knl_session_t *session, space_t *space, page_id_t extent, uint32 *ext_size)
{
    page_head_t *last_page = NULL;

    buf_enter_page(session, extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    last_page = (page_head_t *)session->curr_page;

    *ext_size = spc_get_page_ext_size(space, last_page->ext_size);

    extent = AS_PAGID(last_page->next_ext);
    buf_leave_page(session, GS_FALSE);
    return extent;
}

page_id_t spc_get_next_undo_ext_prefetch(knl_session_t *session, page_id_t extent)
{
    page_head_t *last_page = NULL;

    buf_enter_prefetch_page_num(session, extent, UNDO_PREFETCH_NUM, LATCH_MODE_S, ENTER_PAGE_HIGH_AGE);
    last_page = (page_head_t *)session->curr_page;
    extent = AS_PAGID(last_page->next_ext);
    buf_leave_page(session, GS_FALSE);
    return extent;
}

uint32 spc_get_df_used_pages(knl_session_t *session, space_t *space, uint32 file_no)
{
    datafile_t *df = NULL;

    if (SPACE_IS_BITMAPMANAGED(space)) {
        df = DATAFILE_GET(space->ctrl->files[file_no]);
        return df_get_used_pages(session, df);
    } else {
        return space->head->hwms[file_no];
    }
}

status_t spc_get_space_name(knl_session_t *session, uint32 space_id, text_t *space_name)
{
    space_t *space = NULL;

    if (space_id >= GS_MAX_SPACES) {
        GS_THROW_ERROR(ERR_TOO_MANY_OBJECTS, GS_MAX_SPACES, "tablespace");
        return GS_ERROR;
    }

    space = SPACE_GET(space_id);
    if (!space->ctrl->used) {
        GS_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tablespace", space_id);
        return GS_ERROR;
    }

    cm_str2text(space->ctrl->name, space_name);
    return GS_SUCCESS;
}

status_t spc_get_space_id(knl_session_t *session, const text_t *name, uint32 *space_id)
{
    space_t *space = NULL;
    uint32 i = 0;
    CM_POINTER3(session, name, space_id);

    for (i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(i);
        if (!space->ctrl->used) {
            continue;
        }

        if (cm_text_str_equal(name, space->ctrl->name)) {
            break;
        }
    }

    if (i >= GS_MAX_SPACES) {
        GS_THROW_ERROR(ERR_SPACE_NOT_EXIST, T2S(name));
        return GS_ERROR;
    }

    *space_id = i;
    return GS_SUCCESS;
}

status_t spc_check_user_privs(knl_session_t *session, uint32 space_id)
{
    space_t *space = SPACE_GET(space_id);

    if (!(IS_SYSTEM_SPACE(space) || IS_SYSAUX_SPACE(space))) {
        return GS_SUCCESS;
    }

    if (knl_check_sys_priv_by_uid(session, session->uid, USE_ANY_TABLESPACE)) {
        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_NO_SPACE_PRIV, space->ctrl->name);
    return GS_ERROR;
}

// get space id and check if space is usable in the tenant by user id
status_t spc_check_by_uid(knl_session_t *session, const text_t *name, uint32 space_id, uint32 uid)
{
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, uid, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    if (spc_check_user_privs(session, space_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return spc_check_by_tid(session, name, space_id, user->desc.tenant_id);
}

// get space id and check if space is usable in the tenant by tenant id
status_t spc_check_by_tid(knl_session_t *session, const text_t *name, uint32 space_id, uint32 tid)
{
    dc_tenant_t *tenant = NULL;
    bool32 flag;

    if (tid == SYS_TENANTROOT_ID) {
        return GS_SUCCESS;
    }
    if (dc_open_tenant_by_id(session, tid, &tenant) != GS_SUCCESS) {
        return GS_ERROR;
    }

    flag = dc_get_tenant_tablespace_bitmap(&tenant->desc, space_id);
    dc_close_tenant(session, tid);
    if (!flag) {
        GS_THROW_ERROR(ERR_SPACE_DISABLED, T2S(name));
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

uint64 spc_count_pages(knl_session_t *session, space_t *space, bool32 used)
{
    datafile_t *df = NULL;
    uint64 total_pages = 0;

    CM_POINTER2(session, space);

    cm_spin_lock(&space->lock, &session->stat_space);

    /*
     * for undo space , total pages is less than 2^22 * 1000
     * for other spaces, total pages is less than 2^30 * 1000
     */
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        if (used) {
            total_pages += SPACE_HEAD_RESIDENT(space)->hwms[i];
        } else {
            df = DATAFILE_GET(space->ctrl->files[i]);
            total_pages += (uint32)((uint64)df->ctrl->size / DEFAULT_PAGE_SIZE);
        }
    }

    cm_spin_unlock(&space->lock);

    return total_pages;
}

uint64 spc_count_backup_pages(knl_session_t *session, space_t *space)
{
    datafile_t *df = NULL;
    uint64 total_pages = 0;
    uint32 dw_file_id = knl_get_dbwrite_file_id(session);

    CM_POINTER2(session, space);
    cm_spin_lock(&space->lock, &session->stat_space);

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        /*
         * in datafile including double write area, double write area only backup space_head page
         * in normal datafile, read skip file_hdr
         */
        df = DATAFILE_GET(space->ctrl->files[i]);
        if (!DATAFILE_IS_ONLINE(df) || !df->ctrl->used) {
            continue;
        }
        if (DATAFILE_CONTAINS_DW(df, dw_file_id)) { 
            total_pages += (SPACE_HEAD_RESIDENT(space)->hwms[i] - DW_SPC_HWM_START + 1);
        } else {
            total_pages += (SPACE_HEAD_RESIDENT(space)->hwms[i] - 1);
        }       
    }

    cm_spin_unlock(&space->lock);
    return total_pages;
}

uint64 spc_count_pages_with_ext(knl_session_t *session, space_t *space, bool32 used)
{
    datafile_t *df = NULL;
    uint64 total_pages = 0;

    CM_POINTER2(session, space);
    cm_spin_lock(&space->lock, &session->stat_space);
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        if (used) {
            total_pages += SPACE_HEAD_RESIDENT(space)->hwms[i];
        } else {
            df = DATAFILE_GET(space->ctrl->files[i]);
            if (!DATAFILE_IS_ONLINE(df)) {
                continue;
            }
            if (DATAFILE_IS_AUTO_EXTEND(df)) {
                total_pages += (uint64)df->ctrl->auto_extend_maxsize / DEFAULT_PAGE_SIZE;
            } else {
                total_pages += (uint32)((uint64)df->ctrl->size / DEFAULT_PAGE_SIZE);
            }
        }
    }

    cm_spin_unlock(&space->lock);

    return total_pages;
}

uint32 spc_ext_cnt_by_pages(space_t *space, uint32 page_count)
{
    uint32 extent_cnt = 0;

    if (page_count == 0 || page_count == GS_INVALID_INT64) {
        return GS_INVALID_INT32;
    }

    if (SPACE_IS_AUTOALLOCATE(space)) {
        if (page_count >= EXT_SIZE_1024_PAGE_BOUNDARY) {
            extent_cnt = CM_CALC_ALIGN(page_count - EXT_SIZE_1024_PAGE_BOUNDARY, EXT_SIZE_8192) / EXT_SIZE_8192;
            extent_cnt += EXT_SIZE_1024_BOUNDARY;
        } else if (page_count >= EXT_SIZE_128_PAGE_BOUNDARY) {
            extent_cnt = CM_CALC_ALIGN(page_count - EXT_SIZE_128_PAGE_BOUNDARY, EXT_SIZE_1024) / EXT_SIZE_1024;
            extent_cnt += EXT_SIZE_128_BOUNDARY;
        } else if (page_count >= EXT_SIZE_8_PAGE_BOUNDARY) {
            extent_cnt = CM_CALC_ALIGN(page_count - EXT_SIZE_8_PAGE_BOUNDARY, EXT_SIZE_128) / EXT_SIZE_128;
            extent_cnt += EXT_SIZE_8_BOUNDARY;
        } else {
            extent_cnt = CM_CALC_ALIGN(page_count, EXT_SIZE_8) / EXT_SIZE_8;
        }
    } else {
        extent_cnt = CM_CALC_ALIGN(page_count, space->ctrl->extent_size) / space->ctrl->extent_size;
    }
    return extent_cnt;
}

static inline void spc_alloc_datafile_temp_extent(knl_session_t *session, space_t *space, uint32 id,
    page_id_t *extent, uint32 extent_size)
{
    knl_panic_log(IS_SWAP_SPACE(space), "space is not swap, panic info: page %u-%u", extent->file, extent->page);

    extent->page = SPACE_HEAD_RESIDENT(space)->hwms[id];
    extent->file = space->ctrl->files[id];
    space->head->hwms[id] += extent_size;  // the maximum page hwm of a datafile is 2^30
}

static status_t spc_extend_temp_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "space is not swap, panic info: page %u-%u", extent->file, extent->page);
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 size, extent_size, unused_size;
    uint32 file_no, id, hwm;

    size = 0;
    file_no = GS_INVALID_ID32;
    extent_size = (int64)space->ctrl->extent_size * DEFAULT_PAGE_SIZE;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (GS_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[id]);
        hwm = SPACE_HEAD_RESIDENT(space)->hwms[id];
        unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE;

        if (unused_size < extent_size) {
            if (DATAFILE_IS_AUTO_EXTEND(df) && (df->ctrl->size < size || size == 0)) {
                /* extend one extent at least */
                if (df->ctrl->size + extent_size - unused_size > df->ctrl->auto_extend_maxsize) {
                    continue;
                }

                file_no = id;
                size = df->ctrl->size;
            }
            continue;
        }

        if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
            continue;
        }

        buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
        spc_alloc_datafile_temp_extent(session, space, id, extent, space->ctrl->extent_size);
        buf_leave_temp_page(session);
        return GS_SUCCESS;
    }

    if (GS_INVALID_ID32 == file_no) {
        GS_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        return GS_ERROR;
    }

    hwm = SPACE_HEAD_RESIDENT(space)->hwms[file_no];
    if (hwm + space->ctrl->extent_size > MAX_FILE_PAGES(space->ctrl->type)) {
        GS_THROW_ERROR(ERR_MAX_DATAFILE_PAGES, hwm, MAX_FILE_PAGES(space->ctrl->type), space->ctrl->name);
        return GS_ERROR;
    }

    df = DATAFILE_GET(space->ctrl->files[file_no]);
    handle = DATAFILE_FD(space->ctrl->files[file_no]);
    unused_size = df->ctrl->size - (int64)hwm * DEFAULT_PAGE_SIZE;

    if (df->ctrl->size + df->ctrl->auto_extend_size > df->ctrl->auto_extend_maxsize) {
        size = df->ctrl->auto_extend_maxsize - df->ctrl->size;
    } else {
        size = df->ctrl->auto_extend_size;
    }

    if (size + unused_size < extent_size) {
        size = extent_size - unused_size;
    }

    if (GS_SUCCESS != spc_extend_datafile(session, df, handle, size, GS_FALSE)) {
        return GS_ERROR;
    }

    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    spc_alloc_datafile_temp_extent(session, space, file_no, extent, space->ctrl->extent_size);
    buf_leave_temp_page(session);

    return GS_SUCCESS;
}

static void spc_alloc_free_temp_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    *extent = space->head->free_extents.first;
    space->head->free_extents.count--;
    
    knl_panic_log(!IS_INVALID_PAGID(*extent), "extent is invalid page, panic info: page %u-%u", extent->file,
                  extent->page);
    
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    } else {
        page_id_t next_ext = spc_get_next_temp_ext(session, *extent);
        knl_panic_log(!IS_INVALID_PAGID(next_ext), "next extent is invalid page, panic info: next extent %u-%u",
                      next_ext.file, next_ext.page);
        space->head->free_extents.first = next_ext;
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
    }

    buf_leave_temp_page(session);
}

status_t spc_alloc_swap_extent_normal(knl_session_t *session, space_t *space, page_id_t *extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "[SPACE] space %u is not swap space, type is %u.",
        space->ctrl->id, space->ctrl->type);
    CM_POINTER3(session, space, extent);

    cm_spin_lock(&space->lock, &session->stat_space);
    for (;;) {
        if (space->head->free_extents.count == 0) {
            if (GS_SUCCESS != spc_extend_temp_extent(session, space, extent)) {
                cm_spin_unlock(&space->lock);
                return GS_ERROR;
            }
            cm_spin_unlock(&space->lock);
            return GS_SUCCESS;
        }

        spc_alloc_free_temp_extent(session, space, extent);
        if (extent->page >= space->head->hwms[DATAFILE_GET(extent->file)->file_no]) {
            GS_LOG_RUN_INF("ignore invalid extent(%u-%d), space %s, file no %u", 
                           extent->file, extent->page, space->ctrl->name, DATAFILE_GET(extent->file)->file_no);
            continue;
        }
        break;
    }

    cm_spin_unlock(&space->lock);
    return GS_SUCCESS;
}

status_t spc_alloc_swap_extent_map(knl_session_t *session, space_t *space, page_id_t *extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "[SPACE] space %u is not swap space, type is %u.",
        space->ctrl->id, space->ctrl->type);
    cm_spin_lock(&space->lock, &session->stat_space);

    if (spc_alloc_swap_map_extent(session, space, space->ctrl->extent_size, extent) == GS_SUCCESS) {
        knl_panic_log(!IS_INVALID_PAGID(*extent),
            "alloc bitmap extent (%u-%u) error, page id is invalid.", extent->file, extent->page);
        cm_spin_unlock(&space->lock);
        return GS_SUCCESS;
    }

    if (spc_extend_swap_datafile_map(session, space, space->ctrl->extent_size, extent) != GS_SUCCESS) {
        cm_spin_unlock(&space->lock);
        GS_LOG_RUN_ERR("[SPACE] space %u extend datafile failed, extend size is %u.",
            space->ctrl->id, space->ctrl->extent_size);
        return GS_ERROR;
    }

    knl_panic(!IS_INVALID_PAGID(*extent));
    cm_spin_unlock(&space->lock);
    return GS_SUCCESS;
}

status_t spc_alloc_swap_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    if (SECUREC_LIKELY(SPACE_SWAP_BITMAP(space))) {
        return spc_alloc_swap_extent_map(session, space, extent);
    } else {
        return spc_alloc_swap_extent_normal(session, space, extent);
    }
}

void spc_free_temp_extent_normal(knl_session_t *session, space_t *space, page_id_t extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "space is not swap, panic info: page %u-%u", extent.file, extent.page);
    CM_POINTER2(session, space);

    knl_panic_log(!IS_INVALID_PAGID(extent), "current extent is invalid, panic info: extent page %u-%u", extent.file,
                  extent.page);

    cm_spin_lock(&space->lock, &session->stat_space);

    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = extent;
        space->head->free_extents.last = extent;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
        spc_concat_temp_extent(session, space->head->free_extents.last, extent);
        space->head->free_extents.last = extent;
    }
    space->head->free_extents.count++;
    buf_leave_temp_page(session);
    cm_spin_unlock(&space->lock);
}


void spc_free_temp_extent_map(knl_session_t *session, space_t *space, page_id_t extent)
{
    knl_panic_log(IS_SWAP_SPACE(space), "[SPACE] space %u is not swap space, type is %u.",
        space->ctrl->id, space->ctrl->type);
    CM_POINTER2(session, space);
    knl_panic_log(!IS_INVALID_PAGID(extent),
        "alloc bitmap extent (%u-%u) error, page id is invalid.", extent.file, extent.page);

    cm_spin_lock(&space->lock, &session->stat_space);
    df_free_swap_map_extent(session, DATAFILE_GET(extent.file), extent);
    cm_spin_unlock(&space->lock);
}

void spc_free_temp_extent(knl_session_t *session, space_t *space, page_id_t extent)
{
    if (SECUREC_LIKELY(SPACE_SWAP_BITMAP(space))) {
        spc_free_temp_extent_map(session, space, extent);
    } else {
        spc_free_temp_extent_normal(session, space, extent);
    }
}

static status_t spc_load_temp_page_header(knl_session_t *session, page_id_t page_id, page_head_t *page)
{
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 offset;

    if (IS_INVALID_PAGID(page_id)) {
        GS_LOG_RUN_ERR("invalid page id in getting temp page cache");
        knl_panic_log(0, "panic info: page %u-%u type %u", page_id.file, page_id.page, page->type);
    }

    df = DATAFILE_GET(page_id.file);
    handle = DATAFILE_FD(page_id.file);
    offset = (int64)page_id.page * DEFAULT_PAGE_SIZE;  // the maximum offset is 2^30 * 2^13

    if (spc_read_datafile(session, df, handle, offset, page, DEFAULT_PAGE_SIZE) != GS_SUCCESS) {
        spc_close_datafile(df, handle);
        GS_LOG_RUN_ERR("[BUFFER] failed to open datafile %s", df->ctrl->name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t spc_write_temp_page_header(knl_session_t *session, page_id_t page_id, page_head_t *page)
{
    datafile_t *df = NULL;
    int32 *handle = NULL;
    int64 offset;

    if (IS_INVALID_PAGID(page_id)) {
        GS_LOG_RUN_ERR("invalid page id in getting temp page cache");
        knl_panic_log(0, "panic info: page %u-%u type %u", page_id.file, page_id.page, page->type);
    }

    df = DATAFILE_GET(page_id.file);
    handle = DATAFILE_FD(page_id.file);
    offset = (int64)page_id.page * DEFAULT_PAGE_SIZE;  // the maximum offset is 2^30 * 2^13

    if (spc_write_datafile(session, df, handle, offset, page, (int32)DEFAULT_PAGE_SIZE) != GS_SUCCESS) {
        spc_close_datafile(df, handle);
        GS_LOG_RUN_ERR("[BUFFER] failed to write datafile %s", df->ctrl->name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

page_id_t spc_get_next_temp_ext(knl_session_t *session, page_id_t extent)
{
    char *alloc_buffer = (char *)cm_push(session->stack, (uint32)(DEFAULT_PAGE_SIZE + GS_MAX_ALIGN_SIZE_4K));
    char *buffer = (char *)cm_aligned_buf(alloc_buffer);
    page_head_t *last_page;

    last_page = (page_head_t *)buffer;
    if (GS_SUCCESS != spc_load_temp_page_header(session, extent, last_page)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to load temparory page %u-%u", extent.file, extent.page);
    }
    extent = AS_PAGID(last_page->next_ext);

    knl_panic_log(!IS_INVALID_PAGID(extent), "get next temp extent error, page id %u-%u.",
        extent.file, extent.page);
    knl_panic_log(IS_SWAP_SPACE(SPACE_GET(DATAFILE_GET(extent.file)->space_id)),
        "get next temp extent error, page id %u-%u.", extent.file, extent.page);

    cm_pop(session->stack);
    return extent;
}

page_id_t spc_try_get_next_temp_ext(knl_session_t *session, page_id_t extent)
{
    datafile_t *df = NULL;
    space_t *space = NULL;

    if (IS_INVALID_PAGID(extent)) {
        return g_invalid_pagid;
    }

    df = DATAFILE_GET(extent.file);
    space = SPACE_GET(df->space_id);
    if (!IS_SWAP_SPACE(space) || !df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        return g_invalid_pagid;
    }

    return spc_get_next_temp_ext(session, extent);
}

void spc_concat_temp_extent(knl_session_t *session, page_id_t last_ext, page_id_t ext)
{
    char *alloc_buffer = (char *)cm_push(session->stack, (uint32)(DEFAULT_PAGE_SIZE + GS_MAX_ALIGN_SIZE_4K));
    char *buffer = (char *)cm_aligned_buf(alloc_buffer);
    page_head_t *head;

    head = (page_head_t *)buffer;
    if (GS_SUCCESS != spc_load_temp_page_header(session, last_ext, head)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to load temporary page %u-%u", last_ext.file, last_ext.page);
    }

    TO_PAGID_DATA(ext, head->next_ext);

    if (GS_SUCCESS != spc_write_temp_page_header(session, last_ext, head)) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to write temporary page %u-%u", last_ext.file, last_ext.page);
    }

    cm_pop(session->stack);
}

bool32 spc_auto_offline_space(knl_session_t *session, space_t *space, datafile_t *df)
{
    if (!SPACE_IS_AUTOOFFLINE(space)) {
        return GS_FALSE;
    }

    GS_LOG_RUN_INF("[SPACE] auto offline space %s and datafile %s", space->ctrl->name, df->ctrl->name);
    DATAFILE_UNSET_ONLINE(df);
    SPACE_UNSET_ONLINE(space);

    if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when auto offline datafile %s",
                 df->ctrl->name);
    }

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when auto offline space %s",
                 space->ctrl->name);
    }

    return GS_TRUE;
}

status_t spc_rebuild_space(knl_session_t *session, space_t *space)
{
    datafile_t *df = &session->kernel->db.datafiles[space->ctrl->files[0]];
    space_head_t *spc_head = NULL;
    page_id_t page_id;
    char *buf = NULL;
    errno_t ret;

    if (!IS_SWAP_SPACE(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "rebuild space which is not temp");
        return GS_ERROR;
    }

    if (spc_open_datafile(session, df, DATAFILE_FD(df->ctrl->id)) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("[SPACE] failed to open datafile %s when rebuild space", df->ctrl->name);
        return GS_ERROR;
    }

    if (spc_init_datafile_head(session, df) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE + GS_MAX_ALIGN_SIZE_4K);
    char *space_buf = (char *)cm_aligned_buf(buf);
    ret = memset_sp(space_buf, DEFAULT_PAGE_SIZE, 0, DEFAULT_PAGE_SIZE);
    knl_securec_check(ret);

    page_id.file = df->ctrl->id;
    page_id.page = SPACE_ENTRY_PAGE;
    page_init(session, (page_head_t *)space_buf, page_id, PAGE_TYPE_SPACE_HEAD);

    spc_head = (space_head_t *)(space_buf + sizeof(page_head_t));
    space->head = spc_head;
    spc_init_swap_space(session, space);

    if (cm_write_device(df->ctrl->type, session->datafiles[df->ctrl->id], DEFAULT_PAGE_SIZE, space_buf, DEFAULT_PAGE_SIZE)) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    cm_pop(session->stack);
    return GS_SUCCESS;
}

bool32 spc_validate_page_id(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    uint32 dw_file_id;

    if (IS_INVALID_PAGID(page_id) || page_id.page == 0) {
        return GS_FALSE;
    }

    df = DATAFILE_GET(page_id.file);
    if (DF_FILENO_IS_INVAILD(df) || !df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        return GS_FALSE;
    }

    space = SPACE_GET(df->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        return GS_FALSE;
    }

    if (IS_SWAP_SPACE(space)) {
        return GS_FALSE;
    }

    dw_file_id = knl_get_dbwrite_file_id(session);
    if (DATAFILE_CONTAINS_DW(df, dw_file_id)) {
        if (page_id.page < DW_SPC_HWM_START && page_id.page > DW_DISTRICT_BEGIN) {
            return GS_FALSE;
        }
    }

    if (page_id.page >= SPACE_HEAD_RESIDENT(space)->hwms[df->file_no]) {
        return GS_FALSE;
    }

#ifdef DB_DEBUG_VERSION
    /* there is no temp2_undo rollback during recovery */
    if (DB_IS_BG_ROLLBACK_SE(session)) {
        knl_panic_log(SPACE_IS_LOGGING(space), "current space is logging table space, panic info: page %u-%u",
                      page_id.file, page_id.page);
    }
#endif

    return GS_TRUE;
}

status_t space_head_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    space_head_t *space_head = (space_head_t *)((char *)page_head + PAGE_HEAD_SIZE);

    cm_dump(dump, "space head information\n");
    cm_dump(dump, "\tsegment_count: %u", space_head->segment_count);
    cm_dump(dump, "\tdatafile_count: %u", space_head->datafile_count);
    cm_dump(dump, "\tfree_extents: count %u \tfirst %u-%u \tlast %u-%u\n", space_head->free_extents.count,
        space_head->free_extents.first.file, space_head->free_extents.first.page,
        space_head->free_extents.last.file, space_head->free_extents.last.page);
    cm_dump(dump, "datafile hwms information:");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 slot = 0; slot < GS_MAX_SPACE_FILES; slot++) {

        /* space files per line 80 */
        if (slot % SPACE_FILE_PER_LINE == 0) {
            cm_dump(dump, "\n\t");
        }

        cm_dump(dump, "%u ", space_head->hwms[slot]);
        CM_DUMP_WRITE_FILE(dump);
    }

    return GS_SUCCESS;
}

void spc_init_swap_space_bitmap(knl_session_t *session, space_t *space)
{
    datafile_t *df = NULL;
    buf_enter_temp_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    space_head_t *spc_head = space->head;
    page_init(session, (page_head_t *)CURR_PAGE, space->entry, PAGE_TYPE_SPACE_HEAD);
    knl_securec_check(memset_sp(space->head, sizeof(space_head_t), 0, sizeof(space_head_t)));
    // free_extents will not be used for bitmap swap space
    spc_head->free_extents.first = INVALID_PAGID;
    spc_head->free_extents.last = INVALID_PAGID;
    space->swap_bitmap = GS_TRUE;

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[i]);
        spc_head->datafile_count++;
        // init map group and update hwms
        df_init_swap_map_head(session, df);
        spc_head->hwms[i] = DF_MAP_GROUP_SIZE;
    }
    buf_leave_temp_page(session);

    GS_LOG_RUN_INF("[SPACE] init swap space %u bitmap head.", space->ctrl->id);
}

void spc_init_swap_space_normal(space_t *space)
{
    space_head_t *spc_head = space->head;

    spc_head->segment_count = 0;
    spc_head->free_extents.count = 0;
    spc_head->datafile_count = 0;
    spc_head->free_extents.first = INVALID_PAGID;
    spc_head->free_extents.last = INVALID_PAGID;
    space->swap_bitmap = GS_FALSE;

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        spc_head->datafile_count++;
        spc_head->hwms[i] = (i == 0) ? DF_FIRST_HWM_START : DF_HWM_START;
    }
}

void spc_init_swap_space(knl_session_t *session, space_t *space)
{
    if (SECUREC_LIKELY(SPACE_SWAP_BITMAP(space))) {
        spc_init_swap_space_bitmap(session, space);
    } else {
        spc_init_swap_space_normal(space);
    }
    GS_LOG_RUN_INF("[SPACE] init swap space end.");
}

/*
 * get total page count by extent count
 */
uint32 spc_pages_by_ext_cnt(space_t *space, uint32 extent_cnt, uint8 seg_page_type)
{
    uint32 total_pages = 0;

    if (SPACE_IS_AUTOALLOCATE(space) && seg_page_type != PAGE_TYPE_LOB_HEAD) {
        if (extent_cnt > EXT_SIZE_1024_BOUNDARY) {
            total_pages += (extent_cnt - EXT_SIZE_1024_BOUNDARY) * EXT_SIZE_8192;
            extent_cnt = EXT_SIZE_1024_BOUNDARY;
        }

        if (extent_cnt > EXT_SIZE_128_BOUNDARY) {
            total_pages += (extent_cnt - EXT_SIZE_128_BOUNDARY) * EXT_SIZE_1024;
            extent_cnt = EXT_SIZE_128_BOUNDARY;
        }

        if (extent_cnt > EXT_SIZE_8_BOUNDARY) {
            total_pages += (extent_cnt - EXT_SIZE_8_BOUNDARY) * EXT_SIZE_128;
            extent_cnt = EXT_SIZE_8_BOUNDARY;
        }

        total_pages += extent_cnt * EXT_SIZE_8;
    } else {
        total_pages = extent_cnt * space->ctrl->extent_size;
    }
    return total_pages;
}

uint32 spc_degrade_extent_size(space_t *space, uint32 size)
{
    // there are 2 Scenarios:
    // 1. bitmap try degrade, should not degrade then init exten_size;
    // 2. normal space, should not try degrade (equals here), return 0, will terminate degrade
    if (space->ctrl->extent_size == size) {
        return 0;
    }

    if (size == EXT_SIZE_8192) {
        return EXT_SIZE_1024;
    } else if (size == EXT_SIZE_1024) {
        return EXT_SIZE_128;
    } else if (size == EXT_SIZE_128) {
        return EXT_SIZE_8;
    }
    return 0;
}

bool32 spc_try_lock_space_file(knl_session_t *session, space_t *space, datafile_t *df)
{
    if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
        return GS_FALSE;
    }

    if (!DATAFILE_IS_ONLINE(df) || df->space_id >= GS_MAX_SPACES || DF_FILENO_IS_INVAILD(df) || space->is_empty
        || !space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        char *space_name = (df->space_id >= GS_MAX_SPACES) ? "invalid space" : space->ctrl->name;
        cm_spin_unlock(&space->lock);
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space_name, "punch space failed");
        return GS_FALSE;
    }

    return GS_TRUE;
}

static inline void spc_init_punch_head(knl_session_t *session, space_t *space)
{
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    spc_init_page_list(&punch_head->punching_exts);
    spc_init_page_list(&punch_head->punched_exts);
}

bool32 spc_try_init_punch_head(knl_session_t *session, space_t *space)
{
    if (!spc_punch_check_normalspc_invaild(session, space)) {
        return GS_FALSE;
    }

    spc_init_punch_head(session, space);

    return GS_TRUE;
}

void spc_set_datafile_ctrl_punched(knl_session_t *session, uint16 file_id)
{
    knl_panic_log(file_id != GS_INVALID_ID32, "file id is invalid when set datafile ctrl punched");
    datafile_t *df = DATAFILE_GET(file_id);
    if (!df->ctrl->punched) {
        df->ctrl->punched = GS_TRUE;
        if (db_save_datafile_ctrl(session, file_id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save datafile ctrl");
        }
    }
}

// warning: ext_size need to less than KNL_MAX_ATOMIC_PAGES
void spc_punch_extent(knl_session_t *session, page_id_t first_page, uint32 ext_size)
{
    page_id_t punch_page = first_page;
    page_tail_t *tail = NULL;
    rd_punch_page_t redo = {0};

    spc_set_datafile_ctrl_punched(session, punch_page.file);
    for (uint32 i = 0; i < ext_size; i++) {
        log_atomic_op_begin(session);
        buf_enter_page(session, punch_page, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        page_head_t *page = (page_head_t*)session->curr_page;
        TO_PAGID_DATA(punch_page, page->id);
        page->type = PAGE_TYPE_PUNCH_PAGE;
        page->size_units = page_size_units(DEFAULT_PAGE_SIZE);
        page->pcn = 0;
        tail = PAGE_TAIL(page);
        tail->checksum = 0;
        tail->pcn = 0;
        redo.page_id.page = punch_page.page;
        redo.page_id.file = punch_page.file;
        log_put(session, RD_PUNCH_FORMAT_PAGE, &redo, sizeof(rd_punch_page_t), LOG_ENTRY_FLAG_NONE);
        buf_leave_page(session, GS_TRUE);
        punch_page.page++;
        log_atomic_op_end(session); 
    }
}

static inline bool32 spc_punch_normal_verify_extent(page_id_t *page_id)
{
    if (IS_INVALID_PAGID(*page_id) || page_id->file == 0) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

void spc_punch_residual_extents(knl_session_t *session, uint32 extent_size, page_list_t *punch_exts)
{
    page_id_t page_id = punch_exts->first;
    page_id_t next_page_id;
    for (uint32 i = 0; i < punch_exts->count; i++) {
        // first get next page id, because extent may be punched by ckpt
        if (!spc_punch_normal_verify_extent(&page_id)) {
            GS_LOG_RUN_WAR("punch extent(%u-%u) is invailed, extent list first is %u-%u.",
                page_id.file, page_id.page, punch_exts->first.file, punch_exts->first.page);
            GS_LOG_RUN_WAR("punch residual extent is invailed, may cause %llu space leak.",
                (uint64)extent_size * (punch_exts->count - i) * DEFAULT_PAGE_SIZE);
            return;
        }
        next_page_id = spc_get_next_ext(session, page_id);
        // normal space do not punhc extent's first page, so we can get next extent after punch
        spc_punch_extent(session, page_id, extent_size);
        page_id = next_page_id;
    }
}

static inline void spc_punch_extents(knl_session_t *session, uint32 extent_size, page_id_t *ext_firsts,
    uint32 ext_num)
{
    for (uint32 i = 0; i < ext_num; i++) {
        // normal space do not punhc extent's first page, so we can get next extent after punch
        spc_punch_extent(session, ext_firsts[i], extent_size);
    }
}

status_t spc_punch_bitmap_batch_extents(knl_session_t *session, df_map_page_t *map_page, spc_punch_info_t *punch_info,
    uint32 *bit, int64 *punch_size)
{
    datafile_t *df = DATAFILE_GET(map_page->first_page.file);
    uint8 *bitmap = map_page->bitmap;
    int32 i = (int32)*bit;
    int64 punch_pages = 0;
    status_t status = GS_SUCCESS;

    while (i >= 0) {
        if (DF_MAP_MATCH(bitmap, *bit)) {
            // to punch
            page_id_t extent = map_page->first_page;
            extent.page += *bit * df->map_head->bit_unit;
            spc_punch_extent(session, extent, df->map_head->bit_unit);
            *punch_size += df->map_head->bit_unit * DEFAULT_PAGE_SIZE;
            punch_info->do_punch_size -= DEFAULT_PAGE_SIZE *  df->map_head->bit_unit;
            punch_pages += df->map_head->bit_unit;
        }

        (*bit)--;
        i--;

        if (punch_info->do_punch_size <= 0) {
            break;
        }

        if (punch_pages == SPACE_PUNCH_CKPT_INTERVAL) {
            break;
        }

        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = GS_ERROR;
            break;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            status = GS_ERROR;
            break;
        }
    }

    return status;
}

bool32 spc_check_bitmap_enable_punch(knl_session_t *session, page_id_t map_pageid, uint32 *curr_hwm, datafile_t *df)
{
    buf_enter_page(session, map_pageid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    df_map_page_t *map_page = (df_map_page_t *)CURR_PAGE;

    if (map_page->first_page.page > *curr_hwm) {
        buf_leave_page(session, GS_FALSE);
        return GS_FALSE;
    }

    if (map_page->free_bits == 0) {
        *curr_hwm -= (DF_MAP_BIT_CNT * df->map_head->bit_unit) + 1;
        buf_leave_page(session, GS_FALSE);
        return GS_FALSE;
    }
    buf_leave_page(session, GS_FALSE);
    return GS_TRUE;
}

bool32 spc_punch_bitmap_check_break(knl_session_t *session, spc_punch_info_t *punch_info, status_t *status)
{
    if (punch_info->do_punch_size <= 0) {
        return GS_TRUE;
    }

    if (session->canceled) {
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);
        *status = GS_ERROR;
        return GS_TRUE;
    }

    if (session->killed) {
        GS_THROW_ERROR(ERR_OPERATION_KILLED);
        *status = GS_ERROR;
        return GS_TRUE;
    }

    return GS_FALSE;
}

static status_t spc_punch_bitmap_free_bits(knl_session_t *session, datafile_t *df, page_id_t map_pagid, 
    uint32 *curr_hwm, spc_punch_info_t *punch_info)
{
    status_t status = GS_SUCCESS;
    int64 punch_size = 0;
    space_t *space = SPACE_GET(df->space_id);
    df_map_page_t *map_page = (df_map_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE);
    int32 i = GS_INVALID_INT32;
    uint32 bit_uints = 0;
    uint32 bit = DF_MAP_BIT_CNT;

    for (;;) {
        if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
            status = GS_ERROR;
            break;
        }

        buf_enter_page(session, map_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        errno_t ret = memcpy_sp(map_page, DEFAULT_PAGE_SIZE, CURR_PAGE, DEFAULT_PAGE_SIZE);
        knl_securec_check(ret);
        buf_leave_page(session, GS_FALSE);

        if (i == GS_INVALID_INT32) {
            bit_uints = *curr_hwm - map_page->first_page.page;
            bit = (bit_uints / df->map_head->bit_unit) - 1;
            i = (int32)bit;
        }

        if (spc_punch_bitmap_batch_extents(session, map_page, punch_info, &bit, &punch_size) != GS_SUCCESS) {
            cm_spin_unlock(&space->lock);
            status = GS_ERROR;
            break;
        }

        cm_spin_unlock(&space->lock);
        // do inc ckpt when punching 4096 pages
        ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_INC);

        i = (int32)bit;

        if (i < 0) {
            break;
        }

        if (spc_punch_bitmap_check_break(session, punch_info, &status)) {
            break;
        }
    }

    *curr_hwm -= bit_uints + 1;
    punch_info->real_punch_size += punch_size;
    cm_pop(session->stack);
    GS_LOG_DEBUG_INF("[SPC] punch expected page count %llu in map page %d-%d", punch_size / DEFAULT_PAGE_SIZE,
        map_pagid.file, map_pagid.page);
    return status;
}

status_t spc_punch_fetch_bitmap_group(knl_session_t *session, space_t *space, datafile_t *df, 
    uint32 hwm, spc_punch_info_t *punch_info)
{
    df_map_group_t *map_group = NULL;
    page_id_t curr_map;
    uint32 curr_hwm = hwm;

    for (int32 i = df->map_head->group_count - 1; i >= 0; i--) {
        map_group = &df->map_head->groups[i];
        curr_map = map_group->first_map;
        curr_map.page += (map_group->page_count - 1);

        for (int32 k = map_group->page_count; k > 0; k--) {
            if (punch_info->do_punch_size <= 0) {
                break;
            }

            if (!spc_try_lock_space_file(session, space, df)) {
                return GS_ERROR;
            }

            if (!spc_check_bitmap_enable_punch(session, curr_map, &curr_hwm, df)) {
                cm_spin_unlock(&space->lock);
                curr_map.page--;
                continue;
            }

            cm_spin_unlock(&space->lock);

            if (spc_punch_bitmap_free_bits(session, df, curr_map, &curr_hwm, punch_info) != GS_SUCCESS) {
                return GS_ERROR;
            }

            curr_map.page--;
        }
    }

    return GS_SUCCESS;
}

status_t spc_punch_precheck(knl_session_t *session, space_t *space)
{
    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "punch tablespace");
        return GS_ERROR;
    }

    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "punch tablespace failed");
        return GS_ERROR;
    }

    return spc_punch_check_space_invaild(session, space) != GS_SUCCESS;
}

status_t spc_punch_space_bitmap(knl_session_t *session, space_t *space, spc_punch_info_t *punch_info)
{
    datafile_t *df = NULL;
    status_t status = GS_SUCCESS;

    if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
        return GS_ERROR;
    }

    if (space->punching) {
        spc_unlock_space(space);
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "space %s is punching, parallel punching is not allowed",
            space->ctrl->name);
        return GS_ERROR;
    }

    space->punching = GS_TRUE;
    spc_unlock_space(space);

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        df = DATAFILE_GET(space->ctrl->files[i]);

        if (DATAFILE_IS_COMPRESS(df) || !DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        if (spc_punch_fetch_bitmap_group(session, space, df, space->head->hwms[i], punch_info) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }
    }

    if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
        space->punching = GS_FALSE;
        return GS_ERROR;
    }

    space->punching = GS_FALSE;
    spc_unlock_space(space);
    return status;
}

// output is target_ext: new_head->first --> target_ext-->last
void spc_concat_page_to_pagelist(knl_session_t *session, page_id_t new_head, page_list_t *target_ext)
{
    if (target_ext->count == 0) {
        target_ext->count++;
        target_ext->first = new_head;
        target_ext->last = new_head;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(target_ext->first),
            "punch the first of free_extents is invalid page, panic info: first page of extents %u-%u",
            target_ext->first.file, target_ext->first.page);
        knl_panic_log(!IS_INVALID_PAGID(target_ext->last),
            "punch the last of free_extents is invalid page, panic info: last page of extents %u-%u",
            target_ext->last.file, target_ext->last.page);
        spc_concat_extent(session, new_head, target_ext->first);
        target_ext->first = new_head;
        target_ext->count++;
    }
}

void spc_clean_punching_extents(knl_session_t *session, space_t *space)
{
    log_atomic_op_begin(session);
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);

    spc_init_page_list(&punch_head->punching_exts);
    log_put(session, RD_SPC_PUNCH_EXTENTS, &punch_head->punching_exts, sizeof(rd_punch_extents_t),
        LOG_ENTRY_FLAG_NONE);

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
    spc_print_punch_log(session, space, "clean punching extens");
}

void spc_punch_free_extent(knl_session_t *session, space_t *space)
{
    log_atomic_op_begin(session);
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    page_id_t ext = space->head->free_extents.first;

    space->head->free_extents.first = spc_get_next_ext(session, ext);
    space->head->free_extents.count--;
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    }

    // pick free extents first, reset punching, set new head to punched extent
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    page_list_t *punching = &(punch_head->punching_exts);
    knl_panic_log(punching->count <= 1, "punching extent count %u is large than 1, first(%u-%u) last(%u-%u)",
        punching->count, punching->first.file, punching->first.page, punching->last.file, punching->last.page);
    punching->count = 1;
    punching->first = ext;
    punching->last = ext;
    spc_concat_page_to_pagelist(session, ext, &punch_head->punched_exts);

    log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    log_put(session, RD_SPC_PUNCH_EXTENTS, &punch_head->punching_exts,
        sizeof(rd_punch_extents_t), LOG_ENTRY_FLAG_NONE);

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    spc_print_punch_log(session, space, "punch free extent");
}

void spc_force_reset_punching_stat(knl_session_t *session, spinlock_t *lock, volatile bool8 *punching)
{
    if (cm_get_error_code() == ERR_SPACE_OFFLINE) {
        *punching = GS_FALSE;
        return;
    }

    cm_spin_lock(lock, &session->stat_space);
    *punching = GS_FALSE;
    cm_spin_unlock(lock);
}

void spc_clean_residual_punching_extent(knl_session_t *session, space_t *space)
{
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    int64 punching_num = punch_head->punching_exts.count;
    if (SECUREC_LIKELY(punching_num == 0)) {
        return;
    }

    spc_punch_residual_extents(session, space->ctrl->extent_size, &punch_head->punching_exts);
    spc_clean_punching_extents(session, space);
    spc_print_punch_log(session, space, "free residual punching extens");
}

// punch part(one extent) one by one
status_t spc_punching_free_extents_part(knl_session_t *session, space_t *space, uint32 expect_exts, uint32 *real_exts)
{
    *real_exts = 0;
    page_id_t punch_ext;

    if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(spc_is_punching(session, space, "parallel punch"))) {
        spc_unlock_space(space);
        return GS_ERROR;
    }

    // extent size maybe 8192, ckpt_exts can not be 0, so + 1
    uint32 ckpt_exts = SPACE_PUNCH_CKPT_INTERVAL / space->ctrl->extent_size + 1;
    space->punching = GS_TRUE;
    spc_clean_residual_punching_extent(session, space);

    while (expect_exts > *real_exts) {
        if (SECUREC_UNLIKELY(!SPACE_IS_ONLINE(space))) {
            GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "punch tablespace failed");
            space->punching = GS_FALSE;
            spc_unlock_space(space);
            return GS_ERROR;
        }

        if (space->head->free_extents.count == 0) {
            break;
        }

        punch_ext = space->head->free_extents.first;
        spc_punch_free_extent(session, space);
        spc_unlock_space(space);

        spc_punch_extent(session, punch_ext, space->ctrl->extent_size);
        (*real_exts)++;
        if ((*real_exts) % ckpt_exts == 0) {
            ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_INC);
        }

        if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
            // reset space->punching inside
            spc_force_reset_punching_stat(session, &space->lock, &space->punching);
            return GS_ERROR;
        }
    }

    spc_clean_punching_extents(session, space);
    space->punching = GS_FALSE;
    spc_unlock_space(space);
    return GS_SUCCESS;
}

static inline status_t spc_punch_space_normal(knl_session_t *session, space_t *space, spc_punch_info_t *punch_info)
{
    uint32 expect_num = (uint32)(punch_info->do_punch_size / DEFAULT_PAGE_SIZE / space->ctrl->extent_size);
    uint32 real_punch_exts;
    status_t status = spc_punching_free_extents_part(session, space, expect_num, &real_punch_exts);
    punch_info->real_punch_size = (int64)real_punch_exts * DEFAULT_PAGE_SIZE * space->ctrl->extent_size;
    return status;
}

status_t spc_punch_space(knl_session_t *session, space_t *space, spc_punch_info_t *punch_info)
{
    if (!SPACE_IS_BITMAPMANAGED(space)) {
        return spc_punch_space_normal(session, space, punch_info);
    }

    return spc_punch_space_bitmap(session, space, punch_info);
}

status_t spc_punch_hole(knl_session_t *session, space_t *space, int64 punch_size)
{
    if (spc_punch_precheck(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint64 space_size = DEFAULT_PAGE_SIZE * spc_count_pages_with_ext(session, space, GS_TRUE);
    spc_punch_info_t punch_info;
    if (punch_size == GS_INVALID_INT64) {
        punch_info.do_punch_size = space_size;
    } else {
        punch_info.do_punch_size = (space_size < punch_size) ? space_size : punch_size;
    }

    punch_info.real_punch_size = 0;
    status_t status = spc_punch_space(session, space, &punch_info);

    GS_LOG_RUN_INF("[SPC] punch space %s, expect size %lld, punched size %lld.", space->ctrl->name,
        punch_info.do_punch_size, punch_info.real_punch_size);
    return status;
}

#ifdef __cplusplus
}
#endif

