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
 * knl_index.c
 *    implement of index
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/index/knl_index.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_index.h"
#include "rcr_btree_scan.h"
#include "knl_context.h"
#include "pcr_btree_scan.h"
#include "knl_table.h"
#include "temp_btree.h"
#include "cm_decimal.h"
#include "dc_subpart.h"

#define MAX_DUPKEY_MSG_LEN 256
#define MAX_INDEX_COLUMN_MSG_LEN 128
#define MAX_INDEX_COLUMN_STR_LEN 6  // sizeof("65535,")

static text_t g_idx_ts_fmt = { "YYYY-MM-DD HH24:MI:SS.FF", 24 };
static text_t g_idx_tstz_fmt = { "YYYY-MM-DD HH24:MI:SS.FF TZH:TZM", 32 };

/* btree index access method */
idx_accessor_t g_btree_acsor = { (knl_cursor_operator_t)btree_fetch, (knl_cursor_operator_t)btree_insert,
                                 (knl_cursor_operator_t)btree_delete };

/* PCR btree index access method */
idx_accessor_t g_pcr_btree_acsor = { (knl_cursor_operator_t)pcrb_fetch, (knl_cursor_operator_t)pcrb_insert,
                                     (knl_cursor_operator_t)pcrb_delete };

/* temp btree index access method */
idx_accessor_t g_temp_btree_acsor = { (knl_cursor_operator_t)temp_btree_fetch, (knl_cursor_operator_t)temp_btree_insert,
                                      (knl_cursor_operator_t)temp_btree_delete };

/* temp btree index access method */
idx_accessor_t g_invalid_index_acsor = { (knl_cursor_operator_t)db_invalid_cursor_operation,
                                         (knl_cursor_operator_t)db_invalid_cursor_operation,
                                         (knl_cursor_operator_t)db_invalid_cursor_operation };

typedef struct st_idx_data_info {
    idx_put_key_data_t put_method;
    char *key_buf;
    index_t *index;
    uint16 cols;
    uint16 key_size;
} idx_data_info_t;

static void idx_get_varaint_data(variant_t *expr_value, char **data, uint16 *len, char *buf, uint32 buf_size)
{
    row_assist_t ra;
    uint16 offset;

    if (expr_value->is_null) {
        *data = NULL;
        *len = GS_NULL_VALUE_LEN;
        return;
    }

    switch (expr_value->type) {
        case GS_TYPE_UINT32:
            *data = (char *)&expr_value->v_uint32;
            *len = sizeof(uint32);
            break;
        case GS_TYPE_INTEGER:
            *data = (char *)&expr_value->v_int;
            *len = sizeof(int32);
            break;

        case GS_TYPE_BOOLEAN:
            *data = (char *)&expr_value->v_bool;
            *len = sizeof(bool32);
            break;

        case GS_TYPE_BIGINT:
        case GS_TYPE_DATE:
        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
        case GS_TYPE_TIMESTAMP_LTZ:
            *data = (char *)&expr_value->v_bigint;
            *len = sizeof(int64);
            break;

        case GS_TYPE_TIMESTAMP_TZ:
            *data = (char *)&expr_value->v_tstamp_tz;
            *len = sizeof(timestamp_tz_t);
            break;

        case GS_TYPE_INTERVAL_DS:
            *data = (char *)&expr_value->v_itvl_ds;
            *len = sizeof(interval_ds_t);
            break;

        case GS_TYPE_INTERVAL_YM:
            *data = (char *)&expr_value->v_itvl_ym;
            *len = sizeof(interval_ym_t);
            break;

        case GS_TYPE_REAL:
            *data = (char *)&expr_value->v_real;
            *len = sizeof(double);
            break;

        case GS_TYPE_DECIMAL:
        case GS_TYPE_NUMBER:
            row_init(&ra, buf, buf_size, 1);
            (void)row_put_dec8(&ra, &expr_value->v_dec);
            cm_decode_row((char *)ra.head, &offset, len, NULL);
            *data = ra.buf + offset;
            break;

        case GS_TYPE_BINARY:
        case GS_TYPE_VARBINARY:
        case GS_TYPE_RAW:
            *data = (char *)expr_value->v_bin.bytes;
            *len = expr_value->v_bin.size;
            break;

        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
        case GS_TYPE_STRING:
        default:
            *data = expr_value->v_text.str;
            *len = expr_value->v_text.len;
            break;
    }
}

void idx_decode_row(knl_session_t *session, knl_cursor_t *cursor, uint16 *offsets, uint16 *lens, uint16 *size)
{
    dc_entity_t *entity;
    index_t *index;
    knl_column_t *column = NULL;
    char *key_buf = NULL;
    uint32 i;
    uint16 bitmap;
    uint32 col_id;
    uint32 off;

    index = (index_t *)cursor->index;
    entity = index->entity;

    if (index->desc.cr_mode == CR_PAGE) {
        bitmap = cursor->bitmap;
    } else {
        if (cursor->index_dsc) {
            key_buf = cursor->scan_range.r_key.buf;
        } else {
            key_buf = cursor->scan_range.l_key.buf;
        }

        btree_convert_row(session, &index->desc, key_buf, cursor->row, &bitmap);
    }

    off = sizeof(row_head_t);
    /* elements of offsets, i.e., offsets[i], cannot exceed the upper limit of uint16 */
    for (i = 0; i < index->desc.column_count; i++) {
        col_id = index->desc.columns[i];
        column = dc_get_column(entity, col_id);

        if (!btree_get_bitmap(&bitmap, i)) {
            lens[i] = GS_NULL_VALUE_LEN;
            continue;
        }

        switch (column->datatype) {
            case GS_TYPE_UINT32:
            case GS_TYPE_INTEGER:
            case GS_TYPE_BOOLEAN:
                lens[i] = sizeof(uint32);
                offsets[i] = off;
                off += sizeof(uint32);
                break;
            case GS_TYPE_BIGINT:
            case GS_TYPE_REAL:
            case GS_TYPE_DATE:
            case GS_TYPE_TIMESTAMP:
            case GS_TYPE_TIMESTAMP_TZ_FAKE:
            case GS_TYPE_TIMESTAMP_LTZ:
                lens[i] = sizeof(int64);
                offsets[i] = off;
                off += sizeof(int64);
                break;
            case GS_TYPE_TIMESTAMP_TZ:
                lens[i] = sizeof(timestamp_tz_t);
                offsets[i] = off;
                off += sizeof(timestamp_tz_t);
                break;
            case GS_TYPE_INTERVAL_YM:
                lens[i] = sizeof(interval_ym_t);
                offsets[i] = off;
                off += sizeof(interval_ym_t);
                break;
            case GS_TYPE_INTERVAL_DS:
                lens[i] = sizeof(interval_ds_t);
                offsets[i] = off;
                off += sizeof(interval_ds_t);
                break;
            case GS_TYPE_DECIMAL:
            case GS_TYPE_NUMBER:
                if (index->desc.cr_mode == CR_PAGE) {
                    lens[i] = DECIMAL_LEN(((char *)cursor->row + off));
                    offsets[i] = off;
                    off += CM_ALIGN4(lens[i]);
                    break;
                }
            // fall-through
            case GS_TYPE_CHAR:
            case GS_TYPE_VARCHAR:
            case GS_TYPE_STRING:
            case GS_TYPE_BINARY:
            case GS_TYPE_VARBINARY:
            case GS_TYPE_RAW:
                lens[i] = *(uint16 *)((char *)cursor->row + off);
                offsets[i] = (uint16)sizeof(uint16) + off;
                off += CM_ALIGN4(lens[i] + sizeof(uint16));
                break;
            default:
                knl_panic_log(0, "column's datatype is unknown, panic info: table %s index %s column datatype %u "
                              "page %u-%u type %u", entity->table.desc.name, index->desc.name, column->datatype,
                              cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type);
        }
    }
}

static void index_print_key(index_t *index, char *key, char *buf, uint16 buf_len)
{
    dc_entity_t *entity = index->entity;
    knl_column_t *column = NULL;
    uint16 bitmap;
    char *data = NULL;
    uint16 i;
    uint16 col_id;
    text_t value;
    errno_t ret;
    binary_t bin;
    uint16 size_left = buf_len;
    uint16 offset = 0;
    char col_str[MAX_INDEX_COLUMN_MSG_LEN];

    value.str = (char *)col_str;
    value.len = MAX_INDEX_COLUMN_MSG_LEN;

    if (index->desc.cr_mode == CR_PAGE) {
        bitmap = ((pcrb_key_t *)key)->bitmap;
        data = key + sizeof(pcrb_key_t);
    } else {
        bitmap = ((btree_key_t *)key)->bitmap;
        data = key + sizeof(btree_key_t);
    }

    for (i = 0; i < index->desc.column_count; i++) {
        col_id = index->desc.columns[i];
        column = dc_get_column(entity, col_id);

        if (!btree_get_bitmap(&bitmap, i)) {
            ret = strcpy_s(value.str, MAX_INDEX_COLUMN_MSG_LEN, "null");
            knl_securec_check(ret);
            value.len = (uint32)strlen("null");
        } else {
            switch (column->datatype) {
                case GS_TYPE_UINT32:
                    cm_uint32_to_text(*(uint32 *)data, &value);
                    data += sizeof(uint32);
                    break;
                case GS_TYPE_INTEGER:
                    cm_int2text(*(int32 *)data, &value);
                    data += sizeof(int32);
                    break;
                case GS_TYPE_BOOLEAN:
                    cm_bool2text(*(bool32 *)data, &value);
                    data += sizeof(bool32);
                    break;
                case GS_TYPE_BIGINT:
                    cm_bigint2text(*(int64 *)data, &value);
                    data += sizeof(int64);
                    break;
                case GS_TYPE_REAL:
                    cm_real2text(*(double *)data, &value);
                    data += sizeof(double);
                    break;
                case GS_TYPE_DATE:
                    (void)cm_date2text(*(date_t *)data, &g_idx_ts_fmt, &value, MAX_INDEX_COLUMN_MSG_LEN);
                    data += sizeof(date_t);
                    break;
                case GS_TYPE_TIMESTAMP:
                case GS_TYPE_TIMESTAMP_TZ_FAKE:
                case GS_TYPE_TIMESTAMP_LTZ:
                    (void)cm_timestamp2text(*(timestamp_t *)data, &g_idx_ts_fmt, &value, MAX_INDEX_COLUMN_MSG_LEN);
                    data += sizeof(timestamp_t);
                    break;
                case GS_TYPE_TIMESTAMP_TZ:
                    (void)cm_timestamp_tz2text((timestamp_tz_t *)data, &g_idx_tstz_fmt, &value,
                                               MAX_INDEX_COLUMN_MSG_LEN);
                    data += sizeof(timestamp_tz_t);
                    break;
                case GS_TYPE_INTERVAL_YM:
                    cm_yminterval2text(*(interval_ym_t *)data, &value);
                    data += sizeof(interval_ym_t);
                    break;
                case GS_TYPE_INTERVAL_DS:
                    cm_dsinterval2text(*(interval_ds_t *)data, &value);
                    data += sizeof(interval_ds_t);
                    break;
                case GS_TYPE_DECIMAL:
                case GS_TYPE_NUMBER: {
                    dec4_t *d4 = NULL;
                    if (index->desc.cr_mode == CR_PAGE) {
                        d4 = (dec4_t *)data;
                        data += DECIMAL_FORMAT_LEN(data);
                    } else {
                        d4 = (dec4_t *)(data + sizeof(uint16));
                        data += CM_ALIGN4(*(uint16 *)data + sizeof(uint16));
                    }
                    (void)cm_dec4_to_text(d4, GS_MAX_DEC_OUTPUT_PREC, &value);
                    break;
                }
                // if not, go to varchar branch
                case GS_TYPE_CHAR:
                case GS_TYPE_VARCHAR:
                case GS_TYPE_STRING:
                    value.len = *(uint16 *)data;
                    if (value.len > 0) {
                        value.len = MIN(value.len, MAX_INDEX_COLUMN_MSG_LEN);
                        ret = memcpy_sp(value.str, MAX_INDEX_COLUMN_MSG_LEN, data + sizeof(uint16), value.len);
                        knl_securec_check(ret);
                    }
                    data += CM_ALIGN4(sizeof(uint16) + *(uint16 *)data);
                    break;
                case GS_TYPE_BINARY:
                case GS_TYPE_VARBINARY:
                case GS_TYPE_RAW:
                    bin.size = *(uint16 *)data;

                    /*
                     * the size of binary type is bin.size * 2
                     * and MAX_INDEX_COLUMN_MSG_LEN is a half of MAX_DUPKEY_MSG_LEN
                     * total here maximum size of bin is a quarter of MAX_DUPKEY_MSG_LEN
                     */
                    bin.size = MIN(bin.size, (MAX_DUPKEY_MSG_LEN - 1) / 4);
                    bin.bytes = (uint8 *)data + sizeof(uint16);
                    (void)cm_bin2text(&bin, GS_FALSE, &value);
                    data += CM_ALIGN4(sizeof(uint16) + bin.size);
                    break;
                default:
                    knl_panic_log(0, "column's datatype is unknown, panic info: table %s index %s column datatype %u",
                                  entity->table.desc.name, index->desc.name, column->datatype);
            }
        }

        if (value.len + 1 > size_left) {
            break;
        }

        size_left -= value.len + 1;

        if (i > 0) {
            buf[offset++] = '-';
        }
        if (value.len > 0) {
            ret = memcpy_sp(buf + offset, buf_len - offset, value.str, value.len);
            knl_securec_check(ret);
            offset += value.len;
        }
        value.len = MAX_INDEX_COLUMN_MSG_LEN;
    }
    buf[offset] = '\0';
}

status_t idx_generate_dupkey_error(index_t *index, char *key)
{
    char msg_buf[MAX_DUPKEY_MSG_LEN] = { 0 };
    errno_t ret;

    ret = snprintf_s(msg_buf, MAX_DUPKEY_MSG_LEN, MAX_DUPKEY_MSG_LEN - 1, ", index %s, duplicate key ",
                     index->desc.name);
    knl_securec_check_ss(ret);

    index_print_key(index, key, (char *)msg_buf + strlen(msg_buf), (uint16)(MAX_DUPKEY_MSG_LEN - strlen(msg_buf)));
    GS_THROW_ERROR(ERR_DUPLICATE_KEY, msg_buf);

    return GS_ERROR;
}

static status_t idx_try_put_key_data(uint16 col_size, uint32 datatype, const char *data, idx_data_info_t *key_info,
                                     uint32 idx_col_slot)
{
    key_info->key_size += CM_ALIGN4(sizeof(uint16) + col_size);
    if (key_info->key_size > key_info->index->desc.max_key_size) {
        index_t *index = key_info->index;
        key_info->key_size = (uint16)knl_get_key_size(&index->desc, key_info->key_buf) +
                             btree_max_column_size(datatype, col_size, (index->desc.cr_mode == CR_PAGE));
        if (key_info->key_size > key_info->index->desc.max_key_size) {
            GS_THROW_ERROR(ERR_MAX_KEYLEN_EXCEEDED, key_info->index->desc.max_key_size);
            return GS_ERROR;
        }
    }

    key_info->put_method(key_info->key_buf, datatype, data, col_size, idx_col_slot);
    return GS_SUCCESS;
}

static status_t idx_make_virtual_col_data(knl_session_t *session, knl_cursor_t *cursor, index_t *index,
                                          uint32 idx_col_slot, idx_data_info_t *key_info)
{
    knl_column_t *column = dc_get_column(index->entity, index->desc.columns[idx_col_slot]);
    variant_t expr_value;
    char *data = NULL;
    uint16 col_size;

    CM_SAVE_STACK(session->stack);
    if (g_knl_callback.func_idx_exec(session, (void *)cursor, column->datatype, column->default_expr, &expr_value,
                                     GS_FALSE)) {
        return GS_ERROR;
    }

    if (expr_value.is_null) {
        if (index->desc.primary) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_NULL, column->name);
            return GS_ERROR;
        }

        key_info->put_method(key_info->key_buf, column->datatype, NULL, GS_NULL_VALUE_LEN, idx_col_slot);
        return GS_SUCCESS;
    }
    /* should keep stack memory for index key value before next push operation */
    cm_keep_stack_variant(session->stack, var_get_buf(&expr_value));
    char *buf = (char *)cm_push(session->stack, GS_KEY_BUF_SIZE);
    idx_get_varaint_data(&expr_value, &data, &col_size, buf, GS_KEY_BUF_SIZE);
    uint32 type = (uint32)expr_value.type;
    status_t status = idx_try_put_key_data(col_size, type, data, key_info, idx_col_slot);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t idx_make_col_data(knl_session_t *session, knl_cursor_t *cursor, index_t *index, uint32 idx_col_slot,
                                  idx_data_info_t *key_info)
{
    uint32 col_id = index->desc.columns[idx_col_slot];
    knl_column_t *column = dc_get_column(index->entity, col_id);

    if (SECUREC_UNLIKELY(KNL_COLUMN_IS_VIRTUAL(column))) {
        return idx_make_virtual_col_data(session, cursor, index, idx_col_slot, key_info);
    }

    bool32 is_null = (CURSOR_COLUMN_SIZE(cursor, col_id) == GS_NULL_VALUE_LEN);
    if (is_null) {
        if (index->desc.primary) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_NULL, column->name);
            return GS_ERROR;
        }

        key_info->put_method(key_info->key_buf, column->datatype, NULL, GS_NULL_VALUE_LEN, idx_col_slot);
        return GS_SUCCESS;
    }

    uint16 col_size = CURSOR_COLUMN_SIZE(cursor, col_id);
    char *data = CURSOR_COLUMN_DATA(cursor, col_id);
    return idx_try_put_key_data(col_size, column->datatype, data, key_info, idx_col_slot);
}

static void idx_init_key_data(knl_cursor_t *cursor, index_t *index, char *key_buf, idx_data_info_t *key_info)
{
    key_info->key_buf = key_buf;
    key_info->index = index;
    if (index->desc.cr_mode == CR_PAGE) {
        pcrb_init_key((pcrb_key_t *)key_buf, &cursor->rowid);
        key_info->put_method = pcrb_put_key_data;
        key_info->key_size = sizeof(pcrb_key_t);
    } else {
        btree_init_key((btree_key_t *)key_buf, &cursor->rowid);
        key_info->put_method = btree_put_key_data;
        key_info->key_size = sizeof(btree_key_t);
    }
}

status_t knl_make_key(knl_handle_t session, knl_cursor_t *cursor, index_t *index, char *key_buf)
{
    idx_data_info_t key_info;

    idx_init_key_data(cursor, index, key_buf, &key_info);
    /* the max value of index->desc.column_count is 16 */
    for (uint32 i = 0; i < index->desc.column_count; i++) {
        if (idx_make_col_data((knl_session_t *)session, cursor, index, i, &key_info) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    /*
     * append part_id for global index of partitioned table. when stats_make_index_key will use this function
     * its cursor->table is null and not supoort partation table .
     */
    if (cursor->table != NULL && IS_PART_TABLE(cursor->table) && !IS_PART_INDEX(index)) {
        if (index->desc.cr_mode == CR_PAGE) {
            pcrb_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.part_id);
            if (IS_SUB_TABPART(&((table_part_t *)cursor->table_part)->desc)) {
                pcrb_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.parent_partid);
            }
        } else {
            btree_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.part_id);
            if (IS_SUB_TABPART(&((table_part_t *)cursor->table_part)->desc)) {
                btree_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.parent_partid);  
            }
        }
    }

    return GS_SUCCESS;
}

static status_t idx_generate_update_keyinfo(knl_session_t *session, knl_cursor_t *cursor, uint16 *map,
                                            uint32 idx_col_slot, idx_data_info_t *key_info)
{
    index_t *index = (index_t *)cursor->index;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    knl_update_info_t *ui = &cursor->update_info;
    uint32 col_id = index->desc.columns[idx_col_slot];
    knl_column_t *column = dc_get_column(entity, col_id);
    variant_t expr_value;
    char *data = NULL;
    char *buf = NULL;
    uint16 col_size;
    uint32 type;
    bool32 is_new = (map[idx_col_slot] != GS_INVALID_ID16);

    CM_SAVE_STACK(session->stack);
    if (SECUREC_UNLIKELY(KNL_COLUMN_IS_VIRTUAL(column))) {
        if (g_knl_callback.func_idx_exec(session, (void *)cursor, column->datatype, column->default_expr, &expr_value,
                                         is_new) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (is_new && index->desc.primary && expr_value.is_null) {
            GS_THROW_ERROR(ERR_COLUMN_NOT_NULL, index->desc.name);
            return GS_ERROR;
        }
        /* should keep stack memory for index key value before next push operation */
        cm_keep_stack_variant(session->stack, var_get_buf(&expr_value));
        buf = (char *)cm_push(session->stack, GS_KEY_BUF_SIZE);
        type = (uint32)expr_value.type;
        idx_get_varaint_data(&expr_value, &data, &col_size, buf, GS_KEY_BUF_SIZE);
    } else {
        type = column->datatype;
        if (is_new) {
            uint32 uid = map[idx_col_slot];
            if (index->desc.primary && ui->lens[uid] == GS_NULL_VALUE_LEN) {
                GS_THROW_ERROR(ERR_COLUMN_NOT_NULL, index->desc.name);
                return GS_ERROR;
            }
            data = ui->data + ui->offsets[uid];
            col_size = ui->lens[uid];
        } else {
            data = CURSOR_COLUMN_DATA(cursor, col_id);
            col_size = CURSOR_COLUMN_SIZE(cursor, col_id);
        }
    }

    status_t status = idx_try_put_key_data(col_size, type, data, key_info, idx_col_slot);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_make_update_key(knl_handle_t session, knl_cursor_t *cursor, index_t *index, char *key_buf,
                             knl_update_info_t *ui, uint16 *map)
{
    idx_data_info_t key_info;

    idx_init_key_data(cursor, index, key_buf, &key_info);
    /* the max value of index->desc.column_count is 16 */
    for (uint32 i = 0; i < index->desc.column_count; i++) {
        if (idx_generate_update_keyinfo(session, cursor, map, i, &key_info) != GS_SUCCESS) {
            cm_pop(((knl_session_t *)session)->stack);
            return GS_ERROR;
        }
    }

    /* append part_id for global index of partitioned table */
    if (IS_PART_TABLE(cursor->table) && !IS_PART_INDEX(cursor->index)) {
        if (index->desc.cr_mode == CR_PAGE) {
            pcrb_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.part_id);
            if (cursor->part_loc.subpart_no != GS_INVALID_ID32) {
                pcrb_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.parent_partid);
            }
        } else {
            btree_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.part_id);
            if (cursor->part_loc.subpart_no != GS_INVALID_ID32) {
                btree_put_part_id(key_buf, ((table_part_t *)cursor->table_part)->desc.parent_partid);
            }
        }
    }

    return GS_SUCCESS;
}

status_t idx_construct(btree_mt_context_t *ctx)
{
    btree_t *btree;
    index_t *index;

    btree = (btree_t *)ctx->mtrl_ctx.segments[ctx->seg_id]->cmp_items;
    index = btree->index;

    if (index->desc.cr_mode == CR_PAGE) {
        return pcrb_construct(ctx);
    } else {
        return btree_construct(ctx);
    }
}

void idx_recycle_trigger(knl_session_t *session, index_t *index, knl_handle_t idx_handle, uint32 partno)
{
    index_recycle_ctx_t *ctx = &session->kernel->index_ctx.recycle_ctx;
    index_recycle_item_t *item = NULL;
    uint32 id;
    btree_t *btree = NULL;
    uint32 list_count;

    if (index->desc.type != INDEX_TYPE_BTREE) {
        return;
    }

    btree = (btree_t *)idx_handle;

    cm_spin_lock(&ctx->lock, NULL);

    if (btree->is_recycling || ctx->idx_list.count == GS_MAX_RECYCLE_INDEXES) {
        cm_spin_unlock(&ctx->lock);
        return;
    }

    id = ctx->free_list.first;
    item = &ctx->items[id];
    item->scn = DB_CURR_SCN(session);
    item->uid = (uint16)index->desc.uid;
    item->part_no = partno;
    item->table_id = index->desc.table_id;
    item->index_id = (uint8)index->desc.id;
    ctx->free_list.count--;
    ctx->free_list.first = item->next;
    item->next = GS_INVALID_ID8;

    if (ctx->free_list.count == 0) {
        ctx->free_list.last = GS_INVALID_ID8;
    }

    if (ctx->idx_list.count == 0) {
        ctx->idx_list.first = id;
    } else {
        /* the max value of id is 255 */
        ctx->items[ctx->idx_list.last].next = id;
    }

    ctx->idx_list.last = id;
    ctx->idx_list.count++;

    btree->is_recycling = GS_TRUE;
    list_count = ctx->idx_list.count;
    cm_spin_unlock(&ctx->lock);

    GS_LOG_RUN_INF("prepare to recycle pages of index %s, %d indexes are waiting for recycling", index->desc.name,
                   list_count);
}

static btree_t *idx_get_recycle_btree(knl_dictionary_t *dc, index_recycle_item_t *item, knl_part_locate_t *part_loc)
{
    index_t *index = NULL;
    index = dc_find_index_by_id(DC_ENTITY(dc), item->index_id);
    if (index == NULL) {
        return NULL;
    }

    part_loc->part_no = GS_INVALID_ID32;
    part_loc->subpart_no = GS_INVALID_ID32;

    if (item->part_org_scn == GS_INVALID_ID64) {        
        return &index->btree;
    }

    table_t *table = DC_TABLE(dc);

    if (!IS_PART_TABLE(table)) {
        return NULL;
    }

    if (!IS_PART_INDEX(index)) {
        return NULL;
    }

    table_part_t *table_part = NULL;

    if (!IS_COMPART_TABLE(table->part_table)) {
        table_part = dc_get_table_part(table->part_table, item->part_org_scn);
    } else {
        table_part = dc_get_table_subpart(table->part_table, item->part_org_scn);
    }

    if (table_part == NULL) {
        return NULL;
    }

    index_part_t *index_part = NULL;
    table_part_t *parent_tabpart = NULL;
    if (IS_SUB_TABPART(&table_part->desc)) {
        parent_tabpart = PART_GET_ENTITY(table->part_table, table_part->parent_partno);
        knl_panic_log(parent_tabpart != NULL, "parent_tabpart is NULL, panic info: table %s table_part %s index %s",
                      table->desc.name, table_part->desc.name, index->desc.name);
        index_part = INDEX_GET_PART(index, parent_tabpart->part_no);
        index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[table_part->part_no]); 
    } else {
        index_part = INDEX_GET_PART(index, table_part->part_no);
    }

    if (index_part == NULL) {
        return NULL;
    }

    if (parent_tabpart != NULL) {
        part_loc->part_no = parent_tabpart->part_no;
        part_loc->subpart_no = table_part->part_no;
    } else {
        part_loc->part_no = table_part->part_no;
        part_loc->subpart_no = GS_INVALID_ID32;
    }
    
    return &index_part->btree;
}

static status_t idx_coalesce(knl_session_t *session, knl_dictionary_t *dc, index_recycle_item_t *item,
                             idx_recycle_stats_t *stats)
{
    bool32 lock_inuse = GS_FALSE;
    btree_t *btree = NULL;
    knl_part_locate_t part_loc;

    if (!lock_table_without_xact(session, dc->handle, &lock_inuse)) {
        stats->need_coalesce = GS_FALSE;
        return GS_ERROR;
    }

    btree = idx_get_recycle_btree(dc, item, &part_loc);
    if (btree == NULL || btree->segment == NULL) {
        stats->need_coalesce = GS_FALSE;
        unlock_table_without_xact(session, dc->handle, lock_inuse);
        return GS_SUCCESS;
    }

    if (btree_coalesce(session, btree, stats, part_loc) != GS_SUCCESS) {
        unlock_table_without_xact(session, dc->handle, lock_inuse);
        return GS_ERROR;
    }

    unlock_table_without_xact(session, dc->handle, lock_inuse);

    return GS_SUCCESS;
}

static status_t idx_recycle_index_pages(knl_session_t *session, index_recycle_item_t *item, idx_recycle_stats_t *stats)
{
    knl_dictionary_t dc;
    status_t status;
    timeval_t time = {0};
    time_t init_time = KNL_INVALID_SCN;
    uint32 force_recycle_interval = KNL_IDX_FORCE_RECYCLE_INTERVAL(session->kernel);
    knl_scn_t min_scn = btree_get_recycle_min_scn(session);
    stats->need_coalesce = GS_FALSE;
    stats->force_recycle_scn = GS_INVALID_ID64;
    time.tv_sec = force_recycle_interval;

    if (item->is_tx_active) {
        txn_info_t txn_info;
        itl_t itl = { 0 };

        itl.is_active = 1;
        itl.xid = item->xid;

        tx_get_itl_info(session, GS_FALSE, &itl, &txn_info);

        if (txn_info.status != XACT_END) {
            stats->need_coalesce = GS_TRUE;
            return GS_SUCCESS;
        }

        item->is_tx_active = GS_FALSE;
        item->scn = txn_info.scn;
    }

    knl_scn_t force_recycle_scn = KNL_TIME_TO_SCN(&time, init_time);
    knl_scn_t cur_scn = DB_CURR_SCN(session);
    if (item->scn > min_scn) {
        if (!GS_INVALID_SCN(force_recycle_scn) &&
            (cur_scn - item->scn) > force_recycle_scn) {
            stats->force_recycle_scn = force_recycle_scn;
        } else {
            stats->need_coalesce = GS_TRUE;
            return GS_SUCCESS;
        }
    }

    if (knl_open_dc_by_id(session, item->uid, item->table_id, &dc, GS_TRUE) != GS_SUCCESS) {
        stats->need_coalesce = GS_FALSE;
        return GS_ERROR;
    }

    status = idx_coalesce(session, &dc, item, stats);
    if (status == GS_SUCCESS && stats->need_coalesce) {
        item->scn = DB_CURR_SCN(session);
    }

    dc_close(&dc);

    return status;
}

static void idx_recycle_move_to_tail(knl_session_t *session)
{
    index_recycle_ctx_t *ctx = &session->kernel->index_ctx.recycle_ctx;
    uint32 id;

    cm_spin_lock(&ctx->lock, NULL);

    if (ctx->idx_list.count == 1) {
        cm_spin_unlock(&ctx->lock);
        return;
    }

    id = ctx->idx_list.first;
    /* the max value of id is 255 */
    ctx->items[ctx->idx_list.last].next = id;
    ctx->idx_list.first = ctx->items[id].next;
    ctx->idx_list.last = id;
    ctx->items[id].next = GS_INVALID_ID8;
    cm_spin_unlock(&ctx->lock);
}

void idx_try_recycle(knl_session_t *session)
{
    index_recycle_ctx_t *ctx = &session->kernel->index_ctx.recycle_ctx;
    index_recycle_item_t *item = NULL;
    uint32 id;
    idx_recycle_stats_t stats;

    cm_spin_lock(&ctx->lock, NULL);

    if (ctx->idx_list.count == 0) {
        cm_spin_unlock(&ctx->lock);
        return;
    }

    id = ctx->idx_list.first;
    cm_spin_unlock(&ctx->lock);

    if (id != GS_INVALID_ID8) {
        item = &ctx->items[id];

        if (idx_recycle_index_pages(session, item, &stats) == GS_SUCCESS) {
            if (stats.need_coalesce) {
                idx_recycle_move_to_tail(session);
                return;
            }
        } else {
            cm_reset_error();
        }

        cm_spin_lock(&ctx->lock, NULL);

        if (ctx->free_list.count == 0) {
            ctx->free_list.first = id;
        } else {
            /* the max value of id is 255 */
            ctx->items[ctx->free_list.last].next = id;
        }

        ctx->free_list.last = id;
        ctx->free_list.count++;
        id = item->next;
        ctx->idx_list.count--;
        ctx->idx_list.first = id;

        if (ctx->idx_list.count == 0) {
            ctx->idx_list.last = GS_INVALID_ID8;
        }

        item->next = GS_INVALID_ID8;
        cm_spin_unlock(&ctx->lock);
    }
}

void idx_recycle_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    index_recycle_ctx_t *ctx = &session->kernel->index_ctx.recycle_ctx;
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;
    uint32 count = 0;

    cm_set_thread_name("index_recycle");
    GS_LOG_RUN_INF("index page recycle thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());

    ctx->is_working = GS_FALSE;

    while (!thread->closed) {
        if (session->kernel->db.status != DB_STATUS_OPEN) {
            session->status = SESSION_INACTIVE;
            cm_sleep(1000);
            continue;
        }

        if (DB_IS_MAINTENANCE(session) || DB_IS_READONLY(session) || !DB_IS_PRIMARY(&session->kernel->db)) {
            session->status = SESSION_INACTIVE;
            cm_sleep(100);
            continue;
        }

        if (!session->kernel->dc_ctx.completed || DB_IN_BG_ROLLBACK(session)) {
            session->status = SESSION_INACTIVE;
            cm_sleep(100);
            continue;
        }

        if (session->status == SESSION_INACTIVE) {
            session->status = SESSION_ACTIVE;
        }

        if (count % INDEX_RECY_CLOCK == 0) {
            db_set_with_switchctrl_lock(ctrl, &ctx->is_working);
            if (!ctx->is_working) {
                cm_sleep(100);
                continue;
            }

            idx_try_recycle(session);
            ctx->is_working = GS_FALSE;
        }

        cm_sleep(200);
        count++;
    }

    GS_LOG_RUN_INF("index_recycle thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

void idx_recycle_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    index_recycle_ctx_t *ctx = &kernel->index_ctx.recycle_ctx;
    knl_session_t *recycle_se = kernel->sessions[SESSION_ID_IDX_RECYCLE];

    recycle_se->killed = GS_TRUE;
    cm_close_thread(&ctx->thread);
}

// calculate total count of keys in origin scan range by level
static uint32 idx_cal_keys_count(knl_session_t *session, idx_range_info_t org_info, uint32 level)
{
    uint32 keys = 0;
    btree_page_t *page = NULL;
    page_id_t next_page_id;

    buf_enter_page(session, org_info.l_page[level], LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page = (btree_page_t *)session->curr_page;
    next_page_id = AS_PAGID(page->next);
    if (IS_INVALID_PAGID(next_page_id) || IS_SAME_PAGID(org_info.l_page[level], org_info.r_page[level])) {
        keys += org_info.r_slot[level] - org_info.l_slot[level] + 1;
        buf_leave_page(session, GS_FALSE);
        return keys;
    }

    keys += page->keys - org_info.l_slot[level];
    buf_leave_page(session, GS_FALSE);

    for (;;) {
        buf_enter_page(session, next_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (btree_page_t *)session->curr_page;

        if (IS_SAME_PAGID(next_page_id, org_info.r_page[level])) {
            keys += org_info.r_slot[level] + 1;
            buf_leave_page(session, GS_FALSE);
            break;
        }
        keys += page->keys;
        next_page_id = AS_PAGID(page->next);
        buf_leave_page(session, GS_FALSE);

        if (IS_INVALID_PAGID(next_page_id)) {
            return keys;
        }
    }

    return keys;
}

void idx_binary_search(index_t *index, char *curr_page, knl_scan_key_t *scan_key, btree_path_info_t *path_info,
                       bool32 cmp_rowid, bool32 *is_same)
{
    btree_page_t *page = (btree_page_t *)curr_page;

    if (index->desc.cr_mode == CR_PAGE) {
        pcrb_binary_search(index, page, scan_key, path_info, cmp_rowid, is_same);
    } else {
        btree_binary_search(index, page, scan_key, path_info, cmp_rowid, is_same);
    }
}

status_t idx_get_tree_info(knl_session_t *session, btree_t *btree, knl_scn_t org_scn, knl_tree_info_t *tree_info)
{
    btree_segment_t *segment = NULL;
    page_head_t *head = NULL;

    if (buf_read_page(session, btree->entry, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }
    head = (page_head_t *)session->curr_page;
    segment = BTREE_GET_SEGMENT;
    if (head->type != PAGE_TYPE_BTREE_HEAD || segment->org_scn != org_scn) {
        buf_leave_page(session, GS_FALSE);
        GS_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, btree->index->desc.name);
        return GS_ERROR;
    }

    tree_info->value = cm_atomic_get(&BTREE_SEGMENT(btree->entry, btree->segment)->tree_info.value);
    if (!spc_validate_page_id(session, AS_PAGID(tree_info->root))) {
        buf_leave_page(session, GS_FALSE);
        GS_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, btree->index->desc.name);
        return GS_ERROR;
    }

    buf_leave_page(session, GS_FALSE);
    return GS_SUCCESS;
}

// get left border info and right border info on (root - 1) level from org_key
static void idx_get_org_range(knl_session_t *session, index_t *index, knl_tree_info_t tree_info, knl_scan_key_t org_key,
                              uint32 *slot, page_id_t *page_id)
{
    pcrb_dir_t *pcrb_dir = NULL;
    pcrb_key_t *pcrb_key = NULL;
    btree_dir_t *btree_dir = NULL;
    btree_key_t *btree_key = NULL;
    btree_page_t *page = NULL;
    page_id_t child_page_id;
    btree_path_info_t path_info;
    bool32 is_same = GS_FALSE;

    child_page_id = AS_PAGID(tree_info.root);
    for (;;) {
        buf_enter_page(session, child_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = (btree_page_t *)session->curr_page;

        idx_binary_search(index, session->curr_page, &org_key, &path_info, GS_TRUE, &is_same);
        slot[page->level] = (uint32)path_info.path[page->level].slot;
        page_id[page->level] = AS_PAGID(page->head.id);

        /* level 2 means root level is 1, we split range at least on level 1 */
        if (tree_info.level == 2 || page->level < tree_info.level - 1) {
            buf_leave_page(session, GS_FALSE);
            break;
        }

        if (index->desc.cr_mode == CR_PAGE) {
            pcrb_dir = pcrb_get_dir(page, (uint32)path_info.path[page->level].slot);
            pcrb_key = PCRB_GET_KEY(page, pcrb_dir);
            child_page_id = pcrb_get_child(pcrb_key);
        } else {
            btree_dir = BTREE_GET_DIR(page, (uint32)path_info.path[page->level].slot);
            btree_key = BTREE_GET_KEY(page, btree_dir);
            child_page_id = btree_key->child;
        }

        buf_leave_page(session, GS_FALSE);
    }
}

status_t idx_get_paral_schedule(knl_session_t *session, btree_t *btree, knl_scn_t org_scn,
                                knl_idx_paral_info_t paral_info, knl_index_paral_range_t *sub_ranges)
{
    knl_tree_info_t tree_info;
    idx_range_info_t org_info;
    knl_scan_range_t *org_range = paral_info.org_range;
    uint32 i, root_level;
    errno_t err;

    if (paral_info.workers == 1) {
        sub_ranges->workers = 1;
        return GS_SUCCESS;
    }

    if (idx_get_tree_info(session, btree, org_scn, &tree_info) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (tree_info.level == 1) {
        sub_ranges->workers = 1;
        return GS_SUCCESS;
    }

    root_level = tree_info.level - 1;
    err = memset_sp(&org_info, sizeof(idx_range_info_t), 0, sizeof(idx_range_info_t));
    knl_securec_check(err);
    idx_get_org_range(session, btree->index, tree_info, org_range->l_key, org_info.l_slot, org_info.l_page);
    idx_get_org_range(session, btree->index, tree_info, org_range->r_key, org_info.r_slot, org_info.r_page);

    for (i = root_level; i >= root_level - 1; i--) {
        org_info.level = i;
        org_info.keys = idx_cal_keys_count(session, org_info, i);
        if (root_level == 1 || org_info.keys >= paral_info.workers) {
            break;
        }
    }

    if (org_info.keys <= 1) {
        sub_ranges->workers = 1;
        return GS_SUCCESS;
    }
    sub_ranges->workers = (org_info.keys < paral_info.workers) ? org_info.keys : paral_info.workers;

    if (btree->index->desc.cr_mode == CR_PAGE) {
        pcrb_get_parl_schedule(session, btree->index, paral_info, org_info, root_level, sub_ranges);
    } else {
        btree_get_parl_schedule(session, btree->index, paral_info, org_info, root_level, sub_ranges);
    }

    for (i = 0; i < sub_ranges->workers; i++) {
        sub_ranges->index_range[i]->is_equal = GS_FALSE;
    }
    return GS_SUCCESS;
}

void idx_enter_next_range(knl_session_t *session, page_id_t page_id, uint32 slot, uint32 step, uint32 *border)
{
    btree_page_t *page = NULL;
    page_id_t next_page_id;
    uint32 num = 0;

    buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page = BTREE_CURR_PAGE;

    if (step + slot < page->keys) {
        *border = step + slot;
        return;
    }

    num += page->keys - slot - 1;
    next_page_id = AS_PAGID(page->next);
    buf_leave_page(session, GS_FALSE);

    for (;;) {
        buf_enter_page(session, next_page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE;

        if (num + page->keys > step) {
            knl_panic_log(step > num, "curr step is smaller than num, panic info: page %u-%u type %u step %u num %u",
                          AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type, step, num);
            *border = step - num - 1;
            break;
        } else if (num + page->keys == step) {
            *border = page->keys - 1;
            break;
        }

        num += page->keys;
        next_page_id = AS_PAGID(page->next);
        buf_leave_page(session, GS_FALSE);
    }
}