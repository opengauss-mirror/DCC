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
 * pcr_heap.c
 *    kernel page consistent read access method code
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/table/pcr_heap.c
 *
 * -------------------------------------------------------------------------
 */
#include "pcr_heap.h"
#include "cm_log.h"
#include "knl_context.h"
#include "pcr_pool.h"
#include "dc_part.h"

#define MAX_ITL_UNDO_SIZE             sizeof(pcrh_undo_itl_t)  // sizeof(pcrh_poly_undo_itl_t)
#define PCRH_INSERT_UNDO_COUNT        2 // itl undo and insert undo

/*
 * PCR init a normal row
 * @param kernel session, row assist, row buffer, column count, itl_id, row flags
 */
static void pcrh_init_row(knl_session_t *session, row_assist_t *ra, char *buf,
    uint32 column_count, uint8 itl_id, uint16 flags)
{
    if (ra->is_csf) {
        csf_row_init(ra, buf, GS_MAX_ROW_SIZE, column_count);
        ra->head->flags = flags;
        ra->head->is_csf = 1;
    } else {
        row_init(ra, buf, GS_MAX_ROW_SIZE, column_count);
        ra->head->flags = flags;
        ra->head->is_csf = 0;
    }
    ROW_SET_ITL_ID(ra->head, itl_id);
}

/*
 * PCR init a migration row
 * @note For link row, the next rowid of migration row is invalid rowid.
 * For chain rows, next rowid points to next chain row.
 * @param kernel session, row assist, row buffer, column count, itl_id, row flags, next rowid
 */
static void pcrh_init_migr_row(knl_session_t *session, row_assist_t *ra, char *buf, uint32 column_count,
    uint8 itl_id, uint16 flags, rowid_t next_rid)
{
    if (ra->is_csf) {
        csf_row_init(ra, buf, GS_MAX_ROW_SIZE, column_count);
        ra->head->flags = flags;
        ra->head->is_csf = 1;
    } else {
        row_init(ra, buf, GS_MAX_ROW_SIZE, column_count);
        ra->head->flags = flags;
        ra->head->is_csf = 0;
    }
    ROW_SET_ITL_ID(ra->head, itl_id);
    ra->head->is_migr = 1;

    *(rowid_t *)(buf + ra->head->size) = next_rid;

    /* sizeof(rowid_t) is 8, row size will not exceed  PCRH_MAX_ROW_SIZE, less than max value(65535) of uint16 */
    ra->head->size += sizeof(rowid_t);
}

/*
 * construct compact row list
 * @param compact list, compact items, row offset
 */
static void pcrh_add_compact_item(compact_list_t *list, compact_item_t *compact_items, uint16 offset)
{
    compact_item_t *item = NULL;
    uint16 id = list->count;
    uint16 curr = list->last;

    compact_items[id].offset = offset;

    if (list->count == 0) {
        compact_items[id].prev = GS_INVALID_ID16;
        compact_items[id].next = GS_INVALID_ID16;

        list->first = id;
        list->last = id;
        list->count++;
        return;
    }

    for (;;) {
        item = &compact_items[curr];

        if (offset > item->offset) {
            if (item->next != GS_INVALID_ID16) {
                compact_items[item->next].prev = id;
            }

            compact_items[id].next = item->next;
            compact_items[id].prev = curr;
            item->next = id;

            if (list->last == curr) {
                list->last = id;
            }
            break;
        }

        if (item->prev == GS_INVALID_ID16) {
            knl_panic_log(list->first == curr,
                "the first of compact list is not curr, panic info: list's first %u curr %u", list->first, curr);
            compact_items[id].prev = GS_INVALID_ID16;
            compact_items[id].next = curr;
            item->prev = id;
            list->first = id;
            break;
        }

        curr = item->prev;
    }

    list->count++;
    return;
}

/*
 * compact PCR heap page
 * @note The algorithm is like heap_compact page, but a little different, because
 * rows are not continuous and physically compact any more. We use session stack
 * to temporarily sort offset of rows to get an ordered row list.
 * @param kernel session, heap page
 */
void pcrh_compact_page(knl_session_t *session, heap_page_t *page)
{
    row_head_t *row = NULL;
    pcr_row_dir_t *dir = NULL;
    pcr_itl_t *itl = NULL;
    uint16 i, copy_size;
    compact_list_t list;
    space_t *space = SPACE_GET(DATAFILE_GET(AS_PAGID_PTR(page->head.id)->file)->space_id);
    errno_t ret;

    list.count = 0;
    list.first = list.last = GS_INVALID_ID16;
    compact_item_t *items = (compact_item_t *)cm_push(session->stack, PAGE_SIZE(page->head));

    for (i = 0; i < page->dirs; i++) {
        dir = pcrh_get_dir(page, i);
        if (PCRH_DIR_IS_FREE(dir)) {
            continue;
        }

        /*
         * If row has been deleted and transaction is committed
         * and itl has cleaned, which means the itl has not been
         * reused or clean completed, we should free the remained
         * row size to page->free_size.
         */
        row = PCRH_GET_ROW(page, dir);
        if (row->is_deleted) {
            knl_panic_log(ROW_ITL_ID(row) != GS_INVALID_ID8, "row_itl_id is invalid, panic info: page %u-%u type %u",
                          AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
            itl = pcrh_get_itl(page, ROW_ITL_ID(row));
            if (!itl->is_active) {
                page->free_size += sizeof(row_head_t);
                *dir = page->first_free_dir | PCRH_DIR_FREE_MASK;
                page->first_free_dir = i;
                continue;
            }
        }

        pcrh_add_compact_item(&list, items, *dir);

        /* use row sprs_count to mark slot */
        *dir = row->sprs_count;
        row->sprs_count = i;
    }

    /* use ordered compact list to compact every active row */
    row_head_t *free_addr = (row_head_t *)((char *)page + sizeof(heap_page_t) + space->ctrl->cipher_reserve_size);
    i = list.first;

    while (i != GS_INVALID_ID16) {
        row = (row_head_t *)((char *)page + items[i].offset);
        dir = pcrh_get_dir(page, row->sprs_count);

        copy_size = (row->is_deleted) ? sizeof(row_head_t) : row->size;
        if (free_addr != row && copy_size != 0) {
            ret = memmove_s(free_addr, copy_size, row, copy_size);
            knl_securec_check(ret);
        }

        /* reset sprs_count and directory */
        free_addr->size = copy_size;
        free_addr->sprs_count = *dir;
        *dir = (uint16)((char *)free_addr - (char *)page);

        free_addr = (row_head_t *)((char *)free_addr + free_addr->size);
        i = items[i].next;
    }

    knl_panic_log((char *)free_addr <= (char *)page + page->free_begin,
                  "free_addr of page is wrong, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    /* free_addr - page is less than page size (8192)  */
    page->free_begin = (uint16)((char *)free_addr - (char *)page);

    cm_pop(session->stack);
}

/*
 * check row visible
 * We do this check before we try to construct a CR page in rowid fetch
 * The main idea is to reduce CR page construct as little as possible.
 * @attention This function in only called under PCR heap point fetch.
 * @param kernel session, kernel cursor, query scn, heap page, row slot
 */
static bool32 pcrh_check_row_visible(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
    heap_page_t *page, uint16 slot)
{
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    txn_info_t txn_info;

    /* invalid slot, no need to construct CR page */
    if (SECUREC_UNLIKELY(slot >= page->dirs)) {
        return GS_TRUE;
    }

    dir = pcrh_get_dir(page, slot);
    if (SECUREC_LIKELY(!PCRH_DIR_IS_FREE(dir))) {
        row = PCRH_GET_ROW(page, dir);
    }

    if (row == NULL || !row->is_changed || ROW_ITL_ID(row) == GS_INVALID_ID8) {
        txn_info.scn = page->scn;
        txn_info.status = (uint8)XACT_END;
    } else {
        itl = pcrh_get_itl(page, ROW_ITL_ID(row));
        tx_get_pcr_itl_info(session, GS_TRUE, itl, &txn_info);
    }

    if (txn_info.status == (uint8)XACT_END) {
        if (txn_info.scn <= query_scn) {
            return GS_TRUE;
        }
    } else {
        if (itl->xid.value == cursor->xid && itl->ssn < cursor->ssn) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

/*
 * get invisible itl from current CR page
 * @note This is the core function to construct a CR page.
 *
 * The CR rollback algorithm is as follow:
 * 1. Find all active transactions in current page to do CR rollback (neglect transaction order).
 * 2. For current transaction, we only rollback changes after current cursor to keep statement consistency.
 * 3. Find all inactive transactions in current page to do CR rollback (rollback in commit scn order).
 *
 * We do serialize check in page level not row level.
 * If current itl commit scn is ow_scn and query scn < commit scn, we can't decide whether to do rollback or not,
 * just throw 'snapshot too old' error here.
 * @param kernel session, kernel cursor, query scn, CR page, invisible itl(output), cleanout page
 */
static status_t pcrh_get_invisible_itl(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                       heap_page_t *cr_page, pcr_itl_t **itl, bool8 *cleanout)
{
    pcr_itl_t *item = NULL;
    txn_info_t txn_info;
    uint8 i;

    *itl = NULL;

    for (i = 0; i < cr_page->itls; i++) {
        item = pcrh_get_itl(cr_page, i);
        tx_get_pcr_itl_info(session, GS_TRUE, item, &txn_info);

        if (txn_info.status == (uint8)XACT_END) {
            if (item->is_active) {
                *cleanout = GS_TRUE;
                cr_page->free_size += item->fsc;
                item->is_active = 0;
                item->scn = txn_info.scn;
                item->is_owscn = (uint16)txn_info.is_owscn;
            } else if (item->is_fast) {
                *cleanout = GS_TRUE;
            }

            if (txn_info.scn <= query_scn) {
                continue;
            }

            if (txn_info.is_owscn) {
                tx_record_sql(session);
                GS_LOG_RUN_ERR("snapshot too old, detail: itl owscn %llu, query scn %llu", txn_info.scn, query_scn);
                GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
                return GS_ERROR;
            }

            if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE) {
                cursor->ssi_conflict = GS_TRUE;
            }

            /* find the recent itl to do CR rollback */
            if ((*itl) == NULL || (*itl)->scn < item->scn) {
                *itl = item;
            }
        } else {
            if (item->xid.value == cursor->xid) {
                if (item->ssn < cursor->ssn) {
                    continue;
                }
            } else if (TX_XA_CONSISTENCY(session)) {
                if ((txn_info.status == (uint8)XACT_PHASE1 ||
                    txn_info.status == (uint8)XACT_PHASE2) &&
                    txn_info.scn < query_scn) {
                    GS_LOG_DEBUG_INF("wait prepared transaction %u-%u-%u, status %u, scn %llu, query_scn %llu",
                                     item->xid.xmap.seg_id, item->xid.xmap.slot, item->xid.xnum, txn_info.status,
                                     txn_info.scn, query_scn);
                    session->wxid = item->xid;
                    ROWID_COPY(session->wrid, cursor->rowid);
                }
            }

            /* for active itl, just return to do CR rollback */
            *itl = item;
            return GS_SUCCESS;
        }
    }

    if (*itl != NULL) {
        return GS_SUCCESS;
    }

    /* user current query_scn as CR page scn */
    cr_page->scn = query_scn;

    return GS_SUCCESS;
}

/*
 * CR rollback function
 * revert an itl operation from undo
 * @param kernel session, CR page, itl, undo row
 */
static inline void pcrh_revert_itl(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl, undo_row_t *ud_row)
{
    itl->xid = *(xid_t *)ud_row->data;
    itl->scn = ud_row->scn;
    itl->is_owscn = ud_row->is_owscn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
    itl->is_active = GS_FALSE;
}

static void pcrh_revert_row_insert(knl_session_t *session, rowid_t rid, bool32 is_xfirst, heap_page_t *cr_page)
{
    pcr_row_dir_t *dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
    row_head_t *row = PCRH_GET_ROW(cr_page, dir);

    /* free directly if is last row */
    if (cr_page->free_begin == *dir + row->size) {
        cr_page->free_begin = *dir;
    }

    /* free directly if is last and new allocated dir */
    if (is_xfirst) {
        if ((uint16)rid.slot + 1 == cr_page->dirs) {
            /*
             * free_size and free_end both within DEFAULT_PAGE_SIZE,
             * sizeof(pcr_row_dir_t) is 2, so the sum less than max value(65535) of uint16.
             */
            cr_page->free_end += sizeof(pcr_row_dir_t);
            cr_page->free_size += sizeof(pcr_row_dir_t);
            cr_page->dirs--;
        } else {
            /* set dir to new dir with free mask, so that we can recycle later */
            *dir = PCRH_DIR_NEW_MASK | PCRH_DIR_FREE_MASK;
        }
    } else {
        *dir = PCRH_DIR_FREE_MASK;
    }

    /*
     * free_size less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
     * the sum is less than max value(65535) of uint16
     */
    cr_page->free_size += row->size;
    cr_page->rows--;
}
/*
 * CR rollback function
 * revert an insert operation from undo
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_insert(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl, undo_row_t *ud_row)
{
    rowid_t rid = ud_row->rowid;
    knl_panic_log(itl->xid.value == ud_row->xid.value, "the xid of itl and ud_row are not equal, panic info: "
                  "page %u-%u type %u itl xid %llu ud_row xid %llu", AS_PAGID(cr_page->head.id).file,
                  AS_PAGID(cr_page->head.id).page, cr_page->head.type, itl->xid.value, ud_row->xid.value);
    pcrh_revert_row_insert(session, rid, ud_row->is_xfirst, cr_page);
    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback function
 * revert batch insert operation from undo
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_batch_insert(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl,
    undo_row_t *ud_row)
{
    rowid_t rid;
    uint16 is_xfirst;
    pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)ud_row->data;

    rid = ud_row->rowid;
    for (int32 i = batch_undo->count - 1; i >= 0; i--) {
        rid.slot = batch_undo->undos[i].slot;
        /* For compatibility reasons, we need to use ud_row->is_xfirst to decide which xfirst to use */
        is_xfirst = ud_row->is_xfirst ? ud_row->is_xfirst : batch_undo->undos[i].is_xfirst;
        pcrh_revert_row_insert(session, rid, is_xfirst, cr_page);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}
/*
 * CR rollback function
 * reorganize a heap row by current row and undo update info
 * @param kernel session, current row, undo update info, origin row
 */
static void pcrh_reorganize_undo_update(knl_session_t *session, row_head_t *row,
                                        heap_undo_update_info_t *undo_info, row_head_t *ori_row)
{
    knl_update_info_t info;
    row_assist_t ra;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    rowid_t next_rid;
    uint16 col_size;
    errno_t ret;
    ra.is_csf = row->is_csf;

    CM_SAVE_STACK(session->stack);

    CM_PUSH_UPDATE_INFO(session, info);
    /* max value of max_column_count is GS_MAX_COLUMNS(4096) */
    offsets = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));
    lens = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));

    info.count = undo_info->count;
    /* info.count will not exceed GS_MAX_COLUMNS(4096), so col_size less than max value(65535) of uint16  */
    col_size = info.count * sizeof(uint16);
    if (col_size != 0) {
        ret = memcpy_sp(info.columns, (session)->kernel->attr.max_column_count * sizeof(uint16),
            undo_info->columns, col_size);
        knl_securec_check(ret);
    }

    info.data = (char *)undo_info + HEAP_UNDO_UPDATE_INFO_SIZE(info.count);
    cm_decode_row(info.data, info.offsets, info.lens, NULL);
    cm_decode_row((char *)row, offsets, lens, NULL);

    if (!row->is_migr) {
        pcrh_init_row(session, &ra, (char *)ori_row, undo_info->old_cols, ROW_ITL_ID(row), row->flags);
    } else {
        next_rid = *PCRH_NEXT_ROWID(row);
        pcrh_init_migr_row(session, &ra, (char *)ori_row, undo_info->old_cols, ROW_ITL_ID(row), row->flags, next_rid);
    }

    heap_reorganize_with_update(row, offsets, lens, &info, &ra);

    CM_RESTORE_STACK(session->stack);
}

/*
 * CR rollback function
 * We try to revert alloc itl and dir to free more space for revert update/delete.
 * Theoretically, it's safe to remove those dirs and itls now.
 * @param kernel session, CR page
 */
void pcrh_revert_alloc_space(knl_session_t *session, heap_page_t *cr_page)
{
    pcr_row_dir_t *dir = NULL;
    pcr_itl_t *itl = NULL;
    char *src = NULL;
    char *dst = NULL;
    int16 slot;
    int8 id, count;
    errno_t ret;

    for (slot = (int16)(cr_page->dirs - 1); slot >= 0; slot--) {
        dir = pcrh_get_dir(cr_page, slot);
        if (!PCRH_DIR_IS_FREE(dir)) {
            break;
        }

        if (PCRH_DIR_IS_NEW(dir)) {
            /*
             * free_size and free_end both within DEFAULT_PAGE_SIZE, sizeof(pcr_row_dir_t) is 2,
             * so the sum less than max value(65535) of uint16
             */
            cr_page->free_end += sizeof(pcr_row_dir_t);
            cr_page->free_size += sizeof(pcr_row_dir_t);
            cr_page->dirs--;
        }
    }

    count = 0;
    for (id = cr_page->itls - 1; id >= 0; id--) {
        itl = pcrh_get_itl(cr_page, id);
        if (itl->is_active || itl->scn != 0) {
            break;
        }
        count++;
    }

    if (count > 0) {
        if (cr_page->dirs > 0) {
            src = (char *)cr_page + cr_page->free_end;
            dst = src + count * sizeof(pcr_itl_t);

            ret = memmove_s(dst, cr_page->dirs * sizeof(pcr_row_dir_t), src, cr_page->dirs * sizeof(pcr_row_dir_t));
            knl_securec_check(ret);
        }

        /*
         * free_size and free_end both within DEFAULT_PAGE_SIZE, sizeof(pcr_row_dir_t) is 2,
         * so the sum less than max value(65535) of uint16
         */
        cr_page->free_end += count * sizeof(pcr_itl_t);
        cr_page->free_size += count * sizeof(pcr_itl_t);
        cr_page->itls -= (uint8)count;
    }
}

/*
 * CR rollback function
 * revert an update operation from undo
 * @note during rollback update, we may be need to compact current CR page to get an enough page space
 * to insert old row, if there is any space in itl fsc, just use it.
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_update(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl, undo_row_t *ud_row)
{
    rowid_t rid;
    pcr_row_dir_t *dir;
    row_head_t *row;
    row_head_t *ori_row = NULL;
    int16 inc_size;
    errno_t ret;

    rid = ud_row->rowid;

    dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
    row = PCRH_GET_ROW(cr_page, dir);

    CM_SAVE_STACK(session->stack);

    if (ud_row->type == UNDO_PCRH_UPDATE_FULL) {
        ori_row = (row_head_t *)ud_row->data;
    } else {
        knl_panic_log(!row->is_link, "row is link, panic info: page %u-%u type %u", AS_PAGID(cr_page->head.id).file,
                      AS_PAGID(cr_page->head.id).page, cr_page->head.type);
        ori_row = (row_head_t *)cm_push(session->stack, PCRH_MAX_MIGR_SIZE);
        pcrh_reorganize_undo_update(session, row, (heap_undo_update_info_t *)ud_row->data, ori_row);
    }

    inc_size = ori_row->size - row->size;

    if (inc_size > 0) {
        if (cr_page->free_size < inc_size) {
            pcrh_revert_alloc_space(session, cr_page);
            dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
            row = PCRH_GET_ROW(cr_page, dir);
        }

        if (cr_page->free_end - cr_page->free_begin < ori_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, cr_page);
        }

        *dir = cr_page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE, row size less than PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16
         */
        cr_page->free_begin += ori_row->size;
        cr_page->free_size -= inc_size;
        knl_panic_log(cr_page->free_begin <= cr_page->free_end, "cr_page's free size begin is bigger than end, panic "
                      "info: free_begin %u free_end %u page %u-%u type %u", cr_page->free_begin, cr_page->free_end,
                      AS_PAGID(cr_page->head.id).file, AS_PAGID(cr_page->head.id).page, cr_page->head.type);

        /* relocate the row position */
        row = PCRH_GET_ROW(cr_page, dir);
    } else {
        /* inc_size is negative and the ads value of inc_size is less than page size(8192) */
        cr_page->free_size -= inc_size;
    }

    ret = memcpy_sp(row, DEFAULT_PAGE_SIZE - *dir, (char *)ori_row, ori_row->size);
    knl_securec_check(ret);

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    CM_RESTORE_STACK(session->stack);

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback function
 * revert an delete operation from undo
 * @note delete rollback update, we may be need to compact current CR page, because the deleted space would
 * be used after the delete operation, if there is any space in itl fsc, just use it.
 * @param kernel session, CR page, itl, undo row
 */
static void pcrh_revert_delete(knl_session_t *session, heap_page_t *cr_page, pcr_itl_t *itl, undo_row_t *ud_row)
{
    row_head_t *row = NULL;

    rowid_t rid = ud_row->rowid;
    row_head_t *ori_row = (row_head_t *)ud_row->data;

    pcr_row_dir_t *dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
    if (!PCRH_DIR_IS_FREE(dir)) {
        row = PCRH_GET_ROW(cr_page, dir);
        if (row->size == ori_row->size) {
            /* deleted row has not been compacted, we can rollback directly */
            row->is_deleted = 0;
        } else {
            /* row has been compact, we should find a new space in page to revert delete */
            knl_panic_log(row->size == sizeof(row_head_t),
                "row size is abnormal, panic info: page %u-%u type %u row_size %u", AS_PAGID(cr_page->head.id).file,
                AS_PAGID(cr_page->head.id).page, cr_page->head.type, row->size);

            row = NULL;
        }

        /* current row is deleted, the remained size can free to CR page */
        cr_page->free_size += sizeof(row_head_t);
    }

    if (row == NULL) {
        if (cr_page->free_size < ori_row->size) {
            pcrh_revert_alloc_space(session, cr_page);
            dir = pcrh_get_dir(cr_page, (uint16)rid.slot);
            row = PCRH_GET_ROW(cr_page, dir);
        }

        if (cr_page->free_end - cr_page->free_begin < ori_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, cr_page);
        }

        *dir = cr_page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16
         */
        cr_page->free_begin += ori_row->size;
        knl_panic_log(cr_page->free_begin <= cr_page->free_end, "cr_page's free size begin is bigger than end, panic "
                      "info: free_begin %u free_end %u page %u-%u type %u", cr_page->free_begin, cr_page->free_end,
                      AS_PAGID(cr_page->head.id).file, AS_PAGID(cr_page->head.id).page, cr_page->head.type);

        /* relocate the row position */
        row = PCRH_GET_ROW(cr_page, dir);
        errno_t ret = memcpy_sp(row, DEFAULT_PAGE_SIZE - *dir, ori_row, ori_row->size);
        knl_securec_check(ret);
    }

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    knl_panic_log(cr_page->free_size >= row->size, "cr_page's free_size is smaller than row's size, panic info: "
                  "page %u-%u type %u free_size %u row size %u", AS_PAGID(cr_page->head.id).file,
                  AS_PAGID(cr_page->head.id).page, cr_page->head.type, cr_page->free_size, row->size);
    cr_page->free_size -= row->size;
    cr_page->rows++;

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback function
 * revert an update next rowid operation from undo
 * @param kernel session, CR page, itl, undo row
 */
static inline void pcrh_revert_update_next_rid(knl_session_t *session, heap_page_t *cr_page,
                                               pcr_itl_t *itl, undo_row_t *ud_row)
{
    pcr_row_dir_t *dir = pcrh_get_dir(cr_page, (uint16)ud_row->rowid.slot);
    knl_panic(!PCRH_DIR_IS_FREE(dir));
    row_head_t *row = PCRH_GET_ROW(cr_page, dir);
    knl_panic(row->is_link || row->is_migr);

    /* revert link rowid */
    *PCRH_NEXT_ROWID(row) = *(rowid_t *)ud_row->data;

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback function
 * revert an lock link row operation
 * @param kernel session, itl, undo row
 */
static inline void pcrh_revert_update_link_ssn(knl_session_t *session, heap_page_t *cr_page,
                                               pcr_itl_t *itl, undo_row_t *ud_row)
{
    pcr_row_dir_t *dir = pcrh_get_dir(cr_page, (uint16)ud_row->rowid.slot);
    knl_panic(!PCRH_DIR_IS_FREE(dir));
    row_head_t *row = PCRH_GET_ROW(cr_page, dir);

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
}

/*
 * CR rollback interface
 * @param kernel session, CR page, itl_id, undo row
 */
static void pcrh_reorganize_with_undo(knl_session_t *session, heap_page_t *cr_page,
    pcr_itl_t *itl, undo_row_t *ud_row)
{
    switch (ud_row->type) {
        case UNDO_PCRH_ITL:
            pcrh_revert_itl(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_INSERT:
            pcrh_revert_insert(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_DELETE:
        case UNDO_PCRH_COMPACT_DELETE:
            pcrh_revert_delete(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_UPDATE:
        case UNDO_PCRH_UPDATE_FULL:
            pcrh_revert_update(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_UPDATE_LINK_SSN:
            pcrh_revert_update_link_ssn(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_UPDATE_NEXT_RID:
            pcrh_revert_update_next_rid(session, cr_page, itl, ud_row);
            break;

        case UNDO_PCRH_BATCH_INSERT:
            pcrh_revert_batch_insert(session, cr_page, itl, ud_row);
            break;

        default:
            break;
    }
}

/*
 * PCR reorganize with undo list
 * @note rollback from the specified itl undo snapshot, as we know,
 * different rows in same page changed by the same transaction, there undos
 * are in the same undo list, so we don't check rowid here, just check xid.
 * We keep statement level read consistency when visit undo snapshot.
 * @param kernel session, kernel cursor, CR page, itl_id, flashback mark
 */
static status_t pcrh_reorganize_with_undo_list(knl_session_t *session, knl_cursor_t *cursor,
                                               heap_page_t *cr_page, pcr_itl_t *itl, bool8 *fb_mark)
{
    /*
     * When we are going to revert an itl, we take over the free space management
     * for the whole page revert to keep enough free space for every itl.
     * And if itl is inactive, set to active before revert.
     */
    if (!itl->is_active) {
        itl->is_active = GS_TRUE;
    } else {
        /* free_size and itl->fsc both within DEFAULT_PAGE_SIZE, so the sum less than max value(65535) of uint16 */
        cr_page->free_size += itl->fsc;
    }

    itl->is_hist = GS_TRUE;
    itl->fsc = 0;

    /* on condition of nologging, no undo page */
    if (IS_INVALID_PAGID(PAGID_U2N(itl->undo_page))) {
        tx_record_sql(session);
        GS_LOG_RUN_ERR("snapshot too old: invalid undo page_id, itl scn %llu", itl->scn);
        GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
        return GS_ERROR;
    }

    for (;;) {
        if (buf_read_page(session, PAGID_U2N(itl->undo_page), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }

        undo_page_t *ud_page = (undo_page_t *)CURR_PAGE;
        if (itl->undo_slot >= ud_page->rows) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot slot %u, undo rows %u, query scn %llu",
                           (uint32)itl->undo_slot, (uint32)ud_page->rows, cursor->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        undo_row_t *ud_row = UNDO_ROW(ud_page, itl->undo_slot);
        if (itl->xid.value != ud_row->xid.value) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot xid %llu, undo row xid %llu, query scn %llu",
                           itl->xid.value, ud_row->xid.value, cursor->query_scn);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        /* support statement level read consistency */
        if (ud_row->xid.value == cursor->xid && ud_row->ssn < cursor->ssn) {
            itl->ssn = ud_row->ssn;
            buf_leave_page(session, GS_FALSE);
            return GS_SUCCESS;
        }

        pcrh_reorganize_with_undo(session, cr_page, itl, ud_row);

        /* current itl is done, caller should find a new recent itl to do CR rollback */
        if (ud_row->type == UNDO_PCRH_ITL) {
            buf_leave_page(session, GS_FALSE);
            return GS_SUCCESS;
        }

        /* for flashback, we mark row has been roll backed in flashback buffer */
        if (fb_mark != NULL) {
            if (ud_row->type == UNDO_PCRH_BATCH_INSERT) {
                /* for batch insert, we need mark every row */
                pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)ud_row->data;
                for (uint32 i = 0; i < batch_undo->count; i++) {
                    fb_mark[batch_undo->undos[i].slot] = 1;
                }
            } else {
                fb_mark[ud_row->rowid.slot] = 1;
            }
        }

        buf_leave_page(session, GS_FALSE);
    }
}

/*
 * PCR construct CR page interface
 * @note use the given query scn to rollback current page to a consistent status
 * After rollback, the CR page may not be exist in history, but it's consistent for current query scn
 * @attention stop rollback when we detect that we need to wait prepared transaction
 * @param kernel session, kernel cursor, query scn, CR page, flashback mark, cleanout page
 */
static status_t pcrh_construct_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                       heap_page_t *cr_page, bool8 *fb_mark, bool8 *cleanout)
{
    pcr_itl_t *itl = NULL;
    cursor->ssi_conflict = GS_FALSE;
    bool8 constructed = GS_FALSE;
    for (;;) {
        if (pcrh_get_invisible_itl(session, cursor, query_scn, cr_page, &itl, cleanout) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (itl == NULL || session->wxid.value != GS_INVALID_ID64) {
            /*
             * 1.no invisible itl, just return current CR page
             * 2.waiting for prepared transaction
             */
            if (constructed) {
                session->stat.pcr_construct_count++;
            }
            return GS_SUCCESS;
        }

        if (pcrh_reorganize_with_undo_list(session, cursor, cr_page, itl, fb_mark) != GS_SUCCESS) {
            return GS_ERROR;
        }
        constructed = GS_TRUE;
    }
}

/*
 * PCR heap prefetch CR page
 * @note enter a current page, rollback it to a consistent status during query scn
 * @param kernel session, kernel cursor, query scn, page id, CR page, flashback mark
 */
status_t pcrh_prefetch_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                               page_id_t page_id, char *page_buf, bool8 *fb_mark)
{
    heap_page_t *page = NULL;
    errno_t ret;

    for (;;) {
        if (cursor->isolevel == ISOLATION_CURR_COMMITTED) {
            cursor->query_scn = DB_CURR_SCN(session);
            query_scn = cursor->query_scn;
            cursor->cc_cache_time = KNL_NOW(session);
        }

        /* try get page from CR pool */
        pcrp_enter_page(session, page_id, query_scn, (uint32)cursor->ssn);
        page = (heap_page_t *)CURR_CR_PAGE;

        if (page != NULL && SECUREC_LIKELY(cursor->isolevel != ISOLATION_SERIALIZABLE)) {
            if (heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
                ret = memcpy_s(page_buf, DEFAULT_PAGE_SIZE, page, DEFAULT_PAGE_SIZE);
                knl_securec_check(ret);
                pcrp_leave_page(session, GS_FALSE);
                return GS_SUCCESS;
            } else {
                /* current CR page is no used for current session, just release it */
                pcrp_leave_page(session, GS_TRUE);
            }
        }

        if (page != NULL) {
            pcrp_leave_page(session, GS_TRUE);
        }

        if (buf_read_prefetch_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL) != GS_SUCCESS) {
            return GS_ERROR;
        }

        page = (heap_page_t *)CURR_PAGE;

        if (!heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
            buf_leave_page(session, GS_FALSE);
            HEAP_CHECKPAGE_ERROR(cursor);
            return GS_ERROR;
        }

        ret = memcpy_sp(page_buf, DEFAULT_PAGE_SIZE, page, DEFAULT_PAGE_SIZE);
        knl_securec_check(ret);
        buf_leave_page(session, GS_FALSE);

        if (pcrh_construct_cr_page(session, cursor, query_scn, (heap_page_t *)page_buf,
                                   fb_mark, &cursor->cleanout) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (session->wxid.value != GS_INVALID_ID64) {
            if (tx_wait(session, 0, ENQ_TX_READ_WAIT) != GS_SUCCESS) {
                tx_record_rowid(session->wrid);
                return GS_ERROR;
            }
            continue;
        }

        if (cursor->global_cached) {
            pcrp_alloc_page(session, page_id, query_scn, (uint32)cursor->ssn);
            ret = memcpy_s(CURR_CR_PAGE, DEFAULT_PAGE_SIZE, page_buf, DEFAULT_PAGE_SIZE);
            knl_securec_check(ret);
            pcrp_leave_page(session, GS_FALSE);
        }

        return GS_SUCCESS;
    }
}

/*
 * PCR heap enter CR page
 * @note enter a current page, check if *current row* is visible to us,
 * if visible, return current page, otherwise, copy it as cached page,
 * rollback the copied page to a consistent status using query scn
 * @param kernel session, kernel cursor, query scn, rowid
 */
static status_t pcrh_enter_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, rowid_t rowid)
{
    bool8 cleanout = GS_FALSE;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    heap_page_t *page = NULL;
    errno_t ret;

    for (;;) {
        if (buf_read_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }
        page = (heap_page_t *)CURR_PAGE;

        if (!heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
            buf_leave_page(session, GS_FALSE);
            HEAP_CHECKPAGE_ERROR(cursor);
            return GS_ERROR;
        }

        /* check row in current page is visible or not */
        if (pcrh_check_row_visible(session, cursor, query_scn, page, (uint16)rowid.slot)) {
            cursor->page_cache = NO_PAGE_CACHE;
            return GS_SUCCESS;
        }

        /* try get page from CR pool */
        pcrp_enter_page(session, page_id, query_scn, (uint32)cursor->ssn);
        page = (heap_page_t *)CURR_CR_PAGE;

        if (page != NULL && SECUREC_LIKELY(cursor->isolevel != ISOLATION_SERIALIZABLE)) {
            /*
             * if current CR page is valid, leave current page and use CR page.
             * otherwise, reuse it to generate a new CR page
             */
            if (heap_check_page(session, cursor, page, PAGE_TYPE_PCRH_DATA)) {
                buf_leave_page(session, GS_FALSE);
                cursor->page_cache = GLOBAL_PAGE_CACHE;
                return GS_SUCCESS;
            }
        } else {
            if (page != NULL) {
                pcrp_leave_page(session, GS_TRUE);
            }

            pcrp_alloc_page(session, page_id, query_scn, (uint32)cursor->ssn);
            page = (heap_page_t *)CURR_CR_PAGE;
        }

        ret = memcpy_sp((char *)page, DEFAULT_PAGE_SIZE, CURR_PAGE, DEFAULT_PAGE_SIZE);
        knl_securec_check(ret);
        buf_leave_page(session, GS_FALSE);

        if (pcrh_construct_cr_page(session, cursor, query_scn, page, NULL, &cleanout) != GS_SUCCESS) {
            pcrp_leave_page(session, GS_TRUE);
            return GS_ERROR;
        }

        if (session->wxid.value != GS_INVALID_ID64) {
            pcrp_leave_page(session, GS_TRUE);
            if (tx_wait(session, 0, ENQ_TX_READ_WAIT) != GS_SUCCESS) {
                tx_record_rowid(session->wrid);
                return GS_ERROR;
            }
            continue;
        }

        cursor->page_cache = GLOBAL_PAGE_CACHE;
        return GS_SUCCESS;
    }
}

/*
 * get current heap page during current page cache type
 */
static inline heap_page_t *pcrh_get_curr_page(knl_session_t *session, knl_cursor_t *cursor)
{
    switch (cursor->page_cache) {
        case NO_PAGE_CACHE:
            return (heap_page_t *)CURR_PAGE;
        case GLOBAL_PAGE_CACHE:
            return (heap_page_t *)CURR_CR_PAGE;
        case LOCAL_PAGE_CACHE:
            return (heap_page_t *)cursor->page_buf;
        default:
            return NULL;
    }
}

/*
 * release current heap page during current page cache type
 */
static inline void pcrh_leave_curr_page(knl_session_t *session, knl_cursor_t *cursor)
{
    switch (cursor->page_cache) {
        case NO_PAGE_CACHE:
            buf_leave_page(session, GS_FALSE);
            break;
        case GLOBAL_PAGE_CACHE:
            pcrp_leave_page(session, GS_FALSE);
            break;
        default:
            break;
    }
}

/*
 * PCR clean itl
 * @note only clean delete rows and return itl->fsc to page->free_size
 * @attention if we use fast commit during commit is ok, sames oracle cleaned all
 * @param kernel session, kernel cursor, heap page, clean itl redo
 */
void pcrh_clean_itl(knl_session_t *session, heap_page_t *page, rd_pcrh_clean_itl_t *redo)
{
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl;
    uint16 i;

    itl = pcrh_get_itl(page, redo->itl_id);

    if (page->scn < redo->scn) {
        page->scn = redo->scn;
    }

    if (itl->is_active) {
        /* free_size and itl->fsc both within DEFAULT_PAGE_SIZE, so the sum less than max value(65535) of uint16 */
        page->free_size += itl->fsc;
        itl->is_active = 0;
        itl->scn = redo->scn;
        itl->is_owscn = (uint16)redo->is_owscn;
    }

    itl->is_fast = (uint16)redo->is_fast;

    if (redo->is_fast) {
        return;
    }

    for (i = 0; i < page->dirs; i++) {
        dir = pcrh_get_dir(page, i);
        if (PCRH_DIR_IS_FREE(dir)) {
            continue;
        }

        row = PCRH_GET_ROW(page, dir);
        if (ROW_ITL_ID(row) != redo->itl_id) {
            continue;
        }

        if (row->is_deleted) {
            /*
             * free_size and free_end both within DEFAULT_PAGE_SIZE, sizeof(pcr_row_dir_t) is 2,
             * less than max value(65535) of uint16.
             */
            page->free_size += sizeof(row_head_t);
            *dir = page->first_free_dir | PCRH_DIR_FREE_MASK;
            page->first_free_dir = i;
        }
    }
}

/*
 * PCR heap clean lock
 * @note clean heap itl during transaction end
 * @param kernel session, lock item
 */
void pcrh_clean_lock(knl_session_t *session, lock_item_t *item)
{
    heap_t *heap = NULL;
    heap_page_t *page = NULL;
    pcr_itl_t *itl = NULL;
    uint8 owner_list;
    page_id_t page_id;
    seg_stat_t temp_stat;
    rd_pcrh_clean_itl_t rd_clean;
    uint8 option = !session->kernel->attr.delay_cleanout ? ENTER_PAGE_NORMAL : (ENTER_PAGE_NORMAL | ENTER_PAGE_TRY);

    page_id = MAKE_PAGID(item->file, item->page);
    SEG_STATS_INIT(session, &temp_stat);
    log_atomic_op_begin(session);

    buf_enter_page(session, page_id, LATCH_MODE_X, option);

    if (session->curr_page == NULL) {
        log_atomic_op_end(session);
        return;
    }

    page = (heap_page_t *)CURR_PAGE;
    itl = pcrh_get_itl(page, item->itl);
    if (!itl->is_active || itl->xid.value != session->rm->xid.value) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        return;
    }

    knl_part_locate_t part_loc;
    part_loc.part_no = item->part_no;
    part_loc.subpart_no = item->subpart_no;
    heap = dc_get_heap(session, page->uid, page->oid, part_loc, NULL);

    rd_clean.itl_id = item->itl;
    rd_clean.scn = session->rm->txn->scn;
    rd_clean.is_owscn = 0;
    rd_clean.is_fast = 1;
    rd_clean.aligned = 0;
    pcrh_clean_itl(session, page, &rd_clean);
    if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
        log_put(session, RD_PCRH_CLEAN_ITL, &rd_clean, sizeof(rd_pcrh_clean_itl_t), LOG_ENTRY_FLAG_NONE);
    }

    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, page_id);
    SEG_STATS_RECORD(session, temp_stat, &heap->stat);
}

void pcrh_cleanout_itls(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page, bool32 *changed)
{
    pcr_itl_t *itl = NULL;
    txn_info_t txn_info;
    uint8 i;
    rd_pcrh_clean_itl_t rd_clean;

    for (i = 0; i < page->itls; i++) {
        itl = pcrh_get_itl(page, i);
        if (!itl->is_active && !itl->is_fast) {
            continue;
        }

        tx_get_pcr_itl_info(session, GS_FALSE, itl, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            continue;
        }

        rd_clean.itl_id = i;
        rd_clean.scn = txn_info.scn;
        rd_clean.is_owscn = (uint8)txn_info.is_owscn;
        rd_clean.is_fast = 0;
        rd_clean.aligned = 0;
        pcrh_clean_itl(session, page, &rd_clean);
        if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
            log_put(session, RD_PCRH_CLEAN_ITL, &rd_clean, sizeof(rd_pcrh_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }
        *changed = GS_TRUE;
    }
}

/*
 * PCR get row from page
 * @note in current page, all rows are visible to us after CR rollback (if necessary), just read it.
 * @param kernel session, kernel cursor, query_scn, CR page,
 */
static bool32 pcrh_get_row(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, heap_page_t *page)
{
    pcr_row_dir_t *dir = NULL;
    pcr_itl_t *itl = NULL;
    row_head_t *row = NULL;
    txn_info_t txn_info;
    errno_t ret;

    dir = pcrh_get_dir(page, (uint16)cursor->rowid.slot);
    if (PCRH_DIR_IS_FREE(dir)) {
        return GS_FALSE;
    }

    row = PCRH_GET_ROW(page, dir);
    if (row->is_deleted) {
        return GS_FALSE;
    }

    if (row->is_migr) {
        session->has_migr = GS_TRUE;
        return GS_FALSE;
    }

    if (!row->is_link) {
        if (cursor->page_cache == LOCAL_PAGE_CACHE) {
            /* cursor row can point to local CR page row directly */
            cursor->row = row;
        } else {
            /* we should copy row to row buffer from current page */
            cursor->row = (row_head_t *)cursor->buf;
            ret = memcpy_sp((cursor)->row, DEFAULT_PAGE_SIZE, (row), (row)->size);
            knl_securec_check(ret);
        }
    } else {
        /* If we see a link flag in current page, it means we have to read the migration */
        cursor->link_rid = *PCRH_NEXT_ROWID(row);
    }

    if (cursor->page_cache != NO_PAGE_CACHE || ROW_ITL_ID(row) == GS_INVALID_ID8 || !row->is_changed) {
        /** use the current query_scn as row scn */
        cursor->scn = query_scn;
    } else {
        itl = pcrh_get_itl(page, ROW_ITL_ID(row));
        tx_get_pcr_itl_info(session, GS_TRUE, itl, &txn_info);
        cursor->scn = txn_info.scn;
    }

    return GS_TRUE;
}

/*
 * PCR heap scan CR page
 * @param kernel session, kernel cursor, query_scn, CR page, is_found(output)
 */
static status_t pcrh_scan_cr_page(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                  heap_page_t *cr_page, bool32 *is_found)
{
    *is_found = GS_FALSE;

    cursor->chain_count = 0;
    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);

    for (;;) {
        if (cursor->rowid.slot == INVALID_SLOT) {
            cursor->rowid.slot = 0;
        } else {
            cursor->rowid.slot++;
        }

        if (cursor->rowid.slot == cr_page->dirs) {
            if (IS_SAME_PAGID(cursor->scan_range.r_page, AS_PAGID(cr_page->head.id))) {
                SET_ROWID_PAGE(&cursor->rowid, INVALID_PAGID);
            } else {
                SET_ROWID_PAGE(&cursor->rowid, AS_PAGID(cr_page->next));
            }

            cursor->rowid.slot = INVALID_SLOT;

            return GS_SUCCESS;
        } else if (cursor->rowid.slot > cr_page->dirs) {
            GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
            return GS_ERROR;
        }

        if (pcrh_get_row(session, cursor, query_scn, cr_page)) {
            *is_found = GS_TRUE;
            return GS_SUCCESS;
        }
    }
}

/*
* PCR fetch single chain row interface
* @note some single chain rows will construct the whole row. if fetching success, current page would be 
*       release after merge chain row.
* @param kernel session, kernel cursor, query scn, rowid
*/
static status_t pcrh_get_chain_row(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, 
    rowid_t rowid, row_head_t **row)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;

    if (pcrh_enter_cr_page(session, cursor, query_scn, rowid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    page = pcrh_get_curr_page(session, cursor);
    if (rowid.slot >= page->dirs) {
        pcrh_leave_curr_page(session, cursor);
        GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return GS_ERROR;
    }

    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    if (PCRH_DIR_IS_FREE(dir)) {
        pcrh_leave_curr_page(session, cursor);
        GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return GS_ERROR;
    }

    *row = PCRH_GET_ROW(page, dir);
    knl_panic((*row)->is_migr == 1);
    return GS_SUCCESS;
}

/*
* PCR fetch chain rows interface
* @note use the query scn to construct CR pages of every chain row, reorganize all chain rows to origin row
* @param kernel session, kernel cursor, query scn, CR page
*/
static status_t pcrh_fetch_chain_rows(knl_session_t *session, knl_cursor_t *cursor,
    knl_scn_t query_scn, row_head_t *row)
{
    dc_entity_t *entity;
    row_chain_t *chain = (row_chain_t *)cursor->chain_info;
    rowid_t rowid, prev_rid;
    row_assist_t ra;
    uint16 slot;
    uint16 column_count;
    uint16 data_offset;
    uint16 size;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);

    slot = 0;
    column_count = 0;
    rowid = cursor->link_rid;
    prev_rid = cursor->rowid;
    entity = (dc_entity_t *)cursor->dc_entity;

    cm_row_init(&ra, (char *)cursor->row, max_row_len, entity->column_count, row->is_csf);
    data_offset = cursor->row->size;

    for (;;) {
        chain[slot].chain_rid = rowid;
        chain[slot].owner_rid = prev_rid;
        chain[slot].col_start = column_count;
        chain[slot].col_count = ROW_COLUMN_COUNT(row);
        chain[slot].row_size = row->size;

        cm_decode_row((char *)row, cursor->offsets, cursor->lens, &size);

        heap_merge_chain_row(cursor, row, column_count, size, &data_offset);

        /* max column count of table is GS_MAX_COLUMNS(4096) , so the sum will not exceed max value of uint16 */
        column_count += chain[slot].col_count;

        prev_rid = rowid;
        rowid = *PCRH_NEXT_ROWID(row);

        pcrh_leave_curr_page(session, cursor); /** leave current page */

        if (IS_INVALID_ROWID(rowid)) {
            break;
        }

        /* if fetching success, current page would be release after merge chain row. */
        if (pcrh_get_chain_row(session, cursor, query_scn, rowid, &row) != GS_SUCCESS) {
            return GS_ERROR;
        }

        slot++;
    }

    cursor->chain_count = slot + 1;

    if (column_count != entity->column_count) {
        heap_reorganize_chain_row(session, cursor, &ra, column_count);
    }
    row_end(&ra);

    return GS_SUCCESS;
}

static status_t pcrh_chain_row_column_count(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
    uint32 *col_count)
{
    rowid_t rowid;
    row_head_t *row = NULL;
    rowid = cursor->link_rid;

    for (;;) {
        if (IS_INVALID_ROWID(rowid)) {
            break;
        }

        if (pcrh_get_chain_row(session, cursor, query_scn, rowid, &row) != GS_SUCCESS) {
            return GS_ERROR;
        }

        *col_count += ROW_COLUMN_COUNT(row);
        rowid = *PCRH_NEXT_ROWID(row);

        pcrh_leave_curr_page(session, cursor); /** leave current page */
    }

    return GS_SUCCESS;
}

/*
 * PCR fetch chain rows interface in current committed isolation level
 * @note use the query scn to construct CR pages of every chain row, reorganize all chain rows to origin row
 * @note the column count of dc may be less the column count of row in cc-isolation level,so we need get real 
         the column count of row to init row and decode row.
 * @param kernel session, kernel cursor, query scn, CR page
 */
static status_t pcrh_fetch_cc_chain_rows(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn, 
    bool32 is_csf)
{
    dc_entity_t *entity;
    row_chain_t *chain = (row_chain_t *)cursor->chain_info;
    row_head_t *row = NULL;
    rowid_t rowid, prev_rid;
    row_assist_t ra;
    uint16 slot;
    uint16 column_count;
    uint16 data_offset;
    uint16 size;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);
    uint32 col_count = 0;

    slot = 0;
    column_count = 0;
    rowid = cursor->link_rid;
    prev_rid = cursor->rowid;
    entity = (dc_entity_t *)cursor->dc_entity;

    if (pcrh_chain_row_column_count(session, cursor, query_scn, &col_count) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_row_init(&ra, (char *)cursor->row, max_row_len, col_count, is_csf);
    data_offset = cursor->row->size;
    for (;;) {
        if (IS_INVALID_ROWID(rowid)) {
            break;
        }

        /* if fetch chain row success, current page would be release after merge chain row */
        if (pcrh_get_chain_row(session, cursor, query_scn, rowid, &row) != GS_SUCCESS) {
            return GS_ERROR;
        }

        chain[slot].chain_rid = rowid;
        chain[slot].owner_rid = prev_rid;
        chain[slot].col_start = column_count;
        chain[slot].col_count = ROW_COLUMN_COUNT(row);
        chain[slot].row_size = row->size;

        cm_decode_row((char *)row, cursor->offsets, cursor->lens, &size);
        heap_merge_chain_row(cursor, row, column_count, size, &data_offset);

        /* max column count of table is GS_MAX_COLUMNS(4096) , so the sum will not exceed max value of uint16 */
        column_count += chain[slot].col_count;

        prev_rid = rowid;
        rowid = *PCRH_NEXT_ROWID(row);

        pcrh_leave_curr_page(session, cursor); /** leave current page */

        slot++;
    }

    cursor->chain_count = (uint8)slot;

    if (column_count != entity->column_count) {
        heap_reorganize_chain_row(session, cursor, &ra, column_count);
    }
    row_end(&ra);

    return GS_SUCCESS;
}

/*
 * PCR fetch link row
 * @param kernel session, kernel cursor, query scn
 */
static status_t pcrh_fetch_link_row(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn)
{
    /* for temp CR page, cursor row should point to cursor row buffer */
    cursor->chain_count = 1;
    cursor->row = (row_head_t *)cursor->buf;

    if (pcrh_enter_cr_page(session, cursor, query_scn, cursor->link_rid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    heap_page_t *page = pcrh_get_curr_page(session, cursor);
    if (cursor->link_rid.slot >= page->dirs) {
        pcrh_leave_curr_page(session, cursor);
        GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return GS_ERROR;
    }

    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)cursor->link_rid.slot);
    if (PCRH_DIR_IS_FREE(dir)) {
        pcrh_leave_curr_page(session, cursor);
        GS_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return GS_ERROR;
    }

    row_head_t *row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_migr == 1, "the row is not migr, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);
    rowid_t next_rid = *PCRH_NEXT_ROWID(row);
    bool32 is_csf = row->is_csf;
    if (IS_INVALID_ROWID(next_rid)) {
        /* we should copy current row to cursor row buffer */
        errno_t ret = memcpy_sp(cursor->row, DEFAULT_PAGE_SIZE, row, row->size);
        knl_securec_check(ret);
        pcrh_leave_curr_page(session, cursor);
        return GS_SUCCESS;
    }

    if (knl_cursor_use_vm(session, cursor, GS_TRUE) != GS_SUCCESS) {
        pcrh_leave_curr_page(session, cursor);
        return GS_ERROR;
    }

    if (cursor->isolevel != (uint8)ISOLATION_CURR_COMMITTED) {
        /* current page would be release during chain rows fetch */
        if (pcrh_fetch_chain_rows(session, cursor, query_scn, row) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        pcrh_leave_curr_page(session, cursor);
        /* when isolation level is current committed, entity may be invalid during fetching rows, column count of 
         * entity may be less the column count of row in cr page (eg :select and add column concurrently).we need get 
         * the actual column count in row to init row and decode row. 
         */
        if (pcrh_fetch_cc_chain_rows(session, cursor, query_scn, is_csf) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

/*
 * PCR fetch CR page
 * in current committed isolation, we update query scn when constructing a CR page
 * @param kernel session, kernel cursor, is_found(output)
 */
static status_t pcrh_fetch_cr_page(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_found)
{
    heap_page_t *page = NULL;

    if (heap_cached_invalid(session, cursor)) {
        if (pcrh_prefetch_cr_page(session, cursor, cursor->query_scn, GET_ROWID_PAGE(cursor->rowid),
                                  cursor->page_buf, NULL) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    cursor->page_cache = LOCAL_PAGE_CACHE;
    page = (heap_page_t *)cursor->page_buf;

    if (pcrh_scan_cr_page(session, cursor, cursor->query_scn, page, is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*is_found && !IS_INVALID_ROWID(cursor->link_rid)) {
        if (pcrh_fetch_link_row(session, cursor, cursor->query_scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
 * PCR alloc new itl
 * @attention when alloc a new itl, memset it to zero, so we can generate itl undo directly
 * @param kernel session, heap page
 */
uint8 pcrh_new_itl(knl_session_t *session, heap_page_t *page)
{
    char *src = NULL;
    char *dst = NULL;
    uint8 itl_id;
    errno_t ret;

    if (page->itls == GS_MAX_TRANS || page->free_size < sizeof(pcr_itl_t)) {
        return GS_INVALID_ID8;
    }

    if (page->free_begin + sizeof(pcr_itl_t) > page->free_end) {
        pcrh_compact_page(session, page);
    }

    src = (char *)page + page->free_end;
    dst = src - sizeof(pcr_itl_t);

    if (page->dirs > 0) {
        ret = memmove_s(dst, page->dirs * sizeof(pcr_row_dir_t), src, page->dirs * sizeof(pcr_row_dir_t));
        knl_securec_check(ret);
    }

    *(pcr_itl_t *)(dst + page->dirs * sizeof(pcr_row_dir_t)) = g_init_pcr_itl;

    itl_id = page->itls;
    page->itls++;
    /* free_end is larger than free_size, free size is larger than sizeof(pcr_itl_t) */
    page->free_end -= sizeof(pcr_itl_t);
    page->free_size -= sizeof(pcr_itl_t);

    return itl_id;
}

/*
 * disconnect the relationship between itl an its rows, and
 * try to refresh the page ow_scn, to keep tracking the commit scn
 */
void pcrh_reuse_itl(knl_session_t *session, heap_page_t *page, pcr_itl_t *itl, uint8 itl_id)
{
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    uint16 i;

    for (i = 0; i < page->dirs; i++) {
        dir = pcrh_get_dir(page, i);
        if (PCRH_DIR_IS_FREE(dir)) {
            continue;
        }

        row = PCRH_GET_ROW(page, dir);
        if (ROW_ITL_ID(row) != itl_id) {
            continue;
        }

        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
        if (!row->is_changed) {
            row->is_changed = 1;
            continue;
        }

        if (row->is_deleted) {
            /*
             * free_size less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
             * the sum is less than max value(65535) of uint16.
             */
            page->free_size += sizeof(row_head_t);
            *dir = page->first_free_dir | PCRH_DIR_FREE_MASK;
            page->first_free_dir = i;
        }
    }
}

/*
 * generate undo for PCR heap itl
 * @param kernel session, kernel cursor, heap page, itl, undo
 */
static void pcrh_generate_itl_undo(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                   pcr_itl_t *itl, undo_data_t *undo)
{
    pcrh_undo_itl_t undo_itl;

    undo->snapshot.scn = itl->scn;
    undo->snapshot.is_owscn = itl->is_owscn;
    undo->snapshot.undo_page = itl->undo_page;
    undo->snapshot.undo_slot = itl->undo_slot;
    undo->snapshot.is_xfirst = GS_TRUE;

    undo_itl.xid = itl->xid;
    undo_itl.part_loc = cursor->part_loc;
    undo->size = sizeof(pcrh_undo_itl_t);
    undo->data = (char *)&undo_itl;

    undo->type = UNDO_PCRH_ITL;
    undo->rowid.file = AS_PAGID_PTR(page->head.id)->file;
    undo->rowid.page = AS_PAGID_PTR(page->head.id)->page;
    undo->rowid.slot = session->itl_id;
    /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
    undo->ssn = (uint32)cursor->ssn;

    undo_write(session, undo, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type));
}

/*
 * reset row self changed flag
 * This is necessary to distinguish the different row in same
 * transaction, because we forbid row self changed in same statement.
 * @param kernel session, heap page, itl_id
 */
void pcrh_reset_self_changed(knl_session_t *session, heap_page_t *page, uint8 itl_id)
{
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    uint16 i;

    for (i = 0; i < page->dirs; i++) {
        dir = pcrh_get_dir(page, i);
        if (PCRH_DIR_IS_FREE(dir)) {
            continue;
        }

        row = PCRH_GET_ROW(page, dir);
        if (ROW_ITL_ID(row) != itl_id) {
            continue;
        }

        row->self_chg = 0;
    }
}

static status_t pcrh_get_reusable_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                      pcr_itl_t **itl, bool32 *changed)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    pcr_itl_t *item = NULL;
    txn_info_t txn_info;
    uint8 i, owner_list;
    rd_pcrh_clean_itl_t rd_clean;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    session->change_list = 0;

    for (i = 0; i < page->itls; i++) {
        item = pcrh_get_itl(page, i);
        if (item->xid.value == session->rm->xid.value) {
            knl_panic_log(item->is_active, "current itl is inactive, panic info: page %u-%u type %u table %s",
                cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);
            session->itl_id = i;  // itl already exists
            *itl = item;

            if (item->ssn != cursor->ssn) {
                /* new statement, reset all changed rows in page */
                pcrh_reset_self_changed(session, page, i);
                if (cursor->logging && need_redo) {
                    log_put(session, RD_PCRH_RESET_SELF_CHANGE, &i, sizeof(uint8), LOG_ENTRY_FLAG_NONE);
                }
            }
            return GS_SUCCESS;
        }

        if (!item->is_active) {
            /* find the oldest itl to reuse */
            if (*itl == NULL || item->scn < (*itl)->scn) {
                session->itl_id = i;
                *itl = item;
            }
            continue;
        }

        tx_get_pcr_itl_info(session, GS_FALSE, item, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            continue;
        }

        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < txn_info.scn) {
            GS_THROW_ERROR(ERR_SERIALIZE_ACCESS);
            return GS_ERROR;
        }

        rd_clean.itl_id = i;
        rd_clean.scn = txn_info.scn;
        rd_clean.is_owscn = (uint8)txn_info.is_owscn;
        rd_clean.is_fast = 1;
        rd_clean.aligned = 0;
        pcrh_clean_itl(session, page, &rd_clean);
        if (cursor->logging && need_redo) {
            log_put(session, RD_PCRH_CLEAN_ITL, &rd_clean, sizeof(rd_pcrh_clean_itl_t), LOG_ENTRY_FLAG_NONE);
        }
        *changed = GS_TRUE;

        if (*itl == NULL || item->scn < (*itl)->scn) {
            session->itl_id = i;
            *itl = item;
        }

        owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
        session->change_list = owner_list - (uint8)page->map.list_id;
    }

    return GS_SUCCESS;
}

static void pcrh_init_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
    pcr_itl_t **itl, bool32 *changed)
{
    undo_data_t undo;
    rd_pcrh_reuse_itl_t rd_reuse;
    rd_pcrh_new_itl_t rd_new;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    if (*itl == NULL) {
        session->itl_id = pcrh_new_itl(session, page);
        if (session->itl_id == GS_INVALID_ID8) {
            return;
        }

        *itl = pcrh_get_itl(page, session->itl_id);
        /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
        rd_new.ssn = (uint32)cursor->ssn;
        rd_new.xid = session->rm->xid;
        rd_new.undo_rid = undo_page_info->undo_rid;

        if (cursor->logging) {
            pcrh_generate_itl_undo(session, cursor, page, *itl, &undo);
            tx_init_pcr_itl(session, *itl, &rd_new.undo_rid, rd_new.xid, rd_new.ssn);
            if (need_redo) {
                log_put(session, RD_PCRH_NEW_ITL, &rd_new, sizeof(rd_pcrh_new_itl_t), LOG_ENTRY_FLAG_NONE);
            }
        } else {
            tx_init_pcr_itl(session, *itl, &rd_new.undo_rid, rd_new.xid, rd_new.ssn);
        }
    } else {
        pcrh_reuse_itl(session, page, *itl, session->itl_id);

        rd_reuse.ssn = (uint32)cursor->ssn;
        rd_reuse.xid = session->rm->xid;
        rd_reuse.undo_rid = undo_page_info->undo_rid;
        rd_reuse.itl_id = session->itl_id;

        if (cursor->logging) {
            pcrh_generate_itl_undo(session, cursor, page, *itl, &undo);
            tx_init_pcr_itl(session, *itl, &rd_reuse.undo_rid, rd_reuse.xid, rd_reuse.ssn);
            if (need_redo) {
                log_put(session, RD_PCRH_REUSE_ITL, &rd_reuse, sizeof(rd_pcrh_reuse_itl_t), LOG_ENTRY_FLAG_NONE);
            }
        } else {
            tx_init_pcr_itl(session, *itl, &rd_reuse.undo_rid, rd_reuse.xid, rd_reuse.ssn);
        }
    }

    *changed = GS_TRUE;
}

/*
 * reuse an oldest itl or alloc a new itl for caller.
 * caller should reserved enough undo space for undo itl
 */
static status_t pcrh_alloc_itl(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                               pcr_itl_t **itl, bool32 *changed)
{
    *changed = GS_FALSE;
    *itl = NULL;
    session->itl_id = GS_INVALID_ID8;

    if (pcrh_get_reusable_itl(session, cursor, page, itl, changed) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (*itl != NULL && (*itl)->xid.value == session->rm->xid.value) {
        return GS_SUCCESS;
    }

    pcrh_init_itl(session, cursor, page, itl, changed);

    if (session->itl_id == GS_INVALID_ID8) {
        return GS_SUCCESS;
    }

    if (DB_NOT_READY(session)) {
        (*itl)->is_active = 0;
        return GS_SUCCESS;
    }

    knl_panic_log(!DB_IS_READONLY(session), "current DB is readonly, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);

    knl_part_locate_t part_loc;
    if (IS_PART_TABLE(cursor->table)) {
        part_loc.part_no = cursor->part_loc.part_no;
        part_loc.subpart_no = cursor->part_loc.subpart_no;
    } else {
        part_loc.part_no = GS_INVALID_ID24;
        part_loc.subpart_no = GS_INVALID_ID32;
    }

    if (lock_itl(session, *AS_PAGID_PTR(page->head.id), session->itl_id, part_loc,
                 g_invalid_pagid, LOCK_TYPE_PCR_RX) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * PCR check locking row
 * 1. If there's active transaction on current row, try re-read the latest version later,
 * suppose most transactions are committed, set row changed status.
 * 2. If row changed by current transaction, do write consistency check to avoid row changed
 * by same cursor more than once later, set row lock status.
 * 3. If row deleted by other transaction, skip re-read the latest version, set row deleted status.
 * 4. If row changed by other transaction, re-read the latest version, set row changed status.
 * 5. If the current row is the row we just fetched, set row changed status.
 * @param kernel session, kernel cursor, heap page, lock row status, page changed
 */
static status_t pcrh_check_lock_row(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *page,
                                    lock_row_status_t *status, bool32 *changed)
{
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    uint8 itl_id;
    txn_info_t txn_info;

    *changed = GS_FALSE;

    dir = pcrh_get_dir(page, (uint16)cursor->rowid.slot);
    if (PCRH_DIR_IS_FREE(dir)) {
        *status = ROW_IS_DELETED;
        return GS_SUCCESS;
    }

    row = PCRH_GET_ROW(page, dir);
    itl_id = ROW_ITL_ID(row);
    if (itl_id != GS_INVALID_ID8) {
        itl = pcrh_get_itl(page, itl_id);
        if (itl->xid.value == session->rm->xid.value) {
            /*
             * We saw a visible version, and current is our migration row which
             * means the origin row has been deleted, and the dir is reused by
             * current transaction during update(because insert doesn't lock row
             * and delete doesn't alloc dir), so we treat it as deleted row.
             */
            if (row->is_migr) {
                *status = ROW_IS_DELETED;
                return GS_SUCCESS;
            }

            /* transaction has lock current page */
            if (itl->ssn != cursor->ssn) {
                /* new statement, reset all changed rows in page */
                pcrh_reset_self_changed(session, page, itl_id);
                if (IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
                    log_put(session, RD_PCRH_RESET_SELF_CHANGE, &itl_id, sizeof(uint8), LOG_ENTRY_FLAG_NONE);
                }
                *changed = GS_TRUE;
            }

            /*
             * If row is locked by current transaction without change before,
             * we should ensure that the cursor row is the latest version.
             * Make a rough comparison by comparing with page scn.
             */
            if (!row->self_chg && cursor->scn < page->scn) {
                *status = ROW_IS_CHANGED;
            } else {
                *status = ROW_IS_LOCKED;
            }
            return GS_SUCCESS;
        }

        tx_get_pcr_itl_info(session, GS_FALSE, itl, &txn_info);
        if (txn_info.status != (uint8)XACT_END) {
            session->wxid = itl->xid;
            ROWID_COPY(session->wrid, cursor->rowid);
            *status = ROW_IS_CHANGED;
            return GS_SUCCESS;
        }

        if (!row->is_changed) {
            txn_info.scn = page->scn;
        }
    } else {
        txn_info.scn = page->scn;
    }

    /* detect SSI conflict */
    if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < txn_info.scn) {
        GS_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return GS_ERROR;
    }

    if (row->is_deleted) {
        *status = ROW_IS_DELETED;
        return GS_SUCCESS;
    }

    /* row is changed, need re-read */
    if (cursor->scn < txn_info.scn) {
        *status = ROW_IS_CHANGED;
        return GS_SUCCESS;
    }

    *status = ROW_IS_LOCKABLE;
    return GS_SUCCESS;
}

/*
 * try clean the itl of locking row
 * We are trying to lock a row whose itl is still active, we should
 * do a fast clean on it before lock the row
 * @param kernel session, heap page, itl_id, need_redo
 */
static void pcrh_try_clean_itl(knl_session_t *session, heap_page_t *page, uint8 itl_id, bool32 need_redo)
{
    pcr_itl_t *itl = NULL;
    rd_pcrh_clean_itl_t rd_clean;
    txn_info_t txn_info;

    itl = pcrh_get_itl(page, itl_id);
    if (!itl->is_active) {
        return;
    }

    tx_get_pcr_itl_info(session, GS_FALSE, itl, &txn_info);

    rd_clean.itl_id = itl_id;
    rd_clean.scn = txn_info.scn;
    rd_clean.is_owscn = (uint8)txn_info.is_owscn;
    rd_clean.is_fast = 1;
    rd_clean.aligned = 0;
    pcrh_clean_itl(session, page, &rd_clean);

    if (need_redo) {
        log_put(session, RD_PCRH_CLEAN_ITL, &rd_clean, sizeof(rd_pcrh_clean_itl_t), LOG_ENTRY_FLAG_NONE);
    }
}

/*
 * PCR try lock heap row
 * @note this is the executor of lock row interface
 * Get the locking row status, if row is not lockable, just return.
 * Alloc an itl to lock current row, and if all itl are active, wait for page itl.
 * @attention migration row and chain rows are not locked here.
 * @param kernel session, kernel cursor, lock status(output)
 */
static status_t pcrh_try_lock_row(knl_session_t *session, knl_cursor_t *cursor,
                                  heap_t *heap, lock_row_status_t *status)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    uint8 owner_list;
    rd_pcrh_lock_row_t rd_lock;
    bool32 changed = GS_FALSE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    for (;;) {
        log_atomic_op_begin(session);

        buf_enter_page(session, GET_ROWID_PAGE(cursor->rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE;

        if (pcrh_check_lock_row(session, cursor, page, status, &changed) != GS_SUCCESS) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            return GS_ERROR;
        }

        if (*status != ROW_IS_LOCKABLE) {
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            return GS_SUCCESS;
        }

        if (pcrh_alloc_itl(session, cursor, page, &itl, &changed) != GS_SUCCESS) {
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            heap_try_change_map(session, heap, GET_ROWID_PAGE(cursor->rowid));
            return GS_ERROR;
        }

        if (itl == NULL) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            if (knl_begin_itl_waits(session, &heap->stat.itl_waits) != GS_SUCCESS) {
                knl_end_itl_waits(session);
                return GS_ERROR;
            }
            knl_end_itl_waits(session);
            continue;
        }
        break;
    }

    dir = pcrh_get_dir(page, (uint16)cursor->rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    if (ROW_ITL_ID(row) != GS_INVALID_ID8) {
        pcrh_try_clean_itl(session, page, ROW_ITL_ID(row), need_redo);
    }

    ROW_SET_ITL_ID(row, session->itl_id);
    row->is_changed = 0;
    row->self_chg = 0;

    rd_lock.slot = (uint16)cursor->rowid.slot;
    rd_lock.itl_id = session->itl_id;
    rd_lock.aligned = 0;
    if (need_redo) {
        log_put(session, RD_PCRH_LOCK_ROW, &rd_lock, sizeof(rd_pcrh_lock_row_t), LOG_ENTRY_FLAG_NONE);
    }

    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, GET_ROWID_PAGE(cursor->rowid));

    *status = ROW_IS_LOCKED;
    cursor->is_locked = GS_TRUE;
    return GS_SUCCESS;
}

static inline bool32 pcrh_check_visible_with_itl(knl_session_t *session, knl_cursor_t *cursor,
    heap_page_t *cr_page, undo_row_t *ud_row, pcr_itl_t *itl)
{
    /* no need to check the same transaction, this code may be not necessary */
    if (ud_row->xid.value == cursor->xid && ud_row->ssn < cursor->ssn) {
        itl->ssn = ud_row->ssn;
        return GS_FALSE;
    }

    if (ud_row->type == UNDO_PCRH_ITL) {
        pcrh_revert_itl(session, cr_page, itl, ud_row);
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t pcrh_check_visible_with_udrow(knl_session_t *session, knl_cursor_t *cursor,
    undo_row_t *ud_row, bool32 check_restart, bool32 *is_found)
{
    if (check_restart) {
        if (ud_row->type == UNDO_PCRH_COMPACT_DELETE && IS_SAME_ROWID(ud_row->rowid, cursor->rowid)) {
            GS_THROW_ERROR(ERR_NEED_RESTART);
            return GS_ERROR;
        }

        return GS_SUCCESS;
    }

    /* current row is not visible, don't do following check */
    if (ud_row->type == UNDO_PCRH_INSERT && IS_SAME_ROWID(ud_row->rowid, cursor->rowid)) {
        *is_found = GS_FALSE;
        return GS_SUCCESS;
    }

    if (ud_row->type != UNDO_PCRH_BATCH_INSERT) {
        return GS_SUCCESS;
    }

    pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)ud_row->data;
    for (int32 i = batch_undo->count - 1; i >= 0; i--) {
        if (cursor->rowid.slot == batch_undo->undos[i].slot) {
            *is_found = GS_FALSE;
            return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

/*
 * PCR check visible with undo snapshot
 * @note check the row we just read in current committed mode are the row we wants
 * or which has been deleted and inserted. This is necessary to keep consistent read
 * in read committed isolation level.
 * @param kernel session, kernel cursor, CR page, itl, is_found(output)
 */
static status_t pcrh_check_visible_with_udss(knl_session_t *session, knl_cursor_t *cursor, heap_page_t *cr_page,
    pcr_itl_t *itl, bool32 check_restart, bool32 *is_found)
{
    itl->is_hist = GS_TRUE;
    if (!itl->is_active) {
        itl->is_active = GS_TRUE;
        itl->is_owscn = GS_FALSE;
        itl->fsc = 0;
    }

    for (;;) {
        if (buf_read_page(session, PAGID_U2N(itl->undo_page), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            return GS_ERROR;
        }

        undo_page_t *ud_page = (undo_page_t *)CURR_PAGE;
        if (itl->undo_slot >= ud_page->rows) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot slot %u, undo rows %u, "
                "query scn %llu, check_restart %u", (uint32)itl->undo_slot,
                (uint32)ud_page->rows, cursor->query_scn, (uint32)check_restart);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        undo_row_t *ud_row = UNDO_ROW(ud_page, itl->undo_slot);
        if (itl->xid.value != ud_row->xid.value) {
            buf_leave_page(session, GS_FALSE);
            tx_record_sql(session);
            GS_LOG_RUN_ERR("snapshot too old, detail: snapshot xid %llu, undo row xid %llu, "
                "query scn %llu, check_restart %u", itl->xid.value, ud_row->xid.value,
                cursor->query_scn, (uint32)check_restart);
            GS_THROW_ERROR(ERR_SNAPSHOT_TOO_OLD);
            return GS_ERROR;
        }

        if (!pcrh_check_visible_with_itl(session, cursor, cr_page, ud_row, itl)) {
            buf_leave_page(session, GS_FALSE);
            return GS_SUCCESS;
        }

        itl->ssn = ud_row->ssn;
        itl->undo_page = ud_row->prev_page;
        itl->undo_slot = ud_row->prev_slot;

        if (pcrh_check_visible_with_udrow(session, cursor, ud_row, check_restart, is_found) != GS_SUCCESS) {
            buf_leave_page(session, GS_FALSE);
            return GS_ERROR;
        }
        buf_leave_page(session, GS_FALSE);

        if (!(*is_found)) {
            return GS_SUCCESS;
        }
    }
}

/*
 * PCR check current visible
 * @note check current row is the row we are reading or not.
 * this would be called when are re-reading in current read when concurrent update/delete happens
 * @param kernel session, kernel cursor, CR page, is_found(output)
 */
static status_t pcrh_check_current_visible(knl_session_t *session, knl_cursor_t *cursor,
                                           heap_page_t *cr_page, bool32 check_restart, bool32 *is_found)
{
    pcr_itl_t *itl = NULL;
    bool8 cleanout = GS_FALSE;

    for (;;) {
        if (pcrh_get_invisible_itl(session, cursor, cursor->query_scn, cr_page, &itl, &cleanout) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (itl == NULL) {
            /* all itls have been checked read consistency */
            return GS_SUCCESS;
        }

        // We treat it as invisible transaction because it's unnecessary to wait prepared transaction here.
        if (session->wxid.value != GS_INVALID_ID64) {
            session->wxid.value = GS_INVALID_ID64;
        }

        if (pcrh_check_visible_with_udss(session, cursor, cr_page, itl, check_restart, is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (check_restart) {
            continue;
        }

        if (!*is_found) {
            /* visible row has been deleted */
            return GS_SUCCESS;
        }
    }
}

/*
 * PCR read by given rowid
 * @note support read current committed, serialize read, read committed
 * In this function we should push a temp CR page to do following work, because
 * we could not use the second cursor buffer when doing index fetch.
 * @param kernel session, kernel cursor, query_scn, isolation level, is_found(output)
 */
static status_t pcrh_read_by_rowid(knl_session_t *session, knl_cursor_t *cursor, knl_scn_t query_scn,
                                   isolation_level_t isolevel, bool32 *is_found)
{
    heap_page_t *page = NULL;
    heap_page_t *temp_page = NULL;
    errno_t ret;

    cursor->chain_count = 0;
    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);

    if (pcrh_enter_cr_page(session, cursor, query_scn, cursor->rowid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    page = pcrh_get_curr_page(session, cursor);
    if (cursor->rowid.slot >= page->dirs) {
        pcrh_leave_curr_page(session, cursor);
        GS_THROW_ERROR(ERR_INVALID_ROWID);
        return GS_ERROR;
    }

    if (!pcrh_get_row(session, cursor, query_scn, page)) {
        pcrh_leave_curr_page(session, cursor);
        *is_found = GS_FALSE;
        return GS_SUCCESS;
    }

    *is_found = GS_TRUE;

    if (isolevel == (uint8)ISOLATION_CURR_COMMITTED &&
        cursor->isolevel != (uint8)ISOLATION_SERIALIZABLE &&
        cursor->scn > cursor->query_scn) {
        /*
         * We cannot check current visible on current page or current global CR page,
         * so, alloc a temp page to this check.
         */
        temp_page = (heap_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE);
        ret = memcpy_sp((char *)temp_page, DEFAULT_PAGE_SIZE, page, DEFAULT_PAGE_SIZE);
        knl_securec_check(ret);
        pcrh_leave_curr_page(session, cursor);

        if (pcrh_check_current_visible(session, cursor, temp_page, GS_FALSE, is_found) != GS_SUCCESS) {
            cm_pop(session->stack);
            return GS_ERROR;
        }

        cm_pop(session->stack);

        if (!*is_found) {
            return GS_SUCCESS;
        }
    } else {
        pcrh_leave_curr_page(session, cursor);
    }

    if (!IS_INVALID_ROWID(cursor->link_rid)) {
        if (pcrh_fetch_link_row(session, cursor, query_scn) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t pcrh_prepare_lock_row(knl_session_t *session, knl_cursor_t *cursor)
{
    if (knl_cursor_ssi_conflict(cursor, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (lock_table_shared(session, cursor->dc_entity, LOCK_INF_WAIT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (undo_prepare(session, MAX_ITL_UNDO_SIZE, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t pcrh_check_restart(knl_session_t *session, knl_cursor_t *cursor)
{
    bool32 is_found = GS_TRUE;
    heap_t *heap = CURSOR_HEAP(cursor);
    heap_segment_t *segment = HEAP_SEGMENT(heap->entry, heap->segment);

    if (heap->ashrink_stat == ASHRINK_WAIT_SHRINK && cursor->query_scn >= segment->shrinkable_scn) {
        return GS_SUCCESS;
    }

    if (cursor->for_update_fetch) {
        GS_LOG_DEBUG_INF("select for update checked when shrink table");
        return GS_SUCCESS;
    }

    cursor->chain_count = 0;
    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);
    if (pcrh_enter_cr_page(session, cursor, DB_CURR_SCN(session), cursor->rowid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    heap_page_t *page = pcrh_get_curr_page(session, cursor);
    if (cursor->rowid.slot >= page->dirs) {
        pcrh_leave_curr_page(session, cursor);
        GS_THROW_ERROR(ERR_INVALID_ROWID);
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    heap_page_t *temp_page = (heap_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE);
    errno_t ret = memcpy_sp((char *)temp_page, DEFAULT_PAGE_SIZE, page, DEFAULT_PAGE_SIZE);
    knl_securec_check(ret);
    pcrh_leave_curr_page(session, cursor);

    if (pcrh_check_current_visible(session, cursor, temp_page, GS_TRUE, &is_found) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static inline status_t pcrh_try_check_restart(knl_session_t *session, knl_cursor_t *cursor,
    heap_t *heap, table_t *table, bool32 is_deleted)
{
    if (SECUREC_UNLIKELY(ASHRINK_HEAP(table, heap)
        && is_deleted && !session->compacting)) {
        if (pcrh_check_restart(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
 * PCR lock heap row interface
 * @note lock the specified row, before we lock the row, we should
 * do SSI conflict check in serialize isolation.
 * We may temporarily enter the current committed mode to read the latest
 * row version to lock it.
 * @param kernel session, kernel cursor, is_locked(output)
 */
status_t pcrh_lock_row(knl_session_t *session, knl_cursor_t *cursor, bool32 *is_locked)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    table_t *table = (table_t *)cursor->table;
    lock_row_status_t status;
    bool32 is_skipped = GS_FALSE;
    bool32 is_found = GS_FALSE;
    bool32 is_deleted = GS_FALSE;

    if (pcrh_prepare_lock_row(session, cursor) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (;;) {
        if (pcrh_try_lock_row(session, cursor, heap, &status) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (status != ROW_IS_CHANGED) {
            is_deleted = (bool32)(status == ROW_IS_DELETED);
            break;
        }

        if (session->wxid.value != GS_INVALID_ID64) {
            if (heap_try_tx_wait(session, cursor, &is_skipped) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (is_skipped) {
                break;
            }
        }

        /* try read the latest committed row version */
        if (pcrh_read_by_rowid(session, cursor, DB_CURR_SCN(session),
                               ISOLATION_CURR_COMMITTED, &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!is_found) {
            is_deleted = GS_TRUE;
            break;
        }

        if (knl_match_cond(session, cursor, &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!is_found) {
            break;
        }
    }

    *is_locked = (status == ROW_IS_LOCKED);
    if (!*is_locked && cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE) {
        GS_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return GS_ERROR;
    }

    return pcrh_try_check_restart(session, cursor, heap, table, is_deleted);
}

/*
 * PCR fetch row by rowid
 * @param kernel session, kernel cursor, is_found(output)
 */
status_t pcrh_fetch_by_rowid(knl_session_t *session, knl_cursor_t *cursor)
{
    cursor->ssi_conflict = GS_FALSE;
    if (pcrh_read_by_rowid(session, cursor, cursor->query_scn, cursor->isolevel, &cursor->is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->is_found) {
        return GS_SUCCESS;
    }

    if (knl_match_cond(session, cursor, &cursor->is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->is_found || cursor->action <= CURSOR_ACTION_SELECT) {
        return GS_SUCCESS;
    }

    if (pcrh_lock_row(session, cursor, &cursor->is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * PCR rowid scan fetch interface
 * @param kernel session, kernel cursor
 */
status_t pcrh_rowid_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    for (;;) {
        if (cursor->rowid_no == cursor->rowid_count) {
            cursor->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        ROWID_COPY(cursor->rowid, cursor->rowid_array[cursor->rowid_no]);
        cursor->rowid_no++;

        if (!spc_validate_page_id((knl_session_t *)session, GET_ROWID_PAGE(cursor->rowid))) {
            continue;
        }

        if (IS_DUAL_TABLE((table_t *)cursor->table)) {
            cursor->rowid.slot = INVALID_SLOT;
            return dual_fetch((knl_session_t *)session, cursor);
        }

        if (cursor->isolevel == ISOLATION_CURR_COMMITTED) {
            cursor->query_scn = DB_CURR_SCN((knl_session_t *)session);
            cursor->cc_cache_time = KNL_NOW((knl_session_t *)session);
        }

        if (pcrh_fetch_by_rowid((knl_session_t *)session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->is_found) {
            return GS_SUCCESS;
        }
    }
}

/*
 * PCR heap fetch interface
 * @param kernel session handle, kernel cursor
 */
status_t pcrh_fetch(knl_handle_t handle, knl_cursor_t *cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    rowid_t row_id;
    heap_t *heap = NULL;
    seg_stat_t temp_stat;
    status_t status;

    knl_panic_log(cursor->is_valid, "current cursor is invalid, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    if (IS_DUAL_TABLE((table_t *)cursor->table)) {
        return dual_fetch(session, cursor);
    }

    status = GS_SUCCESS;
    heap = CURSOR_HEAP(cursor);
    SEG_STATS_INIT(session, &temp_stat);
    
    for (;;) {
        if (IS_INVALID_ROWID(cursor->rowid)) {
            cursor->is_found = GS_FALSE;
            cursor->eof = GS_TRUE;
            return GS_SUCCESS;
        }

        row_id = cursor->rowid;
        if (pcrh_fetch_cr_page(session, cursor, &cursor->is_found) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (!IS_SAME_PAGID_BY_ROWID(row_id, cursor->rowid)) {
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

            if (cursor->cleanout) {
                heap_cleanout_page(session, cursor, GET_ROWID_PAGE(row_id), GS_TRUE);
            }
        }

        if (!cursor->is_found) {
            continue;
        }

        if (knl_match_cond(session, cursor, &cursor->is_found) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (!cursor->is_found) {
            continue;
        }

        if (cursor->action <= CURSOR_ACTION_SELECT) {
            break;
        }

        if (pcrh_lock_row(session, cursor, &cursor->is_found) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }

        if (cursor->is_found) {
            break;
        }
    }

    SEG_STATS_RECORD(session, temp_stat, &heap->stat);

    return status;
}

/*
 * PCR calculate insert row cost size
 * @param kernel session, heap segment, insert row
 */
uint32 pcrh_calc_insert_cost(knl_session_t *session, heap_segment_t *segment, uint16 row_size)
{
    uint32 cost_size;
    space_t *space = SPACE_GET(segment->space_id);

    cost_size = sizeof(pcr_itl_t) + sizeof(pcr_row_dir_t);

    if (row_size + segment->list_range[1] < (uint16)PCRH_MAX_ROW_SIZE - space->ctrl->cipher_reserve_size) {
        cost_size += row_size + segment->list_range[1];
    } else {
        cost_size += PCRH_MAX_ROW_SIZE - space->ctrl->cipher_reserve_size;
    }

    return cost_size;
}

/*
 * PCR insert row into heap page
 * @note insert the given row into the specified heap page, insert undo
 * is recorded on itl for PCR.
 * @param kernel session, heap page, row, undo data, insert redo, insert slot(output)
 */
void pcrh_insert_into_page(knl_session_t *session, heap_page_t *page, row_head_t *row,
                           undo_data_t *undo, rd_pcrh_insert_t *rd, uint16 *slot)
{
    pcr_itl_t *itl = NULL;
    pcr_row_dir_t *dir = NULL;
    char *row_addr = NULL;
    errno_t ret;

    if (page->free_begin + row->size + sizeof(pcr_row_dir_t) > page->free_end) {
        pcrh_compact_page(session, page);
    }

    if (page->first_free_dir == PCRH_NO_FREE_DIR || rd->new_dir) {
        *slot = page->dirs;
        page->dirs++;
        dir = pcrh_get_dir(page, *slot);

        /* alloc of directory must use page free size */
        /* free size is larger than sizeof(pcr_row_dir_t), free_end is larger than free_size */
        page->free_end -= sizeof(pcr_row_dir_t);
        page->free_size -= sizeof(pcr_row_dir_t);
        undo->snapshot.is_xfirst = GS_TRUE;
    } else {
        *slot = page->first_free_dir;
        dir = pcrh_get_dir(page, *slot);
        page->first_free_dir = PCRH_NEXT_FREE_DIR(dir);
        undo->snapshot.is_xfirst = PCRH_DIR_IS_NEW(dir);
    }

    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    undo->snapshot.undo_page = itl->undo_page;
    undo->snapshot.undo_slot = itl->undo_slot;
    undo->snapshot.scn = DB_CURR_SCN(session);
    undo->snapshot.is_owscn = GS_FALSE;

    itl->undo_page = rd->undo_page;
    itl->undo_slot = rd->undo_slot;
    itl->ssn = rd->ssn;

    *dir = page->free_begin;
    row->is_changed = 1;
    row->self_chg = 1;
    row_addr = (char *)page + *dir;
    ret = memcpy_sp(row_addr, page->free_end - *dir, row, row->size);
    knl_securec_check(ret);

    /*
     * free_begin less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
     * the sum is less than max value(65535) of uint16.
     */
    page->free_begin += row->size;

    if (itl->fsc >= row->size) {
        itl->fsc -= row->size;
    } else {
        /* free_size is larger than row->size */
        page->free_size -= (row->size - itl->fsc);
        itl->fsc = 0;
    }

    page->rows++;
}

/*
 * PCR enter insert page
 * @note find a heap page from map tree to insert the specified row
 * We lazy init the page itl here if it's a new page.
 * @attention caller should reserved enough undo for alloc itl.
 * @param kernel session kernel cursor, row cost size, page_id(output)
 */
static status_t pcrh_enter_insert_page(knl_session_t *session, knl_cursor_t *cursor,
                                       row_head_t *row, page_id_t *page_id)
{
    heap_t *heap;
    heap_segment_t *segment;
    pcr_itl_t *itl = NULL;
    heap_page_t *page = NULL;
    bool32 appendonly;
    bool32 use_cached;
    uint8 owner_list;
    uint32 maxtrans;
    bool32 changed = GS_FALSE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    bool32 degrade_mid = GS_FALSE;
    uint8 mid;
    uint32 cost_size;

    use_cached = GS_TRUE;
    heap = CURSOR_HEAP(cursor);
    segment = HEAP_SEGMENT(heap->entry, heap->segment);
    appendonly = heap_use_appendonly(session, cursor, segment);

    cost_size = pcrh_calc_insert_cost(session, segment, row->size);
    // list id range is [0, HEAP_FREE_LIST_COUNT-1(5)]
    mid = (uint8)heap_get_target_list(session, segment, cost_size);

    for (;;) {
        if (appendonly) {
            if (heap_find_appendonly_page(session, heap, cost_size, page_id) != GS_SUCCESS) {
                knl_end_itl_waits(session);
                GS_THROW_ERROR(ERR_FIND_FREE_SPACE, cost_size);
                return GS_ERROR;
            }
        } else {
            if (heap_find_free_page(session, heap, mid, use_cached, page_id, &degrade_mid) != GS_SUCCESS) {
                knl_end_itl_waits(session);
                GS_THROW_ERROR(ERR_FIND_FREE_SPACE, cost_size);
                return GS_ERROR;
            }
        }

        log_atomic_op_begin(session);

        if (buf_read_page(session, *page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            return GS_ERROR;
        }
        page = (heap_page_t *)CURR_PAGE;

        /* if the page is not heap page, we should skip it and try again */
        if (page->head.type != PAGE_TYPE_PCRH_DATA) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            heap_remove_cached_page(session, appendonly);
            use_cached = GS_FALSE;
            continue;
        }

        knl_panic_log(page->oid == segment->oid && page->uid == segment->uid && page->org_scn == segment->org_scn &&
                      page->seg_scn == segment->seg_scn, "the oid/uid/org_scn/seg_scn of page and segment are not "
                      "equal, panic info: page %u-%u type %u table %s page_oid %u seg_oid %u page_uid %u seg_uid %u",
                      cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name,
                      page->oid, segment->oid, page->uid, segment->uid);

        if (page->free_size < cost_size
            && !(page->rows == 0 && page->free_size >= row->size + sizeof(pcr_itl_t) + sizeof(pcr_row_dir_t))) {
            owner_list = heap_get_owner_list(session, segment, page->free_size);
            session->change_list = owner_list - (uint8)page->map.list_id;
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            if (degrade_mid && (owner_list == mid - 1)) {
                heap_degrade_change_map(session, heap, *page_id, owner_list - 1);
            } else {
                heap_try_change_map(session, heap, *page_id);
            }

            heap_remove_cached_page(session, appendonly);
            use_cached = GS_FALSE;
            continue;
        }

        if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < page->scn) {
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            GS_THROW_ERROR(ERR_SERIALIZE_ACCESS);
            return GS_ERROR;
        }

        if (page->itls == 0) {
            maxtrans = (page->free_size - cost_size) / sizeof(pcr_itl_t);
            page->itls = (maxtrans < segment->initrans) ? maxtrans : segment->initrans;
            /*
             * free_size is larger than page->itls * sizeof(pcr_itl_t) in empty page,
             * free_end larger than free_size
             */
            page->free_end -= page->itls * sizeof(pcr_itl_t);
            page->free_size -= page->itls * sizeof(pcr_itl_t);
            if (cursor->logging && need_redo) {
                log_put(session, RD_PCRH_INIT_ITLS, &page->itls, sizeof(uint32), LOG_ENTRY_FLAG_NONE);
            }
        }

        if (pcrh_alloc_itl(session, cursor, page, &itl, &changed) != GS_SUCCESS) {
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            heap_try_change_map(session, heap, *page_id);
            return GS_ERROR;
        }

        if (itl == NULL) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);

            if (knl_begin_itl_waits(session, &heap->stat.itl_waits) != GS_SUCCESS) {
                knl_end_itl_waits(session);
                return GS_ERROR;
            }
            use_cached = GS_FALSE;
            continue;
        }

        knl_end_itl_waits(session);
        return GS_SUCCESS;
    }
}

/*
 * PCR insert heap row
 * @note insert a given row into the heap, return the rowid
 * @param kernel session, kernel cursor, heap, insert row, cost size,
 *        rowid(output), logic replication column start id
 */
static status_t pcrh_simple_insert(knl_session_t *session, knl_cursor_t *cursor, heap_t *heap, row_head_t *row,
                                   rowid_t *rowid, uint16 col_start)
{
    heap_page_t *page = NULL;
    page_id_t page_id;
    rd_pcrh_insert_t rd;
    undo_data_t undo;
    uint8 owner_list;
    uint16 slot;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc)
        && (!row->is_link);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);

    *rowid = INVALID_ROWID;

    /* We prepare two undo rows (itl undo and insert undo) */
    if (cursor->logging) {
        if (undo_multi_prepare(session, PCRH_INSERT_UNDO_COUNT, MAX_ITL_UNDO_SIZE,
                               IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (pcrh_enter_insert_page(session, cursor, row, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    SET_ROWID_PAGE(rowid, page_id);
    page = (heap_page_t *)CURR_PAGE;

    ROW_SET_ITL_ID(row, session->itl_id);
    /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
    rd.ssn = (uint32)cursor->ssn;
    rd.undo_page = undo_page_info->undo_rid.page_id;
    rd.undo_slot = undo_page_info->undo_rid.slot;
    /* alloc new dir for cross update insert, otherwise,we can not judge if it is self updated row */
    rd.new_dir = (cursor->action == CURSOR_ACTION_UPDATE && !row->is_migr);
    rd.aligned = 0;

    pcrh_insert_into_page(session, page, row, &undo, &rd, &slot);
    rowid->slot = slot;

    if (cursor->logging) {
        undo.type = UNDO_PCRH_INSERT;
        undo.size = 0;
        undo.rowid = *rowid;
        /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
        undo.ssn = (uint32)cursor->ssn;
        undo_write(session, &undo, need_redo);

        if (need_redo) {
            log_encrypt_prepare(session, page->head.type, need_encrypt);
            log_put(session, RD_PCRH_INSERT, &rd, OFFSET_OF(rd_pcrh_insert_t, data), entry_flag);
            log_append_data(session, row, row->size);
            if (has_logic) {
                log_append_data(session, &col_start, sizeof(uint16));
            }
        }
    }

    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    heap_try_change_map(session, heap, page_id);

    return GS_SUCCESS;
}

/*
 * PCR calculate chain split border
 * @param kernel session, original row, lens, chain assist array
 */
static uint16 pcrh_calc_split_border(knl_session_t *session, knl_cursor_t *cursor, row_head_t *ori_row, uint16 *lens,
    row_chain_t *chain)
{
    row_assist_t ra;
    uint16 i, slot;
    uint16 cost_size, ex_size;
    uint16 col_count;
    knl_cal_col_size_t  calc_col_size_func = ori_row->is_csf ?
        heap_calc_csf_col_actualsize : heap_calc_bmp_col_actualsize;
    knl_calc_row_head_inc_size_t calc_row_head_inc_func = ori_row->is_csf ?
        heap_calc_csf_row_head_inc_size : heap_calc_bmp_row_head_inc_size;
    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;

    col_count = ROW_COLUMN_COUNT(ori_row);
    slot = 0;
    cost_size = 0;

    cm_attach_row(&ra, (char *)ori_row);

    ex_size = sizeof(pcr_itl_t) + sizeof(pcr_row_dir_t);

    for (i = 0; i < PCRH_INSERT_MAX_CHAIN_COUNT; i++) {
        chain[i].col_count = 0;
    }

    for (i = 0; i < col_count; i++) {
        if (chain[slot].col_count == 0) {
            cost_size = cm_row_init_size(ra.is_csf, 0) + sizeof(rowid_t);
            chain[slot].col_start = i;
        }

        cost_size += calc_col_size_func(ra.head, lens, i);
        cost_size += calc_row_head_inc_func(chain[slot].col_count + 1, chain[slot].col_count);
        if (CM_ALIGN4(cost_size) + ex_size > (uint16)PCRH_MAX_COST_SIZE - cipher_reserve_size) {
            i--;
            slot++;
            continue;
        } else {
            chain[slot].col_count++;
        }
    }

    return (uint16)(slot + 1);
}

/*
 * PCR init link row
 * @param kernel session, row assist, row buffer, next rowid
 */
static void pcrh_init_link_row(knl_session_t *session, row_assist_t *ra, char *buf, rowid_t next_rid)
{
    if (ra->is_csf) {
        csf_row_init(ra, buf, GS_MAX_ROW_SIZE, 1);
    } else {
        row_init(ra, buf, GS_MAX_ROW_SIZE, 1);
    }
    ROW_SET_ITL_ID(ra->head, GS_INVALID_ID8);
    ra->head->is_link = 1;

    *(rowid_t *)(buf + ra->head->size) = next_rid;
    ra->head->size = PCRH_MIN_ROW_SIZE;
}

/*
 * PCR insert chain rows
 * @note split origin row into several chain rows and do insert
 * @param kernel session, kernel cursor, heap, origin row, offsets,
 *        lens, next rowid, logic replication column start id
 */
static status_t pcrh_insert_chain_rows(knl_session_t *session, knl_cursor_t *cursor, heap_t *heap, row_head_t *ori_row,
                                       uint16 *offsets, uint16 *lens, rowid_t *next_rid, uint16 col_start)
{
    row_chain_t chains[PCRH_INSERT_MAX_CHAIN_COUNT];
    row_chain_t *chain;
    row_assist_t ra;
    row_head_t *migr_row = NULL;
    int32 i;
    uint16 j, col_id;
    uint8 chain_count;
    knl_put_row_column_t put_col_func = ori_row->is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;
    ra.is_csf = ori_row->is_csf;

    chain = (cursor->action == CURSOR_ACTION_INSERT) ? (row_chain_t *)cursor->chain_info : chains;

    *next_rid = (ori_row->is_migr) ? *PCRH_NEXT_ROWID(ori_row) : INVALID_ROWID;
    migr_row = (row_head_t *)cm_push(session->stack, PCRH_MAX_MIGR_SIZE);

    chain_count = (uint8)pcrh_calc_split_border(session, cursor, ori_row, lens, chain);

    for (i = chain_count - 1; i >= 0; i--) {
        pcrh_init_migr_row(session, &ra, (char *)migr_row, chain[i].col_count, GS_INVALID_ID8, 0, *next_rid);

        for (j = 0; j < chain[i].col_count; j++) {
            col_id = chain[i].col_start + j;

            put_col_func(ori_row, offsets, lens, col_id, &ra);
        }
        row_end(&ra);

        if (pcrh_simple_insert(session, cursor, heap, migr_row, next_rid,
                               col_start + chain[i].col_start) != GS_SUCCESS) {
            cm_pop(session->stack);
            return GS_ERROR;
        }

        chain[i].chain_rid = *next_rid;
    }

    cm_pop(session->stack);

    if (cursor->action == CURSOR_ACTION_INSERT) {
        cursor->chain_count = chain_count;
    }

    return GS_SUCCESS;
}

/*
 * PCR chain insert
 * @note split origin row into several chain rows and insert a link row to manage them.
 * @param kernel session, cursor, heap
 */
static status_t pcrh_chain_insert(knl_session_t *session, knl_cursor_t *cursor, heap_t *heap)
{
    row_assist_t ra;
    row_head_t *link_row = NULL;
    rowid_t next_rid;
    ra.is_csf = cursor->row->is_csf;

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, NULL);

    if (pcrh_insert_chain_rows(session, cursor, heap, cursor->row, cursor->offsets,
                               cursor->lens, &next_rid, 0) != GS_SUCCESS) {
        return GS_ERROR;
    }

    link_row = (row_head_t *)cm_push(session->stack, PCRH_MIN_ROW_SIZE);

    pcrh_init_link_row(session, &ra, (char *)link_row, next_rid);

    if (pcrh_simple_insert(session, cursor, heap, link_row, &cursor->rowid, 0) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    cm_pop(session->stack);

    return GS_SUCCESS;
}

static uint16 pcrh_batch_insert_into_page(knl_session_t *session, uint32 row_count, heap_t *heap,
    knl_cursor_t *cursor, pcrh_undo_batch_insert_t *batch_undo)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    heap_page_t *page = (heap_page_t *)CURR_PAGE;
    pcr_itl_t *itl = pcrh_get_itl(page, session->itl_id);
    page_id_t page_id = AS_PAGID(page->head.id);
    rd_pcrh_insert_t rd = {.new_dir = 0, .aligned = 0};
    row_head_t *row = cursor->row;
    row_head_t *next_row = NULL;
    undo_data_t undo;
    uint16 slot;
    bool32 is_last_row = GS_FALSE;
    uint32 col_start = 0;

    rd.ssn = (uint32)cursor->ssn;

    for (uint32 i = 0; i < row_count; i++) {
        ROW_SET_ITL_ID(row, session->itl_id);
        /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
        pcrh_insert_into_page(session, page, row, &undo, &rd, &slot);
        batch_undo->undos[batch_undo->count].slot = slot;
        batch_undo->undos[batch_undo->count].is_xfirst = undo.snapshot.is_xfirst;
        batch_undo->count++;
        next_row = (row_head_t *)((char *)row + row->size);

        is_last_row = (i == row_count - 1) ? GS_TRUE :
            (pcrh_calc_insert_cost(session, (heap_segment_t *)heap->segment, next_row->size) > page->free_size);

        rd.undo_page = is_last_row ? undo_page_info->undo_rid.page_id : itl->undo_page;
        rd.undo_slot = is_last_row ? undo_page_info->undo_rid.slot : itl->undo_slot;

        if (cursor->logging && need_redo) {
            log_put(session, RD_PCRH_INSERT, &rd, OFFSET_OF(rd_pcrh_insert_t, data), entry_flag);
            log_append_data(session, row, row->size);
            if (has_logic) {
                log_append_data(session, &col_start, sizeof(uint16));
            }
        }

        SET_ROWID_PAGE(cursor->rowid_array + cursor->rowid_no, page_id);
        cursor->rowid_array[cursor->rowid_no].slot = slot;
        cursor->rowid_no++;
        if (is_last_row) {
            break;
        }
        row = next_row;
    }

    itl->undo_page = rd.undo_page;
    itl->undo_slot = rd.undo_slot;

    return (uint16)((char *)next_row - (char *)cursor->row);
}

/*
 * PCR insert heap row
 * @note insert a given row into the heap, return the rowid
 * @param kernel session, kernel cursor, heap, insert row, cost size,
 * rowid(output), logic replication column start id
 */
static status_t pcrh_batch_insert_rows(knl_session_t *session, knl_cursor_t *cursor, heap_t *heap, uint16 *rows_size)
{
    page_id_t page_id;
    undo_data_t undo;
    uint8 owner_list;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);

    knl_panic_log(cursor->rowid_no <= cursor->rowid_count, "cursor's rowid_no is bigger than rowid_count, panic info: "
                  "rowid_no %u rowid_count %u page %u-%u type %u table %s", cursor->rowid_no, cursor->rowid_count,
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);
    uint32 row_count = MIN(cursor->rowid_count - cursor->rowid_no, KNL_ROWID_ARRAY_SIZE);
    uint32 max_undo_size = CM_ALIGN4(sizeof(pcrh_batch_undo_t) * row_count + OFFSET_OF(pcrh_undo_batch_insert_t, undos));
    /* We prepare two undo rows (itl undo and insert undo) */
    if (cursor->logging) {
        if (undo_multi_prepare(session, PCRH_INSERT_UNDO_COUNT, MAX_ITL_UNDO_SIZE + max_undo_size,
            IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (pcrh_enter_insert_page(session, cursor, cursor->row, &page_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    heap_page_t *page = (heap_page_t *)CURR_PAGE;
    pcr_itl_t *itl = pcrh_get_itl(page, session->itl_id);
    undo.snapshot.undo_page = itl->undo_page;
    undo.snapshot.undo_slot = itl->undo_slot;
    undo.snapshot.scn = DB_CURR_SCN(session);
    undo.snapshot.is_owscn = GS_FALSE;
    undo.snapshot.is_xfirst = GS_FALSE;

    pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)cm_push(session->stack, max_undo_size);
    batch_undo->count = 0;
    batch_undo->aligned = 0;

    *rows_size = pcrh_batch_insert_into_page(session, row_count, heap, cursor, batch_undo);

    if (cursor->logging) {
        undo.type = UNDO_PCRH_BATCH_INSERT;
        undo.size = CM_ALIGN4(sizeof(pcrh_batch_undo_t) * batch_undo->count + OFFSET_OF(pcrh_undo_batch_insert_t, undos));
        SET_ROWID_PAGE(&undo.rowid, page_id);
        undo.rowid.slot = batch_undo->undos[0].slot;
        undo.data = (char *)batch_undo;
        /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
        undo.ssn = (uint32)cursor->ssn;
        undo_write(session, &undo, need_redo);
    }

    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    heap_try_change_map(session, heap, page_id);
    cm_pop(session->stack);
    return GS_SUCCESS;
}

static status_t pcrh_batch_insert(knl_session_t *session, knl_cursor_t *cursor, heap_t *heap)
{
    status_t status = GS_SUCCESS;
    row_head_t *row_addr = cursor->row;
    uint16 offset = 0;
    cursor->rowid_no = 0;

    do {
        if (cursor->row->size <= PCRH_MAX_ROW_SIZE - heap->cipher_reserve_size) {
            status = pcrh_batch_insert_rows(session, cursor, heap, &offset);
            cursor->row = (row_head_t *)((char *)cursor->row + offset);
        } else {
            status = pcrh_chain_insert(session, cursor, heap);
            cursor->rowid_array[cursor->rowid_no++] = cursor->rowid;
            cursor->row = (row_head_t *)((char *)cursor->row + cursor->row->size);
        }
    } while (cursor->rowid_count > cursor->rowid_no && status == GS_SUCCESS);

    cursor->rowid_no = 0;
    cursor->row_offset = 0;
    cursor->row = row_addr;
    return status;
}

/*
 * PCR heap insert interface
 * @param kernel session, kernel cursor
 */
status_t pcrh_insert(knl_session_t *session, knl_cursor_t *cursor)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    row_head_t *row = cursor->row;
    uint16 column_count = ROW_COLUMN_COUNT(row);
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);

    SYNC_POINT(session, "SP_B4_HEAP_INSERT");

    if (row->size > max_row_len) {
        if (heap_convert_insert(session, cursor, max_row_len) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    /*
     * I tested oracle with only 1 init trans, only 1 column with integer type.
     * It seems that it's only insert 733 rows and has considered about the min row size
     */
    if (row->size < PCRH_MIN_ROW_SIZE) {
        row->size = PCRH_MIN_ROW_SIZE;
    }

    if (lock_table_shared(session, cursor->dc_entity, LOCK_INF_WAIT) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cursor->xid != session->rm->xid.value) {
        cursor->xid = session->rm->xid.value;
    }

    if (IS_PART_TABLE(cursor->table)) {
        if (!heap->loaded) {
            if (dc_load_table_part_segment(session, cursor->dc_entity,
                (table_part_t *)cursor->table_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        if (heap->segment == NULL) {
            if (heap_create_part_entry(session, (table_part_t *)cursor->table_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

    } else {
        cursor->part_loc.part_no = GS_INVALID_ID32;
        if (heap->segment == NULL) {
            if (heap_create_entry(session, heap) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    if (has_logic && cursor->logging && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_atomic_op_begin(session);
        log_put(session, RD_LOGIC_REP_INSERT, &column_count, sizeof(uint16), LOG_ENTRY_FLAG_WITH_LOGIC_OID);
        heap_append_logic_data(session, cursor, GS_FALSE);
        log_atomic_op_end(session);
    }

    cursor->chain_count = 0;
    SET_ROWID_PAGE(&cursor->link_rid, INVALID_PAGID);

    status_t status;
    if (SECUREC_UNLIKELY(cursor->rowid_count > 0)) {
        status = pcrh_batch_insert(session, cursor, heap);
    } else if (row->size <= PCRH_MAX_ROW_SIZE - heap->cipher_reserve_size) {
        status = pcrh_simple_insert(session, cursor, heap, row, &cursor->rowid, 0);
    } else {
        status = pcrh_chain_insert(session, cursor, heap);
    }

    SYNC_POINT(session, "SP_AFTER_HEAP_INSERT");

    return status;
}

/*
 * PCR update in page
 * @param kernel session, heap page, update assist
 */
void pcrh_update_inpage(knl_session_t *session, heap_page_t *page, heap_update_assist_t *ua)
{
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl;
    row_assist_t ra;
    rowid_t next_rid;
    uint16 flags, old_size;
    uint8 itl_id;

    dir = pcrh_get_dir(page, (uint16)ua->rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    flags = row->flags;
    old_size = row->size;

    itl_id = ROW_ITL_ID(row);
    itl = pcrh_get_itl(page, itl_id);
    ra.is_csf = row->is_csf;

    if (ua->inc_size > 0) {
        /*  ua->new_size is less than page size(8192) for update inpage mode */
        if (page->free_end - page->free_begin < (uint16)ua->new_size) {
            /* set row dir to free, so we can reuse the old row space */
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, page);
        }

        *dir = page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE(8192),
         * ua->new_size is less than page size(8192) for update inpage mode,
         * the sum is less than max value(65535) of uint16.
         */
        page->free_begin += ua->new_size;
        knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is bigger than end, panic info: "
                      "page %u-%u type %u free_begin %u free_end %u", AS_PAGID(page->head.id).file,
                      AS_PAGID(page->head.id).page, +page->head.type, page->free_begin, page->free_end);

        if (itl->fsc >= ua->inc_size) {
            itl->fsc -= ua->inc_size;
        } else {
            /* free_size is larger than ua->inc_size */
            page->free_size -= (ua->inc_size - itl->fsc);
            itl->fsc = 0;
        }

        /* relocate the row position */
        row = PCRH_GET_ROW(page, dir);
    }

    if (!ua->row->is_migr) {
        pcrh_init_row(session, &ra, (char *)row, ua->new_cols, itl_id, flags);
    } else {
        next_rid = *PCRH_NEXT_ROWID(ua->row);
        pcrh_init_migr_row(session, &ra, (char *)row, ua->new_cols, itl_id, flags, next_rid);
    }

    row->is_changed = 1;
    row->self_chg = 1;
    heap_reorganize_with_update(ua->row, ua->offsets, ua->lens, ua->info, &ra);

    if (ua->inc_size > 0) {
        knl_panic_log(row->size > old_size, "current row_size is bigger than old_size when row increased size is "
                      "bigger than 0, panic info: current row_size %u old_size %u page %u-%u type %u", row->size,
                      old_size, AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
    } else {
        knl_panic_log(row->size <= old_size, "current row_size is bigger than old_size when row increased size is not "
                      "bigger than 0, panic info: current row_size %u old_size %u page %u-%u type %u", row->size,
                      old_size, AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type);
        /* itl->fsc and (old_size - row->size) both less than page size (8192) , so the sum will not exceed */
        itl->fsc += old_size - row->size;
    }
}

/*
 * convert current row to link row
 * @param kernel session, kernel cursor, origin row, rowid, link rowid
 */
static status_t pcrh_convert_link_row(knl_session_t *session, knl_cursor_t *cursor, row_head_t *ori_row,
                                      rowid_t rowid, rowid_t link_rid, bool32 self_update_check)
{
    undo_data_t undo;
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    pcrh_set_next_rid_t redo;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    heap_t *heap = CURSOR_HEAP(cursor);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);

    if (undo_prepare(session, ori_row->size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), need_encrypt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    undo.type = UNDO_PCRH_UPDATE_FULL;
    undo.size = ori_row->size;
    undo.rowid = rowid;

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    if (row->self_chg && self_update_check && itl->ssn == cursor->ssn) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        GS_THROW_ERROR(ERR_ROW_SELF_UPDATED);
        return GS_ERROR;
    }

    knl_panic_log(!row->is_link && !row->is_migr, "the row is link or migr, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);

    undo.snapshot.scn = DB_CURR_SCN(session);
    undo.snapshot.is_owscn = itl->is_owscn;
    undo.snapshot.undo_page = itl->undo_page;
    undo.snapshot.undo_slot = itl->undo_slot;
    undo.snapshot.is_xfirst = !row->is_changed;
    /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
    undo.ssn = (uint32)cursor->ssn;

    itl->undo_page = undo_page_info->undo_rid.page_id;
    itl->undo_slot = undo_page_info->undo_rid.slot;
    itl->ssn = (uint32)cursor->ssn;
    /* itl->fsc and row->size is both less than page size(8192) */
    itl->fsc += row->size - PCRH_MIN_ROW_SIZE;

    undo.data = (char *)ori_row;
    undo_write(session, &undo, need_redo);

    row->is_link = 1;
    row->is_changed = 1;
    row->self_chg = 1;
    *PCRH_NEXT_ROWID(row) = link_rid;
    row->size = PCRH_MIN_ROW_SIZE;

    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;
    redo.slot = (uint16)rowid.slot;
    redo.ssn = (uint32)cursor->ssn;
    redo.next_rid = link_rid;
    if (need_redo) {
        log_put(session, RD_PCRH_CONVERT_LINK, &redo, sizeof(pcrh_set_next_rid_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    return GS_SUCCESS;
}

/*
 * PCR update next rowid
 * @note current row must be link row or migration row
 * @param kernel session, kernel cursor, rowid, new link rowid
 */
static status_t pcrh_update_next_rid(knl_session_t *session, knl_cursor_t *cursor, rowid_t rowid, rowid_t next_rid)
{
    undo_data_t undo;
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    pcrh_set_next_rid_t redo;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    if (undo_prepare(session, sizeof(rowid_t), IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    undo.type = UNDO_PCRH_UPDATE_NEXT_RID;
    undo.size = sizeof(rowid_t);
    undo.rowid = rowid;

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));

    undo.snapshot.scn = DB_CURR_SCN(session);
    undo.snapshot.is_owscn = itl->is_owscn;
    undo.snapshot.undo_page = itl->undo_page;
    undo.snapshot.undo_slot = itl->undo_slot;
    undo.snapshot.is_xfirst = !row->is_changed;
    /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for untemp table */
    undo.ssn = (uint32)cursor->ssn;

    itl->undo_page = undo_page_info->undo_rid.page_id;
    itl->undo_slot = undo_page_info->undo_rid.slot;
    itl->ssn = (uint32)cursor->ssn;

    undo.data = (char *)(PCRH_NEXT_ROWID(row));
    undo_write(session, &undo, need_redo);

    row->is_changed = 1;
    row->self_chg = 1;
    *PCRH_NEXT_ROWID(row) = next_rid;

    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;
    redo.slot = (uint16)rowid.slot;
    redo.ssn = (uint32)cursor->ssn;
    redo.next_rid = next_rid;
    if (need_redo) {
        log_put(session, RD_PCRH_UPDATE_NEXT_RID, &redo, sizeof(pcrh_set_next_rid_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    return GS_SUCCESS;
}

/*
 * PCR simple delete
 * @note delete the specified row by rowid
 * @param kernel session, kernel cursor, rowid, row size
 */
static status_t pcrh_simple_delete(knl_session_t *session, knl_cursor_t *cursor, rowid_t rowid,
                                   uint16 size, bool32 self_update_check)
{
    undo_data_t undo;
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    rd_pcrh_delete_t redo;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);
    heap_t *heap = CURSOR_HEAP(cursor);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);
    if (undo_prepare(session, size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), need_encrypt) != GS_SUCCESS) {
        return GS_ERROR;
    }

    undo.type = UNDO_PCRH_DELETE;
    undo.size = size;
    ROWID_COPY(undo.rowid, rowid);
    if (SECUREC_UNLIKELY(session->compacting)) {
        undo.type = UNDO_PCRH_COMPACT_DELETE;
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    if (row->self_chg && self_update_check && itl->ssn == cursor->ssn) {
        cursor->is_found = (row->is_deleted == 0);
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);

        if (cursor->is_found) {
            GS_THROW_ERROR(ERR_ROW_SELF_UPDATED);
            return GS_ERROR;
        } else {
            return GS_SUCCESS;
        }
    }

    knl_panic_log(itl->xid.value == session->rm->xid.value, "xid of itl and rm are not equal, panic info: "
                  "page %u-%u type %u table %s itl xid %llu rm xid %llu", cursor->rowid.file, cursor->rowid.page,
                  page->head.type, ((table_t *)cursor->table)->desc.name, itl->xid.value, session->rm->xid.value);

    undo.snapshot.scn = DB_CURR_SCN(session);
    undo.snapshot.is_owscn = itl->is_owscn;
    undo.snapshot.undo_page = itl->undo_page;
    undo.snapshot.undo_slot = itl->undo_slot;
    undo.snapshot.is_xfirst = !row->is_changed;
    undo.ssn = (uint32)cursor->ssn;

    itl->undo_page = undo_page_info->undo_rid.page_id;
    itl->undo_slot = undo_page_info->undo_rid.slot;
    itl->ssn = (uint32)cursor->ssn;

    /*
     * In PCR heap, we have space recycling mechanism in transaction,
     * When row is deleted, its space can be reused by following statement,
     * but we need track the deleted row during transaction commit or
     * rollback, and itl_id is on row, so we must keep a minimum row
     * tracking the current transaction.
     * Second, we don't change row actual size here, because we try
     * to keep page space continuity which would be beneficial for
     * for page compact.
     */
    itl->fsc += row->size - sizeof(row_head_t);

    /* write undo, before we change the row */
    undo.data = (char *)row;
    undo_write(session, &undo, need_redo);

    knl_panic_log(!row->is_deleted, "the row is deleted, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);
    row->is_deleted = 1;
    row->is_changed = 1;
    row->self_chg = 1;
    page->rows--;

    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;
    redo.slot = (uint16)rowid.slot;
    redo.ssn = (uint32)cursor->ssn;
    if (need_redo) {
        log_put(session, RD_PCRH_DELETE, &redo, sizeof(rd_pcrh_delete_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    return GS_SUCCESS;
}

/*
 * PCR lock migration row
 * @note simple version of lock row interface, no transaction wait here.
 * @attention we call this lock migration row, but for the first migration row,
 * it's previous row is link row, and it has been lock during scan, just skip here.
 * @param kernel session, kernel cursor, rowid
 */
static status_t pcrh_lock_migr_row(knl_session_t *session, knl_cursor_t *cursor, rowid_t rowid)
{
    heap_t *heap;
    heap_page_t *page = NULL;
    pcr_itl_t *itl = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    uint8 owner_list;
    uint8 itl_id;
    bool32 changed = GS_FALSE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    rd_pcrh_lock_row_t rd;

    heap = CURSOR_HEAP(cursor);

    if (undo_prepare(session, MAX_ITL_UNDO_SIZE, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (;;) {
        log_atomic_op_begin(session);

        buf_enter_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
        page = (heap_page_t *)CURR_PAGE;
        dir = pcrh_get_dir(page, (uint16)rowid.slot);
        knl_panic_log(!PCRH_DIR_IS_FREE(dir), "the dir is free, panic info: page %u-%u type %u table %s",
                      cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);
        row = PCRH_GET_ROW(page, dir);
        knl_panic_log(!row->is_deleted, "the row is deleted, panic info: page %u-%u type %u table %s",
                      cursor->rowid.file, cursor->rowid.page, page->head.type, ((table_t *)cursor->table)->desc.name);

        itl_id = ROW_ITL_ID(row);
        if (itl_id != GS_INVALID_ID8) {
            itl = pcrh_get_itl(page, itl_id);
            if (itl->xid.value == session->rm->xid.value) {
                if (itl->ssn == cursor->ssn) {
                    buf_leave_page(session, GS_FALSE);
                    log_atomic_op_end(session);
                    knl_end_itl_waits(session);
                    return GS_SUCCESS;
                }

                /* new statement, reset all changed rows in page */
                pcrh_reset_self_changed(session, page, itl_id);
                if (need_redo) {
                    log_put(session, RD_PCRH_RESET_SELF_CHANGE, &itl_id, sizeof(uint8), LOG_ENTRY_FLAG_NONE);
                }
                buf_leave_page(session, GS_TRUE);
                log_atomic_op_end(session);
                knl_end_itl_waits(session);
                return GS_SUCCESS;
            }
        }

        if (pcrh_alloc_itl(session, cursor, page, &itl, &changed) != GS_SUCCESS) {
            buf_leave_page(session, changed);
            log_atomic_op_end(session);
            knl_end_itl_waits(session);
            heap_try_change_map(session, heap, GET_ROWID_PAGE(rowid));
            return GS_ERROR;
        }

        if (itl == NULL) {
            session->wpid = AS_PAGID(page->head.id);
            buf_leave_page(session, GS_FALSE);
            log_atomic_op_end(session);

            if (knl_begin_itl_waits(session, &heap->stat.itl_waits) != GS_SUCCESS) {
                knl_end_itl_waits(session);
                return GS_ERROR;
            }
            continue;
        }
        break;
    }
    knl_end_itl_waits(session);

    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    ROW_SET_ITL_ID(row, session->itl_id);
    row->is_changed = 0;
    row->self_chg = 0;

    rd.slot = (uint16)rowid.slot;
    rd.itl_id = session->itl_id;
    rd.aligned = 0;
    if (need_redo) {
        log_put(session, RD_PCRH_LOCK_ROW, &rd, sizeof(rd_pcrh_lock_row_t), LOG_ENTRY_FLAG_NONE);
    }

    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    session->change_list = owner_list - (uint8)page->map.list_id;
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, GET_ROWID_PAGE(rowid));

    return GS_SUCCESS;
}

/*
 * migrate current update
 * @note find a free page, using delete old + insert new to do migrate update
 * @param kernel session, kernel cursor, heap update assist, prev rowid, logic replication column start id
 */
static status_t pcrh_migrate_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                    rowid_t prev_rowid, uint16 col_start)
{
    heap_t *heap;
    row_assist_t ra;
    rowid_t migr_rid, next_rid;
    row_head_t *migr_row = NULL;
    uint16 migr_row_size;

    heap = CURSOR_HEAP(cursor);
    ra.is_csf = cursor->row->is_csf;

    migr_row_size = ua->new_size;
    /* migr_row_size is less than page size(8192) */
    migr_row_size += (ua->row->is_migr) ? 0 : sizeof(rowid_t); /** append next_rid */

    migr_row = (row_head_t *)cm_push(session->stack, migr_row_size);
    next_rid = (ua->row->is_migr) ? *PCRH_NEXT_ROWID(ua->row) : INVALID_ROWID;
    pcrh_init_migr_row(session, &ra, (char *)migr_row, ua->new_cols, GS_INVALID_ID8, ua->row->flags, next_rid);

    heap_reorganize_with_update(ua->row, ua->offsets, ua->lens, ua->info, &ra);
    knl_panic_log(migr_row->size == migr_row_size, "migr_row_size is abnormal, panic info: page %u-%u type %u "
        "table %s migr_row's size %u migr_row_size %u", cursor->rowid.file, cursor->rowid.page,
        ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, migr_row->size, migr_row_size);

    if (pcrh_simple_insert(session, cursor, heap, migr_row, &migr_rid, col_start) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    cm_pop(session->stack);

    if (!ua->row->is_migr) {
        /* convert origin row to link row */
        if (pcrh_convert_link_row(session, cursor, ua->row, ua->rowid, migr_rid, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        /* delete old migration row, update link */
        if (pcrh_simple_delete(session, cursor, ua->rowid, ua->row->size, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }

        /* try lock the prev row to do next_rid update */
        if (pcrh_lock_migr_row(session, cursor, prev_rowid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (pcrh_update_next_rid(session, cursor, prev_rowid, migr_rid) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
 * PCR chain update
 * @note update a normal row to chain rows
 * @param kernel session, kernel cursor, update assist
 */
static status_t pcrh_chain_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    heap_t *heap;
    row_assist_t ra;
    row_head_t *split_row = NULL;
    rowid_t next_rid;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;

    heap = CURSOR_HEAP(cursor);

    CM_SAVE_STACK(session->stack);
    ra.is_csf = ua->row->is_csf;

    split_row = (row_head_t *)cm_push(session->stack, ua->new_size);
    /* max column count of table is GS_MAX_COLUMNS(4096) */
    offsets = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));
    lens = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));

    pcrh_init_row(session, &ra, (char *)split_row, ua->new_cols, GS_INVALID_ID8, 0);
    heap_reorganize_with_update(ua->row, ua->offsets, ua->lens, ua->info, &ra);
    knl_panic_log(split_row->size == ua->new_size, "split_row's size and new_size in ua are not equal, panic info: "
        "page %u-%u type %u table %s split_row size %u ua new_size %u", cursor->rowid.file, cursor->rowid.page,
        ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, split_row->size, ua->new_size);

    cm_decode_row((char *)split_row, offsets, lens, NULL);

    if (pcrh_insert_chain_rows(session, cursor, heap, split_row, offsets, lens, &next_rid, 0) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* convert origin row to link row */
    if (pcrh_convert_link_row(session, cursor, ua->row, ua->rowid, next_rid, GS_TRUE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

/*
 * PCR simple update
 * @note update the given row in current page in in-place mode or in-page mode
 * @param kernel session, kernel cursor, update assist, undo data
 */
static void pcrh_simple_update(knl_session_t *session, knl_cursor_t *cursor,
    heap_update_assist_t *ua, undo_data_t *undo)
{
    heap_t *heap;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    heap_page_t *page;
    pcr_itl_t *itl = NULL;
    uint8 owner_list;
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    uint8 entry_flag = has_logic ? LOG_ENTRY_FLAG_WITH_LOGIC_OID : LOG_ENTRY_FLAG_NONE;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    heap = CURSOR_HEAP(cursor);
    page = (heap_page_t *)CURR_PAGE;
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);

    ROWID_COPY(undo->rowid, ua->rowid);

    dir = pcrh_get_dir(page, (uint16)ua->rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
        "page %u-%u type %u table %s itl xid %llu rm xid %llu", cursor->rowid.file, cursor->rowid.page,
        page->head.type, ((table_t *)cursor->table)->desc.name, itl->xid.value, session->rm->xid.value);

    undo->snapshot.scn = DB_CURR_SCN(session);
    undo->snapshot.is_owscn = itl->is_owscn;
    undo->snapshot.undo_page = itl->undo_page;
    undo->snapshot.undo_slot = itl->undo_slot;
    undo->snapshot.is_xfirst = !row->is_changed;
    /* cursor->ssn is from session->xact_ssn(uint32) or stmt->xact_ssn(uint32) for not temp table */
    undo->ssn = (uint32)cursor->ssn;

    itl->undo_page = undo_page_info->undo_rid.page_id;
    itl->undo_slot = undo_page_info->undo_rid.slot;
    itl->ssn = (uint32)cursor->ssn;

    undo_write(session, undo, need_redo);

    if (ua->mode == UPDATE_INPLACE) {
        if (need_redo) {
            rd_pcrh_update_inplace_t rd_inplace;

            rd_inplace.ssn = (uint32)cursor->ssn;
            rd_inplace.slot = (uint16)ua->rowid.slot;
            rd_inplace.undo_page = itl->undo_page;
            rd_inplace.undo_slot = itl->undo_slot;
            rd_inplace.count = ua->info->count;
            rd_inplace.aligned = 0;
            log_encrypt_prepare(session, page->head.type, need_encrypt);
            log_put(session, RD_PCRH_UPDATE_INPLACE, &rd_inplace, sizeof(rd_pcrh_update_inplace_t), entry_flag);
            log_append_data(session, ua->info->columns, sizeof(uint16) * ua->info->count);
            log_append_data(session, ua->info->data, ((row_head_t *)ua->info->data)->size);
        }

        row->self_chg = 1;
        heap_update_inplace(session, ua->offsets, ua->lens, ua->info, row);
        session->change_list = 0;
    } else {
        if (need_redo) {
            rd_pcrh_update_inpage_t rd_inpage;

            rd_inpage.ssn = (uint32)cursor->ssn;
            rd_inpage.slot = (uint16)ua->rowid.slot;
            rd_inpage.undo_page = itl->undo_page;
            rd_inpage.undo_slot = itl->undo_slot;
            rd_inpage.count = ua->info->count;
            rd_inpage.new_cols = ua->new_cols;
            rd_inpage.inc_size = ua->inc_size;
            rd_inpage.aligned = 0;
            log_encrypt_prepare(session, page->head.type, need_encrypt);
            log_put(session, RD_PCRH_UPDATE_INPAGE, &rd_inpage, sizeof(rd_pcrh_update_inpage_t), entry_flag);
            log_append_data(session, ua->info->columns, sizeof(uint16) * ua->info->count);
            log_append_data(session, ua->info->data, ((row_head_t *)ua->info->data)->size);
        }

        pcrh_update_inpage(session, page, ua);
        owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
        session->change_list = owner_list - (uint8)page->map.list_id;
    }
}

/*
 * PCR split migration row
 * @note convert current migration row to chain rows
 * @param kernel session, kernel cursor, update assist, prev rowid, logic replication column start id
 */
static status_t pcrh_split_migr_row(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                    rowid_t prev_rowid, uint16 col_start)
{
    heap_t *heap;
    row_assist_t ra;
    row_head_t *split_row = NULL;
    rowid_t next_rid;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;

    heap = CURSOR_HEAP(cursor);

    CM_SAVE_STACK(session->stack);
    ra.is_csf = ua->row->is_csf;

    split_row = (row_head_t *)cm_push(session->stack, ua->new_size);
    /* max column count of table is GS_MAX_COLUMNS(4096) */
    offsets = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));
    lens = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));

    pcrh_init_migr_row(session, &ra, (char *)split_row, ua->new_cols, GS_INVALID_ID8, 0, *PCRH_NEXT_ROWID(ua->row));
    heap_reorganize_with_update(ua->row, ua->offsets, ua->lens, ua->info, &ra);
    knl_panic_log(split_row->size == ua->new_size, "split_row's size and new_size in ua are not equal, panic info: "
        "page %u-%u type %u table %s split_row size %u ua new_size %u", cursor->rowid.file, cursor->rowid.page,
        ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, split_row->size, ua->new_size);

    cm_decode_row((char *)split_row, offsets, lens, NULL);

    if (pcrh_insert_chain_rows(session, cursor, heap, split_row, offsets, lens, &next_rid, col_start) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* delete old migration row */
    if (pcrh_simple_delete(session, cursor, ua->rowid, ua->row->size, GS_FALSE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* try lock the prev row to do next_rid update */
    if (pcrh_lock_migr_row(session, cursor, prev_rowid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (pcrh_update_next_rid(session, cursor, prev_rowid, next_rid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

/*
 * PCR update row
 * @note update the given normal row or migration row or chain row
 * @param kernel session, kernel cursor, update assist, prev rowid, logic replication column start id
 */
static status_t pcrh_update_row(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
                                rowid_t prev_rowid, uint16 col_start, bool32 self_update_check)
{
    heap_t *heap = NULL;
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    undo_data_t undo;

    undo.data = (char *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    if (ua->undo_size >= ua->row->size) {
        undo.type = UNDO_PCRH_UPDATE_FULL;
        undo.data = (char *)ua->row;
        undo.size = ua->row->size;
    } else {
        undo.type = UNDO_PCRH_UPDATE;
        heap_get_update_undo_data(session, ua, &undo, GS_MAX_ROW_SIZE);
    }

    heap = CURSOR_HEAP(cursor);
    bool32 need_encrypt = SPACE_NEED_ENCRYPT(heap->cipher_reserve_size);
    if (undo_prepare(session, undo.size, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), need_encrypt) != GS_SUCCESS) {
        cm_pop(session->stack);
        return GS_ERROR;
    }

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(ua->rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)ua->rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    if (row->self_chg && self_update_check && itl->ssn == cursor->ssn) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        cm_pop(session->stack);
        GS_THROW_ERROR(ERR_ROW_SELF_UPDATED);
        return GS_ERROR;
    }

    knl_panic_log(!row->is_link, "the row is link, panic info: page %u-%u type %u table %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((table_t *)cursor->table)->desc.name);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
                  "page %u-%u type %u table %s itl xid %llu rm xid %llu", AS_PAGID(page->head.id).file,
                  AS_PAGID(page->head.id).page, page->head.type, ((table_t *)cursor->table)->desc.name, itl->xid.value,
                  session->rm->xid.value);

    /* calculate the accurate inc_size and row new_size, row->size >= ua->data_size */
    ua->inc_size = ua->new_size - row->size;

    if (ua->inc_size > 0 && ua->inc_size > page->free_size + itl->fsc) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        cm_pop(session->stack);

        return pcrh_migrate_update(session, cursor, ua, prev_rowid, col_start);
    }

    if (cursor->isolevel == (uint8)ISOLATION_SERIALIZABLE && cursor->query_scn < page->scn &&
        ua->inc_size > 0 && ua->inc_size > itl->fsc) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        cm_pop(session->stack);
        GS_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return GS_ERROR;
    }

    pcrh_simple_update(session, cursor, ua, &undo);
    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    heap_try_change_map(session, heap, GET_ROWID_PAGE(ua->rowid));
    cm_pop(session->stack);

    return GS_SUCCESS;
}

static status_t pcrh_update_link_ssn(knl_session_t *session, knl_cursor_t *cursor, rowid_t rowid)
{
    undo_data_t undo;
    pcrh_update_link_ssn_t redo;
    bool32 need_redo = IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type);
    undo_page_info_t *undo_page_info = UNDO_GET_PAGE_INFO(session, need_redo);

    if (undo_prepare(session, 0, IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type), GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    undo.type = UNDO_PCRH_UPDATE_LINK_SSN;
    undo.size = 0;
    ROWID_COPY(undo.rowid, rowid);

    log_atomic_op_begin(session);

    buf_enter_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_X, ENTER_PAGE_NORMAL);
    heap_page_t *page = (heap_page_t *)CURR_PAGE;
    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    if (row->self_chg && itl->ssn == cursor->ssn) {
        buf_leave_page(session, GS_FALSE);
        log_atomic_op_end(session);
        GS_THROW_ERROR(ERR_ROW_SELF_UPDATED);
        return GS_ERROR;
    }

    knl_panic_log(row->is_link && !row->is_deleted,
                  "the row is not link, or the row is deleted, panic info: page %u-%u type %u table %s",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((table_t *)cursor->table)->desc.name);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
                  "itl xid %llu rm xid %llu page %u-%u type %u table %s", itl->xid.value, session->rm->xid.value,
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, page->head.type,
                  ((table_t *)cursor->table)->desc.name);

    undo.snapshot.scn = DB_CURR_SCN(session);
    undo.snapshot.is_owscn = itl->is_owscn;
    undo.snapshot.undo_page = itl->undo_page;
    undo.snapshot.undo_slot = itl->undo_slot;
    undo.snapshot.is_xfirst = !row->is_changed;
    undo.ssn = (uint32)cursor->ssn;

    itl->undo_page = undo_page_info->undo_rid.page_id;
    itl->undo_slot = undo_page_info->undo_rid.slot;
    itl->ssn = (uint32)cursor->ssn;

    undo_write(session, &undo, need_redo);

    row->is_changed = 1;
    row->self_chg = 1;

    if (need_redo) {
        redo.undo_page = itl->undo_page;
        redo.undo_slot = itl->undo_slot;
        redo.slot = (uint16)rowid.slot;
        redo.ssn = (uint32)cursor->ssn;
        log_put(session, RD_PCRH_UPDATE_LINK_SSN, &redo, sizeof(pcrh_update_link_ssn_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);

    log_atomic_op_end(session);

    return GS_SUCCESS;
}

/*
 * PCR update migration row
 * @note support tow scenarios:
 * 1. split current migration row into chain rows.
 * 2. update current migration row
 * @attention we alloc itl for migration row here.
 * @param kernel session, kernel cursor, update assist, prev rowid, logic replication column start id
 */
static status_t pcrh_update_migr_row(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua,
    rowid_t prev_rid, uint16 col_start)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;
    if (pcrh_lock_migr_row(session, cursor, ua->rowid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (ua->new_size > PCRH_MAX_MIGR_SIZE - cipher_reserve_size) {
        return pcrh_split_migr_row(session, cursor, ua, prev_rid, col_start);
    }

    if (pcrh_update_row(session, cursor, ua, prev_rid, col_start, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * PCR reorganize chain update info
 * @note reorganize a new update info for current chain.
 * @param kernel session, chain assist, origin update info, new update info, last chain
 */
static bool32 pcrh_reorganize_chain_update_info(knl_session_t *session, row_chain_t *chain, knl_update_info_t *ori_info,
                                                knl_update_info_t *new_info, bool32 is_last)
{
    row_assist_t ra;
    uint16 i, start;
    bool32 is_csf = ((row_head_t *)ori_info->data)->is_csf;
    knl_put_row_column_t put_col_func = is_csf ? heap_put_csf_row_column : heap_put_bmp_row_column;

    new_info->count = 0;
    start = GS_INVALID_ID16;

    for (i = 0; i < ori_info->count; i++) {
        if (ori_info->columns[i] < chain->col_start) {
            continue;
        }

        if (ori_info->columns[i] >= chain->col_start + chain->col_count && !is_last) {
            break;
        }

        if (start == GS_INVALID_ID16) {
            start = i;
        }

        new_info->count++;
    }

    if (new_info->count == 0) {
        return GS_FALSE;
    }

    cm_row_init(&ra, new_info->data, GS_MAX_ROW_SIZE, new_info->count, is_csf);

    for (i = 0; i < new_info->count; i++) {
        new_info->columns[i] = ori_info->columns[i + start] - chain->col_start;

        put_col_func((row_head_t *)ori_info->data, ori_info->offsets, ori_info->lens, i + start, &ra);
    }
    row_end(&ra);

    cm_decode_row(new_info->data, new_info->offsets, new_info->lens, NULL);

    return GS_TRUE;
}

/*
 * PCR get migration row
 * @note simple get specified chain row.
 * @param kernel session, rowid, row buffer
 */
static status_t pcrh_get_migr_row(knl_session_t *session, rowid_t rowid, char *buf)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    errno_t ret;

    if (buf_read_page(session, GET_ROWID_PAGE(rowid), LATCH_MODE_S, ENTER_PAGE_NORMAL) != GS_SUCCESS) {
        return GS_ERROR;
    }
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    knl_panic_log(!PCRH_DIR_IS_FREE(dir), "the dir is free, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, ((page_head_t *)CURR_PAGE)->type);
    row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_migr == 1, "the row is not migr, panic info: page %u-%u type %u",
                  AS_PAGID(page->head.id).file, AS_PAGID(page->head.id).page, ((page_head_t *)CURR_PAGE)->type);

    ret = memcpy_sp(buf, PCRH_MAX_MIGR_SIZE, row, row->size);
    knl_securec_check(ret);

    buf_leave_page(session, GS_FALSE);

    return GS_SUCCESS;
}

/*
 * PCR update chain rows
 * @note try to update chain rows in reverse order, reorganize
 * a new temp update info for the chain if the chain need to be updated.
 * Call the migration row update interface directly.
 * @param kernel session, kernel cursor, update assist
 */
static status_t pcrh_update_chain_rows(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    row_chain_t *chain = (row_chain_t *)cursor->chain_info;
    knl_update_info_t *update_info = ua->info;
    knl_update_info_t new_info;
    row_head_t *migr_row = NULL;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    uint16 data_size;
    int16 i;
    bool32 is_last = GS_FALSE;

    CM_SAVE_STACK(session->stack);

    new_info.data = (char *)cm_push(session->stack, GS_MAX_ROW_SIZE);
    CM_PUSH_UPDATE_INFO(session, new_info);

    migr_row = (row_head_t *)cm_push(session->stack, PCRH_MAX_MIGR_SIZE);
    offsets = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));
    lens = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));

    for (i = cursor->chain_count - 1; i >= 0; i--) {
        is_last = (i == cursor->chain_count - 1);

        if (!pcrh_reorganize_chain_update_info(session, &chain[i], update_info, &new_info, is_last)) {
            continue;
        }

        /* get the migration row and prepare for update */
        if (pcrh_get_migr_row(session, chain[i].chain_rid, (char *)migr_row) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
        cm_decode_row((char *)migr_row, offsets, lens, &data_size);

        ua->old_cols = chain[i].col_count;
        ua->new_cols = is_last ? (entity->column_count - chain[i].col_start) : chain[i].col_count;
        ua->info = &new_info;
        heap_update_prepare(session, migr_row, offsets, lens, data_size, ua);

        /* now, update the migration row */
        ROWID_COPY(ua->rowid, chain[i].chain_rid);

        if (pcrh_update_migr_row(session, cursor, ua, chain[i].owner_rid, chain[i].col_start) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

/*
 * PCR merge chain update
 * @note insert a new chain delete old chains when chain count exceed PCRH_MERGE_CHAIN_COUNT,
 * otherwise chain count will increase exceed GS_MAX_CHAIN_COUNT after update
 * @param kernel session, kernel cursor, update assist
 */
status_t pcrh_merge_chain_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    row_chain_t *chain = (row_chain_t *)cursor->chain_info;
    uint8 i;
    row_assist_t ra;
    row_head_t *split_row = NULL;
    rowid_t next_rid;
    uint16 *offsets = NULL;
    uint16 *lens = NULL;
    ra.is_csf = ua->row->is_csf;

    knl_panic_log(cursor->chain_info != NULL, "cursor's chain_info is NULL, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    CM_SAVE_STACK(session->stack);

    split_row = (row_head_t *)cm_push(session->stack, ua->new_size);
    /** max column count of table is GS_MAX_COLUMNS(4096) */
    offsets = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));
    lens = (uint16 *)cm_push(session->stack, session->kernel->attr.max_column_count * sizeof(uint16));

    pcrh_init_row(session, &ra, (char *)split_row, ua->new_cols, GS_INVALID_ID8, 0);
    heap_reorganize_with_update(ua->row, ua->offsets, ua->lens, ua->info, &ra);
    knl_panic_log(split_row->size == ua->new_size, "split_row's size and new_size in ua are not equal, panic info: "
        "page %u-%u type %u table %s split_row size %u ua new_size %u", cursor->rowid.file, cursor->rowid.page,
        ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name, split_row->size, ua->new_size);

    cm_decode_row((char *)split_row, offsets, lens, NULL);

    if (pcrh_insert_chain_rows(session, cursor, heap, split_row, offsets, lens, &next_rid, 0) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (pcrh_update_next_rid(session, cursor, cursor->rowid, next_rid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /** delete chain rows one by one */
    for (i = 0; i < cursor->chain_count; i++) {
        if (pcrh_lock_migr_row(session, cursor, chain[i].chain_rid) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (pcrh_simple_delete(session, cursor, chain[i].chain_rid, chain[i].row_size, GS_FALSE) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

/**
 * PCR do update
 * @note the executor of update, as mentioned above
 * @param kernel session, kernel cursor, dc entity, update assist
 */
static status_t pcrh_do_update(knl_session_t *session, knl_cursor_t *cursor,
    dc_entity_t *entity, heap_update_assist_t *ua)
{
    heap_t *heap = CURSOR_HEAP(cursor);
    uint8 cipher_reserve_size = heap->cipher_reserve_size;

    if (entity->contain_lob) {
        if (lob_update(session, cursor, ua) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (cursor->chain_count == 0) {
        ROWID_COPY(ua->rowid, cursor->rowid);

        if (ua->new_size > PCRH_MAX_ROW_SIZE - cipher_reserve_size) {
            return pcrh_chain_update(session, cursor, ua);
        }

        return pcrh_update_row(session, cursor, ua, INVALID_ROWID, 0, GS_TRUE);
    } else {
        if (pcrh_update_link_ssn(session, cursor, cursor->rowid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (cursor->chain_count == 1) {
            ROWID_COPY(ua->rowid, cursor->link_rid);

            return pcrh_update_migr_row(session, cursor, ua, cursor->rowid, 0);
        } else if (cursor->chain_count < PCRH_MERGE_CHAIN_COUNT) {
            return pcrh_update_chain_rows(session, cursor, ua);
        } else {
            return pcrh_merge_chain_update(session, cursor, ua);
        }
    }
}

/*
 * @note the function should work as follow:
 * 1. try to update deleted column
 * 2. try convert inline lob in update info to outline
 * 3. try convert inline lob not in update info to outline
 * 4. use new update info to do following update
 * @param kernel session, kernel cursor, old update assist
 */
status_t pcrh_convert_update(knl_session_t *session, knl_cursor_t *cursor, heap_update_assist_t *ua)
{
    dc_entity_t *entity = NULL;
    knl_update_info_t *del_info = NULL;
    knl_update_info_t *lob_info = NULL;
    bool32 is_reorg = GS_FALSE;
    status_t status;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);

    CM_SAVE_STACK(session->stack);

    entity = (dc_entity_t *)cursor->dc_entity;

    if (heap_check_deleted_column(cursor, &cursor->update_info, cursor->row, cursor->lens)) {
        del_info = (knl_update_info_t *)cm_push(session->stack, sizeof(knl_update_info_t) + GS_MAX_ROW_SIZE);
        del_info->data = (char *)del_info + sizeof(knl_update_info_t);
        CM_PUSH_UPDATE_INFO(session, *del_info);
        heap_reorganize_del_column_update_info(session, cursor, ua->info, del_info);
        ua->info = del_info;
        heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, ua);
    }

    if (entity->contain_lob && ua->new_size > max_row_len) {
        lob_info = (knl_update_info_t *)cm_push(session->stack, sizeof(knl_update_info_t) + GS_MAX_ROW_SIZE);
        lob_info->data = (char *)lob_info + sizeof(knl_update_info_t);
        CM_PUSH_UPDATE_INFO(session, *lob_info);

        /*
         * lob_reorganize_update_info will check new size and throw ERR_RECORD_SIZE_OVERFLOW when row size overflow
         */
        if (lob_reorganize_columns(session, cursor, ua, lob_info, &is_reorg) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (is_reorg) {
            ua->info = lob_info;
            heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, ua);
        }
    }

    if (ua->new_size > max_row_len) {
        CM_RESTORE_STACK(session->stack);
        GS_THROW_ERROR(ERR_RECORD_SIZE_OVERFLOW, "update row", ua->new_size, max_row_len);
        return GS_ERROR;
    }

    status = pcrh_do_update(session, cursor, entity, ua);
    CM_RESTORE_STACK(session->stack);
    return status;
}

/*
 * PCR heap update interface
 * @note support following update scenarios:
 * 1. normal row update (in-place and in-page)
 * 2. normal row migrate update (row migration)
 * 3. migration row normal update (in-place, in-page, row migration again)
 * 4. normal row update to chain rows (chain update)
 * 5. migration row update to chain rows (migration row split)
 * 6. chain rows update (chain row normal update, chain row split)
 * @param kernel session, kernel cursor
 */
status_t pcrh_update(knl_session_t *session, knl_cursor_t *cursor)
{
    dc_entity_t *entity = NULL;
    heap_update_assist_t ua;
    rd_logic_rep_head logic_head;
    status_t status;
    uint32 max_row_len = heap_table_max_row_len(cursor->table, GS_MAX_ROW_SIZE, cursor->part_loc);

    SYNC_POINT(session, "SP_B4_HEAP_UPDATE");
    knl_panic_log(cursor->is_valid, "current cursor is invalid, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);
    knl_panic_log(cursor->row->is_csf == ((row_head_t *)(cursor->update_info.data))->is_csf,
                  "the status of csf is mismatch, panic info: "
                  "page %u-%u type %u table %s row csf status %u update csf status %u", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name,
                  cursor->row->is_csf, ((row_head_t *)(cursor->update_info.data))->is_csf);

    if (cursor->xid != session->rm->xid.value) {
        cursor->xid = session->rm->xid.value;
    }

    entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);
    if (has_logic && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type)) {
        log_atomic_op_begin(session);
        logic_head.col_count = cursor->update_info.count;
        logic_head.is_pcr = GS_TRUE;
        logic_head.unused = 0;
        log_put(session, RD_LOGIC_REP_UPDATE, &logic_head, sizeof(rd_logic_rep_head), LOG_ENTRY_FLAG_WITH_LOGIC_OID);
        log_append_data(session, cursor->update_info.columns, cursor->update_info.count * sizeof(uint16));
        heap_append_logic_data(session, cursor, GS_TRUE);
        log_atomic_op_end(session);
    }

    ua.old_cols = ROW_COLUMN_COUNT(cursor->row);
    ua.new_cols = entity->column_count;
    ua.info = &cursor->update_info;
    heap_update_prepare(session, cursor->row, cursor->offsets, cursor->lens, cursor->data_size, &ua);

    if (ua.new_size <= max_row_len) {
        status = pcrh_do_update(session, cursor, entity, &ua);
    } else {
        status = pcrh_convert_update(session, cursor, &ua);
    }

    SYNC_POINT(session, "SP_AFTER_HEAP_UPDATE");

    return status;
}

/*
 * PCR delete link row
 * @note delete every chain row and its link row
 * @attention for chain row, during row locking, we didn't alloc an itl for them,
 * we just alloc an itl for every chain using for fsc tracking.
 * @param kernel session, kernel cursor
 */
static status_t pcrh_delete_chain_rows(knl_session_t *session, knl_cursor_t *cursor)
{
    row_chain_t *chain = (row_chain_t *)cursor->chain_info;
    uint8 i;

    knl_panic_log(cursor->chain_info != NULL, "cursor's chain_info is NULL, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    /* we must delete origin row first to keep consistency */
    if (pcrh_simple_delete(session, cursor, cursor->rowid, PCRH_MIN_ROW_SIZE, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->is_found) {
        return GS_SUCCESS;
    }

    /* delete chain rows one by one */
    for (i = 0; i < cursor->chain_count; i++) {
        if (pcrh_lock_migr_row(session, cursor, chain[i].chain_rid) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (pcrh_simple_delete(session, cursor, chain[i].chain_rid, chain[i].row_size, GS_FALSE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
 * PCR delete link row
 * @note support delete migration row and chain row
 * @attention for migration row, during row locking, we didn't alloc an itl for it,
 * we just alloc an itl for it using for fsc tracking.
 * @param kernel session, kernel cursor
 */
static status_t pcrh_delete_link_row(knl_session_t *session, knl_cursor_t *cursor)
{
    if (cursor->chain_count > 1) {
        return pcrh_delete_chain_rows(session, cursor);
    }

    /* delete origin row */
    if (pcrh_simple_delete(session, cursor, cursor->rowid, PCRH_MIN_ROW_SIZE, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (!cursor->is_found) {
        return GS_SUCCESS;
    }

    /* delete migration row */
    if (pcrh_lock_migr_row(session, cursor, cursor->link_rid) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (pcrh_simple_delete(session, cursor, cursor->link_rid, cursor->row->size, GS_FALSE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/*
 * PCR heap delete interface
 * @note support single row delete and chain row delete
 * @param kernel session, kernel cursor
 */
status_t pcrh_delete(knl_session_t *session, knl_cursor_t *cursor)
{
    dc_entity_t *entity = NULL;

    SYNC_POINT(session, "SP_B4_HEAP_DELETE");
    knl_panic_log(cursor->is_valid, "current cursor is invalid, panic info: page %u-%u type %u table %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type,
                  ((table_t *)cursor->table)->desc.name);

    if (cursor->xid != session->rm->xid.value) {
        cursor->xid = session->rm->xid.value;
    }

    entity = (dc_entity_t *)cursor->dc_entity;
    bool32 has_logic = LOGIC_REP_DB_ENABLED(session) && dc_replication_enabled(session, entity, cursor->part_loc);

    if (has_logic && IS_LOGGING_TABLE_BY_TYPE(cursor->dc_type) && (!IS_SYS_TABLE(&entity->table))) {
        log_atomic_op_begin(session);
        log_put(session, RD_LOGIC_REP_DELETE, NULL, 0, LOG_ENTRY_FLAG_WITH_LOGIC_OID);
        heap_append_logic_data(session, cursor, GS_TRUE);
        log_atomic_op_end(session);
    }

    if (entity->contain_lob) {
        if (lob_delete(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (IS_INVALID_ROWID(cursor->link_rid)) {
        if (pcrh_simple_delete(session, cursor, cursor->rowid, cursor->row->size, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        if (pcrh_delete_link_row(session, cursor) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    SYNC_POINT(session, "SP_AFTER_HEAP_DELETE");

    return GS_SUCCESS;
}

void pcrh_undo_insert_row(knl_session_t *session, bool32 is_xfirst, uint16 slot, pcr_row_dir_t *dir, row_head_t *row)
{
    heap_page_t *page = (heap_page_t *)CURR_PAGE;
    if (page->free_begin == *dir + row->size) {
        page->free_begin = *dir;
    }

    /* free directly if is last and new allocated dir */
    if (is_xfirst) {
        if (slot + 1 == page->dirs) {
            /*
             * free_size and free_end both within DEFAULT_PAGE_SIZE,
             * sizeof(pcr_row_dir_t) is 2, so the sum less than max value(65535) of uint16.
             */
            page->free_end += sizeof(pcr_row_dir_t);
            page->free_size += sizeof(pcr_row_dir_t);
            page->dirs--;
        } else {
            *dir = page->first_free_dir | PCRH_DIR_NEW_MASK | PCRH_DIR_FREE_MASK;
            page->first_free_dir = (uint16)slot;
        }
    } else {
        *dir = page->first_free_dir | PCRH_DIR_FREE_MASK;
        page->first_free_dir = slot;
    }

    row->is_deleted = 1;
    page->rows--;
}
/*
 * PCR heap undo insert
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    rd_pcrh_undo_t redo;

    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    /* first of all, verify undo information on itl of target row */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    heap_page_t *page = (heap_page_t *)CURR_PAGE;
    pcr_row_dir_t *dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row_head_t *row = PCRH_GET_ROW(page, dir);
    pcr_itl_t *itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);

    pcrh_undo_insert_row(session, ud_row->is_xfirst, (uint16)rowid.slot, dir, row);

    /*
     * rollback itl information from undo
     * 1.we only need to set ssn until undo itl
     * 2.we just return row space to fsc and release all space when undo itl.
     */
    itl->fsc += row->size;
    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    redo.slot = (uint16)rowid.slot;
    redo.ssn = ud_row->ssn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;
    redo.is_xfirst = ud_row->is_xfirst;
    if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
        log_put(session, RD_PCRH_UNDO_INSERT, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
    }

    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo batch insert
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_batch_insert(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    pcr_itl_t *itl = NULL;
    row_head_t *row = NULL;
    rowid_t rowid;
    rd_pcrh_undo_t redo;
    page_id_t page_id;
    pcrh_undo_batch_insert_t *batch_undo = (pcrh_undo_batch_insert_t *)ud_row->data;

    rowid = ud_row->rowid;
    page_id = GET_ROWID_PAGE(rowid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    /* first of all, verify undo information on itl of target row */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)batch_undo->undos[0].slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);
    redo.ssn = itl->ssn;
    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;

    for (int32 i = batch_undo->count - 1; i >= 0; i--) {
        dir = pcrh_get_dir(page, batch_undo->undos[i].slot);
        row = PCRH_GET_ROW(page, dir);
        redo.is_xfirst = ud_row->is_xfirst ? ud_row->is_xfirst : batch_undo->undos[i].is_xfirst;
        pcrh_undo_insert_row(session, redo.is_xfirst, batch_undo->undos[i].slot, dir, row);

        itl->fsc += row->size;
        redo.slot = batch_undo->undos[i].slot;
        if (i == 0) {
            redo.ssn = ud_row->ssn;
            redo.undo_page = ud_row->prev_page;
            redo.undo_slot = ud_row->prev_slot;
            /*
             * rollback itl information from undo
             * 1.we only need to set ssn until undo itl
             * 2.we just return row space to fsc and release all space when undo itl.
             */
            itl->ssn = ud_row->ssn;
            itl->undo_page = ud_row->prev_page;
            itl->undo_slot = ud_row->prev_slot;
        }
        if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
            log_put(session, RD_PCRH_UNDO_INSERT, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
        }
    }

    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo delete
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_delete(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    row_head_t *org_row = NULL;
    pcr_itl_t *itl = NULL;
    rd_pcrh_undo_t redo;
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    errno_t ret;

    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    org_row = (row_head_t *)ud_row->data;

    /* first of all, verify undo information on itl of target row */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_deleted, "row is not deleted, panic info: ud_page %u-%u type %u, page %u-%u type %u",
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);

    if (row->size == org_row->size) {
        /* deleted row has not been compacted, we can rollback directly */
        row->is_deleted = 0;
    } else {
        /* row has been compact, we should find a new space in page to revert delete */
        knl_panic_log(row->size == sizeof(row_head_t),
                      "row's size is abnormal, panic info: ud_page %u-%u type %u, page %u-%u type %u row size %u",
                      AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                      page_id.file, page_id.page, page->head.type, row->size);

        if (page->free_end - page->free_begin < org_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, page);
        }

        *dir = page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE, row size PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16.
         */
        page->free_begin += org_row->size;
        knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                      "ud_page %u-%u type %u, page %u-%u type %u free_begin %u free_end %u",
                      AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                      page_id.file, page_id.page, page->head.type, page->free_begin, page->free_end);

        /* relocate the row position */
        row = PCRH_GET_ROW(page, dir);
        ret = memcpy_sp(row, page->free_end - *dir, org_row, org_row->size);
        knl_securec_check(ret);
    }

    knl_panic_log(itl->fsc >= row->size - sizeof(row_head_t),
        "itl's fsc is abnormal, panic info: ud_page %u-%u type %u, page %u-%u type %u itl fsc %u row size %u",
        AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
        page_id.page, page->head.type, itl->fsc, row->size);
    itl->fsc -= row->size - sizeof(row_head_t);
    page->rows++;

    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
    itl->ssn = ud_row->ssn;
    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    redo.slot = (uint16)rowid.slot;
    redo.is_xfirst = (uint8)ud_row->is_xfirst;
    redo.ssn = ud_row->ssn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;
    if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
        log_put(session, RD_PCRH_UNDO_DELETE, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, org_row, org_row->size);
    }
    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo update
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_update(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    rd_pcrh_undo_update_t redo;
    heap_page_t *page = NULL;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    row_head_t *org_row = NULL;
    pcr_itl_t *itl = NULL;
    rowid_t rowid = ud_row->rowid;
    page_id_t page_id = GET_ROWID_PAGE(rowid);
    int16 inc_size;
    errno_t ret;

    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    /* first of all, verify undo information on itl of target row */
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
                  itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);

    /*
     * UNDO_PCRH_UPDATE need to reorganize row
     */
    if (ud_row->type == UNDO_PCRH_UPDATE_FULL) {
        org_row = (row_head_t *)ud_row->data;
    } else {
        knl_panic_log(!row->is_link, "row is link, panic info: ud_page %u-%u type %u, page %u-%u type %u",
                      AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                      page_id.file, page_id.page, page->head.type);
        org_row = (row_head_t *)cm_push(session->stack, PCRH_MAX_MIGR_SIZE);
        pcrh_reorganize_undo_update(session, row, (heap_undo_update_info_t *)ud_row->data, org_row);
    }

    inc_size = org_row->size - row->size;

    /*
     * if need more space to rollback row, insert the origin row into free
     * begin directly and release older space
     */
    if (inc_size > 0) {
        if (page->free_end - page->free_begin < org_row->size) {
            *dir |= PCRH_DIR_FREE_MASK;
            pcrh_compact_page(session, page);
        }

        *dir = page->free_begin;
        /*
         * free_begin less than DEFAULT_PAGE_SIZE(8192), row size PCRH_MAX_ROW_SIZE,
         * the sum is less than max value(65535) of uint16
         */
        page->free_begin += org_row->size;
        knl_panic_log(page->free_begin <= page->free_end, "page's free size begin is more than end, panic info: "
                      "ud_page %u-%u type %u, page %u-%u type %u free_begin %u free_end %u",
                      AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page, ud_page->head.type,
                      page_id.file, page_id.page, page->head.type, page->free_begin, page->free_end);

        if (itl->fsc >= inc_size) {
            itl->fsc -= inc_size;
        } else {
            page->free_size -= (inc_size - itl->fsc);
            itl->fsc = 0;
        }

        row = PCRH_GET_ROW(page, dir);
    } else {
        /* inc_size is negative, itl->fsc and  abs(inc_size) is less than page size 8192 */
        itl->fsc -= inc_size;
    }

    ret = memcpy_sp(row, page->free_end - *dir, (char *)org_row, org_row->size);
    knl_securec_check(ret);

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }
    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    redo.slot = (uint16)rowid.slot;
    redo.is_xfirst = (uint8)ud_row->is_xfirst;
    redo.ssn = ud_row->ssn;
    redo.undo_page = ud_row->prev_page;
    redo.undo_slot = ud_row->prev_slot;
    redo.type = (uint8)ud_row->type;
    redo.aligned = 0;
    if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
        log_put(session, RD_PCRH_UNDO_UPDATE, &redo, sizeof(rd_pcrh_undo_update_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, org_row, org_row->size);
    }
    buf_leave_page(session, GS_TRUE);

    if (ud_row->type == UNDO_PCRH_UPDATE) {
        cm_pop(session->stack);
    }
}

/*
 * PCR heap undo update next row id
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_update_next_rid(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    heap_page_t *page = NULL;
    rowid_t rowid;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    rd_pcrh_undo_t redo;
    page_id_t page_id;

    rowid = ud_row->rowid;
    page_id = GET_ROWID_PAGE(rowid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_link || row->is_migr, "row is neither link nor migr, panic info: ud_page %u-%u type %u, "
                  "page %u-%u type %u", AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page,
                  ud_page->head.type, page_id.file, page_id.page, page->head.type);
    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
                  itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file,
                  page_id.page, page->head.type, itl->xid.value, session->rm->xid.value);

    /* rollback next rowid */
    *PCRH_NEXT_ROWID(row) = *(rowid_t *)ud_row->data;

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    redo.slot = (uint16)rowid.slot;
    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;
    redo.ssn = itl->ssn;
    redo.is_xfirst = ud_row->is_xfirst;
    if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
        log_put(session, RD_PCRH_UNDO_NEXT_RID, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, ud_row->data, sizeof(rowid_t));
    }
    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo lock link
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_update_link_ssn(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot)
{
    heap_page_t *page = NULL;
    rowid_t rowid;
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    pcr_itl_t *itl = NULL;
    rd_pcrh_undo_t redo;
    page_id_t page_id;

    rowid = ud_row->rowid;
    page_id = GET_ROWID_PAGE(rowid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    dir = pcrh_get_dir(page, (uint16)rowid.slot);
    row = PCRH_GET_ROW(page, dir);
    knl_panic_log(row->is_link, "row is not link, panic info: ud_page %u-%u type %u, page %u-%u type %u",
                  AS_PAGID(ud_page->head.id).file, AS_PAGID(ud_page->head.id).page,
                  ud_page->head.type, page_id.file, page_id.page, page->head.type);

    itl = pcrh_get_itl(page, ROW_ITL_ID(row));
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
                  "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
                  "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
                  itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: ud_page "
                  "%u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
                  AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
                  itl->xid.value, session->rm->xid.value);

    if (ud_row->is_xfirst) {
        ROW_SET_ITL_ID(row, GS_INVALID_ID8);
    }

    itl->ssn = ud_row->ssn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;

    redo.slot = (uint16)rowid.slot;
    redo.undo_page = itl->undo_page;
    redo.undo_slot = itl->undo_slot;
    redo.ssn = itl->ssn;
    redo.is_xfirst = ud_row->is_xfirst;
    if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
        log_put(session, RD_PCRH_UNDO_UPDATE_LINK_SSN, &redo, sizeof(rd_pcrh_undo_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap undo update
 * @param kernel session, undo row, undo page, undo slot
 */
void pcrh_undo_itl(knl_session_t *session, undo_row_t *ud_row, undo_page_t *ud_page, int32 ud_slot,
                   knl_dictionary_t *dc, heap_undo_assist_t *heap_assist)
{
    heap_page_t *page = NULL;
    pcr_itl_t *itl = NULL;
    heap_t *heap = NULL;
    rowid_t rowid;
    uint8 itl_id;
    uint8 owner_list;
    page_id_t page_id;

    rowid = ud_row->rowid;
    page_id = GET_ROWID_PAGE(rowid);
    if (!spc_validate_page_id(session, page_id)) {
        return;
    }

    /* first of all, verify undo information on itl of target row */
    itl_id = (uint8)rowid.slot;
    buf_enter_page(session, page_id, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    page = (heap_page_t *)CURR_PAGE;
    itl = pcrh_get_itl(page, itl_id);
    knl_panic_log(IS_SAME_PAGID(itl->undo_page, AS_PAGID(ud_page->head.id)), "itl's undo_page and ud_page are not "
        "same page, panic info: ud_page %u-%u type %u, page %u-%u type %u", AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type);
    knl_panic_log(itl->undo_slot == ud_slot, "itl's undo_slot and ud_slot are not equal, panic info: ud_page %u-%u "
        "type %u page %u-%u type %u itl undo_slot %u ud_slot %u", AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
        itl->undo_slot, ud_slot);
    knl_panic_log(itl->xid.value == session->rm->xid.value, "the xid of itl and rm are not equal, panic info: "
        "ud_page %u-%u type %u page %u-%u type %u itl xid %llu rm xid %llu", AS_PAGID(ud_page->head.id).file,
        AS_PAGID(ud_page->head.id).page, ud_page->head.type, page_id.file, page_id.page, page->head.type,
        itl->xid.value, session->rm->xid.value);

    /* undo itl means rollback to last transaction, so we need to recover scn and xid on itl */
    page->free_size += itl->fsc;  // itl->fsc and free_size is both less than page size(8192)

    itl->xid = *(xid_t *)ud_row->data;
    itl->scn = ud_row->scn;
    itl->is_owscn = ud_row->is_owscn;
    itl->undo_page = ud_row->prev_page;
    itl->undo_slot = ud_row->prev_slot;
    itl->is_active = GS_FALSE;

    if (SPC_IS_LOGGING_BY_PAGEID(page_id)) {
        log_put(session, RD_PCRH_UNDO_ITL, itl, sizeof(pcr_itl_t), LOG_ENTRY_FLAG_NONE);
        log_append_data(session, &itl_id, sizeof(uint8));
    }

    knl_part_locate_t part_loc = ((pcrh_undo_itl_t *)ud_row->data)->part_loc;

    heap = dc_get_heap(session, page->uid, page->oid, part_loc, dc);
    owner_list = heap_get_owner_list(session, (heap_segment_t *)heap->segment, page->free_size);
    heap_assist->change_list[0] = owner_list - (uint8)page->map.list_id;
    heap_assist->page_id[0] = page_id;

    heap_assist->heap = heap;
    heap_assist->rows = 1;

    buf_leave_page(session, GS_TRUE);
}

/*
 * PCR heap validate page
 * @param kernel session, page
 */
void pcrh_validate_page(knl_session_t *session, page_head_t *page)
{
    space_t *space = SPACE_GET(DATAFILE_GET(AS_PAGID_PTR(page->id)->file)->space_id);
    uint32 total_fsc = 0;

    heap_page_t *copy_page = (heap_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE);
    errno_t ret = memcpy_sp(copy_page, DEFAULT_PAGE_SIZE, page, DEFAULT_PAGE_SIZE);
    knl_securec_check(ret);

    for (uint8 j = 0; j < copy_page->itls; j++) {
        pcr_itl_t *itl = pcrh_get_itl(copy_page, j);
        if (itl->is_active) {
            knl_panic_log(itl->xid.value != GS_INVALID_ID64,
                          "itl's xid is invalid, panic info: copy_page %u-%u type %u, page %u-%u type %u",
                          AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
                          AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);
            /* the sum of itl's fsc is less than page size(8192) */
            total_fsc += itl->fsc;
        }
    }

    for (uint16 i = 0; i < copy_page->dirs; i++) {
        pcr_row_dir_t *dir = pcrh_get_dir(copy_page, i);
        if (PCRH_DIR_IS_FREE(dir)) {
            continue;
        }
        knl_panic_log(*dir < copy_page->free_begin, "Position of dir is wrong, panic info: copy_page %u-%u "
            "type %u free_begin %u, page %u-%u type %u dir's position %u", AS_PAGID(copy_page->head.id).file,
            AS_PAGID(copy_page->head.id).page, copy_page->head.type, copy_page->free_begin, AS_PAGID(page->id).file,
            AS_PAGID(page->id).page, page->type, *dir);
        knl_panic_log(*dir >= sizeof(heap_page_t) + space->ctrl->cipher_reserve_size, "Position of dir is wrong, "
            "panic info: copy_page %u-%u type %u, page %u-%u type %u dir's position %u cipher_reserve_size %u",
            AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page, copy_page->head.type,
            AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, *dir, space->ctrl->cipher_reserve_size);
        row_head_t *row = PCRH_GET_ROW(copy_page, dir);
        uint8 itl_id = ROW_ITL_ID(row);
        knl_panic_log(itl_id == GS_INVALID_ID8 || itl_id < copy_page->itls, "itl_id is abnormal, panic info: " 
                      "copy_page itls %u copy_page %u-%u type %u, page %u-%u type %u itl_id %u",
                      copy_page->itls, AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page,
                      copy_page->head.type, AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, itl_id);
    }

    pcrh_compact_page(session, copy_page);
    knl_panic_log(copy_page->free_begin + copy_page->free_size + total_fsc == copy_page->free_end,
                  "copy_page is abnormal, panic info: copy_page %u-%u type %u free_begin %u free_size %u free_end %u "
                  "total_fsc %u, page %u-%u type %u", copy_page->free_begin, copy_page->free_size, copy_page->free_end,
                  total_fsc, AS_PAGID(copy_page->head.id).file, AS_PAGID(copy_page->head.id).page,
                  copy_page->head.type, AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);
    cm_pop(session->stack);
}

/*
 * PCR dump page information
 * @param kernel session, page
 */
status_t pcrh_dump_page(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    heap_page_t *page = (heap_page_t *)page_head;

    cm_dump(dump, "heap page information\n");

    cm_dump(dump, "\tmap index info: map %u-%u, lid %u, &lenth %u\n",
        (uint32)page->map.file, (uint32)page->map.page, (uint32)page->map.list_id, (uint32)page->map.slot);
    cm_dump(dump, "\ttable info: uid %u, oid %u, org_scn %llu, seg_scn %llu\n",
        page->uid, page->oid, page->org_scn, page->seg_scn);
    cm_dump(dump, "\tpage info: next_page %u-%u, free_begin %u, free_end %u, free_size %u, first_free_dir %u ",
        AS_PAGID_PTR(page->next)->file, AS_PAGID_PTR(page->next)->page, page->free_begin,
        page->free_end, page->free_size, page->first_free_dir);
    cm_dump(dump, "itls %u, dirs %u, rows %u\n", page->itls, page->dirs, page->rows);

    cm_dump(dump, "itl information on this page\n");

    CM_DUMP_WRITE_FILE(dump);
    pcr_itl_t *itl = NULL;
    for (uint8 slot_itl = 0; slot_itl < page->itls; slot_itl++) {
        itl = pcrh_get_itl(page, slot_itl);

        cm_dump(dump, "\tslot: #%-3u", slot_itl);
        cm_dump(dump, "\tscn: %llu", itl->scn);
        cm_dump(dump, "\txmap: %u-%u", itl->xid.xmap.seg_id, itl->xid.xmap.slot);
        cm_dump(dump, "\txnum: %u", itl->xid.xnum);
        cm_dump(dump, "\tfsc: %u", itl->fsc);
        cm_dump(dump, "\tis_active: %u", itl->is_active);
        cm_dump(dump, "\tis_owscn: %u\n", itl->is_owscn);
        cm_dump(dump, "\tis_hist: %u\n", itl->is_hist);
        cm_dump(dump, "\tis_fast: %u\n", itl->is_fast);

        CM_DUMP_WRITE_FILE(dump);
    }

    cm_dump(dump, "row information on this page\n");
    pcr_row_dir_t *dir = NULL;
    row_head_t *row = NULL;
    for (uint16 slot_dir = 0; slot_dir < page->dirs; slot_dir++) {
        dir = pcrh_get_dir(page, slot_dir);
        cm_dump(dump, "\tslot: #%-3u", slot_dir);
        cm_dump(dump, "\toffset: %-5u", dir);

        if (PCRH_DIR_IS_FREE(dir)) {
            cm_dump(dump, "\t(free_dir)\n");
            CM_DUMP_WRITE_FILE(dump);
            continue;
        }

        row = PCRH_GET_ROW(page, dir);
        cm_dump(dump, "\tsize: %u", row->size);
        cm_dump(dump, "\tcols: %u", ROW_COLUMN_COUNT(row));
        cm_dump(dump, "\titl_id: %u", ROW_ITL_ID(row));
        cm_dump(dump, "\tdeleted/link/migr/self_chg/changed %u/%u/%u/%u/%u\n",
            row->is_deleted, row->is_link, row->is_migr, row->self_chg, row->is_changed);

        CM_DUMP_WRITE_FILE(dump);
    }
    return GS_SUCCESS;
}

