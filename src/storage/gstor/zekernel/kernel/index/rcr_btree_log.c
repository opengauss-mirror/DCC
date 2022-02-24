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
 * rcr_btree_log.c
 *    implement of btree index redo
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/index/rcr_btree_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "rcr_btree_log.h"
#include "index_common.h"
#include "knl_context.h"

void rd_btree_init_segment(knl_session_t *session, log_entry_t *log)
{
    btree_segment_t *segment = BTREE_GET_SEGMENT;
    errno_t err;

    err = memcpy_sp(segment, sizeof(btree_segment_t), log->data, sizeof(btree_segment_t));
    knl_securec_check(err);
}

void print_btree_init_segment(log_entry_t *log)
{
    btree_segment_t *seg = (btree_segment_t *)log->data;

    printf("uid %u, table_id %u, index_id %u, space %u, initrans %u, pctfree %u, "
           "org_scn %llu, seg_scn %llu, crmode %u, ",
           seg->uid, seg->table_id, seg->index_id, seg->space_id, seg->initrans, seg->pctfree,
           seg->org_scn, seg->seg_scn, seg->cr_mode);

    printf("btree(root %u-%u, level %u), ", (uint32)AS_PAGID(seg->tree_info.root).file,
           (uint32)AS_PAGID(seg->tree_info.root).page, (uint32)seg->tree_info.level);
    printf("extents(count %u, first %u-%u, last %u-%u), ufp_count %u, ufp_first %u-%u, ufp_extent %u-%u, ",
           seg->extents.count,
           (uint32)seg->extents.first.file, (uint32)seg->extents.first.page, (uint32)seg->extents.last.file,
           (uint32)seg->extents.last.page,
           seg->ufp_count, (uint32)seg->ufp_first.file, (uint32)seg->ufp_first.page, (uint32)seg->ufp_extent.file,
           (uint32)seg->ufp_extent.page);
    printf("del_scn %llu, del_pages(count %u, first %u-%u, last %u-%u)\n", seg->del_scn, seg->del_pages.count,
           (uint32)seg->del_pages.first.file, (uint32)seg->del_pages.first.page, (uint32)seg->del_pages.last.file,
           (uint32)seg->del_pages.last.page);
}

void rd_btree_init_entry(knl_session_t *session, log_entry_t *log)
{
    page_head_t *page = (page_head_t *)CURR_PAGE;
    rd_btree_init_entry_t *redo = (rd_btree_init_entry_t *)log->data;
    page_init(session, page, redo->page_id, PAGE_TYPE_BTREE_HEAD);
    page->ext_size = spc_ext_id_by_size(redo->extent_size);
}

void print_btree_init_entry(log_entry_t *log)
{
    page_id_t *redo = (page_id_t *)log->data;
    printf("entry %u-%u\n", (uint32)redo->file, (uint32)redo->page);
}

void rd_btree_format_page(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page = BTREE_CURR_PAGE;
    rd_btree_page_init_t *redo = (rd_btree_page_init_t *)log->data;

    btree_init_page(session, page, redo);
}

void print_btree_format_page(log_entry_t *log)
{
    rd_btree_page_init_t *redo = (rd_btree_page_init_t *)log->data;

    printf("cr_mode %u seg_scn %llu level %u page_id %u-%u itls %u extent_size %u reserve_ext %u\n", 
           (uint32)redo->cr_mode, redo->seg_scn, (uint32)redo->level,
           (uint32)redo->page_id.file, (uint32)redo->page_id.page, (uint32)redo->itls,
           (uint32)redo->extent_size, (uint32)redo->reserve_ext);
}

void rd_btree_change_seg(knl_session_t *session, log_entry_t *log)
{
    btree_segment_t *btree = BTREE_GET_SEGMENT;
    errno_t err;

    err = memcpy_sp(btree, sizeof(btree_segment_t), (btree_segment_t *)log->data, sizeof(btree_segment_t));
    knl_securec_check(err);
}

void print_btree_change_seg(log_entry_t *log)
{
    btree_segment_t *seg = (btree_segment_t *)log->data;

    printf("uid %u, table_id %u, index_id %u, space %u, initrans %u, pctfree %u, "
           "org_scn %llu, seg_scn %llu, crmode %u, ",
           seg->uid, seg->table_id, seg->index_id, seg->space_id, seg->initrans, seg->pctfree,
           seg->org_scn, seg->seg_scn, seg->cr_mode);
    printf("btree(root %u-%u, level %u), ", (uint32)AS_PAGID(seg->tree_info.root).file,
           (uint32)AS_PAGID(seg->tree_info.root).page, (uint32)seg->tree_info.level);
    printf("extents(count %u, first %u-%u, last %u-%u), ufp_count %u, ufp_first %u-%u, ufp_extent %u-%u, ",
           seg->extents.count, (uint32)seg->extents.first.file, (uint32)seg->extents.first.page,
           (uint32)seg->extents.last.file, (uint32)seg->extents.last.page, seg->ufp_count,
           (uint32)seg->ufp_first.file, (uint32)seg->ufp_first.page,
           (uint32)seg->ufp_extent.file, (uint32)seg->ufp_extent.page);
    printf("del_scn %llu, del_pages(count %u, first %u-%u, last %u-%u), ", seg->del_scn, seg->del_pages.count,
           (uint32)seg->del_pages.first.file, (uint32)seg->del_pages.first.page,
           (uint32)seg->del_pages.last.file, (uint32)seg->del_pages.last.page);
    printf("page_count %u\n", seg->page_count);
}

void rd_btree_delete(knl_session_t *session, log_entry_t *log)
{
    rd_btree_delete_t *redo = (rd_btree_delete_t *)log->data;
    btree_delete_key(session, BTREE_CURR_PAGE, redo);
}

void print_btree_delete(log_entry_t *log)
{
    rd_btree_delete_t *redo = (rd_btree_delete_t *)log->data;

    printf("slot %u, ssn %u, itl_id %u, undo_page %u-%u, undo_slot %u\n", (uint32)redo->slot, redo->ssn,
           (uint32)redo->itl_id, (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void rd_btree_compact(knl_session_t *session, log_entry_t *log)
{
    knl_scn_t scn = *(knl_scn_t *)log->data;

    if (session->kernel->db.status > DB_STATUS_RECOVERY && log->size > sizeof(knl_scn_t) + LOG_ENTRY_SIZE) {
        rd_btree_info_t btree_info;

        btree_info = *(rd_btree_info_t *)log->data;
        btree_set_min_scn(session, btree_info);
    }

    btree_compact_page(session, BTREE_CURR_PAGE, scn);
}

void print_btree_compact(log_entry_t *log)
{
    knl_scn_t scn = *(knl_scn_t *)log->data;

    printf("min_scn %llu\n", scn);
}

void rd_btree_insert(knl_session_t *session, log_entry_t *log)
{
    rd_btree_insert_t *redo = (rd_btree_insert_t *)log->data;
    btree_key_t *key = (btree_key_t *)redo->key;
    btree_insert_into_page(session, BTREE_CURR_PAGE, key, redo);
}

void print_btree_insert(log_entry_t *log)
{
    rd_btree_insert_t *redo = (rd_btree_insert_t *)log->data;
    btree_key_t *key = (btree_key_t *)redo->key;

    printf("slot %u, itl_id %u, is_reuse %u, ", (uint32)redo->slot, (uint32)redo->itl_id, (uint32)redo->is_reuse);
    printf("key: size %u, scn %llu, owscn/deleted/infinite/cleaned %u/%u/%u/%u, ", (uint32)key->size, key->scn,
           (uint32)key->is_owscn, (uint32)key->is_deleted, (uint32)key->is_infinite, (uint32)key->is_cleaned);
    printf("heap_page %u-%u, heap_slot %u, undo_page %u-%u, undo_slot %u\n",
           (uint32)key->rowid.file, (uint32)key->rowid.page, (uint32)key->rowid.slot,
           (uint32)key->undo_page.file, (uint32)key->undo_page.page, (uint32)key->undo_slot);
}

void rd_btree_clean_moved_keys(knl_session_t *session, log_entry_t *log)
{
    rd_btree_clean_keys_t *redo = (rd_btree_clean_keys_t *)log->data;
    btree_page_t *page = BTREE_CURR_PAGE;
    btree_dir_t *dir = NULL;
    btree_key_t *key = NULL;
    uint16 i;

    for (i = redo->keys; i < page->keys; i++) {
        dir = BTREE_GET_DIR(page, i);
        key = BTREE_GET_KEY(page, dir);
        if (!key->is_cleaned) {
            key->is_cleaned = (uint16)GS_TRUE;
        }
    }
    page->keys = redo->keys;
    page->free_size = redo->free_size;
    page->free_end = (uint16)((char *)BTREE_GET_DIR(page, page->keys - 1) - (char *)page);
}

void print_btree_clean_moved_keys(log_entry_t *log)
{
    rd_btree_clean_keys_t *redo = (rd_btree_clean_keys_t *)log->data;

    printf("keys %u, free_size %u\n", (uint32)redo->keys, (uint32)redo->free_size);
}

void rd_btree_new_itl(knl_session_t *session, log_entry_t *log)
{
    xid_t xid = *(xid_t *)log->data;
    btree_page_t *page = BTREE_CURR_PAGE;
    uint8 itl_id = btree_new_itl(session, page);
    itl_t *itl = BTREE_GET_ITL(page, itl_id);
    tx_init_itl(session, itl, xid);
}

void print_btree_new_itl(log_entry_t *log)
{
    xid_t *redo = (xid_t *)log->data;

    printf("xmap %u-%u, xnum %u\n", (uint32)redo->xmap.seg_id, (uint32)redo->xmap.slot, redo->xnum);
}

void rd_btree_reuse_itl(knl_session_t *session, log_entry_t *log)
{
    rd_btree_reuse_itl_t *redo = (rd_btree_reuse_itl_t *)log->data;
    btree_page_t *page = BTREE_CURR_PAGE;
    itl_t *itl = BTREE_GET_ITL(page, redo->itl_id);

    btree_reuse_itl(session, page, itl, redo->itl_id, redo->min_scn);
    tx_init_itl(session, itl, redo->xid);
}

void print_btree_reuse_itl(log_entry_t *log)
{
    rd_btree_reuse_itl_t *redo = (rd_btree_reuse_itl_t *)log->data;

    printf("itl_id %u, xmap %u-%u, xnum %u, min_scn %llu\n", (uint32)redo->itl_id,
           (uint32)redo->xid.xmap.seg_id, (uint32)redo->xid.xmap.slot, redo->xid.xnum, (uint64)redo->min_scn);
}

void rd_btree_extent_itl(knl_session_t *session, log_entry_t *log)
{
    (void)btree_new_itl(session, BTREE_CURR_PAGE);
}

void rd_btree_clean_itl(knl_session_t *session, log_entry_t *log)
{
    rd_btree_clean_itl_t *redo = (rd_btree_clean_itl_t *)log->data;
    btree_page_t *page = BTREE_CURR_PAGE;
    itl_t *itl = BTREE_GET_ITL(page, redo->itl_id);
    itl->scn = redo->scn;
    itl->is_active = 0;
    itl->is_owscn = redo->is_owscn;
    itl->is_copied = redo->is_copied;
    itl->xid.value = GS_INVALID_ID64;
}

void print_btree_clean_itl(log_entry_t *log)
{
    rd_btree_clean_itl_t *redo = (rd_btree_clean_itl_t *)log->data;

    printf("itl_id %u, scn %llu, is_owscn %u, is_copied %u\n", (uint32)redo->itl_id,
           redo->scn, (uint32)redo->is_owscn, (uint32)redo->is_copied);
}

void rd_btree_undo_insert(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page;
    btree_dir_t *dir;
    btree_key_t *key;
    rd_btree_undo_t *redo = (rd_btree_undo_t *)log->data;

    page = BTREE_CURR_PAGE;
    dir = BTREE_GET_DIR(page, redo->slot);
    key = BTREE_GET_KEY(page, dir);

    key->undo_page = redo->undo_page;
    key->undo_slot = redo->undo_slot;
    key->scn = redo->scn;
    key->is_owscn = redo->is_owscn;
    key->is_deleted = GS_TRUE;
    key->rowid = redo->rowid;

    if (redo->is_xfirst) {
        dir->itl_id = GS_INVALID_ID8;
    }
}

void print_btree_undo_insert(log_entry_t *log)
{
    rd_btree_undo_t *redo = (rd_btree_undo_t *)log->data;
    printf("slot %u, is_xfirst %u, scn %llu, is_owscn %u, ", (uint32)redo->slot, (uint32)redo->is_xfirst, redo->scn,
           (uint32)redo->is_owscn);
    printf("heap_page %u-%u, heap_slot %u, undo_page %u-%u, undo_slot %u\n",
           (uint32)redo->rowid.file, (uint32)redo->rowid.page, (uint32)redo->rowid.slot,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void rd_btree_undo_delete(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page;
    btree_dir_t *dir;
    btree_key_t *key;
    rd_btree_undo_t *redo = (rd_btree_undo_t *)log->data;

    page = BTREE_CURR_PAGE;
    dir = BTREE_GET_DIR(page, redo->slot);
    key = BTREE_GET_KEY(page, dir);

    key->undo_page = redo->undo_page;
    key->undo_slot = redo->undo_slot;
    key->scn = redo->scn;
    key->is_owscn = redo->is_owscn;
    key->is_deleted = GS_FALSE;

    if (redo->is_xfirst) {
        dir->itl_id = GS_INVALID_ID8;
    }
}

void print_btree_undo_delete(log_entry_t *log)
{
    rd_btree_undo_t *redo = (rd_btree_undo_t *)log->data;
    printf("slot %u, is_xfirst %u, scn %llu, is_owscn %u, ", (uint32)redo->slot, (uint32)redo->is_xfirst, redo->scn,
           (uint32)redo->is_owscn);
    printf("heap_page %u-%u, heap_slot %u, undo_page %u-%u, undo_slot %u\n",
           (uint32)redo->rowid.file, (uint32)redo->rowid.page, (uint32)redo->rowid.slot,
           (uint32)redo->undo_page.file, (uint32)redo->undo_page.page, (uint32)redo->undo_slot);
}

void rd_btree_change_chain(knl_session_t *session, log_entry_t *log)
{
    page_id_t *prev = (page_id_t *)log->data;
    btree_page_t *page = BTREE_CURR_PAGE;

    TO_PAGID_DATA(*prev, page->prev);
    TO_PAGID_DATA(*(prev + 1), page->next);
}

void print_btree_change_chain(log_entry_t *log)
{
    page_id_t *prev = (page_id_t *)log->data;
    page_id_t *next = prev + 1;

    printf("prev_page %u-%u, next_page %u-%u\n", (uint32)prev->file, (uint32)prev->page,
           (uint32)next->file, (uint32)next->page);
}

void rd_btree_copy_itl(knl_session_t *session, log_entry_t *log)
{
    itl_t *itl = (itl_t *)log->data;

    (void)btree_copy_itl(session, itl, BTREE_CURR_PAGE);
}

void print_btree_copy_itl(log_entry_t *log)
{
    itl_t *redo = (itl_t *)log->data;

    printf("xmap %u-%u, xnum %u, scn %llu, owscn/active/copied %u/%u/%u\n", (uint32)redo->xid.xmap.seg_id,
           (uint32)redo->xid.xmap.slot, redo->xid.xnum, redo->scn, redo->is_owscn, redo->is_active, redo->is_copied);
}

void rd_btree_copy_key(knl_session_t *session, log_entry_t *log)
{
    btree_dir_t *dir = NULL;
    btree_key_t *dst_key;
    btree_page_t *page = BTREE_CURR_PAGE;
    btree_key_t *key = (btree_key_t *)log->data;
    uint8 *itl_id = (uint8 *)((char *)log->data + CM_ALIGN4((uint32)key->size));
    errno_t err;

    dst_key = (btree_key_t *)((char *)page + page->free_begin);
    err = memcpy_sp(dst_key, GS_KEY_BUF_SIZE, key, (size_t)key->size);
    knl_securec_check(err);
    dir = BTREE_GET_DIR(page, page->keys);
    dir->offset = page->free_begin;
    dir->itl_id = *itl_id;
    page->free_begin += (uint16)key->size;
    page->free_end -= sizeof(btree_dir_t);
    page->free_size -= ((uint16)key->size + sizeof(btree_dir_t));
    page->keys++;
}

void print_btree_copy_key(log_entry_t *log)
{
    btree_key_t *key = (btree_key_t *)log->data;

    printf("size %u, scn %llu, owscn/deleted/infinite/cleaned %u/%u/%u/%u, ", (uint32)key->size, key->scn,
           (uint32)key->is_owscn, (uint32)key->is_deleted, (uint32)key->is_infinite, (uint32)key->is_cleaned);
    printf("heap_page %u-%u, heap_slot %u, undo_page %u-%u, undo_slot %u\n",
           (uint32)key->rowid.file, (uint32)key->rowid.page, (uint32)key->rowid.slot,
           (uint32)key->undo_page.file, (uint32)key->undo_page.page, (uint32)key->undo_slot);
}

void rd_btree_construct_page(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page = BTREE_CURR_PAGE;
    char *page_body = log->data;
    errno_t err;

    err = memcpy_sp(BTREE_PAGE_BODY(page), BTREE_PAGE_BODY_SIZE(page), page_body, BTREE_PAGE_BODY_SIZE(page));
    knl_securec_check(err);
}

void rd_btree_change_itl_copied(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page = BTREE_CURR_PAGE;
    itl_t *itl = NULL;
    uint8 *itl_map = (uint8 *)log->data;
    uint8 i;

    for (i = 0; i < page->itls; i++) {
        if (itl_map[i] != GS_INVALID_ID8) {
            itl = BTREE_GET_ITL(page, i);
            itl->is_copied = 1;
        }
    }
}

void rd_btree_clean_key(knl_session_t *session, log_entry_t *log)
{
    uint16 redo_dir = *(uint16 *)log->data;
    btree_page_t *page = BTREE_CURR_PAGE;

    btree_clean_key(session, page, redo_dir);
}

void print_btree_clean_key(log_entry_t *log)
{
    uint16 redo_dir = *(uint16 *)log->data;

    printf("slot %u\n", (uint32)redo_dir);
}

void rd_btree_set_recycle(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page = BTREE_CURR_PAGE;
    page_id_t *next_del_page = NULL;
    // get space use for BTREE_NEXT_DEL_PAGE
    space_t *space = SPACE_GET(DATAFILE_GET(AS_PAGID_PTR(page->head.id)->file)->space_id);
    page->is_recycled = 1;

    if (log->size > LOG_ENTRY_SIZE) {
        rd_btree_info_t btree_info;
        btree_info = *(rd_btree_info_t *)log->data;
        btree_set_min_scn(session, btree_info);
    }
    next_del_page = BTREE_NEXT_DEL_PAGE;
    *next_del_page = INVALID_PAGID;
}

void rd_btree_next_del_page(knl_session_t *session, log_entry_t *log)
{
    page_id_t *next_del_page = NULL;
    page_id_t leaf_id = *(page_id_t *)log->data;
    // get space use for BTREE_NEXT_DEL_PAGE
    space_t *space = SPACE_GET(DATAFILE_GET(leaf_id.file)->space_id);
    next_del_page = BTREE_NEXT_DEL_PAGE;
    *next_del_page = leaf_id;
}

void print_btree_next_del_page(log_entry_t *log)
{
    page_id_t leaf_id = *(page_id_t *)log->data;

    printf("next delete page %u-%u:", (uint32)leaf_id.file, (uint32)leaf_id.page);
}

void rd_btree_update_partid(knl_session_t *session, log_entry_t *log)
{
    btree_page_t *page = BTREE_CURR_PAGE;
    rd_update_btree_partid_t *redo = (rd_update_btree_partid_t *)log->data;

    btree_dir_t *dir = BTREE_GET_DIR(page, redo->slot);
    btree_key_t *key = BTREE_GET_KEY(page, dir);

    if (redo->is_compart_table) {
        *(uint32 *)((char *)key + key->size - sizeof(uint32)) = redo->parent_partid;
        *(uint32 *)((char *)key + key->size - sizeof(uint32) - sizeof(uint32)) = redo->part_id;
    } else {
        *(uint32 *)((char *)key + key->size - sizeof(uint32)) = redo->part_id;
    }
}

void print_update_btree_partid(log_entry_t *log)
{
    rd_update_btree_partid_t *redo = (rd_update_btree_partid_t *)log->data;
    if (redo->is_compart_table) {
        printf("new part id appended to the key: part_id %d, parent_partid %d\n", redo->part_id, redo->parent_partid);
    } else {
        printf("new part id appended to the key: part_id %d\n", redo->part_id);
    }
}
