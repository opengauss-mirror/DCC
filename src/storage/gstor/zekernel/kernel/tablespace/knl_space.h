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
 * knl_space.h
 *    kernel space manager
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/tablespace/knl_space.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SPACE_H__
#define __KNL_SPACE_H__

#include "cm_defs.h"
#include "cm_latch.h"
#include "cm_list.h"
#include "cm_text.h"
#include "knl_datafile.h"
#include "knl_log.h"
#include "knl_session.h"
#include "knl_abr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYS_SPACE_ID  0


/*
 * page distribution in datafile with bitmap including double write area :
 * ----- ------ ----------------------- ------ --------------------------------------------------
 * |file_hdr|spc head|border| double write district |border| map head | map pages | data pages
 * ----- ------ ----------------------- ------ ---------------------------------------------------
 *    1         1      2          8*1024                2       1         121         ...
 * in normap datafile, hwm start following the border.
 */
#define DOUBLE_WRITE_PAGES  (uint32)(8 * 1024)
#define DW_DISTRICT_BEGIN   (uint32)4
#define DW_DISTRICT_END     (uint32)(DW_DISTRICT_BEGIN + DOUBLE_WRITE_PAGES)
#define DW_SPC_HWM_START    (uint32)(DW_DISTRICT_END + 2)
#define DW_DISTRICT_PAGES   (uint32)(DOUBLE_WRITE_PAGES + 4)

#define DW_MAP_HEAD_PAGE     DW_SPC_HWM_START
#define DW_MAP_INIT_SIZE    121
#define DW_MAP_HWM_START    (uint32)(DW_MAP_HEAD_PAGE + DW_MAP_INIT_SIZE)

#define SPACE_HEAD_END          2
#define SPACE_ENTRY_PAGE        (uint32)1
#define SPACE_MDL_LATCH_TIMEOUT 5

#define SPACE_FLAG_ONLINE       0x0001
#define SPACE_FLAG_TEMPORARY    0x0002
#define SPACE_FLAG_INMEMORY     0x0004
#define SPACE_FLAG_AUTOPURGE    0x0008
#define SPACE_FLAG_NOLOGGING    0x0010
#define SPACE_FLAG_AUTOOFFLINE  0x0020
#define SPACE_FLAG_AUTOALLOCATE 0x0040       // extent size of segment is dynamic or not
#define SPACE_FLAG_BIMAPMANAGED 0x0080       // extent is managed by bitmap or list
#define SPACE_FLAG_ENCRYPT      0x0100

#define SPACE_IS_AUTOOFFLINE(space)    ((space)->ctrl->flag & SPACE_FLAG_AUTOOFFLINE)
#define SPACE_SET_AUTOOFFLINE(space)   CM_SET_FLAG((space)->ctrl->flag, SPACE_FLAG_AUTOOFFLINE)
#define SPACE_UNSET_AUTOOFFLINE(space) CM_CLEAN_FLAG((space)->ctrl->flag, SPACE_FLAG_AUTOOFFLINE)

// this is only be used in scanrio:
// 1,elder version(do not have type), upgrade to 'typed' version
// 2,new verison need to know this space is nologging (elder version have set flg)
// 3,for 'typed' version, will not hit 'SPACE_FLAG_NOLOGGING'
#define SPACE_IS_USER_NOLOGGING(space) ((space)->ctrl->flag & SPACE_FLAG_NOLOGGING)

#define SPACE_IS_ONLINE(space)    ((space)->ctrl->flag & SPACE_FLAG_ONLINE)
#define SPACE_SET_ONLINE(space)    CM_SET_FLAG((space)->ctrl->flag, SPACE_FLAG_ONLINE)
#define SPACE_UNSET_ONLINE(space)  CM_CLEAN_FLAG((space)->ctrl->flag, SPACE_FLAG_ONLINE)

#define IS_DEFAULT_SPACE(space) (((space)->ctrl->type & SPACE_TYPE_DEFAULT) != 0)
#define IS_SYSTEM_SPACE(space) (((space)->ctrl->type & SPACE_TYPE_SYSTEM) != 0)
#define IS_SYSAUX_SPACE(space) (((space)->ctrl->type & SPACE_TYPE_SYSAUX) != 0)
#define IS_UNDO_SPACE(space) (((space)->ctrl->type & SPACE_TYPE_UNDO) != 0)
#define IS_TEMP_SPACE(space) (((space)->ctrl->type & SPACE_TYPE_TEMP) != 0)
#define IS_SWAP_SPACE(space) (((space)->ctrl->type & SPACE_TYPE_SWAP) != 0)
#define IS_USER_SPACE(space) (((space)->ctrl->type & SPACE_TYPE_USERS) != 0)

#define SPACE_IS_INMEMORY(space)    ((space)->ctrl->flag & SPACE_FLAG_INMEMORY)
#define SPACE_SET_INMEMORY(space)   CM_SET_FLAG((space)->ctrl->flag, SPACE_FLAG_INMEMORY)
#define SPACE_UNSET_INMEMORY(space) CM_CLEAN_FLAG((space)->ctrl->flag, SPACE_FLAG_INMEMORY)

#define SPACE_IS_AUTOPURGE(space)    ((space)->ctrl->flag & SPACE_FLAG_AUTOPURGE)
#define SPACE_SET_AUTOPURGE(space)   CM_SET_FLAG((space)->ctrl->flag, SPACE_FLAG_AUTOPURGE)
#define SPACE_UNSET_AUTOPURGE(space) CM_CLEAN_FLAG((space)->ctrl->flag, SPACE_FLAG_AUTOPURGE)

#define SPACE_IS_LOGGING(space)     (((space)->ctrl->type & SPACE_TYPE_TEMP) == 0)
#define SPC_IS_LOGGING_BY_PAGEID(pagid) (SPACE_IS_LOGGING(SPACE_GET((DATAFILE_GET((pagid).file))->space_id)))
#define SPACE_IS_NOLOGGING(space)   (((space)->ctrl->type & SPACE_TYPE_TEMP) != 0)
#define SPACE_IS_DEFAULT(space)     (((space)->ctrl->type & SPACE_TYPE_DEFAULT) != 0)

#define SPACE_IS_AUTOALLOCATE(space)    ((space)->ctrl->flag & SPACE_FLAG_AUTOALLOCATE)
#define SPACE_SET_AUTOALLOCATE(space)   CM_SET_FLAG((space)->ctrl->flag, SPACE_FLAG_AUTOALLOCATE)
#define SPACE_UNSET_AUTOALLOCATE(space) CM_CLEAN_FLAG((space)->ctrl->flag, SPACE_FLAG_AUTOALLOCATE)

#define SPACE_ATTR_SWAP_BITMAP          (((knl_session_t *)session)->kernel->attr.enable_temp_bitmap)
#define SPACE_SWAP_BITMAP(space)   ((space)->swap_bitmap)
#define IS_SWAP_SPACE_BITMAP(space)     (IS_SWAP_SPACE(space) && SPACE_SWAP_BITMAP(space))

#define SPACE_CTRL_IS_BITMAPMANAGED(space)  ((space)->ctrl->flag & SPACE_FLAG_BIMAPMANAGED)
// swap space may also be bitmap managed
#define SPACE_IS_BITMAPMANAGED(space)   \
    (SPACE_CTRL_IS_BITMAPMANAGED(space) || IS_SWAP_SPACE_BITMAP(space))
#define SPACE_SET_BITMAPMANAGED(space)   CM_SET_FLAG((space)->ctrl->flag, SPACE_FLAG_BIMAPMANAGED)
#define SPACE_UNSET_BITMAPMANAGED(space) CM_CLEAN_FLAG((space)->ctrl->flag, SPACE_FLAG_BIMAPMANAGED)

#define SPACE_IS_ENCRYPT(space)         ((space)->ctrl->flag & SPACE_FLAG_ENCRYPT)
#define SPACE_SET_ENCRYPT(space)        CM_SET_FLAG((space)->ctrl->flag, SPACE_FLAG_ENCRYPT)
#define SPACE_UNSET_ENCRYPT(space)      CM_CLEAN_FLAG((space)->ctrl->flag, SPACE_FLAG_ENCRYPT)
#define SPACE_NEED_ENCRYPT(size)        ((size) > 0) ? GS_TRUE : GS_FALSE; 

#define SPC_UNPROTECT_HEAD(space)         BUF_UNPROTECT_PAGE((char *)((space)->head) - sizeof(page_head_t))
#define SPC_PROTECT_HEAD(space)           BUF_PROTECT_PAGE((char *)((space)->head) - sizeof(page_head_t))

#define SPACE_HEAD_RESIDENT(space) \
    ((buf_check_resident_page_version(session, (space)->entry)) ? ((space)->head) : ((space)->head))

#define SPACE_TYPE_IS_UNDEFINED(space)    ((space)->ctrl->type == SPACE_TYPE_UNDEFINED)

#define IS_SPACE_COMPRESSIBLE(space) \
    (IS_USER_SPACE((space)) && SPACE_IS_BITMAPMANAGED((space)) && !IS_TEMP_SPACE((space)) && \
    !SPACE_IS_NOLOGGING((space)) && !SPACE_IS_ENCRYPT((space)))

typedef struct st_space_ctrl {
    uint32 id;
    bool32 used;
    char name[GS_NAME_BUFFER_SIZE];
    uint16 flag;
    uint16 block_size;
    uint32 extent_size;  // extent pages count
    uint32 file_hwm;     // max allocated datafile count
    uint32 type;
    knl_scn_t org_scn;
    uint8 encrypt_version;
    uint8 cipher_reserve_size;
    uint8 unused[GS_RESERVED_BYTES_14];

    uint32 files[GS_MAX_SPACE_FILES];  // datafile id array
} space_ctrl_t;

typedef struct st_space_head {
    uint32 segment_count;
    page_list_t free_extents;
    uint32 datafile_count;
    uint32 hwms[GS_MAX_SPACE_FILES];
} space_head_t;

typedef struct st_spc_punch_head {
    page_list_t punching_exts;
    page_list_t punched_exts;
} spc_punch_head_t;

typedef struct st_space {
    spinlock_t lock;
    page_id_t entry;
    space_ctrl_t *ctrl;
    space_head_t *head;
    bool8 purging;
    bool8 is_empty;
    bool8 allow_extend;
    bool8 alarm_enabled;   // throw usage alarm or not
    bool8 swap_bitmap;
    volatile bool8 punching;
    uint8 reserved[2];
} space_t;

typedef enum st_ext_size {
    EXT_SIZE_8 = 8,
    EXT_SIZE_128 = 128,
    EXT_SIZE_1024 = 1024,
    EXT_SIZE_8192 = 8192,
} ext_size_t;

typedef enum st_ext_size_id {
    EXT_SIZE_8_ID = 0,
    EXT_SIZE_128_ID = 1,
    EXT_SIZE_1024_ID = 2,
    EXT_SIZE_8192_ID = 3,
} ext_size_id_t;

typedef enum st_ext_boundary {
    EXT_SIZE_8_BOUNDARY = 16,
    EXT_SIZE_128_BOUNDARY = 143,
    EXT_SIZE_1024_BOUNDARY = 255,
} ext_boundary_t;

typedef enum st_pages_boundary {
    EXT_SIZE_8_PAGE_BOUNDARY = EXT_SIZE_8_BOUNDARY * EXT_SIZE_8,
    EXT_SIZE_128_PAGE_BOUNDARY = EXT_SIZE_8_PAGE_BOUNDARY + (EXT_SIZE_128_BOUNDARY - EXT_SIZE_8_BOUNDARY) * EXT_SIZE_128,
    EXT_SIZE_1024_PAGE_BOUNDARY = EXT_SIZE_128_PAGE_BOUNDARY + (EXT_SIZE_1024_BOUNDARY - EXT_SIZE_128_BOUNDARY) * EXT_SIZE_1024, 
} pages_boundary_t;

#define SPACE_GET(id)              (&session->kernel->db.spaces[(id)])
#define KNL_GET_SPACE(session, id) (&(session)->kernel->db.spaces[(id)])
#define SPACE_HEAD                 (space_head_t *)(session->curr_page + PAGE_HEAD_SIZE)
#define SPACE_PUNCH_HEAD           (spc_punch_head_t *)((char *)SPACE_HEAD + sizeof(space_head_t))
#define SPACE_PUNCH_HEAD_PTR(space) ((spc_punch_head_t *)((char *)((space)->head) + sizeof(space_head_t)))
#define SPACE_PUNCH_HEAD_RESIDENT(space) \
    ((buf_check_resident_page_version(session, (space)->entry)) ? \
    (SPACE_PUNCH_HEAD_PTR(space)) : (SPACE_PUNCH_HEAD_PTR(space)))

#pragma pack(4)
typedef struct st_rd_create_space {
    uint32 space_id;
    uint32 extent_size;
    uint64 org_scn;
    uint16 flags;
    uint16 block_size;
    char name[GS_NAME_BUFFER_SIZE];
    uint32 type;
    uint8 encrypt_version;
    uint8 cipher_reserve_size;
    uint32 reserved2;
} rd_create_space_t;

typedef struct st_rd_create_datafile {
    uint32 id;        // datafile id in whole database
    uint32 space_id;  // tablespace id
    uint32 file_no;   // sequence number in tablespace
    uint16 flags;
    uint16 reserve;
    uint64 size;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
    char name[GS_FILE_NAME_BUFFER_SIZE];
    uint32 type;
} rd_create_datafile_t;

typedef struct st_rd_extend_undo {
    uint16 old_undo_segments;
    uint16 undo_segments;
} rd_extend_undo_segments_t;

typedef struct st_rd_remove_space {
    uint32 space_id;
    uint32 options;
} rd_remove_space_t;

typedef struct st_rd_remove_datafile {
    uint32 id;        // datafile id in whole database
    uint32 space_id;  // tablespace id
    uint32 file_no;   // sequence number in tablespace
} rd_remove_datafile_t;

typedef struct st_rd_set_df_autoextend {
    uint32 op_type;
    uint32 id;
    bool32 auto_extend;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
} rd_set_df_autoextend_t;

typedef struct st_rd_update_head {
    page_id_t entry;
    uint16 space_id;  // tablespace id
    uint16 file_no;   // sequence number in tablespace
} rd_update_head_t;

typedef struct st_rd_set_space_autoextend {
    uint32 op_type;
    uint32 space_id;
    bool32 auto_extend;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
} rd_set_space_autoextend_t;

typedef struct st_rd_set_space_flag {
    uint32 op_type;
    uint32 space_id;
    uint16 flags;
} rd_set_space_flag_t;

typedef struct st_rd_rename_space {
    uint32 op_type;
    uint32 space_id;
    char name[GS_NAME_BUFFER_SIZE];
} rd_rename_space_t;

typedef struct st_rd_shrink_space {
    uint32 op_type;
    uint32 space_id;
    uint32 flags;
} rd_shrink_space_t;

typedef struct st_rd_update_hwm {
    uint32 file_no;  // sequence number in tablespace
    uint32 file_hwm;
} rd_update_hwm_t;

typedef struct st_rd_punch_page {
    page_id_t page_id;
    char reverse[4];
} rd_punch_page_t;

typedef struct st_rd_punch_extents {
    page_list_t punching_exts;
    page_list_t punched_exts;
} rd_punch_extents_t;

typedef struct st_spc_punch_info {
    int64 do_punch_size;
    int64 real_punch_size;
} spc_punch_info_t;

#pragma pack()

static inline uint32 spc_first_extent_id(knl_session_t *session, space_t *space, page_id_t page_id)
{
    if (space->ctrl->files[0] == page_id.file) {
        // if in init db process,  file_id is 0 ,to avoid system space get wrong hwm
        // verify db->ctrl.core.dw_end, if dw_end == 0 means doublewrite is not inited,
        // that will be inited in dbc_init_doublewrite
        if (page_id.file == (uint16)knl_get_dbwrite_file_id(session) && knl_get_dbwrite_end(session) != 0) {
            return SPACE_IS_BITMAPMANAGED(space) ? DW_MAP_HWM_START : DW_SPC_HWM_START;
        } else {
            return SPACE_IS_BITMAPMANAGED(space) ? DF_MAP_HWM_START : DF_FIRST_HWM_START;
        }
    } else {
        return SPACE_IS_BITMAPMANAGED(space) ? DF_MAP_HWM_START : DF_HWM_START;
    }
}

static inline bool32 spc_is_extent_first(knl_session_t *session, space_t *space, page_id_t page_id)
{
    uint32 start_id;

    start_id = spc_first_extent_id(session, space, page_id);
    return (((page_id.page - start_id) % space->ctrl->extent_size) == 0);
}

static inline bool32 spc_is_extent_last(knl_session_t *session, space_t *space, page_id_t page_id)
{
    uint32 start_id;
    start_id = spc_first_extent_id(session, space, page_id);
    if (page_id.page < start_id) {
        return GS_FALSE;
    }
    return (((page_id.page - start_id + 1) % space->ctrl->extent_size) == 0);
}

static inline page_id_t spc_get_extent_first(knl_session_t *session, space_t *space, page_id_t page_id)
{
    uint32 start_id;
    page_id_t first;

    first = page_id;
    start_id = spc_first_extent_id(session, space, page_id);
    first.page = page_id.page - ((page_id.page - start_id) % space->ctrl->extent_size);
    first.aligned = 0;

    return first;
}

static inline page_id_t spc_get_extent_last(knl_session_t *session, space_t *space, page_id_t page_id)
{
    page_id_t last;

    last = spc_get_extent_first(session, space, page_id);
    last.page += space->ctrl->extent_size - 1;
    last.aligned = 0;

    return last;
}

static inline uint32 spc_get_hwm_start(knl_session_t *session, space_t *space, datafile_t *df)
{
    page_id_t page_id;

    page_id.file = df->ctrl->id;
    page_id.page = 0;
    page_id.aligned = 0;

    return spc_first_extent_id(session, space, page_id);
}

/*
 * we have four type extent with different size, which are identify by two
 * bits(size id) on page head. extent auto-increased based on extents count,
 * following is the detail:
 * ------------   -----------------  -----------  ----------------------- --------------
 * extent size  | extent page count |   size id  |   extents count range |  total size
 * ------------   -----------------  -----------  ----------------------- --------------
 *    64K               8                0            [1, 16]                   1M
 * ------------   -----------------  ------------ ----------------------- --------------
 *    1M               128               1            [17, 143]                128M
 * ------------   -----------------  ------------ ----------------------- --------------
 *    8M               1024              2            [144, 255]                1G
 * ------------   -----------------  ------------ ----------------------- --------------
 *    64M              8192              3            [256, ...)                ...
 * ------------   -----------------  ------------ ----------------------- --------------
 */
static inline uint8 spc_ext_id_by_size(uint32 extent_size)
{
    switch (extent_size) {
        case EXT_SIZE_8:
            return EXT_SIZE_8_ID;
        case EXT_SIZE_128:
            return EXT_SIZE_128_ID;
        case EXT_SIZE_1024:
            return EXT_SIZE_1024_ID;
        case EXT_SIZE_8192:
            return EXT_SIZE_8192_ID;
        default:
            return EXT_SIZE_8_ID;
    }
}

/*
 * get extent size by id in page head
 */
static inline uint32 spc_ext_size_by_id(uint8 size_id)
{
    switch (size_id) {
        case EXT_SIZE_8_ID:
            return EXT_SIZE_8;
        case EXT_SIZE_128_ID:
            return EXT_SIZE_128;
        case EXT_SIZE_1024_ID:
            return EXT_SIZE_1024;
        case EXT_SIZE_8192_ID:
            return EXT_SIZE_8192;
        default:
            return EXT_SIZE_8;
    }
}

/*
 * get extent size by extent count
 */
static inline uint32 spc_ext_size_by_cnt(uint32 count)
{
    if (count < EXT_SIZE_8_BOUNDARY) {
        return EXT_SIZE_8;
    } else if (count < EXT_SIZE_128_BOUNDARY) {
        return EXT_SIZE_128;
    } else if (count < EXT_SIZE_1024_BOUNDARY) {
        return EXT_SIZE_1024;
    } else {
        return EXT_SIZE_8192;
    }
}

/*
 * calculate extent size by extents count
 */
static inline uint32 spc_get_ext_size(space_t *space, uint32 extents_count)
{
    if (SPACE_IS_AUTOALLOCATE(space)) {
        return spc_ext_size_by_cnt(extents_count);
    }
    return space->ctrl->extent_size;
}

static inline uint32 spc_get_page_ext_size(space_t *space, uint8 ext_size_id)
{
    if (SPACE_IS_AUTOALLOCATE(space)) {
        return spc_ext_size_by_id(ext_size_id);
    }
    return space->ctrl->extent_size;
}

/*
 * get datafile minisize by space type
 */
static inline int64 spc_get_datafile_minsize_byspace(knl_session_t *session, space_t *space)
{
    uint64 min_file_size = GS_MIN_USER_DATAFILE_SIZE;

    if (IS_SYSTEM_SPACE(space) || (IS_UNDO_SPACE(space) && !IS_TEMP_SPACE(space))) {
        min_file_size = GS_MIN_SYSTEM_DATAFILE_SIZE;
    } else if (IS_SYSAUX_SPACE(space)) {
        min_file_size = GS_MIN_SYSAUX_DATAFILE_SIZE;
    }

    return min_file_size;
}

// if change this func, plz change func spc_punch_check_space_invaild
static inline bool32 spc_punch_check_normalspc_invaild(knl_session_t *session, space_t *space)
{
    if (SPACE_IS_DEFAULT(space) || SPACE_IS_ENCRYPT(space) || IS_UNDO_SPACE(space) ||
        IS_TEMP_SPACE(space) || SPACE_IS_BITMAPMANAGED(space)) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

static inline uint32 spc_get_punch_extents(knl_session_t *session, space_t *space)
{
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    if (!spc_punch_check_normalspc_invaild(session, space) || space->head == NULL) {
        return 0;
    }

    return punch_head->punched_exts.count;
}

bool32 spc_auto_offline_space(knl_session_t *session, space_t *space, datafile_t *df);
bool32 spc_valid_space_object(knl_session_t *session, uint32 space_id);
status_t spc_create_space_precheck(knl_session_t *session, knl_space_def_t *def);
status_t spc_create_space(knl_session_t *session, knl_space_def_t *def, uint32 *id);
status_t spc_drop_online_space(knl_session_t *session, space_t *space, uint32 options);
status_t spc_drop_space_remove_objects(knl_session_t *session, space_t *space, uint32 options);
status_t spc_check_object_exist(knl_session_t *session, space_t *space);
status_t spc_mount_space(knl_session_t *session, space_t *space, bool32 auto_offline);
void spc_set_space_id(knl_session_t *session);
void spc_umount_space(knl_session_t *session, space_t *space);
void spc_clean_nologging_data(knl_session_t *session);
bool32 spc_need_clean(space_t *space);
status_t spc_drop_nologging_table(knl_session_t *session);
status_t spc_get_space_id(knl_session_t *session, const text_t *name, uint32 *space_id);
status_t spc_check_by_uid(knl_session_t *session, const text_t *name, uint32 space_id, uint32 uid);
status_t spc_check_by_tid(knl_session_t *session, const text_t *name, uint32 space_id, uint32 tid);
status_t spc_get_space_name(knl_session_t *session, uint32 space_id, text_t *space_name);
uint64 spc_count_pages(knl_session_t *session, space_t *space, bool32 used);
uint64 spc_count_backup_pages(knl_session_t *session, space_t *space);
uint64 spc_count_pages_with_ext(knl_session_t *session, space_t *space, bool32 used);
status_t spc_set_autoextend(knl_session_t *session, space_t *space, knl_autoextend_def_t *autoextend);
status_t spc_set_autooffline(knl_session_t *session, space_t *space, bool32 auto_offline);
status_t spc_rename_space(knl_session_t *session, space_t *space, text_t *new_space_name);
status_t spc_rename_datafiles(knl_session_t *session, space_t *space, galist_t *datafile, galist_t *new_datafile);
void spc_offline_space_files(knl_session_t *session, uint32 *files, uint32 file_hwm);
status_t spc_offline_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles);
status_t spc_drop_offlined_space(knl_session_t *session, space_t *space, uint32 options);
status_t spc_set_autopurge(knl_session_t *session, space_t *spcae, bool32 auto_purge);
status_t spc_shrink_space(knl_session_t *session, space_t *space, knl_shrink_def_t *shrink);

status_t spc_create_datafiles(knl_session_t *session, space_t *space, knl_altspace_def_t *def);
status_t spc_drop_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles);
status_t spc_remove_datafile(knl_session_t *session, space_t *space, uint32 id, bool32 drop_datafile);
void spc_remove_datafile_info(knl_session_t *session, datafile_t *df, uint32 id);
void spc_remove_datafile_device(knl_session_t *session, datafile_t *df);
status_t spc_remove_mount_datafile(knl_session_t *session, space_t *space, uint32 id, uint32 options);
void spc_create_segment(knl_session_t *session, space_t *space);
void spc_drop_segment(knl_session_t *session, space_t *space);
status_t spc_clean_garbage_space(knl_session_t *session);

status_t spc_alloc_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent, 
    bool32 is_compress);
bool32 spc_alloc_undo_extent(knl_session_t *session, space_t *space, page_id_t *extent, uint32 *extent_size);
void spc_free_extent(knl_session_t *session, space_t *space, page_id_t extent);
void spc_free_undo_extents(knl_session_t *session, space_t *space, undo_page_list_t *extents);
void spc_free_extents(knl_session_t *session, space_t *space, page_list_t *extents);
status_t spc_free_extent_from_list(knl_session_t *sesion, space_t *space, const char *oper);
void spc_concat_extent(knl_session_t *session, page_id_t last_ext, page_id_t ext);
void spc_concat_extents(knl_session_t *session, page_list_t *extents, const page_list_t *next_exts);
page_id_t spc_get_next_ext(knl_session_t *session, page_id_t extent);
page_id_t spc_get_size_next_ext(knl_session_t *session, space_t *space, page_id_t extent, uint32 *ext_size);
page_id_t spc_get_next_undo_ext_prefetch(knl_session_t *session, page_id_t extent);
uint32 spc_get_df_used_pages(knl_session_t *session, space_t *space, uint32 file_no);

#ifdef DB_DEBUG_VERSION
void spc_validate_extents(knl_session_t *session, page_list_t *extents);
void spc_validate_undo_extents(knl_session_t *session, undo_page_list_t *extents);
#endif

status_t spc_alloc_swap_extent(knl_session_t *session, space_t *space, page_id_t *extent);
void spc_free_temp_extent(knl_session_t *session, space_t *space, page_id_t extent);
page_id_t spc_get_next_temp_ext(knl_session_t *session, page_id_t extent);
page_id_t spc_try_get_next_temp_ext(knl_session_t *session, page_id_t extent);
void spc_concat_temp_extent(knl_session_t *session, page_id_t last_ext, page_id_t ext);
bool32 spc_validate_page_id(knl_session_t *session, page_id_t page_id);

status_t spc_rebuild_space(knl_session_t *session, space_t *space);

void spc_wait_data_buffer(knl_session_t *session, space_t *space);
status_t spc_remove_space(knl_session_t *session, space_t *space, uint32 options, bool32 ignore_error);

status_t space_head_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump);

space_t *spc_get_temp_undo(knl_session_t *session);
status_t spc_remove_space_online(knl_session_t *session, space_t *space, uint32 options);
status_t spc_active_undo_encrypt(knl_session_t *session, uint32 space_id);
status_t spc_active_swap_encrypt(knl_session_t *session);
uint32 spc_get_encrypt_space_count(knl_session_t *session);
status_t spc_try_inactive_swap_encrypt(knl_session_t *session);
uint32 spc_ext_cnt_by_pages(space_t *space, uint32 page_count);
void spc_init_swap_space(knl_session_t *session, space_t *space);
uint32 spc_pages_by_ext_cnt(space_t *space, uint32 extent_cnt, uint8 seg_page_type);
void spc_set_datafile_autoextend(knl_session_t *session, datafile_t *df, knl_autoextend_def_t *def);
void spc_alloc_datafile_hwm_extent(knl_session_t *session, space_t *space,
    uint32 id, page_id_t *extent, uint32 extent_size);
status_t spc_extend_undo_segments(knl_session_t *session, uint32 count, datafile_t *df);
status_t spc_df_alloc_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    datafile_t *df);

status_t spc_try_alloc_extent(knl_session_t *session, space_t *space, page_id_t *extent,
    uint32 *extent_size, bool32 *is_degrade, bool32 is_compress);
uint32 spc_degrade_extent_size(space_t *space, uint32 size);
bool32 spc_view_try_lock_space(knl_session_t *session, space_t *space, const char *operation);
void spc_unlock_space(space_t *space);

bool32 spc_try_init_punch_head(knl_session_t *session, space_t *space);
status_t spc_punch_hole(knl_session_t *session, space_t *space, int64 punch_size);
void spc_set_datafile_ctrl_punched(knl_session_t *session, uint16 file_id);


#ifdef __cplusplus
}
#endif

#endif

