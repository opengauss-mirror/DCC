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
 * knl_backup.h
 *    implement of backup
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/backup/knl_backup.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __BAK_BACKUP_H__
#define __BAK_BACKUP_H__

#include "bak_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_bak_columns {
    BAK_COL_RECID = 0,
    BAK_COL_TYPE = 1,
    BAK_COL_STAGE = 2,
    BAK_COL_STATUS = 3,
    BAK_COL_LEVEL = 4,
    BAK_COL_TAG = 5,
    BAK_COL_SCN = 6,
    BAK_COL_LSN = 7,
    BAK_COL_DEVICE_TYPE = 8,
    BAK_COL_BASE_TAG = 9,
    BAK_COL_DIR = 10,
    BAK_COL_RESETLOGS = 11,
    BAK_COL_POLICY = 12,
    BAK_COL_RCY_ASN = 13,
    BAK_COL_RCY_OFFSET = 14,
    BAK_COL_RCY_LFN = 15,
    BAK_COL_LRP_ASN = 16,
    BAK_COL_LRP_OFFSET = 17,
    BAK_COL_LRP_LFN = 18,
    BAK_COL_START_TIME = 19,
    BAK_COL_COMPLETION_TIME = 20,
} bak_columns_t;

bool32 bak_paral_task_enable(knl_session_t *session);

status_t bak_backup_database(knl_session_t *session, knl_backup_t *param);
status_t bak_get_last_rcy_point(knl_session_t *session, log_point_t *point);

status_t bak_backup_proc(knl_session_t *session);
status_t bak_precheck(knl_session_t *session);
status_t bak_paral_create_bakfile(knl_session_t *session, uint32 file_index, uint32 sec_id);
status_t bak_local_write(bak_local_t *local, const void *buf, int32 size, bak_t *bak);
status_t bak_read_datafile(knl_session_t *session, bak_process_t *bak_proc, bool32 to_disk);
status_t bak_read_logfile(knl_session_t *session, bak_context_t *ctx, bak_process_t *bak_proc,
                          uint32 block_size, bool32 to_disk);
void bak_read_prepare(knl_session_t *session, bak_process_t *process, datafile_t *datafile, uint32 sec_id);
void bak_unlatch_logfile(knl_session_t *session, bak_process_t *process);
void bak_reset_fileinfo(bak_assignment_t *assign_ctrl);
void bak_update_progress(bak_t *bak, uint64 size);
void bak_close(knl_session_t *session);
bool32 bak_logfile_not_backed(knl_session_t *session, uint32 asn);
status_t bak_load_tablespaces(knl_session_t *session);
void bak_unload_tablespace(knl_session_t *session);
void bak_record_new_file(bak_t *bak, bak_file_type_t file_type, uint32 file_id, uint32 sec_id);
status_t bak_read_datafile_pages(knl_session_t *session, bak_process_t *bak_proc);
status_t bak_load_log_batch(knl_session_t *session, log_point_t *point, uint32 *data_size, aligned_buf_t *buf,
    uint32 *block_size);
#ifdef __cplusplus
}
#endif

#endif