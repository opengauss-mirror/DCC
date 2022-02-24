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
 * bak_restore.h
 *    implement of restore
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/backup/bak_restore.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __BAK_RESTORE_H__
#define __BAK_RESTORE_H__
    
#include "knl_database.h"
#include "bak_common.h"
#include "knl_backup.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_rst_assist {
    int64 file_offset;
    uint32 page_count;
    page_id_t page_id;
    datafile_t *datafile;
} rst_assist_t;

status_t rst_check_backupset_path(knl_restore_t *param);
void rst_close_ctrl_file(ctrlfile_set_t *ctrlfiles);
void rst_close_log_files(knl_session_t *session);
status_t rst_read_data(bak_context_t *ctx, void *buf, int32 buf_size, int32 *read_size, bool32 *end);
status_t rst_wait_ctrlfile_ready(bak_t *bak);
status_t rst_wait_agent_process(bak_t *bak);
void rst_wait_write_end(bak_t *ctrl);
status_t rst_set_head(knl_session_t *session, bak_head_t *head, bool32 set_config);
status_t rst_read_file(knl_session_t *session, uint32 file_index);
status_t rst_restore_config_param(knl_session_t *session);
status_t rst_start_write_thread(bak_process_t *common_proc);
status_t rst_set_logfile_ctrl(knl_session_t *session, uint32 curr_file_index, log_file_head_t *head,
                              bak_ctrl_t *ctrl, bool32 *ignore_data);
char *rst_fetch_filename(bak_t *bak);
status_t rst_fill_file_gap(device_type_t type, int32 handle, int64 start, int64 end, const char *buf, uint32 buf_size);
status_t rst_restore_datafile(knl_session_t *session, bak_t *bak, bak_process_t *ctx, char *buf, const char *filename);
status_t rst_write_data(knl_session_t *session, bak_ctrl_t *ctrl, const char *buf, int32 size);
status_t rst_read_check_size(int32 read_size, int32 expect_size, const char* file_name);
status_t rst_delete_track_file(knl_session_t *session, bak_t *bak, bool32 allow_not_exist);

#ifdef __cplusplus
}
#endif

#endif