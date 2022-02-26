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
 * knl_archive.h
 *    kernel archive definitions 
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/persist/knl_archive.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_ARCHIVE_H__
#define __KNL_ARCHIVE_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_log.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARCH_DEFAULT_DEST 1
#define ARCH_FAIL_PRINT_THRESHOLD (2 * MICROSECS_PER_MIN)

typedef struct st_arch_file {
    log_file_head_t head;
    char name[GS_FILE_NAME_BUFFER_SIZE];
    int32 handle;
} arch_file_t;

/** LOG_ARCHIVE_DEST_STATE_n value definition  @see e_arch_dest_state */
typedef enum e_arch_dest_state {
    STATE_ENABLE = 0,
    STATE_DEFER = 1,
    STATE_ALTERNATE = 2,
    STATE_DSIABLE = 3
} arch_dest_state_t;

typedef union st_arch_log_id {
    struct {
        uint32 rst_id;
        uint32 asn;
    };
    uint64 arch_log;
} arch_log_id_t;

typedef enum en_arch_affirm {
    LOG_ARCH_DEFAULT = 0,
    LOG_ARCH_AFFIRM = 1,
    LOG_ARCH_NOAFFIRM = 2
} arch_affirm_t;

typedef enum en_trans_mode {
    LOG_TRANS_MODE_DEFAULT = 0,
    LOG_TRANS_MODE_ARCH = 1,
    LOG_TRANS_MODE_LGWR = 2
} trans_mode_t;

typedef enum en_arch_dest_type {
    LOG_ARCH_DEST_DEFAULT = 0,
    LOG_ARCH_DEST_LOCATION = 1,
    LOG_ARCH_DEST_SERVICE = 2
} arch_dest_type_t;

typedef struct st_arch_service {
    char host[GS_HOST_NAME_BUFFER_SIZE];
    uint16 port;
    uint16 reserved;
} arch_service_t;

typedef enum en_net_trans_mode {
    LOG_NET_TRANS_MODE_DEFAULT = 0,
    LOG_NET_TRANS_MODE_SYNC = 1,
    LOG_NET_TRANS_MODE_ASYNC = 2
} net_trans_mode_t;

typedef enum en_log_sync_mode {
    LOG_SYNC_MODE_DEFAULT = 0,
    LOG_SYNC_MODE_FIRST = 1,
    LOG_SYNC_MODE_ANY = 2,
    LOG_SYNC_MODE_INVALID = 3,
} log_sync_mode_t;

typedef enum en_role_valid {
    VALID_FOR_DEFAULT = 0,
    VALID_FOR_ALL_ROLES = 1,
    VALID_FOR_PRIMARY_ROLE = 2,
    VALID_FOR_STANDBY_ROLE = 3
} role_valid_t;

typedef struct st_archived_info {
    uint32 recid;
    uint32 dest_id;
    uint32 rst_id;
    uint32 asn;
    int64 stamp;
    int32 blocks;
    int32 block_size;
    knl_scn_t first;
    knl_scn_t last;
    uint8 reserve[32];
    char name[GS_FILE_NAME_BUFFER_SIZE];
} arch_ctrl_t;

typedef struct st_arch_attr {
    arch_affirm_t affirm_mode;
    trans_mode_t trans_mode;
    arch_dest_type_t dest_mode;
    arch_service_t service;
    char local_path[GS_MAX_FILE_NAME_LEN];
    net_trans_mode_t net_mode;
    role_valid_t role_valid;
    bool32 used;
    bool32 enable;
    char local_host[GS_HOST_NAME_BUFFER_SIZE];
    compress_algo_t compress_alg;
} arch_attr_t;

typedef struct st_log_sync_param {
    log_sync_mode_t mode_type;
    uint32 sync_num;
} log_sync_param_t;

typedef struct st_arch_proc_context {
    spinlock_t record_lock;  // lock for record archive info
    uint32 arch_id;
    bool32 enabled;
    thread_t thread;
    knl_session_t *session;
    char arch_dest[GS_FILE_NAME_BUFFER_SIZE];
    arch_dest_state_t dest_status;
    uint32 last_file_id;
    uint32 next_file_id;
    bool32 alarmed;
    arch_log_id_t last_archived_log;
    int64 curr_arch_size;
    char *arch_buf;
    date_t fail_time;
} arch_proc_context_t;

typedef struct st_archive_ctx {
    spinlock_t dest_lock;
    spinlock_t record_lock;  // lock for record archive info
    bool32 is_archive;
    bool32 initialized;
    char arch_format[GS_FILE_NAME_BUFFER_SIZE];
    arch_proc_context_t arch_proc[GS_MAX_ARCH_DEST];
    uint16 arch_dest_num;
    uint16 reserved;
    uint32 archived_recid;
    log_point_t *rcy_point;
    uint32 arch_trace;
    uint64 total_bytes;    /* archived total bytes of current archive file */
    uint64 begin_redo_bytes; /* flushed redo bytes when current file begin to archive */
    uint64 prev_redo_bytes;
    volatile bool32 arch_dest_state_changed;
} arch_context_t;

typedef enum en_arch_dest_sync {
    ARCH_DEST_SYNCHRONIZED = 0,
    ARCH_DEST_NO_SYNCHRONIZED = 1,
    ARCH_DEST_UNKNOWN = 2,
} arch_dest_sync_t;

status_t arch_init(knl_session_t *session);
status_t arch_start(knl_session_t *session);
void arch_close(knl_session_t *session);
void arch_last_archived_log(knl_session_t *session, uint32 dest_pos, arch_log_id_t *arch_log_out);
void arch_set_archive_log_name(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos, char *buf,
                               uint32 buf_size);
status_t arch_record_archinfo(knl_session_t *session, uint32 dest_pos, const char *file_name,
                              log_file_head_t *log_head);

status_t arch_set_dest(arch_context_t *arch_ctx, char *value, uint32 pos);
status_t arch_set_dest_state(knl_session_t *session, const char *value, uint32 pos, bool32 notify);
status_t arch_set_format(arch_context_t *arch_ctx, char *value);
status_t arch_set_max_processes(knl_session_t *session, char *value);
status_t arch_set_min_succeed(arch_context_t *ctx, char *value);
status_t arch_set_trace(char *value, uint32 *arch_trace);

void arch_get_last_rstid_asn(knl_session_t *session, uint32 *rst_id, uint32 *asn);
char *arch_get_dest_type(knl_session_t *session, uint32 id, arch_attr_t *attr, bool32 *is_primary);
void arch_get_dest_path(knl_session_t *session, uint32 id, arch_attr_t *arch_attr, char *path, uint32 path_size);
char *arch_get_sync_status(knl_session_t *session, uint32 id, arch_attr_t *arch_attr, arch_dest_sync_t *sync);
char *arch_get_dest_sync(const arch_dest_sync_t *sync);

status_t arch_force_clean(knl_session_t *session, knl_alterdb_archivelog_t *def);

void arch_reset_file_id(knl_session_t *session, uint32 dest_pos);
bool32 arch_get_archived_log_name(knl_session_t *session, uint32 rst_id, uint32 asn, 
                                  uint32 dest_pos, char *buf, uint32 buf_size);
bool32 arch_archive_log_recorded(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos);
bool32 arch_dest_state_disabled(knl_session_t *session, uint32 inx);
void arch_set_deststate_disabled(knl_session_t *session, uint32 inx);
status_t arch_regist_archive(knl_session_t *session, const char *file_name);
status_t arch_try_regist_archive(knl_session_t *session, uint32 rst_id, uint32 *asn);
bool32 arch_dest_state_match_role(knl_session_t *session, arch_attr_t *arch_attr);
status_t arch_check_dest_service(void *attr, arch_attr_t *arch_attr, uint32 slot);
bool32 arch_has_valid_arch_dest(knl_session_t *session);
void arch_reset_archfile(knl_session_t *session, uint32 replay_asn);
bool32 arch_log_not_archived(knl_session_t *session, uint32 req_rstid, uint32 req_asn);
void arch_get_bind_host(knl_session_t *session, const char *srv_host, char *bind_host, uint32 buf_size);
void arch_get_files_num(knl_session_t *session, uint32 dest_id, uint32 *arch_num);
arch_ctrl_t *arch_get_archived_log_info(knl_session_t *session, uint32 rst_id, uint32 asn, uint32 dest_pos);
status_t arch_archive_file(knl_session_t *session, char *buf, const char *src_name, const char *arch_file_name, log_file_t *logfile);
arch_ctrl_t *arch_get_last_log(knl_session_t *session);
status_t arch_process_existed_archfile(knl_session_t *session, const char *arch_name,
    log_file_head_t head, bool32 *ignore_data);
status_t arch_redo_alloc_resource(knl_session_t *session, aligned_buf_t *log_buf, char **buf);
status_t arch_archive_redo(knl_session_t *session, log_file_t *logfile, char *arch_buf, aligned_buf_t log_buf,
    bool32 *is_continue);
status_t arch_try_arch_redo(knl_session_t *session, uint32 *max_asn);

#ifdef __cplusplus
}
#endif

#endif
