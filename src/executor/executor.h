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
 * executor.h
 *
 *
 * IDENTIFICATION
 *    src/executor/executor.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_EXECUTOR_H__
#define __DCC_EXECUTOR_H__

#include "cm_types.h"
#include "dcc_interface.h"
#include "executor_defs.h"
#include "cm_list.h"
#include "cm_error.h"
#include "cm_text.h"
#include "cm_num.h"
#include "dcc_msg_protocol.h"
#include "cm_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_exc_consense_obj {
    uint64 key;
    uint32 cmd;  // just for 'PUT' 'DEL' cmd type.
    bool32 cmd_result;
    uint64 index;
    uint32 sequence;
} exc_consense_obj_t;

typedef struct st_msg_entry {
    kvp_t       kvp;
    uint32      cmd;
    union {
        struct {
            uint32 ephemeral;  // reserved
            uint64 ttl;        // reserved
            uint32 sequence;
            uint32 not_existed;
            text_t expect_value;
            text_t leaseid;
        } put_op;
        struct {
            bool32 is_prefix;
        } del_op;
        struct {
            text_t leaseid;
            uint32 ttl;
            int64 renew_time;
        } lease_op;
    } all_op;
    char*       buf;
    uint64      index;
    uint64      write_key;
    uint32      sequence_no;
    atomic32_t  ref_count;
    struct st_msg_entry *prev;
    struct st_msg_entry *next;
} msg_entry_t;

typedef struct st_exc_lease_info_t {
    uint32 ttl;
    uint32 remain_ttl;
} exc_lease_info_t;

#define ENTRY_K(entry) (&(entry)->kvp.key)
#define ENTRY_V(entry) (&(entry)->kvp.value)
#define DCC_BACKUP_DIR          "dcc_backup"
#define DCC_GSTOR_DIR           "gstor"
#define DCC_DCFDATA_DIR         "dcf_data"
#define DCC_DATA_DIR            "gstor/data"
#define DCC_BUILD_STATUS_FILE   "build.status"
#define DCC_FIRST_INIT_DIR      "dcc_first_init"
#define DCC_GSTOR_DIR_BK        "gstor_backup"
#define DCC_DCFDATA_DIR_BK      "dcf_data_backup"

typedef enum e_exc_build_cmd {
    BUILD_START_REQ = 1,    // follower->leader:build start request
    BUILD_PKT_SEND = 2,     // leader->follower:build pkt send
    BUILD_PKT_ACK = 3,      // follower->leader:build pkt ack
    BUILD_PKT_SEND_END = 4, // leader->follower:build pkt send end
    BUILD_OK_REQ = 5,       // follower->leader:build ok request
    BUILD_OK_ACK = 6,       // leader->follower:build ok ack
    BUILD_CANCEL_REQ = 7,   // leader<->follower:cancel build request
 } exc_build_cmd_t;

typedef enum e_exc_build_status {
    BUILD_NONE = 0,

    // follower build status
    FOLLOWER_BUILD_START = 1,
    FOLLOWER_BUILD_PKT_RECV = 2,
    FOLLOWER_BUILD_PKT_RECV_END = 3,
    FOLLOWER_BUILD_OK_REQ_SEND = 4,
    FOLLOWER_BUILD_OK_ACK_RECV = 5,

    // leader build status
    LEADER_BUILD_PKT_SEND = 6,
    LEADER_BUILD_PKT_SEND_END = 7,
    LEADER_BUILD_OK_REQ_RECV = 8,

    //commom build status
    BUILD_CANCEL = 9,
} exc_build_status_t;

typedef enum en_exc_build_version {
    EXC_BUILD_VERSION_1 = 1,
    // add new versions here in the future if needed
} exc_build_version_t;

#define EXC_BUILD_CUR_VERSION   EXC_BUILD_VERSION_1

#define FOLLOWER_BUILD_PKT_RECV_TIMEOUT          300
#define FOLLOWER_BUILD_OK_REQ_SEND_TIMEOUT       10
#define LEADER_WAIT_FOLLOWER_RESTORE_TIMEOUT     300

#define BUILD_PKT_MAX_BODY_SIZE                  SIZE_K(60)
#define BUILD_FILE_MAX_NUM                       64

#define BUILD_PKT_CREDIT_NUM                     100
#define BUILD_PKTS_PER_ACK                       10

typedef struct st_exc_build_file_info_t {
    int32   fd;
    bool32  is_write_end;
    char    filename[CM_MAX_NAME_LEN];
} exc_build_file_info_t;

typedef struct st_exc_build_info_t {
    volatile uint32                 send_serial_number;
    volatile uint32                 recv_serial_number;
    volatile uint32                 leader_id;
    volatile uint32                 follower_id;
    volatile exc_build_status_t     build_status;
    volatile timespec_t             last_update_time;
    thread_t                        thread;
    cm_event_t                      send_event;
    volatile char                   old_restore_path[CM_FILE_NAME_BUFFER_SIZE];
    volatile exc_build_file_info_t  build_file[BUILD_FILE_MAX_NUM];
} exc_build_info_t;

typedef struct st_exc_build_msg_head_t {
    uint32 version;
    exc_build_cmd_t cmd;
    uint32 cur_size;
    uint32 cur_offset;
    uint32 filesize;
    uint32 serial_number;
    char reserved[8];   // reserved for future use
    char filename[CM_MAX_NAME_LEN];
} exc_build_msg_head_t;

typedef struct st_exc_build_msg_t {
    exc_build_msg_head_t head;
    char body[BUILD_PKT_MAX_BODY_SIZE];
} exc_build_msg_t;
 
static inline void exc_entry_inc_ref(msg_entry_t *entry)
{
    (void)cm_atomic32_inc(&entry->ref_count);
}

static inline void exc_entry_dec_ref(msg_entry_t *entry)
{
    int32 ref_count = cm_atomic32_dec(&entry->ref_count);
    CM_ASSERT(ref_count >= 0);
    if (ref_count == 0) {
        gfree(entry);
    }
}

typedef status_t (*exc_cb_consensus_proc_t)(const exc_consense_obj_t* obj);

/* executing interface API called by API and instance */
status_t exc_register_consensus_proc(exc_cb_consensus_proc_t cb_func);

status_t exc_register_status_notify_proc(dcc_cb_status_notify_t cb_func);

status_t exc_init(void);

void exc_deinit(void);

status_t exc_alloc_handle(void** handle);

void exc_free_handle(void* handle);

void *exc_alloc(uint64 size);

void exc_free(void *p);

status_t exc_read_handle4table(void *handle, const char *table_name);

status_t exc_put(void* handle, const text_t* buf, unsigned long long write_key, unsigned long long* index);

status_t exc_get(void* handle, text_t *key, text_t *val, uint32 read_level, bool32 *eof);

status_t exc_open_cursor(void* handle, text_t *key, uint32 read_level, bool32 *eof);

status_t exc_cursor_next(void* handle, bool32 *eof);

status_t exc_cursor_fetch(void* handle, text_t* result_key, text_t* result_value);

status_t exc_del(void* handle, const text_t* buf, unsigned long long write_key, unsigned long long* index);

status_t exc_watch(void* handle, const text_t* key, dcc_watch_proc_t proc, const dcc_option_t* option,
    text_t *watch_key);

status_t exc_unwatch(void* handle, const text_t* key, const dcc_option_t* option);

status_t exc_node_is_healthy(dcc_node_status_t *node_stat);

bool8 exc_is_leader(void);

bool32 exc_is_idle(void);

status_t exc_lease_create(void *handle, const text_t *buf, unsigned long long write_key, unsigned long long *index);
status_t exc_lease_destroy(void *handle, const text_t *buf, unsigned long long write_key, unsigned long long *index);
status_t exc_lease_renew(void *handle, const text_t *buf, unsigned long long write_key, unsigned long long *index);
status_t exc_lease_query(void *handle, const text_t *leasename, exc_lease_info_t *lease_info);

void exc_dealing_del(msg_entry_t* entry);
void exc_try_self_recovery(void);
status_t exc_check_first_init(void);
status_t exc_init_done_tryclean(void);

#ifdef __cplusplus
}
#endif

#endif
