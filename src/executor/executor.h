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

#ifdef __cplusplus
}
#endif

#endif
