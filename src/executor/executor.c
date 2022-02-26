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
 * executor.c
 *
 *
 * IDENTIFICATION
 *    src/executor/executor.c
 *
 * -------------------------------------------------------------------------
 */

#include "executor.h"
#include "executor_watch.h"
#include "executor_watch_group.h"
#include "executor_lease.h"
#include "dcf_interface.h"
#include "util_stat.h"
#include "executor_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

static exc_msg_queue_t g_exc_msg_queue;
exc_check_thread_t g_exc_check_thread;
static uint32 g_current_node_dcf_role = DCF_ROLE_FOLLOWER;
static uint64 g_min_applied_idx = 0;
static uint64 g_min_applied_idx_frozen_cnt = 0;
static uint64 g_set_stg_applied_idx = 0;
static atomic_t g_node_commit_idx = 0;
static uint32 g_node_id = 0;
static exc_cb_consensus_proc_t  g_cb_consensus_proc_notify = NULL;
static dcc_cb_status_notify_t g_cb_status_notify = NULL;
static mem_pool_t *g_exc_mem_pool = NULL;

#define DCC_SEQUENCE_START          "0000000000"

static void exc_dealing_put(msg_entry_t* entry);

/* inner API */
bool8 exc_is_leader(void)
{
    bool8 ret = CM_FALSE;
    if (g_current_node_dcf_role == DCF_ROLE_LEADER) {
        ret = CM_TRUE;
    } else {
        ret = CM_FALSE;
    }
    return ret;
}

static dcc_role_t exc_exchange_role(dcf_role_t node_type)
{
    switch (node_type) {
        case DCF_ROLE_LEADER:
            return DCC_ROLE_LEADER;
        case DCF_ROLE_FOLLOWER:
            return DCC_ROLE_FOLLOWER;
        case DCF_ROLE_LOGGER:
            return DCC_ROLE_LOGGER;
        case DCF_ROLE_PASSIVE:
            return DCC_ROLE_PASSIVE;
        case DCF_ROLE_PRE_CANDIDATE:
            return DCC_ROLE_PRE_CANDIDATE;
        case DCF_ROLE_CANDIDATE:
            return DCC_ROLE_CANDIDATE;
        case DCF_ROLE_UNKNOWN:
        case DCF_ROLE_CEIL:
        default:
            return DCC_ROLE_UNKNOWN;
    }
}

static void dcf_log_output_callback(int log_type, int log_level, const char *code_file_name, uint32 code_line_num,
    const char *module_name, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (log_type == LOG_RUN || log_type == LOG_DEBUG || log_type == LOG_OPER || log_type == LOG_PROFILE) {
        cm_write_normal_log_common((log_type_t)log_type, (log_level_t)log_level, code_file_name, code_line_num,
            module_name, CM_TRUE, format, args);
    }
    va_end(args);
}

static status_t exc_set_dcf_param(param_value_t* dcf_config)
{
    char dcf_data_path[EXC_PATH_MAX_SIZE];
    param_value_t data_path, temp_node_id;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_DATA_PATH, &data_path));
    if (CM_IS_EMPTY_STR(data_path.str_val)) {
        LOG_RUN_ERR("[EXC] The data path got is empty.");
        return CM_ERROR;
    }
    int len = sprintf_s(dcf_data_path, EXC_PATH_MAX_SIZE, "%s/dcf_data", (char *)data_path.str_val);
    if (len < 0 || len > EXC_PATH_MAX_SIZE) {
        LOG_RUN_ERR("[EXC] Setting data path crosses the max size.");
        return CM_ERROR;
    }

    int ret = dcf_set_param("DATA_PATH", dcf_data_path);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC] Setting data path is failed.");
        return CM_ERROR;
    }

    // get node id
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_NODE_ID, &temp_node_id));
    g_node_id = temp_node_id.uint32_val;

    // get server list for json-config
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_DCF_CONFIG, dcf_config));
    if (CM_IS_EMPTY_STR(dcf_config->long_str_val)) {
        LOG_RUN_ERR("[EXC] DCF config string is empty.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t exc_set_dcf_applied_index(void)
{
    bool32 eof;
    uint64 applied_index = 0;
    text_t temp_key, stg_value;
    temp_key.str = (char *)EXC_DCF_APPLIED_INDEX_KEY;
    temp_key.len = EXC_DCF_APPLIED_INDEX_LEN;
    if (exc_wr_handle_get(DCC_RESERVED_TABLE_ID, &temp_key, &stg_value, &eof) != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC] Get the applied index from db storage failed.");
        return CM_ERROR;
    }

    if (!eof) {
        CM_RETURN_IFERR(cm_str2uint64(stg_value.str, &applied_index));
        if (dcf_set_applied_index(EXC_STREAM_ID_DEFAULT, applied_index) != CM_SUCCESS) {
            CM_THROW_ERROR(ERR_EXC_INIT_FAILED, "it sets local applied index");
            LOG_RUN_ERR("[EXC] Set the applied index for starting DCC failed.");
            return CM_ERROR;
        }
        (void)cm_atomic_set(&g_node_commit_idx, (int64)applied_index);
    }
    LOG_RUN_INF("[EXC] Set the local applied index:%llu for starting DCC.", applied_index);
    return CM_SUCCESS;
}

static void exc_check_applied_flag_entry(thread_t *thread)
{
    uint32 all_applied = CM_FALSE;
    date_t start_time, now;
    cm_set_thread_name("exc_check_applied_flag");
    start_time = 0;
    exc_check_thread_t* entry_info = (exc_check_thread_t *)thread->argument;

    while (!thread->closed) {
        cm_sleep(EXC_THREAD_SLEEP_TIME);

        cm_latch_x(&entry_info->lock, 0, NULL);
        if (entry_info->is_check_all_applied) {
            now = g_timer()->now;
            start_time = (start_time == 0) ? now : start_time;
            if (((uint64)(now - start_time)) / MICROSECS_PERP_MILLISEC >= EXC_DCF_WAIT_ALL_APPLY_TIMEOUT) {
                LOG_DEBUG_ERR("[EXC] Waiting all logs applied timeout.");
                entry_info->is_check_all_applied = CM_FALSE;
                start_time = 0;
                cm_unlatch(&entry_info->lock, NULL);
                continue;
            }

            if (dcf_check_if_all_logs_applied(EXC_STREAM_ID_DEFAULT, &all_applied) != CM_SUCCESS) {
                LOG_DEBUG_ERR("[EXC] Read all applied flag failed.");
            }
            if (!all_applied) {
                cm_unlatch(&entry_info->lock, NULL);
                continue;
            }
            if (exc_lease_promote() != CM_SUCCESS) {
                LOG_DEBUG_ERR("[EXC] exc lease promote failed.");
            }
            // update role
            g_current_node_dcf_role = entry_info->role_type;
            dcc_role_t role_type = exc_exchange_role((dcf_role_t)entry_info->role_type);
            if (g_cb_status_notify != NULL && g_cb_status_notify(role_type) != CM_SUCCESS) {
                LOG_DEBUG_ERR("[EXC] Callback node status notify func g_cb_status_notify failed.");
            }
            entry_info->is_check_all_applied = CM_FALSE;
            start_time = 0;
        }
        cm_unlatch(&entry_info->lock, NULL);
    }
}

static status_t exc_init_check_applied_flag_thread(void)
{
    MEMS_RETURN_IFERR(memset_sp(&g_exc_check_thread, sizeof(exc_check_thread_t), 0, sizeof(exc_check_thread_t)));
    CM_RETURN_IFERR(cm_create_thread(exc_check_applied_flag_entry, 0, &g_exc_check_thread,
        &g_exc_check_thread.thread));
    return CM_SUCCESS;
}

static void exc_uninit_applied_flag_thread(void)
{
    cm_close_thread(&g_exc_check_thread.thread);
}

static status_t exc_init_global_param(void)
{
    return exc_wr_handle_init();
}

static void exc_free_global_param(void)
{
    exc_wr_handle_deinit();
    g_current_node_dcf_role = 0;
    g_min_applied_idx = 0;
    g_set_stg_applied_idx = 0;
    (void)cm_atomic_set(&g_node_commit_idx, 0);
    g_node_id = 0;
    g_cb_consensus_proc_notify = NULL;
    g_cb_status_notify = NULL;
}

static inline status_t exc_get_uint64(const char* buff, uint32 size, uint64* value, uint32* offset)
{
    CM_ASSERT(buff != NULL);
    if (sizeof(uint64) + *offset > size) {
        LOG_RUN_ERR("[EXC] The length is over with remain size for parsing buff.");
        return CM_ERROR;
    }
    *value = *(uint64 *)(buff + *offset);
    *offset += sizeof(uint64);
    return CM_SUCCESS;
}

static inline status_t exc_get_uint32(const char* buff, uint32 size, uint32* value, uint32* offset)
{
    CM_ASSERT(buff != NULL);
    if (sizeof(uint32) + *offset > size) {
        LOG_RUN_ERR("[EXC] The length is over with remain size for parsing buff.");
        return CM_ERROR;
    }
    *value = *(uint32 *)(buff + *offset);
    *offset += sizeof(uint32);
    return CM_SUCCESS;
}

static status_t exc_get_text(const char* buff, uint32 size, text_t *text, uint32* offset)
{
    CM_ASSERT(buff != NULL);
    if (sizeof(uint32) + *offset > size) {
        LOG_RUN_ERR("[EXC] The length is over with remain size for parsing buff.");
        return CM_ERROR;
    }
    text->len = *(uint32 *)(buff + *offset);
    *offset += sizeof(uint32);
    if (text->len == 0) {
        text->str = NULL;
        return CM_SUCCESS;
    }
    text->str = (char *)(buff + *offset);
    *offset += CM_ALIGN4(text->len);
    return CM_SUCCESS;
}

static status_t exc_parse_request_info(const char* buf, uint32 size, msg_entry_t *entry)
{
    uint32 offset = 0;
    CM_RETURN_IFERR(exc_get_uint32(buf, size, &entry->cmd, &offset));
    if (entry->cmd == DCC_CMD_DELETE) {
        CM_RETURN_IFERR(exc_get_uint32(buf, size, &entry->all_op.del_op.is_prefix, &offset));
        CM_RETURN_IFERR(exc_get_text(buf, size, (text_t*)&entry->kvp.key, &offset));
        return CM_SUCCESS;
    } else if (entry->cmd == DCC_CMD_PUT) {
        CM_RETURN_IFERR(exc_get_uint32(buf, size, &entry->all_op.put_op.sequence, &offset));
        CM_RETURN_IFERR(exc_get_uint32(buf, size, &entry->all_op.put_op.not_existed, &offset));
        CM_RETURN_IFERR(exc_get_text(buf, size, (text_t*)&entry->kvp.value, &offset));
        CM_RETURN_IFERR(exc_get_text(buf, size, &entry->all_op.put_op.expect_value, &offset));
        CM_RETURN_IFERR(exc_get_text(buf, size, &entry->all_op.put_op.leaseid, &offset));
        CM_RETURN_IFERR(exc_get_text(buf, size, (text_t*)&entry->kvp.key, &offset));
    } else if (entry->cmd == DCC_CMD_LEASE_CREATE) {
        CM_RETURN_IFERR(exc_get_text(buf, size, (text_t*)&entry->all_op.lease_op.leaseid, &offset));
        CM_RETURN_IFERR(exc_get_uint32(buf, size, &entry->all_op.lease_op.ttl, &offset));
    } else if (entry->cmd == DCC_CMD_LEASE_DESTROY || entry->cmd == DCC_CMD_LEASE_EXPIRE ||
        entry->cmd == DCC_CMD_LEASE_RENEW) {
        CM_RETURN_IFERR(exc_get_text(buf, size, (text_t*)&entry->all_op.lease_op.leaseid, &offset));
    } else if (entry->cmd == DCC_CMD_LEASE_SYNC) {
        CM_RETURN_IFERR(exc_get_text(buf, size, (text_t*)&entry->all_op.lease_op.leaseid, &offset));
        CM_RETURN_IFERR(exc_get_uint64(buf, size, (uint64 *)&entry->all_op.lease_op.renew_time, &offset));
    }

    return CM_SUCCESS;
}

static status_t exc_dcf_wait_all_apply(void)
{
    bool32 is_healthy = CM_FALSE;
    dcf_role_t node_type;
    uint32 all_applied = CM_FALSE;
    date_t start_time = g_timer()->now;
    while (CM_TRUE) {
        cm_sleep(EXC_DCF_START_LOOP);
        if (dcf_node_is_healthy(EXC_STREAM_ID_DEFAULT, &node_type, &is_healthy) != CM_SUCCESS) {
            CM_THROW_ERROR(ERR_EXC_INIT_FAILED, "it gets healthy information");
            LOG_RUN_ERR("[EXC] Get healthy information failed on node %u.", g_node_id);
            return CM_ERROR;
        }
        if (node_type != DCF_ROLE_LEADER) {
            break;
        }

        if (node_type == DCF_ROLE_LEADER && is_healthy) {
            if (dcf_check_if_all_logs_applied(EXC_STREAM_ID_DEFAULT, &all_applied) != CM_SUCCESS) {
                CM_THROW_ERROR(ERR_EXC_INIT_FAILED, "it gets all applied flag");
                LOG_RUN_ERR("[EXC] Get all_applied flag failed on node %u.", g_node_id);
                return CM_ERROR;
            }
            if (all_applied) {
                g_current_node_dcf_role = DCF_ROLE_LEADER;
                break;
            }
        }

        date_t now = g_timer()->now;
        if (((uint64)(now - start_time)) / MICROSECS_PERP_MILLISEC >= EXC_DCF_WAIT_ALL_APPLY_TIMEOUT) {
            CM_THROW_ERROR(ERR_EXC_INIT_FAILED, "it waits all applied flag timeout");
            LOG_RUN_ERR("[EXC] Waiting all logs applied timeout.");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t exc_save_apply_index(uint64 index)
{
    text_t temp_key, temp_value;
    char data_value[EXC_DIGIT_MAX_SIZE];
    temp_key.str = (char *)EXC_DCF_APPLIED_INDEX_KEY;
    temp_key.len = EXC_DCF_APPLIED_INDEX_LEN;
    int len = sprintf_s(data_value, EXC_DIGIT_MAX_SIZE, "%llu", index);
    if (len < 0 || len > EXC_PATH_MAX_SIZE) {
        return CM_ERROR;
    }
    temp_value.str = data_value;
    temp_value.len = (uint32)len;
    exc_wr_handle_write_commit(DCC_RESERVED_TABLE_ID, &temp_key, &temp_value);
    g_set_stg_applied_idx = index;
    return CM_SUCCESS;
}

static bool32 exc_need_truncate(uint64 min_applied_idx, uint64 *first_index_kept)
{
    if (min_applied_idx >= g_min_applied_idx + EXC_DCF_TRUNCATE_SIZE) {
        g_min_applied_idx_frozen_cnt = 0;
        *first_index_kept = min_applied_idx;
        LOG_DEBUG_INF("[EXC] exc need truncate, set first_index_kept as min_applied_idx:%llu", min_applied_idx);
        return CM_TRUE;
    }

    g_min_applied_idx_frozen_cnt++;
    if (g_min_applied_idx_frozen_cnt > EXC_DCF_APPLY_IDX_FROZEN_CNT_THOLD) {
        uint64 total_disk_size;
        uint64 avail_disk_size;
        param_value_t data_path;
        if (srv_get_param(DCC_PARAM_DATA_PATH, &data_path) != CM_SUCCESS) {
            return CM_FALSE;
        }
        if (cm_get_disk_size(data_path.str_val, TOTAL_SIZE, &total_disk_size) != CM_SUCCESS) {
            return CM_FALSE;
        }
        if (cm_get_disk_size(data_path.str_val, AVAIL_SIZE, &avail_disk_size) != CM_SUCCESS) {
            return CM_FALSE;
        }
        if (total_disk_size != 0 && ((double)avail_disk_size) / total_disk_size <= EXC_DISK_AVAIL_RATE) {
            *first_index_kept = g_set_stg_applied_idx;
            g_min_applied_idx_frozen_cnt = 0;
            LOG_DEBUG_WAR("[EXC] exc need truncate, set first_index_kept as stg_applied_idx:%llu",
                g_set_stg_applied_idx);
            return CM_TRUE;
        }
        g_min_applied_idx_frozen_cnt = 0;
    }

    return CM_FALSE;
}

static status_t exc_dcf_truncate(void)
{
    uint64 min_applied_idx = 0;
    uint64 first_index_kept = 0;
    if (dcf_get_cluster_min_applied_idx(EXC_STREAM_ID_DEFAULT, (unsigned long long*)&min_applied_idx) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (exc_need_truncate(min_applied_idx, &first_index_kept) && first_index_kept <= g_set_stg_applied_idx) {
        int ret = dcf_truncate(EXC_STREAM_ID_DEFAULT, first_index_kept);
        if (ret != CM_SUCCESS) {
            CM_THROW_ERROR(ERR_EXC_TRUNCATE_FAILED, first_index_kept);
            LOG_DEBUG_ERR("[EXC] exc_dcf_truncate failed, first_index_kept=%llu", first_index_kept);
            return CM_ERROR;
        }
        g_min_applied_idx = first_index_kept;
        LOG_DEBUG_INF("[EXC] exc_dcf_truncate success, first_index_kept=%llu", first_index_kept);
    }

    return CM_SUCCESS;
}

static status_t exc_init_msg_queue(exc_msg_queue_t *msg_queue)
{
    GS_INIT_SPIN_LOCK(msg_queue->lock);
    biqueue_init(&msg_queue->msg_queue);

    if (cm_event_init(&msg_queue->event) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] exc_init_msg_queue init event failed.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static msg_entry_t* exc_add_entry(const char *buf, uint32 size, uint64 index, uint64 key)
{
    errno_t ret;
    uint64 total_size = sizeof(msg_entry_t) + size + 1;
    msg_entry_t *entry = (msg_entry_t *)exc_alloc(total_size);
    if (entry == NULL) {
        LOG_DEBUG_ERR("[EXC] exc_add_entry alloc msg entry failed.");
        return NULL;
    }
    ret = memset_sp(entry, total_size, 0, total_size);
    if (ret != EOK) {
        exc_free(entry);
        return NULL;
    }

    entry->write_key = key;
    entry->index     = index;
    entry->ref_count = 1;
    entry->sequence_no = 0;
    entry->buf = (char *)entry + sizeof(msg_entry_t);
    errno_t errcode = memcpy_s(entry->buf, size + 1, buf, size);
    if (errcode != EOK) {
        exc_free(entry);
        LOG_DEBUG_ERR("[EXC] exc_add_entry copy buff failed.");
        return NULL;
    }
    entry->buf[size] = '\0';
    return entry;
}

static inline void exc_append_db_task(msg_entry_t *entry)
{
    exc_entry_inc_ref(entry);
    cm_spin_lock(&g_exc_msg_queue.lock, NULL);
    biqueue_add_tail(&g_exc_msg_queue.msg_queue, QUEUE_NODE_OF(entry));
    cm_spin_unlock(&g_exc_msg_queue.lock);
    cm_event_notify(&g_exc_msg_queue.event);
}

static inline void call_srv_callback(const msg_entry_t* entry, bool32 result)
{
    if (g_cb_consensus_proc_notify == NULL) {
        return;
    }
    // call session func
    exc_consense_obj_t obj;
    obj.key = entry->write_key;
    obj.cmd = entry->cmd;
    obj.index = entry->index;
    obj.cmd_result = result;
    obj.sequence = entry->sequence_no;
    (void)g_cb_consensus_proc_notify(&obj);
}

int exc_cb_consensus_follow_notify(unsigned int stream_id, unsigned long long index,
    const char *buf, unsigned int size, unsigned long long key)
{
    uint32 total_size = size + CM_SEQUENCE_OFFSET;
    msg_entry_t *entry = exc_add_entry(buf, total_size, index, key);
    if (entry == NULL) {
        LOG_RUN_ERR("[EXC] Add entry failed when it executes consensus-notify function.");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(exc_parse_request_info(entry->buf, total_size, entry));
    exc_append_db_task(entry);

    if ((entry->cmd == DCC_CMD_DELETE) ||
        (entry->cmd == DCC_CMD_PUT &&
        (CM_IS_EMPTY(&entry->all_op.put_op.expect_value) &&
        entry->all_op.put_op.sequence == 0 &&
        entry->all_op.put_op.not_existed == 0))) {
        call_srv_callback(entry, CM_TRUE);
    }
    exc_entry_dec_ref(entry);
    return CM_SUCCESS;
}

int exc_cb_consensus_leader_notify(unsigned int stream_id, unsigned long long index,
    const char *buf, unsigned int size, unsigned long long key, int error_no)
{
    return exc_cb_consensus_follow_notify(stream_id, index, buf, size, key);
}

int exc_cb_status_notify(unsigned int stream_id, dcf_role_t new_role)
{
    if (g_current_node_dcf_role == DCF_ROLE_FOLLOWER && new_role == DCF_ROLE_LEADER) {
        // awaken thread to wait all applied flag.
        cm_latch_x(&g_exc_check_thread.lock, 0, NULL);
        g_exc_check_thread.is_check_all_applied = CM_TRUE;
        g_exc_check_thread.role_type = new_role;
        cm_unlatch(&g_exc_check_thread.lock, NULL);
        return CM_SUCCESS;
    }

    exc_lease_demote();

    // update role
    g_current_node_dcf_role = new_role;
    dcc_role_t role_type = exc_exchange_role(new_role);
    LOG_RUN_INF("[EXC] Role has changed to %u .", new_role);
    if (g_cb_status_notify != NULL && g_cb_status_notify(role_type) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int exc_register_logger_cb_func(void)
{
    int ret;
    log_param_t *log_param = cm_log_param_instance();
    if (log_param->log_write != NULL) {
        ret = dcf_register_log_output(log_param->log_write);
    } else {
        ret = dcf_register_log_output(dcf_log_output_callback);
    }
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC]Setting dcf log callback is failed.");
    }
    return ret;
}

static status_t exc_dcf_start(void)
{
    // register p cb
    if (dcf_register_after_writer(exc_cb_consensus_leader_notify) != CM_SUCCESS) {
        return CM_ERROR;
    }

    // register s cb
    if (dcf_register_consensus_notify(exc_cb_consensus_follow_notify) != CM_SUCCESS) {
        return CM_ERROR;
    }

    // register status cb
    if (dcf_register_status_notify(exc_cb_status_notify) != CM_SUCCESS) {
        return CM_ERROR;
    }

    // register log callback func
    if (exc_register_logger_cb_func() != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC] Register logger callback function failed.");
        return CM_ERROR;
    }

    // set param
    param_value_t dcf_config;
    if (exc_set_dcf_param(&dcf_config) != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC] Set dcf parameters failed.");
        return CM_ERROR;
    }

    // set apply index
    CM_RETURN_IFERR(exc_set_dcf_applied_index());

    if (dcf_start(g_node_id, dcf_config.long_str_val) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_EXC_INIT_FAILED, "it starts DCF mode");
        LOG_RUN_ERR("[EXC] Start dcf failed on node %u.", g_node_id);
        return CM_ERROR;
    }
    // waiting all logs applied
    CM_RETURN_IFERR(exc_dcf_wait_all_apply());
    return CM_SUCCESS;
}

static inline void exc_push_apply_index(uint64 index)
{
    (void)cm_atomic_set(&g_node_commit_idx, (int64)index);

    // save apply index to stg for starting dcf
    if (exc_save_apply_index(index) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] Saved applied index failed on leader.");
    }

    // truncate
    if (exc_dcf_truncate() != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] Truncate dcf applied index failed on leader.");
    }
}

static inline status_t exc_text2uint32(const text_t *text, uint32* val)
{
    char buf[CM_SEQUENCE_OFFSET + 1] = {0};
    CM_RETURN_IFERR(cm_text2str(text, buf, CM_SEQUENCE_OFFSET + 1));
    return cm_str2uint32(buf, val);
}

static status_t exc_write_sequence(msg_entry_t* entry)
{
    bool32 eof;
    text_t val;
    status_t ret = exc_wr_handle_get(DCC_SEQUENCE_TABLE_ID, (text_t*)ENTRY_K(entry), &val, &eof);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC]open cursor for sequence failed, ret:%d", ret);
        return ret;
    }
    if (eof) {
        if (entry->all_op.put_op.sequence != 0 && entry->kvp.key.len != 0) {
            cm_concat_fmt((text_t*)&entry->kvp.key, CM_SEQUENCE_OFFSET + 1, "%s", DCC_SEQUENCE_START);
        }
    } else {
        uint32 sequence = 0;
        ret = exc_text2uint32(&val, &sequence);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[EXC]convert sequence to number failed, ret:%d", ret);
        }
        LOG_DEBUG_INF("[EXC]the sequence is %u", sequence);
        entry->sequence_no = sequence + 1;
        text_t tmp = {.str = entry->kvp.key.value + entry->kvp.key.len, .len = 0};
        cm_concat_fmt(&tmp, CM_SEQUENCE_OFFSET + 1, "%010d", entry->sequence_no);
        entry->kvp.key.len += CM_SEQUENCE_OFFSET;
    }
    // update sequence
    text_t num_key = {.str = ((text_t*)ENTRY_K(entry))->str,
        .len = ((text_t*)ENTRY_K(entry))->len - CM_SEQUENCE_OFFSET};
    text_t num_val = {.str = (((text_t*)ENTRY_K(entry))->str + ((text_t*)ENTRY_K(entry))->len) - CM_SEQUENCE_OFFSET,
        .len = (uint32) CM_SEQUENCE_OFFSET};

    exc_wr_handle_put(DCC_SEQUENCE_TABLE_ID, &num_key, &num_val);

    return CM_SUCCESS;
}

static inline status_t key_existed(text_t* key, bool32* existed)
{
    text_t value;
    bool32 eof = CM_FALSE;
    if (exc_wr_handle_get(DCC_KV_TABLE_ID, key, &value, &eof) != CM_SUCCESS) {
        return CM_ERROR;
    }
    *existed = (eof == CM_TRUE) ? CM_FALSE : CM_TRUE;
    return CM_SUCCESS;
}

static void exc_watch_notify(msg_entry_t* entry, int watch_event)
{
    status_t ret = exc_watch_cb_proc(entry, watch_event);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] Func exc_watch_cb_proc execute cmd:%d failed on leader.", watch_event);
    }
    ret = exc_watch_group_proc(entry, watch_event);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] Func exc_watch_group_proc execute cmd:%d failed on leader.", watch_event);
    }
}

void exc_dealing_del(msg_entry_t* entry)
{
    uint32 count = 0;

    exc_wr_handle_delete(DCC_KV_TABLE_ID, (text_t *) ENTRY_K(entry), entry->all_op.del_op.is_prefix, &count);
    if (count == 0) {
        return;
    }
    exc_watch_notify(entry, DCC_WATCH_EVENT_DELETE);

    exc_wr_handle_delete(DCC_SEQUENCE_TABLE_ID, (text_t *) ENTRY_K(entry), entry->all_op.del_op.is_prefix, &count);
}

static void exc_dealing_put(msg_entry_t* entry)
{
    exc_wr_handle_put(DCC_KV_TABLE_ID, (text_t *) ENTRY_K(entry), (text_t *) ENTRY_V(entry));
    exc_watch_notify(entry, DCC_WATCH_EVENT_PUT);
}

static void exc_dealing_lease(const msg_entry_t* entry)
{
    status_t ret;
    if (entry->cmd == DCC_CMD_LEASE_CREATE) {
        ret = exc_cb_consensus_lease_create(&(entry->all_op.lease_op.leaseid), entry->all_op.lease_op.ttl);
    } else if (entry->cmd == DCC_CMD_LEASE_DESTROY || entry->cmd == DCC_CMD_LEASE_EXPIRE) {
        ret = exc_cb_consensus_lease_destroy(&(entry->all_op.lease_op.leaseid));
    } else if (entry->cmd == DCC_CMD_LEASE_RENEW) {
        ret = exc_cb_consensus_lease_renew(&(entry->all_op.lease_op.leaseid));
    } else if (entry->cmd == DCC_CMD_LEASE_SYNC) {
        ret = exc_cb_consensus_lease_sync(&(entry->all_op.lease_op.leaseid), entry->all_op.lease_op.renew_time);
    } else {
        ret = CM_ERROR;
    }
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc dealing lease failed, cmd:%u leaseid:%s",
            entry->cmd, entry->all_op.lease_op.leaseid.str);
    }
    if (entry->cmd == DCC_CMD_LEASE_CREATE || entry->cmd == DCC_CMD_LEASE_DESTROY ||
        entry->cmd == DCC_CMD_LEASE_RENEW) {
        bool32 result = (ret == CM_SUCCESS) ? CM_TRUE : CM_FALSE;
        call_srv_callback(entry, result);
    }
}

static inline bool32 expect_value_exists(text_t* key, const text_t* expect_val)
{
    text_t value;
    bool32 eof = CM_FALSE;

    if (exc_wr_handle_get(DCC_KV_TABLE_ID, key, &value, &eof) != CM_SUCCESS) {
        return CM_FALSE;
    }

    if (eof || !cm_text_equal(&value, expect_val)) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

static inline void exc_dealing_cas(msg_entry_t* entry)
{
    if (!expect_value_exists((text_t*)ENTRY_K(entry), &entry->all_op.put_op.expect_value)) {
        call_srv_callback(entry, CM_FALSE);
        return;
    }

    call_srv_callback(entry, CM_TRUE);
    exc_dealing_put(entry);
}

static void exc_dealing_sequence(msg_entry_t *entry)
{
    status_t ret = exc_write_sequence(entry);
    if (ret != CM_SUCCESS) {
        call_srv_callback(entry, CM_FALSE);
        return;
    }
    call_srv_callback(entry, CM_TRUE);
    exc_dealing_put(entry);
}

static inline void exc_dealing_create(msg_entry_t *entry)
{
    bool32 existed = CM_FALSE;

    status_t ret = key_existed((text_t *) ENTRY_K(entry), &existed);
    if (ret != CM_SUCCESS || existed) {
        call_srv_callback(entry, CM_FALSE);
        return;
    }
    call_srv_callback(entry, CM_TRUE);

    exc_dealing_put(entry);
}

static status_t exc_dealing_put_attach_lease(const msg_entry_t* entry)
{
    const text_t *leaseid = &(entry->all_op.put_op.leaseid);
    text_t *entry_key = (text_t*)ENTRY_K(entry);
    bool32 eof = CM_TRUE;
    uint32 size = EXC_LEASE_KEY_PREFIX_LEN + entry_key->len;
    char *lease_key = (char *)exc_alloc(size);
    if (lease_key == NULL) {
        LOG_DEBUG_ERR("exc_alloc leasekey buf failed.");
        return CM_ERROR;
    }
    if (memcpy_s(lease_key, size, EXC_LEASE_KEY_PREFIX, EXC_LEASE_KEY_PREFIX_LEN) != EOK) {
        exc_free(lease_key);
        return CM_ERROR;
    }
    if (memcpy_s(lease_key + EXC_LEASE_KEY_PREFIX_LEN, size - EXC_LEASE_KEY_PREFIX_LEN,
        entry_key->str, entry_key->len) != EOK) {
        exc_free(lease_key);
        return CM_ERROR;
    }
    text_t key = {
        .str = lease_key,
        .len = EXC_LEASE_KEY_PREFIX_LEN + entry_key->len };
    text_t val = { 0 };
    status_t ret = exc_wr_handle_get(DCC_LEASE_TABLE_ID, &key, &val, &eof);
    exc_free(lease_key);
    if (ret == CM_SUCCESS && eof == CM_FALSE) {
        CM_RETURN_IFERR(exc_cb_consensus_lease_detach(entry_key, &val));
    }

    return exc_cb_consensus_lease_attach(entry_key, leaseid);
}

static void exc_dealing_single_entry(msg_entry_t* entry)
{
    if (entry->cmd == DCC_CMD_PUT) {
        if (!CM_IS_EMPTY(&entry->all_op.put_op.expect_value)) {
            exc_dealing_cas(entry);
        } else {
            if (entry->all_op.put_op.not_existed) {
                exc_dealing_create(entry);
            } else if (entry->all_op.put_op.sequence) {
                exc_dealing_sequence(entry);
            } else {
                exc_dealing_put(entry);
            }
        }
        if (!CM_IS_EMPTY(&entry->all_op.put_op.leaseid)) {
            if (exc_dealing_put_attach_lease(entry) != CM_SUCCESS) {
                LOG_DEBUG_ERR("[EXC] dealing put attach lease failed.");
            }
        }
    } else if (entry->cmd == DCC_CMD_DELETE) {
        exc_dealing_del(entry);
    } else if (entry->cmd >= DCC_CMD_LEASE_FLOOR && entry->cmd <= DCC_CMD_LEASE_CEIL) {
        exc_dealing_lease(entry);
    }

    exc_entry_dec_ref(entry);
}

static void exc_msg_process(biqueue_t* msg_queue)
{
    uint32 count = 0;
    uint64 last_index  = 0;
    msg_entry_t* entry = NULL;
    biqueue_node_t *node = biqueue_del_head(msg_queue);

    exc_wr_handle_begin();

    while (node != NULL) {
        entry = OBJECT_OF(msg_entry_t, node);
        last_index = entry->index;

        exc_dealing_single_entry(entry);

        if (++count == EXC_MSG_BATCH_COMMIT) {
            exc_wr_handle_commit();
            exc_push_apply_index(last_index);
            exc_wr_handle_begin();
            count = 0;
        }
        node = biqueue_del_head(msg_queue);
    }

    exc_wr_handle_commit();
    if (count > 0) {
        exc_push_apply_index(last_index);
    }
}

static inline void exc_get_queue_flush_info(biqueue_t* msg_queue)
{
    cm_spin_lock(&g_exc_msg_queue.lock, NULL);
    biqueue_move(msg_queue, &g_exc_msg_queue.msg_queue);
    cm_spin_unlock(&g_exc_msg_queue.lock);
}

static void exc_msg_dealing_entry(thread_t *thread)
{
    cm_set_thread_name("exc_msg_dealing");

    biqueue_t msg_queue;
    biqueue_init(&msg_queue);
    while (!thread->closed) {
        if (biqueue_empty(&g_exc_msg_queue.msg_queue)) {
            (void)cm_event_timedwait(&g_exc_msg_queue.event, EXC_SLEEP_1_FIXED);
            continue;
        }

        exc_get_queue_flush_info(&msg_queue);
        // dealing with every entry
        exc_msg_process(&msg_queue);
    }
}

static status_t exc_init_msg_dealing_thread(void)
{
    CM_RETURN_IFERR(cm_create_thread(exc_msg_dealing_entry, 0, NULL, &g_exc_msg_queue.thread));
    return CM_SUCCESS;
}

static void exc_uninit_msg_dealing_thread(void)
{
    cm_close_thread(&g_exc_msg_queue.thread);
}

static status_t exc_init_srv_mem_pool(void)
{
    if (g_exc_mem_pool == NULL) {
        g_exc_mem_pool = (mem_pool_t *)malloc(sizeof(mem_pool_t));
        if (g_exc_mem_pool == NULL) {
            CM_THROW_ERROR(ERR_MALLOC_MEM, "it init server memory pool");
            LOG_DEBUG_ERR("[EXC]exc_init_srv_mem_pool malloc failed.");
            return CM_ERROR;
        }
    }

    param_value_t init_size, max_size;
    CM_RETURN_IFERR_EX(srv_get_param(DCC_PARAM_SRV_INST_POOL_INIT_SIZE, &init_size), CM_FREE_PTR(g_exc_mem_pool));
    CM_RETURN_IFERR_EX(srv_get_param(DCC_PARAM_SRV_INST_POOL_MAX_SIZE, &max_size), CM_FREE_PTR(g_exc_mem_pool));
    if (buddy_pool_init((char *)"dcc_srv", init_size.uint64_val, max_size.uint64_val, g_exc_mem_pool) != CM_SUCCESS) {
        CM_FREE_PTR(g_exc_mem_pool);
        CM_THROW_ERROR(ERR_EXC_INIT_FAILED, "it init server memory pool");
        LOG_RUN_ERR("[EXC]Init buddy pool failed.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void exc_uninit_srv_mem_pool(void)
{
    if (g_exc_mem_pool == NULL) {
        return;
    }
    buddy_pool_deinit(g_exc_mem_pool);
    CM_FREE_PTR(g_exc_mem_pool);
}

static dcf_commit_index_type_t exc_get_dcf_commit_index_type(uint32 read_level)
{
    if (read_level == DCC_READ_LEVEL_CONSISTENT) {
        return DCF_CONSENSUS_COMMIT_INDEX;
    } else if (read_level == DCC_READ_LEVEL_LEADER) {
        return DCF_LEADER_COMMIT_INDEX;
    } else if (read_level == DCC_READ_LEVEL_LOCAL) {
        return DCF_LOCAL_COMMIT_INDEX;
    }
    return DCF_INDEX_UNKNOWN;
}

static int exc_get_last_commit_index(uint32 read_level, unsigned long long* dcf_commit_index)
{
    dcf_commit_index_type_t index_type = exc_get_dcf_commit_index_type(read_level);
    if (index_type == DCF_INDEX_UNKNOWN) {
        LOG_DEBUG_ERR("[EXC]exc get last commit index with unknown index type: %u", index_type);
        return CM_ERROR;
    }
    return dcf_get_data_commit_index(EXC_STREAM_ID_DEFAULT, index_type, dcf_commit_index);
}

static status_t exc_wait_local_commit_index(unsigned long long dcf_commit_index)
{
    uint32 wait_time = 0;
    uint64 db_commit_index = (uint64)cm_atomic_get(&g_node_commit_idx);

    while (dcf_commit_index > db_commit_index) {
        cm_sleep(1); // ms
        wait_time++;
        if (wait_time >= EXC_WAIT_DB_COMMIT_TIMEOUT) {
            CM_THROW_ERROR(ERR_EXC_WAIT_COMMIT_INDEX, "");
            LOG_DEBUG_ERR("[EXC] Exc waits db commit timeout for time:%d ms, wait_index:%llu db_commit_index:%llu",
                EXC_WAIT_DB_COMMIT_TIMEOUT, dcf_commit_index, db_commit_index);
            return CM_ERROR;
        }
        db_commit_index = (uint64)cm_atomic_get(&g_node_commit_idx);
    }
    return CM_SUCCESS;
}

/* executing interface API called by API and instance */
status_t exc_init(void)
{
    // init global param
    CM_RETURN_IFERR(exc_init_global_param());

    // init dcc srv mem pool
    CM_RETURN_IFERR(exc_init_srv_mem_pool());

    // init watch
    CM_RETURN_IFERR(exc_watch_init());

    // init watch group
    CM_RETURN_IFERR(exc_watch_group_init());

    // init check all apply thread
    CM_RETURN_IFERR(exc_init_check_applied_flag_thread());

    // alloc msg cash
    CM_RETURN_IFERR(exc_init_msg_queue(&g_exc_msg_queue));
    // init stg dealing thread
    CM_RETURN_IFERR(exc_init_msg_dealing_thread());

    // init lease mgr
    CM_RETURN_IFERR(exc_lease_mgr_init());

    // start dcf
    CM_RETURN_IFERR(exc_dcf_start());

    if (exc_is_leader()) {
        CM_RETURN_IFERR(exc_lease_promote());
    }

    return CM_SUCCESS;
}

void exc_deinit(void)
{
    (void)dcf_stop();

    exc_uninit_msg_dealing_thread();
    exc_uninit_applied_flag_thread();

    exc_lease_mgr_deinit();
    exc_watch_deinit();
    exc_watch_group_deinit();
    exc_uninit_srv_mem_pool();
    exc_free_global_param();
}

status_t exc_register_consensus_proc(exc_cb_consensus_proc_t cb_func)
{
    g_cb_consensus_proc_notify = cb_func;
    return CM_SUCCESS;
}

status_t exc_register_status_notify_proc(dcc_cb_status_notify_t cb_func)
{
    g_cb_status_notify = cb_func;
    return CM_SUCCESS;
}

status_t exc_alloc_handle(void** handle)
{
    return db_alloc(handle);
}

void exc_free_handle(void* handle)
{
    db_free(handle);
}

void *exc_alloc(uint64 size)
{
    return galloc(size, g_exc_mem_pool);
}

void exc_free(void *p)
{
    if (p != NULL) {
        gfree(p);
    }
}

status_t exc_read_handle4table(void *handle, const char *table_name)
{
    return db_open_table(handle, table_name);
}

status_t exc_put(void* handle, const text_t* buf, unsigned long long write_key, unsigned long long* index)
{
    if (buf->str == NULL || buf->len == 0) {
        return CM_ERROR;
    }

    if (dcf_universal_write(EXC_STREAM_ID_DEFAULT, buf->str, buf->len, write_key, index) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_EXC_PUT_FAILED, "");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t exc_get(void* handle, text_t *key, text_t *val, uint32 read_level, bool32 *eof)
{
    uint64 dcf_commit_index = 0;
    if (exc_get_last_commit_index(read_level, &dcf_commit_index) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_EXC_GET_LAST_COMMIT_INDEX, "it executes get operation");
        LOG_DEBUG_ERR("[EXC] Executor gets last commit index failed for getting-operation");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(exc_wait_local_commit_index(dcf_commit_index));
    return db_get(handle, key, val, eof);
}

status_t exc_open_cursor(void* handle, text_t *key, uint32 read_level, bool32 *eof)
{
    uint64 dcf_commit_index = 0;
    if (exc_get_last_commit_index(read_level, &dcf_commit_index) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_EXC_GET_LAST_COMMIT_INDEX, "it executes open cursor operation");
        LOG_DEBUG_ERR("[EXC] Executor gets last commit index failed for opening-operation");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(exc_wait_local_commit_index(dcf_commit_index));
    return db_open_cursor(handle, key, CM_PREFIX_FLAG, eof);
}

status_t exc_cursor_next(void* handle, bool32 *eof)
{
    return db_cursor_next(handle, eof);
}

status_t exc_cursor_fetch(void* handle, text_t* result_key, text_t* result_value)
{
    return db_cursor_fetch(handle, result_key, result_value);
}

status_t exc_del(void* handle, const text_t* buf, unsigned long long write_key, unsigned long long* index)
{
    if (buf->str == NULL || buf->len == 0) {
        return CM_ERROR;
    }

    if (dcf_universal_write(EXC_STREAM_ID_DEFAULT, buf->str, buf->len, write_key, index) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_EXC_DEL_FAILED, "");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t exc_watch(void* handle, const text_t* key, dcc_watch_proc_t proc, const dcc_option_t* option,
    text_t* watch_key)
{
    if (option->watch_op.is_prefix) {
        return exc_watch_group_insert(key, option->sid, proc, watch_key);
    }
    return exc_add_watch(key, option->sid, proc, watch_key);
}

status_t exc_unwatch(void* handle, const text_t* key, const dcc_option_t* option)
{
    if (option->watch_op.is_prefix) {
        exc_watch_group_delete(key, option->sid);
        return CM_SUCCESS;
    }
    exc_del_watch(key, option->sid);
    return CM_SUCCESS;
}

status_t exc_node_is_healthy(dcc_node_status_t *node_stat)
{
    // dcf interface
    bool32 is_healthy = CM_FALSE;
    dcf_role_t node_type;
    if (dcf_node_is_healthy(EXC_STREAM_ID_DEFAULT, &node_type, &is_healthy) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_EXC_GET_HEALTHY_INFO, "");
        LOG_DEBUG_ERR("[EXC] Executor gets node healthy information failed");
        return CM_ERROR;
    }
    node_stat->role_type = exc_exchange_role(node_type);
    node_stat->is_healthy = is_healthy;
    return CM_SUCCESS;
}

bool32 exc_is_idle(void)
{
    bool32 eof;
    text_t applied_key, applied_val;
    uint64 applied_idx = 0;
    uint64 dcf_commit_index = CM_INVALID_ID64;
    int ret = dcf_get_data_commit_index(EXC_STREAM_ID_DEFAULT, DCF_LOCAL_COMMIT_INDEX, &dcf_commit_index);
    if (ret != CM_SUCCESS && dcf_commit_index != 0) {
        LOG_RUN_ERR("[EXC] get data commit index failed");
        return CM_FALSE;
    }
    applied_key.str = (char *)EXC_DCF_APPLIED_INDEX_KEY;
    applied_key.len = EXC_DCF_APPLIED_INDEX_LEN;
    if (exc_wr_handle_get(DCC_RESERVED_TABLE_ID, &applied_key, &applied_val, &eof) != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC] get applied index failed.");
        return CM_FALSE;
    }
    if (!eof) {
        status_t ret1 = cm_str2uint64(applied_val.str, &applied_idx);
        if (ret1 != CM_SUCCESS) {
            return CM_FALSE;
        }
    }
    if (applied_idx >= dcf_commit_index) {
        LOG_DEBUG_INF("[EXC] no tasks to do");
        return CM_TRUE;
    }
    return CM_FALSE;
}

#ifdef __cplusplus
}
#endif

