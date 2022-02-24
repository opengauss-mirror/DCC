
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
 * srv_param.h
 *
 *
 * IDENTIFICATION
 *    src/server/srv_param.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SRV_PARAM_H__
#define __SRV_PARAM_H__

#include "cm_types.h"
#include "util_error.h"
#include "cm_defs.h"
#include "cm_log.h"
#include "cm_latch.h"
#include "cm_list.h"
#include "util_defs.h"
#include "cm_text.h"
#include "cm_utils.h"
#include "cm_file.h"


#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PARAM_RANGE_LEN (2 * CM_MAX_NUMBER_LEN + 4)
#define MAX_PARAM_NAME_LEN 100
#define MAX_PARAM_VALUE_LEN 512
#define MAX_PARAM_ENDPOINT_LIST_SIZE (SIZE_K(4) - MAX_PARAM_NAME_LEN)

typedef enum en_dcc_param {
    DCC_PARAM_UNKNOWN = 0,
    DCC_PARAM_DATA_PATH,
    DCC_PARAM_LOG_PATH,
    DCC_PARAM_LOG_LEVEL,
    DCC_PARAM_LOG_BACKUP_FILE_COUNT,
    DCC_PARAM_MAX_LOG_FILE_SIZE,
    DCC_PARAM_LOG_FILE_PERMISSION,
    DCC_PARAM_LOG_PATH_PERMISSION,
    DCC_PARAM_LOG_SUPPRESS_ENABLE,
    DCC_PARAM_OPTIMIZED_WORKER_THREADS,
    DCC_PARAM_MAX_WORKER_THREADS,
    DCC_PARAM_REACTOR_THREADS,
    DCC_PARAM_MAX_SESSIONS,
    DCC_PARAM_LSNR_ADDR,
    DCC_PARAM_LSNR_PORT,
    DCC_PARAM_MAX_ALLOWED_PACKET,
    DCC_PARAM_NODE_ID,
    DCC_PARAM_SRV_INST_POOL_INIT_SIZE,
    DCC_PARAM_SRV_INST_POOL_MAX_SIZE,
    DCC_PARAM_SRV_AGENT_SHRINK_THRESHOLD,
    DCC_PARAM_DB_TYPE,
    DCC_PARAM_DATA_BUFFER_SIZE,
    DCC_PARAM_BUF_POOL_NUM,
    DCC_PARAM_LOG_BUFFER_SIZE,
    DCC_PARAM_LOG_BUFFER_COUNT,
    DCC_PARAM_MAX_HANDLE,
    DCC_PARAM_SPACE_SIZE,
    DCC_PARAM_SSL_ENABLE,
    DCC_PARAM_SSL_CA,
    DCC_PARAM_SSL_KEY,
    DCC_PARAM_SSL_CERT,
    DCC_PARAM_SSL_VERIFY_PEER,
    DCC_PARAM_SSL_CRL,
    DCC_PARAM_SSL_CIPHER,
    DCC_PARAM_SSL_KEYPWD_FILE_PATH,
    DCC_PARAM_SSL_CERT_EXPIRE_ALERT_THRESHOLD,
    DCC_PARAM_SESS_APPLY_INST_NUM,
    DCC_PARAM_DCF_CONFIG,
    DCC_PARAM_DCF_ELECTION_TIMEOUT,
    DCC_PARAM_DCF_RUN_MODE,
    DCC_PARAM_DCF_MEC_AGENT_THREAD_NUM,
    DCC_PARAM_DCF_MEC_REACTOR_THREAD_NUM,
    DCC_PARAM_DCF_MEC_CHANNEL_NUM,
    DCC_PARAM_DCF_MEM_POOL_INIT_SIZE,
    DCC_PARAM_DCF_MEM_POOL_MAX_SIZE,
    DCC_PARAM_DCF_COMPRESS_ALGORITHM,
    DCC_PARAM_DCF_COMPRESS_LEVEL,
    DCC_PARAM_DCF_SOCKET_TIMEOUT,
    DCC_PARAM_DCF_CONNECT_TIMEOUT,
    DCC_PARAM_DCF_REP_APPEND_THREAD_NUM,
    DCC_PARAM_DCF_MEC_FRAGMENT_SIZE,
    DCC_PARAM_DCF_STG_POOL_INIT_SIZE,
    DCC_PARAM_DCF_STG_POOL_MAX_SIZE,
    DCC_PARAM_DCF_MEC_POOL_MAX_SIZE,
    DCC_PARAM_DCF_MEC_BATCH_SIZE,
    DCC_PARAM_DCF_FLOW_CONTROL_CPU_THRESHOLD,
    DCC_PARAM_DCF_FLOW_CONTROL_NET_QUEUE_MESSAGE_NUM_THRESHOLD,
    DCC_PARAM_DCF_FLOW_CONTROL_DISK_RAWAIT_THRESHOLD,
    DCC_PARAM_DCF_ELECTION_PRIORITY,
    DCC_PARAM_DCF_SSL_CA,
    DCC_PARAM_DCF_SSL_KEY,
    DCC_PARAM_DCF_SSL_CRL,
    DCC_PARAM_DCF_SSL_CERT,
    DCC_PARAM_DCF_SSL_CIPHER,
    DCC_PARAM_DCF_SSL_PWD_PLAINTEXT,
    DCC_PARAM_DCF_SSL_PWD_CIPHERTEXT,
    DCC_PARAM_DCF_SSL_CERT_NOTIFY_TIME,
    DCC_PARAM_CEIL
} dcc_param_t;

typedef union un_param_value {
    char str_val[MAX_PARAM_VALUE_LEN + 1];
    uint32 uint32_val;
    uint32 enum_val;
    uint64 uint64_val;
    char *long_str_val;
} param_value_t;

typedef enum en_param_val_type {
    PARAM_STRING,
    PARAM_INTEGER,
    PARAM_ENUM,
    PARAM_LONG_STRING,
    PARAM_UNKNOW
} param_val_type_t;

typedef enum en_config_effect {
    EFFECT_IMMEDIATELY = 0,
    EFFECT_REBOOT = 1
} param_effect_t;

typedef enum en_unit {
    UNIT_B = 0,
    UNIT_KB,
    UNIT_K,
    UNIT_MB,
    UNIT_M,
    UNIT_GB,
    UNIT_G,
    UNIT_TB,
    UNIT_T,
    UNIT_MS,
    UNIT_S,
    UNIT_MIN,
    UNIT_H,
    UNIT_D,
    UNIT_UNKNOW,
    UNIT_NONE
} param_unit_t;
typedef enum en_unit_type {
    UNIT_T_MEM,
    UNIT_T_TIME,
    UNIT_T_UNKNOW
} en_unit_type_t;

typedef struct st_unit {
    text_t unit_name;
    en_unit_type_t unit_type;
    uint64 unit_dimemsion;
} unit_t;


typedef status_t (*param_verify_t)(dcc_param_t param_id, const char *param_value, param_value_t *out_value);
typedef status_t (*param_notify_t)(dcc_param_t param_id, const char *param_value, param_value_t out_value);

typedef struct st_param_item {
    const char *name; // param name
    param_value_t value;
    param_verify_t verify;
    param_notify_t notify;
    param_val_type_t val_type;
    char *range; // [min_val, max_val]
    param_effect_t effect;
    param_unit_t unit;
} param_item_t;


status_t srv_get_param(dcc_param_t param_id, param_value_t *param_value);
// only used when DCC deployed with CM
status_t srv_set_param(const char *param_name, const char *param_value);

status_t get_param_id_by_name(const char *param_name, uint32 *param_id);
param_val_type_t get_param_val_type(uint32 param_id);
status_t get_param_name_by_id(uint32 param_id, char *param_name);
bool32 is_param_can_reloaded(uint32 param_id);

// verify function
status_t verify_param_string(dcc_param_t param_id, const char *param_value, param_value_t *out_value);
status_t verify_param_ip(dcc_param_t param_id, const char *param_value, param_value_t *out_value);
status_t verify_param_server_list(dcc_param_t param_id, const char *param_value, param_value_t *out_value);

status_t verify_param_uint64(dcc_param_t param_id, const char *param_value, param_value_t *out_value);

status_t verify_param_log_level(dcc_param_t param_id, const char *param_value, param_value_t *out_value);

status_t verify_param_enum(dcc_param_t param_id, const char *param_value, param_value_t *out_value);
status_t verify_param_long_string(dcc_param_t param_id, const char *param_value, param_value_t *out_value);
/**
 * will notify others after param value changed
 * @param param_id
 * @param param_value
 * @return CM_SUCCESS or CM_ERROR
 */
status_t notify_param_value(dcc_param_t param_id, const char *param_value, param_value_t out_value);
status_t notify_set_dcf_param(dcc_param_t param_id, const char *param_value, param_value_t out_value);

status_t parse_log_level_cfg(const char *log_cfg, uint32 *log_level);
#ifdef __cplusplus
}
#endif

#endif
