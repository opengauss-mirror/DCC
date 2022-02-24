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
 * srv_param.c
 *    API
 *
 * IDENTIFICATION
 *    src/server/srv_param.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include "cm_error.h"
#include "cm_log.h"
#include "cm_text.h"
#include "cm_num.h"
#include "cm_latch.h"
#include "cm_date.h"
#include "cm_ip.h"
#include "util_defs.h"
#include "dcf_interface.h"
#include "srv_param.h"


#ifdef __cplusplus
extern "C" {
#endif
static latch_t latch = {0};

#define PARAM_FIX_NUM_2 2

#define MAX_LOG_LEVEL_SIZE 10

#define DCF_RUN_MODE_AUTO 0
#define DCF_RUN_MODE_MANUAL 1
#define DCF_RUN_MODE_DISABLE 2

static char *g_log_level_str[MAX_LOG_LEVEL_SIZE] = {
    "RUN_ERR", "RUN_WAR", "RUN_INF", "DEBUG_ERR", "DEBUG_WAR", "DEBUG_INF", "MEC", "OPER", "TRACE", "PROFILE"};
static uint32 g_log_level_val[MAX_LOG_LEVEL_SIZE] = {
    LOG_RUN_ERR_LEVEL,
    LOG_RUN_WAR_LEVEL,
    LOG_RUN_INF_LEVEL,
    LOG_DEBUG_ERR_LEVEL,
    LOG_DEBUG_WAR_LEVEL,
    LOG_DEBUG_INF_LEVEL,
    LOG_MEC_LEVEL,
    LOG_OPER_LEVEL,
    LOG_TRACE_LEVEL,
    LOG_PROFILE_LEVEL
};
static unit_t g_units[] = {
    [UNIT_B]={{"B", 1}, UNIT_T_MEM, 1},
    [UNIT_KB]={{"KB", 2}, UNIT_T_MEM, SIZE_K(1)},
    [UNIT_K]={{"K", 1}, UNIT_T_MEM, SIZE_K(1)},
    [UNIT_MB]={{"MB", 2}, UNIT_T_MEM, SIZE_M(1)},
    [UNIT_M]={{"M", 1}, UNIT_T_MEM, SIZE_M(1)},
    [UNIT_GB]={{"GB", 2}, UNIT_T_MEM, SIZE_G(1)},
    [UNIT_G]={{"G", 1}, UNIT_T_MEM, SIZE_G(1)},
    [UNIT_TB]={{"TB", 2}, UNIT_T_MEM, SIZE_T(1)},
    [UNIT_T]={{"T", 1}, UNIT_T_MEM, SIZE_T(1)},
    [UNIT_MS]={{"MS", 2}, UNIT_T_TIME, 1},
    [UNIT_S]={{"S", 1}, UNIT_T_TIME, MILLISECS_PER_SECOND},
    [UNIT_MIN]={{"MIN", 3}, UNIT_T_TIME, SECONDS_PER_MIN * MILLISECS_PER_SECOND},
    [UNIT_H]={{"H", 1}, UNIT_T_TIME, SECONDS_PER_HOUR * MILLISECS_PER_SECOND},
    [UNIT_D]={{"D", 1}, UNIT_T_TIME, SECONDS_PER_DAY * MILLISECS_PER_SECOND},
    [UNIT_NONE]={{"-", 1}, UNIT_T_UNKNOW, 1}
};
// from enum to value array
uint32 log_file_perm_values[] = {DEFAULT_LOG_FILE_PERMISSION, MAX_LOG_FILE_PERMISSION};
uint32 log_path_perm_values[] = {DEFAULT_LOG_PATH_PERMISSION, MAX_LOG_PATH_PERMISSION};

uint32 dcf_run_mode_values[] = {DCF_RUN_MODE_AUTO, DCF_RUN_MODE_DISABLE};
static char g_param_endpoint_list[MAX_PARAM_ENDPOINT_LIST_SIZE] = {0};

static param_item_t g_parameters[] = {
    [DCC_PARAM_DATA_PATH] = {"DATA_PATH",
        {.str_val = ""},
        verify_param_string,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_LOG_PATH] = {"LOG_PATH",
        {.str_val = ""},
        verify_param_string,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_LOG_LEVEL] = {"LOG_LEVEL",
        {.str_val = "RUN_ERR|RUN_WAR|RUN_INF|DEBUG_ERR|DEBUG_WAR|OPER|PROFILE"},
        verify_param_log_level,
        notify_param_value,
        PARAM_STRING,
        "RUN_ERR|RUN_WAR|RUN_INF|DEBUG_ERR|DEBUG_WAR|DEBUG_INF|OPER|TRACE|PROFILE",
        EFFECT_IMMEDIATELY,
        UNIT_NONE},
    [DCC_PARAM_LOG_BACKUP_FILE_COUNT] = {"LOG_BACKUP_FILE_COUNT",
        {.uint32_val = 10},
        verify_param_uint64,
        notify_param_value,
        PARAM_INTEGER,
        "[1,100]",
        EFFECT_IMMEDIATELY,
        UNIT_NONE},
    [DCC_PARAM_MAX_LOG_FILE_SIZE] = {"MAX_LOG_FILE_SIZE",
        {.uint64_val = SIZE_M(10)},
        verify_param_uint64,
        notify_param_value,
        PARAM_INTEGER,
        "[1M,1000M]",
        EFFECT_IMMEDIATELY,
        UNIT_B},
    [DCC_PARAM_LOG_FILE_PERMISSION] = {"LOG_FILE_PERMISSION",
        {.uint32_val = DEFAULT_LOG_FILE_PERMISSION},
        verify_param_enum,
        NULL,
        PARAM_ENUM,
        "600,640",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_LOG_PATH_PERMISSION] = {"LOG_PATH_PERMISSION",
        {.uint32_val = DEFAULT_LOG_PATH_PERMISSION},
        verify_param_enum,
        NULL,
        PARAM_ENUM,
        "700,750",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_LOG_SUPPRESS_ENABLE] = {"LOG_SUPPRESS_ENABLE",
        {.uint32_val = 1},
        verify_param_enum,
        notify_param_value,
        PARAM_ENUM,
        "0,1",
        EFFECT_IMMEDIATELY,
        UNIT_NONE},
    [DCC_PARAM_OPTIMIZED_WORKER_THREADS] = {"OPTIMIZED_WORKER_THREADS",
        {.uint32_val = 80},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1,8000]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_MAX_WORKER_THREADS] = {"MAX_WORKER_THREADS",
        {.uint32_val = 100},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1,8000]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_REACTOR_THREADS] = {"REACTOR_THREADS",
        {.uint32_val = 10},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1,100]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_MAX_SESSIONS] = {"MAX_SESSIONS",
        {.uint32_val = 200},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[50,16320]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_LSNR_ADDR] = {"LSNR_ADDR",
        {.str_val = "127.0.0.1"},
        verify_param_ip,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_LSNR_PORT] = {"LSNR_PORT",
        {.uint32_val = 9000},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1,65535]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_MAX_ALLOWED_PACKET] = {"MAX_ALLOWED_PACKET",
        {.uint32_val = SIZE_K(96)},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[96KB,64MB]",
        EFFECT_REBOOT,
        UNIT_B},
    [DCC_PARAM_NODE_ID] = {"NODE_ID",
        {.uint32_val = 0},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "(0,32]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SRV_INST_POOL_INIT_SIZE] = {"SRV_INSTANCE_POOL_INIT_SIZE",
        {.uint64_val = SIZE_M(32)},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1M,128M]",
        EFFECT_REBOOT,
        UNIT_B },
    [DCC_PARAM_SRV_INST_POOL_MAX_SIZE] = {"SRV_INSTANCE_POOL_MAX_SIZE",
#ifdef DCC_LITE
        {.uint64_val = SIZE_M(32)},
#else
        {.uint64_val = SIZE_G(2)},
#endif
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1M, 2048M]",
        EFFECT_REBOOT,
        UNIT_B },
    [DCC_PARAM_SRV_AGENT_SHRINK_THRESHOLD] = {"SRV_AGENT_SHRINK_THRESHOLD",
        {.uint32_val = 10 },
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1, 1000]",
        EFFECT_REBOOT,
        UNIT_B },
    [DCC_PARAM_DB_TYPE] = {"DB_TYPE",
        {.uint32_val = 0 },
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        NULL, // 0 - max_unit64
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DATA_BUFFER_SIZE] = {"DATA_BUFFER_SIZE",
        {.uint64_val = SIZE_M(128)},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[64M,40960M]",
        EFFECT_REBOOT,
        UNIT_B },
    [DCC_PARAM_BUF_POOL_NUM] = {"BUF_POOL_NUM",
        {.uint32_val = 1 },
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1,128]",
        EFFECT_REBOOT,
        UNIT_NONE },

    [DCC_PARAM_LOG_BUFFER_SIZE] = {"LOG_BUFFER_SIZE",
        {.uint64_val = SIZE_M(16)},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1M,128M]",
        EFFECT_REBOOT,
        UNIT_B },

    [DCC_PARAM_LOG_BUFFER_COUNT] = {"LOG_BUFFER_COUNT",
        {.uint32_val = 4 },
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1,16]",
        EFFECT_REBOOT,
        UNIT_NONE },

    [DCC_PARAM_MAX_HANDLE] = {"MAX_HANDLE",
        {.uint32_val = 1024 },
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1,8000]",
        EFFECT_REBOOT,
        UNIT_NONE },

    [DCC_PARAM_SPACE_SIZE] = {"SPACE_SIZE",
        {.uint64_val = SIZE_M(128) },
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[128M,4096M]",
        EFFECT_REBOOT,
        UNIT_B },
    [DCC_PARAM_SSL_ENABLE] = {"DCC_SSL_ENABLE",
        {.enum_val = 1},
        verify_param_enum,
        NULL,
        PARAM_ENUM,
        "0,1",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SSL_CA] = {"DCC_SSL_CA",
        {.str_val = ""},
        verify_param_string,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SSL_KEY] = {"DCC_SSL_KEY",
        {.str_val = ""},
        verify_param_string,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SSL_CERT] = {"DCC_SSL_CERT",
        {.str_val = ""},
        verify_param_string,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SSL_VERIFY_PEER] = {"DCC_SSL_VERIFY_PEER",
        {.enum_val = 1},
        verify_param_enum,
        NULL,
        PARAM_ENUM,
        "0,1",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SSL_CRL] = {"DCC_SSL_CRL",
        {.str_val = ""},
        verify_param_string,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SSL_CIPHER] = {"DCC_SSL_CIPHER",
        {.str_val = ""},
        verify_param_string,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SSL_KEYPWD_FILE_PATH] = {"DCC_SSL_KEYPWD_FILE_PATH",
        {.str_val = ""},
        verify_param_string,
        NULL,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SSL_CERT_EXPIRE_ALERT_THRESHOLD] = {"DCC_SSL_CERT_EXPIRE_ALERT_THRESHOLD",
        {.uint32_val = 90},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[7,180]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_SESS_APPLY_INST_NUM] = {"SESS_APPLY_INST_NUM",
        {.uint32_val = 1},
        verify_param_uint64,
        NULL,
        PARAM_INTEGER,
        "[1,40]",
        EFFECT_REBOOT,
        UNIT_NONE},
    // begin of dcf parameters
    [DCC_PARAM_DCF_CONFIG] = {"ENDPOINT_LIST",
        {.long_str_val = NULL},
        verify_param_long_string,
        NULL,
        PARAM_LONG_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_ELECTION_TIMEOUT] = {"ELECTION_TIMEOUT",
        {.uint64_val = 3},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[1S,600S]",
        EFFECT_IMMEDIATELY,
        UNIT_S},
    [DCC_PARAM_DCF_RUN_MODE] = {"RUN_MODE",
        {.enum_val = 0},
        verify_param_enum,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "0,2",
        EFFECT_IMMEDIATELY,
        UNIT_NONE},
    [DCC_PARAM_DCF_MEC_AGENT_THREAD_NUM] = {"MEC_AGENT_THREAD_NUM",
        {.uint64_val = 10},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[1,1000]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_MEC_REACTOR_THREAD_NUM] = {"MEC_REACTOR_THREAD_NUM",
        {.uint64_val = 1},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[1,100]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_MEC_CHANNEL_NUM] = {"MEC_CHANNEL_NUM",
        {.uint64_val = 1},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[1,64]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_MEM_POOL_INIT_SIZE] = {"MEM_POOL_INIT_SIZE",
        {.uint64_val = 32},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[32MB,2147483647MB]",
        EFFECT_REBOOT,
        UNIT_MB},
    [DCC_PARAM_DCF_MEM_POOL_MAX_SIZE] = {"MEM_POOL_MAX_SIZE",
#ifdef DCC_LITE
        {.uint64_val = 32},
#else
        {.uint64_val = 2*SIZE_K(1)},
#endif
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[32MB,2147483647MB]",
        EFFECT_REBOOT,
        UNIT_MB},
    [DCC_PARAM_DCF_COMPRESS_ALGORITHM] = {"COMPRESS_ALGORITHM",
        {.enum_val = 0},
        verify_param_enum,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "0,1,2",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_COMPRESS_LEVEL] = {"COMPRESS_LEVEL",
        {.uint64_val = 1},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[1,22]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_SOCKET_TIMEOUT] = {"SOCKET_TIMEOUT",
        {.uint64_val = 5000},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[10MS,600000MS]",
        EFFECT_REBOOT,
        UNIT_MS},
    [DCC_PARAM_DCF_CONNECT_TIMEOUT] = {"CONNECT_TIMEOUT",
        {.uint64_val = 60000},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[10MS,600000MS]",
        EFFECT_REBOOT,
        UNIT_MS},
    [DCC_PARAM_DCF_REP_APPEND_THREAD_NUM] = {"REP_APPEND_THREAD_NUM",
        {.uint64_val = 2},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[1,1000]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_MEC_FRAGMENT_SIZE] = {"MEC_FRAGMENT_SIZE",
        {.uint64_val = 64},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[64KB,10240KB]",
        EFFECT_REBOOT,
        UNIT_KB},
    [DCC_PARAM_DCF_STG_POOL_INIT_SIZE] = {"STG_POOL_INIT_SIZE",
        {.uint64_val = 32},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[32MB,2147483647MB]",
        EFFECT_REBOOT,
        UNIT_MB},
    [DCC_PARAM_DCF_STG_POOL_MAX_SIZE] = {"STG_POOL_MAX_SIZE",
#ifdef DCC_LITE
        {.uint64_val = 32},
#else
        {.uint64_val = 2*SIZE_K(1)},
#endif
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[32MB,2147483647MB]",
        EFFECT_REBOOT,
        UNIT_MB},
    [DCC_PARAM_DCF_MEC_POOL_MAX_SIZE] = {"MEC_POOL_MAX_SIZE",
#ifdef DCC_LITE
        {.uint64_val = 32},
#else
        {.uint64_val = 200},
#endif
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[32MB,2147483647MB]",
        EFFECT_REBOOT,
        UNIT_MB},
    [DCC_PARAM_DCF_MEC_BATCH_SIZE] = {"MEC_BATCH_SIZE",
        {.uint64_val = 0},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[0,1024]",
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_FLOW_CONTROL_CPU_THRESHOLD] = {"FLOW_CONTROL_CPU_THRESHOLD",
        {.uint64_val = 100},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[0,2147483647]",
        EFFECT_IMMEDIATELY,
        UNIT_NONE},
    [DCC_PARAM_DCF_FLOW_CONTROL_NET_QUEUE_MESSAGE_NUM_THRESHOLD] = {"FLOW_CONTROL_NET_QUEUE_MESSAGE_NUM_THRESHOLD",
        {.uint64_val = 1024},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[0,2147483647]",
        EFFECT_IMMEDIATELY,
        UNIT_NONE},
    [DCC_PARAM_DCF_FLOW_CONTROL_DISK_RAWAIT_THRESHOLD] = {"FLOW_CONTROL_DISK_RAWAIT_THRESHOLD",
        {.uint64_val = 100000},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[0,2147483647]",
        EFFECT_IMMEDIATELY,
        UNIT_NONE},
    [DCC_PARAM_DCF_ELECTION_PRIORITY] = {"ELECTION_PRIORITY",
        {.uint64_val = 0},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[0,2147483647]",
        EFFECT_IMMEDIATELY,
        UNIT_NONE},
    [DCC_PARAM_DCF_SSL_CA] = {"SSL_CA",
        {.str_val = ""},
        verify_param_string,
        notify_set_dcf_param,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_SSL_KEY] = {"SSL_KEY",
        {.str_val = ""},
        verify_param_string,
        notify_set_dcf_param,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_SSL_CRL] = {"SSL_CRL",
        {.str_val = ""},
        verify_param_string,
        notify_set_dcf_param,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_SSL_CERT] = {"SSL_CERT",
        {.str_val = ""},
        verify_param_string,
        notify_set_dcf_param,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_SSL_CIPHER] = {"SSL_CIPHER",
        {.str_val = ""},
        verify_param_string,
        notify_set_dcf_param,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_SSL_PWD_PLAINTEXT] = {"SSL_PWD_PLAINTEXT",
        {.str_val = ""},
        verify_param_string,
        notify_set_dcf_param,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_SSL_PWD_CIPHERTEXT] = {"SSL_PWD_CIPHERTEXT",
        {.str_val = ""},
        verify_param_string,
        notify_set_dcf_param,
        PARAM_STRING,
        NULL,
        EFFECT_REBOOT,
        UNIT_NONE},
    [DCC_PARAM_DCF_SSL_CERT_NOTIFY_TIME] = {"SSL_CERT_NOTIFY_TIME",
        {.uint32_val = 90},
        verify_param_uint64,
        notify_set_dcf_param,
        PARAM_INTEGER,
        "[7,180]",
        EFFECT_REBOOT,
        UNIT_NONE},
    // end of dcf parameters
};

static status_t get_param(dcc_param_t param_id, param_value_t *param_value)
{
    if (param_id >= DCC_PARAM_CEIL) {
        return CM_ERROR;
    }
    *param_value = g_parameters[param_id].value;
    return CM_SUCCESS;
}

static status_t set_param(dcc_param_t param_id, const param_value_t *param_value)
{
    if (param_value == NULL) {
        return CM_ERROR;
    }
    g_parameters[param_id].value = *param_value;
    return CM_SUCCESS;
}

status_t get_param_name_by_id(uint32 param_id, char *param_name)
{
    if (param_id >= DCC_PARAM_CEIL || param_id == DCC_PARAM_UNKNOWN) {
        return CM_ERROR;
    }
    CM_RETURN_IFERR(strcpy_s(param_name, MAX_PARAM_NAME_LEN + 1, g_parameters[param_id].name));
    return CM_SUCCESS;
}

param_val_type_t get_param_val_type(uint32 param_id)
{
    if (param_id >= DCC_PARAM_CEIL || param_id == DCC_PARAM_UNKNOWN) {
        return PARAM_UNKNOW;
    }
    return g_parameters[param_id].val_type;
}
status_t get_param_id_by_name(const char *param_name, uint32 *param_id)
{
    uint32 count = ELEMENT_COUNT(g_parameters);
    for (uint32 i = 0; i < count; i++) {
        if (g_parameters[i].name == NULL) {
            continue;
        }
        if (cm_str_equal_ins(param_name, g_parameters[i].name)) {
            *param_id = i;
            return CM_SUCCESS;
        }
    }

    CM_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, param_name);
    return CM_ERROR;
}

bool32 is_param_can_reloaded(uint32 param_id)
{
    if (param_id >= DCC_PARAM_CEIL || param_id == DCC_PARAM_UNKNOWN) {
        return CM_FALSE;
    }
    return (g_parameters[param_id].notify != NULL
        && g_parameters[param_id].effect == EFFECT_IMMEDIATELY) ? CM_TRUE : CM_FALSE;
}

static status_t verify_param_value(
    const char *param_name, const char *param_value, dcc_param_t *param_id, param_value_t *out_value)
{
    status_t ret;
    uint32 param_name_id;
    ret = get_param_id_by_name(param_name, &param_name_id);
    if (ret == CM_ERROR || g_parameters[param_name_id].verify == NULL) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, param_name);
        return CM_ERROR;
    }
    // is unit not null, parse unit
    *param_id = (dcc_param_t) param_name_id;
    ret = g_parameters[param_name_id].verify((dcc_param_t) param_name_id, param_value, out_value);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_VALUE, param_name, param_value);
    }
    return ret;
}

status_t srv_get_param(dcc_param_t param_id, param_value_t *param_value)
{
    cm_latch_s(&latch, 0, CM_FALSE, NULL);
    status_t ret = get_param(param_id, param_value);
    cm_unlatch(&latch, NULL);
    return ret;
}

status_t srv_set_param(const char* param_name, const char* param_value)
{
    if (CM_IS_EMPTY_STR(param_name)) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, param_name);
        return CM_ERROR;
    }

    if (CM_IS_EMPTY_STR(param_value)) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_VALUE, param_name, param_value);
        return CM_ERROR;
    }
    cm_latch_x(&latch, 0, NULL);
    dcc_param_t param_id;
    param_value_t out_value = { 0 };

    status_t ret = verify_param_value(param_name, param_value, &param_id, &out_value);
    if (ret != CM_SUCCESS) {
        cm_unlatch(&latch, NULL);
        return CM_ERROR;
    }
    ret = set_param(param_id, &out_value);
    if (ret == CM_SUCCESS && g_parameters[param_id].notify != NULL) {
        ret = g_parameters[param_id].notify(param_id, param_value, out_value);
    }
    cm_unlatch(&latch, NULL);
    return ret;
}

// begin of verify function
status_t verify_param_string(dcc_param_t param_id, const char *param_value, param_value_t *out_value)
{
    // remove quotes of begin and end
    text_t text;
    if (param_id == DCC_PARAM_DCF_SSL_PWD_PLAINTEXT) {
        cm_str2text("***", &text);
    } else {
        cm_str2text((char *) param_value, &text);
    }
    if ((CM_TEXT_BEGIN(&text) == '\'' && CM_TEXT_END(&text) == '\'') ||
        (CM_TEXT_BEGIN(&text) == '\"' && CM_TEXT_END(&text) == '\"')) {
        CM_REMOVE_ENCLOSED_CHAR(&text);
    }
    // valid string
    status_t ret = cm_text2str(&text, out_value->str_val, MAX_PARAM_VALUE_LEN + 1);

    return ret;
}

status_t verify_param_long_string(dcc_param_t param_id, const char *param_value, param_value_t *out_value)
{
    text_t text;
    cm_str2text((char *) param_value, &text);
    if ((CM_TEXT_BEGIN(&text) == '\'' && CM_TEXT_END(&text) == '\'') ||
        (CM_TEXT_BEGIN(&text) == '\"' && CM_TEXT_END(&text) == '\"')) {
        CM_REMOVE_ENCLOSED_CHAR(&text);
    }

    if (param_id == (dcc_param_t)DCC_PARAM_DCF_CONFIG) {
        out_value->long_str_val = g_param_endpoint_list;
    } else {
        return CM_ERROR;
    }

    status_t ret = cm_text2str(&text, out_value->long_str_val, MAX_PARAM_ENDPOINT_LIST_SIZE);

    return ret;
}

status_t verify_param_ip(dcc_param_t param_id, const char *param_value, param_value_t *out_value)
{
    CM_RETURN_IFERR(verify_param_string(param_id, param_value, out_value));
    CM_RETURN_IF_FALSE(cm_check_ip_valid(out_value->str_val));
    return CM_SUCCESS;
}

static inline en_unit_type_t get_unit_type(param_unit_t unit)
{
    if ((unit) >= UNIT_UNKNOW) {
        return UNIT_T_UNKNOW;
    } else if ((unit) <= UNIT_T) {
        return UNIT_T_MEM;
    } else {
        return UNIT_T_TIME;
    }
}

static status_t get_num_and_unit(char *param_value, char *num_part, uint32 num_len, text_t *unit_part)
{
    text_t text_param;
    cm_str2text(param_value, &text_param);
    cm_trim_text(&text_param);
    uint32 i = 0;
    for (; i < text_param.len; i++) {
        if (!CM_IS_DIGIT(text_param.str[i])) {
            break;
        }
    }
    unit_part->str = &text_param.str[i];
    unit_part->len = text_param.len - i;
    text_param.len = i;
    CM_RETURN_IFERR(cm_text2str(&text_param, num_part, num_len + 1));
    return CM_SUCCESS;
}

static status_t parse_param_with_units(const char *param_value, param_unit_t default_unit, uint64 *out_value)
{
    text_t text_unit;
    uint64 size;
    char param_val[MAX_PARAM_VALUE_LEN + 1] = {0};
    char num_part[CM_MAX_NUMBER_LEN + 1] = {0};
    MEMS_RETURN_IFERR(strcpy_s(param_val, MAX_PARAM_VALUE_LEN, param_value));
    CM_RETURN_IFERR(get_num_and_unit(param_val, num_part, CM_MAX_NUMBER_LEN, &text_unit));
    cm_trim_text(&text_unit);
    CM_RETURN_IFERR(cm_str2uint64(num_part, &size));
    if (CM_IS_EMPTY(&text_unit)) {
        // this param with no unit, just return success
        *out_value = size;
        return CM_SUCCESS;
    }
    for (uint32 i = 0; i < ELEMENT_COUNT(g_units); i++) {
        if (get_unit_type(default_unit) != g_units[i].unit_type) {
            continue;
        }
        if (cm_text_equal_ins(&text_unit, &g_units[i].unit_name)) {
            size *= g_units[i].unit_dimemsion;
            *out_value = size / g_units[(uint32) default_unit].unit_dimemsion;
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}


static status_t parse_integer_range(const char *range, param_unit_t default_unit, uint64 *min_val, uint64 *max_val)
{
    CM_CHECK_NULL_PTR(min_val);
    CM_CHECK_NULL_PTR(max_val);
    char *token = NULL;
    char *next_token = NULL;
    if (range == NULL) {
        *min_val = 0;
        *max_val = CM_MAX_UINT64;
        return CM_SUCCESS;
    }
    char buf[MAX_PARAM_RANGE_LEN + 1] = {0};
    MEMS_RETURN_IFERR(strcpy_sp(buf, MAX_PARAM_RANGE_LEN + 1, range));
    text_t text = {
        .str = buf,
        .len = (uint32)(strlen(buf))
    };
    cm_trim_text(&text);

    int32 left_close_itl = CM_TEXT_BEGIN(&text) == '[' ? 1 : (CM_TEXT_BEGIN(&text) == '(' ? 0 : -1);
    int32 right_close_itl = CM_TEXT_END(&text) == ']' ? 1 : (CM_TEXT_END(&text) == ')' ? 0 : -1);
    if (left_close_itl == -1 || right_close_itl == -1) {
        return CM_ERROR;
    }
    text.str++;
    text.len -= PARAM_FIX_NUM_2;

    token = strtok_s(text.str, ",", &next_token);
    if (token == NULL) {
        return CM_ERROR;
    }
    CM_RETURN_IFERR(parse_param_with_units(token, default_unit, min_val));
    if (!left_close_itl && *min_val != CM_MAX_UINT64) {
        (*min_val)++;
    }
    text.str = next_token;
    text.len -= (uint32)(strlen(token) + 1);
    uint32 next_token_len = strlen(next_token);
    cm_assert((bool32)(next_token_len == (text.len + 1)));
    next_token[text.len] = '\0';
    CM_RETURN_IFERR(parse_param_with_units(text.str, default_unit, max_val));
    if (!right_close_itl && *max_val != 0) {
        (*max_val)--;
    }
    return CM_SUCCESS;
}
status_t verify_param_uint64(dcc_param_t param_id, const char *param_value, param_value_t *out_value)
{
    uint64 min_val, max_val, value;
    if (g_parameters[param_id].unit != UNIT_NONE) {
        CM_RETURN_IFERR(parse_param_with_units(param_value, g_parameters[param_id].unit, &value));
    } else {
        CM_RETURN_IFERR(cm_str2uint64(param_value, &value));
    }
    CM_RETURN_IFERR(parse_integer_range(g_parameters[param_id].range, g_parameters[param_id].unit, &min_val, &max_val));
    if (value >= min_val && value <= max_val) {
        out_value->uint64_val = value;
        return CM_SUCCESS;
    }
    CM_THROW_ERROR(ERR_INVALID_PARAMETER_VALUE, g_parameters[param_id].name, param_value);
    return CM_ERROR;
}

status_t parse_log_level_cfg(const char *log_cfg, uint32 *log_level)
{
    *log_level = LOG_NONE;
    text_t text, left, right, tmp;
    text_t text_none = {
        .str = "NONE",
        .len = 4
    };
    cm_str2text((char *) log_cfg, &text);
    if (text.len == 0) {
        return CM_ERROR;
    }
    if (cm_text_equal_ins(&text, &text_none)) {
        return CM_SUCCESS;
    }
    if ((CM_TEXT_BEGIN(&text) == '\'' && CM_TEXT_END(&text) == '\'') ||
        (CM_TEXT_BEGIN(&text) == '\"' && CM_TEXT_END(&text) == '\"')) {
        CM_REMOVE_ENCLOSED_CHAR(&text);
    }
    while (text.len != 0) {
        cm_split_text(&text, '|', 0, &left, &right);
        if (left.len == 0) {
            return CM_ERROR;
        }
        bool32 found = CM_FALSE;
        for (int i = 0; i < MAX_LOG_LEVEL_SIZE; i++) {
            cm_str2text(g_log_level_str[i], &tmp);
            if (cm_text_equal_ins(&left, &tmp)) {
                *log_level |= g_log_level_val[i];
                found = CM_TRUE;
                break;
            }
        }
        if (!found) {
            return CM_ERROR;
        }
        text = right;
    }
    return CM_SUCCESS;
}

status_t verify_param_log_level(dcc_param_t param_id, const char *param_value, param_value_t *out_value)
{
    uint32 log_level = 0;
    // only handle NULL or "" error, set to default log level
    if (CM_IS_EMPTY_STR(param_value)) {
        out_value->uint32_val = DEFAULT_LOG_LEVEL;
        return CM_SUCCESS;
    }
    CM_RETURN_IFERR(verify_param_string(param_id, param_value, out_value));
    int ret = parse_log_level_cfg(param_value, &log_level);
    if (ret != CM_SUCCESS || log_level > MAX_LOG_LEVEL) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t valid_param_enum(const char *range, const char *enum_value, uint32 *enum_pos)
{
    if (range == NULL || enum_value == NULL) {
        return CM_ERROR;
    }
    if (cm_strstri(range, " ") != NULL) {
        return CM_ERROR;
    }
    char buf[MAX_PARAM_RANGE_LEN + 1] = {0};
    MEMS_RETURN_IFERR(strcpy_sp(buf, MAX_PARAM_RANGE_LEN + 1, range));
    char *token = NULL;
    char *next_token = NULL;
    uint32 i = 0;
    token = strtok_s(buf, ",", &next_token);
    while (token) {
        if (cm_str_equal_ins(token, enum_value)) {
            if (enum_pos != NULL) {
                *enum_pos = i;
            }
            return CM_SUCCESS;
        }
        i++;
        token = strtok_s(NULL, ",", &next_token);
    }

    return CM_ERROR;
}

status_t verify_param_enum(dcc_param_t param_id, const char *param_value, param_value_t *out_value)
{
    uint32 enum_value;
    CM_RETURN_IFERR(valid_param_enum(g_parameters[param_id].range, param_value, &enum_value));

    switch (param_id) {
        case DCC_PARAM_LOG_FILE_PERMISSION:
            out_value->enum_val = log_file_perm_values[enum_value];
            break;
        case DCC_PARAM_LOG_PATH_PERMISSION:
            out_value->enum_val = log_path_perm_values[enum_value];
            break;
        case DCC_PARAM_DCF_RUN_MODE:
            out_value->enum_val = dcf_run_mode_values[enum_value];
            break;
        default:
            out_value->enum_val = enum_value;
            return CM_SUCCESS;
    }

    return CM_SUCCESS;
}
// end of verify function

// begin of notify function
static inline status_t dcf_set_param_wrap(const char *param, const char *value)
{
    int ret = dcf_set_param(param, value);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[PARAM] set dcf param %s to value %s failed", param, value);
    }
    if (cm_str_equal(param, "SSL_PWD_PLAINTEXT")) {
        LOG_RUN_INF("[PARAM] set dcf param %s value %s success", param, "***");
    } else {
        LOG_RUN_INF("[PARAM] set dcf param %s value %s success", param, value);
    }
    return (ret == CM_SUCCESS) ? CM_SUCCESS : CM_ERROR;
}

status_t notify_param_value(dcc_param_t param_id, const char *param_value, param_value_t out_value)
{
    char buf[MAX_PARAM_VALUE_LEN + 1] = {0};
    uint32 log_level = 0;
    status_t ret = CM_SUCCESS;
    switch (param_id) {
        case DCC_PARAM_LOG_LEVEL:
            (void)parse_log_level_cfg(out_value.str_val, &log_level);
            cm_log_param_instance()->log_level = log_level;
            ret = dcf_set_param_wrap("LOG_LEVEL", out_value.str_val);
            break;
        case DCC_PARAM_LOG_BACKUP_FILE_COUNT:
            cm_log_param_instance()->log_backup_file_count = out_value.uint32_val;
            PRTS_RETURN_IFERR(snprintf_s(buf, MAX_PARAM_VALUE_LEN + 1, MAX_PARAM_VALUE_LEN,
                "%u", out_value.uint32_val));
            ret = dcf_set_param_wrap("LOG_BACKUP_FILE_COUNT", buf);
            break;
        case DCC_PARAM_MAX_LOG_FILE_SIZE:
            cm_log_param_instance()->max_log_file_size = out_value.uint64_val;
            PRTS_RETURN_IFERR(snprintf_s(buf, MAX_PARAM_VALUE_LEN + 1, MAX_PARAM_VALUE_LEN,
                "%llu", out_value.uint64_val / SIZE_M(1)));
            ret = dcf_set_param_wrap("MAX_LOG_FILE_SIZE", buf);
            break;
        case DCC_PARAM_LOG_SUPPRESS_ENABLE:
            cm_log_param_instance()->log_suppress_enable = out_value.enum_val == 1 ? CM_TRUE : CM_FALSE;
            LOG_RUN_INF("[PARAM] set dcc param %s value %u success", "LOG_SUPPRESS_ENABLE", out_value.enum_val);
            break;
        default:
            return CM_SUCCESS;
    }
    return ret;
}

status_t notify_set_dcf_param(dcc_param_t param_id, const char *param_value, param_value_t out_value)
{
    if (g_parameters[param_id].val_type == PARAM_STRING) {
        return dcf_set_param_wrap(g_parameters[param_id].name, param_value);
    }

    char dcf_param_value[MAX_PARAM_VALUE_LEN + 1] = {0};
    PRTS_RETURN_IFERR(snprintf_s(dcf_param_value, MAX_PARAM_VALUE_LEN + 1,
        MAX_PARAM_VALUE_LEN, "%llu", out_value.uint64_val));
    return dcf_set_param_wrap(g_parameters[param_id].name, dcf_param_value);
}

// end of notify function

#ifdef __cplusplus
}
#endif
