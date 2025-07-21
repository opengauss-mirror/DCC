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
 * srv_logger.c
 *
 *
 * IDENTIFICATION
 *    src/server/srv_logger.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_log.h"
#include "srv_param.h"
#include "dcf_interface.h"
#ifdef __cplusplus
extern "C" {
#endif


static status_t init_logger_param(log_param_t *log_param)
{
    param_value_t param_value;
    char buf[MAX_PARAM_VALUE_LEN + 1] = {0};
    uint32 log_level = 0;
    char real_path[CM_FILE_NAME_BUFFER_SIZE] = {0};
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_PATH, &param_value));
    if (strlen(param_value.str_val) == 0) {
        CM_RETURN_IFERR(srv_get_param(DCC_PARAM_DATA_PATH, &param_value));
        CM_RETURN_IFERR(realpath_file(param_value.str_val, real_path, CM_FILE_NAME_BUFFER_SIZE));
        PRTS_RETURN_IFERR(snprintf_s(log_param->log_home, CM_MAX_LOG_HOME_LEN, CM_MAX_LOG_HOME_LEN - 1, "%s/%s",
            real_path, "dcc_log"));
    } else {
        CM_RETURN_IFERR(realpath_file(param_value.str_val, real_path, CM_FILE_NAME_BUFFER_SIZE));
        PRTS_RETURN_IFERR(snprintf_s(log_param->log_home, CM_MAX_LOG_HOME_LEN, CM_MAX_LOG_HOME_LEN - 1,
            "%s", real_path));
    }

    PRTS_RETURN_IFERR(
        snprintf_s(log_param->instance_name, CM_MAX_NAME_LEN, CM_MAX_NAME_LEN - 1, "%s", DCC_LOG_MODULE_NAME));
    CM_RETURN_IFERR(cm_set_log_module_name(DCC_LOG_MODULE_NAME, DCC_LOG_MODULE_NAME_LEN));
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_LEVEL, &param_value));
    CM_RETURN_IFERR(parse_log_level_cfg(param_value.str_val, &log_level));
    log_param->log_level = log_level;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_BACKUP_FILE_COUNT, &param_value));
    log_param->log_backup_file_count = param_value.uint32_val;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_MAX_LOG_FILE_SIZE, &param_value));
    log_param->max_log_file_size = param_value.uint64_val;

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_FILE_PERMISSION, &param_value));
    cm_log_set_file_permissions((uint16)param_value.enum_val);
    PRTS_RETURN_IFERR(
        snprintf_s(buf, MAX_PARAM_VALUE_LEN + 1, MAX_PARAM_VALUE_LEN, "%u", (uint16)param_value.enum_val));
    int ret = dcf_set_param("LOG_FILE_PERMISSION", buf);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("dcf set param LOG_FILE_PERMISSION %s error", buf);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_PATH_PERMISSION, &param_value));
    cm_log_set_path_permissions((uint16)param_value.enum_val);
    buf[0] = '\0';
    PRTS_RETURN_IFERR(
        snprintf_s(buf, MAX_PARAM_VALUE_LEN + 1, MAX_PARAM_VALUE_LEN, "%u", (uint16)param_value.enum_val));
    ret = dcf_set_param("LOG_PATH_PERMISSION", buf);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("dcf set param LOG_PATH_PERMISSION %s error", buf);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t init_logger(void)
{
    char file_name[CM_FULL_PATH_BUFFER_SIZE] = { '\0' };
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_instance_startup = CM_FALSE;
    CM_RETURN_IFERR(init_logger_param(log_param));
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/run/%s",
        log_param->log_home, "run.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_RUN, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/debug/%s",
        log_param->log_home, "debug.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_DEBUG, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/oper/%s",
        log_param->log_home, "oper.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_OPER, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/alarm/%s",
        log_param->log_home, "alarm.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_ALARM, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/mec/%s",
        log_param->log_home, "mec.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_MEC, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/trace/%s",
        log_param->log_home, "trace.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_TRACE, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/profile/%s",
        log_param->log_home, "profile.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_PROFILE, file_name));

    log_param->log_instance_startup = CM_TRUE;
    log_param->log_suppress_enable = CM_FALSE;
    return CM_SUCCESS;
}

void uninit_logger(void)
{
    cm_log_param_instance()->log_suppress_enable = CM_FALSE;
    cm_log_uninit();
}

#ifdef __cplusplus
}
#endif