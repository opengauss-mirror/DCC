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
 * gstor_adpt.c
 *    gstor adapter
 *
 * IDENTIFICATION
 *    src/storage/gstor_adpt.c
 *
 * -------------------------------------------------------------------------
 */

#include "gstor_adpt.h"
#include "srv_param.h"

status_t load_gstor_params(char *path)
{
    param_value_t param_val;
    char buf[CM_FULL_PATH_BUFFER_SIZE];

    // DATA_BUFFER_SIZE
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_DATA_BUFFER_SIZE, &param_val));
    PRTS_RETURN_IFERR(sprintf_s(buf, CM_FULL_PATH_BUFFER_SIZE, "%llu", param_val.uint64_val));
    CM_RETURN_IFERR(gstor_set_param("DATA_BUFFER_SIZE", buf, path));

    // BUF_POOL_NUM
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_BUF_POOL_NUM, &param_val));
    PRTS_RETURN_IFERR(sprintf_s(buf, CM_FULL_PATH_BUFFER_SIZE, "%u", param_val.uint32_val));
    CM_RETURN_IFERR(gstor_set_param("BUF_POOL_NUM", buf, path));

    // LOG_BUFFER_SIZE
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_BUFFER_SIZE, &param_val));
    PRTS_RETURN_IFERR(sprintf_s(buf, CM_FULL_PATH_BUFFER_SIZE, "%llu", param_val.uint64_val));
    CM_RETURN_IFERR(gstor_set_param("LOG_BUFFER_SIZE", buf, path));

    // LOG_BUFFER_COUNT
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_BUFFER_COUNT, &param_val));
    PRTS_RETURN_IFERR(sprintf_s(buf, CM_FULL_PATH_BUFFER_SIZE, "%u", param_val.uint32_val));
    CM_RETURN_IFERR(gstor_set_param("LOG_BUFFER_COUNT", buf, path));

    // SPACE_SIZE
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SPACE_SIZE, &param_val));
    PRTS_RETURN_IFERR(sprintf_s(buf, CM_FULL_PATH_BUFFER_SIZE, "%llu", param_val.uint64_val));
    CM_RETURN_IFERR(gstor_set_param("SPACE_SIZE", buf, path));

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LOG_LEVEL, &param_val));
    uint32 log_level;
    CM_RETURN_IFERR(parse_log_level_cfg(param_val.str_val, &log_level));
    PRTS_RETURN_IFERR(sprintf_s(buf, CM_FULL_PATH_BUFFER_SIZE, "%u", (log_level & 0x0000007F)));
    CM_RETURN_IFERR(gstor_set_param("LOG_LEVEL", buf, path));

    return CM_SUCCESS;
}