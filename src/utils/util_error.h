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
 * util_error.h
 *
 *
 * IDENTIFICATION
 *    src/utils/util_error.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef UTIL_ERROR
#define UTIL_ERROR
#include "cm_error.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DCC_BASE_ERROR_COUNT 1000
#define DCC_ERROR_COUNT 2000
/*
 * @Note
 *   Attention1: add error code to the corresponding range
 *
 *   ERROR                                  |   RANGE
 *   server errors(API)                     |   1000 - 1099
 *   server errors                          |   1100 - 1199
 *   storage errors                         |   1200 - 1299
 *   tools errors                           |   1300 - 1399
 *   executor errors                        |   1400 - 1499
 *   network errors                         |   1500 - 1599
 *   utils errors                           |   1600 - 1699
 */
typedef enum en_DCC_errno {
    ERR_DCC_BASE = DCC_BASE_ERROR_COUNT,
    /* server errors , PUBLIC TO USER */
    /* errcode when only using dcc srv api interface */
    DCC_ERRNO_SRV_API_BEGIN           = 1000,
    ERR_SERVER_START_FAILED       = DCC_ERRNO_SRV_API_BEGIN,
    ERR_SERVER_STOPPED            = 1001,
    ERR_API_COMMIT_TIMEOUT        = 1002,
    ERR_MALLOC_MEM                = 1003,
    ERR_INVALID_PARAMETER_VALUE   = 1004,
    ERR_INVALID_PARAMETER_NAME    = 1005,
    ERR_KEY_NOT_FOUND             = 1006,
    ERR_SERVER_IS_BLOCKED         = 1007,
    ERR_DCF_INTERNAL              = 1008,
    ERR_STORAGE_INTERNAL          = 1009,
    ERR_INVALID_CMD_CONTENT       = 1010,
    ERR_INVALID_CMD_TYPE          = 1011,
    DCC_ERRNO_SRV_API_END         = ERR_INVALID_CMD_TYPE + 1,
    /* errcode when using dcc_server */
    DCC_ERRNO_SRV_BEGIN           = 1100,
    ERR_LINE_SIZE_TOO_LONG        = DCC_ERRNO_SRV_BEGIN,
    ERR_FILE_NOT_EXIST            = 1101,
    ERR_FILE_SIZE_TOO_LARGE       = 1102,
    ERR_DUPLICATE_PARAMETER       = 1103,
    ERR_PARAM_COMMENT_TOO_LONG    = 1104,
    ERR_WAIT_DB_COMMIT_TIMEOUT    = 1105,
    ERR_DECODE_REQUEST            = 1106,
    // need update DCC_ERRNO_SRV_END after add new ERRNO
    DCC_ERRNO_SRV_END             = ERR_DECODE_REQUEST + 1,

    /* storage errors */
    DCC_ERRNO_STG_BEGIN         = 1200,
    ERR_STG_INIT_FAILED         = 1200,
    // need update DCC_ERRNO_STG_END after add new ERRNO
    DCC_ERRNO_STG_END           = ERR_STG_INIT_FAILED + 1,

    /* tools errors */
    DCC_ERRNO_TOOLS_BEGIN        = 1300,
    DCC_ERRNO_TOOLS_END          = DCC_ERRNO_TOOLS_BEGIN + 1,

    /* executor errors */
    DCC_ERRNO_EXECUTOR_BEGIN           = 1400,
    ERR_EXC_INIT_FAILED                = DCC_ERRNO_EXECUTOR_BEGIN,
    ERR_EXC_PUT_FAILED                 = 1401,
    ERR_EXC_DEL_FAILED                 = 1402,
    ERR_EXC_GET_LAST_COMMIT_INDEX      = 1403,
    ERR_EXC_WAIT_COMMIT_INDEX          = 1404,
    ERR_EXC_GET_HEALTHY_INFO           = 1405,
    ERR_EXC_SAVE_APPLY_INDEX_FAILED    = 1406,
    ERR_EXC_TRUNCATE_FAILED            = 1407,
    ERR_EXC_INIT_GROUP_NODE_FAILED     = 1408,
    DCC_ERRNO_EXECUTOR_END             = ERR_EXC_INIT_GROUP_NODE_FAILED + 1,

    /* network errors */
    DCC_ERRNO_NETWORK_BEGIN        = 1500,
    DCC_ERRNO_NETWORK_END          = DCC_ERRNO_NETWORK_BEGIN + 1,

    /* utils errors */
    DCC_ERRNO_UTILS_BEGIN        = 1600,
    DCC_ERRNO_UTILS_END          = DCC_ERRNO_UTILS_BEGIN + 1,
    ERR_DCC_CEIL = DCC_ERROR_COUNT,
}DCC_errno_t;

void init_dcc_errno_desc(void);
void util_convert_exc_errno(void);

#ifdef __cplusplus
}
#endif

#endif
