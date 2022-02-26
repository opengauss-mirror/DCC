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
 * util_error.c
 *
 *
 * IDENTIFICATION
 *    src/utils/util_error.c
 *
 * -------------------------------------------------------------------------
 */


#include "util_error.h"

#ifdef __cplusplus
extern "C" {
#endif
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
const char *g_dcc_error_desc[DCC_ERROR_COUNT] = {

    /* server errors, PUBLIC TO USER */
    /* errcode when only using dcc srv api interface */
    [ERR_SERVER_START_FAILED]         = "Server startup failed, %s",
    [ERR_SERVER_STOPPED]              = "Server status is not running %s",
    [ERR_API_COMMIT_TIMEOUT]          = "Server command operation committed timeout %s",
    [ERR_MALLOC_MEM]                  = "Server malloc handle failed when %s",
    [ERR_INVALID_PARAMETER_VALUE]     = "Server parameter verify failed, name %s, value %s",
    [ERR_INVALID_PARAMETER_NAME]      = "Server parameter name %s was invalid",
    [ERR_KEY_NOT_FOUND]               = "Key not found",
    [ERR_SERVER_IS_BLOCKED]           = "Server is blocked",
    [ERR_DCF_INTERNAL]                = "Server internal error in DCF",
    [ERR_STORAGE_INTERNAL]            = "Server internal error in storage",
    [ERR_INVALID_CMD_CONTENT]         = "Server command content is error",
    [ERR_INVALID_CMD_TYPE]            = "Server command type is invalid",
    /* errcode when using dcc_server */
    [ERR_LINE_SIZE_TOO_LONG]          = "The length of row %d in dcc_server.ini is too long",
    [ERR_FILE_NOT_EXIST]              = "config %s file %s does not exist",
    [ERR_FILE_SIZE_TOO_LARGE]         = "The size of config file %s is too large",
    [ERR_DUPLICATE_PARAMETER]         = "The parameter name in config file %s is duplicated",
    [ERR_PARAM_COMMENT_TOO_LONG]      = "The parameter comment in config file is too long, len %d, content %s",
    [ERR_WAIT_DB_COMMIT_TIMEOUT]      = "Timeout when waiting for db commit",
    [ERR_DECODE_REQUEST]              = "The request packet is error",
    /* storage errors */
    [ERR_STG_INIT_FAILED]             = "Failed to init storage",

    /* tools errors */

    /* executor errors */
    [ERR_EXC_INIT_FAILED]             = "Failed to init executor when %s",
    [ERR_EXC_PUT_FAILED]              = "Failed to write message when it executes put operation",
    [ERR_EXC_DEL_FAILED]              = "Failed to write message when it executes delete operation",
    [ERR_EXC_GET_LAST_COMMIT_INDEX]   = "Failed to get last commit index when %s",
    [ERR_EXC_WAIT_COMMIT_INDEX]       = "Wait local commit index timeout",
    [ERR_EXC_GET_HEALTHY_INFO]        = "Failed to get node healthy information",
    [ERR_EXC_SAVE_APPLY_INDEX_FAILED] = "Failed to save apply index: %llu",
    [ERR_EXC_TRUNCATE_FAILED]         = "Failed to truncate for index: %llu",
    [ERR_EXC_INIT_GROUP_NODE_FAILED]  = "Failed to init watch group node information.",
    /* network errors */

    /* utils errors */
};

static void init_server_errno(void)
{
    for (int i = DCC_ERRNO_SRV_API_BEGIN; i < DCC_ERRNO_SRV_API_END; i++) {
        cm_register_error((uint16)i, g_dcc_error_desc[i]);
    }
    for (int i = DCC_ERRNO_SRV_BEGIN; i < DCC_ERRNO_SRV_END; i++) {
        cm_register_error((uint16)i, g_dcc_error_desc[i]);
    }
    for (int i = DCC_ERRNO_EXECUTOR_BEGIN; i < DCC_ERRNO_EXECUTOR_END; i++) {
        cm_register_error((uint16)i, g_dcc_error_desc[i]);
    }
    for (int i = DCC_ERRNO_STG_BEGIN; i < DCC_ERRNO_STG_END; i++) {
        cm_register_error((uint16)i, g_dcc_error_desc[i]);
    }
}
static void init_tools_errno(void)
{
    for (int i = DCC_ERRNO_TOOLS_BEGIN; i < DCC_ERRNO_TOOLS_END; i++) {
        cm_register_error((uint16)i, g_dcc_error_desc[i]);
    }
    for (int i = DCC_ERRNO_UTILS_BEGIN; i < DCC_ERRNO_UTILS_END; i++) {
        cm_register_error((uint16)i, g_dcc_error_desc[i]);
    }
    for (int i = DCC_ERRNO_NETWORK_BEGIN; i < DCC_ERRNO_NETWORK_END; i++) {
        cm_register_error((uint16)i, g_dcc_error_desc[i]);
    }
}

void init_dcc_errno_desc(void)
{
    init_server_errno();
    init_tools_errno();
}

void util_convert_exc_errno(void)
{
    int32 err_code = cm_get_error_code();
    LOG_DEBUG_ERR("[API] executor error found, err_no:%d, err_msg:%s", err_code, cm_get_errormsg(err_code));
    cm_reset_error();
    if (err_code >= (int32)DCC_ERRNO_EXECUTOR_BEGIN && err_code < (int32)DCC_ERRNO_EXECUTOR_END) {
        CM_THROW_ERROR(ERR_DCF_INTERNAL, "");
    } else {
        CM_THROW_ERROR(ERR_STORAGE_INTERNAL, "");
    }
}

#ifdef __cplusplus
}
#endif
