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
 * dcc_ctl_execute.h
 *    Client tool
 *
 * IDENTIFICATION
 *    src/tools/dcc_ctl/dcc_ctl_execute.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DCC_CTL_EXECUTE_H__
#define __DCC_CTL_EXECUTE_H__

#include "cm_error.h"
#include "cm_text.h"
#include "dcc_cmd_parse.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t ctl_execute_process(ctl_command_t *ctl_command);

#ifdef __cplusplus
}
#endif

#endif