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
 * cm_system.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_system.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_SYSTEM_H__
#define __CM_SYSTEM_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
status_t cm_get_host_ip(char *ipstr, uint32 len);
uint64 cm_sys_pid();
char *cm_sys_program_name();
char *cm_sys_user_name();
char *cm_sys_host_name();
char *cm_sys_platform_name();
int64 cm_sys_ticks();
int64 cm_sys_process_start_time(uint64 pid);
bool32 cm_sys_process_alived(uint64 pid, int64 start_ticks);
void cm_try_init_system(void);
uint32 cm_sys_get_nprocs();
#ifndef WIN32
status_t cm_get_file_host_name(char *path, char *host_name);
#endif

#ifdef __cplusplus
}
#endif

#endif
