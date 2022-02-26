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
 * util_stat.h
 *    util statistics
 *
 * IDENTIFICATION
 *    src/utils/util_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __UTIL_STAT_H__
#define __UTIL_STAT_H__

#include "cm_defs.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TOTAL_SIZE,
    AVAIL_SIZE
} disk_size_type_e;

status_t cm_get_disk_size(const char *path, disk_size_type_e disk_type, uint64 *size);

#ifdef __cplusplus
}
#endif

#endif
