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
 * util_stat.c
 *    util statistics
 *
 * IDENTIFICATION
 *    src/utils/util_stat.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_log.h"
#include "util_stat.h"
#ifndef WIN32
#include <sys/statfs.h>
#endif

#define CM_MB_2_B_SHIFT_BITS 20

#ifndef WIN32
status_t cm_get_disk_size(const char *path, disk_size_type_e disk_type, uint64 *size)
{
    uint64 f_mbsize = 0;
    struct statfs disk_inf;
    if (statfs(path, &disk_inf) == CM_ERROR) {
        LOG_DEBUG_ERR("cm_get_disk_f_mbsize statfs failed.");
        return CM_ERROR;
    }
    switch (disk_type) {
        case TOTAL_SIZE:
            f_mbsize = (disk_inf.f_bsize * disk_inf.f_blocks) >> CM_MB_2_B_SHIFT_BITS;
            break;
        case AVAIL_SIZE:
            f_mbsize = (disk_inf.f_bsize * disk_inf.f_bavail) >> CM_MB_2_B_SHIFT_BITS;
            break;
        default:
            break;
    }
    *size = f_mbsize;
    return CM_SUCCESS;
}
#else
status_t cm_get_disk_size(const char *path, disk_size_type_e disk_type, uint64 *size)
{
    uint64 f_mbsize = 0;
    uint64 avail, total, free;
    if (!GetDiskFreeSpaceEx(path, (ULARGE_INTEGER*)&avail, (ULARGE_INTEGER*)&total, (ULARGE_INTEGER*)&free)) {
        LOG_DEBUG_ERR("cm_get_disk_f_mbsize GetDiskFreeSpaceEx failed.");
        return CM_ERROR;
    }
    switch (disk_type) {
        case TOTAL_SIZE:
            f_mbsize = total >> CM_MB_2_B_SHIFT_BITS;
            break;
        case AVAIL_SIZE:
            f_mbsize = avail >> CM_MB_2_B_SHIFT_BITS;
            break;
        default:
            break;
    }
    *size = f_mbsize;
    return CM_SUCCESS;
}
#endif
