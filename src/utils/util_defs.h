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
 * util_defs.h
 *
 *
 * IDENTIFICATION
 *    src/utils/util_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef UTIL_DEFS
#define UTIL_DEFS
#include "cm_defs.h"
#include "cs_packet.h"
#include "time.h"
#include "cm_date_to_text.h"
#include "cm_num.h"

#ifdef __cplusplus
extern "C" {
#endif
#define DCC_LOG_MODULE_NAME "DCC"
#define DCC_LOG_MODULE_NAME_LEN 3
#define DEFAULT_LOG_FILE_PERMISSION 600
#define MAX_LOG_FILE_PERMISSION 640
#define DEFAULT_LOG_PATH_PERMISSION 700
#define MAX_LOG_PATH_PERMISSION 750

#define CM_EV_WAIT_TIMEOUT           16
#define CM_EV_WAIT_NUM               256
#define CM_MAX_PACKET_SIZE         (uint32) SIZE_M(16)

#define CM_SLEEP_1_FIXED 1
#define CM_SLEEP_5_FIXED 5
#define CM_SLEEP_50_FIXED 50

#define CM_SEQUENCE_OFFSET  10
#define CM_PREFIX_FLAG      (1)
#define CM_SEQUENCE_FLAG    (1<<1)

#define SRV_MAX_KEY_SIZE                (4 * 1024)              // 4KB
#define SRV_MAX_VAL_SIZE                (10 * 1024 * 1024)      // 10M

typedef enum dcc_stat_item_id_en {
    DCC_PUT = 0,
    DCC_GET,
    DCC_FETCH,
    DCC_DELETE,
    DCC_WATCH,
    DCC_UNWATCH,
    DCC_DB_PUT,
    DCC_DB_GET,
    DCC_DB_DEL,
} dcc_stat_item_id_t;

static inline status_t cm_reserve_space(cs_packet_t *pack, uint32 size)
{
    CM_RETURN_IFERR(cs_try_realloc_send_pack(pack, CM_ALIGN4(size)));
    pack->head->size += CM_ALIGN4(size);
    return CM_SUCCESS;
}

typedef uint64 timespec_t;
#define NANOSECS_PER_MILLISEC 1000000U
static inline uint64 cm_clock_now_ms()
{
#ifndef WIN32
    struct timespec now = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * MILLISECS_PER_SECOND + ((uint64)(now.tv_nsec)) / NANOSECS_PER_MILLISEC;
#else
    uint64 now = GetTickCount();
    return now;
#endif
}

#ifdef __cplusplus
}
#endif

#endif
