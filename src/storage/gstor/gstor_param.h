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
 * gstor_param.h
 *    gstor param
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_param.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PARAM_H__
#define __KNL_PARAM_H__

#include "cm_config.h"

#ifdef DCC_LITE
#define DEFAULT_VMA_SIZE (uint32)SIZE_M(4)
#define DEFAULT_LARGE_VMA_SIZE (uint32)SIZE_M(1)
#define DEFAULT_LARGE_POOL_SIZE (uint32)SIZE_M(4)
#define DEFAULT_TEMP_BUF_SIZE (uint32)SIZE_M(4)
#define DEFAULT_CR_POOL_SIZE (uint32)SIZE_M(1)
#define DEFAULT_INDEX_BUF_SIZE (uint32)SIZE_K(16)
#define DEFAULT_STATS_SAMPLE_SIZE SIZE_M(32)
#define DEFAULT_UNDO_RESERVER_SIZE (uint32)64
#define DEFAULT_UNDO_SEGMENTS (uint32)2
#define DEFAULT_UNDO_ACTIVE_SEGMENTS (uint32)2
#else
#define DEFAULT_VMA_SIZE (uint32)SIZE_M(16)
#define DEFAULT_LARGE_VMA_SIZE (uint32)SIZE_M(16)
#define DEFAULT_LARGE_POOL_SIZE (uint32)SIZE_M(16)
#define DEFAULT_TEMP_BUF_SIZE (uint32)SIZE_M(128)
#define DEFAULT_CR_POOL_SIZE (uint32)SIZE_M(64)
#define DEFAULT_INDEX_BUF_SIZE (uint32)SIZE_M(32)
#define DEFAULT_STATS_SAMPLE_SIZE SIZE_M(128)
#define DEFAULT_UNDO_RESERVER_SIZE (uint32)1024
#define DEFAULT_UNDO_SEGMENTS (uint32)32
#define DEFAULT_UNDO_ACTIVE_SEGMENTS (uint32)32
#endif
#define DEFAULT_SHARE_AREA_SIZE (uint32)SIZE_M(128)
#define DEFAULT_SQL_POOL_FACTOR (0.5)
#define DEFAULT_TEMP_POOL_NUM (uint32)1
#define DEFAULT_CR_POOL_COUNT (uint32)1
#define DEFAULT_CKPT_INTERVAL (uint32)1000000
#define DEFAULT_CKPT_IO_CAPACITY (uint32)4096
#define DEFAULT_LOG_REPLAY_PROCESSES (uint32)1
#define DEFAULT_RCY_SLEEP_INTERVAL (uint32)32
#define DEFAULT_DBWR_PROCESSES (uint32)1
#define DEFAULT_UNDO_RETENTION_TIME (uint32)100
#define DEFAULT_UNDO_AUTON_TRANS_SEGMENTS (uint32)1
#define DEFAULT_TX_ROLLBACK_PROC_NUM (uint32)2
#define DEFAULT_MAX_ARCH_FILES_SIZE (uint32)SIZE_G(2)
#define DEFAULT_EXTENTS (uint32)128
#define DEFAULT_ALG_ITER (uint32)2000
#define DEFAULT_MAX_COLUMN_COUNT (uint32)128

#define DEFAULT_PRIVATE_KEY_LOCKS (uint32)8
#define DEFAULT_PRIVATE_ROW_LOCKS (uint32)8
#define DEFAULT_SPC_USAGE_ALARM_THRESHOLD (uint32)80
#define DEFAULT_STATS_MAX_BUCKETS (uint32)254
#define DEFAULT_LOG_REUSE_THRESHOLD (uint32)SIZE_M(80)
#define DEFAULT_INIT_LOCKPOOL_PAGES (uint32)1024
#define DEFAULT_MAX_TEMP_TABLES (uint32)128
#define DEFAULT_STACK_SIZE SIZE_K(512)

#define DEFAULT_SPIN_COUNT (uint32)1000
#define DEFAULT_ASHRINK_WAIT_TIME (uint32)21600
#define DEFAULT_CKPT_TIMEOUT (uint32)3
#define DEFAULT_REPL_WAIT_TIMEOUT (uint32)10
#define DEFAULT_NBU_BACKUP_TIMEOUT (uint32)90
#define DEFAULT_XA_SUSPEND_TIMEOUT (uint32)60
#define DEFAULT_BUILD_KEEP_ALIVE_TIMEOUT (uint32)30
#define DEFAULT_INITTRANS (uint32)2
#define DEFAULT_LSND_WAIT_TIME (uint32)3
#define DEFAULT_DDL_LOCK_TIMEOUT (uint32)30

#define FIX_NUM_DAYS_YEAR (uint32)365

void knl_param_get_config_info(config_item_t **params, uint32 *count);
status_t knl_param_get_size_uint64(config_t *config, char *param_name, uint64 *param_value);
status_t knl_param_get_uint32(config_t *config, char *param_name, uint32 *param_value);
status_t knl_param_get_size_uint32(config_t *config, char *param_name, uint32 *param_value);
#endif
