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
 * gstor_sys_def.c
 *    load instance realization
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_sys_def.c
 *
 * -------------------------------------------------------------------------
 */

#include "gstor_sys_def.h"
#include "knl_context.h"
#include "gstor_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_LOG_FILE  3
#define DEFAULT_CTRL_FILE 3
#define DEFAULT_USER_FILE 3
#define DEFAULT_SWAP_FILE 2

static const text_t g_user = { (char*)"SYS", 3 };
static const text_t g_db   = { (char*)"DCC_DB", 6 };

// SYS_CONSTRAINT_DEFS
column_def_t g_consdef_cols[] = {
    { { .str = (char*)"USER#",      .len = 5  }, GS_TYPE_INTEGER, 4,    GS_FALSE },
    { { .str = (char*)"TABLE#",     .len = 6  }, GS_TYPE_INTEGER, 4,    GS_FALSE },
    { { .str = (char*)"CONS_NAME",  .len = 9  }, GS_TYPE_VARCHAR, 64,   GS_FALSE },
    { { .str = (char*)"CONS_TYPE",  .len = 9  }, GS_TYPE_INTEGER, 4,    GS_FALSE },
    { { .str = (char*)"COLS",       .len = 4  }, GS_TYPE_INTEGER, 4,    GS_TRUE  },
    { { .str = (char*)"COL_LIST",   .len = 8  }, GS_TYPE_VARCHAR, 128,  GS_TRUE  },
    { { .str = (char*)"IND#",       .len = 4  }, GS_TYPE_INTEGER, 4,    GS_TRUE  },
    { { .str = (char*)"REF_USER#",  .len = 9  }, GS_TYPE_INTEGER, 4,    GS_TRUE  },
    { { .str = (char*)"REF_TABLE#", .len = 10 }, GS_TYPE_INTEGER, 4,    GS_TRUE  },
    { { .str = (char*)"REF_CONS",   .len = 8  }, GS_TYPE_INTEGER, 4,    GS_TRUE  },
    { { .str = (char*)"COND_TEXT",  .len = 9  }, GS_TYPE_VARCHAR, 2048, GS_TRUE  },
    { { .str = (char*)"COND_DATA",  .len = 9  }, GS_TYPE_BINARY,  4096, GS_TRUE  },
    { { .str = (char*)"FLAGS",      .len = 5  }, GS_TYPE_INTEGER, 4,    GS_TRUE  },
    { { .str = (char*)"REFACT",     .len = 6  }, GS_TYPE_INTEGER, 4,    GS_TRUE  }
};

text_t g_consdef_idx01_cols[] = {
    { .str = (char*)"USER#",  .len = 5 },
    { .str = (char*)"TABLE#", .len = 6 }
};

text_t g_consdef_idx02_cols[] = {
    { .str = (char*)"REF_USER#",  .len = 9  },
    { .str = (char*)"REF_TABLE#", .len = 10 }
};

text_t g_consdef_idx03_cols[] = {
    {.str = (char*)"USER#",     .len = 5 },
    {.str = (char*)"CONS_NAME", .len = 9 }
};

#define CONSDEF_COL_COUNT       (sizeof(g_consdef_cols) / sizeof(column_def_t))
#define CONSDEF_IDX01_COL_COUNT (sizeof(g_consdef_idx01_cols) / sizeof(text_t))
#define CONSDEF_IDX02_COL_COUNT (sizeof(g_consdef_idx02_cols) / sizeof(text_t))
#define CONSDEF_IDX03_COL_COUNT (sizeof(g_consdef_idx03_cols) / sizeof(text_t))

static index_def_t g_consdef_indexes[] = {
    { {.str = (char*)"IX_CONSDEF$001", .len = 14 }, g_consdef_idx01_cols, CONSDEF_IDX01_COL_COUNT, GS_FALSE },
    { {.str = (char*)"IX_CONSDEF$002", .len = 14 }, g_consdef_idx02_cols, CONSDEF_IDX02_COL_COUNT, GS_FALSE },
    { {.str = (char*)"IX_CONSDEF$003", .len = 14 }, g_consdef_idx03_cols, CONSDEF_IDX03_COL_COUNT, GS_TRUE }
};

// SYS_GARBAGE_SEGMENTS
column_def_t g_garbage_segments_cols[] = {
    { { .str = (char*)"UID",       .len = 3 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"OID",       .len = 3 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"INDEX_ID",  .len = 8 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"COLUMN_ID", .len = 9 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"SPACE",     .len = 5 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"ENTRY",     .len = 5 }, GS_TYPE_BIGINT,  8,  GS_TRUE },
    { { .str = (char*)"ORG_SCN",   .len = 7 }, GS_TYPE_BIGINT,  8,  GS_TRUE },
    { { .str = (char*)"SEG_SCN",   .len = 7 }, GS_TYPE_BIGINT,  8,  GS_TRUE },
    { { .str = (char*)"INITRANS",  .len = 8 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"PCTFREE",   .len = 7 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"OP_TYPE",   .len = 7 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"REUSE",     .len = 5 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"SERIAL",    .len = 6 }, GS_TYPE_BIGINT,  8,  GS_TRUE },
    { { .str = (char*)"SPARE2",    .len = 6 }, GS_TYPE_INTEGER, 4,  GS_TRUE },
    { { .str = (char*)"SPARE3",    .len = 6 }, GS_TYPE_INTEGER, 4,  GS_TRUE }
};

text_t g_garbage_segment_idx01_cols[] = {
    { .str = (char*)"UID", .len = 3 },
    { .str = (char*)"OID", .len = 3 }
};

#define GARBAGE_SEGMENTS_COL_COUNT      (sizeof(g_garbage_segments_cols) / sizeof(column_def_t))
#define GARBAGE_SEGMENT_IDX01_COL_COUNT (sizeof(g_garbage_segment_idx01_cols) / sizeof(text_t))

static index_def_t g_garbage_segment_indexes[] = {{{.str = (char *)"IX_GARBAGE_SEGMENT$001", .len = 22},
    g_garbage_segment_idx01_cols,
    GARBAGE_SEGMENT_IDX01_COL_COUNT,
    GS_FALSE}};

// SYS_INSTANCE_INFO
column_def_t g_sys_instance_info_cols[] = {
    { {.str = (char*)"NAME",  .len = 4 }, GS_TYPE_VARCHAR, 64,  GS_FALSE },
    { {.str = (char*)"VALUE", .len = 5 }, GS_TYPE_BIGINT,   8,  GS_FALSE }
};

text_t g_sys_instance_info_idx01_cols[] = {
    {.str = (char*)"NAME", .len = 4 }
};

#define SYS_INSTANCE_INFO_COL_COUNT       (sizeof(g_sys_instance_info_cols) / sizeof(column_def_t))
#define SYS_INSTANCE_INFO_IDX01_COL_COUNT (sizeof(g_sys_instance_info_idx01_cols) / sizeof(text_t))

static index_def_t g_sys_instance_info_indexes[] = {{{.str = (char *)"IDX_SYS_INSTANCE_INFO_001", .len = 25},
    g_sys_instance_info_idx01_cols,
    SYS_INSTANCE_INFO_IDX01_COL_COUNT,
    GS_TRUE}};

// SYS_LOBS
column_def_t g_sys_lobs_cols[] = {
    { {.str = (char*)"USER#",      .len = 5  }, GS_TYPE_INTEGER, 4,  GS_FALSE },
    { {.str = (char*)"TABLE#",     .len = 6  }, GS_TYPE_INTEGER, 4,  GS_FALSE },
    { {.str = (char*)"COLUMN#",    .len = 7  }, GS_TYPE_INTEGER, 4,  GS_FALSE },
    { {.str = (char*)"SPACE#",     .len = 6  }, GS_TYPE_INTEGER, 4,  GS_FALSE },
    { {.str = (char*)"ENTRY",      .len = 5  }, GS_TYPE_BIGINT,  8,  GS_TRUE  },
    { {.str = (char*)"ORG_SCN",    .len = 7  }, GS_TYPE_BIGINT,  8,  GS_TRUE  },
    { {.str = (char*)"CHG_SCN",    .len = 7  }, GS_TYPE_BIGINT,  8,  GS_TRUE  },
    { {.str = (char*)"CHUNK",      .len = 5  }, GS_TYPE_INTEGER, 4,  GS_TRUE  },
    { {.str = (char*)"PCTVERSION", .len = 10 }, GS_TYPE_INTEGER, 4,  GS_TRUE  },
    { {.str = (char*)"RETENSION",  .len = 9  }, GS_TYPE_INTEGER, 4,  GS_TRUE  },
    { {.str = (char*)"FLAGS",      .len = 5  }, GS_TYPE_INTEGER, 4,  GS_TRUE  }
};

text_t g_sys_lobs_idx01_cols[] = {
    {.str = (char*)"USER#",   .len = 5 },
    {.str = (char*)"TABLE#",  .len = 6 },
    {.str = (char*)"COLUMN#", .len = 7 }
};

#define SYS_LOBS_COL_COUNT       (sizeof(g_sys_lobs_cols) / sizeof(column_def_t))
#define SYS_LOBS_IDX01_COL_COUNT (sizeof(g_sys_lobs_idx01_cols) / sizeof(text_t))

static index_def_t g_sys_lobs_indexes[] = {
    { {.str = (char*)"IX_LOB$001", .len = 10 }, g_sys_lobs_idx01_cols, SYS_LOBS_IDX01_COL_COUNT, GS_TRUE }
};

// SYS_DISTRIBUTE_STRATEGIES
column_def_t g_distribute_strategy_cols[] = {
    { {.str = (char*)"USER#",         .len = 5  }, GS_TYPE_INTEGER,  4,    GS_FALSE },
    { {.str = (char*)"TABLE#",        .len = 6  }, GS_TYPE_INTEGER,  4,    GS_FALSE },
    { {.str = (char*)"DIST_DATA",     .len = 9  }, GS_TYPE_VARCHAR,  1024, GS_FALSE },
    { {.str = (char*)"BUCKETS",       .len = 7  }, GS_TYPE_BLOB,     8000, GS_TRUE  },
    { {.str = (char*)"SLICE_COUNT",   .len = 11 }, GS_TYPE_INTEGER,  4,    GS_TRUE  },
    { {.str = (char*)"FROZEN_STATUS", .len = 13 }, GS_TYPE_INTEGER,  4,    GS_TRUE  },
    { {.str = (char*)"DIST_TEXT",     .len = 9  }, GS_TYPE_VARCHAR,  1024, GS_TRUE  }
};

text_t g_distribute_strategy_idx01_cols[] = {
    {.str = (char*)"USER#",  .len = 5 },
    {.str = (char*)"TABLE#", .len = 6 }
};

#define DISTRIBUTE_STRATEGY_COL_COUNT       (sizeof(g_distribute_strategy_cols) / sizeof(column_def_t))
#define DISTRIBUTE_STRATEGY_IDX01_COL_COUNT (sizeof(g_distribute_strategy_idx01_cols) / sizeof(text_t))

static index_def_t g_distribute_strategy_indexes[] = {{{.str = (char *)"IX_DISTRIBUTE_STRATEGY$001", .len = 26},
    g_distribute_strategy_idx01_cols,
    DISTRIBUTE_STRATEGY_IDX01_COL_COUNT,
    GS_TRUE}};

// SYS_POLICIES
column_def_t g_sys_policies_cols[] = {
    { {.str = (char*)"OBJ_SCHEMA_ID",  .len = 13 }, GS_TYPE_INTEGER, 4,   GS_FALSE },
    { {.str = (char*)"OBJ_NAME",       .len = 8  }, GS_TYPE_VARCHAR, 64,  GS_FALSE },
    { {.str = (char*)"PNAME",          .len = 5  }, GS_TYPE_VARCHAR, 64,  GS_FALSE },
    { {.str = (char*)"PF_SCHEMA",      .len = 9  }, GS_TYPE_VARCHAR, 64,  GS_FALSE },
    { {.str = (char*)"PF_NAME",        .len = 7  }, GS_TYPE_VARCHAR, 128, GS_FALSE },
    { {.str = (char*)"STMT_TYPE",      .len = 9  }, GS_TYPE_INTEGER, 4,   GS_FALSE },
    { {.str = (char*)"PTYPE",          .len = 5  }, GS_TYPE_INTEGER, 4,   GS_FALSE },
    { {.str = (char*)"CHK_OPTION",     .len = 10 }, GS_TYPE_INTEGER, 4,   GS_FALSE },
    { {.str = (char*)"ENABLE",         .len = 6  }, GS_TYPE_INTEGER, 4,   GS_FALSE },
    { {.str = (char*)"LONG_PREDICATE", .len = 14 }, GS_TYPE_INTEGER, 4,   GS_FALSE }
};

text_t g_sys_policies_idx01_cols[] = {
    {.str = (char*)"OBJ_SCHEMA_ID", .len = 13 },
    {.str = (char*)"OBJ_NAME",      .len = 8  },
    {.str = (char*)"PNAME",         .len = 5  }
};

#define SYS_POLICIES_COL_COUNT       (sizeof(g_sys_policies_cols) / sizeof(column_def_t))
#define SYS_POLICIES_IDX01_COL_COUNT (sizeof(g_sys_policies_idx01_cols) / sizeof(text_t))

static index_def_t g_sys_policies_indexes[] = {{{.str = (char *)"IDX_SYS_POLICY_001", .len = 18},
    g_sys_policies_idx01_cols,
    SYS_POLICIES_IDX01_COL_COUNT,
    GS_TRUE}};

// SYS_DDM
column_def_t g_sys_ddm_cols[] = {
    { {.str = (char*)"USER#",     .len = 5 }, GS_TYPE_INTEGER,  4,    GS_TRUE },
    { {.str = (char*)"TABLE#",    .len = 6 }, GS_TYPE_INTEGER,  4,    GS_TRUE },
    { {.str = (char*)"COLUMN#",   .len = 7 }, GS_TYPE_INTEGER,  4,    GS_TRUE },
    { {.str = (char*)"RULE_NAME", .len = 9 }, GS_TYPE_VARCHAR,  64,   GS_TRUE },
    { {.str = (char*)"TYPE_NAME", .len = 9 }, GS_TYPE_VARCHAR,  64,   GS_TRUE },
    { {.str = (char*)"PARAM",     .len = 5 }, GS_TYPE_VARCHAR,  1024, GS_TRUE }
};

text_t g_sys_ddm_idx01_cols[] = {
    {.str = (char*)"USER#",   .len = 5 },
    {.str = (char*)"TABLE#",  .len = 6 },
    {.str = (char*)"COLUMN#", .len = 7 }
};

text_t g_sys_ddm_idx02_cols[] = {
    {.str = (char*)"USER#",     .len = 5 },
    {.str = (char*)"TABLE#",    .len = 6 },
    {.str = (char*)"RULE_NAME", .len = 9 }
};

#define SYS_DDM_COL_COUNT       (sizeof(g_sys_ddm_cols) / sizeof(column_def_t))
#define SYS_DDM_IDX01_COL_COUNT (sizeof(g_sys_ddm_idx01_cols) / sizeof(text_t))
#define SYS_DDM_IDX02_COL_COUNT (sizeof(g_sys_ddm_idx02_cols) / sizeof(text_t))

static index_def_t g_sys_ddm_indexes[] = {
    { {.str = (char*)"IDX_DDM_001", .len = 11 }, g_sys_ddm_idx01_cols, SYS_DDM_IDX01_COL_COUNT, GS_FALSE },
    { {.str = (char*)"IDX_DDM_002", .len = 11 }, g_sys_ddm_idx02_cols, SYS_DDM_IDX02_COL_COUNT, GS_FALSE }
};

// SYS_DML_STATS
column_def_t g_sys_dml_stats_cols[] = {
    { {.str = (char*)"USER#",         .len = 5  }, GS_TYPE_INTEGER,   4,  GS_FALSE },
    { {.str = (char*)"TABLE#",        .len = 6  }, GS_TYPE_INTEGER,   4,  GS_FALSE },
    { {.str = (char*)"INSERTS",       .len = 7  }, GS_TYPE_INTEGER,   4,  GS_FALSE },
    { {.str = (char*)"UPDATES",       .len = 7  }, GS_TYPE_INTEGER,   4,  GS_FALSE },
    { {.str = (char*)"DELETES",       .len = 7  }, GS_TYPE_INTEGER,   4,  GS_FALSE },
    { {.str = (char*)"MODIFY_TIME",   .len = 11 }, GS_TYPE_TIMESTAMP, 8,  GS_FALSE },
    { {.str = (char*)"FLAGS",         .len = 5  }, GS_TYPE_INTEGER,   4,  GS_FALSE },
    { {.str = (char*)"DROP_SEGMENTS", .len = 13 }, GS_TYPE_INTEGER,   4,  GS_FALSE },
    { {.str = (char*)"PARTED",        .len = 6  }, GS_TYPE_INTEGER,   4,  GS_TRUE  },
    { {.str = (char*)"PART#",         .len = 5  }, GS_TYPE_INTEGER,   4,  GS_TRUE  }
};

text_t g_sys_dml_stats_idx01_cols[] = {
    {.str = (char*)"USER#",  .len = 5 },
    {.str = (char*)"TABLE#", .len = 6 },
};

text_t g_sys_dml_stats_idx02_cols[] = {
    {.str = (char*)"MODIFY_TIME#", .len = 11 }
};

text_t g_sys_dml_stats_idx03_cols[] = {
    {.str = (char*)"USER#",  .len = 5 },
    {.str = (char*)"TABLE#", .len = 6 },
    {.str = (char*)"PART#",  .len = 5 }
};

#define SYS_DML_STATS_COL_COUNT       (sizeof(g_sys_dml_stats_cols) / sizeof(column_def_t))
#define SYS_DML_STATS_IDX01_COL_COUNT (sizeof(g_sys_dml_stats_idx01_cols) / sizeof(text_t))
#define SYS_DML_STATS_IDX02_COL_COUNT (sizeof(g_sys_dml_stats_idx02_cols) / sizeof(text_t))
#define SYS_DML_STATS_IDX03_COL_COUNT (sizeof(g_sys_dml_stats_idx03_cols) / sizeof(text_t))

static index_def_t g_sys_dml_stats_indexes[] = {
    { {.str = (char*)"IX_MODS_001", .len = 11 }, g_sys_dml_stats_idx01_cols, SYS_DML_STATS_IDX01_COL_COUNT, GS_FALSE },
    { {.str = (char*)"IX_MODS_002", .len = 11 }, g_sys_dml_stats_idx02_cols, SYS_DML_STATS_IDX02_COL_COUNT, GS_FALSE },
    { {.str = (char*)"IX_MODS_003", .len = 11 }, g_sys_dml_stats_idx03_cols, SYS_DML_STATS_IDX03_COL_COUNT, GS_TRUE },
};

// SYS_SHADOW_INDEXES
column_def_t g_shadow_indexes_cols[] = {
    { {.str = (char*)"USER#",      .len = 5  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"TABLE#",     .len = 6  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"ID",         .len = 2  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"NAME",       .len = 4  }, GS_TYPE_VARCHAR,   64,  GS_FALSE },
    { {.str = (char*)"SPACE#",     .len = 6  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"SEQUENCE#",  .len = 9  }, GS_TYPE_BIGINT,    8,   GS_FALSE },
    { {.str = (char*)"ENTRY",      .len = 5  }, GS_TYPE_BIGINT,    8,   GS_FALSE },
    { {.str = (char*)"IS_PRIMARY", .len = 10 }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"IS_UNIQUE",  .len = 9  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"TYPE",       .len = 4  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"COLS",       .len = 4  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"COL_LIST",   .len = 8  }, GS_TYPE_VARCHAR,   128, GS_FALSE },
    { {.str = (char*)"INITRANS",   .len = 8  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"CR_MODE",    .len = 7  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"FLAGS",      .len = 5  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"PARTED",     .len = 6  }, GS_TYPE_INTEGER,   4,   GS_FALSE },
    { {.str = (char*)"PCTFREE",    .len = 7  }, GS_TYPE_INTEGER,   4,   GS_FALSE }
};

text_t g_shadow_indexes_idx01_cols[] = {
    {.str = (char*)"USER#",  .len = 5 },
    {.str = (char*)"TABLE#", .len = 6 }
};

#define SHADOW_INDEXES_COL_COUNT       (sizeof(g_shadow_indexes_cols) / sizeof(column_def_t))
#define SHADOW_INDEXES_IDX01_COL_COUNT (sizeof(g_shadow_indexes_idx01_cols) / sizeof(text_t))

static index_def_t g_shadow_indexes_indexes[] = {{{.str = (char *)"IX_SHADOW_INDEX$_001", .len = 20},
    g_shadow_indexes_idx01_cols,
    SHADOW_INDEXES_IDX01_COL_COUNT,
    GS_TRUE}};

// SYS_SHADOW_INDEX_PARTS
column_def_t g_shw_indexpart_cols[] = {
    { {.str = (char*)"USER#",        .len = 5  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"TABLE#",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"INDEX#",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"PART#",        .len = 5  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"NAME",         .len = 4  }, GS_TYPE_VARCHAR,   64,     GS_FALSE },
    { {.str = (char*)"HIBOUNDLEN",   .len = 10 }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"HIBOUNDVAL",   .len = 10 }, GS_TYPE_VARCHAR,   4000,   GS_TRUE  },
    { {.str = (char*)"SPACE#",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"ORG_SCN",      .len = 7  }, GS_TYPE_BIGINT,    8,      GS_FALSE },
    { {.str = (char*)"ENTRY",        .len = 5  }, GS_TYPE_BIGINT,    8,      GS_FALSE },
    { {.str = (char*)"INITRANS",     .len = 8  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"PCTFREE",      .len = 7  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"FLAGS",        .len = 5  }, GS_TYPE_INTEGER,   4,      GS_TRUE  },
    { {.str = (char*)"BHIBOUNDVAL",  .len = 11 }, GS_TYPE_BINARY,    4000,   GS_TRUE  },
    { {.str = (char*)"PARENT_PART#", .len = 12 }, GS_TYPE_INTEGER,   4,      GS_TRUE  }
};

text_t g_shw_indexpart_idx01_cols[] = {
    {.str = (char*)"USER#",        .len = 5 },
    {.str = (char*)"TABLE#",       .len = 6 },
    {.str = (char*)"INDEX#",       .len = 6 },
    {.str = (char*)"PART#",        .len = 6 },
    {.str = (char*)"PARENT_PART#", .len = 12 }
};

#define SHW_INDEXPART_COL_COUNT       (sizeof(g_shw_indexpart_cols) / sizeof(column_def_t))
#define SHW_INDEXPART_IDX01_COL_COUNT (sizeof(g_shw_indexpart_idx01_cols) / sizeof(text_t))

static index_def_t g_shw_indexpart_indexes[] = {{{.str = (char *)"IX_SHW_INDEXPART$001", .len = 20},
    g_shw_indexpart_idx01_cols,
    SHW_INDEXPART_IDX01_COL_COUNT,
    GS_FALSE}};

// SYS_TABLE_PARTS
column_def_t g_table_parts_cols[] = {
    { {.str = (char*)"USER#",       .len = 5  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"TABLE#",      .len = 6  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"PART#",       .len = 5  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"NAME",        .len = 4  }, GS_TYPE_VARCHAR,   64,     GS_FALSE },
    { {.str = (char*)"HIBOUNDLEN",  .len = 10 }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"HIBOUNDVAL",  .len = 10 }, GS_TYPE_VARCHAR,   4000,   GS_TRUE  },
    { {.str = (char*)"SPACE#",      .len = 6  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"ORG_SCN",     .len = 7  }, GS_TYPE_BIGINT,    8,      GS_FALSE },
    { {.str = (char*)"ENTRY",       .len = 5  }, GS_TYPE_BIGINT,    8,      GS_FALSE },
    { {.str = (char*)"INITRANS",    .len = 8  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"PCTFREE",     .len = 7  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"FLAGS",       .len = 5  }, GS_TYPE_INTEGER,   4,      GS_TRUE  },
    { {.str = (char*)"BHIBOUNDVAL", .len = 11 }, GS_TYPE_BINARY,    4000,   GS_TRUE  },
    { {.str = (char*)"ROWCNT",      .len = 6  }, GS_TYPE_INTEGER,   4,      GS_TRUE  },
    { {.str = (char*)"BLKCNT",      .len = 6  }, GS_TYPE_INTEGER,   4,      GS_TRUE  },
    { {.str = (char*)"EMPCNT",      .len = 6  }, GS_TYPE_INTEGER,   4,      GS_TRUE  },
    { {.str = (char*)"AVGRLN",      .len = 6  }, GS_TYPE_INTEGER,   4,      GS_TRUE  },
    { {.str = (char*)"SAMPLESIZE",  .len = 10 }, GS_TYPE_INTEGER,   4,      GS_TRUE  },
    { {.str = (char*)"ANALYZETIME", .len = 11 }, GS_TYPE_DATE,      8,      GS_TRUE  },
    { {.str = (char*)"SUBPARTCNT",  .len = 10 }, GS_TYPE_INTEGER,   4,      GS_TRUE  }
};

text_t g_table_parts_idx01_cols[] = {
    {.str = (char*)"USER#",  .len = 5 },
    {.str = (char*)"TABLE#", .len = 6 },
    {.str = (char*)"PART#",  .len = 6 }
};

#define TABLE_PARTS_COL_COUNT       (sizeof(g_table_parts_cols) / sizeof(column_def_t))
#define TABLE_PARTS_IDX01_COL_COUNT (sizeof(g_table_parts_idx01_cols) / sizeof(text_t))

static index_def_t g_table_parts_indexes[] = {
    { {.str = (char*)"IX_TABLEPART$001", .len = 16 }, g_table_parts_idx01_cols, TABLE_PARTS_IDX01_COL_COUNT, GS_TRUE }
};

// SYS_SUB_TABLE_PARTS
column_def_t g_subtable_parts_cols[] = {
    { {.str = (char*)"USER#",        .len = 5  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"TABLE#",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"SUBPART#",     .len = 8  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"NAME",         .len = 4  }, GS_TYPE_VARCHAR,   64,     GS_FALSE },
    { {.str = (char*)"HIBOUNDLEN",   .len = 10 }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"HIBOUNDVAL",   .len = 10 }, GS_TYPE_VARCHAR,   4000,   GS_TRUE },
    { {.str = (char*)"SPACE#",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"ORG_SCN",      .len = 7  }, GS_TYPE_BIGINT,    8,      GS_FALSE },
    { {.str = (char*)"ENTRY",        .len = 5  }, GS_TYPE_BIGINT,    8,      GS_FALSE },
    { {.str = (char*)"INITRANS",     .len = 8  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"PCTFREE",      .len = 7  }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"FLAGS",        .len = 5  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"BHIBOUNDVAL",  .len = 11 }, GS_TYPE_BINARY,    4000,   GS_TRUE },
    { {.str = (char*)"ROWCNT",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"BLKCNT",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"EMPCNT",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"AVGRLN",       .len = 6  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"SAMPLESIZE",   .len = 10 }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"ANALYZETIME",  .len = 11 }, GS_TYPE_DATE,      8,      GS_TRUE },
    { {.str = (char*)"PARENT_PART#", .len = 12 }, GS_TYPE_INTEGER,   4,      GS_FALSE }
};

text_t g_subtable_parts_idx01_cols[] = {
    {.str = (char*)"USER#",        .len = 5  },
    {.str = (char*)"TABLE#",       .len = 6  },
    {.str = (char*)"PARENT_PART#", .len = 12 },
    {.str = (char*)"SUBPART#",     .len = 8  }
};

text_t g_subtable_parts_idx02_cols[] = {
    {.str = (char*)"USER#",  .len = 5 },
    {.str = (char*)"TABLE#", .len = 6 },
    {.str = (char*)"NAME",   .len = 4 }
};

#define SUBTABLE_PARTS_COL_COUNT       (sizeof(g_subtable_parts_cols) / sizeof(column_def_t))
#define SUBTABLE_PARTS_IDX01_COL_COUNT (sizeof(g_subtable_parts_idx01_cols) / sizeof(text_t))
#define SUBTABLE_PARTS_IDX02_COL_COUNT (sizeof(g_subtable_parts_idx02_cols) / sizeof(text_t))

static index_def_t g_subtable_parts_indexes[] = {
    {{.str = (char *)"IX_SUBTABLEPART$001", .len = 19},
        g_subtable_parts_idx01_cols,
        SUBTABLE_PARTS_IDX01_COL_COUNT,
        GS_TRUE},
    {{.str = (char *)"IX_SUBTABLEPART$002", .len = 19},
        g_subtable_parts_idx02_cols,
        SUBTABLE_PARTS_IDX02_COL_COUNT,
        GS_TRUE}};

// SYS_PENDING_TRANS
column_def_t g_pending_trans_cols[] = {
    { {.str = (char*)"GLOBAL_TRAN_ID", .len = 14 }, GS_TYPE_VARCHAR,   256,      GS_FALSE },
    { {.str = (char*)"LOCAL_TRAN_ID",  .len = 13 }, GS_TYPE_BIGINT,    8,        GS_TRUE  },
    { {.str = (char*)"TLOCK_LOBS",     .len = 10 }, GS_TYPE_BINARY,    4000,     GS_TRUE  },
    { {.str = (char*)"TLOCK_LOBS_EXT", .len = 14 }, GS_TYPE_BLOB,      8000,     GS_TRUE  },
    { {.str = (char*)"FORMAT_ID",      .len = 9  }, GS_TYPE_BIGINT,    8,        GS_TRUE  },
    { {.str = (char*)"BRANCH_ID",      .len = 9  }, GS_TYPE_VARCHAR,   128,      GS_TRUE  },
    { {.str = (char*)"OWNER",          .len = 5  }, GS_TYPE_INTEGER,   4,        GS_TRUE  },
    { {.str = (char*)"PREPARE_SCN",    .len = 11 }, GS_TYPE_BIGINT,    8,        GS_TRUE  },
    { {.str = (char*)"COMMIT_SCN",     .len = 10 }, GS_TYPE_BIGINT,    8,        GS_TRUE  }
};

#define PENDING_TRANS_COL_COUNT       (sizeof(g_pending_trans_cols) / sizeof(column_def_t))

// SYS_TMP_SEG_STATS
column_def_t g_tmp_seg_stats_cols[] = {
    { {.str = (char*)"ORG_SCN",         .len = 7  }, GS_TYPE_BIGINT,   8,      GS_FALSE },
    { {.str = (char*)"UID",             .len = 3  }, GS_TYPE_INTEGER,  4,      GS_TRUE  },
    { {.str = (char*)"OID",             .len = 3  }, GS_TYPE_INTEGER,  4,      GS_TRUE  },
    { {.str = (char*)"LOGIC_READS",     .len = 11 }, GS_TYPE_BIGINT,   8,      GS_TRUE  },
    { {.str = (char*)"PHYSICAL_WRITES", .len = 15 }, GS_TYPE_BIGINT,   8,      GS_TRUE  },
    { {.str = (char*)"PHYSICAL_READS",  .len = 14 }, GS_TYPE_BIGINT,   8,      GS_TRUE  },
    { {.str = (char*)"ITL_WAITS",       .len = 9  }, GS_TYPE_BIGINT,   8,      GS_TRUE  },
    { {.str = (char*)"BUF_BUSY_WAITS",  .len = 14 }, GS_TYPE_BIGINT,   8,      GS_TRUE  },
    { {.str = (char*)"ROW_LOCK_WAITS",  .len = 14 }, GS_TYPE_BIGINT,   8,      GS_TRUE  }
};

text_t g_object_idx01_cols[] = {
    {.str = (char*)"ORG_SCN", .len = 7 }
};

text_t g_object_idx02_cols[] = {
    {.str = (char*)"UID", .len = 3 },
    {.str = (char*)"OID", .len = 3 }
};

#define TMP_SEG_STATS_COL_COUNT   (sizeof(g_tmp_seg_stats_cols) / sizeof(column_def_t))
#define OBJECT_IDX01_COL_COUNT    (sizeof(g_object_idx01_cols) / sizeof(text_t))
#define OBJECT_IDX02_COL_COUNT    (sizeof(g_object_idx02_cols) / sizeof(text_t))

static index_def_t g_tmp_seg_stats_indexes[] = {
    { {.str = (char*)"IDX_OBJECT01", .len = 12 }, g_object_idx01_cols, OBJECT_IDX01_COL_COUNT, GS_TRUE },
    { {.str = (char*)"IDX_OBJECT",   .len = 10 }, g_object_idx02_cols, OBJECT_IDX02_COL_COUNT, GS_FALSE }
};

// SYS_TEMP_HISTGRAM
column_def_t g_temp_histgram_cols[] = {
    { {.str = (char*)"USER#",    .len = 5 }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"TABLE#",   .len = 6 }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"COL#",     .len = 4 }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"BUCKET",   .len = 6 }, GS_TYPE_VARCHAR,   4000,   GS_TRUE },
    { {.str = (char*)"ENDPOINT", .len = 8 }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"PART#",    .len = 5 }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"EPVALUE",  .len = 7 }, GS_TYPE_VARCHAR,   1000,   GS_TRUE },
    { {.str = (char*)"SPARE1",   .len = 6 }, GS_TYPE_BIGINT,    8,      GS_TRUE },
    { {.str = (char*)"SPARE2",   .len = 6 }, GS_TYPE_BIGINT,    8,      GS_TRUE },
    { {.str = (char*)"SPARE3",   .len = 6 }, GS_TYPE_BIGINT,    8,      GS_TRUE }
};
text_t g_temp_histgram_idx01_cols[] = {
    {.str = (char*)"USER#",    .len = 5 },
    {.str = (char*)"TABLE#",   .len = 6 },
    {.str = (char*)"COL#",     .len = 4 },
    {.str = (char*)"PART#",    .len = 5 },
    {.str = (char*)"ENDPOINT", .len = 8 }
};
#define TEMP_HISTGRAM_COL_COUNT          (sizeof(g_temp_histgram_cols) / sizeof(column_def_t))
#define TEMP_HISTGRAM_IDX01_COL_COUNT    (sizeof(g_temp_histgram_idx01_cols) / sizeof(text_t))

static index_def_t g_temp_histgram_indexes[] = {{{.str = (char *)"IX_TEMP_HIST_003", .len = 16},
    g_temp_histgram_idx01_cols,
    TEMP_HISTGRAM_IDX01_COL_COUNT,
    GS_FALSE}};

// SYS_TEMP_HISTGRAM_ABSTR
column_def_t g_temp_hist_abstr_cols[] = {
    { {.str = (char*)"USER#",        .len = 5  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"TAB#",         .len = 4  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"COL#",         .len = 4  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"BUCKET_NUM",   .len = 10 }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"ROW_NUM",      .len = 7  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"NULL_NUM",     .len = 8  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"ANALYZE_TIME", .len = 12 }, GS_TYPE_DATE,      8,      GS_TRUE },
    { {.str = (char*)"MINVALUE",     .len = 8  }, GS_TYPE_VARCHAR,   4000,   GS_TRUE },
    { {.str = (char*)"MAXVALUE",     .len = 8  }, GS_TYPE_VARCHAR,   4000,   GS_TRUE },
    { {.str = (char*)"DIST_NUM",     .len = 8  }, GS_TYPE_INTEGER,   4,      GS_TRUE },
    { {.str = (char*)"DENSITY",      .len = 7  }, GS_TYPE_REAL,      8,      GS_TRUE },
    { {.str = (char*)"SPARE1",       .len = 6  }, GS_TYPE_BIGINT,    8,      GS_TRUE },
    { {.str = (char*)"SPARE2",       .len = 6  }, GS_TYPE_BIGINT,    8,      GS_TRUE },
    { {.str = (char*)"SPARE3",       .len = 6  }, GS_TYPE_BIGINT,    8,      GS_TRUE },
    { {.str = (char*)"SPARE4",       .len = 6  }, GS_TYPE_BIGINT,    8,      GS_TRUE }
};

text_t g_temp_hist_abstr_idx01_cols[] = {
    {.str = (char*)"ANALYZE_TIME", .len = 12 }
};

text_t g_temp_hist_abstr_idx02_cols[] = {
    {.str = (char*)"USER#",  .len = 5 },
    {.str = (char*)"TAB#",   .len = 4 },
    {.str = (char*)"COL#",   .len = 4 },
    {.str = (char*)"SPARE1", .len = 6 }
};

#define TEMP_HIST_ABSTR_COL_COUNT          (sizeof(g_temp_hist_abstr_cols) / sizeof(column_def_t))
#define TEMP_HIST_ABSTR_IDX01_COL_COUNT    (sizeof(g_temp_hist_abstr_idx01_cols) / sizeof(text_t))
#define TEMP_HIST_ABSTR_IDX02_COL_COUNT    (sizeof(g_temp_hist_abstr_idx02_cols) / sizeof(text_t))

static index_def_t g_temp_hist_abstr_indexes[] = {
    {{.str = (char *)"IX_TEMP_HIST_HEAD_002", .len = 21},
        g_temp_hist_abstr_idx01_cols,
        TEMP_HIST_ABSTR_IDX01_COL_COUNT,
        GS_FALSE},
    {{.str = (char *)"IX_TEMP_HIST_HEAD_003", .len = 21},
        g_temp_hist_abstr_idx02_cols,
        TEMP_HIST_ABSTR_IDX02_COL_COUNT,
        GS_TRUE}};

// SYS_DUMMY
column_def_t g_sys_dummy_cols[] = {
    { {.str = (char*)"DUMMY", .len = 5 }, GS_TYPE_VARCHAR,   1,      GS_FALSE },
};
#define SYS_DUMMY_COL_COUNT       (sizeof(g_sys_dummy_cols) / sizeof(column_def_t))

// SYS_PRIVS
column_def_t g_sys_privs_cols[] = {
    { {.str = (char*)"GRANTEE_ID",   .len = 10 }, GS_TYPE_INTEGER,    4,     GS_FALSE },
    { {.str = (char*)"GRANTEE_TYPE", .len = 12 }, GS_TYPE_INTEGER,    4,     GS_FALSE },
    { {.str = (char*)"PRIVILEGE",    .len = 9  }, GS_TYPE_INTEGER,    4,     GS_FALSE },
    { {.str = (char*)"ADMIN_OPTION", .len = 12 }, GS_TYPE_INTEGER,    4,     GS_FALSE },
};

text_t g_sys_privs_idx01_cols[] = {
    {.str = (char*)"GRANTEE_ID",   .len = 10 },
    {.str = (char*)"GRANTEE_TYPE", .len = 12 },
    {.str = (char*)"PRIVILEGE",    .len = 9  }
};

#define SYS_PRIVS_COL_COUNT          (sizeof(g_sys_privs_cols) / sizeof(column_def_t))
#define SYS_PRIVS_IDX01_COL_COUNT    (sizeof(g_sys_privs_idx01_cols) / sizeof(text_t))

static index_def_t g_sys_privs_indexes[] = {
    { {.str = (char*)"IX_SYS_PRIVS$_001", .len = 17 }, g_sys_privs_idx01_cols, SYS_PRIVS_IDX01_COL_COUNT, GS_TRUE }
};

// SYS_ROLES
column_def_t g_sys_roles_cols[] = {
    { {.str = (char*)"ID",        .len = 2 }, GS_TYPE_INTEGER,    4,     GS_FALSE },
    { {.str = (char*)"OWNER_UID", .len = 9 }, GS_TYPE_INTEGER,    4,     GS_FALSE },
    { {.str = (char*)"NAME",      .len = 4 }, GS_TYPE_VARCHAR,    64,    GS_FALSE },
    { {.str = (char*)"PASSWORD",  .len = 8 }, GS_TYPE_VARCHAR,    256,   GS_TRUE  },
};

text_t g_sys_roles_idx01_cols[] = {
    {.str = (char*)"ID",   .len = 2 },
    {.str = (char*)"NAME", .len = 4 }
};

text_t g_sys_roles_idx02_cols[] = {
    {.str = (char*)"OWNER_UID", .len = 9 }
};

#define SYS_ROLES_COL_COUNT          (sizeof(g_sys_roles_cols) / sizeof(column_def_t))
#define SYS_ROLES_IDX01_COL_COUNT    (sizeof(g_sys_roles_idx01_cols) / sizeof(text_t))
#define SYS_ROLES_IDX02_COL_COUNT    (sizeof(g_sys_roles_idx02_cols) / sizeof(text_t))

static index_def_t g_sys_roles_indexes[] = {
    { {.str = (char*)"IX_ROLES$_001", .len = 13 }, g_sys_roles_idx01_cols, SYS_ROLES_IDX01_COL_COUNT, GS_TRUE },
    { {.str = (char*)"IX_ROLES$_002", .len = 13 }, g_sys_roles_idx02_cols, SYS_ROLES_IDX02_COL_COUNT, GS_FALSE }
};

// SYS_PROFILE
column_def_t g_sys_profile_cols[] = {
    { {.str = (char*)"NAME",      .len = 4 }, GS_TYPE_VARCHAR,    64,   GS_FALSE },
    { {.str = (char*)"PROFILE#",  .len = 8 }, GS_TYPE_INTEGER,    4,    GS_FALSE },
    { {.str = (char*)"RESOURCE#", .len = 9 }, GS_TYPE_INTEGER,    4,    GS_FALSE },
    { {.str = (char*)"THRESHOLD", .len = 9 }, GS_TYPE_INTEGER,    4,    GS_FALSE },
};

text_t g_sys_profile_idx01_cols[] = {
    {.str = (char*)"PROFILE#",  .len = 8 },
    {.str = (char*)"RESOURCE#", .len = 9 }
};

#define SYS_PROFILE_COL_COUNT          (sizeof(g_sys_profile_cols) / sizeof(column_def_t))
#define SYS_PROFILE_IDX01_COL_COUNT    (sizeof(g_sys_profile_idx01_cols) / sizeof(text_t))

static index_def_t g_sys_profile_indexes[] = {
    { {.str = (char*)"IX_PROFILE$_001", .len = 15 }, g_sys_profile_idx01_cols, SYS_PROFILE_IDX01_COL_COUNT, GS_TRUE }
};

// SYS_USER_HISTORY
column_def_t g_user_history_cols[] = {
    { {.str = (char*)"USER#",         .len = 5  }, GS_TYPE_INTEGER,   4,    GS_FALSE },
    { {.str = (char*)"PASSWORD",      .len = 8  }, GS_TYPE_BINARY,    512,  GS_TRUE  },
    { {.str = (char*)"PASSWORD_DATE", .len = 13 }, GS_TYPE_DATE,      8,    GS_TRUE  }
};

text_t g_user_history_idx01_cols[] = {
    {.str = (char*)"USER#",         .len = 5  },
    {.str = (char*)"PASSWORD_DATE", .len = 13 }
};

#define USER_HISTORY_COL_COUNT          (sizeof(g_user_history_cols) / sizeof(column_def_t))
#define USER_HISTORY_IDX01_COL_COUNT    (sizeof(g_user_history_idx01_cols) / sizeof(text_t))

static index_def_t g_user_history_indexes[] = {{{.str = (char *)"IX_USER_HISTORY$001", .len = 19},
    g_user_history_idx01_cols,
    USER_HISTORY_IDX01_COL_COUNT,
    GS_TRUE}};

// SYS_TENANTS
column_def_t g_sys_tenants_cols[] = {
    { {.str = (char*)"TENANT_ID",    .len = 9  }, GS_TYPE_INTEGER,   4,    GS_FALSE },
    { {.str = (char*)"NAME",         .len = 4  }, GS_TYPE_VARCHAR,   32,   GS_FALSE },
    { {.str = (char*)"DATA_SPACE#",  .len = 11 }, GS_TYPE_INTEGER,   4,    GS_FALSE },
    { {.str = (char*)"SPACE_NUM",    .len = 9  }, GS_TYPE_INTEGER,   4,    GS_FALSE },
    { {.str = (char*)"SPACE_BITMAP", .len = 12 }, GS_TYPE_RAW,       256,  GS_FALSE },
    { {.str = (char*)"CTIME",        .len = 5  }, GS_TYPE_DATE,      8,    GS_FALSE },
    { {.str = (char*)"OPTIONS",      .len = 7  }, GS_TYPE_RAW,       128,  GS_TRUE  }
};

text_t g_sys_tenants_idx01_cols[] = {
    {.str = (char*)"TENANT_ID", .len = 9 },
};

text_t g_sys_tenants_idx02_cols[] = {
    {.str = (char*)"NAME", .len = 4 }
};

#define SYS_TENANTS_COL_COUNT          (sizeof(g_sys_tenants_cols) / sizeof(column_def_t))
#define SYS_TENANTS_IDX01_COL_COUNT    (sizeof(g_sys_tenants_idx01_cols) / sizeof(text_t))
#define SYS_TENANTS_IDX02_COL_COUNT    (sizeof(g_sys_tenants_idx02_cols) / sizeof(text_t))

static index_def_t g_sys_tenants_indexes[] = {
    {{.str = (char *)"IDX_SYS_TENANT_001", .len = 18}, g_sys_tenants_idx01_cols, SYS_TENANTS_IDX01_COL_COUNT, GS_TRUE},
    {{.str = (char *)"IDX_SYS_TENANT_002", .len = 18}, g_sys_tenants_idx02_cols, SYS_TENANTS_IDX02_COL_COUNT, GS_TRUE}};

// SYS_VIEWS
column_def_t g_sys_views_cols[] = {
    { {.str = (char*)"USER#",       .len = 5 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"ID",          .len = 2 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"NAME",        .len = 4 }, GS_TYPE_VARCHAR,   64,    GS_FALSE },
    { {.str = (char*)"COLS",        .len = 4 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"FLAGS",       .len = 5 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"ORG_SCN",     .len = 7 }, GS_TYPE_BIGINT,    8,     GS_TRUE  },
    { {.str = (char*)"CHG_SCN",     .len = 7 }, GS_TYPE_BIGINT,    8,     GS_TRUE  },
    { {.str = (char*)"TEXT_LENGTH", .len = 11}, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"TEXT",        .len = 4 }, GS_TYPE_CLOB,      8000,  GS_FALSE },
    { {.str = (char*)"SQL_TYPE",    .len = 8 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"OBJ#",        .len = 4 }, GS_TYPE_INTEGER,   4,     GS_FALSE }
};

text_t g_sys_views_idx01_cols[] = {
    {.str = (char*)"USER#", .len = 5 },
    {.str = (char*)"NAME",  .len = 4 },
};

text_t g_sys_views_idx02_cols[] = {
    {.str = (char*)"USER#", .len = 5 },
    {.str = (char*)"ID",    .len = 2 },
};

#define SYS_VIEWS_COL_COUNT          (sizeof(g_sys_views_cols) / sizeof(column_def_t))
#define SYS_VIEWS_IDX01_COL_COUNT    (sizeof(g_sys_views_idx01_cols) / sizeof(text_t))
#define SYS_VIEWS_IDX02_COL_COUNT    (sizeof(g_sys_views_idx02_cols) / sizeof(text_t))

static index_def_t g_sys_views_indexes[] = {
    { {.str = (char*)"IX_VIEW$001", .len = 11 }, g_sys_views_idx01_cols, SYS_VIEWS_IDX01_COL_COUNT, GS_TRUE },
    { {.str = (char*)"IX_VIEW$002", .len = 11 }, g_sys_views_idx02_cols, SYS_VIEWS_IDX02_COL_COUNT, GS_TRUE }
};

// SYS_SYNONYMS
column_def_t g_sys_synonyms_cols[] = {
    { {.str = (char*)"USER#",        .len = 5 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"ID",           .len = 2 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"ORG_SCN",      .len = 7 }, GS_TYPE_BIGINT,    8,     GS_TRUE  },
    { {.str = (char*)"CHG_SCN",      .len = 7 }, GS_TYPE_BIGINT,    8,     GS_TRUE  },
    { {.str = (char*)"SYNONYM_NAME", .len = 12}, GS_TYPE_VARCHAR,   64,    GS_FALSE },
    { {.str = (char*)"TABLE_OWNER",  .len = 11}, GS_TYPE_VARCHAR,   64,    GS_FALSE },
    { {.str = (char*)"TABLE_NAME",   .len = 10}, GS_TYPE_VARCHAR,   64,    GS_FALSE },
    { {.str = (char*)"FLAGS",        .len = 5 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"TYPE",         .len = 4 }, GS_TYPE_INTEGER,   4,     GS_FALSE }
};

text_t g_sys_synonyms_idx01_cols[] = {
    {.str = (char*)"USER#",        .len = 5 },
    {.str = (char*)"SYNONYM_NAME", .len = 12 },
};

text_t g_sys_synonyms_idx02_cols[] = {
    {.str = (char*)"USER#", .len = 5 },
    {.str = (char*)"ID",    .len = 2 },
};

#define SYS_SYNONYMS_COL_COUNT          (sizeof(g_sys_synonyms_cols) / sizeof(column_def_t))
#define SYS_SYNONYMS_IDX01_COL_COUNT    (sizeof(g_sys_synonyms_idx01_cols) / sizeof(text_t))
#define SYS_SYNONYMS_IDX02_COL_COUNT    (sizeof(g_sys_synonyms_idx02_cols) / sizeof(text_t))

static index_def_t g_sys_synonyms_indexes[] = {
    { {.str = (char*)"IX_SYNONYM$001", .len = 14 }, g_sys_synonyms_idx01_cols, SYS_SYNONYMS_IDX01_COL_COUNT, GS_TRUE },
    { {.str = (char*)"IX_SYNONYM$002", .len = 14 }, g_sys_synonyms_idx02_cols, SYS_SYNONYMS_IDX02_COL_COUNT, GS_FALSE }
};

// SYS_USER_ROLES
column_def_t g_user_roles_cols[] = {
    { {.str = (char*)"GRANTEE_ID",      .len = 10 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"GRANTEE_TYPE",    .len = 12 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"GRANTED_ROLE_ID", .len = 15 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"ADMIN_OPTION",    .len = 12 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"DEFAULT_ROLE",    .len = 12 }, GS_TYPE_INTEGER,   4,     GS_TRUE  }
};

text_t g_user_roles_idx01_cols[] = {
    {.str = (char*)"GRANTEE_ID",      .len = 10 },
    {.str = (char*)"GRANTEE_TYPE",    .len = 12 },
    {.str = (char*)"GRANTED_ROLE_ID", .len = 15 }
};

text_t g_user_roles_idx02_cols[] = {
    {.str = (char*)"GRANTED_ROLE_ID", .len = 15 }
};

#define USER_ROLES_COL_COUNT          (sizeof(g_user_roles_cols) / sizeof(column_def_t))
#define USER_ROLES_IDX01_COL_COUNT    (sizeof(g_user_roles_idx01_cols) / sizeof(text_t))
#define USER_ROLES_IDX02_COL_COUNT    (sizeof(g_user_roles_idx02_cols) / sizeof(text_t))

static index_def_t g_user_roles_indexes[] = {
    { {.str = (char*)"IX_USER_ROLES$_001", .len = 18 }, g_user_roles_idx01_cols, USER_ROLES_IDX01_COL_COUNT, GS_TRUE },
    { {.str = (char*)"IX_USER_ROLES$_002", .len = 18 }, g_user_roles_idx02_cols, USER_ROLES_IDX02_COL_COUNT, GS_FALSE }
};

// SYS_OBJECT_PRIVS
column_def_t g_object_privs_cols[] = {
    { {.str = (char*)"GRANTEE",      .len = 7 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"GRANTEE_TYPE", .len = 12}, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"OBJECT_OWNER", .len = 12}, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"OBJECT_NAME",  .len = 11}, GS_TYPE_VARCHAR,   64,    GS_FALSE },
    { {.str = (char*)"OBJECT_TYPE",  .len = 11}, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"PRIVILEGE",    .len = 9 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"GRANTABLE",    .len = 9 }, GS_TYPE_INTEGER,   4,     GS_FALSE },
    { {.str = (char*)"GRANTOR",      .len = 7 }, GS_TYPE_INTEGER,   4,     GS_FALSE }
};

text_t g_object_privs_idx01_cols[] = {
    {.str = (char*)"GRANTEE",      .len = 7  },
    {.str = (char*)"GRANTEE_TYPE", .len = 12 },
    {.str = (char*)"OBJECT_OWNER", .len = 12 },
    {.str = (char*)"OBJECT_NAME",  .len = 11 },
    {.str = (char*)"OBJECT_TYPE",  .len = 11 },
    {.str = (char*)"PRIVILEGE",    .len = 9  }
};

text_t g_object_privs_idx02_cols[] = {
    {.str = (char*)"OBJECT_OWNER", .len = 12 },
    {.str = (char*)"OBJECT_NAME",  .len = 11 },
    {.str = (char*)"OBJECT_TYPE",  .len = 11 }
};

text_t g_object_privs_idx03_cols[] = {
    {.str = (char*)"GRANTOR",      .len = 7  },
    {.str = (char*)"OBJECT_OWNER", .len = 12 },
    {.str = (char*)"OBJECT_NAME",  .len = 11 },
    {.str = (char*)"OBJECT_TYPE",  .len = 11 },
    {.str = (char*)"PRIVILEGE",    .len = 9  },
};

#define OBJECT_PRIVS_COL_COUNT          (sizeof(g_object_privs_cols) / sizeof(column_def_t))
#define OBJECT_PRIVS_IDX01_COL_COUNT    (sizeof(g_object_privs_idx01_cols) / sizeof(text_t))
#define OBJECT_PRIVS_IDX02_COL_COUNT    (sizeof(g_object_privs_idx02_cols) / sizeof(text_t))
#define OBJECT_PRIVS_IDX03_COL_COUNT    (sizeof(g_object_privs_idx03_cols) / sizeof(text_t))

static index_def_t g_object_privs_indexes[] = {
    {{.str = (char *)"IX_OBJECT_PRIVS$_001", .len = 18},
        g_object_privs_idx01_cols,
        OBJECT_PRIVS_IDX01_COL_COUNT,
        GS_TRUE},
    {{.str = (char *)"IX_OBJECT_PRIVS$_002", .len = 18},
        g_object_privs_idx02_cols,
        OBJECT_PRIVS_IDX02_COL_COUNT,
        GS_FALSE},
    {{.str = (char *)"IX_OBJECT_PRIVS$_004", .len = 18},
        g_object_privs_idx03_cols,
        OBJECT_PRIVS_IDX03_COL_COUNT,
        GS_FALSE}};

// SYS_DISTRIBUTE_RULES
column_def_t g_distribute_rules_cols[] = {
    { {.str = (char*)"UID",          .len = 3 }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"ID",           .len = 2 }, GS_TYPE_INTEGER,   4,      GS_FALSE },
    { {.str = (char*)"DIST_DATA",    .len = 9 }, GS_TYPE_VARCHAR,   1024,   GS_FALSE },
    { {.str = (char*)"BUCKETS",      .len = 7 }, GS_TYPE_BLOB,      8000,   GS_TRUE  },
    { {.str = (char*)"NAME",         .len = 4 }, GS_TYPE_VARCHAR,   64,     GS_FALSE },
    { {.str = (char*)"ORG_SCN",      .len = 7 }, GS_TYPE_BIGINT,    8,      GS_TRUE  },
    { {.str = (char*)"CHG_SCN",      .len = 7 }, GS_TYPE_BIGINT,    8,      GS_TRUE  },
    { {.str = (char*)"COLUMNS",      .len = 7 }, GS_TYPE_VARCHAR,   1024,   GS_TRUE  },
    { {.str = (char*)"COLUMN_COUNT", .len = 12}, GS_TYPE_INTEGER,   4,      GS_FALSE }
};

text_t g_distribute_rules_idx01_cols[] = {
    {.str = (char*)"NAME", .len = 4 }
};

text_t g_distribute_rules_idx02_cols[] = {
    {.str = (char*)"ID", .len = 2 }
};

text_t g_distribute_rules_idx03_cols[] = {
    {.str = (char*)"UID", .len = 3 }
};

#define DISTRIBUTE_RULES_COL_COUNT          (sizeof(g_distribute_rules_cols) / sizeof(column_def_t))
#define DISTRIBUTE_RULES_IDX01_COL_COUNT    (sizeof(g_distribute_rules_idx01_cols) / sizeof(text_t))
#define DISTRIBUTE_RULES_IDX02_COL_COUNT    (sizeof(g_distribute_rules_idx02_cols) / sizeof(text_t))
#define DISTRIBUTE_RULES_IDX03_COL_COUNT    (sizeof(g_distribute_rules_idx03_cols) / sizeof(text_t))

static index_def_t g_distribute_rules_indexes[] = {
    {{.str = (char *)"IX_DISTRIBUTE_RULE$001", .len = 22},
        g_distribute_rules_idx01_cols,
        DISTRIBUTE_RULES_IDX01_COL_COUNT,
        GS_FALSE},
    {{.str = (char *)"IX_DISTRIBUTE_RULE$002", .len = 22},
        g_distribute_rules_idx02_cols,
        DISTRIBUTE_RULES_IDX02_COL_COUNT,
        GS_FALSE},
    {{.str = (char *)"IX_DISTRIBUTE_RULE$003", .len = 22},
        g_distribute_rules_idx03_cols,
        DISTRIBUTE_RULES_IDX03_COL_COUNT,
        GS_FALSE}};

// SYS_LINKS
column_def_t g_sys_links_cols[] = {
    { {.str = (char*)"OWNER#",   .len = 6 }, GS_TYPE_INTEGER,    4,        GS_FALSE },
    { {.str = (char*)"NAME",     .len = 4 }, GS_TYPE_VARCHAR,    128,      GS_FALSE },
    { {.str = (char*)"CTIME",    .len = 5 }, GS_TYPE_DATE,       8,        GS_FALSE },
    { {.str = (char*)"NODE_ID",  .len = 7 }, GS_TYPE_INTEGER,    4,        GS_FALSE },
    { {.str = (char*)"HOST",     .len = 4 }, GS_TYPE_VARCHAR,    2000,     GS_TRUE  },
    { {.str = (char*)"USERID",   .len = 6 }, GS_TYPE_VARCHAR,    64,       GS_TRUE  },
    { {.str = (char*)"PASSWORD", .len = 8 }, GS_TYPE_VARCHAR,    512,      GS_TRUE  }
};

text_t g_sys_links_idx01_cols[] = {
    {.str = (char*)"OWNER#", .len = 6 },
    {.str = (char*)"NAME",   .len = 4 }
};

#define SYS_LINKS_COL_COUNT          (sizeof(g_sys_links_cols) / sizeof(column_def_t))
#define SYS_LINKS_IDX01_COL_COUNT    (sizeof(g_sys_links_idx01_cols) / sizeof(text_t))

static index_def_t g_sys_links_indexes[] = {
    { {.str = (char*)"IX_LINK$001", .len = 11 }, g_sys_links_idx01_cols, SYS_LINKS_IDX01_COL_COUNT, GS_TRUE }
};

// SYS_USER_PRIVS
column_def_t g_user_privs_cols[] = {
    { {.str = (char*)"UID",       .len = 3 }, GS_TYPE_INTEGER,    4,      GS_FALSE },
    { {.str = (char*)"GRANTOR",   .len = 7 }, GS_TYPE_INTEGER,    4,      GS_FALSE },
    { {.str = (char*)"GRANTEE",   .len = 7 }, GS_TYPE_INTEGER,    4,      GS_FALSE },
    { {.str = (char*)"PRIVILEGE", .len = 9 }, GS_TYPE_INTEGER,    4,      GS_FALSE },
    { {.str = (char*)"OPTION",    .len = 6 }, GS_TYPE_INTEGER,    4,      GS_TRUE  }
};

text_t g_user_privs_idx01_cols[] = {
    {.str = (char*)"UID",       .len = 3 },
    {.str = (char*)"GRANTEE",   .len = 7 },
    {.str = (char*)"PRIVILEGE", .len = 9 }
};

#define USER_PRIVS_COL_COUNT          (sizeof(g_user_privs_cols) / sizeof(column_def_t))
#define USER_PRIVS_IDX01_COL_COUNT    (sizeof(g_user_privs_idx01_cols) / sizeof(text_t))

static index_def_t g_user_privs_indexes[] = {
    { {.str = (char*)"IX_USER_PRIVS$_001", .len = 18 }, g_user_privs_idx01_cols, USER_PRIVS_IDX01_COL_COUNT, GS_TRUE }
};

// SYS_RECYCLEBIN
column_def_t g_recyclebin_cols[] = {
    { {.str = (char*)"ID",             .len = 2  }, GS_TYPE_BIGINT,     8,       GS_FALSE },
    { {.str = (char*)"NAME",           .len = 4  }, GS_TYPE_VARCHAR,    30,      GS_FALSE },
    { {.str = (char*)"USER#",          .len = 5  }, GS_TYPE_INTEGER,    4,       GS_FALSE },
    { {.str = (char*)"ORG_NAME",       .len = 8  }, GS_TYPE_VARCHAR,    64,      GS_FALSE },
    { {.str = (char*)"PARTITION_NAME", .len = 14 }, GS_TYPE_VARCHAR,    64,      GS_TRUE  },
    { {.str = (char*)"TYPE# ",         .len = 5  }, GS_TYPE_INTEGER,    4,       GS_FALSE },
    { {.str = (char*)"OPERATION#",     .len = 10 }, GS_TYPE_INTEGER,    4,       GS_FALSE },
    { {.str = (char*)"SPACE#",         .len = 6  }, GS_TYPE_INTEGER,    4,       GS_FALSE },
    { {.str = (char*)"ENTRY",          .len = 5  }, GS_TYPE_BIGINT,     8,       GS_TRUE  },
    { {.str = (char*)"FLAGS",          .len = 5  }, GS_TYPE_INTEGER,    4,       GS_FALSE },
    { {.str = (char*)"ORG_SCN",        .len = 7  }, GS_TYPE_BIGINT,     8,       GS_FALSE },
    { {.str = (char*)"REC_SCN",        .len = 7  }, GS_TYPE_BIGINT,     8,       GS_FALSE },
    { {.str = (char*)"TCHG_SCN",       .len = 8  }, GS_TYPE_BIGINT,     8,       GS_TRUE  },
    { {.str = (char*)"BASE_ID",        .len = 7  }, GS_TYPE_BIGINT,     8,       GS_FALSE },
    { {.str = (char*)"PURGE_ID",       .len = 8  }, GS_TYPE_BIGINT,     8,       GS_FALSE },
};

text_t g_recyclebin_idx01_cols[] = {
    {.str = (char*)"ID", .len = 3 }
};

text_t g_recyclebin_idx02_cols[] = {
    {.str = (char*)"BASE_ID",  .len = 7 },
    {.str = (char*)"PURGE_ID", .len = 8 }
};

text_t g_recyclebin_idx03_cols[] = {
    {.str = (char*)"SPACE#", .len = 6 }
};

text_t g_recyclebin_idx04_cols[] = {
    {.str = (char*)"USER#", .len = 5 }
};
#define RECYCLEBIN_COL_COUNT          (sizeof(g_recyclebin_cols) / sizeof(column_def_t))
#define RECYCLEBIN_IDX01_COL_COUNT    (sizeof(g_recyclebin_idx01_cols) / sizeof(text_t))
#define RECYCLEBIN_IDX02_COL_COUNT    (sizeof(g_recyclebin_idx02_cols) / sizeof(text_t))
#define RECYCLEBIN_IDX03_COL_COUNT    (sizeof(g_recyclebin_idx03_cols) / sizeof(text_t))
#define RECYCLEBIN_IDX04_COL_COUNT    (sizeof(g_recyclebin_idx04_cols) / sizeof(text_t))

static index_def_t g_recyclebin_indexes[] = {
    { {.str = (char*)"IX_RB$001", .len = 9 }, g_recyclebin_idx01_cols, RECYCLEBIN_IDX01_COL_COUNT, GS_TRUE  },
    { {.str = (char*)"IX_RB$002", .len = 9 }, g_recyclebin_idx02_cols, RECYCLEBIN_IDX02_COL_COUNT, GS_FALSE },
    { {.str = (char*)"IX_RB$003", .len = 9 }, g_recyclebin_idx03_cols, RECYCLEBIN_IDX03_COL_COUNT, GS_FALSE },
    { {.str = (char*)"IX_RB$004", .len = 9 }, g_recyclebin_idx04_cols, RECYCLEBIN_IDX04_COL_COUNT, GS_FALSE }
};

// SYS_BACKUP_SETS
column_def_t g_backup_set_cols[] = {
    { {.str = (char*)"RECID",             .len = 5  }, GS_TYPE_BIGINT,      8,       GS_FALSE },
    { {.str = (char*)"TYPE",              .len = 4  }, GS_TYPE_INTEGER,     4,       GS_FALSE },
    { {.str = (char*)"STAGE",             .len = 5  }, GS_TYPE_INTEGER,     4,       GS_FALSE },
    { {.str = (char*)"STATUS",            .len = 6  }, GS_TYPE_INTEGER,     4,       GS_FALSE },
    { {.str = (char*)"INCREMENTAL_LEVEL", .len = 17 }, GS_TYPE_INTEGER,     4,       GS_FALSE },
    { {.str = (char*)"TAG ",              .len = 3  }, GS_TYPE_VARCHAR,     64,      GS_FALSE },
    { {.str = (char*)"SCN",               .len = 3  }, GS_TYPE_BIGINT,      8,       GS_FALSE },
    { {.str = (char*)"LSN",               .len = 3  }, GS_TYPE_BIGINT,      8,       GS_FALSE },
    { {.str = (char*)"DEVICE_TYPE",       .len = 11 }, GS_TYPE_INTEGER,     4,       GS_FALSE },
    { {.str = (char*)"BASE_TAG",          .len = 8  }, GS_TYPE_VARCHAR,     64,      GS_FALSE },
    { {.str = (char*)"DIR",               .len = 3  }, GS_TYPE_VARCHAR,     256,     GS_FALSE },
    { {.str = (char*)"RESETLOGS",         .len = 9  }, GS_TYPE_INTEGER,     4,       GS_FALSE },
    { {.str = (char*)"POLICY",            .len = 6  }, GS_TYPE_VARCHAR,     128,     GS_FALSE },
    { {.str = (char*)"RCY_ASN",           .len = 7  }, GS_TYPE_INTEGER,     4,       GS_FALSE },
    { {.str = (char*)"RCY_OFFSET",        .len = 10 }, GS_TYPE_BIGINT,      8,       GS_FALSE },
    { {.str = (char*)"RCY_LFN",           .len = 7  }, GS_TYPE_BIGINT,      8,       GS_FALSE },
    { {.str = (char*)"LRP_ASN",           .len = 7  }, GS_TYPE_INTEGER,     4,       GS_FALSE },
    { {.str = (char*)"LRP_OFFSET",        .len = 10 }, GS_TYPE_BIGINT,      8,       GS_FALSE },
    { {.str = (char*)"LRP_LFN",           .len = 7  }, GS_TYPE_BIGINT,      8,       GS_FALSE },
    { {.str = (char*)"START_TIME",        .len = 10 }, GS_TYPE_TIMESTAMP,   8,       GS_FALSE },
    { {.str = (char*)"COMPLETION_TIME",   .len = 15 }, GS_TYPE_TIMESTAMP,   8,       GS_FALSE },
};

text_t g_backup_set_idx01_cols[] = {
    {.str = (char*)"RECID", .len = 5 }
};

text_t g_backup_set_idx02_cols[] = {
    {.str = (char*)"TAG", .len = 3 }
};

#define BACKUP_SET_COL_COUNT          (sizeof(g_backup_set_cols) / sizeof(column_def_t))
#define BACKUP_SET_IDX01_COL_COUNT    (sizeof(g_backup_set_idx01_cols) / sizeof(text_t))
#define BACKUP_SET_IDX02_COL_COUNT    (sizeof(g_backup_set_idx02_cols) / sizeof(text_t))

static index_def_t g_backup_set_indexes[] = {
    { {.str = (char*)"IX_BACKUP_SET$001", .len = 17 }, g_backup_set_idx01_cols, BACKUP_SET_IDX01_COL_COUNT, GS_TRUE },
    { {.str = (char*)"IX_BACKUP_SET$002", .len = 17 }, g_backup_set_idx02_cols, BACKUP_SET_IDX02_COL_COUNT, GS_TRUE },
};

// SYS_HISTGRAM_ABSTR
column_def_t g_histgram_abstr_cols[] = {
    { {.str = (char*)"USER#",        .len = 5  }, GS_TYPE_INTEGER,     4,       GS_TRUE },
    { {.str = (char*)"TAB#",         .len = 4  }, GS_TYPE_INTEGER,     4,       GS_TRUE },
    { {.str = (char*)"COL#",         .len = 4  }, GS_TYPE_INTEGER,     4,       GS_TRUE },
    { {.str = (char*)"BUCKET_NUM",   .len = 10 }, GS_TYPE_INTEGER,     4,       GS_TRUE },
    { {.str = (char*)"ROW_NUM",      .len = 7  }, GS_TYPE_INTEGER,     4,       GS_TRUE },
    { {.str = (char*)"NULL_NUM ",    .len = 8  }, GS_TYPE_INTEGER,     4,       GS_TRUE },
    { {.str = (char*)"ANALYZE_TIME", .len = 12 }, GS_TYPE_DATE,        8,       GS_TRUE },
    { {.str = (char*)"MINVALUE",     .len = 8  }, GS_TYPE_VARCHAR,     4000,    GS_TRUE },
    { {.str = (char*)"MAXVALUE",     .len = 8  }, GS_TYPE_VARCHAR,     4000,    GS_TRUE },
    { {.str = (char*)"DIST_NUM",     .len = 8  }, GS_TYPE_INTEGER,     4,       GS_TRUE },
    { {.str = (char*)"DENSITY",      .len = 7  }, GS_TYPE_REAL,        8,       GS_TRUE },
    { {.str = (char*)"SPARE1",       .len = 6  }, GS_TYPE_BIGINT,      8,       GS_TRUE },
    { {.str = (char*)"SPARE2",       .len = 6  }, GS_TYPE_BIGINT,      8,       GS_TRUE },
    { {.str = (char*)"SPARE3",       .len = 6  }, GS_TYPE_BIGINT,      8,       GS_TRUE },
    { {.str = (char*)"SPARE4",       .len = 6  }, GS_TYPE_BIGINT,      8,       GS_TRUE },
};

text_t g_histgram_abstr_idx01_cols[] = {
    {.str = (char*)"ANALYZE_TIME", .len = 12 }
};

text_t g_histgram_abstr_idx02_cols[] = {
    {.str = (char*)"USER#",  .len = 5 },
    {.str = (char*)"TAB#",   .len = 4 },
    {.str = (char*)"COL#",   .len = 4 },
    {.str = (char*)"SPARE1", .len = 6 },
    {.str = (char*)"SPARE2", .len = 6 }
};

#define HISTGRAM_ABSTR_COL_COUNT          (sizeof(g_histgram_abstr_cols) / sizeof(column_def_t))
#define HISTGRAM_ABSTR_IDX01_COL_COUNT    (sizeof(g_histgram_abstr_idx01_cols) / sizeof(text_t))
#define HISTGRAM_ABSTR_IDX02_COL_COUNT    (sizeof(g_histgram_abstr_idx02_cols) / sizeof(text_t))

static index_def_t g_histgram_abstr_indexes[] = {
    {{.str = (char *)"IX_HIST_HEAD_002", .len = 16},
        g_histgram_abstr_idx01_cols,
        HISTGRAM_ABSTR_IDX01_COL_COUNT,
        GS_FALSE},
    {{.str = (char *)"IX_HIST_HEAD_003", .len = 16},
        g_histgram_abstr_idx02_cols,
        HISTGRAM_ABSTR_IDX02_COL_COUNT,
        GS_TRUE},
};

/************************************table define end*************************************/
status_t knl_open_sys_database(knl_session_t *session)
{
    knl_alterdb_def_t def;
    MEMS_RETURN_IFERR(memset_s(&def, sizeof(knl_alterdb_def_t), 0, sizeof(knl_alterdb_def_t)));
    def.action = STARTUP_DATABASE_OPEN;
    return knl_alter_database(session, &def);
}

static status_t build_space_datafile(knl_session_t *session, char *home,
    galist_t *list, char *name, uint32 count, int64 size, bool32 autoextend)
{
    knl_device_def_t *dev_def = NULL;
    for (uint32 i = 1; i <= count; i++) {
        GS_RETURN_IFERR(cm_galist_new(list, sizeof(knl_device_def_t), (pointer_t *)&dev_def));
        dev_def->name.str = cm_push(session->stack, GS_FILE_NAME_BUFFER_SIZE);
        if (dev_def->name.str == NULL) {
            return GS_ERROR;
        }
        if (count > 1) {
            PRTS_RETURN_IFERR(snprintf_s(dev_def->name.str, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                "%s/data/%s%u", home, name, i));
        } else {
            PRTS_RETURN_IFERR(snprintf_s(dev_def->name.str, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
                "%s/data/%s", home, name));
        }
        dev_def->name.len = (uint32)strlen(dev_def->name.str);
        dev_def->size = size;
        dev_def->autoextend.enabled = autoextend;
        if (dev_def->autoextend.enabled) {
            dev_def->autoextend.nextsize = SIZE_M(16);
        }
    }
    return GS_SUCCESS;
}

static inline status_t build_ctrlfile(knl_session_t *session, char *home, galist_t *list)
{
    text_t *ctrl_file = NULL;
    for (uint32 i = 1; i <= DEFAULT_CTRL_FILE; i++) {
        GS_RETURN_IFERR(cm_galist_new(list, sizeof(text_t), (pointer_t *)&ctrl_file));
        ctrl_file->str = cm_push(session->stack, GS_FILE_NAME_BUFFER_SIZE);
        if (ctrl_file->str == NULL) {
            return GS_ERROR;
        }
        PRTS_RETURN_IFERR(snprintf_s(ctrl_file->str, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
            "%s/data/ctrl%u", home, i));
        ctrl_file->len = (uint32)strlen(ctrl_file->str);
    }
    return GS_SUCCESS;
}

static status_t build_create_database_def(knl_session_t *session, char *home, knl_database_def_t *def)
{
    int64 space_size = (int64)g_instance->attr.space_size;

    MEMS_RETURN_IFERR(memset_s(def, sizeof(knl_database_def_t), 0, sizeof(knl_database_def_t)));
    cm_galist_init(&def->ctrlfiles, session->stack, cm_stack_alloc);
    cm_galist_init(&def->logfiles, session->stack, cm_stack_alloc);
    cm_galist_init(&def->undo_space.datafiles, session->stack, cm_stack_alloc);
    cm_galist_init(&def->system_space.datafiles, session->stack, cm_stack_alloc);
    cm_galist_init(&def->swap_space.datafiles, session->stack, cm_stack_alloc);
    cm_galist_init(&def->user_space.datafiles, session->stack, cm_stack_alloc);
    cm_galist_init(&def->temp_space.datafiles, session->stack, cm_stack_alloc);
    cm_galist_init(&def->temp_undo_space.datafiles, session->stack, cm_stack_alloc);
    cm_galist_init(&def->sysaux_space.datafiles, session->stack, cm_stack_alloc);

    def->name = g_db;
    def->system_space.name = g_system;
    def->system_space.type = SPACE_TYPE_SYSTEM | SPACE_TYPE_DEFAULT;
    def->undo_space.name = g_undo;
    def->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT;
    def->swap_space.name = g_swap;
    def->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT;
    def->user_space.name = g_users;
    def->user_space.type = SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    def->temp_space.name = g_temp;
    def->temp_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_USERS | SPACE_TYPE_DEFAULT;
    def->temp_undo_space.name = g_temp_undo;
    def->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_TEMP | SPACE_TYPE_DEFAULT;
    def->sysaux_space.name = g_sysaux;
    def->sysaux_space.type = SPACE_TYPE_SYSAUX | SPACE_TYPE_DEFAULT;

    // ctrl file
    GS_RETURN_IFERR(build_ctrlfile(session, home, &def->ctrlfiles));
    // log file
    GS_RETURN_IFERR(
        build_space_datafile(session, home, &def->logfiles, "redo", DEFAULT_LOG_FILE, space_size, GS_FALSE));
    // SYSTEM
    GS_RETURN_IFERR(
        build_space_datafile(session, home, &def->system_space.datafiles, "system", 1, space_size, GS_TRUE));
    // UNDO
    GS_RETURN_IFERR(build_space_datafile(session, home, &def->undo_space.datafiles, "undo", 1, space_size, GS_TRUE));
    // DEFAULT
    GS_RETURN_IFERR(build_space_datafile(
        session, home, &def->user_space.datafiles, "user", DEFAULT_USER_FILE, space_size, GS_TRUE));
    // TEMPORARY
    GS_RETURN_IFERR(build_space_datafile(
        session, home, &def->swap_space.datafiles, "swap", DEFAULT_SWAP_FILE, space_size, GS_TRUE));
    // SYSAUX
    GS_RETURN_IFERR(
        build_space_datafile(session, home, &def->sysaux_space.datafiles, "sysaux", 1, space_size, GS_FALSE));
    def->arch_mode = ARCHIVE_LOG_ON;
    return GS_SUCCESS;
}

status_t knl_create_sys_database(knl_session_t *knl_session, char *home)
{
    knl_database_def_t def;

    CM_SAVE_STACK(knl_session->stack);
    if (build_create_database_def(knl_session, home, &def) != GS_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }
    if (knl_create_database(knl_session, &def) != GS_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return GS_ERROR;
    }
    CM_RESTORE_STACK(knl_session->stack);
    return GS_SUCCESS;
}

static status_t build_index_def(
    knl_session_t *session, const table_def_t *table_def, const index_def_t *index_def, knl_index_def_t *def)
{
    knl_index_col_def_t *column = NULL;

    def->user   = g_user;
    def->name   = index_def->name;
    def->table  = table_def->name;
    def->space  = *table_def->space;
    def->unique = index_def->is_unique;
    def->cr_mode = CR_PAGE;
    def->options |= CREATE_IF_NOT_EXISTS;

    cm_galist_init(&def->columns, session->stack, cm_stack_alloc);
    for (uint32 i = 0; i < index_def->col_count; i++) {
        GS_RETURN_IFERR(cm_galist_new(&def->columns, sizeof(knl_index_col_def_t), (void **)&column));
        MEMS_RETURN_IFERR(memset_s(column, sizeof(knl_index_col_def_t), 0, sizeof(knl_index_col_def_t)));
        column->name = index_def->cols[i];
        column->mode = SORT_MODE_ASC;
    }
    return GS_SUCCESS;
}

static status_t knl_create_sys_index(knl_session_t *session, table_def_t *table_def, index_def_t *index_def)
{
    knl_index_def_t def;
    MEMS_RETURN_IFERR(memset_s(&def, sizeof(knl_index_def_t), 0, sizeof(knl_index_def_t)));

    CM_SAVE_STACK(session->stack);
    if (build_index_def(session, table_def, index_def, &def) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    status_t status = knl_create_index(session, &def);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t build_table_def(knl_session_t *session, table_def_t *table_def, knl_table_def_t *def)
{
    knl_column_def_t *column = NULL;

    def->name   = table_def->name;
    def->sysid  = table_def->sysid;
    def->space  = *table_def->space;
    def->type   = table_def->type;
    def->schema = g_user;
    def->cr_mode = CR_PAGE;
    def->options |= CREATE_IF_NOT_EXISTS;

    cm_galist_init(&def->columns, session->stack, cm_stack_alloc);
    cm_galist_init(&def->constraints, session->stack, cm_stack_alloc);

    for (uint32 i = 0; i < table_def->col_count; i++) {
        GS_RETURN_IFERR(cm_galist_new(&def->columns, sizeof(knl_column_def_t), (pointer_t *)&column));
        MEMS_RETURN_IFERR(memset_s(column, sizeof(knl_column_def_t), 0, sizeof(knl_column_def_t)));
        column->name = table_def->cols[i].name;
        cm_galist_init(&column->ref_columns, session->stack, cm_stack_alloc);
        column->table = (void *)&def;
        column->has_null = GS_TRUE;
        column->primary  = GS_FALSE;
        column->nullable = table_def->cols[i].nullable;
        column->typmod.size = table_def->cols[i].size;
        column->typmod.datatype = table_def->cols[i].type;
    }
    return GS_SUCCESS;
}

static status_t knl_create_sys_table(knl_session_t *session, table_def_t *table_def)
{
    knl_table_def_t def;

    MEMS_RETURN_IFERR(memset_s(&def, sizeof(knl_table_def_t), 0, sizeof(knl_table_def_t)));

    CM_SAVE_STACK(session->stack);
    if (build_table_def(session, table_def, &def) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    status_t status = knl_create_table(session, &def);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t knl_load_sys_def(knl_session_t *session, text_t *table)
{
    knl_alter_sys_def_t def;
    MEMS_RETURN_IFERR(memset_s(&def, sizeof(knl_alter_sys_def_t), 0, sizeof(knl_alter_sys_def_t)));
    def.action = ALSYS_LOAD_DC;
    MEMS_RETURN_IFERR(strncpy_s(def.value, GS_PARAM_BUFFER_SIZE, table->str, table->len));
    MEMS_RETURN_IFERR(strncpy_s(def.param, GS_NAME_BUFFER_SIZE, g_user.str, g_user.len));
    return knl_load_sys_dc(session, &def);
}

static inline status_t knl_create_table_func(knl_session_t *knl_session, table_def_t *table_def)
{
    if (knl_create_sys_table(knl_session, table_def) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < table_def->index_count; i++) {
        GS_RETURN_IFERR(knl_create_sys_index(knl_session, table_def, &table_def->index[i]));
    }
    return knl_load_sys_def(knl_session, &table_def->name);
}

static table_def_t g_sys_tables[] = {
    {{.str = (char *)"SYS_LOBS", .len = 8},
        g_sys_lobs_cols,
        SYS_LOBS_COL_COUNT,
        (text_t *)&g_system,
        SYS_LOB_ID,
        1,
        g_sys_lobs_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_RECYCLEBIN", .len = 14},
        g_recyclebin_cols,
        RECYCLEBIN_COL_COUNT,
        (text_t *)&g_system,
        SYS_RB_ID,
        4,
        g_recyclebin_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_CONSTRAINT_DEFS", .len = 19},
        g_consdef_cols,
        CONSDEF_COL_COUNT,
        (text_t *)&g_system,
        SYS_CONSDEF_ID,
        3,
        g_consdef_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_VIEWS", .len = 9},
        g_sys_views_cols,
        SYS_VIEWS_COL_COUNT,
        (text_t *)&g_system,
        SYS_VIEW_ID,
        2,
        g_sys_views_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_DUMMY", .len = 9},
        g_sys_dummy_cols,
        SYS_DUMMY_COL_COUNT,
        (text_t *)&g_system,
        DUAL_ID,
        0,
        NULL,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_PENDING_TRANS", .len = 17},
        g_pending_trans_cols,
        PENDING_TRANS_COL_COUNT,
        (text_t *)&g_system,
        SYS_PENDING_TRANS_ID,
        0,
        NULL,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_SYNONYMS", .len = 12},
        g_sys_synonyms_cols,
        SYS_SYNONYMS_COL_COUNT,
        (text_t *)&g_system,
        SYS_SYN_ID,
        2,
        g_sys_synonyms_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_PRIVS", .len = 9},
        g_sys_privs_cols,
        SYS_PRIVS_COL_COUNT,
        (text_t *)&g_system,
        SYS_PRIVS_ID,
        1,
        g_sys_privs_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_OBJECT_PRIVS", .len = 16},
        g_object_privs_cols,
        OBJECT_PRIVS_COL_COUNT,
        (text_t *)&g_system,
        OBJECT_PRIVS_ID,
        3,
        g_object_privs_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_USER_ROLES", .len = 14},
        g_user_roles_cols,
        USER_ROLES_COL_COUNT,
        (text_t *)&g_system,
        SYS_USER_ROLES_ID,
        2,
        g_user_roles_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_ROLES", .len = 9},
        g_sys_roles_cols,
        SYS_ROLES_COL_COUNT,
        (text_t *)&g_system,
        SYS_ROLES_ID,
        2,
        g_sys_roles_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_TABLE_PARTS", .len = 15},
        g_table_parts_cols,
        TABLE_PARTS_COL_COUNT,
        (text_t *)&g_system,
        SYS_TABLEPART_ID,
        1,
        g_table_parts_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_SHADOW_INDEXES", .len = 18},
        g_shadow_indexes_cols,
        SHADOW_INDEXES_COL_COUNT,
        (text_t *)&g_system,
        SYS_SHADOW_INDEX_ID,
        1,
        g_shadow_indexes_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_PROFILE", .len = 11},
        g_sys_profile_cols,
        SYS_PROFILE_COL_COUNT,
        (text_t *)&g_system,
        SYS_PROFILE_ID,
        1,
        g_sys_profile_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_SHADOW_INDEX_PARTS", .len = 22},
        g_shw_indexpart_cols,
        SHW_INDEXPART_COL_COUNT,
        (text_t *)&g_system,
        SYS_SHADOW_INDEXPART_ID,
        1,
        g_shw_indexpart_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_BACKUP_SETS", .len = 15},
        g_backup_set_cols,
        BACKUP_SET_COL_COUNT,
        (text_t *)&g_system,
        SYS_BACKUP_SET_ID,
        2,
        g_backup_set_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_DISTRIBUTE_STRATEGIES", .len = 25},
        g_distribute_strategy_cols,
        DISTRIBUTE_STRATEGY_COL_COUNT,
        (text_t *)&g_system,
        SYS_DISTRIBUTE_STRATEGY_ID,
        1,
        g_distribute_strategy_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_GARBAGE_SEGMENTS", .len = 20},
        g_garbage_segments_cols,
        GARBAGE_SEGMENTS_COL_COUNT,
        (text_t *)&g_system,
        SYS_GARBAGE_SEGMENT_ID,
        1,
        g_garbage_segment_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_USER_HISTORY", .len = 16},
        g_user_history_cols,
        USER_HISTORY_COL_COUNT,
        (text_t *)&g_system,
        SYS_USER_HISTORY_ID,
        1,
        g_user_history_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_DML_STATS", .len = 13},
        g_sys_dml_stats_cols,
        SYS_DML_STATS_COL_COUNT,
        (text_t *)&g_system,
        SYS_MON_MODS_ALL_ID,
        3,
        g_sys_dml_stats_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_LINKS", .len = 9},
        g_sys_links_cols,
        SYS_LINKS_COL_COUNT,
        (text_t *)&g_system,
        SYS_LINK_ID,
        1,
        g_sys_links_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_DISTRIBUTE_RULES", .len = 20},
        g_distribute_rules_cols,
        DISTRIBUTE_RULES_COL_COUNT,
        (text_t *)&g_system,
        SYS_DISTRIBUTE_RULE_ID,
        3,
        g_distribute_rules_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_TMP_SEG_STATS", .len = 17},
        g_tmp_seg_stats_cols,
        TMP_SEG_STATS_COL_COUNT,
        (text_t *)&g_swap,
        SYS_TMP_SEG_STAT_ID,
        2,
        g_tmp_seg_stats_indexes,
        TABLE_TYPE_TRANS_TEMP},
    {{.str = (char *)"SYS_SUB_TABLE_PARTS", .len = 19},
        g_subtable_parts_cols,
        SUBTABLE_PARTS_COL_COUNT,
        (text_t *)&g_system,
        SYS_SUB_TABLE_PARTS_ID,
        2,
        g_subtable_parts_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_DDM", .len = 7},
        g_sys_ddm_cols,
        SYS_DDM_COL_COUNT,
        (text_t *)&g_system,
        SYS_DDM_ID,
        2,
        g_sys_ddm_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_POLICIES", .len = 12},
        g_sys_policies_cols,
        SYS_POLICIES_COL_COUNT,
        (text_t *)&g_system,
        SYS_POLICY_ID,
        1,
        g_sys_policies_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_USER_PRIVS", .len = 14},
        g_user_privs_cols,
        USER_PRIVS_COL_COUNT,
        (text_t *)&g_system,
        SYS_USER_PRIVS_ID,
        1,
        g_user_privs_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_TENANTS", .len = 11},
        g_sys_tenants_cols,
        SYS_TENANTS_COL_COUNT,
        (text_t *)&g_system,
        SYS_TENANTS_ID,
        2,
        g_sys_tenants_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_INSTANCE_INFO", .len = 17},
        g_sys_instance_info_cols,
        SYS_INSTANCE_INFO_COL_COUNT,
        (text_t *)&g_system,
        SYS_INSTANCE_INFO_ID,
        1,
        g_sys_instance_info_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_TEMP_HISTGRAM", .len = 17},
        g_temp_histgram_cols,
        TEMP_HISTGRAM_COL_COUNT,
        (text_t *)&g_sysaux,
        SYS_TEMP_HISTGRAM_ID,
        1,
        g_temp_histgram_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_TEMP_HISTGRAM_ABSTR", .len = 23},
        g_temp_hist_abstr_cols,
        TEMP_HIST_ABSTR_COL_COUNT,
        (text_t *)&g_sysaux,
        SYS_TEMP_HIST_HEAD_ID,
        2,
        g_temp_hist_abstr_indexes,
        TABLE_TYPE_HEAP},
    {{.str = (char *)"SYS_HISTGRAM_ABSTR", .len = 18},
        g_histgram_abstr_cols,
        HISTGRAM_ABSTR_COL_COUNT,
        (text_t *)&g_sysaux,
        SYS_HIST_HEAD_ID,
        2,
        g_histgram_abstr_indexes,
        TABLE_TYPE_HEAP},
};

static inline status_t knl_build_sys_tables(knl_session_t *session)
{
    uint32 sys_table_count = sizeof(g_sys_tables) / sizeof(table_def_t);

    for (uint32 i = 0; i < sys_table_count; ++i) {
        GS_RETURN_IFERR(knl_create_table_func(session, &g_sys_tables[i]));
    }
    return GS_SUCCESS;
}

static inline  status_t knl_create_role_func(knl_session_t *session, char *name)
{
    knl_role_def_t def;

    def.owner_uid   = 0;
    def.password[0] = '\0';
    def.is_encrypt  = GS_FALSE;

    int32 ret = sprintf_s(def.name, GS_NAME_BUFFER_SIZE, "%s", name);
    knl_securec_check_ss(ret);
    return knl_create_role(session, &def);
}

static char *g_sys_roles[] = {
    (char*)"DBA",
    (char*)"RESOURCE"
};

static inline status_t knl_build_sys_roles(knl_session_t *session)
{
    uint32 sys_role_count = sizeof(g_sys_roles) / sizeof(char*);
    for (uint32 i = 0; i < sys_role_count; ++i) {
        GS_RETURN_IFERR(knl_create_role_func(session, g_sys_roles[i]));
    }
    return GS_SUCCESS;
}

status_t knl_build_sys_objects(knl_handle_t handle)
{
    knl_session_t *session = (knl_session_t*)handle;

    if (knl_build_sys_tables(session) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (knl_build_sys_roles(session) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t knl_create_user_table(knl_session_t * session, table_def_t *table)
{
    return knl_create_table_func(session, table);
}

#ifdef __cplusplus
}
#endif

