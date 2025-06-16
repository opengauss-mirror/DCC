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
 * gstor_executor.c
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_executor.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_file.h"
#include "cm_buddy.h"
#include "gstor_param.h"
#include "gstor_handle.h"
#include "gstor_sys_def.h"
#include "gstor_executor.h"
#include "gstor_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

#define G_STOR_SEQUENCE_9       '9'
#define G_STOR_PREFIX_FLAG      (1<<0)
#define G_STOR_SEQUENCE_FLAG    (1<<1)
#define G_STOR_DEFAULT_FLAG     (0)
#define G_STOR_SEQUENCE_OFFSET  (10)
#define GSTOR_IDX_EXT_NAME1     ("IX_")
#define GSTOR_IDX_EXT_NAME2     ("_001")
#define G_STOR_TABLE_EXT_SIZE   (7)


#define G_STOR_DEFAULT_COLS     (2)
#define G_STOR_DEFAULT_IDX_CNT  (1)
#define G_SOTR_DEFAULT_TBL_ID   ((uint32)64)

typedef struct st_lob_buf {
    char  *buf;
    uint32 size;
}lob_buf_t;

typedef struct st_ec_handle {
    lob_buf_t      lob_buf;
    knl_cursor_t  *cursor;
    knl_session_t *session;
    knl_dictionary_t dc;
}ec_handle_t;

instance_t *g_instance = NULL;
static config_t *g_config = NULL;
static uint32 g_cur_table_id = G_SOTR_DEFAULT_TBL_ID;
static const char *g_inst_name = "gstor";
static const char *g_lock_file = "gstor.lck";
static const text_t g_user_table_col1 = { .str = (char*)"KEY",   .len = 3 };
static const text_t g_user_table_col2 = { .str = (char*)"VALUE", .len = 5 };

#define KNL_ATTR            (&g_instance->kernel.attr)
#define MEM_POOL            (&g_instance->sga.buddy_pool)
#define EC_LOBBUF(handle)   (&((ec_handle_t*)(handle))->lob_buf)
#define EC_CURSOR(handle)   ((ec_handle_t*)(handle))->cursor
#define EC_SESSION(handle)  ((ec_handle_t*)(handle))->session
#define EC_DC(handle)       (&(((ec_handle_t*)(handle))->dc))
#define GS_MAX_KEY_LEN      (uint32)4000

static status_t gstor_init_config(char *data_path)
{
    char cfg_path[GS_FILE_NAME_BUFFER_SIZE];

    PRTS_RETURN_IFERR(sprintf_s(cfg_path, GS_FILE_NAME_BUFFER_SIZE, "%s/gstor/cfg", data_path));
    if (!cm_dir_exist(cfg_path)) {
        GS_RETURN_IFERR(cm_create_dir_ex(cfg_path));
    }

    g_config = (config_t*)malloc(sizeof(config_t));
    if (g_config == NULL) {
        GS_LOG_DEBUG_ERR("alloc config object failed");
        return GS_ERROR;
    }

    uint32  param_count = 0;
    config_item_t *params = NULL;

    knl_param_get_config_info(&params, &param_count);
    cm_init_config(params, param_count, g_config);

    errno_t err = sprintf_s(g_config->file_name, GS_FILE_NAME_BUFFER_SIZE, "%s/%s", cfg_path, "gstor.ini");
    if (err == -1) {
        CM_FREE_PTR(g_config);
        return GS_ERROR;
    }

    if (!cm_file_exist(g_config->file_name)) {
        int32 fd = -1;
        GS_RETURN_IFERR(cm_create_file(g_config->file_name, O_BINARY | O_SYNC | O_RDWR | O_EXCL, &fd));
        cm_close_file(fd);
    }
    return GS_SUCCESS;
}

static void gstor_deinit_config(void)
{
    uint32 param_count = 0;
    config_item_t *params = NULL;

    knl_param_get_config_info(&params, &param_count);
    for (uint32 i = 0; i < param_count; ++i) {
        params[i].is_default = GS_TRUE;
    }
    if (g_config == NULL) {
        return;
    }
    CM_FREE_PTR(g_config->value_buf);
    CM_FREE_PTR(g_config);
}

int gstor_set_param(char *name, char *value, char *data_path)
{
    if (g_config == NULL) {
        GS_RETURN_IFERR(gstor_init_config(data_path));
    }
    return cm_alter_config(g_config, name, value, CONFIG_SCOPE_MEMORY, GS_TRUE);
}

static inline void gstor_init_lob_buf(lob_buf_t *lob_buf)
{
    lob_buf->buf  = NULL;
    lob_buf->size = 0;
}

static inline void gstor_free_lob_buf(lob_buf_t *lob_buf)
{
    lob_buf->size = 0;
    BUDDY_FREE_PTR(lob_buf->buf);
}

static inline status_t gstor_realloc_log_buf(lob_buf_t *lob_buf, uint32 size)
{
    gstor_free_lob_buf(lob_buf);
    lob_buf->buf = galloc(MEM_POOL, size);
    if (lob_buf->buf == NULL) {
        GS_LOG_DEBUG_ERR(
            "alloc lob buf %u failed, mem pool remain %llu", size, MEM_POOL->max_size - MEM_POOL->used_size);
        return GS_ERROR;
    }
    lob_buf->size = size;
    return GS_SUCCESS;
}

static inline status_t gstor_open_kv_table(knl_instance_t *kernel, const char *tablename, knl_dictionary_t *dc)
{
    text_t user  = {.str = (char*)"SYS",    .len = 3};
    text_t table = {.str = (char*)tablename, .len = strlen(tablename) };
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    return knl_open_dc(session, &user, &table, dc);
}

int gstor_alloc(void **handle)
{
    ec_handle_t *ec_handle = (ec_handle_t *)malloc(sizeof(ec_handle_t));
    if (ec_handle == NULL) {
        GS_LOG_DEBUG_ERR("alloc exec handle memory failed");
        return GS_ERROR;
    }

    if (knl_alloc_session(&ec_handle->session) != GS_SUCCESS) {
        CM_FREE_PTR(ec_handle);
        return GS_ERROR;
    }

    if (knl_alloc_cursor(&ec_handle->cursor) != GS_SUCCESS) {
        knl_free_session(ec_handle->session);
        CM_FREE_PTR(ec_handle);
        return GS_ERROR;
    }
    ec_handle->dc.handle = NULL;
    gstor_init_lob_buf(&ec_handle->lob_buf);
    *handle = ec_handle;
    return GS_SUCCESS;
}

static status_t gstor_create_table(const char *table_name)
{
    column_def_t user_table_cols[] = {
        { g_user_table_col1, GS_TYPE_VARCHAR, GS_MAX_KEY_LEN, GS_FALSE },
        { g_user_table_col2, GS_TYPE_CLOB,    GS_MAX_KEY_LEN, GS_TRUE },
    };

    uint32 table_len = (uint32)strlen(table_name);
    uint32 idx_len = table_len + G_STOR_TABLE_EXT_SIZE;
    char idx_name[idx_len + 1];
    PRTS_RETURN_IFERR(sprintf_s(idx_name, idx_len + 1, "%s%s%s",
        GSTOR_IDX_EXT_NAME1, table_name, GSTOR_IDX_EXT_NAME2));
    idx_name[idx_len] = '\0';

    index_def_t user_kv_indexes[] = {
        { {.str = idx_name, .len = idx_len}, (text_t*)&g_user_table_col1, 1, GS_TRUE}
    };

    table_def_t user_table = {{.str = (char*)table_name, .len = (uint32)strlen(table_name)},
                              user_table_cols,
                              G_STOR_DEFAULT_COLS,
                              (text_t *)&g_users,
                              g_cur_table_id,
                              G_STOR_DEFAULT_IDX_CNT,
                              user_kv_indexes,
                              TABLE_TYPE_HEAP};
    status_t ret = knl_create_user_table(g_instance->kernel.sessions[SESSION_ID_KERNEL], &user_table);
    if (ret == GS_SUCCESS) {
        ++g_cur_table_id;
        return GS_SUCCESS;
    }
    return GS_ERROR;
}

int gstor_open_table(void *handle, const char *table_name)
{
    knl_dictionary_t *dc = EC_DC(handle);
    knl_close_dc(dc);
    if (gstor_open_kv_table(&g_instance->kernel, table_name, dc) != GS_SUCCESS) {
        if (cm_get_error_code() == ERR_TABLE_OR_VIEW_NOT_EXIST) {
            cm_reset_error();
            status_t ret = gstor_create_table(table_name);
            if (ret != GS_SUCCESS) {
                GS_LOG_RUN_ERR("create table failed, error code %d", cm_get_error_code());
                return GS_ERROR;
            }
            return gstor_open_kv_table(&g_instance->kernel, table_name, dc);
        }
    }

    return GS_SUCCESS;
}

void gstor_clean(void *handle)
{
    gstor_free_lob_buf(EC_LOBBUF(handle));

    knl_cleanup_session(EC_SESSION(handle));

    knl_close_cursor(EC_SESSION(handle), EC_CURSOR(handle));
}

void gstor_free(void *handle)
{
    knl_close_dc(EC_DC(handle));

    gstor_free_lob_buf(EC_LOBBUF(handle));

    knl_free_session(EC_SESSION(handle));

    CM_FREE_PTR(EC_CURSOR(handle));

    CM_FREE_PTR(handle);
}

static inline bool32 gstor_check_db(knl_session_t *session)
{
    text_t ctrlfiles;
    bool32 is_found  = GS_FALSE;
    bool32 db_exists = GS_FALSE;

    log_param_t *log_param = cm_log_param_instance();
    uint32 log_level = log_param->log_level;

    // close log for db check
    log_param->log_level = 0;
    db_exists = (db_check(session, &ctrlfiles, &is_found) == GS_SUCCESS && is_found);
    log_param->log_level = log_level;
    cm_reset_error();
    return db_exists;
}

static status_t gstor_try_build_sys_tables(knl_handle_t handle, const char* file_name, bool8 is_necessary)
{
    if (!g_instance->sys_defined) {
        GS_RETURN_IFERR(knl_build_sys_objects(handle));
        g_instance->sys_defined = GS_TRUE;
    }
    return GS_SUCCESS;
}

static void rsrc_accumate_io(knl_handle_t sess, io_type_t type)
{
}

static void sql_pool_recycle_all()
{
}

static bool32 knl_have_ssl(void)
{
    return GS_FALSE;
}

static void clean_open_cursors(knl_handle_t sess, uint64 lsn)
{
}

static void clean_open_temp_cursors(knl_handle_t sess, void *temp_cache)
{
}

static status_t return_callback(knl_handle_t sess)
{
    return GS_SUCCESS;
}

static void void_callback(knl_handle_t sess)
{
}

static inline void knl_init_mtrl_vmc(handle_t *mtrl)
{
    mtrl_context_t *ctx = (mtrl_context_t *)mtrl;
    vmc_init(&g_instance->vmp, &ctx->vmc);
}

static void gstor_set_callback(void)
{
    g_knl_callback.alloc_rm = knl_alloc_rm;
    g_knl_callback.release_rm = knl_release_rm;
    g_knl_callback.alloc_auton_rm = knl_alloc_auton_rm;
    g_knl_callback.release_auton_rm = knl_release_auton_rm;
    g_knl_callback.get_xa_xid = knl_get_xa_xid;
    g_knl_callback.add_xa_xid = knl_add_xa_xid;
    g_knl_callback.delete_xa_xid = knl_delete_xa_xid;
    g_knl_callback.attach_suspend_rm = knl_attach_suspend_rm;
    g_knl_callback.detach_suspend_rm = knl_detach_suspend_rm;
    g_knl_callback.attach_pending_rm = knl_attach_pending_rm;
    g_knl_callback.detach_pending_rm = knl_detach_pending_rm;
    g_knl_callback.shrink_xa_rms = knl_shrink_xa_rms;
    g_knl_callback.before_commit = (knl_before_commit_t)knl_clean_before_commit;
    g_knl_callback.accumate_io = rsrc_accumate_io;
    g_knl_callback.sql_pool_recycle_all = sql_pool_recycle_all;
    g_knl_callback.load_scripts = gstor_try_build_sys_tables;
    g_knl_callback.set_min_scn = void_callback;
    g_knl_callback.have_ssl = knl_have_ssl;
    g_knl_callback.invalidate_cursor = clean_open_cursors;
    g_knl_callback.pl_init = return_callback;
    g_knl_callback.init_shard_resource = return_callback;
    g_knl_callback.init_sql_maps = return_callback;
    g_knl_callback.init_resmgr = return_callback;
    g_knl_callback.init_vmc = knl_init_mtrl_vmc;
    g_knl_callback.invalidate_temp_cursor = clean_open_temp_cursors;
}

static status_t gstor_init_db_home(char *data_path)
{
    if (data_path == NULL) {
        return GS_ERROR;
    }

    char home[GS_MAX_PATH_BUFFER_SIZE];
    GS_RETURN_IFERR(realpath_file(data_path, home, GS_MAX_PATH_BUFFER_SIZE));

    if (cm_check_exist_special_char(home, (uint32)strlen(home))) {
        GS_THROW_ERROR(ERR_INVALID_DIR, home);
        return GS_ERROR;
    }
    cm_trim_home_path(home, (uint32)strlen(home));

    PRTS_RETURN_IFERR(sprintf_s(g_instance->home, GS_MAX_PATH_BUFFER_SIZE, "%s/gstor", home));
    g_instance->kernel.home = g_instance->home;

    PRTS_RETURN_IFERR(sprintf_s(home, GS_MAX_PATH_BUFFER_SIZE, "%s/data", g_instance->home));
    if (!cm_dir_exist(home)) {
        GS_RETURN_IFERR(cm_create_dir_ex(home));
    }
    return GS_SUCCESS;
}

static inline status_t gstor_lock_db(void)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { 0 };

    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1, "%s/%s",
        g_instance->home, g_lock_file));

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_instance->lock_fd) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return cm_lock_fd(g_instance->lock_fd);
}

static void gstor_init_default_size(knl_attr_t *attr)
{
    attr->vma_size = DEFAULT_VMA_SIZE;
    attr->large_vma_size = DEFAULT_LARGE_VMA_SIZE;
    attr->shared_area_size = DEFAULT_SHARE_AREA_SIZE;
    attr->sql_pool_factor = DEFAULT_SQL_POOL_FACTOR;
    attr->large_pool_size = DEFAULT_LARGE_POOL_SIZE;
    attr->temp_buf_size = DEFAULT_TEMP_BUF_SIZE;
    attr->temp_pool_num = DEFAULT_TEMP_POOL_NUM;
    attr->cr_pool_size = DEFAULT_CR_POOL_SIZE;
    attr->cr_pool_count = DEFAULT_CR_POOL_COUNT;
    attr->index_buf_size = DEFAULT_INDEX_BUF_SIZE;
    attr->max_rms = GS_MAX_RMS;
    attr->ckpt_interval = DEFAULT_CKPT_INTERVAL;
    attr->ckpt_io_capacity = DEFAULT_CKPT_IO_CAPACITY;
    attr->log_replay_processes = DEFAULT_LOG_REPLAY_PROCESSES;
    attr->rcy_sleep_interval = DEFAULT_RCY_SLEEP_INTERVAL;
    attr->dbwr_processes = DEFAULT_DBWR_PROCESSES;
    attr->undo_reserve_size = DEFAULT_UNDO_RESERVER_SIZE;
    attr->undo_retention_time = DEFAULT_UNDO_RETENTION_TIME;
    attr->undo_segments = DEFAULT_UNDO_SEGMENTS;
    attr->undo_active_segments = DEFAULT_UNDO_ACTIVE_SEGMENTS;
    attr->undo_auton_trans_segments = DEFAULT_UNDO_AUTON_TRANS_SEGMENTS;
    attr->tx_rollback_proc_num = DEFAULT_TX_ROLLBACK_PROC_NUM;
    attr->max_arch_files_size = DEFAULT_MAX_ARCH_FILES_SIZE;
    attr->default_extents = DEFAULT_EXTENTS;
    attr->alg_iter = DEFAULT_ALG_ITER;
    attr->max_column_count = DEFAULT_ALG_ITER;
    attr->stats_sample_size = DEFAULT_STATS_SAMPLE_SIZE;
    attr->private_key_locks = DEFAULT_PRIVATE_KEY_LOCKS;
    attr->private_row_locks = DEFAULT_PRIVATE_ROW_LOCKS;
    attr->spc_usage_alarm_threshold = DEFAULT_SPC_USAGE_ALARM_THRESHOLD;
    attr->stats_max_buckets = DEFAULT_STATS_MAX_BUCKETS;
    attr->lob_reuse_threshold = DEFAULT_LOG_REUSE_THRESHOLD;
    attr->init_lockpool_pages = DEFAULT_INIT_LOCKPOOL_PAGES;
    attr->max_temp_tables = DEFAULT_MAX_TEMP_TABLES;
    attr->buddy_init_size = BUDDY_INIT_BLOCK_SIZE;
    attr->buddy_max_size = BUDDY_MEM_POOL_INIT_SIZE;
    attr->lgwr_head_buf_size = GS_SHARED_PAGE_SIZE;
    attr->lgwr_async_buf_size = GS_SHARED_PAGE_SIZE;
    attr->buf_iocbs_size = sizeof(buf_iocb_t) * BUF_IOCBS_MAX_NUM;
    g_instance->attr.stack_size = DEFAULT_STACK_SIZE;
}

static status_t gstor_init_default_params(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;

    gstor_init_default_size(attr);

    attr->spin_count = DEFAULT_SPIN_COUNT;
    attr->cpu_count = cm_sys_get_nprocs();
    attr->enable_double_write = GS_TRUE;
    attr->rcy_check_pcn = GS_TRUE;
    attr->ashrink_wait_time = DEFAULT_ASHRINK_WAIT_TIME;
    attr->db_block_checksum = (uint32)CKS_FULL;
    attr->db_isolevel = (uint8)ISOLATION_READ_COMMITTED;
    attr->ckpt_timeout = DEFAULT_CKPT_TIMEOUT;
    attr->enable_OSYNC = GS_TRUE;
    attr->enable_logdirectIO = GS_FALSE;
    attr->undo_auto_shrink = GS_TRUE;
    attr->repl_wait_timeout = DEFAULT_REPL_WAIT_TIMEOUT;
    attr->restore_check_version = GS_TRUE;
    attr->nbu_backup_timeout = DEFAULT_NBU_BACKUP_TIMEOUT;
    attr->check_sysdata_version = GS_TRUE;
    attr->xa_suspend_timeout = DEFAULT_XA_SUSPEND_TIMEOUT;
    attr->build_keep_alive_timeout = DEFAULT_BUILD_KEEP_ALIVE_TIMEOUT;
    attr->enable_upper_case_names = GS_TRUE;
    attr->recyclebin = GS_TRUE;
    attr->alg_iter = DEFAULT_ALG_ITER;
    attr->enable_idx_key_len_check = GS_TRUE;
    attr->initrans = DEFAULT_INITTRANS;
    attr->cr_mode = CR_PAGE;
    attr->idx_auto_recycle = GS_TRUE;
    attr->lsnd_wait_time = DEFAULT_LSND_WAIT_TIME;
    attr->ddl_lock_timeout = DEFAULT_DDL_LOCK_TIMEOUT;
    attr->systime_inc_threshold = (int64)DAY2SECONDS(FIX_NUM_DAYS_YEAR);
    attr->enable_degrade_search = GS_TRUE;
    attr->delay_cleanout = GS_TRUE;
    attr->ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_FULL;
    attr->arch_ignore_backup = GS_TRUE;
    attr->timer = g_timer();
    PRTS_RETURN_IFERR(sprintf_s(attr->pwd_alg, GS_NAME_BUFFER_SIZE, "%s", "PBKDF2"));
    return GS_SUCCESS;
}

static status_t gstor_init_runtime_params(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;

    attr->config = g_config;
    uint32 page_size = attr->page_size;
    attr->max_row_size = page_size - 256;
    /* the max value of page_size is 32768 and GS_PLOG_PAGES is 7 */
    attr->plog_buf_size = page_size * GS_PLOG_PAGES;
    attr->cursor_size = (uint32)(sizeof(knl_cursor_t) + page_size * 2 + attr->max_column_count * sizeof(uint16) * 2);
    /* the min value of inst->attr.max_map_nodes is 8192 */
    attr->max_map_nodes = (page_size - sizeof(map_page_t) - sizeof(page_tail_t)) / sizeof(map_node_t);
    attr->xpurpose_buf = cm_aligned_buf(g_instance->xpurpose_buf);

    attr->dbwr_buf_size = (uint64)GS_CKPT_GROUP_SIZE * attr->page_size;
    attr->lgwr_cipher_buf_size = attr->log_buf_size / 2 + sizeof(cipher_ctrl_t);
    attr->lgwr_cipher_buf_size = CM_CALC_ALIGN(attr->lgwr_cipher_buf_size, SIZE_K(4));

    attr->lgwr_buf_size = attr->lgwr_cipher_buf_size;
    attr->tran_buf_size = knl_txn_buffer_size(attr->page_size, attr->undo_segments);

    char control_files[GS_MAX_CONFIG_LINE_SIZE];
    PRTS_RETURN_IFERR(sprintf_s(control_files, GS_MAX_CONFIG_LINE_SIZE, "(%s/data/ctrl1,%s/data/ctrl2,%s/data/ctrl3)",
        g_instance->home, g_instance->home, g_instance->home));
    return cm_alter_config(g_config, "CONTROL_FILES", control_files, CONFIG_SCOPE_BOTH, GS_TRUE);
}

static status_t gstor_load_param_config(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;

    GS_RETURN_IFERR(knl_param_get_size_uint64(g_config, "DATA_BUFFER_SIZE", &attr->data_buf_size));
    if (attr->data_buf_size < GS_MIN_DATA_BUFFER_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "DATA_BUFFER_SIZE", GS_MIN_DATA_BUFFER_SIZE);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(knl_param_get_uint32(g_config, "BUF_POOL_NUM", &attr->buf_pool_num));
    if (attr->buf_pool_num > GS_MAX_BUF_POOL_NUM || attr->buf_pool_num <= 0) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUF_POOL_NUM", (int64)1, (int64)GS_MAX_BUF_POOL_NUM);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(knl_param_get_size_uint64(g_config, "LOG_BUFFER_SIZE", &attr->log_buf_size));
    if (attr->log_buf_size < GS_MIN_LOG_BUFFER_SIZE || attr->log_buf_size > GS_MAX_LOG_BUFFER_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "LOG_BUFFER_SIZE", GS_MIN_LOG_BUFFER_SIZE, GS_MAX_LOG_BUFFER_SIZE);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(knl_param_get_uint32(g_config, "LOG_BUFFER_COUNT", &attr->log_buf_count));
    if (!(attr->log_buf_count > 0 && attr->log_buf_count <= GS_MAX_LOG_BUFFERS)) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "LOG_BUFFER_COUNT");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(knl_param_get_size_uint32(g_config, "PAGE_SIZE", &attr->page_size));
    if (!(attr->page_size == 8192 || attr->page_size == 16384 || attr->page_size == 32768)) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "PAGE_SIZE");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(knl_param_get_size_uint64(g_config, "SPACE_SIZE", &g_instance->attr.space_size));
    if (g_instance->attr.space_size < SIZE_M(32)) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "SPACE_SIZE");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline void gstor_check_file_errno()
{
    if (errno == EMFILE || errno == ENFILE) {
        GS_LOG_ALARM(WARN_FILEDESC, "'instance-name':'%s'}", g_instance->kernel.instance_name);
    }
}

static status_t gstor_init_loggers(void)
{
    char file_name[GS_FILE_NAME_BUFFER_SIZE] = { '\0' };
    cm_log_allinit();

    log_param_t *log_param = cm_log_param_instance();

    MEMS_RETURN_IFERR(strcpy_sp(log_param->instance_name, GS_MAX_NAME_LEN, g_instance->kernel.instance_name));

    log_param->log_backup_file_count = 10;
    log_param->max_log_file_size = SIZE_M(10);
    GS_RETURN_IFERR(knl_param_get_size_uint32(g_config, "LOG_LEVEL", &(log_param->log_level)));
    cm_log_set_file_permissions(600);
    cm_log_set_path_permissions(700);

    // RUN
    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/run/%s",
        log_param->log_home, "gstor_run.log"));
    cm_log_init(LOG_RUN, file_name);

    // DEBUG
    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/debug/%s",
        log_param->log_home, "gstor_debug.log"));
    cm_log_init(LOG_DEBUG, file_name);

    // ALARM
    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN, "%s/%s_alarm.log",
        log_param->log_home, log_param->instance_name));
    cm_log_init(LOG_ALARM, file_name);

    log_file_handle_t *log_file_handle = cm_log_logger_file(LOG_ALARM);
    cm_log_open_file(log_file_handle);

    // TRACE
    PRTS_RETURN_IFERR(snprintf_s(file_name, GS_FILE_NAME_BUFFER_SIZE, GS_MAX_FILE_NAME_LEN,
        "%s/%s_smon_%05u.trc", log_param->log_home, log_param->instance_name, (uint32)SESSION_ID_SMON));

    cm_log_init(LOG_TRACE, file_name);
    log_file_handle = cm_log_logger_file(LOG_TRACE);
    cm_log_open_file(log_file_handle);

    // callback
    cm_init_error_handler(cm_set_sql_error);
    g_check_file_error = gstor_check_file_errno;
    return GS_SUCCESS;
}

static inline status_t gstor_load_params(char *data_path)
{
    if (g_config == NULL) {
        GS_RETURN_IFERR(gstor_init_config(data_path));
    }

    if (gstor_init_default_params() != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (gstor_load_param_config() != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (gstor_init_runtime_params() != GS_SUCCESS) {
        return GS_ERROR;
    }
    return gstor_init_loggers();
}

static status_t gstor_init_instance(char *data_path)
{
    g_instance = (instance_t *)malloc(sizeof(instance_t));
    if (g_instance == NULL) {
        GS_LOG_RUN_ERR("[knl_init_instance] alloc instance failed");
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(g_instance, sizeof(instance_t), 0, sizeof(instance_t)));

    MEMS_RETURN_IFERR(strncpy_s(g_instance->kernel.instance_name, GS_MAX_NAME_LEN, g_inst_name, strlen(g_inst_name)));

    gstor_set_callback();

    GS_RETURN_IFERR(gstor_init_db_home(data_path));

    GS_RETURN_IFERR(gstor_load_params(data_path));

    GS_RETURN_IFERR(knl_create_sga());

    GS_RETURN_IFERR(vmp_create(&g_instance->sga.vma, 0, &g_instance->vmp));

    rm_pool_init(&g_instance->rm_pool);

    GS_RETURN_IFERR(knl_alloc_sys_sessions());

    g_instance->lock_fd = -1;
    return GS_SUCCESS;
}

static inline status_t gstor_start_db(knl_instance_t *kernel)
{
    knl_session_t *session = kernel->sessions[SESSION_ID_KERNEL];
    if (gstor_check_db(session)) {
        return knl_open_sys_database(session);
    }
    return knl_create_sys_database(session, kernel->home);
}

void gstor_shutdown(void)
{
    cm_close_timer(g_timer());

    if (g_instance == NULL) {
        return;
    }

    while (GS_TRUE) {
        if (g_instance->shutdown_ctx.phase == SHUTDOWN_PHASE_DONE ||
            cm_spin_try_lock(&g_instance->kernel.db.lock)) {
            break;
        }
        cm_sleep(5);
        GS_LOG_RUN_INF("wait for shutdown to complete");
    }

    if (g_instance->shutdown_ctx.phase == SHUTDOWN_PHASE_DONE) {
        return;
    }

    g_instance->shutdown_ctx.phase = SHUTDOWN_PHASE_INPROGRESS;
    g_instance->shutdown_ctx.mode = SHUTDOWN_MODE_ABORT;

    knl_shutdown(NULL, &g_instance->kernel, GS_FALSE);

    rm_pool_deinit(&g_instance->rm_pool);

    knl_free_sys_sessions();

    knl_destroy_sga();

    g_instance->shutdown_ctx.phase = SHUTDOWN_PHASE_DONE;
    CM_FREE_PTR(g_instance);

    gstor_deinit_config();
}

void gstor_set_log_path(char *path)
{
    log_param_t *log_param = cm_log_param_instance();
    (void)snprintf_s(log_param->log_home, GS_MAX_PATH_BUFFER_SIZE, GS_MAX_PATH_LEN, "%s/gstor_log", path);
}

int gstor_startup(char *data_path, unsigned int startup_mode)
{
    do {
        GS_BREAK_IF_ERROR(cm_start_timer(g_timer()));
        GS_BREAK_IF_ERROR(gstor_init_instance(data_path));
        GS_BREAK_IF_ERROR(gstor_lock_db());
        GS_BREAK_IF_ERROR(alck_init_ctx(&g_instance->kernel));
        GS_BREAK_IF_ERROR(knl_startup(&g_instance->kernel));
        if (startup_mode == STARTUP_MODE_OPEN) {
            GS_BREAK_IF_ERROR(gstor_start_db(&g_instance->kernel));
        }
        GS_LOG_RUN_INF("gstore started successfully with startup_mode:%d!", startup_mode);
        return GS_SUCCESS;
    } while (GS_FALSE);

    gstor_shutdown();
    GS_LOG_RUN_INF("gstore started failed with startup_mode:%d!", startup_mode);
    return GS_ERROR;
}

static inline void gstor_prepare(knl_session_t *session, knl_cursor_t *cursor, lob_buf_t *lob_buf)
{
    gstor_free_lob_buf(lob_buf);
    knl_close_cursor(session, cursor);
    knl_set_session_scn(session, GS_INVALID_ID64);
}

static inline status_t gstor_open_cursor_internal(knl_session_t *session,
    knl_cursor_t *cursor, knl_dictionary_t *dc, knl_cursor_action_t action, uint32 index_slot)
{
    cursor->action = action;
    if (index_slot == GS_INVALID_ID32) {
        cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    } else {
        cursor->index_slot = index_slot;
        cursor->scan_mode  = SCAN_MODE_INDEX;
    }

    knl_inc_session_ssn(session);
    return knl_open_cursor(session, cursor, dc);
}

static inline status_t gstor_set_key(char *key, uint32 key_len, row_assist_t *ra)
{
    text_t data;
    data.str = key;
    data.len = key_len;
    return row_put_text(ra, &data);
}

static inline status_t gstor_set_value(
    knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc, text_t *val, row_assist_t *ra)
{
    if (val == NULL) {
        return row_put_null(ra);
    }

    knl_column_t *column = knl_get_column(dc->handle, SYS_KV_VALUE_COL_ID);
    return knl_row_put_lob(session, cursor, column, (void *)val, ra);
}

static inline status_t gstor_insert(knl_session_t *session,
    knl_cursor_t *cursor, knl_dictionary_t *dc, char *key, uint32 key_len, char *val, uint32 val_len)
{
    GS_RETURN_IFERR(gstor_open_cursor_internal(session, cursor, dc, CURSOR_ACTION_INSERT, GS_INVALID_ID32));

    row_assist_t ra;
    uint32 column_count = knl_get_column_count(dc->handle);
    row_init(&ra, (char *)cursor->row, KNL_ATTR->max_row_size, column_count);

    // set key
    GS_RETURN_IFERR(gstor_set_key(key, key_len, &ra));

    // set value
    text_t setval = { .str = val, .len = val_len };
    GS_RETURN_IFERR(gstor_set_value(session, cursor, dc, &setval, &ra));

    return knl_internal_insert(session, cursor);
}

static inline status_t gstor_update_core(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    char *val, uint32 val_len)
{
    row_assist_t ra;
    knl_update_info_t *ui = &cursor->update_info;

    ui->count = 1;
    ui->columns[0] = SYS_KV_VALUE_COL_ID;
    row_init(&ra, ui->data, KNL_ATTR->max_row_size, ui->count);

    text_t setval = { .str = val, .len = val_len };
    GS_RETURN_IFERR(gstor_set_value(session, cursor, dc, &setval, &ra));

    cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);
    return knl_internal_update(session, cursor);
}

static inline status_t gstor_update(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    char *key, uint32 key_len, char *val, uint32 val_len, bool32 *updated)
{
    GS_RETURN_IFERR(gstor_open_cursor_internal(session, cursor, dc, CURSOR_ACTION_UPDATE, IX_SYS_KV_01_ID));

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(
        INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_STRING, key, key_len, SYS_KV_KEY_COL_ID);
    GS_RETURN_IFERR(knl_fetch(session, cursor));
    if (cursor->eof) {
        return GS_SUCCESS;
    }
    *updated = GS_TRUE;
    return gstor_update_core(session, cursor, dc, val, val_len);
}

static status_t gstor_make_scan_key(knl_session_t *session, knl_cursor_t *cursor, char *key, uint32 len, uint32 flags)
{
    GS_LOG_DEBUG_INF("make scan key: %u, key: %s, len: %u", flags, key, len);
    bool32 prefix = ((flags & G_STOR_PREFIX_FLAG) > 0) ? GS_TRUE : GS_FALSE;
    bool32 sequence = ((flags & G_STOR_SEQUENCE_FLAG) > 0) ? GS_TRUE : GS_FALSE;
    knl_init_index_scan(cursor, !(prefix || sequence));
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key,
        GS_TYPE_STRING, key, (uint16)len, SYS_KV_KEY_COL_ID);

    if (flags == G_STOR_DEFAULT_FLAG) {
        return GS_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    char *r_key = (char *)cm_push(session->stack, GS_MAX_KEY_LEN);
    if (r_key == NULL) {
        GS_LOG_DEBUG_ERR("make scan key alloc mem failed");
        return GS_ERROR;
    }
    int32 ret = strncpy_s(r_key, GS_MAX_KEY_LEN, key, len);
    if (ret != EOK) {
        GS_LOG_DEBUG_ERR("make scan key system call failed for strncpy %d", ret);
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }
    if (prefix) {
        // fill padding for key's right range
        r_key[len++] = (char)255;
        if (len < GS_MAX_KEY_LEN) {
            r_key[len++] = (char)255;
        }
    } else {
        if (sequence) {
            for (uint32 i = 0; i < G_STOR_SEQUENCE_OFFSET; i++) {
                r_key[(len - G_STOR_SEQUENCE_OFFSET) + i] = G_STOR_SEQUENCE_9;
            }
        }
    }

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key,
        GS_TYPE_STRING, r_key, (uint16)len, SYS_KV_KEY_COL_ID);
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

static status_t gstor_get_table_row(void *handle, char **key, unsigned int *key_len, char **val, unsigned int *val_len)
{
    knl_cursor_t  *cursor  = EC_CURSOR(handle);
    knl_session_t *session = EC_SESSION(handle);

    // key
    if (key != NULL) {
        *key = CURSOR_COLUMN_DATA(cursor, SYS_KV_KEY_COL_ID);
    }

    if (key_len != NULL) {
        *key_len = CURSOR_COLUMN_SIZE(cursor, SYS_KV_KEY_COL_ID);
    }

    *val_len = CURSOR_COLUMN_SIZE(cursor, SYS_KV_VALUE_COL_ID);
    if (*val_len == GS_NULL_VALUE_LEN) {
        *val = NULL;
        *val_len = 0;
        return GS_SUCCESS;
    }

    // value
    lob_locator_t *locator = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, SYS_KV_VALUE_COL_ID);
    *val_len = locator->head.size;

    // inline
    if (!locator->head.is_outline) {
        *val = (char *)locator + OFFSET_OF(lob_locator_t, data);
        return GS_SUCCESS;
    }

    // outline
    if (*val_len > EC_LOBBUF(handle)->size) {
        GS_RETURN_IFERR(gstor_realloc_log_buf(EC_LOBBUF(handle), (*val_len)));
    }

    *val = EC_LOBBUF(handle)->buf;
    GS_RETURN_IFERR(knl_read_lob(session, locator, 0, (void *)(*val), (*val_len), NULL));
    return GS_SUCCESS;
}

int gstor_put(void *handle, char *key, unsigned int key_len, char *val, unsigned int val_len)
{
    knl_cursor_t  *cursor  = EC_CURSOR(handle);
    knl_session_t *session = EC_SESSION(handle);
    knl_dictionary_t *dc = EC_DC(handle);

    gstor_prepare(session, cursor, EC_LOBBUF(handle));

    for (;;) {
        cm_set_ignore_log(GS_TRUE);
        if (gstor_insert(session, cursor, dc, key, key_len, val, val_len) == GS_SUCCESS) {
            cm_set_ignore_log(GS_FALSE);
            return GS_SUCCESS;
        }
        cm_set_ignore_log(GS_FALSE);
        if (GS_ERRNO != ERR_DUPLICATE_KEY) {
            return GS_ERROR;
        }

        cm_reset_error();
        bool32 updated = GS_FALSE;

        GS_RETURN_IFERR(gstor_update(session, cursor, dc, key, key_len, val, val_len, &updated));
        if (updated) {
            return GS_SUCCESS;
        }
    }
}

int gstor_del(void *handle, char *key, unsigned int key_len, unsigned int prefix, unsigned int *count)
{
    knl_cursor_t  *cursor  = EC_CURSOR(handle);
    knl_session_t *session = EC_SESSION(handle);
    knl_dictionary_t *dc = EC_DC(handle);

    gstor_prepare(session, cursor, EC_LOBBUF(handle));

    GS_RETURN_IFERR(gstor_open_cursor_internal(session, cursor, dc, CURSOR_ACTION_DELETE, IX_SYS_KV_01_ID));

    GS_RETURN_IFERR(gstor_make_scan_key(session, cursor, key, key_len, prefix));

    GS_RETURN_IFERR(knl_fetch(session, cursor));

    *count = 0;
    while (!cursor->eof) {
        GS_RETURN_IFERR(knl_internal_delete(session, cursor));
        GS_RETURN_IFERR(knl_fetch(session, cursor));
        (*count)++;
    }
    return GS_SUCCESS;
}

int gstor_get(void *handle, char *key, unsigned int key_len, char **val, unsigned int *val_len, unsigned int *eof)
{
    knl_cursor_t  *cursor  = EC_CURSOR(handle);
    knl_session_t *session = EC_SESSION(handle);
    knl_dictionary_t *dc = EC_DC(handle);

    gstor_prepare(session, cursor, EC_LOBBUF(handle));

    GS_RETURN_IFERR(gstor_open_cursor_internal(session, cursor, dc, CURSOR_ACTION_SELECT, IX_SYS_KV_01_ID));

    GS_RETURN_IFERR(gstor_make_scan_key(session, cursor, key, key_len, G_STOR_DEFAULT_FLAG));

    GS_RETURN_IFERR(knl_fetch(session, cursor));
    *eof = cursor->eof;
    if (*eof) {
        return GS_SUCCESS;
    }
    return gstor_get_table_row(handle, NULL, NULL, val, val_len);
}

int gstor_open_cursor(void *handle, char *key, unsigned int key_len, unsigned int flags, unsigned int *eof)
{
    knl_cursor_t  *cursor  = EC_CURSOR(handle);
    knl_session_t *session = EC_SESSION(handle);
    knl_dictionary_t *dc = EC_DC(handle);

    gstor_prepare(session, cursor, EC_LOBBUF(handle));

    GS_RETURN_IFERR(gstor_open_cursor_internal(session, cursor, dc, CURSOR_ACTION_SELECT, IX_SYS_KV_01_ID));

    GS_RETURN_IFERR(gstor_make_scan_key(session, cursor, key, key_len, flags));

    GS_RETURN_IFERR(knl_fetch(session, cursor));

    *eof = cursor->eof;
    return GS_SUCCESS;
}

int gstor_cursor_next(void *handle, unsigned int *eof)
{
    GS_RETURN_IFERR(knl_fetch(EC_SESSION(handle), EC_CURSOR(handle)));
    *eof = EC_CURSOR(handle)->eof;
    return GS_SUCCESS;
}

int gstor_cursor_fetch(void *handle, char **key, unsigned int *key_len, char **val, unsigned int *val_len)
{
    return gstor_get_table_row(handle, key, key_len, val, val_len);
}

int gstor_begin(void *handle)
{
    return GS_SUCCESS;
}

int gstor_commit(void *handle)
{
    knl_commit(EC_SESSION(handle));
    return GS_SUCCESS;
}

int gstor_rollback(void *handle)
{
    knl_rollback(EC_SESSION(handle), NULL);
    return GS_SUCCESS;
}

int gstor_vm_alloc(void *handle, unsigned int *vmid)
{
    return vm_alloc(EC_SESSION(handle), EC_SESSION(handle)->temp_pool, vmid);
}

int gstor_vm_open(void *handle, unsigned int vmid, void **page)
{
    return vm_open(EC_SESSION(handle), EC_SESSION(handle)->temp_pool, vmid, (vm_page_t**)page);
}

void gstor_vm_close(void *handle, unsigned int vmid)
{
    vm_close(EC_SESSION(handle), EC_SESSION(handle)->temp_pool, vmid, VM_ENQUE_TAIL);
}

void gstor_vm_free(void *handle, unsigned int vmid)
{
    vm_free(EC_SESSION(handle), EC_SESSION(handle)->temp_pool, vmid);
}

int gstor_vm_swap_out(void *handle, void *page, unsigned long long *swid, unsigned int *cipher_len)
{
    knl_session_t *session = EC_SESSION(handle);
    return session->temp_pool->swapper.out(session, (vm_page_t*)page, swid, cipher_len);
}

int gstor_vm_swap_in(void *handle, unsigned long long swid, unsigned int cipher_len, void *page)
{
    knl_session_t *session = EC_SESSION(handle);
    return session->temp_pool->swapper.in(session, swid, cipher_len, (vm_page_t*)page);
}

int gstor_xa_start(void *handle, unsigned char gtrid_len, const char *gtrid)
{
    knl_session_t *session = EC_SESSION(handle);
    session->rm->xa_xid.fmt_id    = 0;
    session->rm->xa_xid.gtrid_len = gtrid_len;
    MEMS_RETURN_IFERR(memcpy_sp(session->rm->xa_xid.gtrid, GS_MAX_XA_BASE16_GTRID_LEN, gtrid, gtrid_len));
    session->rm->xa_xid.bqual_len = 0;
    return (int)knl_add_xa_xid(&session->rm->xa_xid, session->rm->id, XA_START);
}

int gstor_xa_status(void *handle)
{
    knl_session_t *session = EC_SESSION(handle);

    uint16 rmid = knl_get_xa_xid(&session->rm->xa_xid);
    if (rmid == GS_INVALID_ID16) {
        return XACT_END;
    }

    txn_t *txn = session->kernel->rms[rmid]->txn;
    if (txn == NULL) {
        return XACT_END;
    }

    return (int)txn->status;
}

int gstor_xa_shrink(void *handle)
{
    knl_shrink_xa_rms(EC_SESSION(handle), GS_TRUE);
    return GS_SUCCESS;
}

int gstor_xa_end(void *handle)
{
    knl_session_t *session = EC_SESSION(handle);
    knl_delete_xa_xid(&session->rm->xa_xid);
    return GS_SUCCESS;
}

int gstor_detach_suspend_rm(void *handle)
{
    uint16 rmid;
    knl_session_t *session = EC_SESSION(handle);
    GS_RETURN_IFERR(knl_alloc_rm(&rmid));
    knl_detach_suspend_rm(session, rmid);
    return GS_SUCCESS;
}

int gstor_attach_suspend_rm(void *handle)
{
    knl_session_t *session = EC_SESSION(handle);
    (void)knl_attach_suspend_rm(session, &session->rm->xa_xid, XA_PHASE1, GS_FALSE);
    return GS_SUCCESS;
}

int gstor_detach_pending_rm(void *handle)
{
    knl_session_t *session = EC_SESSION(handle);
    uint16 rmid = session->rmid;
    knl_detach_pending_rm(session, rmid);
    return GS_SUCCESS;
}

int gstor_attach_pending_rm(void *handle)
{
    knl_session_t *session = EC_SESSION(handle);
    (void)knl_attach_pending_rm(session, &session->rm->xa_xid);
    return GS_SUCCESS;
}

int gstor_backup(void *handle, const char *bak_format)
{
    knl_backup_t backup = { 0 };
    knl_backup_t *param_backup = &backup;
    param_backup->type = BACKUP_MODE_FULL;
    param_backup->device = DEVICE_DISK;
    param_backup->format.str = (char *)bak_format;
    param_backup->format.len = strlen(bak_format);
    param_backup->finish_scn = DB_CURR_SCN(EC_SESSION(handle));
    param_backup->target_info.target = TARGET_ALL;
    param_backup->target_info.backup_arch_mode = ARCHIVELOG_ALL;
    param_backup->crypt_info.encrypt_alg = ENCRYPT_NONE;
    int ret = knl_backup(EC_SESSION(handle), param_backup);
    return ret;
}

int gstor_restore(void *handle, const char *restore_path, const char *old_path, const char *new_path)
{
    knl_session_t *session = (knl_session_t *)EC_SESSION(handle);
    knl_attr_t *attr = &session->kernel->attr;
    int ret = GS_SUCCESS;

    if (old_path == NULL || new_path == NULL) {
        GS_LOG_RUN_INF("old_path or new_path null, no need convert_restore_path!");
    } else {
        char convert_value[GS_FILE_NAME_BUFFER_SIZE * 2] = {0};
        const int buffer_size = GS_FILE_NAME_BUFFER_SIZE * 2;
        PRTS_RETURN_IFERR(snprintf_s(convert_value, buffer_size, buffer_size - 1, "%s,%s", old_path, new_path));

        ret = knl_get_convert_params("DB_FILE_NAME_CONVERT", convert_value, &attr->data_file_convert, "home");
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("gstor DB_FILE_NAME_CONVERT failed with retcode(%d)!", ret);
            return GS_ERROR;
        }

        ret = knl_get_convert_params("LOG_FILE_NAME_CONVERT", convert_value, &attr->log_file_convert, "home");
        if (ret != GS_SUCCESS) {
            GS_LOG_RUN_ERR("gstor LOG_FILE_NAME_CONVERT failed with retcode(%d)!", ret);
            return GS_ERROR;
        }
        GS_LOG_RUN_INF("gstor convert_restore_path success, convert_value=%s", convert_value);
    }

    knl_restore_t restore = { 0 };
    knl_restore_t *param_restore = &restore;
    param_restore->type = RESTORE_FROM_PATH;
    param_restore->device = DEVICE_DISK;
    param_restore->path.str = (char *)restore_path;
    param_restore->path.len = strlen(restore_path);
    param_restore->file_type = RESTORE_ALL;
    param_restore->crypt_info.encrypt_alg = ENCRYPT_NONE;
    if (EC_SESSION(handle)->kernel->db.status != DB_STATUS_NOMOUNT) {
        GS_LOG_RUN_ERR("gstore restore failed since db status(%d) not DB_STATUS_NOMOUNT!",
            EC_SESSION(handle)->kernel->db.status);
        return GS_ERROR;
    }

    ret = knl_restore(EC_SESSION(handle), param_restore);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("gstore restore failed with retcode(%d)!", ret);
        return GS_ERROR;
    }

    knl_recover_t recover = { 0 };
    recover.action = RECOVER_NORMAL;
    ret = knl_recover(EC_SESSION(handle), &recover);
    if (ret != GS_SUCCESS) {
        GS_LOG_RUN_ERR("gstore recover failed with retcode(%d)!", ret);
    }
    return ret;
}

#ifdef __cplusplus
}
#endif
