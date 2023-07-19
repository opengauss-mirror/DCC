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
 * cm_log.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_LOG_H__
#define __CM_LOG_H__

#include "cm_defs.h"
#include "cm_spinlock.h"

typedef enum en_log_level {
    LEVEL_ERROR = 0,  // error conditions
    LEVEL_WARN,       // warning conditions
    LEVEL_INFO,       // informational messages
} log_level_t;

typedef enum en_log_id {
    LOG_RUN = 0,
    LOG_DEBUG,
    LOG_ALARM,
    LOG_AUDIT,
    LOG_RAFT,
    LOG_LONGSQL,
    LOG_OPER,
    LOG_ZENCRYPT_OPER,
    LOG_TRACE,
    LOG_OPTINFO,
    LOG_BLACKBOX,
    LOG_ODBC,
    LOG_COUNT  // LOG COUNT
} log_id_t;

// define audit trail mode
#define AUDIT_TRAIL_NONE    (uint8)0
#define AUDIT_TRAIL_FILE    (uint8)1
#define AUDIT_TRAIL_DB      (uint8)2
#define AUDIT_TRAIL_SYSLOG  (uint8)4
#define AUDIT_TRAIL_ALL     (uint8)255

typedef struct st_audit_log_param {
    uint32 audit_level;
    uint8 audit_trail_mode;
    uint8 syslog_facility; // refer to openlog.facility
    uint8 syslog_level; // refer to syslog.level
    uint8 reserved;
} audit_log_param_t;

typedef struct st_log_param {
    char log_home[GS_MAX_PATH_BUFFER_SIZE];
    uint32 log_file_permissions;
    uint32 log_bak_file_permissions;
    uint32 log_path_permissions;
    uint32 log_level;
    uint32 log_backup_file_count;
    uint32 audit_backup_file_count;
    uint64 max_log_file_size;
    uint64 max_audit_file_size;
    uint64 max_pbl_file_size;
    uint64 longsql_timeout;
    char instance_name[GS_MAX_NAME_LEN];
    audit_log_param_t audit_param;
    bool8 log_instance_startup;
    bool8 longsql_print_enable;
    uint8 reserved[2];
} log_param_t;

// if you add new audit level, need add to DDL_AUDIT_ALL
#define SQL_AUDIT_DDL 0x00000001
#define SQL_AUDIT_DCL 0x00000002
#define SQL_AUDIT_DML 0x00000004
#define SQL_AUDIT_PL  0x00000008
#define SQL_AUDIT_PARAM  0x00000010
#define SQL_AUDIT_ALL 0xffffffff

#define LOG_RUN_ERR_ON   (cm_log_param_instance()->log_level & (LOG_RUN_ERR_LEVEL))
#define LOG_RUN_WAR_ON   (cm_log_param_instance()->log_level & (LOG_RUN_WAR_LEVEL))
#define LOG_RUN_INF_ON   (cm_log_param_instance()->log_level & (LOG_RUN_INF_LEVEL))
#define LOG_DEBUG_ERR_ON (cm_log_param_instance()->log_level & (LOG_DEBUG_ERR_LEVEL))
#define LOG_DEBUG_WAR_ON (cm_log_param_instance()->log_level & (LOG_DEBUG_WAR_LEVEL))
#define LOG_DEBUG_INF_ON (cm_log_param_instance()->log_level & (LOG_DEBUG_INF_LEVEL))
#define LOG_LONGSQL_ON   (cm_log_param_instance()->log_level & (LOG_LONGSQL_LEVEL))
#define LOG_OPER_ON      (cm_log_param_instance()->log_level & (LOG_OPER_LEVEL))
#define LOG_ODBC_ERR_ON  (cm_log_param_instance()->log_level & (LOG_ODBC_ERR_LEVEL))
#define LOG_ODBC_WAR_ON  (cm_log_param_instance()->log_level & (LOG_ODBC_WAR_LEVEL))
#define LOG_ODBC_INF_ON  (cm_log_param_instance()->log_level & (LOG_ODBC_INF_LEVEL))

// 0x00010000 ~ 0x00800000 reserved for DTC
#define DTC_MES_LOG_INF_ON      (cm_log_param_instance()->log_level & 0x00100000)  // 1048576
#define DTC_MES_LOG_ERR_ON      (cm_log_param_instance()->log_level & 0x00200000)  // 2097152

#define LOG_ON (cm_log_param_instance()->log_level > 0)

typedef struct st_log_file_handle {
    spinlock_t lock;
    char file_name[GS_FILE_NAME_BUFFER_SIZE];  // log file with the path
    int file_handle;
    uint32 file_inode;
    log_id_t log_id;
} log_file_handle_t;

typedef void (*cm_log_write_func_t)(log_file_handle_t *log_file_handle, char *buf, uint32 size);

#define GS_MIN_LOG_FILE_SIZE        SIZE_M(1)                  // this value can not be less than 1M
#define GS_MAX_LOG_FILE_SIZE        ((uint64)SIZE_M(1024) * 4) // this value can not be larger than 4G
#define GS_MAX_LOG_FILE_COUNT       128                        // this value can not be larger than 128
#define GS_MAX_LOG_CONTENT_LENGTH   GS_MESSAGE_BUFFER_SIZE
#define GS_LOG_LONGSQL_LENGTH_16K   SIZE_K(16)
#define GS_MAX_LOG_HEAD_LENGTH      100     // UTC+8 2019-01-16 22:40:15.292|ZENGINE|00000|140084283451136|INFO> 65
#define GS_MAX_LOG_NEW_BUFFER_SIZE  1048576 // (1024 * 1024)
#define GS_MAX_LOG_PERMISSIONS      777
#define GS_DEF_LOG_PATH_PERMISSIONS 700
#define GS_DEF_LOG_FILE_PERMISSIONS 600
#define GS_MAX_LOG_LONGSQL_LENGTH   1056768

log_file_handle_t *cm_log_logger_file(uint32 log_count);
log_param_t *cm_log_param_instance();
void cm_log_set_session_id(uint32 sess_id);
void cm_log_init(log_id_t log_id, const char *file_name);
void cm_log_set_path_permissions(uint16 val);
void cm_log_set_file_permissions(uint16 val);
void cm_log_open_file(log_file_handle_t *log_file_handle);
status_t cm_log_get_bak_file_list(
    char *backup_file_name[GS_MAX_LOG_FILE_COUNT], uint32 *backup_file_count, const char *log_file);

void cm_write_optinfo_log(const char *format, ...) GS_CHECK_FMT(1, 2);
void cm_write_longsql_log(const char *format, ...) GS_CHECK_FMT(1, 2);
void cm_write_max_longsql_log(const char *format, ...) GS_CHECK_FMT(1, 2);
void cm_write_audit_log(const char *format, ...) GS_CHECK_FMT(1, 2);
void cm_write_alarm_log(uint32 warn_id, const char *format, ...) GS_CHECK_FMT(2, 3);
void cm_write_alarm_log_cn(uint32 warn_id, const char *format, ...) GS_CHECK_FMT(2, 3);
void cm_write_blackbox_log(const char *format, ...) GS_CHECK_FMT(1, 2);

void cm_write_normal_log(log_id_t log_id, log_level_t log_level, const char *code_file_name, uint32 code_line_num,
    const char *module_name, bool32 need_rec_filelog, const char *format, ...) GS_CHECK_FMT(7, 8);
void cm_write_oper_log(char *buf, uint32 len);
void cm_write_trace_log(const char *format, ...);
void cm_fync_logfile();
void cm_write_pe_oper_log(char *buf, uint32 len);
void cm_print_call_link(uint32 stack_depth);
void cm_log_allinit();

#define MODULE_NAME "ZENGINE"

#define GS_LOG_DEBUG_INF(format, ...)                                                                            \
    do {                                                                                                         \
        if (LOG_DEBUG_INF_ON) {                                                                                  \
            cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME, GS_TRUE, \
                format, ##__VA_ARGS__);                                                                          \
        }                                                                                                        \
    } while (0)
    
#define GS_LOG_DEBUG_WAR(format, ...)                                                                            \
    do {                                                                                                         \
        if (LOG_DEBUG_WAR_ON) {                                                                                  \
            cm_write_normal_log(LOG_DEBUG, LEVEL_WARN, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME, GS_TRUE, \
                format, ##__VA_ARGS__);                                                                          \
        }                                                                                                        \
    } while (0)
#define GS_LOG_DEBUG_ERR(format, ...)                                                                             \
    do {                                                                                                          \
        if (LOG_DEBUG_ERR_ON) {                                                                                   \
            cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME, GS_TRUE, \
                format, ##__VA_ARGS__);                                                                           \
        }                                                                                                         \
    } while (0)

#define GS_LOG_RUN_INF(format, ...)                                                                             \
    do {                                                                                                        \
        if (LOG_RUN_INF_ON) {                                                                                   \
            cm_write_normal_log(LOG_RUN, LEVEL_INFO, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME, GS_TRUE,  \
                format, ##__VA_ARGS__);                                                                         \
        }                                                                                                       \
    } while (0)
#define GS_LOG_RUN_WAR(format, ...)                                                                             \
    do {                                                                                                        \
        if (LOG_RUN_WAR_ON) {                                                                                   \
            cm_write_normal_log(LOG_RUN, LEVEL_WARN, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME, GS_TRUE,  \
                format, ##__VA_ARGS__);                                                                         \
        }                                                                                                       \
    } while (0)
#define GS_LOG_RUN_ERR(format, ...)                                                                             \
    do {                                                                                                        \
        if (LOG_RUN_ERR_ON) {                                                                                   \
            cm_write_normal_log(LOG_RUN, LEVEL_ERROR, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME, GS_TRUE, \
                format, ##__VA_ARGS__);                                                                         \
        }                                                                                                       \
    } while (0)

#define GS_LOG_AUDIT(format, ...) cm_write_audit_log(format, ##__VA_ARGS__)

#define GS_LOG_ALARM(warn_id, format, ...)                                  \
    do {                                                                    \
        if (LOG_ON) {                                                       \
            cm_write_alarm_log(warn_id, format"|1", ##__VA_ARGS__);         \
        }                                                                   \
    } while (0)

#define GS_LOG_ALARM_CN(warn_id, format, ...)                                  \
    do {                                                                    \
        if (LOG_ON) {                                                       \
            cm_write_alarm_log_cn(warn_id, format"|1", ##__VA_ARGS__);         \
        }                                                                   \
    } while (0)

#define GS_LOG_ALARM_RECOVER(warn_id, format, ...)                          \
    do {                                                                    \
        if (LOG_ON) {                                                       \
            cm_write_alarm_log(warn_id, format"|2", ##__VA_ARGS__);         \
        }                                                                   \
    } while (0)

#define GS_LOG_ALARM_RECOVER_CN(warn_id, format, ...)                          \
    do {                                                                    \
        if (LOG_ON) {                                                       \
            cm_write_alarm_log_cn(warn_id, format"|2", ##__VA_ARGS__);         \
        }                                                                   \
    } while (0)

#define GS_LOG_RAFT(level, format, ...)                                                                                \
    do {                                                                                                        \
        if (LOG_ON) {                                                                                           \
            cm_write_normal_log(LOG_RAFT, level, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME, GS_TRUE, \
                format, ##__VA_ARGS__);                                                                         \
        }                                                                                                       \
    } while (0)
#define GS_LOG_LONGSQL(sql_length, format, ...)              \
    do {                                                     \
        if (sql_length < 8192) {                             \
            cm_write_longsql_log(format, ##__VA_ARGS__);     \
        } else {                                             \
            cm_write_max_longsql_log(format, ##__VA_ARGS__); \
        }                                                    \
    } while (0)

#define GS_LOG_TRACE(format, ...)        cm_write_trace_log(format, ##__VA_ARGS__)
#define GS_LOG_OPTINFO(format, ...) cm_write_normal_log(LOG_OPTINFO, LEVEL_INFO, (char *)__FILE_NAME__,    \
            (uint32)__LINE__, MODULE_NAME, GS_TRUE, format, ##__VA_ARGS__)

/* no need to print error info in file add/remove log  */
#define GS_LOG_RUN_FILE_INF(need_record_file_log, format, ...)                                           \
    do {                                                                                                 \
        if (LOG_RUN_INF_ON) {                                                                            \
            cm_write_normal_log(LOG_RUN, LEVEL_INFO, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME,    \
                need_record_file_log, format, ##__VA_ARGS__);                                            \
        }                                                                                                \
    } while (0);

/* BLACKBOX LOG PRINT ONLY CALL IN BLACKBOX MODUEL */
#define GS_LOG_BLACKBOX(format, ...)                                           \
    do {                                                                       \
        if (LOG_ON) {                                                          \
            cm_write_blackbox_log(format, ##__VA_ARGS__);                      \
        }                                                                      \
    } while (0)

#define ODBC_MOD_NAME "ODBC"

#define GS_LOG_ODBC_INF(format, ...)                                                                               \
    do {                                                                                                           \
        if (LOG_ODBC_INF_ON) {                                                                                      \
            cm_write_normal_log(LOG_ODBC, LEVEL_INFO, (char *)__FILE_NAME__, (uint32)__LINE__, ODBC_MOD_NAME, GS_FALSE, \
                format, ##__VA_ARGS__);                                                                            \
        }                                                                                                          \
    } while (0)

#define GS_LOG_ODBC_WAR(format, ...)                                                                               \
    do {                                                                                                           \
        if (LOG_ODBC_WAR_ON) {                                                                                      \
            cm_write_normal_log(LOG_ODBC, LEVEL_WARN, (char *)__FILE_NAME__, (uint32)__LINE__, ODBC_MOD_NAME, GS_FALSE, \
                format, ##__VA_ARGS__);                                                                            \
        }                                                                                                          \
    } while (0)

#define GS_LOG_ODBC_ERR(format, ...)                                                                                \
    do {                                                                                                            \
        if (LOG_ODBC_ERR_ON) {                                                                                       \
            cm_write_normal_log(LOG_ODBC, LEVEL_ERROR, (char *)__FILE_NAME__, (uint32)__LINE__, ODBC_MOD_NAME, GS_FALSE, \
                format, ##__VA_ARGS__);                                                                             \
        }                                                                                                           \
    } while (0)

void cm_dump_mem(void *dump_addr, uint32 dump_len);

#define GS_UTIL_DUMP_MEM(msg, size) cm_dump_mem((msg), (size))


/*
 * warning id is composed of source + module + object + code
 * source -- DN(10)/CM(11)/OM(12)/DM(20)
 * module -- File(01)/Transaction(02)/HA(03)/Log(04)/Buffer(05)/Space(06)/Server(07)
 * object -- Host Resource(01)/Run Environment(02)/Cluster Status(03)/
 *           Instance Status(04)/Database Status(05)/Database Object(06)
 * code   -- 0001 and so on
 */
/* 
 * one warn must modify  warn_id_t
 *                       warn_name_t
 *                       g_warn_id
 *                       g_warning_desc               
 */
typedef enum st_warn_id {
    WARN_FILEDESC_ID = 1001010001,
    WARN_DEADLOCK_ID = 1002050001,
    WARN_DEGRADE_ID = 1003050001,
    WARN_REPL_PASSWD_ID = 1003050002,
    WARN_JOB_ID = 1007060001,
    WARN_AGENT_ID = 1007050001,
    WARN_MAXCONNECTIONS_ID = 1007050002,
    WARN_ARCHIVE_ID = 1004060001,
    WARN_FLUSHREDO_ID = 1004060002,
    WARN_FLUSHBUFFER_ID = 1005060001,
    WARN_SPACEUSAGE_ID = 1006060001,
    WARN_FILEMONITOR_ID = 1001060001,
    WARN_MALICIOUSLOGIN_ID = 1007050003,
    WARN_PARAMCHANGE_ID = 1007050004,
    WARN_PASSWDCHANGE_ID = 1007050005,
    WARN_PROFILECHANGE_ID = 1007050006,
    WARN_AUDITLOG_ID = 1004060003,
    WARN_PAGE_CORRUPTED_ID = 1001060002,
    WARN_UNDO_USAGE_ID = 1006060002,
    WARN_NOLOG_OBJ_ID = 1007060002,
}warn_id_t;

typedef enum st_warn_name {
    WARN_FILEDESC,          /* Too many open files in %s */
    WARN_DEADLOCK,          /* Deadlock detected in %s */
    WARN_DEGRADE,           /* LNS(%s:%u) changed to temporary asynchronous in %s */
    WARN_REPL_PASSWD,       /* Replication password has been changed, please generate keys and cipher manually on %s */
    WARN_JOB,               /* Job %lld failed, error message %s */
    WARN_AGENT,             /* Attach dedicate agent failed. sid = %d */
    WARN_MAXCONNECTIONS,    /* Session has exceeded maximum connections %u */
    WARN_ARCHIVE,           /* Failed to archive redo file %s */
    WARN_FLUSHREDO,         /* Failed to flush redo file %s */
    WARN_FLUSHBUFFER,       /* %s failed to flush datafile */
    WARN_SPACEUSAGE,        /* Available data space in tablespace %s has already been up to %d percent of total space */
    WARN_FILEMONITOR,       /* File %s has been removed or moved on disk unexpectedly */
    WARN_MALICIOUSLOGIN,    /* Ip %s failed to log in multiple times in succession. */
    WARN_PARAMCHANGE,    /* Parameter of %s has been changed */
    WARN_PASSWDCHANGE,   /* User password of %s has been changed */
    WARN_PROFILECHANGE,  /* Profile of %s has been changed */
    WARN_AUDITLOG,          /* Failed to write audit log in %s */
    WARN_PAGECORRUPTED,     /* page %s, %s, %s is corrupted */
    WARN_UNDO_USAGE,        /* The undo space size of has been used %s has already been up to %d percent of total undo size */
    WARN_NOLOG_OBJ,         /* Nolog object found in %s */
}warn_name_t;

#endif


