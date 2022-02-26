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
 * cm_key_word.h
 *    APIs of keyword management
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_key_word.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_KEY_WORD_H__
#define __CM_KEY_WORD_H__

#ifdef __cplusplus
extern "C" {
#endif


// 20000 is used for GS_TYPE_BASE in cm_defs.h
#define SQL_KEY_WORD_BASE 10000

#define SQL_RESERVED_WORD_BASE 30000

#define PL_ATTR_WORD_BASE 100000

typedef enum en_key_wid {
    /* NOTE: 1. unknown key word, it is used as an initial value and the base for SQL keywords
             2. the keyword must be arranged by alphabetical ascending order!!! */
    KEY_WORD_0_UNKNOWN = SQL_KEY_WORD_BASE,
    KEY_WORD_ABORT = KEY_WORD_0_UNKNOWN + 1,
    KEY_WORD_ACCOUNT,
    KEY_WORD_ACTIVATE,
    KEY_WORD_ACTIVE,
    KEY_WORD_ADD,
    KEY_WORD_AFTER,
    KEY_WORD_ALL,
    KEY_WORD_ALTER,
    KEY_WORD_ANALYZE,
    KEY_WORD_AND,
    KEY_WORD_ANY,
    KEY_WORD_APPENDONLY,
    KEY_WORD_ARCHIVE,
    KEY_WORD_ARCHIVELOG,
    KEY_WORD_AS,
    KEY_WORD_ASC,
    KEY_WORD_ASYNC,
    KEY_WORD_AUDIT,
    KEY_WORD_AUTO_INCREMENT,
    KEY_WORD_AUTOALLOCATE,
    KEY_WORD_AUTOEXTEND,
    KEY_WORD_AUTOMATIC,
    KEY_WORD_AUTOPURGE,
    KEY_WORD_AUTON_TRANS,
    KEY_WORD_AUTOOFFLINE,
    KEY_WORD_AVAILABILITY,
    KEY_WORD_BACKUP,
    KEY_WORD_BACKUPSET,
    KEY_WORD_BEFORE,
    KEY_WORD_BEGIN,
    KEY_WORD_BETWEEN,
    KEY_WORD_BODY,
    KEY_WORD_BOTH, /* for TRIM expression only */
    KEY_WORD_BUFFER,
    KEY_WORD_BUILD,
    KEY_WORD_BULK,
    KEY_WORD_BY,
    KEY_WORD_CACHE,
    KEY_WORD_CALL,
    KEY_WORD_CANCEL,
    KEY_WORD_CASCADE,
    KEY_WORD_CASCADED,
    KEY_WORD_CASE,
    KEY_WORD_CAST,
    KEY_WORD_CATALOG,
    KEY_WORD_CHARACTER,
    KEY_WORD_CHARSET,
    KEY_WORD_CHECK,
    KEY_WORD_CHECKPOINT,
    KEY_WORD_CLOSE,
    KEY_WORD_COALESCE,
    KEY_WORD_COLLATE,
    KEY_WORD_COLUMN,
    KEY_WORD_COLUMNS,
    KEY_WORD_COLUMN_VALUE,
    KEY_WORD_COMMENT,
    KEY_WORD_COMMIT,
    KEY_WORD_COMPRESS,
    KEY_WORD_CONFIG,
    KEY_WORD_CONNECT,
    KEY_WORD_CONSISTENCY,
    KEY_WORD_CONSTRAINT,
    KEY_WORD_CONTENT,
    KEY_WORD_CONTROLFILE,
    KEY_WORD_CONTINUE,
    KEY_WORD_CONVERT,
    KEY_WORD_COPY,
    KEY_WORD_CREATE,
    KEY_WORD_CRMODE,
    KEY_WORD_CROSS,
    KEY_WORD_CTRLFILE,
    KEY_WORD_CUMULATIVE,
    KEY_WORD_CURRENT,
    KEY_WORD_CURRVAL,
    KEY_WORD_CURSOR,
    KEY_WORD_CYCLE,
    KEY_WORD_DATA,
    KEY_WORD_DATABASE,
    KEY_WORD_DATAFILE,
    KEY_WORD_DEBUG,
    KEY_WORD_DECLARE,
    KEY_WORD_DEFERRABLE, /* for constraint state */
    KEY_WORD_DELETE,
    KEY_WORD_DESC,
    KEY_WORD_DICTIONARY,
    KEY_WORD_DIRECTORY,
    KEY_WORD_DISABLE,
    KEY_WORD_DISCARD,
    KEY_WORD_DISCONNECT,
    KEY_WORD_DISTINCT,
    KEY_WORD_DISTRIBUTE,
    KEY_WORD_DO,
    KEY_WORD_DROP,
    KEY_WORD_DUMP,
    KEY_WORD_DUPLICATE,
    KEY_WORD_ELSE,
    KEY_WORD_ELSIF,
    KEY_WORD_ENABLE,
    KEY_WORD_ENABLE_LOGIC_REPLICATION,
    KEY_WORD_ENCRYPTION,
    KEY_WORD_END,
    KEY_WORD_ERROR,
    KEY_WORD_ESCAPE,
    KEY_WORD_EXCEPT,
    KEY_WORD_EXCEPTION,
    KEY_WORD_EXCLUDE,
    KEY_WORD_EXEC,
    KEY_WORD_EXECUTE,
    KEY_WORD_EXISTS,
    KEY_WORD_EXIT,
    KEY_WORD_EXPLAIN,
    KEY_WORD_EXTENT,
    KEY_WORD_FAILOVER,
    KEY_WORD_FETCH,
    KEY_WORD_FILE,
    KEY_WORD_FILETYPE,
    KEY_WORD_FINAL,
    KEY_WORD_FINISH,
    KEY_WORD_FLASHBACK,
    KEY_WORD_FLUSH,
    KEY_WORD_FOLLOWING,
    KEY_WORD_FOR,
    KEY_WORD_FORALL,
    KEY_WORD_FORCE,
    KEY_WORD_FOREIGN,
    KEY_WORD_FORMAT,
    KEY_WORD_FROM,
    KEY_WORD_FULL,
    KEY_WORD_FUNCTION,
    KEY_WORD_GLOBAL,
    KEY_WORD_GOTO,
    KEY_WORD_GRANT,
    KEY_WORD_GROUP,
    KEY_WORD_GROUPID,
    KEY_WORD_HASH,
    KEY_WORD_HAVING,
    KEY_WORD_IDENTIFIED,
    KEY_WORD_IF,
    KEY_WORD_IGNORE,
    KEY_WORD_IN,
    KEY_WORD_INCLUDE,
    KEY_WORD_INCLUDING,
    KEY_WORD_INCREMENT,
    KEY_WORD_INCREMENTAL,
    KEY_WORD_INDEX,
    KEY_WORD_INDEXCLUSTER,
    KEY_WORD_INDEX_ASC,
    KEY_WORD_INDEX_DESC,
    KEY_WORD_INIT,
    KEY_WORD_INITIAL,
    KEY_WORD_INITIALLY, /* for constraint state */
    KEY_WORD_INITRANS,
    KEY_WORD_INNER,
    KEY_WORD_INSERT,
    KEY_WORD_INSTANCE,
    KEY_WORD_INSTANTIABLE,
    KEY_WORD_INSTEAD,
    KEY_WORD_INTERSECT,
    KEY_WORD_INTO,
    KEY_WORD_INVALIDATE,
    KEY_WORD_IS,
    KEY_WORD_IS_NOT,
    KEY_WORD_JOIN,
    KEY_WORD_JSON,
    KEY_WORD_JSON_TABLE,
    KEY_WORD_KEEP,
    KEY_WORD_KEY,
    KEY_WORD_KILL,
    KEY_WORD_LANGUAGE,
    KEY_WORD_LEADING, /* for TRIM expression only */
    KEY_WORD_LEFT,
    KEY_WORD_LESS,
    KEY_WORD_LEVEL,
    KEY_WORD_LIBRARY,
    KEY_WORD_LIKE,
    KEY_WORD_LIMIT,
    KEY_WORD_LIST,
    KEY_WORD_LNNVL,
    KEY_WORD_LOAD,
    KEY_WORD_LOB,
    KEY_WORD_LOCAL,
    KEY_WORD_LOCK,
    KEY_WORD_LOCK_WAIT,
    KEY_WORD_LOG,
    KEY_WORD_LOGFILE,
    KEY_WORD_LOGGING,
    KEY_WORD_LOGICAL,
    KEY_WORD_LOOP,
    KEY_WORD_MANAGED,
    KEY_WORD_MAXIMIZE,
    KEY_WORD_MAXSIZE,
    KEY_WORD_MAXTRANS,
    KEY_WORD_MAXVALUE,
    KEY_WORD_MEMBER,
    KEY_WORD_MEMORY,
    KEY_WORD_MERGE,
    KEY_WORD_MINUS,
    KEY_WORD_MINVALUE,
    KEY_WORD_MODE,
    KEY_WORD_MODIFY,
    KEY_WORD_MONITOR,
    KEY_WORD_MOUNT,
    KEY_WORD_MOVE,
    KEY_WORD_NEXT,
    KEY_WORD_NEXTVAL,
    KEY_WORD_NOARCHIVELOG,
    KEY_WORD_NO_CACHE,
    KEY_WORD_NO_COMPRESS,
    KEY_WORD_NO_CYCLE,
    KEY_WORD_NODE,
    KEY_WORD_NO_LOGGING,
    KEY_WORD_NO_MAXVALUE,
    KEY_WORD_NO_MINVALUE,
    KEY_WORD_NO_ORDER,
    KEY_WORD_NO_RELY, /* for constraint state */
    KEY_WORD_NOT,
    KEY_WORD_NO_VALIDATE, /* for constraint state */
    KEY_WORD_NOWAIT,
    KEY_WORD_NULL,
    KEY_WORD_NULLS,
    KEY_WORD_OF,
    KEY_WORD_OFF,
    KEY_WORD_OFFLINE,
    KEY_WORD_OFFSET,
    KEY_WORD_ON,
    KEY_WORD_ONLINE,
    KEY_WORD_ONLY,
    KEY_WORD_OPEN,
    KEY_WORD_OR,
    KEY_WORD_ORDER,
    KEY_WORD_ORGANIZATION,
    KEY_WORD_OUTER,
    KEY_WORD_PACKAGE,
    KEY_WORD_PARALLEL,
    KEY_WORD_PARALLELISM,
    KEY_WORD_PARAM,
    KEY_WORD_PARTITION,
    KEY_WORD_PASSWORD,
    KEY_WORD_PATH,
    KEY_WORD_PCTFREE,
    KEY_WORD_PERFORMANCE,
    KEY_WORD_PHYSICAL,
    KEY_WORD_PIVOT,
    KEY_WORD_PLAN,
    KEY_WORD_PRAGMA,
    KEY_WORD_PRECEDING,
    KEY_WORD_PREPARE,
    KEY_WORD_PREPARED,
    KEY_WORD_PRESERVE,
    KEY_WORD_PRIMARY,
    KEY_WORD_PRIOR,
    KEY_WORD_PRIVILEGES,
    KEY_WORD_PROCEDURE,
    KEY_WORD_PROFILE,
    KEY_WORD_PROTECTION,
    KEY_WORD_PUBLIC,
    KEY_WORD_PUNCH,
    KEY_WORD_PURGE,
    KEY_WORD_QUERY,
    KEY_WORD_RAISE,
    KEY_WORD_RANGE,
    KEY_WORD_READ,
    KEY_WORD_READ_ONLY,
    KEY_WORD_READ_WRITE,
    KEY_WORD_REBUILD,
    KEY_WORD_RECOVER,
    KEY_WORD_RECYCLE,
    KEY_WORD_RECYCLEBIN,
    KEY_WORD_REDO,
    KEY_WORD_REFERENCES,
    KEY_WORD_REFRESH,
    KEY_WORD_REGEXP,
    KEY_WORD_REGEXP_LIKE,
    KEY_WORD_REGISTER,
    KEY_WORD_RELEASE,
    KEY_WORD_RELOAD,
    KEY_WORD_RELY,
    KEY_WORD_RENAME,
    KEY_WORD_REPAIR,
    KEY_WORD_REPLACE,
#ifdef Z_SHARDING
    KEY_WORD_REPLICATION,
#endif
    KEY_WORD_RESET,
    KEY_WORD_RESIZE,
    KEY_WORD_RESTORE,
    KEY_WORD_RESTRICT,
    KEY_WORD_RETURN,
    KEY_WORD_RETURNING,
    KEY_WORD_REUSE,
    KEY_WORD_REVOKE,
    KEY_WORD_RIGHT,
    KEY_WORD_ROLE,
    KEY_WORD_ROLLBACK,
    KEY_WORD_ROUTE,
    KEY_WORD_ROWS,
    KEY_WORD_SAVEPOINT,
    KEY_WORD_SCN,
    KEY_WORD_SECONDARY,
    KEY_WORD_SECTION,
    KEY_WORD_SELECT,
    KEY_WORD_SEPARATOR,
    KEY_WORD_SEQUENCE,
    KEY_WORD_SERIALIZABLE,
    KEY_WORD_SERVER,
    KEY_WORD_SESSION,
    KEY_WORD_SET,
    KEY_WORD_SHARE,
    KEY_WORD_SHOW,
    KEY_WORD_SHRINK,
    KEY_WORD_SHUTDOWN,
#ifdef DB_DEBUG_VERSION
    KEY_WORD_SIGNAL,
#endif /* DB_DEBUG_VERSION */
    KEY_WORD_SIZE,
    KEY_WORD_SKIP,
    KEY_WORD_SKIP_ADD_DROP_TABLE,
    KEY_WORD_SKIP_COMMENTS,
    KEY_WORD_SKIP_TRIGGERS,
    KEY_WORD_SKIP_QUOTE_NAMES,
    KEY_WORD_SPACE,
    KEY_WORD_SPLIT,
    KEY_WORD_SPLIT_FACTOR,
    KEY_WORD_SQL_MAP,
    KEY_WORD_STANDARD,
    KEY_WORD_STANDBY,
    KEY_WORD_START,
    KEY_WORD_STARTUP,
    KEY_WORD_STOP,
    KEY_WORD_STORAGE,
    KEY_WORD_SUBPARTITION,
    KEY_WORD_SWAP,
    KEY_WORD_SWITCH,
    KEY_WORD_SWITCHOVER,
#ifdef DB_DEBUG_VERSION
    KEY_WORD_SYNCPOINT,
#endif /* DB_DEBUG_VERSION */
    KEY_WORD_SYNONYM,
    KEY_WORD_SYSAUX,
    KEY_WORD_SYSTEM,
    KEY_WORD_TABLE,
    KEY_WORD_TABLES,
    KEY_WORD_TABLESPACE,
    KEY_WORD_TAG,
    KEY_WORD_TEMP,
    KEY_WORD_TEMPFILE,
    KEY_WORD_TEMPORARY,
    KEY_WORD_TENANT,
    KEY_WORD_THAN,
    KEY_WORD_THEN,
    KEY_WORD_THREAD,
    KEY_WORD_TIMEOUT,
    KEY_WORD_TIMEZONE,
    KEY_WORD_TO,
    KEY_WORD_TRAILING, /* for TRIM expression only */
    KEY_WORD_TRANSACTION,
    KEY_WORD_TRIGGER,
    KEY_WORD_TRUNCATE,
    KEY_WORD_TYPE,
    KEY_WORD_UNDO,
    KEY_WORD_UNIFORM,
    KEY_WORD_UNION,
    KEY_WORD_UNIQUE,
    KEY_WORD_UNLIMITED,
    KEY_WORD_UNLOCK,
    KEY_WORD_UNPIVOT,
    KEY_WORD_UNTIL,
    KEY_WORD_UNUSABLE,
    KEY_WORD_UPDATE,
    KEY_WORD_USER,
    KEY_WORD_USERS,
    KEY_WORD_USING,
    KEY_WORD_VALIDATE, /* for constraint state */
    KEY_WORD_VALUES,
    KEY_WORD_VIEW,
    KEY_WORD_WAIT,
    KEY_WORD_WHEN,
    KEY_WORD_WHERE,
    KEY_WORD_WHILE,
    KEY_WORD_WITH,

    KEY_WORD_DUMB_END,  // dumb key word, just for static assert
} key_wid_t;

typedef enum en_index_hint_key_wid {
    HINT_KEY_WORD_FULL = 0x00000001,
    HINT_KEY_WORD_INDEX = 0x00000002,
    HINT_KEY_WORD_NO_INDEX = 0x00000004,
    HINT_KEY_WORD_INDEX_ASC = 0x00000008,
    HINT_KEY_WORD_INDEX_DESC = 0x00000010,
    HINT_KEY_WORD_INDEX_FFS = 0x00000020,
    HINT_KEY_WORD_NO_INDEX_FFS = 0x00000040,
} index_hint_key_wid_t;

typedef enum en_join_hint_key_wid {
    // join order
    HINT_KEY_WORD_LEADING = 0x00000001,
    HINT_KEY_WORD_ORDERED = 0x00000002,
    // join method
    HINT_KEY_WORD_USE_NL = 0x00000004,
    HINT_KEY_WORD_USE_MERGE = 0x00000008,
    HINT_KEY_WORD_USE_HASH = 0x00000010,
} join_hint_key_wid_t;

typedef enum en_optim_hint_key_wid {
    // rbo
    HINT_KEY_WORD_RULE = 0x00000001,
    HINT_KEY_WORD_PARALLEL = 0x00000002,
    /* insert hints below */
    HINT_KEY_WORD_HASH_BUCKET_SIZE = 0x00000004,
    /* replace hints below */
    HINT_KEY_WORD_THROW_DUPLICATE = 0x00000008,
    /* withas hints below */
    HINT_KEY_WORD_INLINE = 0x00000010,
    HINT_KEY_WORD_MATERIALIZE = 0x00000020,
    /* or expand hints below */
    HINT_KEY_WORD_NO_OR_EXPAND = 0x00000040,
} optim_hint_key_wid_t;

typedef enum en_shard_hint_key_wid {
    // from subquery pullup
    HINT_KEY_WORD_SQL_WHITELIST = 0x00000001,
    HINT_KEY_WORD_SHD_READ_MASTER = 0x00000002,
} shard_hint_key_wid_t;

// the value must be the same as the sequence of g_hints.
typedef enum en_hint_id {
    ID_HINT_FULL = 0,
    ID_HINT_INDEX,
    ID_HINT_INDEX_ASC,
    ID_HINT_INDEX_DESC,
    ID_HINT_INDEX_FFS,
    ID_HINT_NO_INDEX,
    ID_HINT_NO_INDEX_FFS,
    ID_HINT_LEADING,
    // the hint with parameters needs to be added to args in hint_info and placed above id_hint_rule.
    // otherwise, it must be placed under id_hint_rule.
    ID_HINT_RULE,              // the max number of hint with parameters
    ID_HINT_ORDERED,           // use the same arg as leading
    ID_HINT_PARALLEL,          // stmt->context->parallel
    ID_HINT_HASH_BUCKET_SIZE,  // stmt->context->hash_bucket_size
    ID_HINT_USE_HASH,
    ID_HINT_USE_MERGE,
    ID_HINT_USE_NL,
    ID_HINT_NO_OR_EXPAND,
    ID_HINT_INLINE,
    ID_HINT_MATERIALIZE,
    ID_HINT_THROW_DUPLICATE,
#ifdef Z_SHARDING
    ID_HINT_SHD_READ_MASTER,
    ID_HINT_SQL_WHITELIST,
#endif
} hint_id_t;

typedef enum en_hint_type {
    INDEX_HINT = 0,
    JOIN_HINT,
    OPTIM_HINT,
    SHARD_HINT,
    MAX_HINT_TYPE,
} hint_type_t;

#ifdef __cplusplus
}
#endif

#endif