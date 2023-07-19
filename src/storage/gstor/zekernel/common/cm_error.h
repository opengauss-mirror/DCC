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
 * cm_error.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_error.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ERROR_H_
#define __CM_ERROR_H_

#include "cm_types.h"
#include "cm_defs.h"
#include <stdarg.h>


/*
 * @Note
 *   when you added a new errno for kernel, please think it over
 *   whether it is necessary to map the new errno to a standard SQLState.
 *
 *   Attention1: add error code to the corresponding range
 *
 *   ERROR                                  |   RANGE
 *   OS errors                              |   1 - 99
 *   internal errors or common errors       |   100 - 199
 *   invalid configuration errors           |   200 - 299
 *   network errors                         |   300 - 399
 *   instance                               |   400 - 499
 *   client errors                          |   500 - 599
 *   sql engine                             |   600 - 699(full), 1300 - 1399(additional)
 *   database                               |   700 - 899
 *   PL/SQL error                           |   900 - 999
 *   privilege error                        |   1000 - 1099
 *   partition error                        |   1100 - 1199
 *   sharding error                         |   1200 - 1299
 *
 *   Attention2: the following error codes have be relied on and can not be changed
 *   ERR_OPEN_FILE                   = 2,
 *   ERR_CREATE_FILE                 = 3,
 *   ERR_READ_FILE                   = 4,
 *   ERR_WRITE_FILE                  = 5,
 *   ERR_CREATE_DIR                  = 8,
 *   ERR_RENAME_FILE                 = 9,
 *   ERR_REMOVE_FILE                 = 10,
 *   ERR_SQL_SYNTAX_ERROR            = 601,
 *   ERR_COLUMN_NOT_NULL             = 620,
 *   ERR_CONSTRAINT_VIOLATED         = 641,
 *   ERR_TABLE_IS_REFERENCED         = 642,
 *   ERR_DEAD_LOCK                   = 716,
 *   ERR_LOCK_TIMEOUT                = 717,
 *   ERR_DUPLICATE_KEY               = 729,
 *   ERR_CONSTRAINT_VIOLATED_CHECK_FAILED  = 1222,
 *   ERR_CONSTRAINT_VIOLATED_NO_FOUND      = 1223,
 */
typedef enum en_errno {
    /* user define errors */
    ERR_MIN_USER_DEFINE_ERROR = -20999,
    ERR_MAX_USER_DEFINE_ERROR = -20000,

    ERR_ERRNO_BASE = 0,

    /* OS errors: 1 - 99 */
    ERR_ALLOC_MEMORY = 1,
    ERR_OPEN_FILE = 2,
    ERR_CREATE_FILE = 3,
    ERR_READ_FILE = 4,
    ERR_WRITE_FILE = 5,
    ERR_INVALID_FILE_NAME = 6,
    ERR_FILE_SIZE_MISMATCH = 7,
    ERR_CREATE_DIR = 8,
    ERR_RENAME_FILE = 9,
    ERR_REMOVE_FILE = 10,
    ERR_CREATE_THREAD = 11,
    ERR_INIT_THREAD = 12,
    ERR_SET_THREAD_STACKSIZE = 13,
    ERR_CREATE_SEMAPORE = 14,
    ERR_ATTACH_SEMAPORE = 15,
    ERR_CREATE_SHARED_MEMORY = 16,
    ERR_CREATE_EVENT = 17,
    ERR_LOAD_LIBRARY = 18,
    ERR_LOAD_SYMBOL = 19,
    ERR_INIT_SYSTEM = 20,
    ERR_GENERATE_GUID = 21,
    ERR_GENERATE_SHA1 = 22,
    ERR_FILE_ALREADY_EXIST = 23,
    ERR_INVALID_DIR = 24,
    ERR_FILE_PATH_TOO_LONG = 25,
    ERR_ALLOC_MEMORY_REACH_LIMIT = 26,
    ERR_STACK_LIMIT_EXCEED = 27,
    ERR_WRITE_FILE_PART_FINISH = 28,
    ERR_RESET_MEMORY = 29,
    ERR_READ_DEVICE_INCOMPLETE = 30,
    ERR_LOCK_LIMIT_EXCEED = 31,
    ERR_SEEK_FILE = 32,
    ERR_TRUNCATE_FILE = 33,
    ERR_FILE_HAS_EXIST = 34,
    ERR_LOCK_FILE = 35,
    ERR_PROC_BIND_CPU = 36,
    ERR_TOO_MANY_CPUS = 37,
    ERR_EXECUTE_FILE = 38,
    ERR_REMOVE_DIR = 39,
    ERR_UNLOCK_FILE = 40,
    ERR_FALLOCATE_FILE = 41,

    // 42 - 49 available
    ERR_SYSTEM_CALL = 50,
    ERR_DATAFILE_FSYNC = 51,
    ERR_DATAFILE_FDATASYNC = 52,
    ERR_DATAFILE_EXTEND_PARTIALLY = 53,
    ERR_SYSTEM_TIME = 54,
    ERR_READ_LONGSQL_FILE = 55,

    // 60 - 70 buddy memory error
    ERR_MEM_ZONE_INIT = 60,
    ERR_MEM_OUT_OF_MEMORY = 61,
    
    /* internal errors or common errors: 100 - 199 */
    ERR_CAPABILITY_NOT_SUPPORT = 101,
    ERR_OUT_OF_INDEX = 102,
    ERR_ALLOC_GA_MEMORY = 103,
    ERR_STACK_OVERFLOW = 104,
    ERR_TEXT_FORMAT_ERROR = 105,
    ERR_ROW_SIZE_TOO_LARGE = 106,
    ERR_BUFFER_OVERFLOW = 107,
    ERR_LOB_SIZE_TOO_LARGE = 108,
    ERR_MAX_COLUMN_SIZE = 109,
    ERR_ENCRYPTION_ERROR = 110,
    ERR_REUSED_PASSWORD_ERROR = 111,
    ERR_COMPRESS_INIT_ERROR = 112,
    ERR_COMPRESS_ERROR = 113,
    ERR_DECOMPRESS_ERROR = 114,
    ERR_EXECUTER_STACK_OVERFLOW = 115,
    ERR_STACK_OVERSPACE = 116,
    ERR_OBJECT_STACK_OVERDEPTH = 117,
    ERR_DECODE_ERROR = 118,
    ERR_MUTIPLE_FORMAT_ERROR = 119,
    ERR_UNRECOGNIZED_FORMAT_ERROR = 120,
    ERR_COVNERT_FORMAT_ERROR = 121,
    ERR_MALLOC_BYTES_MEMORY = 122,
    ERR_MALLOC_MAX_MEMORY = 123,
    ERR_BUFFER_UNDERFLOW = 124,
    // 124 available
    ERR_HASH_TABLE_TOO_LARGE = 125,
    ERR_DEVICE_NOT_SUPPORT = 127,
    ERR_PROTOCOL_NOT_SUPPORT = 128,
    ERR_INVALID_COMMAND = 129,
    ERR_OPERATIONS_NOT_SUPPORT = 130,
    ERR_MAX_PART_KEY = 131,
    ERR_WRITE_LOG_FAILED = 132,
    ERR_RAFT_MODULE_NOT_INITED = 133,
    ERR_ASSERT_ERROR = 134,
    ERR_COMPRESS_FREE_ERROR = 135,
    ERR_CRYPTION_ERROR = 136,
    ERR_ENCRYPTION_NOT_SUPPORT_DDL = 137,
    ERR_FAILED_PARALL_GATHER_STATS = 138,
    ERR_SYSTEM_BUSY = 139,

    /* invalid configuration errors: 200 - 299 */
    ERR_FILE_SIZE_TOO_LARGE = 200,
    ERR_INVALID_PARAMETER_NAME = 201,
    ERR_INVALID_PARAMETER = 202,
    ERR_ALTER_READONLY_PARAMETER = 203,
    ERR_CONFIG_BUFFER_FULL = 204,
    ERR_LINE_SIZE_TOO_LONG = 205,
    ERR_LL_SYNTAX_ERROR = 206,
    ERR_DUPLICATE_PARAMETER = 207,
    ERR_UNSUPPORTED_EMBEDDED_PARAMETER = 208,
    ERR_PARAMETER_TOO_SMALL = 209,
    ERR_PARAMETER_TOO_LARGE = 210,
    ERR_PARAMETER_OVER_RANGE = 211,
    ERR_INVALID_PARAMETER_ENUM = 212,
    ERR_PARAMETER_CANNOT_IGNORE = 213,
    ERR_INVALID_SYSINFO = 214,
    ERR_ASYNC_ONLY_PARAMETER = 215,
    ERR_UPDATE_PARAMETER_FAIL = 216,
    ERR_NLS_INTERNAL_ERROR = 217,
    ERR_LOG_ARCHIVE_CONFIG_TOO_MANY = 218,
    ERR_PARAMETER_NOT_MODIFIABLE = 219,
    ERR_INVALID_HBA_ITEM = 220,
    ERR_EXCEED_HBA_MAX_SIZE = 221,
    ERR_DUPLICATE_FILE = 222,
    ERR_RANDOM_GENERATE = 223,
    ERR_HBA_MOD_FAILED = 224,
    ERR_HBA_ITEM_NOT_FOUND = 225,
    ERR_PATH_NOT_EXIST_OR_ACCESSABLE = 229,
    ERR_PATH_NOT_EXIST = 230,
    ERR_PATH_NOT_ACCESSABLE = 231,
    ERR_CIPHER_NOT_SUPPORT = 232,
    ERR_EMPTY_STRING_NOT_ALLOWED = 233,
    ERR_FUNC_NULL_ARGUMENT = 240,
    ERR_FUNC_ARGUMENT_WRONG_TYPE = 241,
    ERR_FUNC_ARGUMENT_OUT_OF_RANGE = 242,
    ERR_FUNC_LOCATION = 243,
    ERR_INVALID_REGEXP_INSTR_PARAM = 245,
    ERR_INVALID_REGEXP_INSTR_PARAM_NO_OPT = 246,
    ERR_FUNC_ARG_NEEDED = 247,
    ERR_ANALYTIC_FUNC_NO_CLAUSE = 250,
    ERR_INVALID_SEPARATOR = 251,
    ERR_INVALID_TABFUNC_1ST_ARG = 252,
    ERR_NO_ORDER_BY_CLAUSE = 253,
    ERR_TCP_VALID_NODE_CHECKING = 254,
    ERR_TCP_NODE_EMPTY_CONFIG = 255,
    ERR_CMD_NOT_ALLOWED_TO_EXEC = 256,
    ERR_PATH_NOT_ALLOWED_TO_ACCESS = 257,
    ERR_LSNR_IP_DELETE_ERROR = 258,
    ERR_IPADDRESS_LOCAL_NOT_EXIST = 259,
    ERR_INVALID_REPL_PORT = 260,
    ERR_UNDO_TABLESPACE_NOT_MATCH = 261,
    ERR_RANDOM_INIT = 262,
    // 254 - 298 available
    ERR_GENERIC_INTERNAL_ERROR = 299, /* used for internal logical error, no message template */

    /* network errors: 300 - 399 */
    ERR_INIT_NETWORK_ENV = 301,
    ERR_PROTOCOL_INCOMPATIBALE = 302,
    ERR_ESTABLISH_TCP_CONNECTION = 303,
    ERR_PEER_CLOSED = 304,
    ERR_TCP_TIMEOUT = 305,
    ERR_INVALID_TCP_PACKET = 306,
    ERR_CREATE_SOCKET = 307,
    ERR_SET_SOCKET_OPTION = 308,
    ERR_TCP_PORT_CONFLICTED = 309,
    ERR_SOCKET_BIND = 310,
    ERR_SOCKET_LISTEN = 311,
    ERR_CREATE_AGENT = 312,
    ERR_INVALID_PROTOCOL = 313,
    ERR_SOCKET_TIMEOUT = 314,
    ERR_IPC_LSNR_CLOSED = 315,
    ERR_IPC_CONNECT_ERROR = 316,
    ERR_IPC_UNINITIALIZED = 317,
    ERR_IPC_PROCESS_NOT_EXISTS = 318,
    ERR_IPC_STARTUP = 319,
    ERR_GENERATE_CIPHER = 320,
    ERR_TCP_RECV = 321,
    ERR_SESSION_CLOSED = 322,
    ERR_PRI_NOT_CONNECT = 323,
    ERR_FULL_PACKET = 324,
    ERR_PACKET_READ = 325,
    ERR_REPLICA_AGENT = 326,
    ERR_PASSWORD_EXPIRED = 327,
    ERR_ACCOUNT_LOCK = 328,
    ERR_ACCOUNT_AUTH_FAILED = 329,
    ERR_TCP_INVALID_IPADDRESS = 330,
    ERR_CLI_INVALID_IP_LOGIN = 331,
    ERR_ESTABLISH_UDS_CONNECTION = 332,
    ERR_SSL_INIT_FAILED = 333,
    ERR_EXCEED_SESSIONS_PER_USER = 334,
    ERR_INVALID_IPADDRESS_LENGTH = 335,
    ERR_IPADDRESS_NUM_EXCEED = 336,
    ERR_DB_RESTRICT_STATUS = 337,
    ERR_TCP_TIMEOUT_REMAIN = 338,
    ERR_PEER_CLOSED_REASON = 339,
    ERR_TCP_PKT_VERIFY = 340,
    ERR_SSL_VERIFY_CERT = 341,
    ERR_REPL_PORT_ACCESS = 342,
    ERR_SSL_NOT_SUPPORT = 343,
    ERR_SSL_CA_REQUIRED = 344,
    ERR_SSL_CONNECT_FAILED = 345,
    ERR_SSL_FILE_PERMISSION = 346,
    ERR_SSL_CONNECT_REQUIRED = 347,
    ERR_UDS_BIND = 348,
    ERR_UDS_CONFLICTED = 349,
    ERR_PACKET_SEND = 350,
    ERR_INVALID_ENCRYPTION_ITERATION = 351,
    ERR_SSL_RECV_FAILED = 352,
    ERR_MAX_NORMAL_EMERGE_SESS = 353,

    /* instance: 400 - 499 */
    ERR_HOME_PATH_NOT_FOUND = 401,
    ERR_EXTEND_MEMORY_POOL = 402,
    ERR_TOO_MANY_CONNECTIONS = 403,
    ERR_TOO_MANY_RM_OBJECTS = 404,
    ERR_INVALID_RM_GTID = 405,
    ERR_NESTED_AUTON_SESSIONS = 406,
    ERR_START_INSTANCE_ERROR = 407,
    ERR_ROW_LOCKED_NOWAIT = 408,
    ERR_UNKNOWN_FORUPDATE_MODE = 409,

    /* client errors: 500 - 599 */
    ERR_CLT_UNKNOWN = 500,
    ERR_CLT_INVALID_ATTR = 501,
    ERR_CLT_INVALID_VALUE = 502,
    ERR_CLT_STRING_BUF_TOO_SMALL = 503,
    ERR_CLT_INVALID_BIND = 504,
    ERR_CLT_INVALID_COLUMN = 505,
    ERR_CLT_OUT_OF_INDEX = 506,
    ERR_CLT_TOO_MANY_BINDS = 507,
    ERR_CLT_OUT_OF_API_SEQUENCE = 508,
    ERR_CLT_COL_SIZE_TOO_SMALL = 509,
    ERR_CLT_BIND_SIZE_SMALL = 510,
    ERR_CLT_BUF_SIZE_TOO_SMALL = 511,
    ERR_CLT_OBJECT_IS_NULL = 512,
    ERR_CLT_TRANS_CHARSET = 513,
    ERR_CLT_CONN_CLOSE = 514,
    ERR_CLT_MULTIPLE_SQL = 515,
    ERR_CLT_WSR_ERR = 516,
    ERR_CLT_PARALLEL_LOCK = 517,
    ERR_CLT_FETCH_INVALID_FLAGS = 518,
    ERR_CLT_WRITE_FILE_ERR = 519,
    ERR_CLT_IMP_DATAFILE = 520,
    ERR_CLT_API_NOT_SUPPORTED = 521,
    ERR_CLT_UDS_FILE_EMPTY = 522,
    ERR_CLT_TOO_MANY_ELEMENTS = 523,
    ERR_CLT_UNEXPECTED_CMD = 524,

    ERR_CLT_CLUSTER_INVALID = 525,

    /* sql engine: 500 - 599; add new to: 1300 - 1399 */
    ERR_SQL_VIEW_ERROR = 600,
    ERR_SQL_SYNTAX_ERROR = 601,
    ERR_SQL_TOO_LONG = 602,
    ERR_COORD_NOT_SUPPORT = 603,
    ERR_DUPLICATE_NAME = 604,
    ERR_GROUPING_NOT_ALLOWED = 605,
    ERR_TYPE_MISMATCH = 606,
    ERR_INVALID_DATA_TYPE = 607,
    ERR_INVALID_EXPRESSION = 608,
    ERR_EXPR_NOT_IN_GROUP_LIST = 609,
    ERR_GROUPING_NO_GROUPBY = 610,
    ERR_REQUEST_OUT_OF_SQUENCE = 611,
    ERR_EXPECTED_AGGR_FUNTION = 612,
    ERR_INVALID_OPERATION = 613,
    ERR_INVALID_FUNC_PARAMS = 614,
    ERR_INVALID_FUNC_PARAM_COUNT = 615,
    ERR_TTREE_OVERFLOW_REBALANCE = 616,
    ERR_SQL_INVALID_PRECISION = 617,
    ERR_INVALID_COLUMN_NAME = 618,
    ERR_COLUMNS_MISMATCH = 619,
    ERR_COLUMN_NOT_NULL = 620,
    ERR_SQL_TOO_COMPLEX = 621,
    ERR_NO_FREE_VMEM = 622,
    ERR_SQL_PLAN_ERROR = 623,
    ERR_INVALID_COL_TYPE = 624,
    ERR_EXPR_DATA_TYPE_NOT_MATCH = 625,
    ERR_NOT_COMPATIBLE = 626,
    ERR_STRUCT_MEMBER_NULL = 627,
    ERR_EXECUTE_DML = 628,
    ERR_VM = 629,
    ERR_FUNC_DATE_INVALID = 630,
    ERR_FUNC_RESULT_INVALID = 631,
    ERR_SQL_STACK_FULL = 632,
    ERR_CREATE_INDEX_ON_TYPE = 633,
    ERR_MAX_KEYLEN_EXCEEDED = 634,
    ERR_VALUE_ERROR = 635,
    ERR_INVALID_NUMBER = 636,
    ERR_ZERO_DIVIDE = 637,
    ERR_LOGIN_DENIED = 638,
    ERR_INVALID_ROWID = 639,
    ERR_PRIMRY_KEY_ALREADY_EXISTS = 640,
    ERR_CONSTRAINT_VIOLATED = 641,
    ERR_TABLE_IS_REFERENCED = 642,
    ERR_TABLE_NOT_EMPTY = 643,
    ERR_TOO_LESS_ARGS = 644,
    ERR_INVALID_FLASHBACK_TYPE = 645,
    ERR_INVALID_PURGE_TYPE = 646,
    ERR_INVALID_PURGE_OPER = 647,
    ERR_INVALID_SCAN_MODE = 648,
    ERR_NOT_SUPPORT_TYPE = 649,
    ERR_NO_MATCH_CONSTRAINT = 650,
    ERR_INDEX_ENFORCEMENT = 651,
    ERR_MUTI_DEFAULT_VALUE = 652,
    ERR_INVALID_LIMIT_VALUE = 653,
    ERR_EXCEED_MAX_ROW_SIZE = 654,
    ERR_INVALID_PAGE_ID = 655,
    ERR_DC_CORRUPTED = 656,
    ERR_PASSWORD_IS_TOO_SIMPLE = 657,
    ERR_PASSWORD_FORMAT_ERROR = 658,
    ERR_TYPE_OVERFLOW = 659,
    ERR_CONNECT_BY_LOOP = 660,
    ERR_INVALID_FINISH_SCN = 661,
    ERR_INVALID_BACKUPSET = 662,
    ERR_INVALID_SYNONYM_OBJ_TYPE = 663,
    ERR_CONNECT_BY_LEVEL_MAX = 664,
    ERR_VALUE_CAST_FAILED = 665,
    ERR_ILEGAL_LOB_READ = 666,
    ERR_ILEGAL_LOB_WRITE = 667,
    ERR_PGS_TOO_MANY_BINDS = 668,
    ERR_BACKUP_TAG_EXISTS = 669,
    ERR_BACKUP_RECORD_FAILED = 670,
    ERR_BACKUP_NOT_PREPARE = 671,
    ERR_NO_VALID_BASE_BACKUPSET = 672,
    ERR_INVALID_INTERVAL_TEXT = 673,  /* the errno for parsing interval text */
    ERR_INVALID_INTERVAL_FIELD = 674, /* specifying an invalid field for interval, e.g., the field out of range */
    ERR_INVALID_RESOURCE_LIMIT = 675,
    ERR_SHUTDOWN_IN_PROGRESS = 676,
    ERR_ANCESTOR_LEVEL_MISMATCH = 677,
    ERR_INVALID_OR_LACK_ESCAPE_CHAR = 678,
    ERR_INDEX_NOT_SUITABLE = 679,
    ERR_MAX_PART_CLOUMN_SIZE = 680,
    ERR_REGEXP_COMPILE = 681,
    ERR_REGEXP_EXEC = 682,
    ERR_INVALID_SESSION_ID = 683,
    ERR_CANT_KILL_CURR_SESS = 684,
    ERR_REFERENCED_NO_PRIMARY_KEY = 685,
    ERR_MAX_ROLE_COUNT = 686,
    ERR_TOO_MANY_VALUES = 687,
    ERR_TOO_MANY_BIND = 688,
    ERR_BIND_NOT_MATCH = 689,
    ERR_SEQUENCE_NOT_ALLOWED = 690,
    ERR_ILEGAL_LOB_TYPE = 691,
    ERR_INTERVAL_FIELD_OVERFLOW = 692,
    ERR_INVALID_SEGMENT_ENTRY = 693,
    ERR_TYPE_DATETIME_OVERFLOW = 694,
    ERR_TYPE_TIMESTAMP_OVERFLOW = 695,
    ERR_INVALID_CONN = 696,
    ERR_INVALID_PAGE_TYPE = 697,
    ERR_SIZE_ERROR = 698,
    ERR_ARGUMENT_NOT_FOUND = 699,

    /* database: 700 - 899 */
    ERR_CONTROL_FILE_NOT_COMPLETED = 701,
    ERR_LOAD_CONTROL_FILE = 702,
    ERR_BUILD_CANCELLED = 703,
    ERR_INVALID_CHARSET = 704,
    ERR_INVALID_DATABASE_DEF = 705,
    ERR_TOO_MANY_OBJECTS = 706,
    ERR_INVALID_DC = 707,
    ERR_OBJECT_NOT_EXISTS = 708,
    ERR_COLUMN_HAS_NULL = 709,
    ERR_DC_BUFFER_FULL = 710,
    ERR_INVALID_RCV_END_POINT = 711,
    ERR_INVALID_BATCH = 712,
    ERR_NO_FREE_UNDO_PAGE = 713,
    ERR_LOG_FILE_SIZE_TOO_SMALL = 714,
    ERR_SNAPSHOT_TOO_OLD = 715,
    ERR_DEAD_LOCK = 716,
    ERR_LOCK_TIMEOUT = 717,
    ERR_OPERATION_CANCELED = 718,
    ERR_OPERATION_KILLED = 719,
    ERR_TOO_MANY_PENDING_TRANS = 720,
    ERR_THREAD_EXIT = 721,
    ERR_DC_INVALIDATED = 722,
    ERR_RESOURCE_BUSY = 723,
    ERR_SYNONYM_NOT_EXIST = 724,
    ERR_TOO_MANY_INDEXES = 725,
    ERR_COLUMN_ALREADY_INDEXED = 726,
    ERR_RECORD_SIZE_OVERFLOW = 727,
    ERR_FIND_FREE_SPACE = 728,
    ERR_DUPLICATE_KEY = 729,
    ERR_NO_DB_ACTIVE = 730,
    ERR_MAX_DATAFILE_PAGES = 731,
    ERR_DEF_CHANGED = 732,
    ERR_TXN_IN_PROGRESS = 733,
    ERR_INVALID_ISOLATION_LEVEL = 734,
    ERR_SERIALIZE_ACCESS = 735,
    ERR_SAVEPOINT_NOT_EXIST = 736,
    ERR_TOO_MANY_SAVEPOINTS = 737,
    ERR_DATABASE_ALREADY_MOUNT = 738,
    ERR_DATABASE_ALREADY_OPEN = 739,
    ERR_NO_MORE_LOCKS = 740,
    ERR_TOO_MANY_PENDING_RESULTSET = 741,
    ERR_TABLESPACES_IS_NOT_EMPTY = 742,
    ERR_OBJECT_ID_EXISTS = 743,
    ERR_DATAFILE_HAS_BEEN_USED = 744,
    ERR_DATAFILE_ALREADY_EXIST = 746,
    ERR_NAME_TOO_LONG = 748,
    ERR_DROP_SPACE_NOT_IN_MOUNT = 749,
    ERR_FORBID_ALTER_DATABASE = 750,
    ERR_BACKUP_IN_PROGRESS = 751,
    ERR_RESTORE_IN_PROGRESS = 752,
    ERR_OBJECT_EXISTS = 753,
    ERR_TOO_MANY_COLUMNS = 754,
    ERR_COLUMN_IN_CONSTRAINT = 755,
    ERR_OFFLINE_DATAFILE_NOT_EXIST = 757,
    ERR_SPACE_OFFLINE = 758,
    ERR_INDEX_INVALID = 759,
    ERR_DATAFILE_BREAKDOWN = 760,
    ERR_OFFLINE_WRONG_SPACE = 761,
    ERR_DROP_OFFLINE_SPACE_IN_OPEN = 762,
    ERR_SPACE_NAME_INVALID = 763,
    ERR_DATABASE_NOT_OPEN = 764,
    ERR_DATABASE_NOT_COMPLETED = 766,
    ERR_DATAFILE_SIZE_NOT_ALLOWED = 767,
    ERR_DATABASE_NOT_MOUNT = 768,
    ERR_SPACE_HAS_REPLACED = 769,
    ERR_SHUTDOWN_IN_TRANS = 770,
    ERR_FILE_NOT_EXIST = 771,
    ERR_RAFT_ENABLED = 772,
    ERR_DATABASE_ROLE = 773,
    ERR_FAILOVER_IN_PROGRESS = 774,
    ERR_INVALID_SWITCH_REQUEST = 775,
    ERR_NO_MORE_LOB_ITEMS = 776,
    ERR_DB_TOO_MANY_PRIMARY = 777,
    ERR_DATABASE_NOT_ARCHIVE = 778,
    ERR_BUILD_INDEX_PARALLEL = 779,
    ERR_SPACE_NOT_EXIST = 780,
    ERR_USER_NOT_EXIST = 781,
    ERR_NO_SYNC_STANDBY = 782,
    ERR_ROLE_NOT_EXIST = 783,
    ERR_LRCV_NOT_READY = 784,
    ERR_PROFILE_NOT_EXIST = 785,
    ERR_ALLOC_EXTENT = 786,
    ERR_IN_SHUTDOWN_CANCELED = 787,
    ERR_SPACE_ALREADY_EXIST = 788,
    ERR_CONS_EXISTS = 789,
    ERR_DROP_SPACE_CHECK_FAILED = 790,
    ERR_CASCADED_STANDBY_CONNECTED = 791,
    ERR_DEFAULT_SPACE_TYPE_INVALID = 792,
    ERR_INVALID_ARCHIVE_LOG = 793,
    ERR_OBJECT_ID_NOT_EXIST = 794,
    ERR_TEMP_SPACE_TYPE_INVALID = 795,
    ERR_DATAFILE_NUMBER_NOT_EXIST = 796,
    ERR_NO_ARCHIVE_LOG = 797,
    ERR_THREAD_IS_CLOSED = 798,
    ERR_RECYCLEBIN_MISMATCH = 799,
    ERR_PARTITION_NOT_EXIST = 800,
    ERR_DISTRIBUTE_RULE_NOT_EXIST = 801,
    ERR_NEED_RESTART = 802,
    ERR_PROFILE_ID_NOT_EXIST = 803,
    ERR_SEQ_INVALID = 804,
    ERR_COLUMN_NOT_EMPTY = 805,
    ERR_TOO_OLD_SCN = 806,
    ERR_USER_HAS_LOGIN = 807,
    ERR_PARTITION_NOT_READY = 808,
    ERR_XATXN_IN_PROGRESS = 809,
    ERR_DB_START_IN_PROGRESS = 810,
    ERR_CONS_NOT_EXIST = 811,
    ERR_LOG_FILE_NOT_ENOUGH = 812,
    ERR_LOG_BLOCK_NOT_MATCH = 813,
    ERR_ROW_SELF_UPDATED = 814,
    ERR_USER_IS_REFERENCED = 815,
    ERR_LOCAL_UNIQUE_INDEX = 816,
    ERR_COL_TYPE_MISMATCH = 817,
    ERR_PROFILE_HAS_USED = 818,
    ERR_RAFT_INIT_FAILED = 819,
    ERR_BTREE_LEVEL_EXCEEDED = 820,
    ERR_RECOVER_TIME_INVALID = 821,
    ERR_INVALID_OLD_PASSWORD = 822,
    ERR_INDEX_NOT_STABLE = 823,
    ERR_SYSDBA_LOGIN_FAILED = 824,
    ERR_INVALID_BACKUP_PACKET = 825,
    ERR_NOT_EXPECTED_BACKUP_PACKET = 826,
    ERR_DATABASE_NOT_AVAILABLE = 827,
    ERR_USER_OBJECT_NOT_EXISTS = 828,
    ERR_RECYCLE_OBJ_NOT_EXIST = 829,
    ERR_INDEX_NOT_EXIST = 830,
    ERR_GET_SPIN_LOCK_AREA = 831,
    ERR_XATXN_CHANGED_TEMP_TABLE = 832,
    ERR_CLEAN_ARC_FILE = 833,
    ERR_LOG_FILE_NOT_EXIST = 834,
    ERR_PARAMETER_NOT_MATCH = 836,
    ERR_LOG_FILE_NAME_MISS = 837,
    ERR_DUPLICATE_LOG_ARCHIVE_DEST = 838,
    ERR_FLUSH_REDO_FILE_FAILED = 839,
    ERR_DIR_NOT_EXISTS = 840,
    ERR_LOG_IN_USE = 841,
    ERR_INVALID_ARCHIVE_PARAMETER = 842,
    ERR_TABLE_OR_VIEW_NOT_EXIST = 843,
    ERR_COLUMN_NOT_EXIST = 844,
    ERR_FUNCTION_NOT_EXIST = 845,
    ERR_TABLE_ID_NOT_EXIST = 846,
    ERR_DROP_CONS = 847,
    ERR_SEQ_NOT_EXIST = 848,
    ERR_OBJECT_ALREADY_DROPPED = 849,
    ERR_XA_EXTEND_BUFFER_EXCEEDED = 850,
    ERR_ALLOC_TEMP_EXTENT = 851,
    ERR_RECYCLE_PARTITION_NOT_EXIST = 852,
    ERR_PERMANENTOBJ_IN_TEMPSPACE = 853,
    ERR_SWITCH_LOGFILE = 854,
    ERR_BACKUP_RESTORE = 855,
    ERR_CANNOT_MODIFY_COLUMN = 856,
    ERR_LOG_ARCH_DEST_IN_USE = 857,
    ERR_CANNOT_CLOSE_ARCHIVE = 858,
    ERR_OPEN_RESETLOGS = 859,
    ERR_LOGFILE_OPERATION_CANCELED = 860,
    ERR_SPACE_OPEARTION_CANCELED = 861,
    ERR_READMODE_OPEARTION_CANCELED = 862,
    ERR_RENAME_FUNC_INDEX = 863,
    ERR_ENFORCE_INDEX = 864,
    ERR_EXCEED_MAX_BACKUP_PATH_LEN = 865,
    ERR_NO_AUTO_INCREMENT_COLUMN = 866,
    ERR_DATABASE_IS_ROLLING_BACK = 867,
    ERR_TOO_MANY_TABLES = 868,
    ERR_CHECKSUM_FAILED = 869,
    ERR_NOLOGGING_SPACE = 870,
    ERR_MISUSE_UNDO_SPACE = 871,
    ERR_PART_LIST_COUNT = 872,
    ERR_USER_ID_NOT_EXIST = 873,
    ERR_EXCEED_MAX_INCR_BACKUP = 874,
    ERR_ALTER_DB_TIMEZONE_FAILED = 875,
    ERR_SHRINK_SPACE_SIZE = 876,
    ERR_CANNOT_OPEN_DATABASE = 877,
    ERR_SEND_RECORD_REQ_FAILED = 878,
    ERR_RECORD_BACKUP_FAILED = 879,
    ERR_PAGE_CORRUPTED = 880,
    ERR_DATAFILE_RESIZE_TOO_SMALL = 881,
    ERR_EXCLUDE_SPACES = 882,
    ERR_INDEX_ALREADY_DROPPED = 883,
    ERR_DATAFILE_RESIZE_EXCEED = 884,
    ERR_XA_IN_AUTON_TRANS = 885,
    ERR_SHRINK_EXTEND = 886,
    ERR_OBJECT_INVALID = 887,
    ERR_LIBRARY_NOT_EXIST = 888,
    ERR_STANDBY_LESS_QUORUM = 889,
    ERR_XATXN_CHANGED_NOLOGGING_TABLE = 890,
    ERR_ALCK_RECURSIVE_LEVEL = 891,
    ERR_ALCK_LOCK_THRESHOLD = 892,
    ERR_PAGE_NOT_BELONG_TABLE = 893,
    ERR_UPDATE_MASTER_KEY = 894,
    ERR_NO_BKINFO_REBUILD_CTRL = 895,
    ERR_EXCEED_SEGMENT_MAXSIZE = 896,
    ERR_MAX_SEGMENT_SIZE = 897,
    ERR_BACKUP_TIMEOUT = 898,
    ERR_LOG_SIZE_NOT_MATCH = 899,

    /* PL/SQL Error: 900 - 999 */
    ERR_RETURN_WITHOUT_VALUE = 900,
    ERR_ACCESS_INTO_NULL = 901,
    ERR_CASE_NOT_FOUND = 902,
    ERR_COLLECTION_IS_NULL = 903,
    ERR_CURSOR_ALREADY_OPEN = 904,
    ERR_INVALID_CURSOR = 905,
    ERR_NO_DATA_FOUND = 906,
    ERR_NOT_LOGGED_ON = 907,
    ERR_PROGRAM_ERROR_FMT = 908,
    ERR_TRIG_COMMIT = 909,
    ERR_SELF_IS_NULL = 910,
    ERR_STORAGE_ERROR = 911,
    ERR_SUBSCRIPT_BEYOND_COUNT = 912,
    ERR_SUBSCRIPT_OUTSIDE_LIMIT = 913,
    ERR_INVOKE_EXT_FUNC_ERR = 914,
    ERR_TOO_MANY_ROWS = 915,
    ERR_PL_SYNTAX_ERROR_FMT = 916,
    ERR_THREAD_NOT_START = 917,
    ERR_NO_ARCH_FILE_IN_PRIMARY = 918,
    ERR_PUTBUF_INSUF = 919,
    ERR_UNDEFINED_SYMBOL_FMT = 920,
    ERR_PLSQL_VALUE_ERROR_FMT = 921,
    ERR_PLSQL_ILLEGAL_LINE_FMT = 922,
    ERR_NOT_ENOUGH_VALUES = 923,
    ERR_CURSOR_NOT_OPEN = 924,
    ERR_NO_DATA_NEEDED = 925,
    ERR_RESULT_NOT_MATCH = 926,
    ERR_TAB_MUTATING = 927,
    ERR_TRIG_DDL_DCL = 928,
    // 929 reserved
    ERR_TOO_MANY_RETURN_RESULT = 930,
    ERR_UNHANDLED_USER_EXCEPTION = 931,
    ERR_PL_EXEC = 932,
    ERR_SHRINK_IN_PROGRESS_FMT = 933,
    ERR_PL_KEYWORD_ERROR = 934,
    ERR_EXCEED_TRIGGER_MAX_FMT = 935,
    ERR_SOURCE_SIZE_TOO_LARGE_FMT = 936,
    ERR_TRIG_ALREADY_IN_TAB_FMT = 937,
    ERR_PL_BEGIN_AUTOTRANS = 938,
    ERR_PL_UNDER_STANDYBY = 939,
    ERR_ILEGAL_RETURN_RESULT = 940,
    ERR_PL_ATTR_TYPE_FMT = 941,
    ERR_PL_ATTR_ROWTYPE_FMT = 942,
    ERR_PL_BLOCK_TOO_DEEP_FMT = 943,
    ERR_PL_COMP_FMT = 944,
    ERR_PL_PARAM_USE = 945,
    ERR_PL_REPLAY_UNKNOWN_FMT = 946,
    ERR_PL_DUP_OBJ_FMT = 947,
    ERR_PL_DUP_ARG_FMT = 948,
    ERR_PL_ARG_FMT = 949,
    ERR_PL_EXPR_AS_LEFT_FMT = 950,
    ERR_PL_EXPR_AS_INTO_FMT = 951,
    ERR_PL_CONTEXT_EMPTY = 952,
    ERR_PL_CONTEXT_TYPE_MISMATCH_FMT = 953,
    ERR_PL_EXPECTED_FAIL_FMT = 954,
    ERR_PL_UNEXPECTED_FMT = 955,
    ERR_PL_INVALID_EXCEPTION_FMT = 956,
    ERR_PL_INCOMPLETE_DECL_FMT = 957,
    ERR_PL_UNSUPPORT = 958,
    ERR_PL_EXCEED_LABEL_MAX = 959,
    ERR_PL_OUT_PARAM_WITH_DFT = 960,
    ERR_PL_ENCOUNT_PRIOR = 961,
    ERR_PL_INVALID_ATTR_FMT = 962,
    ERR_PL_ENTRY_LOCK = 963,
    ERR_PL_DC_INVALIDATED = 964,
    ERR_PL_EXPR_WRONG_TYPE = 965,
    ERR_PKG_OBJECT_NODEFINED_FMT = 966,
    ERR_PKG_OBJECT_NOMATCH_FMT = 967,
    ERR_EXT_PROC_NOT_STARTED = 968,
    ERR_EXT_PROC_NOT_WORK = 969,

    // 970 available
    ERR_DYNAMIC_WRONG_TYPE = 971,
    ERR_DYNAMIC_ILLEGAL_INTO = 972,
    ERR_UDF_DDL_DCL = 973,
    ERR_UNEXPECTED_PL_VARIANT = 974,
    ERR_PL_LABEL_INVALID_TYPE = 975,
    ERR_PL_INVALID_LOOP_INDEX = 976,
    ERR_DEBUG_CAN_NOT_ATTACHED = 977,
    ERR_DEBUG_SESSION_TYPE = 978,
    ERR_DEBUG_FORCE_ABORT = 979,
    ERR_DEBUG_BREAK_POINT_EXCEED = 980,
    ERR_DEBUG_TIMEOUT = 981,
    ERR_DEBUG_OPR_BREAK = 982,
    ERR_DEBUG_SESSION_STATUS = 983,
    ERR_PL_INVALID_PROCEDURE = 984,
    ERR_PL_INDEX_ID_OVERFLOW = 985,
    ERR_DEBUG_CAN_NOT_UNINIT = 986,
    ERR_TRIG_INVALID_VIEW = 987,
    ERR_TEMP_TABLE_HOLD = 988,
    ERR_PLE_OUT_PARAM_NOT_FOUND = 989,
    ERR_PLE_CURSOR_IN_OPEN = 990,
    ERR_USER_DEFINED_EXCEPTION = 999,

    /* privilege error: 1000 - 1099 */
    ERR_NO_LOGIN_PRIV = 1000,
    ERR_INSUFFICIENT_PRIV = 1001,
    ERR_PRIVS_NOT_GRANT = 1002,
    ERR_ROLE_CIRCLE_GRANT = 1003,
    ERR_INVALID_REVOKEE = 1004,
    ERR_PRI_GRANT_SELF = 1005,
    ERR_LACK_CREATE_SESSION = 1006,
    ERR_ROLE_NOT_GRANT = 1007,
    ERR_GRANTEE_EXCEED_MAX = 1008,
    ERR_GRANT_OBJ_EXCEED_MAX = 1009,
    ERR_REVOKE_FROM_OBJ_HOLDERS = 1010,
    ERR_NO_INHERIT_PRIV = 1011,
    ERR_RECOMPILE_SYS_OBJECTS = 1012,
    ERR_NO_SPACE_PRIV         = 1013,
    
    /* partition error: 1100 - 1199 */
    ERR_INVALID_PART_NAME = 1100,
    ERR_PARTCNT_NOT_MATCH = 1101,
    ERR_INVALID_PART_TYPE = 1102,
    ERR_INVALID_PART_KEY = 1103,
    ERR_LOB_PART_COLUMN = 1104,
    ERR_MODIFY_PART_COLUMN = 1105,
    ERR_DROP_PART_COLUMN = 1106,
    ERR_DUPLICATE_PART_NAME = 1107,
    ERR_EXCEED_MAX_PARTCNT = 1108,
    ERR_DROP_ONLY_PART = 1109,
    ERR_OPERATIONS_NOT_ALLOW = 1110,
    ERR_PART_INDEX_COALESCE = 1111,
    ERR_MODIFY_PART_INDEX = 1112,
    ERR_DUPLICATE_PART_KEY = 1113,
    ERR_PART_RANGE_NOT_SAME = 1114,
    ERR_PART_HAS_NO_DATA = 1115,
    ERR_PARTNO_NOT_EXIST = 1116,
    ERR_DUPLICATE_SUBPART_NAME = 1117,
    ERR_INVALID_DEST_PART = 1118,
    ERR_EXCEED_MAX_SUBPARTCNT = 1119,
    ERR_INDEX_PART_UNUSABLE = 1120,
    ERR_INVALID_REBUILD_PART_RANGE = 1121,

    /* sharding error: 1200 - 1299 */
#ifdef Z_SHARDING
    // XA and datanode error
    ERR_XA_EXECUTE_FAILED = 1200,
    ERR_XA_WITHOUT_TIMESTAMP = 1201,
    ERR_DATANODE_COUNT_ERROR = 1202,
    ERR_INVALID_NODE_ID = 1203,
    ERR_DATANODE_CONFIGE_FAILED = 1204,
    ERR_REBALANC_CTX_NOT_INIT   = 1205,
    ERR_REBALANCE_TASK_NOT_EXIST = 1206,
    ERR_OLNY_FOR_COORDNODE = 1207,
    ERR_TABLE_FROZEN_STATUS = 1208,
    ERR_NODE_DUP_IP_PORT = 1209,

    // connect error
    ERR_NO_CONN = 1210,
    ERR_CONN_REACH_LIMIT = 1211,
    ERR_CONN_TIMESTAMP_FAILED = 1212,
    ERR_REMOTE_ERROR = 1213,
    ERR_SLOT_RELEASE = 1214,
    ERR_GTS_GETTIME_FAILED = 1215,
    ERR_GTS_INVALID_TIMESTAMP = 1216,
    ERR_GTS_NODE_NOT_EXIST = 1217,
    ERR_BAD_CONN_PIPE = 1218,
    ERR_BAD_GROUP_INFO = 1219,

    // other error
    ERR_NODE_FORBIDDEN_USERNAME = 1220,
    ERR_START_NOT_FINISHED = 1221,

    /* other reserve error in sharding_part: 1222 - 1225 */
    ERR_CONSTRAINT_VIOLATED_CHECK_FAILED = 1222,
    ERR_CONSTRAINT_VIOLATED_NO_FOUND = 1223,
    ERR_DROP_LOGICAL_LOG = 1224,
    ERR_FLASHBACK_NO_SUPPORT = 1225,
    ERR_INVALID_SEQUENCE_CACHE = 1226,
    ERR_SHARD_REFUSESQL = 1227,
    ERR_REFERENCED_BY_LOGICAL_LOG = 1228,
    ERR_DB_ROLE_MISMATCH = 1229,
    ERR_INVALID_LOGICAL_INDEX = 1237,
        
    // re-balance error
    ERR_TABLE_NOT_CONS_HASH_OR_REP = 1230,
    ERR_NO_REBALANCE_TABLE_FOUND = 1231,
    ERR_CALC_REBALANCE_TASK = 1232,
    ERR_ONLY_ROLLBACK_ACCEPTABLE = 1233,
    ERR_NO_REBALANCE_TASK_FOUND = 1235,
    ERR_TABLE_NOT_HEAP = 1236,

    // other error.
    ERR_GET_LOGIN_UID = 1234,

    // shard savepoint
    ERR_SHARD_SAVEPOINT_OPERATION = 1240,
    ERR_STMT_ID_NOT_EXISTS = 1241,
    ERR_DML_FAIL_RB_FAIL = 1242,

    ERR_SELECT_ROWNODEID = 1243,

#endif  // Z_SHARDING

    /* additional: sql engine */
    ERR_DUPLICATE_AUTO_COLUMN = 1300,
    ERR_DUPLICATE_TABLE = 1301,
    ERR_UNKNOWN_LOB_TYPE = 1302,
    ERR_CONVERT_TYPE = 1303,
    ERR_UNSUPPORT_DATATYPE = 1304,
    ERR_UNKNOWN_PLAN_TYPE = 1305,
    ERR_INVALID_DATAFILE_NUMBER = 1306,
    ERR_STORED_PROCEDURE = 1307,
    ERR_FEW_FILLED = 1308,
    ERR_DISTRI_COLUMN_DATA_TYPE = 1309,
    ERR_COMMENT_OBJECT_TYPE = 1310,
    ERR_MUST_BE_FIX_DATATYPE = 1311,
    ERR_KEY_EXPECTED = 1312,
    ERR_INVALID_ATTR_NAME = 1313,
    ERR_ONLY_SUPPORT_STR = 1314,
    ERR_COMPARE_TYPE = 1315,
    ERR_UNEXPECTED_KEY = 1316,
    ERR_UNEXPECTED_ARRG = 1317,
    ERR_UNKNOWN_DATATYPE = 1318,
    ERR_NUM_OVERFLOW = 1319,
    ERR_UNDEFINED_OPER = 1320,
    ERR_UNKNOWN_ARRG_OPER = 1321,
    ERR_CALC_EXPRESSION = 1322,
    ERR_UNSUPPORT_FUNC = 1323,
    ERR_INVOKE_FUNC_FAIL = 1324,
    ERR_COLUMN_DATA_TYPE = 1325,
    ERR_CAST_TO_COLUMN = 1326,
    ERR_UNSUPPORT_OPER_TYPE = 1327,
    ERR_TOO_MANY_ARRG = 1328,
    ERR_INVALID_FUNC = 1329,
    ERR_PARAM_VALUE_OUT_RANGE = 1330,
    ERR_INVALID_PACKAGE = 1331,
    ERR_FORBID_CREATE_SYS_USER = 1332,
    ERR_NO_OPTION_SPECIFIED = 1333,
    ERR_XA_TRANS_EXEC = 1334,
    ERR_READ_LOB_NULL = 1335,
    ERR_DATANODE_EXIST = 1336,
    ERR_DATANODE_NOT_EXIST = 1337,
    ERR_COORDNODE_FORBIDDEN = 1338,
    ERR_DISTRI_COLUMN_FORBIDDEN = 1339,
    ERR_INVALID_SEL4UPDATE = 1340,
    ERR_NO_SORT_ITEM_REMOTE = 1341,
    ERR_COLUM_LIST_EXCEED = 1342,
    ERR_INVALID_PROTOCOL_INVOKE = 1343,
    ERR_INVALID_STATEMENT_ID = 1344,
    ERR_DML_INSIDE_QUERY = 1345,
    ERR_EXCEED_MAX_FIELD_LEN = 1346,
    ERR_FUNCTION_NOT_INDEXABLE = 1347,
    ERR_RESERV_SQL_CURSORS_DECREASE = 1348,
    ERR_SELECT_ROWID = 1349,
    ERR_INVALID_NUMBER_FORAMT = 1350,
    ERR_INVALID_SESSION_TYPE = 1351,
    ERR_SQL_MAP_ONLY_SUPPORT_DML = 1352,
    ERR_SQL_MAP_NOT_EXIST = 1353,
    ERR_TF_ONLY_ONE_TABLE = 1354,
    ERR_TF_TABLE_NAME_NULL = 1355,
    ERR_EXCEED_MAX_STMTS = 1356,
    ERR_DEFAULT_LEN_TOO_LARGE = 1357,
    ERR_EXPECT_COLUMN_HERE = 1358,
    ERR_FOR_UPDATE_FROM_VIEW = 1359,
    ERR_CALC_COLUMN_NOT_ALLOWED = 1360,
    ERR_FOR_UPDATE_NOT_ALLOWED = 1361,
    ERR_INVALID_ARRAY_FORMAT = 1362,
    ERR_WRONG_ELEMENT_COUNT = 1363,
    ERR_INDEX_ON_ARRAY_FIELD = 1364,
    ERR_DATATYPE_NOT_SUPPORT_ARRAY = 1365,
    ERR_INVALID_ARG_TYPE = 1366,
    ERR_CONVERT_CODE_FAILED = 1367,
    ERR_REF_ON_ARRAY_COLUMN = 1368,
    ERR_SET_DEF_ARRAY_VAL = 1369,
    ERR_INVALID_SUBSCRIPT = 1370,
    ERR_USE_WRONG_SUBSCRIPT = 1371,
    ERR_ARRAY_NOT_SUPPORT = 1372,
    ERR_MODIFY_ARRAY_COLUMN = 1373,
    ERR_MODIFY_ARRAY_DATATYPE = 1374,
    ERR_WRONG_TABLE_TYPE = 1375,
    ERR_TF_DDL_ID_NULL = 1376,
    ERR_TF_DDL_INFO_NULL = 1377,
    ERR_TF_DDL_ID_OVER_LEN = 1378,
    ERR_TF_DDL_INFO_OVER_LEN = 1379,
    ERR_ARRAY_TO_STR_FAILED = 1380,
    /* resource manager error */
    ERR_EXCEED_CGROUP_SESSIONS = 1381,
    ERR_EXCEED_MAX_WAIT_TIME = 1382,
    ERR_CGROUP_IS_REFERENCED = 1383,
    ERR_CANNOT_MODIFY_CGROUP = 1384,
    ERR_RSRC_PLAN_INVALIDATED = 1385,
    ERR_LICENSE_CHECK_FAIL = 1386,

    ERR_POLICY_FUNC_CLAUSE = 1387,
    ERR_POLICY_EXEC_FUNC = 1388,

    ERR_FILE_EXEC_PRIV = 1389,
    /* sql engine parallel */
    ERR_PARALLEL_EXECUTE_FAILED = 1390,

    /* tenant */
    ERR_SPACE_DISABLED = 1391,
    ERR_SPACE_INVALID  = 1392,
    ERR_SPACE_ALREADY_USABLE = 1393,
    ERR_TENANT_NOT_EXIST = 1394,
    ERR_TENANT_IS_REFERENCED = 1395,

    ERR_ALCK_MAP_THRESHOLD = 1396,
    ERR_CURSOR_SHARING = 1397,

    /* dblink */
    ERR_DBLINK_NOT_EXIST = 1398,

    /* job error , range 1400- */
    ERR_INTERVAL_TOO_EARLY = 1400,
    ERR_JOB_UNSUPPORT = 1401,
    ERR_PARALLEL_PARAMS = 1402,
    ERR_TF_TABLE_DIST_DDL_ID_NULL = 1403,
    ERR_TF_QUERY_DDL_INFO_FAILED = 1404,

    /* XA Errors */
    ERR_XA_ALREADY_IN_LOCAL_TRANS = 1500,
    ERR_XA_RESUME_TIMEOUT = 1501,
    ERR_XA_BRANCH_NOT_EXISTS = 1502,
    ERR_XA_RM_FAULT = 1503,
    ERR_XA_RDONLY = 1504,
    ERR_XA_INVALID_XID = 1505,
    ERR_XA_DUPLICATE_XID = 1506,
    ERR_XA_TIMING = 1507,
    ERR_SHD_LOCAL_NODE_EXISTS = 1508,
    ERR_XA_IN_ABNORMAL_MODE = 1509,
    ERR_XA_OUTSIDE = 1510,

    /* PL/SQL Error append: 1600 - 1699 */
    ERR_PL_ROLLBACK_EXCEED_SCOPE = 1600,

    // Zenith File System, range [2000, 2500]
    ERR_ZFS_OPEN_VOLUME = 2000,
    ERR_ZFS_READ_VOLUME = 2001,
    ERR_ZFS_WRITE_VOLUME = 2002,
    ERR_ZFS_SEEK_VOLUME = 2003,
    ERR_ZFS_INVALID_PARAM = 2004,
    ERR_ZFS_CREATE_SESSION = 2005,

    // JSON, range [2501, 2599]
    ERR_JSON_INVLID_CLAUSE = 2501,
    ERR_JSON_OUTPUT_TOO_LARGE = 2502,
    ERR_JSON_PATH_SYNTAX_ERROR = 2503,
    ERR_JSON_SYNTAX_ERROR  = 2504,
    ERR_JSON_UNKNOWN_TYPE = 2505,
    ERR_JSON_VALUE_MISMATCHED = 2506,
    ERR_JSON_INSUFFICIENT_MEMORY = 2507,

    // PLSQL UDT ERROR, RANGE[2600, 2699]
    // 2600 available
    ERR_PL_WRONG_ARG_METHOD_INVOKE = 2601,
    ERR_PL_REF_VARIABLE_FAILED = 2602,
    ERR_PL_MULTIPLE_RECORD_FAILED = 2603,
    ERR_PL_NO_DATA_FOUND = 2604,
    ERR_PL_NOT_ALLOW_COLL = 2605,
    ERR_PL_WRONG_ADDR_TYPE = 2606,
    ERR_PL_WRONG_TYPE_VALUE = 2607,
    ERR_PL_REC_FIELD_INVALID = 2608,
    ERR_PL_HSTB_INDEX_TYPE = 2609,

    // MES, rang[2700, 2799]
    ERR_MES_INIT_FAIL           = 2700,
    ERR_MES_CREATE_AREA         = 2701,
    ERR_MES_CREATE_SOCKET       = 2702,
    ERR_MES_INVALID_CMD         = 2703,
    ERR_MES_RECV_FAILED         = 2704,
    ERR_MES_CREATE_MUTEX        = 2705,
    ERR_MES_ILEGAL_MESSAGE      = 2706,
    ERR_MES_PARAMETER           = 2707,
    ERR_MES_ALREADY_CONNECT     = 2708,

    // Tools
    ERR_EXPORT = 3001,
    ERR_IMPORT = 3002,

    // The max error number defined in g_error_desc[]
    ERR_ERRNO_CEIL = 2999,

    // HINT / NOTICE / WARNING
    ERR_HINT = 90002,

    // The max error number can be used in raise exception, it not need to defined in g_error_desc[]
    ERR_CODE_CEIL = 100000,
} gs_errno_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_error_info_t {
    int32 code;
    source_location_t loc;
    char t2s_buf1[GS_T2S_LARGER_BUFFER_SIZE];
    char t2s_buf2[GS_T2S_BUFFER_SIZE];
    char message[GS_MESSAGE_BUFFER_SIZE];
    bool8 is_ignored;
    bool8 is_ignore_log;
    bool8 is_full;
    bool8 reserved;
} error_info_t;

#define GS_MAX_PLC_CNT 32

typedef enum en_err_object {
    ERR_TYPE_SEQUENCE = 1,
    ERR_TYPE_PROCEDURE = 2,
    ERR_TYPE_TRIGGER = 3,
    ERR_TYPE_LIBRARY = 4,
    ERR_TYPE_TYPE = 5,
    ERR_TYPE_TABLE_OR_VIEW = 6
} err_object_t;

typedef struct st_tls_plc_error_t {
    bool8 plc_flag; // The flag indicates whether connecting errors are required
    uint8 plc_cnt; // Count the number of consecutive entering plc_do_compile
    uint16 last_head; // The header of the last line of g_tls_error.message
    uint16 last_head_bak; // backup last_head if last_head will be changed
    uint16 start_pos[GS_MAX_PLC_CNT]; // Store the start position of g_tls_error.message when entering plc_do_compile.
} tls_plc_error_t;

typedef status_t (*cm_error_handler)(const char *file, uint32 line, gs_errno_t code, const char *format,
    va_list args);
void cm_init_error_handler(cm_error_handler handler);
status_t cm_set_srv_error(const char *file, uint32 line, gs_errno_t code, const char *format, va_list args);
status_t cm_set_clt_error(const char *file, uint32 line, gs_errno_t code, const char *format, va_list args);
status_t cm_set_sql_error(const char *file, uint32 line, gs_errno_t code, const char *format, va_list args);
status_t cm_set_plc_error(const char *file, uint32 line, gs_errno_t code, const char *format, va_list args);
void cm_reset_error_user(int err_no, char *user, char *name, err_object_t type);
void cm_set_error_loc(source_location_t loc);
int32 cm_get_error_code();
void cm_try_set_error_loc(source_location_t loc);
void cm_get_error(int32 *code, const char **message, source_location_t *loc);
void cm_reset_error();
void cm_revert_pl_last_error();
void cm_set_ignore_log(bool8 is_ignore_log);
status_t cm_revert_error(int32 code, const char *message, source_location_t *loc);
error_info_t *cm_error_info(void);

/* convert text to string, the buf in thread local storage */
char *cm_get_t2s_addr();
char *cm_t2s(const char *buf, uint32 len);
char *cm_concat_t2s(const char *buf1, uint32 len1, const char *buf2, uint32 len2, char c_mid);
char *cm_t2s_ex(const char *buf, uint32 len);
char *cm_t2s_case(const char *buf, uint32 len, bool32 case_sensitive);
int cm_get_os_error();
int cm_get_sock_error();
void cm_set_sock_error(int32 e);

#ifdef WIN32
extern __declspec(thread) error_info_t g_tls_error;
extern __declspec(thread) tls_plc_error_t g_tls_plc_error;

#else
extern __thread error_info_t g_tls_error;
extern __thread tls_plc_error_t g_tls_plc_error;

#endif
#ifndef EOK
#define EOK (0)
#endif
#ifndef ENOSPC
#define ENOSPC (28)
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP (95)
#endif

#ifndef errno_t
typedef int errno_t;
#endif
const char *cm_get_errormsg(int32 code);

extern bool32 g_enable_err_superposed;

#define GS_ERRNO g_tls_error.code

#define GS_TRACE_ON

#define T2S(text)            cm_t2s((text)->str, (text)->len)
#define T2S_EX(text)         cm_t2s_ex((text)->str, (text)->len)
#define T2S_CASE(text, flag) cm_t2s_case((text)->str, (text)->len, (flag))
#define CC_T2S(text1, text2, c_mid) cm_concat_t2s((text1)->str, (text1)->len, (text2)->str, (text2)->len, (c_mid))

static inline void reset_tls_plc_error()
{
    g_tls_plc_error.plc_flag = GS_FALSE;
    g_tls_error.code = 0;
}

static inline void init_tls_error()
{
    g_tls_plc_error.plc_flag = GS_FALSE;
    g_tls_plc_error.plc_cnt = 0;
    g_tls_plc_error.last_head = 0;
    g_tls_plc_error.last_head_bak = 0;

    g_tls_error.code = 0;
    g_tls_error.is_full = 0;
    g_tls_error.loc.column = 0;
    g_tls_error.loc.line = 0;
}

static inline void set_tls_plc_error()
{
    g_tls_plc_error.plc_flag = GS_TRUE;
}

static inline void reset_inter_plc_cnt()
{
    g_tls_plc_error.plc_cnt--;
}

static inline void set_inter_plc_cnt()
{
    g_tls_plc_error.plc_cnt++;
}

#define GS_SET_HINT(format, ...)            \
    do {                                    \
        cm_set_hint(format, ##__VA_ARGS__); \
    } while (0)

extern const char *g_error_desc[];
#define GS_THROW_ERROR(err_no, ...)                                                                    \
    do {                                                                                               \
        cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, err_no, g_error_desc[err_no], ##__VA_ARGS__); \
    } while (0)

#define GS_SRC_THROW_ERROR(loc, err_no, ...)                                                           \
    do {                                                                                               \
        if (g_tls_plc_error.plc_flag) {                                                                    \
            cm_set_error_loc(loc);                                                                         \
            cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, err_no, g_error_desc[err_no], ##__VA_ARGS__); \
        } else {                                                                                           \
            cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, err_no, g_error_desc[err_no], ##__VA_ARGS__); \
            cm_set_error_loc(loc);                                                                         \
        }                                                                                                  \
    } while (0)

#define GS_THROW_ERROR_TRY_SRC(loc, err_no, ...)                                                           \
    do {                                                                                                     \
        cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, err_no, g_error_desc[err_no], ##__VA_ARGS__);       \
        if (loc != NULL) {                                                                                 \
            cm_set_error_loc(*loc);                                                                        \
        }                                                                                                    \
    } while (0)


#define GS_THROW_ERROR_EX(err_no, format, ...)                                              \
    do {                                                                                    \
        cm_set_error_ex((char *)__FILE_NAME__, (uint32)__LINE__, err_no, format, ##__VA_ARGS__); \
    } while (0)

#define GS_SRC_THROW_ERROR_EX(loc, err_no, format, ...)                                     \
    do {                                                                                    \
        if (g_tls_plc_error.plc_flag) {                                                                    \
            cm_set_error_loc(loc);                                                                         \
            cm_set_error_ex((char *)__FILE_NAME__, (uint32)__LINE__, err_no, format, ##__VA_ARGS__);            \
        } else {                                                                                           \
            cm_set_error_ex((char *)__FILE_NAME__, (uint32)__LINE__, err_no, format, ##__VA_ARGS__);            \
            cm_set_error_loc(loc);                                                                         \
        }                                                                                                  \
    } while (0)

/* PL_THROW_ERROR() and PL_SRC_THROW_ERROR() should be used only in pl layer */
#define PL_THROW_ERROR(err_no, format, ...)                                              \
    do {                                                                                 \
        cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, err_no, format, ##__VA_ARGS__); \
    } while (0)

#define PL_SRC_THROW_ERROR(loc, err_no, format, ...)                                     \
    do {                                                                                 \
        cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, err_no, format, ##__VA_ARGS__); \
        cm_set_error_loc(loc);                                                           \
    } while (0)

void cm_set_error(const char *file, uint32 line, gs_errno_t code, const char *format, ...) GS_CHECK_FMT(4, 5);
void cm_set_hint(const char *format, ...) GS_CHECK_FMT(1, 2);
void cm_set_error_ex(const char *file, uint32 line, gs_errno_t code, const char *format, ...) GS_CHECK_FMT(4, 5);
status_t cm_set_superposed_plc_loc(source_location_t loc, gs_errno_t code, const char *log_msg);
void cm_reset_error_loc();
void cm_log_protocol_error();
#ifdef __cplusplus
}
#endif
#endif
