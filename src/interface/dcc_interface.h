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
 * dcc_interface.h
 *    API for server
 *
 * IDENTIFICATION
 *    src/interface/dcc_interface.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_INTERFACE_H__
#define __DCC_INTERFACE_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__ ((visibility ("default")))
#endif

#define MAX_KV_KEY_LEN  (4 * 1024)
#define MAX_KV_VALUE_LEN (10 * 1024 * 1024)

// don't change the order
typedef enum en_dcc_role {
    DCC_ROLE_UNKNOWN = 0,
    DCC_ROLE_LEADER,
    DCC_ROLE_FOLLOWER,
    DCC_ROLE_LOGGER,
    DCC_ROLE_PASSIVE,
    DCC_ROLE_PRE_CANDIDATE,
    DCC_ROLE_CANDIDATE,
    DCC_ROLE_CEIL,
} dcc_role_t;

typedef enum e_dcc_work_mode {
    DCC_WM_NORMAL = 0,
    DCC_WM_MINORITY = 1,
    DCC_WM_CEIL
}dcc_work_mode_t;

typedef enum e_dcc_read_level {
    DCC_READ_LEVEL_UNKNOWN = 0,
    DCC_READ_LEVEL_LEADER,              // read from leader
    DCC_READ_LEVEL_LOCAL,               // read from connected's node
    DCC_READ_LEVEL_CONSISTENT,          // read from leader with consistency
    DCC_READ_LEVEL_CEIL,
} dcc_read_level_e;

typedef struct st_dcc_text {
    char* value;
    unsigned int len;
} dcc_text_t;

typedef enum en_dcc_event_type {
    DCC_WATCH_EVENT_UNKONOW = 0,
    DCC_WATCH_EVENT_PUT,
    DCC_WATCH_EVENT_DELETE,
} dcc_event_type_t;

typedef struct st_kvp {
    dcc_text_t   key;
    dcc_text_t   value;
}kvp_t;

typedef struct st_dcc_event {
    kvp_t        *kvp;
    unsigned int sid;
    unsigned int is_prefix_notify;  // 1: client register a prefix watch; 0: on the contrary
    dcc_text_t   old_value; // reserved
    dcc_event_type_t event_type;
} dcc_event_t;

typedef int(*dcc_watch_proc_t)(dcc_event_t* watch_obj);

typedef int(*dcc_cb_status_notify_t)(dcc_role_t role_type);

typedef struct st_dcc_option {
    unsigned int sid;
    union {
        struct {
            unsigned int is_prefix;
            unsigned int sequence;
            unsigned int not_existed;
            unsigned int expect_val_size;
            char *expect_value;
        } write_op;
        struct {
            unsigned int is_prefix;
            dcc_read_level_e read_level;
        } read_op;
        struct {
            unsigned int is_prefix;
        } watch_op;
        struct {
            unsigned int is_prefix;
        } del_op;
    };
    unsigned int cmd_timeout; // command-timeout(s)
} dcc_option_t;

typedef struct st_dcc_node_status {
    unsigned int is_healthy;
    dcc_role_t role_type;
} dcc_node_status_t;

typedef void (*usr_cb_log_output_t)(int log_type, int log_level, const char *code_file_name, unsigned int code_line_num,
    const char *module_name, const char *format, ...);

/*
 * Set dcc parameters
 *
 * @param param_name: [in] the parameter name to be set
 * @param param_value: [in] set the parameter value
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_set_param(const char *param_name, const char *param_value);

/**
 * Callback function after dcc node role changed notify
 */
EXPORT_API int srv_dcc_register_status_notify(dcc_cb_status_notify_t cb_func);

/**
 * Callback function for dcc run log output
 */
EXPORT_API int srv_dcc_register_log_output(usr_cb_log_output_t cb_func);

/**
 * Start and run dcc node instance
 *
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_start(void);

/**
 * Stop node instance
 *
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_stop(void);

/*
 * Allocate a handle of dcc session
 *
 * @param handle: [out] allocated handle
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_alloc_handle(void **handle);

/*
 * Free the handle of dcc session
 *
 * @param handle: [in] handle to be freed
 * @return 0:success  !=0:fail
 */
EXPORT_API void srv_dcc_free_handle(void* handle);

/**
 * Get the key/value associated with a key range
 *
 * @param handle: [in] the DCC handle obtained by srv_dcc_alloc_handle
 * @param range:  [in] the name of the key range to query
 * @param option: [in] get_op
 * @param key/value: [out] the key/value result
 * @param eof: [out] !0: end of query  0: not end
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_get(const void *handle, dcc_text_t* range, const dcc_option_t* option, dcc_text_t* key,
    dcc_text_t* value, unsigned int *eof);

/**
 * Fetch the remaining key/value data
 *
 * @param handle: [in] the DCC handle obtained by srv_dcc_alloc_handle
 * @param option: [in] get_op
 * @param key/value: [out] the key/value result
 * @param eof: [out] !0: end of query  0: not end
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_fetch(const void *handle, dcc_text_t *key, dcc_text_t *value, const dcc_option_t *option,
    unsigned int *eof);

/**
 * Sets the key associated with a value
 *
 * @param handle: [in] the DCC handle obtained by srv_dcc_alloc_handle
 * @param key: [in] the name of the key
 * @param val: [in] corresponding Value
 * @param option: [in] put_op
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_put(const void *handle, const dcc_text_t *key, const dcc_text_t *value, dcc_option_t *option);

/**
 * Delete a key-val by a key
 *
 * @param handle: [in] the DCC handle obtained by srv_dcc_alloc_handle
 * @param key: [in] the name of the key
 * @param option: [in] delete_op
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_delete(const void *handle, const dcc_text_t* key, const dcc_option_t* option);

/**
 * Register a watch, dcc will send a notification when the value changes
 *
 * @param handle: [in] the DCC handle obtained by srv_dcc_alloc_handle
 * @param key: [in] the name of the key
 * @param proc: [in] callback function
 * @param option: [in] watch_op
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_watch(const void *handle, dcc_text_t* key, dcc_watch_proc_t proc, dcc_option_t* option);

/**
 * Unregister the watch of a key
 *
 * @param handle: [in] the DCC handle obtained by srv_dcc_alloc_handle
 * @param key: [in] the name of key to be unwatched
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_unwatch(const void *handle, dcc_text_t* key);

/**
 * Get lib version
 *
 * @return version_no
 */
EXPORT_API const char* srv_dcc_get_version(void);

/**
 * Get the error number
 *
 * @return 0 is no error, != 0 is error num, call srv_dcc_get_error can get description
 */
EXPORT_API int srv_dcc_get_errorno(void);

/**
 * Get the error description
 *
 * @return error description
 */
EXPORT_API const char* srv_dcc_get_error(int code);

/**
 * Get dcc node status including health and role info
 *
 * @param node_stat: [out] node_stat info
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_get_node_status(dcc_node_status_t *node_stat);

/**
 * Execute dcc cmd
 *
 * @param handle: [in] the DCC handle obtained by srv_dcc_alloc_handle
 * @param cmd_line: [in] dcc cmdline to be executed
 * @param ans_buf: [out] buf pointed to cmd executed result
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_exec_cmd(void *handle, const dcc_text_t *cmd_line, dcc_text_t* ans_buf);

/**
 * Query dcc cluster info
 *
 * @param buffer: [out] buf pointed to dcc cluster info
 * @param length: [out] buf length of queried cluster info
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_query_cluster_info(char* buffer, unsigned int length);

/**
 * Query dcc leader info
 *
 * @param node_id: [out] leader node id
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_query_leader_info(unsigned int *node_id);

/**
 * Set dcc as blocked status so that dcc put/del may fail
 *
 * @param is_block: [in]
 * @param wait_timeout_ms: [in] wait timeout(ms)
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_set_blocked(unsigned int is_block, unsigned int wait_timeout_ms);

/**
 * Set dcc work mode
 *
 * @param work_mode: [in] normal majority or minority work mode
 * @param vote_num: [in] vote num specified in minority work mode
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_set_work_mode(dcc_work_mode_t work_mode, unsigned int vote_num);

/**
 * demote dcc node to follower
 *
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_demote_follower(void);

/**
 * Set cur node's election_priority
 *
 * @param priority: [in] priority
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_set_election_priority(unsigned long long priority);

/**
 * Promote the specified node to be leader
 *
 * @param node_id: [in] node id to be promoted
 * @param wait_timeout_ms: [in] wait timeout
 * @return 0:success  !=0:fail
 */
EXPORT_API int srv_dcc_promote_leader(unsigned int node_id, unsigned int wait_timeout_ms);

EXPORT_API int srv_dcc_backup(const char *bak_format);

EXPORT_API int srv_dcc_restore(const char *restore_path);

EXPORT_API int srv_dcc_set_dcf_param(const char *param_name, const char *param_value);

#ifdef __cplusplus
}
#endif

#endif
