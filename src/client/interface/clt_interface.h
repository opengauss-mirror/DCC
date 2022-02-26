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
 * clt_interface.h
 *
 *
 * IDENTIFICATION
 *    src/client/interface/clt_interface.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CLT_INTERFACE_H__
#define __CLT_INTERFACE_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__((visibility("default")))
#endif

#define MAX_KEY_SIZE                (4 * 1024)              // 4KB
#define MAX_VAL_SIZE                (10 * 1024 * 1024)      // 10M

#define MAX_LEASE_NAME_SIZE         32

/**
 * The DCC's error code
 */
typedef enum en_errors {
    DCC_OK = 1000,                      // Everything is OK

    /**
     * server's errors
     */
    DCC_SRV_KEY_NOT_EXISTED,            // key is not existed
    DCC_SRV_MESSAGE_TOO_LARGE,          // The message is too large

    /**
     * client's errors
     */
    DCC_CLI_NO_MEMORY_ERR,              // no enough memory
    DCC_CLI_ENDPOINTS_FORMAT_ERR,
    DCC_CLI_BAD_ARGUMENTS,              // invalid arguments
    DCC_CLI_KEY_IS_EMPTY,               // key is empty or null
    DCC_ERROR_CEIL
} dcc_errors;

/**
 * DCC read level
 */
typedef enum en_dcc_read_level {
    DCC_READ_LEVEL_UNKNOWN = 0,
    DCC_READ_LEVEL_LEADER,              // read from leader
    DCC_READ_LEVEL_LOCAL,               // read from connected's node
    DCC_READ_LEVEL_CONSISTENT,
    DCC_READ_LEVEL_CEIL,
} dcc_read_level_t;

/**
 * Describes the key(value) structure
 */
typedef struct st_string {
    char *data;
    unsigned int len;
} dcc_string_t;

/**
 * The options for operating
 */
typedef struct st_dcc_option {
    union {
        struct {
            unsigned int prefix;            // 1: recursively get sub-dir
            dcc_read_level_t read_level;
        } get_op;
        struct {
            dcc_read_level_t read_level;
        } getchildren_op;
        struct {
            unsigned int sequence;          // 1: sequence node, 0: ordinary node
            unsigned int not_existed;       // 1: if no the key, put success. otherwise, put failed. 0: update the val
            unsigned int expect_val_len;    // for cas operation
            char *expect_value;
            dcc_string_t lease_name;
        } put_op;
        struct {
            unsigned int prefix;            // 1: recursively delete sub-dir
        } delete_op;
        struct {
            unsigned int prefix;            // 1: recursively watch sub-dir
        } watch_op;
        struct {
            unsigned int prefix;            // 1: recursively unwatch sub-dir
        } unwatch_op;
    };
} dcc_option_t;

typedef struct st_dcc_lease_info_t {
    unsigned int ttl;
    unsigned int remain_ttl;
} dcc_lease_info_t;

/**
 * The type of watch
 */
typedef enum st_dcc_watch_event_t {
    DCC_WATCH_UNKNOWN = 0,
    DCC_WATCH_EVENT_PUT,                        // update event
    DCC_WATCH_EVENT_DELETE,                     // delete event
    DCC_WATCH_CEIL,
} dcc_watch_event_t;

/**
 * Input parameter for the watch's callback function
 */
typedef struct st_dcc_watch_result {
    dcc_watch_event_t watch_event;
    union {
        struct {
            unsigned int new_data_size;
            char *new_data;
        } data_changed_result;
    };
} dcc_watch_result_t;

/**
 * The return value for function \ref dcc_get or dcc_fetch. The caller should alloc memory
 */
typedef struct st_dcc_result_t {
    unsigned int eof;           // 1: no data; 0: has data
    unsigned int key_len;       // The key's length
    char *key;
    unsigned int val_len;       // The value's length
    char *val;
} dcc_result_t;

/**
 * The return value for function \ref dcc_getchildren. The caller should alloc memory
 */
typedef struct st_dcc_array {
    unsigned int count;
    dcc_string_t **strings;
} dcc_array_t;

/**
 * the level of logger
 */
typedef enum en_dcc_log_level {
    DCC_LOG_LEVEL_ERROR = 0,  // error conditions
    DCC_LOG_LEVEL_WARN,       // warning conditions
    DCC_LOG_LEVEL_INFO,       // informational messages
    DCC_LOG_LEVEL_CEIL,
} dcc_log_level_t;

/**
 * the type of logger, for different directory
 */
typedef enum en_dcc_log_id {
    DCC_LOG_ID_RUN = 0,
    DCC_LOG_ID_DEBUG,
    DCC_LOG_ID_CEIL,
} dcc_log_id_t;

/**
 * Parameters for initializing the handle
 */
typedef struct st_dcc_open_option {
    char *ca_file;              // the file of root certificate.
    char *crt_file;             // the file of client certificate
    char *key_file;             // the file of secret key
    unsigned int time_out;      // unit: ms
    char *clt_name;             // mark the client, the max length is 255
    char *server_list;          // ip:port,ip:port
} dcc_open_option_t;

/**
 * Callback function for watch, when notifications are triggered this function will be invoked
 */
typedef int(*dcc_watch_proc_t)(const char *key, unsigned int key_len, const dcc_watch_result_t *watch_result);

/**
 * Callback function for log
 */
typedef void (*dcc_cb_log_output_t)(dcc_log_id_t log_type, dcc_log_level_t log_level, const char *code_file_name,
                                    unsigned int code_line_num, const char *module_name, const char *format, ...);

/**
 * Create a handle to used communicate with dcc
 *
 * @param open_option: [in]
 * @param handle: [out]
 * @return != 0 fail
 */
EXPORT_API int dcc_open(const dcc_open_option_t *open_option, void **handle);

/**
 * close the DCC handle and free up any resources.
 *
 * @param handle: [in] the DCC handle obtained by a call to \ref dcc_open
 */
EXPORT_API void dcc_close(void **handle);

/**
 * Register the Log Callback Function
 *
 * @param log_write：[in] log call back function
 */
EXPORT_API void dcc_set_log(dcc_cb_log_output_t log_write);

/**
 * Gets the value associated with a key
 *
 * @param handle: [in] the DCC handle obtained by a call to \ref dcc_open
 * @param key:    [in] the name of the key
 * @param option: [in] get_op
 * @param result: [out] The caller needs to allocate memory
 * @return != 0 fail
 */
EXPORT_API int dcc_get(void *handle, const dcc_string_t *key, const dcc_option_t *option, dcc_result_t *result);

/**
 * Multiple pairs of data to obtain the remaining data
 *
 * @param handle: [in] the DCC handle obtained by a call to \ref dcc_open
 * @param result: [out] The caller needs to allocate memory
 * @return != 0 fail
 */
EXPORT_API int dcc_fetch(void *handle, dcc_result_t *result);

/**
 * get all keys
 *
 * @param handle: [in] the DCC handle obtained by a call to \ref dcc_open
 * @param key:    [in] the name of the key
 * @param option: [in] get_children op
 * @param result: [out] dcc allocate memory, you should call \ref dcc_deinit_array to free
 * @return != 0 fail
 */
EXPORT_API int dcc_getchildren(void *handle, const dcc_string_t *key, const dcc_option_t *option,  dcc_array_t *result);

/**
 * free array
 */
EXPORT_API void dcc_deinit_array(dcc_array_t *array);

/**
 * Sets the key associated with a value
 *
 * @param handle: [in] the DCC handle obtained by a call to \ref dcc_open
 * @param key: [in] the name of the key
 * @param val: [in] corresponding Value
 * @param option: [in] put_op
 * @param sequence_buf: [in] when you use flag sequence, you will get she sequence of the key, you should alloc memory
 * @return != 0 fail
 */
EXPORT_API int dcc_put(void *handle, const dcc_string_t *key, const dcc_string_t *val, const dcc_option_t *option,
                       dcc_string_t *sequence_buf);

/**
 * Delete a key-val by a key
 *
 * @param handle: [in] the DCC handle obtained by a call to \ref dcc_open
 * @param key: [in] the name of the key
 * @param option: [in] delete_op
 * @return != 0 fail
 */
EXPORT_API int dcc_delete(void *handle, const dcc_string_t *key, const dcc_option_t *option);

/**
 * Register a watch, the server will send a notification when the value changes
 *
 * @param handle: [in] the DCC handle obtained by a call to \ref dcc_open
 * @param key: [in] the name of the key
 * @param proc: [in] callback function
 * @param option: [in] watch_op
 * @return != 0 fail
 */
EXPORT_API int dcc_watch(void *handle, const dcc_string_t *key, const dcc_watch_proc_t proc,
                         const dcc_option_t *option);

/**
 * Cancel the registered watch for a key
 *
 * @param handle: [in] the DCC handle obtained by a call to \ref dcc_open
 * @param key: [in] the name of the key
 * @param key: [in] unwatch_op
 * @return != 0 fail
 */
EXPORT_API int dcc_unwatch(void *handle, const dcc_string_t *key, const dcc_option_t *option);

/**
 * Client lease manager init
 *
 * @param open_option: [in] open_option for lease handle
 * @return != 0 fail
 */
EXPORT_API int dcc_lease_mgr_init(const dcc_open_option_t *open_option);

/**
 * Client lease manager deinit
 */
EXPORT_API void dcc_lease_mgr_deinit(void);

/**
 * Create a lease with a leasename and ttl
 *
 * @param handle:        [in] the DCC handle obtained by a call to \ref dcc_open
 * @param lease_name:    [in] the lease name
 * @param ttl:           [in] lease time (unit: s)
 * @param is_keep_alive: [in] whether auto keep the lease alive, 1-Yes 0-No
 * @return != 0 fail
 */
EXPORT_API int dcc_lease_create(void *handle, const dcc_string_t *lease_name, const unsigned int ttl,
    const unsigned int is_keep_alive);

/**
 * Keep the specified lease alive
 *
 * @param handle:     [in] the DCC handle obtained by a call to \ref dcc_open
 * @param lease_name: [in] the lease name
 * @return != 0 fail
 */
EXPORT_API int dcc_lease_keep_alive(void *handle, const dcc_string_t *lease_name);

/**
 * Destroy the specified lease
 *
 * @param handle:        [in] the DCC handle obtained by a call to \ref dcc_open
 * @param lease_name:    [in] the lease name
 * @return != 0 fail
 */
EXPORT_API int dcc_lease_destroy(void *handle, const dcc_string_t *lease_name);

/**
 * Query lease info
 *
 * @param handle:     [in] the DCC handle obtained by a call to \ref dcc_open
 * @param lease_name: [in] the lease name
 * @return != 0 fail
 */
EXPORT_API int dcc_lease_query(void *handle, const dcc_string_t *lease_name, dcc_lease_info_t *lease_info);

/**
 * Get the error number
 *
 * @return 0 is no error, != 0 is error num, call dcc_get_error can get description
 */
EXPORT_API int dcc_get_errorno(void);

/**
 * Cancel the registered watch for a key
 *
 * @param errorno: [in] error number
 * @return error description
 */
EXPORT_API const char *dcc_get_error(int errorno);

/**
 * Get lib version
 * @return version_no
 */
EXPORT_API const char *dcc_clt_get_version(void);

#ifdef __cplusplus
}
#endif

#endif
