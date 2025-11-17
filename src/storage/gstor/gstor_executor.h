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
 * gstor_executor.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_executor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_EXECUTOR_H__
#define __KNL_EXECUTOR_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__ ((visibility ("default")))
#endif

EXPORT_API void gstor_shutdown(void);

EXPORT_API int gstor_startup(char *data_path, unsigned int startup_mode);

EXPORT_API int gstor_alloc(void **handle);

EXPORT_API int gstor_open_table(void *handle, const char *table_name);

EXPORT_API void gstor_free(void *handle);

EXPORT_API void gstor_clean(void *handle);

EXPORT_API int gstor_set_param(char *name, char *value, char *data_path);

EXPORT_API int gstor_put(void *handle, char *key,
    unsigned int key_len, char *val, unsigned int val_len);

EXPORT_API int gstor_del(void *handle, char *key,
    unsigned int key_len, unsigned int prefix, unsigned int *count);

EXPORT_API int gstor_get(void *handle, char *key,
    unsigned int key_len, char **val, unsigned int *val_len, unsigned int *eof);

EXPORT_API int gstor_open_cursor(void *handle, char *key,
    unsigned int key_len, unsigned int flags, unsigned int *eof);

EXPORT_API int gstor_cursor_next(void *handle, unsigned int *eof);

EXPORT_API int gstor_cursor_fetch(void *handle, char **key,
    unsigned int *key_len, char **val, unsigned int *val_len);

EXPORT_API int gstor_begin(void *handle);

EXPORT_API int gstor_commit(void *handle);

EXPORT_API int gstor_rollback(void *handle);

EXPORT_API int gstor_backup(void *handle, const char *bak_format);

EXPORT_API int gstor_restore(void *handle, const char *restore_path, const char *old_path, const char *new_path);

EXPORT_API int gstor_vm_alloc(void *handle, unsigned int *vmid);
EXPORT_API int gstor_vm_open(void *handle, unsigned int vmid, void **page);
EXPORT_API void gstor_vm_close(void *handle, unsigned int vmid);
EXPORT_API void gstor_vm_free(void *handle, unsigned int vmid);
EXPORT_API int gstor_vm_swap_out(void *handle, void *page, unsigned long long *swid, unsigned int *cipher_len);
EXPORT_API int gstor_vm_swap_in(void *handle, unsigned long long swid, unsigned int cipher_len, void *page);
EXPORT_API int gstor_xa_start(void *handle, unsigned char gtrid_len, const char *gtrid);
EXPORT_API int gstor_xa_status(void *handle);
EXPORT_API int gstor_xa_shrink(void *handle);
EXPORT_API int gstor_xa_end(void *handle);
EXPORT_API int gstor_detach_suspend_rm(void *handle);
EXPORT_API int gstor_attach_suspend_rm(void *handle);
EXPORT_API int gstor_detach_pending_rm(void *handle);
EXPORT_API int gstor_attach_pending_rm(void *handle);
EXPORT_API void gstor_set_log_path(char *path);

#ifdef __cplusplus
}
#endif

#endif

