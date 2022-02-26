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
 * cm_device.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_device.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DEVICE_H__
#define __CM_DEVICE_H__

#include "cm_defs.h"
#include <time.h>

#ifndef WIN32
#include "libaio.h"
#endif


typedef enum en_device_type {
    DEV_TYPE_FILE = 1,
    DEV_TYPE_RAW = 2,
    DEV_TYPE_CFS = 3,
} device_type_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*cm_check_file_error_t)();
extern cm_check_file_error_t g_check_file_error;

#ifdef WIN32
typedef uint64 cm_io_context_t;
typedef uint64 cm_iocb_t;
typedef void (*cm_io_callback_t)(cm_io_context_t ctx, cm_iocb_t *iocb, long res, long res2);
typedef struct st_aio_event {
    void *data;
    cm_iocb_t *obj;
    long res;
    long res2;
} cm_io_event_t;
#else
typedef struct iocb cm_iocb_t;
typedef struct io_event cm_io_event_t;
typedef io_callback_t cm_io_callback_t;
typedef io_context_t cm_io_context_t;
#endif

#define CM_IOCB_LENTH (sizeof(cm_iocb_t) + sizeof(cm_iocb_t*) + sizeof(cm_io_event_t))

typedef int (*cm_io_setup)(int maxevents, cm_io_context_t *io_ctx);
typedef int (*cm_io_destroy)(cm_io_context_t ctx);
typedef int (*cm_io_submit)(cm_io_context_t ctx, long nr, cm_iocb_t *ios[]);
typedef int (*cm_io_cancel)(cm_io_context_t ctx, cm_iocb_t *iocb, cm_io_event_t *evt);
typedef int (*cm_io_getevents)(cm_io_context_t ctx_id, long min_nr, 
                               long nr, cm_io_event_t *events, struct timespec *timeout);

typedef struct st_aio_cbs {
    cm_iocb_t **iocb_ptrs;
    cm_iocb_t *iocbs;
    cm_io_event_t *events;
}cm_aio_iocbs_t;

typedef struct st_aio_lib {
    void *lib_handle;
    cm_io_setup io_setup;
    cm_io_destroy io_destroy;
    cm_io_submit io_submit;
    cm_io_cancel io_cancel;
    cm_io_getevents io_getevents;
}cm_aio_lib_t;

status_t cm_aio_setup(cm_aio_lib_t *lib_ctx, int maxevents, cm_io_context_t *io_ctx);
status_t cm_aio_destroy(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx);
status_t cm_aio_submit(cm_aio_lib_t *lib_ctx, cm_io_context_t ctx, long nr, cm_iocb_t *ios[]);
status_t cm_aio_getevents(cm_aio_lib_t *lib_ctx, cm_io_context_t ctx_id, long min_nr, long nr,
                          cm_io_event_t *events, int32 *aio_ret);
void cm_aio_prep_read(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset);
void cm_aio_prep_write(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset);
void cm_aio_set_callback(cm_iocb_t *iocb, cm_io_callback_t cb);

status_t cm_remove_device(device_type_t type, const char *name);
status_t cm_open_device(const char *name, device_type_t type, uint32 flags, int32 *handle);
void cm_close_device(device_type_t type, int32 *handle);
status_t cm_rename_device(device_type_t type, const char *src, const char *dst);
status_t cm_read_device(device_type_t type, int32 handle, int64 offset, void *buf, int32 size);
status_t cm_write_device(device_type_t type, int32 handle, int64 offset, const void *buf, int32 size);
int64 cm_seek_device(device_type_t type, int32 handle, int64 offset, int32 origin);
status_t cm_extend_device(device_type_t type, int32 handle, char *buf, uint32 buf_size, int64 size,
    bool32 prealloc);
status_t cm_truncate_device(device_type_t type, int32 handle, int64 keep_size);
status_t cm_build_device(const char *name, device_type_t type, char *buf, uint32 buf_size, int64 size,
    uint32 flags, bool32 prealloc, int32 *handle);
status_t cm_create_device(const char *name, device_type_t type, uint32 flags, int32 *handle);
status_t cm_write_zero_to_device(device_type_t type, char *buf, uint32 buf_size, int64 size, int32 *handle);

#ifdef __cplusplus
}
#endif

#endif
