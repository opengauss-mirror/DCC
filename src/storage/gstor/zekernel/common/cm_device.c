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
 * cm_device.c
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_device.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_device.h"
#include "cm_file.h"
#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

cm_check_file_error_t g_check_file_error = NULL;

static inline void cm_check_file_error()
{
    if (g_check_file_error != NULL) {
        g_check_file_error();
    }
}

status_t cm_create_device(const char *name, device_type_t type, uint32 flags, int32 *handle)
{
    if (type == DEV_TYPE_FILE) {
        if (cm_create_file(name, O_BINARY | O_SYNC | O_RDWR | O_EXCL | flags, handle) != GS_SUCCESS) {
            cm_check_file_error();
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_rename_device(device_type_t type, const char *src, const char *dst)
{
    if (type == DEV_TYPE_FILE) {
        return cm_rename_file(src, dst);
    } else {
        GS_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return GS_ERROR;
    }
}

status_t cm_remove_device(device_type_t type, const char *name)
{
    if (type == DEV_TYPE_FILE) {
        return cm_remove_file(name);
    } else {
        GS_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return GS_ERROR;
    }
}

status_t cm_open_device(const char *name, device_type_t type, uint32 flags, int32 *handle)
{
    if (type == DEV_TYPE_FILE) {
        if (*handle != -1) {
            // device already opened, nothing to do.
            return GS_SUCCESS;
        }

        uint32 mode = O_BINARY | O_RDWR | flags;

        if (cm_open_file(name, mode, handle) != GS_SUCCESS) {
            cm_check_file_error();
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void cm_close_device(device_type_t type, int32 *handle)
{
    if (type == DEV_TYPE_FILE) {
        cm_close_file(*handle);
        *handle = -1;  // reset handle
    }
}

status_t cm_read_device(device_type_t type, int32 handle, int64 offset, void *buf, int32 size)
{
    int32 read_size;

    if (type == DEV_TYPE_FILE) {
        if (cm_pread_file(handle, buf, size, offset, &read_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (read_size != size) {
            GS_THROW_ERROR(ERR_READ_DEVICE_INCOMPLETE, read_size, size);
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_write_device(device_type_t type, int32 handle, int64 offset, const void *buf, int32 size)
{
    if (type == DEV_TYPE_FILE) {
        if (cm_pwrite_file(handle, buf, size, offset) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

int64 cm_seek_device(device_type_t type, int32 handle, int64 offset, int32 origin)
{
    if (type == DEV_TYPE_FILE) {
        return cm_seek_file(handle, offset, origin);
    } else {
        return (int64)0;
    }
}

// prealloc file by fallocate
status_t cm_prealloc_device(int32 handle, int64 offset, int64 size)
{
    return cm_fallocate_file(handle, 0, offset, size);
}

status_t cm_write_device_by_zero(int32 handle, device_type_t type, char *buf, uint32 buf_size,
    int64 offset, int64 size)
{
    errno_t err = memset_sp(buf, (size_t)buf_size, 0, (size_t)buf_size);
    if (err != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (err));
        return GS_ERROR;
    }

    int64 remain_size = size;
    int32 curr_size;
    while (remain_size > 0) {
        curr_size = (remain_size > buf_size) ? (int32)buf_size : (int32)remain_size;
        if (cm_write_device(type, handle, offset, buf, curr_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        offset += curr_size;
        remain_size -= curr_size;
    }

    return GS_SUCCESS;
}

status_t cm_extend_device(device_type_t type, int32 handle, char *buf, uint32 buf_size, int64 size,
    bool32 prealloc)
{
    int64 offset = cm_seek_device(type, handle, 0, SEEK_END);
    if (offset == -1) {
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    if (prealloc) {
        // use falloc to fast build device
        return cm_prealloc_device(handle, offset, size);
    }

    return cm_write_device_by_zero(handle, type, buf, buf_size, offset, size);
}

status_t cm_truncate_device(device_type_t type, int32 handle, int64 keep_size)
{
    if (type == DEV_TYPE_FILE) {
        if (cm_truncate_file(handle, keep_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_DEVICE_NOT_SUPPORT);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_build_device(const char *name, device_type_t type, char *buf, uint32 buf_size, int64 size,
    uint32 flags, bool32 prealloc, int32 *handle)
{
    *handle = -1;
    if (cm_create_device(name, type, flags, handle) != GS_SUCCESS) {
        cm_close_device(type, handle);
        return GS_ERROR;
    }

    status_t status;
    if (prealloc) {
        status = cm_prealloc_device(*handle, 0, size);
    } else {
        status = cm_write_device_by_zero(*handle, type, buf, buf_size, 0, size);
    }

    if (status != GS_SUCCESS) {
        cm_close_device(type, handle);
        return GS_ERROR;
    }

    if (cm_fsync_file(*handle) != GS_SUCCESS) {
        GS_LOG_RUN_ERR("failed to fsync datafile %s", name);
        cm_close_device(type, handle);
        return GS_ERROR;
    }

    cm_close_device(type, handle);
    return GS_SUCCESS;
}

status_t cm_aio_setup(cm_aio_lib_t *lib_ctx, int maxevents, cm_io_context_t *io_ctx)
{
    if (lib_ctx->io_setup(maxevents, io_ctx) < 0) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cm_aio_destroy(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx)
{
    if (lib_ctx->io_destroy(io_ctx) < 0) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cm_aio_getevents(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx, long min_nr, long nr,
                          cm_io_event_t *events, int32 *aio_ret)
{
    struct timespec timeout  = { 0, 200 };
    *aio_ret = lib_ctx->io_getevents(io_ctx, min_nr, nr, events, &timeout);
    if (*aio_ret < 0) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_aio_submit(cm_aio_lib_t *lib_ctx, cm_io_context_t io_ctx, long nr, cm_iocb_t *ios[])
{
    if (lib_ctx->io_submit(io_ctx, nr, ios) != nr) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

void cm_aio_prep_read(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset)
{
#ifndef WIN32
    io_prep_pread(iocb, fd, buf, count, offset);
#endif 
}

void cm_aio_prep_write(cm_iocb_t *iocb, int fd, void *buf, size_t count, long long offset)
{
#ifndef WIN32
    io_prep_pwrite(iocb, fd, buf, count, offset);
#endif 
}

void cm_aio_set_callback(cm_iocb_t *iocb, cm_io_callback_t cb)
{
#ifndef WIN32
    io_set_callback(iocb, cb);
#endif
}

#ifdef __cplusplus
}
#endif

