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
 * cm_debug.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_debug.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DEBUG_H_
#define __CM_DEBUG_H_

#include <stdio.h>
#include <assert.h>
#include <memory.h>
#include "cm_types.h"

#include "cm_log.h"
#include <stdlib.h>

#if defined(_DEBUG) || defined(PCLINT)
#define CM_CHECK_PTR(expr)                                                        \
    {                                                                             \
        if ((expr)) {                                                             \
            printf("warning: null pointer found, %s, %d.\n", __FILE_NAME__, __LINE__); \
        }                                                                         \
    }
#define CM_POINTER(p1)                  CM_CHECK_PTR(p1 == NULL)
#define CM_POINTER2(p1, p2)             CM_CHECK_PTR(p1 == NULL || p2 == NULL)
#define CM_POINTER3(p1, p2, p3)         CM_CHECK_PTR(p1 == NULL || p2 == NULL || p3 == NULL)
#define CM_POINTER4(p1, p2, p3, p4)     CM_CHECK_PTR(p1 == NULL || p2 == NULL || p3 == NULL || p4 == NULL)
#define CM_POINTER5(p1, p2, p3, p4, p5) CM_CHECK_PTR(p1 == NULL || p2 == NULL || p3 == NULL || p4 == NULL || p5 == NULL)
#else
#define CM_POINTER(p1)                  {}
#define CM_POINTER2(p1, p2)             {}
#define CM_POINTER3(p1, p2, p3)         {}
#define CM_POINTER4(p1, p2, p3, p4)     {}
#define CM_POINTER5(p1, p2, p3, p4, p5) {}
#endif

static inline void cm_assert(bool32 condition)
{
    if (!condition) {
        *((uint32 *)NULL) = 1;
    }
}

#ifdef DB_DEBUG_VERSION
#define CM_ASSERT(expr) cm_assert((bool32)(expr))
#else
#define CM_ASSERT(expr) ((void)(expr))
#endif

/* Assert that this command is never executed. */
#define CM_NEVER CM_ASSERT(GS_FALSE)

static inline void cm_exit(int32 exitcode)
{
    _exit(exitcode);
}

#define CM_ABORT(condition, format, ...) \
    do {                                                                                                             \
        if (SECUREC_UNLIKELY(!(condition))) {                                                                                          \
            if (LOG_RUN_ERR_ON) {                                                                                    \
                cm_write_normal_log(LOG_RUN, LEVEL_ERROR, (char *)__FILE_NAME__, (uint32)__LINE__, MODULE_NAME,      \
                    GS_TRUE, format, ##__VA_ARGS__);                                                                 \
            }                                                                                                        \
            cm_print_call_link(GS_DEFAUT_BLACK_BOX_DEPTH);                                                           \
            cm_fync_logfile();                                                                                       \
            cm_exit(-1);                                                                                             \
        }                                                                                                            \
    } while (0);

#ifdef DB_DEBUG_VERSION
#define CM_MAGIC_DECLARE    uint32    cm_magic;
#define CM_MAGIC_SET(obj_declare, obj_struct) ((obj_declare)->cm_magic = obj_struct##_MAGIC)
#define CM_MAGIC_CHECK(obj_declare, obj_struct)                                         \
    do {                                                                                \
        if ((obj_declare) == NULL || ((obj_declare)->cm_magic != obj_struct##_MAGIC)) { \
            GS_LOG_RUN_ERR("[FATAL] Zengine Halt!");                                    \
            CM_NEVER;                                                                   \
        }                                                                               \
    } while (0);

#define CM_MAGIC_CHECK_EX(obj_declare, obj_struct)                                      \
    do {                                                                                \
        if ((obj_declare) != NULL && ((obj_declare)->cm_magic != obj_struct##_MAGIC)) { \
            GS_LOG_RUN_ERR("[FATAL] Zengine Halt!");                                    \
            CM_NEVER;                                                                   \
        }                                                                               \
    } while (0);
#else
#define CM_MAGIC_DECLARE
#define CM_MAGIC_SET(obj_declare, obj_struct) {}
#define CM_MAGIC_CHECK(obj_declare, obj_struct) {}
#define CM_MAGIC_CHECK_EX(obj_declare, obj_struct) {}
#endif

#endif
