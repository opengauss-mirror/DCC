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
 * knl_dlock_stack.h
 *    itl deadlock manage
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/daemon/knl_dlock_stack.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DLOCK_STACK_H__
#define __KNL_DLOCK_STACK_H__

#include "cm_defs.h"

#define NUM GS_MAX_SESSIONS
typedef struct st_knl_dlock_stack {
    void *values[NUM];
    int32 top;
} knl_dlock_stack_t;

static inline bool32 dlock_is_empty(knl_dlock_stack_t *s) 
{
    return s->top == 0;
}

static inline bool32 dlock_is_full(knl_dlock_stack_t *s)
{
    return s->top >= (int32)NUM;
}

static inline void dlock_push(knl_dlock_stack_t *s, void *ptr)
{
    s->values[s->top++] = ptr;
}

static inline bool32 dlock_push_with_check(knl_dlock_stack_t *s, void *ptr) 
{
    if (dlock_is_full(s)) {
        GS_THROW_ERROR(ERR_STACK_OVERSPACE);
        return GS_FALSE;
    }
    dlock_push(s, ptr);
    return GS_TRUE;
}

static inline void *dlock_top(knl_dlock_stack_t *s)
{
    return s->values[s->top - 1];
}

static inline void dlock_pop(knl_dlock_stack_t *s)
{
    s->top--;
}

#endif

