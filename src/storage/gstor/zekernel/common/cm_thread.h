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
 * cm_thread.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_thread.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_THREAD_H__
#define __CM_THREAD_H__

#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_atomic.h"
#include "cm_epoll.h"

#ifdef WIN32
#else
#include <pthread.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/eventfd.h>
#endif

// include file and define of gittid()
#ifndef WIN32
#include <sys/types.h>
#include <sys/syscall.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
typedef CRITICAL_SECTION thread_lock_t;
#else
typedef pthread_mutex_t thread_lock_t;
#endif

typedef struct st_cm_thread_eventfd {
    atomic_t wait_session_cnt;
    int32 epfd;
    int32 efd;
} cm_thread_eventfd_t;

typedef struct st_cm_thread_id {
    uint32 thread_id;
    bool32 has_get;
} cm_thread_id_t;

void cm_init_eventfd(cm_thread_eventfd_t *etfd);
void cm_timedwait_eventfd(cm_thread_eventfd_t *etfd, int32 timeout_ms);
void cm_wakeup_eventfd(cm_thread_eventfd_t *etfd);
void cm_release_eventfd(cm_thread_eventfd_t *etfd);

typedef struct st_cm_thread_cond {
#ifdef WIN32
    HANDLE sem;
    atomic32_t count;
#else
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_condattr_t attr;
#endif
} cm_thread_cond_t;

void cm_init_cond(cm_thread_cond_t *cond);
bool32 cm_wait_cond(cm_thread_cond_t *cond, uint32 ms);
void cm_release_cond(cm_thread_cond_t *cond);
void cm_release_cond_signal(cm_thread_cond_t *cond);
void cm_destory_cond(cm_thread_cond_t *cond);
/* thread lock */
void cm_init_thread_lock(thread_lock_t *lock);
void cm_thread_lock(thread_lock_t *lock);
void cm_thread_unlock(thread_lock_t *lock);

/* thread */
typedef struct st_thread {
#ifdef WIN32
    DWORD id;
    HANDLE handle;
#else
    pthread_t id;
#endif

    volatile bool32 closed;
    void *entry;
    void *argument;
    int32 result;
    uint32 stack_size;
    void *reg_data;
    char *stack_base; /* the start stack address of this thread */
} thread_t;

typedef void (*thread_entry_t)(thread_t *thread);

status_t cm_create_thread(thread_entry_t entry, uint32 stack_size, void *argument, thread_t *thread);
void cm_close_thread(thread_t *thread);
void cm_close_thread_nowait(thread_t *thread);

uint32 cm_get_current_thread_id();
#define CM_THREAD_ID cm_get_current_thread_id()

bool32 cm_is_current_thread_closed();
void cm_release_thread(thread_t *thread);
long cm_get_os_thread_stack_rlimit(void);
void cm_switch_stack_base(thread_t *thread, char *stack_base, char **org_base);

#ifdef __linux
#define cm_set_thread_name(x) prctl(PR_SET_NAME, x)
#else
#define cm_set_thread_name(x)
#endif

#ifdef WIN32
typedef DWORD cpu_set_t;
#endif

#ifdef __cplusplus
}
#endif

#endif
