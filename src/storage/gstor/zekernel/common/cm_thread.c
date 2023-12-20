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
 * cm_thread.c
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_thread.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_thread.h"
#include "cm_error.h"
#include "cm_sync.h"
#ifndef WIN32
#include <sys/time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
__declspec(thread) cm_thread_id_t g_cm_thread_id = { 0 };
#else
__thread cm_thread_id_t g_cm_thread_id = { 0 };
#endif

void cm_init_eventfd(cm_thread_eventfd_t *etfd)
{
#ifndef WIN32
    if (etfd->efd != -1 || etfd->epfd != -1) {
        return;
    }

    cm_atomic_set(&etfd->wait_session_cnt, 0);
    etfd->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE);   // pipe / socket
    etfd->epfd = epoll_create1(EPOLL_CLOEXEC);

    struct epoll_event event;

    event.data.fd = etfd->efd;
    event.events = EPOLLIN;    // level-Triggered
    PRTS_RETVOID_IFERR(epoll_ctl(etfd->epfd, EPOLL_CTL_ADD, etfd->efd, &event));
#endif
}

void cm_timedwait_eventfd(cm_thread_eventfd_t *etfd, int32 timeout_ms)
{
#ifdef WIN32
    cm_sleep(1);
#else
    eventfd_t count;
    int read_result = eventfd_read(etfd->efd, &count);
    if (read_result == -1) {
        struct epoll_event event;
        cm_atomic_inc(&etfd->wait_session_cnt);
        epoll_wait(etfd->epfd, &event, 1, timeout_ms);     // maxevents, timeout
        cm_atomic_dec(&etfd->wait_session_cnt);
    }
#endif // WIN32
}

void cm_wakeup_eventfd(cm_thread_eventfd_t *etfd)
{
#ifndef WIN32
    eventfd_write(etfd->efd, cm_atomic_get(&etfd->wait_session_cnt));
#endif // !WIN32
}

void cm_release_eventfd(cm_thread_eventfd_t *etfd)
{
#ifndef WIN32
    (void)close(etfd->efd);
    (void)epoll_close(etfd->epfd);
    etfd->efd = -1;
    etfd->epfd = -1;
#endif // !WIN32
}

void cm_init_cond(cm_thread_cond_t *cond)
{
    CM_POINTER(cond);
#ifdef WIN32
    cond->sem = CreateSemaphore(NULL, 0, 2048, NULL);
    cond->count = 0;
#else
    (void)pthread_condattr_init(&cond->attr);
    (void)pthread_mutex_init(&cond->lock, NULL);
    (void)pthread_condattr_setclock(&cond->attr, CLOCK_MONOTONIC);
    (void)pthread_cond_init(&cond->cond, &cond->attr);
#endif
}

bool32 cm_wait_cond(cm_thread_cond_t *cond, uint32 ms)
{
    int32 ret;

    if (ms == 0) {
        return GS_TRUE;
    }

#ifdef WIN32
    CM_POINTER(cond);

    (void)cm_atomic32_inc(&cond->count);
    ret = WaitForSingleObject(cond->sem, ms);
    cm_atomic32_dec(&cond->count);
    return (WAIT_OBJECT_0 == ret);
#else
    struct timespec signal_tv;

    CM_POINTER(cond);

    cm_get_timespec(&signal_tv, ms);
    (void)pthread_mutex_lock(&cond->lock);
    ret = pthread_cond_timedwait(&cond->cond, &cond->lock, &signal_tv);
    (void)pthread_mutex_unlock(&cond->lock);
    return (ret == 0);
#endif
}

void cm_release_cond(cm_thread_cond_t *cond)
{
    CM_POINTER(cond);
#ifdef WIN32
    ReleaseSemaphore(cond->sem, cond->count, NULL);
    cond->count = 0;
#else
    (void)pthread_cond_broadcast(&cond->cond);
#endif
}

void cm_release_cond_signal(cm_thread_cond_t *cond)
{
    CM_POINTER(cond);
#ifdef WIN32
    ReleaseSemaphore(cond->sem, cond->count, NULL);
    cond->count = 0;
#else
    (void)pthread_cond_signal(&cond->cond);
#endif
}

void cm_destory_cond(cm_thread_cond_t *cond)
{
    CM_POINTER(cond);

#ifdef WIN32
    (void)CloseHandle(cond->sem);
    cond->count = 0;
#else
    (void)pthread_mutex_destroy(&cond->lock);
    (void)pthread_cond_destroy(&cond->cond);
    (void)pthread_condattr_destroy(&cond->attr);
#endif
}

#ifdef WIN32

void cm_init_thread_lock(thread_lock_t *lock)
{
    InitializeCriticalSection(lock);
}

void cm_thread_lock(thread_lock_t *lock)
{
    EnterCriticalSection(lock);
}

void cm_thread_unlock(thread_lock_t *lock)
{
    LeaveCriticalSection(lock);
}

#else

void cm_init_thread_lock(thread_lock_t *lock)
{
    (void)pthread_mutex_init(lock, NULL);
}

void cm_thread_lock(thread_lock_t *lock)
{
    (void)pthread_mutex_lock(lock);
}

void cm_thread_unlock(thread_lock_t *lock)
{
    (void)pthread_mutex_unlock(lock);
}

#endif

#ifdef WIN32
static DWORD WINAPI cm_thread_run(void *arg)
#else
static void *cm_thread_run(void *arg)
#endif
{
    CM_POINTER(arg);
    thread_t *thread = (thread_t *)arg;
    thread_entry_t entry = (thread_entry_t)thread->entry;
    entry(thread);
#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

status_t cm_create_thread(thread_entry_t entry, uint32 stack_size, void *argument, thread_t *thread)
{
    CM_POINTER2(entry, thread);

    /* if stack_size is zero, set it with default size */
    if (stack_size == 0) {
        stack_size = GS_DFLT_THREAD_STACK_SIZE;
    }

    thread->argument = argument;
    thread->entry = (void *)entry;
    thread->closed = GS_FALSE;
    thread->stack_size = stack_size;
    thread->result = 0;
    thread->reg_data = NULL;

#ifdef WIN32
    thread->handle = CreateThread(NULL, stack_size, cm_thread_run, thread, 0, &thread->id);
    if (thread->handle == INVALID_HANDLE_VALUE) {
        GS_THROW_ERROR(ERR_CREATE_THREAD, "NULL");
        return GS_ERROR;
    }
#else
    pthread_attr_t attr;
    int errnum;

    if (pthread_attr_init(&attr) != 0) {
        GS_THROW_ERROR(ERR_INIT_THREAD);
        return GS_ERROR;
    }

    if (pthread_attr_setstacksize(&attr, stack_size) != 0) {
        (void)pthread_attr_destroy(&attr);
        GS_THROW_ERROR(ERR_SET_THREAD_STACKSIZE);
        return GS_ERROR;
    }
    
    if (pthread_attr_setguardsize(&attr, GS_DFLT_THREAD_GUARD_SIZE) != 0) {
        (void)pthread_attr_destroy(&attr);
        GS_THROW_ERROR(ERR_INIT_THREAD);
        return GS_ERROR;
    }

    errnum = pthread_create(&thread->id, &attr, cm_thread_run, (void *)thread);
    if (errnum != 0) {
        (void)pthread_attr_destroy(&attr);
        GS_THROW_ERROR_EX(ERR_CREATE_THREAD, "error code %d", errnum);
        return GS_ERROR;
    }

    (void)pthread_attr_destroy(&attr);
#endif

    return GS_SUCCESS;
}

void cm_close_thread_nowait(thread_t *thread)
{
    CM_POINTER(thread);
    thread->closed = GS_TRUE;
}

void cm_close_thread(thread_t *thread)
{
    CM_POINTER(thread);
    thread->closed = GS_TRUE;
#ifdef WIN32
    WaitForSingleObject(thread->handle, INFINITE);
#else
    void *ret = NULL;
    if (thread->id != 0) {
        (void)pthread_join(thread->id, &ret);
        thread->id = 0;
    }
#endif
}

void cm_release_thread(thread_t *thread)
{
    CM_POINTER(thread);
#ifdef WIN32
    return;
#else
    (void)pthread_detach(thread->id);
#endif
}

uint32 cm_get_current_thread_id()
{
    if (g_cm_thread_id.has_get) {
        return g_cm_thread_id.thread_id;
    }
#ifdef WIN32
    g_cm_thread_id.thread_id = (uint32)GetCurrentThreadId();
#else
#if (defined __x86_64__)
#define __SYS_GET_SPID 186
#elif (defined __aarch64__)
#define __SYS_GET_SPID 178
#elif (defined __loongarch__)
#include<sys/syscall.h>
#define __SYS_GET_SPID SYS_gettid
#endif
#define gettid() syscall(__SYS_GET_SPID)
    g_cm_thread_id.thread_id = (uint32)gettid();
#endif
    g_cm_thread_id.has_get = GS_TRUE;
    return g_cm_thread_id.thread_id;
}

bool32 cm_is_current_thread_closed()
{
    return GS_TRUE;
}

long cm_get_os_thread_stack_rlimit(void)
{
#ifdef WIN32
    /* no getrlimit */
    return WIN32_STACK_RLIMIT;
#else
    long stack_size = 0;
    struct rlimit rlim;

    if (getrlimit(RLIMIT_STACK, &rlim) < 0) { // The maximum value is used by default when the invoking fails
        stack_size = GS_MAX_THREAD_STACK_SIZE;
        return stack_size;
    }

    if (rlim.rlim_cur == RLIM_INFINITY || rlim.rlim_cur >= GS_MAX_THREAD_STACK_SIZE) {
        stack_size = GS_MAX_THREAD_STACK_SIZE;
    } else {
        stack_size = rlim.rlim_cur;
    }

    return stack_size;
#endif
}

void cm_switch_stack_base(thread_t *thread, char *stack_base, char **org_base)
{
    *org_base = thread->stack_base;
    thread->stack_base = stack_base;
}

#ifdef __cplusplus
}
#endif

