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
 * cm_spinlock.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_spinlock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_SPINLOCK_H_
#define __CM_SPINLOCK_H_

#include "cm_defs.h"

#ifndef WIN32
#include <time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef volatile uint32 spinlock_t;
typedef volatile uint32 ip_spinlock_t;
#if defined(__arm__) || defined(__aarch64__)
#define GS_INIT_SPIN_LOCK(lock)                       \
    {                                                 \
        __atomic_store_n(&lock, 0, __ATOMIC_SEQ_CST); \
    }
#else
#define GS_INIT_SPIN_LOCK(lock) \
    {                           \
        (lock) = 0;               \
    }
#endif

#define GS_SPIN_COUNT             1000
#define SPIN_STAT_INC(stat, item) \
    {                             \
        if ((stat) != NULL) {     \
            ((stat)->item)++;     \
        }                         \
    }

typedef struct st_spin_statis {
    uint64 spins;
    uint64 wait_usecs;
    uint64 fails;
} spin_statis_t;

// caution!! can not use by session 0
typedef struct st_recursive_lock {
    spinlock_t mutex;
    uint16 sid;
    uint16 r_cnt;
} recursive_lock_t;

#if defined(__arm__) || defined(__aarch64__) || defined(__loongarch__)
#define fas_cpu_pause()          \
    {                            \
        __asm__ volatile("nop"); \
    }
#else
#define fas_cpu_pause()            \
    {                              \
        __asm__ volatile("pause"); \
    }
#endif

void cm_spin_sleep_and_stat(spin_statis_t *stat);
void cm_spin_sleep_and_stat2(uint32 ms);
uint64 cm_total_spin_usecs();

#ifdef WIN32

static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    return (uint32)InterlockedExchange(ptr, value);
}

static inline void cm_spin_sleep()
{
    Sleep(1);
}

static inline void cm_spin_sleep_ex(uint32 tick)
{
    Sleep(tick);
}

#else

#if defined(__arm__) || defined(__aarch64__)
static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    uint32 oldvalue = 0;
    return !__atomic_compare_exchange_n(ptr, &oldvalue, value, GS_FALSE, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
static inline void cm_spin_unlock(spinlock_t *lock)
{
    __atomic_store_n(lock, 0, __ATOMIC_SEQ_CST);
}

#else
static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    uint32 oldvalue = 0;
    return (uint32)__sync_val_compare_and_swap(ptr, oldvalue, value);
}
#endif

static inline void cm_spin_sleep()
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100;
    nanosleep(&ts, NULL);
}

static inline void cm_spin_sleep_ex(uint32 tick)
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = tick;
    nanosleep(&ts, NULL);
}

#endif

static inline void cm_spin_lock(spinlock_t *lock, spin_statis_t *stat)
{
    uint32 spin_times = 0;
    uint32 sleep_times = 0;

    if (SECUREC_UNLIKELY(lock == NULL)) {
        return;
    }

    for (;;) {
#if defined(__arm__) || defined(__aarch64__)
        while (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
        while (*lock != 0) {
#endif
            SPIN_STAT_INC(stat, spins);
            spin_times++;
            if (SECUREC_UNLIKELY(spin_times == GS_SPIN_COUNT)) {
                cm_spin_sleep_and_stat(stat);
                spin_times = 0;
            }
        }

        if (SECUREC_LIKELY(cm_spin_set(lock, 1) == 0)) {
            break;
        }

        SPIN_STAT_INC(stat, fails);
        sleep_times++;
#ifndef WIN32
        for (uint32 i = 0; i < sleep_times; i++) {
            fas_cpu_pause();
        }
#endif
    }
}

static inline void cm_spin_lock_ex(spinlock_t *lock, spin_statis_t *stat, uint32 spin_count)
{
    uint32 spin_times = 0;
    uint32 sleep_times = 0;
    if (SECUREC_UNLIKELY(lock == NULL)) {
        return;
    }

    for (;;) {
#if defined(__arm__) || defined(__aarch64__)
        while (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
        while (*lock != 0) {
#endif
            SPIN_STAT_INC(stat, spins);
            spin_times++;
#ifndef WIN32
            fas_cpu_pause();
#endif  // !WIN32

            if (SECUREC_UNLIKELY(spin_times == spin_count)) {
                cm_spin_sleep_and_stat(stat);
                spin_times = 0;
            }
        }

        if (cm_spin_set(lock, 1) != 0) {
            SPIN_STAT_INC(stat, fails);
            sleep_times++;
#ifndef WIN32
            for (uint32 i = 0; i < sleep_times; i++) {
                fas_cpu_pause();
            }
#endif
            continue;
        }
        break;
    }
}

#if !defined(__arm__) && !defined(__aarch64__)
static inline void cm_spin_unlock(spinlock_t *lock)
{
    if (SECUREC_UNLIKELY(lock == NULL)) { 
        return; 
    } 

    *lock = 0;
}
#endif

static inline bool32 cm_spin_try_lock(spinlock_t *lock)
{
#if defined(__arm__) || defined(__aarch64__)
    if (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
    if (*lock != 0) {
#endif
        return GS_FALSE;
    }

    return (cm_spin_set(lock, 1) == 0);
}

static inline bool32 cm_spin_timed_lock(spinlock_t *lock, uint32 timeout_ticks)
{
    uint32 spin_times = 0, wait_ticks = 0;
    uint32 sleep_times = 0;

    for (;;) {
#if defined(__arm__) || defined(__aarch64__)
        while (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
        while (*lock != 0) {
#endif
            if (SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
                return GS_FALSE;
            }

#ifndef WIN32
            fas_cpu_pause();
#endif  // !WIN32

            spin_times++;
            if (SECUREC_UNLIKELY(spin_times == GS_SPIN_COUNT)) {
                cm_spin_sleep();
                spin_times = 0;
                wait_ticks++;
            }
        }

        if (cm_spin_set(lock, 1) != 0) {
            sleep_times++;
#ifndef WIN32
            for (uint32 i = 0; i < sleep_times; i++) {
                fas_cpu_pause();
            }
#endif
            continue;
        }
        break;
    }

    return GS_TRUE;
}

// caution!! can not use by session 0
static inline void cm_recursive_lock(uint16 sid, recursive_lock_t *lock, spin_statis_t *stat)
{
    if (lock->sid == sid) {
        lock->r_cnt++;
        return;
    }

    cm_spin_lock(&lock->mutex, stat);

    lock->sid = sid;
    lock->r_cnt = 1;
}

// caution!! can not use by session 0
static inline void cm_recursive_unlock(recursive_lock_t *lock)
{
    if (lock->r_cnt > 1) {
        lock->r_cnt--;
        return;
    }
    lock->r_cnt = 0;
    lock->sid = 0;
    cm_spin_unlock(&lock->mutex);
}

static inline void cm_spin_lock_if_exists(spinlock_t *lock, spin_statis_t *stat)
{
    if (lock == NULL) {
        return;
    }
    cm_spin_lock(lock, stat);
}

static inline void cm_spin_unlock_if_exists(spinlock_t *lock)
{
    if (lock == NULL) {
        return;
    }
    cm_spin_unlock(lock);
}

#ifdef __cplusplus
}
#endif

#endif
