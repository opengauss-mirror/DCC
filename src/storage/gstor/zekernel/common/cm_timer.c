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
 * cm_timer.c
 *    update system timer timely
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_timer.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_timer.h"
#include "cm_log.h"

#define DAY_USECS (uint64)86400000000
static gs_timer_t timer;
static date_t sync_time;

gs_timer_t *g_timer()
{
    return &timer;
}

date_t cm_get_sync_time()
{
    return sync_time;
}

void cm_set_sync_time(date_t time)
{
    sync_time = time;
}

static void timer_proc(thread_t *thread)
{
    date_t start_time;
    gs_timer_t *timer_temp = (gs_timer_t *)thread->argument;
    int16 tz_min;

    start_time = cm_now();
    sync_time = start_time;
    timer_temp->status = TIMER_STATUS_RUNNING;
    cm_set_thread_name("timer");
    GS_LOG_RUN_INF("timer thread started");

    while (!thread->closed) {
        // In order to solve the thread deadlock problem caused by local_time_r function when fork child process.
        if (timer_temp->status == TIMER_STATUS_PAUSING) {
            timer_temp->status = TIMER_STATUS_PAUSED;
        }
        if (timer_temp->status == TIMER_STATUS_PAUSED) {
            cm_sleep(1);
            sync_time += MICROSECS_PER_MILLISEC;
            continue;
        }
        
        cm_now_detail((date_detail_t *)&timer_temp->detail);
        timer_temp->now = cm_encode_date((const date_detail_t *)&timer_temp->detail);
        timer_temp->monotonic_now = cm_monotonic_now();
        timer_temp->today = (timer_temp->now / DAY_USECS) * DAY_USECS;
        timer_temp->systime = (uint32)((timer_temp->now - start_time) / MICROSECS_PER_SECOND);

        // flush timezone
        tz_min = cm_get_local_tzoffset();
        timer_temp->tz = tz_min;
        timer_temp->host_tz_offset = tz_min * (int)SECONDS_PER_MIN * MICROSECS_PER_SECOND_LL;

        cm_sleep(2);

        // update sync_time
        if (sync_time <= timer_temp->now) {
            sync_time = timer_temp->now;
        } else {
            sync_time += 2 * MICROSECS_PER_MILLISEC;
        }
    }

    GS_LOG_RUN_INF("timer thread closed");
}

status_t cm_start_timer(gs_timer_t *input_timer)
{
    cm_now_detail((date_detail_t *)&input_timer->detail);
    input_timer->now = cm_encode_date((const date_detail_t *)&input_timer->detail);
    input_timer->monotonic_now = cm_monotonic_now();
    input_timer->today = (input_timer->now / DAY_USECS) * DAY_USECS;
    input_timer->systime = 0;
    int16 tz_min = cm_get_local_tzoffset();
    input_timer->tz = tz_min;
    input_timer->host_tz_offset = tz_min * (int)SECONDS_PER_MIN * MICROSECS_PER_SECOND_LL;
    return cm_create_thread(timer_proc, 0, input_timer, &input_timer->thread);
}

void cm_close_timer(gs_timer_t *input_timer)
{
    cm_close_thread(&input_timer->thread);
}

void cm_pause_timer(gs_timer_t *input_timer)
{
    input_timer->status = TIMER_STATUS_PAUSING;
    while (input_timer->status != TIMER_STATUS_PAUSED && !input_timer->thread.closed) {
        cm_sleep(3); // waitting 3s for changing status
    }
}

void cm_resume_timer(gs_timer_t *input_timer)
{
    input_timer->status = TIMER_STATUS_RUNNING;
}