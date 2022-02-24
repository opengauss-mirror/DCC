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
 * srv_agent.h
 *    agent interface
 *
 * IDENTIFICATION
 *    src/server/srv_agent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_AGENT_H__
#define __SRV_AGENT_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_spinlock.h"
#include "cs_pipe.h"
#include "srv_session.h"
#include "cm_sync.h"
#include "cm_stack.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AGENT_SHRINK_THRESHOLD(threshlold_secs) (1000 * (uint32)(threshlold_secs))
#define AGENT_EXTEND_STEP 4

struct st_reactor;
typedef struct st_agent {
    struct st_reactor *reactor;
    session_t *session;
    thread_t thread;
    char *area_buf;
    cm_event_t event;
    cs_packet_t recv_pack;
    cs_packet_t send_pack;
    bool8 is_extend;
    uint8 unused[3];
    struct st_agent *prev;
    struct st_agent *next;
} agent_t;

typedef struct st_agent_pool {
    struct st_reactor *reactor;
    struct st_agent *agents;
    struct st_extend_agent *ext_agents;
    spinlock_t lock_idle;  // lock for idle queue
    biqueue_t idle_agents;
    uint32 idle_count;
    spinlock_t lock_new;     // lock for creating new agent
    biqueue_t blank_agents;  // agents not initialized
    uint32 blank_count;
    uint32 curr_count;  // agent pool has create thread num
    uint32 optimized_count;
    uint32 max_count;
    cm_event_t idle_evnt;  // when an session detached from agent, this event will be triggered.
    uint32 extended_count; //
    atomic32_t shrink_hit_count;
} agent_pool_t;

typedef struct st_extend_agent {
    struct st_agent *slot_agents;
    uint32 slot_agent_count;
} extend_agent_t;

status_t srv_attach_agent(session_t *session, agent_t **agent, bool32 nowait);
void srv_detach_agent(session_t *session);
void srv_bind_sess_agent(session_t *session, agent_t *agent);
status_t srv_create_agent_pool(agent_pool_t *agent_pool);
void srv_destroy_agent_pool(agent_pool_t *agent_pool);
void srv_shrink_agent_pool(agent_pool_t *agent_pool);
void srv_process_free_session(session_t *session);

#ifdef __cplusplus
}
#endif

#endif
