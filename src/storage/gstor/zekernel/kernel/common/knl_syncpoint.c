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
 * knl_syncpoint.c
 *    kernel syncpoint manage
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/common/knl_syncpoint.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_syncpoint.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C"{
#endif

#ifdef DB_DEBUG_VERSION
static uint32 sp_find_syncpoint(syncpoint_action_t *syncpoint_action, const char *name, bool32 *found)
{
    uint32 i = 0;
    uint32 num_active = syncpoint_action->active_syncpoint;
    syncpoint_def_t *def = NULL;

    for (; i < num_active; i++) {
        def = syncpoint_action->syncpoint_def + i;
        if (def->syncpoint_name.str[0] != '\0' && !strncmp(name, def->syncpoint_name.str, def->syncpoint_name.len)) {
            *found = GS_TRUE;
            return i;
        }
    }

    *found = GS_FALSE;
    return i;
}

static void sp_remove_syncpoint(syncpoint_action_t *syncpoint_action, uint32 index)
{
    errno_t err;
    syncpoint_def_t *tmp_def = syncpoint_action->syncpoint_def;
    char *dest = (char *) (tmp_def + index);
    char *src = (char *) (tmp_def + index + 1);

    /* the max number of syncpoint if 10, and sizeof(syncpoint_def_t) is 56, so it can be overflow */ 
    uint32 size = (GS_SESSION_MAX_SYNCPOINT - (index + 1)) * sizeof(syncpoint_def_t);
    uint32 dest_max = (GS_SESSION_MAX_SYNCPOINT - index) * sizeof(syncpoint_def_t);

    err = memmove_s(dest, dest_max, src, size);
    knl_securec_check(err);
    syncpoint_action->active_syncpoint--;
}

status_t sp_add_syncpoint(knl_handle_t knl_session, syncpoint_def_t *syncpoint_def)
{
    errno_t err;
    uint32 inx;
    bool32 found = GS_FALSE;
    syncpoint_action_t *syncpoint_action = &((knl_session_t *) knl_session)->syncpoint_action;
    syncpoint_def_t *tmp_def = NULL;

    inx = sp_find_syncpoint(syncpoint_action, syncpoint_def->syncpoint_name.str, &found);
    if (INDEX_IS_INVALID(inx)) {
        GS_THROW_ERROR(ERR_OUT_OF_INDEX, "syncpoint for single session", GS_SESSION_MAX_SYNCPOINT);
        return GS_ERROR;
    }

    tmp_def = syncpoint_action->syncpoint_def + inx;
    err = memcpy_sp(tmp_def, sizeof(syncpoint_def_t), syncpoint_def, sizeof(syncpoint_def_t));
    knl_securec_check(err);
    if (!found) {
        syncpoint_action->active_syncpoint++;
    }

    return GS_SUCCESS;
}

status_t sp_exec_syncpoint(knl_handle_t knl_session, const char *syncpoint_name)
{
    errno_t err;
    uint32 i, inx, count;
    bool32 found = GS_FALSE;
    bool32 wait_done = GS_FALSE;
    syncpoint_t *syncpoint = &((knl_session_t *) knl_session)->kernel->syncpoint;
    syncpoint_action_t *syncpoint_action = &((knl_session_t *) knl_session)->syncpoint_action;
    syncpoint_def_t *tmp_def = NULL;

    inx = sp_find_syncpoint(syncpoint_action, syncpoint_name, &found);
    if (!found) {
        if (INDEX_IS_INVALID(inx)) {
            GS_THROW_ERROR(ERR_OUT_OF_INDEX, "syncpoint for single session", GS_SESSION_MAX_SYNCPOINT);
            return GS_ERROR;
        } else {
            return GS_SUCCESS;
        }
    }

    tmp_def = syncpoint_action->syncpoint_def + inx;
    if (tmp_def->signal.str != NULL) {
        count = tmp_def->raise_count;

        cm_spin_lock(&syncpoint->syncpoint_lock, NULL);
        for (i = 0; i < count; i++) {
            /* the num_signal is less than GS_CONCURRENT_MAX_SYNCPOINT, so it can not cross array's border */
            err = strncpy_s(syncpoint->signals + syncpoint->num_signal * GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE,
                            tmp_def->signal.str, tmp_def->signal.len);
            knl_securec_check(err);
            syncpoint->num_signal++;
        }
        cm_spin_unlock(&syncpoint->syncpoint_lock);
    }

    if (tmp_def->wait_for.str != NULL) {
        while (!wait_done) {
            cm_spin_lock(&syncpoint->syncpoint_lock, NULL);
            count = syncpoint->num_signal;
            for (i = 0; i < count; i++) {
                if (!cm_strcmpni(tmp_def->wait_for.str, "abort", strlen("abort"))) {
                    CM_ABORT(0, "ABORT INFO: instance exit while doing syncpoint test");
                }

                /*
                 * i < count <= GS_CONCURRENT_MAX_SYNCPOINT,
                 * so it can not access the memory where cross the array's border
                 */
                if (!strncmp(tmp_def->wait_for.str, syncpoint->signals + (i * GS_NAME_BUFFER_SIZE),
                             tmp_def->wait_for.len)) {
                    char *dest = syncpoint->signals + (i * GS_NAME_BUFFER_SIZE);
                    char *src = syncpoint->signals + ((i + 1) * GS_NAME_BUFFER_SIZE);
                    
                    /*
                     * GS_CONCURRENT_MAX_SYNCPOINT equal to 0x80, and GS_NAME_BUFFER_SIZE equal to 68,
                     * so it can be overflow
                     */
                    uint32 size = (GS_CONCURRENT_MAX_SYNCPOINT - (i + 1)) * GS_NAME_BUFFER_SIZE;
                    uint32 dest_max = (GS_CONCURRENT_MAX_SYNCPOINT - i) * GS_NAME_BUFFER_SIZE;

                    err = memmove_s(dest, dest_max, src, size);
                    knl_securec_check(err);
                    syncpoint->num_signal--;
                    wait_done = GS_TRUE;
                }
            }
            cm_spin_unlock(&syncpoint->syncpoint_lock);

            if (!wait_done) {
                cm_sleep(10);
            }
        }
    }

    sp_remove_syncpoint(syncpoint_action, inx);
    return GS_SUCCESS;
}

status_t sp_reset_syncpoint(knl_handle_t knl_session)
{
    errno_t err;
    syncpoint_t *syncpoint = &((knl_session_t *) knl_session)->kernel->syncpoint;

    cm_spin_lock(&syncpoint->syncpoint_lock, NULL);
    err = memset_sp(syncpoint->signals, sizeof(syncpoint->signals), 0, sizeof(syncpoint->signals));
    knl_securec_check(err);
    syncpoint->num_signal = 0;
    cm_spin_unlock(&syncpoint->syncpoint_lock);
    return GS_SUCCESS;
}

void sp_clear_syncpoint_action(knl_handle_t knl_session)
{
    errno_t err;
    syncpoint_action_t *syncpoint_action = &((knl_session_t *) knl_session)->syncpoint_action;
    uint32 syscpoint_size = sizeof(syncpoint_action_t);

    err = memset_sp(syncpoint_action, syscpoint_size, 0, syscpoint_size);
    knl_securec_check(err);
}
#endif /* DB_DEBUG_VERSION */

#ifdef __cplusplus
}
#endif

