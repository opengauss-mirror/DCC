#include "cm_types.h"
#include "securec.h"
#include "cm_file.h"
#include "util_error.h"
#include "srv_config.h"
#include "srv_logger.h"
#include "util_defs.h"
#include "dcc_interface.h"
#include "executor.h"
#include <string>
#include "cm_timer.h"

#ifdef WIN32
#define PRINT_TIME
#define PRINT_TIME_FILE(file)
#else
#define PRINT_TIME_FILE(fp) \
do { \
    time_t now = time(NULL); \
    struct tm result; \
    localtime_r(&now, &result); \
    if((fp) == (void*)-1){ \
        printf("%d-%02d-%02d %02d:%02d:%02d ",result.tm_year + 1900,result.tm_mon + 1,result.tm_mday,\
            result.tm_hour,result.tm_min,result.tm_sec); \
    } \
} while(0);
#define PRINT_TIME  PRINT_TIME_FILE((void*)-1)
#endif

int usr_cb_status_changed_notify(dcc_role_t new_role)
{
    PRINT_TIME;
    printf("usr_cb_status_changed_notify, new_role=%u \n", new_role);
    return 0;
}

static std::string test_dcc_main_root_path = "./test_dcc_main";

static int test_main_srv_dcc_start(uint32 nodeid, char *cfg_str)
{
    char nodeidstr[4] = {0};
    char data_path[256] = {0};
    char gstor_dir[256] = {0};
    int len = sprintf_s(nodeidstr, 4, "%d", nodeid);
    if (len < 0) {
        return CM_ERROR;
    }
    srv_dcc_set_param("NODE_ID", nodeidstr);

    len = sprintf_s(data_path, 256, "%s/node%d", test_dcc_main_root_path.c_str(), nodeid);
    if (len < 0) {
        return CM_ERROR;
    }
    srv_dcc_set_param("DATA_PATH", data_path);

    len = sprintf_s(gstor_dir, 256, "%s/node%d/gstor", test_dcc_main_root_path.c_str(), nodeid);
    if (len < 0) {
        return CM_ERROR;
    }

    if (srv_dcc_set_param("ENDPOINT_LIST", cfg_str) != CM_SUCCESS) {
        printf("srv_dcc_set_param ENDPOINT_LIST failed, %s\n", cfg_str);
        return CM_ERROR;
    } else {
        printf("srv_dcc_set_param ENDPOINT_LIST succedd, %s\n", cfg_str);
    }

    (void)srv_dcc_register_status_notify(usr_cb_status_changed_notify);

    int ret = srv_dcc_start();
    if (ret != CM_SUCCESS) {
        printf("srv_dcc_start failed\n");
        return CM_ERROR;
    }

    sleep(8);

    return CM_SUCCESS;
}

static void test_main_srv_dcc_stop()
{
    int ret = srv_dcc_stop();
    if (ret != CM_SUCCESS) {
        printf("srv_dcc_stop failed\n");
    }
    sleep(2);
}

int main(int argc, char *argv[])
{
    uint32 node_id = 0;
    char* cfg_str;
    char* err = NULL;

    if (argc >= 2) {
        node_id =  (int)strtoll(argv[1], &err, 10);
        printf("current nodeid=%d\n", node_id);
    } else {
        printf("no nodeid\n");
        return 0;
    }

    if (argc >= 3) {
        cfg_str = argv[2];
    } else {
        printf("no cluster cfg info\n");
        return 0;
    }

    int ret = test_main_srv_dcc_start(node_id, cfg_str);
    if (ret != CM_SUCCESS) {
        PRINT_TIME;
        printf("test_main_srv_dcc_start failed\n");
        return 0;
    } else {
        PRINT_TIME;
        printf("test_main_srv_dcc_start succeed\n");
    }

    void *handle = NULL;
    ret = srv_dcc_alloc_handle(&handle);
    if (ret != CM_SUCCESS) {
        return 0;
    }

    int put_cnt = 0;
    do {
        dcc_node_status_t node_stat;
        int ret = srv_dcc_get_node_status(&node_stat);
        if (ret != CM_SUCCESS) {
            printf("srv_dcc_get_node_status failed\n");
            return 0;
        }

        if (node_stat.is_healthy == CM_FALSE || node_stat.role_type != DCC_ROLE_LEADER) {
            PRINT_TIME;
            printf("my role: %d, my healthy: %s\n", node_stat.role_type, (node_stat.is_healthy == CM_TRUE) ? "OK": "NOK");
            sleep(5);
            continue;
        }

        dcc_text_t key, val;
        char value[256] = {'a'};
        value[255] = '\0';
        key.len = 8;
        key.value = (char *)"key4567";
        val.len = 256;
        val.value = value;
        dcc_option_t option;
        option.write_op.is_prefix = 0;
        option.write_op.expect_val_size = 0;
        ret = srv_dcc_put(handle, &key, &val, &option);
        if (ret == CM_SUCCESS) {
            put_cnt++;
            if (put_cnt % 5 == 0) {
                PRINT_TIME;
                printf("put succeed, put cnt=%d\n", put_cnt);
            }
        } else {
            PRINT_TIME;
            printf("put failed, put_cnt=%d\n", put_cnt);
        }
        sleep(1);
    } while (1);

    srv_dcc_free_handle(handle);

    test_main_srv_dcc_stop();

    return 0;
}