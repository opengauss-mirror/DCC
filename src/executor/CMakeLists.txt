file(GLOB_RECURSE CURRENT_HEADERS *.h)
file(GLOB_RECURSE CURRENT_SOURCE *.c)

source_group("Include" FILES ${CURRENT_HEADERS})

include_directories(
        ${DCC_CBB_INC_PATH}
        ${DCC_SECUREC_INC_PATH}
        ${DCC_UTILS_PATH}
        ${DCC_INTERFACE_PATH}
        ${DCC_EXECUTOR_PATH}
        ${DCC_STORAGE_PATH}
        ${DCC_SERVER_PATH}
        ${DCC_DCF_INC_PATH}
)

add_library(executor OBJECT ${CURRENT_SOURCE} ${CURRENT_HEADERS})