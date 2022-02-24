file(GLOB_RECURSE CURRENT_HEADERS *.h)
file(GLOB_RECURSE CURRENT_SOURCE *.c)

source_group("Include" FILES ${CURRENT_HEADERS})

include_directories(
        ${DCC_CBB_INC_PATH}
        ${DCC_SECUREC_INC_PATH}
)

add_library(utils OBJECT ${CURRENT_SOURCE} ${CURRENT_HEADERS})