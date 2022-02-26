cmake_minimum_required(VERSION 3.14.1)

add_subdirectory(gstor)

include_directories(${DCC_SECUREC_INC_PATH})
include_directories(${DCC_CBB_INC_PATH})
include_directories(${DCC_UTILS_PATH})
include_directories(${DCC_SERVER_PATH})
include_directories(${DCC_GSTOR_INC_PATH})

aux_source_directory(. STORAGE_SRC)

add_library(storage OBJECT ${STORAGE_SRC})
target_link_libraries(storage PRIVATE gstor pthread dl m rt ${G_BIN_EXT_LIBS})