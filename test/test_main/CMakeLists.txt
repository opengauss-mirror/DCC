cmake_minimum_required(VERSION 3.14.1)
message(STATUS "dcc_main current_dir=${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_C_FLAGS "-g -D_FILE_NAME_='\"$(notdir $(subst .o,,$(abspath $@)))\"'")
set(CMAKE_CXX_FLAGS "-g -D_FILE_NAME_='\"$(notdir $(subst .o,,$(abspath $@)))\"'")

# include third party
include_directories(${DCC_SECUREC_INC_PATH})
include_directories(${DCC_OPENSSL_PATH})
include_directories(${DCC_CJSON_PATH})
include_directories(${DCC_DCF_INC_PATH})
include_directories(${DCC_CBB_INC_PATH})

# include project headers
include_directories(
${PROJECT_SOURCE_DIR}/src/client
${PROJECT_SOURCE_DIR}/src/client/interface
${PROJECT_SOURCE_DIR}/src/executor
${PROJECT_SOURCE_DIR}/src/network
${PROJECT_SOURCE_DIR}/src/server
${PROJECT_SOURCE_DIR}/src/storage
${PROJECT_SOURCE_DIR}/src/storage/gstor
${PROJECT_SOURCE_DIR}/src/tools
${PROJECT_SOURCE_DIR}/src/utils
${PROJECT_SOURCE_DIR}/src/interface
)

# link project output so
link_directories(${DCC_GSTORE_LIB_PATH})
link_directories(${LIBRARY_OUTPUT_PATH})

add_executable(dcc_main test_main.cpp)
target_link_libraries(dcc_main pthread dl dcc dcc_driver gstor dcf -Wl,--whole-archive ${3rd_lib_crypto} ${3rd_liblz4} ${3rd_libjson} ${3rd_libzstd} ${vpp_libsecurec} ${3rd_libcbb} ${3rd_libssl} ${3rd_libz} -Wl,--no-whole-archive)
target_compile_options(dcc_main PRIVATE -std=c++11)

set_target_properties(dcc_main
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)