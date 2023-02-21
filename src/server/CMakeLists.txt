## other dependency include
include_directories(${DCC_SECUREC_INC_PATH})
include_directories(${DCC_OPENSSL_PATH})
include_directories(${DCC_DCF_INC_PATH})

include_directories(${DCC_CBB_INC_PATH})

## source
include_directories(${DCC_CLIENT_PATH})
include_directories(${DCC_EXECUTOR_PATH})
include_directories(${DCC_NETWORK_PATH})
include_directories(${DCC_SERVER_PATH})
include_directories(${DCC_STORAGE_PATH})
include_directories(${DCC_UTILS_PATH})
include_directories(${DCC_INTERFACE_PATH})
include_directories(${DCC_PARSE_PATH})

aux_source_directory(${DCC_SERVER_PATH} SERVER_SRC)


MESSAGE(STATUS "DCC LIB VERSION  "  ${DD_DCC_LIB_VERSION})
add_compile_definitions(g_DCC_LIB_VERSION=${DD_DCC_LIB_VERSION})
add_compile_definitions(GETLIBVERSION=${DD_GETLIBVERSION})
# output server so

set(DCC_SO_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/../interface/dcc_interface.h
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_agent.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_api.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_config.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_instance.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_logger.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_lsnr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_param.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_reactor.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_session.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_watch.c
        ${CMAKE_CURRENT_SOURCE_DIR}/srv_cmd_exe.c
)
add_library(dcc SHARED ${DCC_SO_SRC})
target_link_libraries(dcc storage dcf executor utils pthread dl rt ${HIDDEN_LIBS} ${G_BIN_EXT_LIBS} ${3rd_libzstd} ${3rd_libssl} ${3rd_lib_crypto} ${3rd_liblz4} ${3rd_libjson} -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libcbb} ${3rd_libz} -Wl,--no-whole-archive)
target_include_directories(dcc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# output server bin

set(DCC_EXE_SRC
        ${DCC_SO_SRC}
        ${CMAKE_CURRENT_SOURCE_DIR}/server.c
)

add_executable(dcc_server ${DCC_EXE_SRC})
target_link_libraries(dcc_server storage dcf executor utils pthread dl rt ${HIDDEN_LIBS} ${3rd_libzstd} ${3rd_libssl} ${3rd_lib_crypto} ${3rd_liblz4} ${3rd_libjson} -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libcbb} ${3rd_libz} -Wl,--no-whole-archive)
target_include_directories(dcc_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(dcc_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
set_target_properties(dcc_server PROPERTIES LINKER_LANGUAGE "C")