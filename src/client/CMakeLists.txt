file(GLOB_RECURSE CURRENT_HEADERS *.h)
file(GLOB_RECURSE CURRENT_SOURCE *.c)

source_group("Include" FILES ${CURRENT_HEADERS})

include_directories(
    ${DCC_CBB_INC_PATH}
)
## other dependency include
include_directories(
    ${DCC_SECUREC_INC_PATH}
    ${DCC_OPENSSL_PATH}
    ${DCC_UTILS_PATH}
    ${DCC_NETWORK_PATH}
)

aux_source_directory(${DCC_CLIENT_PATH} CLIENT_SRC)

MESSAGE(STATUS ${DD_DCC_LIB_VERSION})
MESSAGE(STATUS ${DD_GETLIBVERSION})
add_compile_definitions(g_DCC_LIB_VERSION=${DD_DCC_LIB_VERSION})
add_compile_definitions(GETLIBVERSION=${DD_GETLIBVERSION})

# output client so
set(CLIENT_SRC_LIST ${CLIENT_SRC})
add_library(dcc_driver SHARED ${CLIENT_SRC_LIST})
target_link_libraries(dcc_driver utils network pthread dl rt ${HIDDEN_LIBS} -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libcbb} ${3rd_libssl} ${3rd_libz} -Wl,--no-whole-archive)
