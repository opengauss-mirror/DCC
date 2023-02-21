file(GLOB_RECURSE CURRENT_HEADERS  *.h)
file(GLOB_RECURSE CURRENT_SOURCE  *.c)

source_group("Include" FILES ${CURRENT_HEADERS})

include_directories(${DCC_CBB_INC_PATH})
include_directories(${DCC_PARSE_PATH})

## other dependency include
include_directories(${DCC_SECUREC_INC_PATH})
include_directories(${DCC_OPENSSL_PATH})
include_directories(${DCC_UTILS_PATH})
include_directories(${DCC_CLIENT_PATH}/interface)

aux_source_directory(${DCC_CTL_PATH} CTL_SRC)

# output client bin
set(CTL_SRC_LIST  ${CTL_SRC})
add_executable(dcc_ctl ${CTL_SRC_LIST})
target_link_libraries(dcc_ctl utils dcc_driver pthread dl rt ${HIDDEN_LIBS} ${3rd_libzstd} ${3rd_libssl} ${3rd_lib_crypto} ${3rd_liblz4} -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libcbb} ${3rd_libz} -Wl,--no-whole-archive)
set_target_properties(dcc_ctl PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
set_target_properties(dcc_ctl PROPERTIES LINKER_LANGUAGE "C")