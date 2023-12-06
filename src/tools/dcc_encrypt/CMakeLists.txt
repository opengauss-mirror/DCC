file(GLOB_RECURSE CURRENT_HEADERS  *.h)
file(GLOB_RECURSE CURRENT_SOURCE  *.c)

source_group("Include" FILES ${CURRENT_HEADERS})

include_directories(${DCC_CBB_INC_PATH})


## other dependency include
include_directories(${DCC_OPENSSL_PATH})
include_directories(${DCC_SECUREC_INC_PATH})
include_directories(${DCC_LZ4_INC_PATH})

aux_source_directory(${DCC_ENCRYPT_PATH} ENCRYPT_SRC)

# output client bin
set(ENCRYPT_SRC_LIST  ${ENCRYPT_SRC})
add_executable(dcc_encrypt ${ENCRYPT_SRC_LIST})
target_link_libraries(dcc_encrypt pthread dl rt ${3rd_libcbb} ${3rd_libz} ${3rd_libssl} ${3rd_lib_crypto} ${HIDDEN_LIBS} -Wl,--whole-archive ${vpp_libsecurec} -Wl,--no-whole-archive)
set_target_properties(dcc_encrypt PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
set_target_properties(dcc_encrypt PROPERTIES LINKER_LANGUAGE "C")
