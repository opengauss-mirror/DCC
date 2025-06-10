cmake_minimum_required(VERSION 3.14.1)

project(zekernel)

if (UNIX)
    message(${CMAKE_BUILD_TYPE})
    if (${CMAKE_BUILD_TYPE} STREQUAL "Debug"
         OR ${CMAKE_BUILD_TYPE} STREQUAL "")
        message(STATUS "CMAKE_BUILD_TYPE is Debug")
        set(CMAKE_BUILD_TYPE Debug)
        add_compile_definitions(_DEBUG)
    elseif (${CMAKE_BUILD_TYPE} STREQUAL "Release")
        message(STATUS "CMAKE_BUILD_TYPE is Release")
        set(CMAKE_BUILD_TYPE Release)
        set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
    else ()
        message(STATUS "unknown CMAKE_BUILD_TYPE = " ${CMAKE_BUILD_TYPE})
    endif ()

    OPTION(ENABLE_GCOV "Enable gcov (debug, Linux builds only)" OFF)
    message(STATUS "ZEKERNEL ENABLE_GCOV = ${ENABLE_GCOV}")
    IF (ENABLE_GCOV AND NOT WIN32)
        message(STATUS "ZEKERNEL Enable gcov")
        SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -lgcov")
        SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")

        SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    ENDIF()

    # Use "-fPIC" / "-fPIE" for all targets by default, including static libs
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    # CMake doesn't add "-pie" by default for executables
    add_link_options(-pie)

    execute_process(
            COMMAND uname -p
            OUTPUT_VARIABLE OS_ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(CMAKE_SYSTEM_PROCESSOR ${OS_ARCH})

    if (OS_ARCH STREQUAL "aarch64")
        message(STATUS "aarch64 CPU")
        option(USE_H1620 OFF)
        if (USE_H1620)
            add_compile_options(-march=armv8-a+crc+lse)
            message(STATUS "Toolchain: Build aarch64 USE_H1620")
        else ()
            add_compile_options(-march=armv8-a+crc)
        endif (USE_H1620)

        add_compile_options(-mtune=cortex-a72 -fsigned-char -g -ggdb3 -march=armv8-a+crc -funwind-tables)
    elseif (OS_ARCH STREQUAL "x86_64")
        message(STATUS "x86_64 CPU")
        add_compile_options(-mtune=nocona -fsigned-char -msse4.2 )
    endif ()
else ()
    set(CMAKE_BUILD_TYPE Debug)
    add_compile_definitions(_DEBUG)
endif ()

if ("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    message("++ 64 bit architecture")
    set(ARCHBIT "64")
else ()
    message("++ 32 bit architecture")
    set(ARCHBIT "32")
    add_compile_options(-m32)
endif ()

if (UNIX)
    set_property(TARGET PROPERTY C_STANDARD 99)
    add_compile_options(-fPIC -Wall -MMD -fno-strict-aliasing -fsigned-char -fms-extensions -Wno-array-bounds -Wno-maybe-uninitialized)
    add_compile_definitions(_GNU_SOURCE _LARGEFILE64_SOURCE KNL_PREFIX _REENTRANT)

    add_compile_options(-fvisibility=default -fstack-protector-strong --param ssp-buffer-size=4)
    add_link_options(-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now)
    set(CMAKE_SKIP_RPATH TRUE)
endif ()

# zekernel include_directories
set(ZEKERNEL_CM_PATH common)
set(ZEKERNEL_CM_VAR_PATH common/variant)
set(ZEKERNEL_PROTOCOL_PATH protocol)

# open source include
set(DCC_HOME ../../../..)
set(SECUREC_INC_PATH        "${DCC_HOME}/library/huawei_security/include")
set(OPENSSL_PATH            "${DCC_HOME}/library/openssl/include/")
set(OPENSSL_PATH_EX         "${DCC_HOME}/library/openssl/include/openssl")
set(ZLIB_INC_PATH           "${DCC_HOME}/library/zlib/include")
set(ZSTANDARD_INC_PATH      "${DCC_HOME}/library/zstd/include")
set(LIBAIO_INC_PATH         "${DCC_HOME}/library/libaio/include")
set(PCRE_INC_PATH            "${DCC_HOME}/library/pcre/include")

# open source lib
set(SECUREC_LIB_PATH        "${DCC_HOME}/library/huawei_security/lib")
set(OPENSSL_LIB_PATH        "${DCC_HOME}/library/openssl/lib")
set(ZLIB_LIB_PATH           "${DCC_HOME}/library/zlib/lib")
set(ZSTANDARD_LIB_PATH      "${DCC_HOME}/library/zstd/lib")
set(PCRE_LIB_PATH           "${DCC_HOME}/library/pcre/lib")

set(vpp_libsecurec "securec")
set(3rd_liblz4 "lz4")
set(3rd_libz "z")
set(3rd_libzstd "zstd")
set(3rd_libssl "ssl")
set(3rd_lib_crypto "crypto")
set(3rd_libpcre "pcre")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -g -ldl -pthread -D__FILE_NAME__='\"$(notdir $(subst .o,,$(abspath $@)))\"'")
add_compile_options(-fno-common)
add_compile_options(-Wtrampolines)
add_compile_options(-freg-struct-return)
add_compile_options(-pipe)
add_link_options(-Wl,-Bsymbolic)
if (UNIX)
    add_link_options(-rdynamic)
endif()

include_directories(${ZEKERNEL_CM_PATH})
include_directories(${ZEKERNEL_CM_VAR_PATH})
include_directories(${ZEKERNEL_PROTOCOL_PATH})
include_directories(${SECUREC_INC_PATH})
include_directories(${OPENSSL_PATH})
include_directories(${OPENSSL_PATH_EX})
include_directories(${LZ4_INC_PATH})
include_directories(${ZLIB_INC_PATH})
include_directories(${ZSTANDARD_INC_PATH})
include_directories(${LIBAIO_INC_PATH})
include_directories(${PCRE_INC_PATH})

link_directories(${SECUREC_LIB_PATH} ${OPENSSL_LIB_PATH} ${LZ4_LIB_PATH} ${ZLIB_LIB_PATH} ${ZSTANDARD_LIB_PATH} ${LIBRARY_OUTPUT_PATH} ${PCRE_LIB_PATH})

add_subdirectory(common)
add_subdirectory(protocol)
add_subdirectory(kernel)