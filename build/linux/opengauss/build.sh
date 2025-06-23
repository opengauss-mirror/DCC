#!/bin/bash
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
# Description  : dcc build for opengauss
#############################################################################

set -e

function print_help()
{
    echo "Usage: $0 [OPTION]
    -h|--help                show help information.
    -3rd|--{binarylib_dir}   the directory of third party binarylibs.
    -m|--version_mode        this values of paramenter is Debug, Release, the default value is Release.
    -t|--build_tool          this values of parameter is cmake, make, the default value is cmake.
"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_help
            exit 1
            ;;
        -3rd|--{binarylib_dir})
            if [ "$2"X = X ]; then
                echo "no given binarylib directory values"
                exit 1
            fi
            binarylib_dir=$2
            shift 2
            ;;
        -m|--version_mode)
          if [ "$2"X = X ]; then
              echo "no given version number values"
              exit 1
          fi
          version_mode=$2
          shift 2
          ;;
        -t|--build_tool)
          if [ "$2"X = X ]; then
              echo "no given build_tool values"
              exit 1
          fi
          build_tool=$2
          shift 2
          ;;
         *)
            echo "Internal Error: option processing error: $1" 1>&2
            echo "please input right paramtenter, the following command may help you"
            echo "./build.sh --help or ./build.sh -h"
            exit 1
    esac
done

if [ -z "${version_mode}" ] || [ "$version_mode"x == ""x ]; then
    version_mode=Release
fi
if [ -z "${binarylib_dir}" ]; then
    echo "ERROR: 3rd bin dir not set"
    exit 1
fi
if [ -z "${build_tool}" ] || [ "$build_tool"x == ""x ]; then
    build_tool=cmake
fi
if [ ! "$version_mode"x == "Debug"x ] && [ ! "$version_mode"x == "Release"x ]; then
    echo "ERROR: version_mode param is error"
    exit 1
fi
if [ ! "$build_tool"x == "make"x ] && [ ! "$build_tool"x == "cmake"x ]; then
    echo "ERROR: build_tool param is error"
    exit 1
fi
export CFLAGS="-std=gnu99"

LOCAL_PATH=${0}

CUR_PATH=$(pwd)

LOCAL_DIR=$(dirname "${LOCAL_PATH}")

export PACKAGE=$LOCAL_DIR/../../../
export OUT_PACKAGE=dcc

export DCC_LIBRARYS=$(pwd)/../../../library

[ -d "${DCC_LIBRARYS}" ] && rm -rf ${DCC_LIBRARYS}
mkdir -p $DCC_LIBRARYS/huawei_security
mkdir -p $DCC_LIBRARYS/openssl
mkdir -p $DCC_LIBRARYS/huawei_security
mkdir -p $DCC_LIBRARYS/openssl
mkdir -p $DCC_LIBRARYS/zstd
mkdir -p $DCC_LIBRARYS/cJSON
mkdir -p $DCC_LIBRARYS/zlib
mkdir -p $DCC_LIBRARYS/libaio/include
mkdir -p $DCC_LIBRARYS/dcf
mkdir -p $DCC_LIBRARYS/cbb

LIB_PATH=${binarylib_dir}/kernel/dependency/
PLAT_LIB_PATH=${binarylib_dir}/kernel/platform/
COPT_LIB_PATH=${binarylib_dir}/kernel/component/

cp -r $PLAT_LIB_PATH/Huawei_Secure_C/comm/lib     $DCC_LIBRARYS/huawei_security/lib
cp -r $LIB_PATH/openssl/comm/lib                  $DCC_LIBRARYS/openssl/lib
cp -r $LIB_PATH/zstd/lib                          $DCC_LIBRARYS/zstd/lib
cp -r $LIB_PATH/cjson/comm/lib                    $DCC_LIBRARYS/cJSON/lib
cp -r $LIB_PATH/zlib*/comm/lib                    $DCC_LIBRARYS/zlib/lib

cp -r $PLAT_LIB_PATH/Huawei_Secure_C/comm/include $DCC_LIBRARYS/huawei_security/include
cp -r $LIB_PATH/openssl/comm/include              $DCC_LIBRARYS/openssl/include
cp -r $LIB_PATH/zstd/include                      $DCC_LIBRARYS/zstd/include
cp -r $LIB_PATH/cjson/comm/include/cjson          $DCC_LIBRARYS/cJSON/include
cp -r $LIB_PATH/zlib*/comm/include                $DCC_LIBRARYS/zlib/include
cp -r /usr/include/libaio.h                       $DCC_LIBRARYS/libaio/include

cp -r $COPT_LIB_PATH/cbb/include                  $DCC_LIBRARYS/cbb/include
cp -r $COPT_LIB_PATH/cbb/lib                      $DCC_LIBRARYS/cbb/lib

cp -r $COPT_LIB_PATH/dcf/include                  $DCC_LIBRARYS/dcf/include
cp -r $COPT_LIB_PATH/dcf/lib                      $DCC_LIBRARYS/dcf/lib

cd $PACKAGE
if [ "$build_tool"x == "cmake"x ];then
    cmake -DCMAKE_BUILD_TYPE=${version_mode} -DTEST=OFF -DUT=OFF -DENABLE_GCOV=OFF -DENABLE_DCC_LITE=ON \
    -DENABLE_MEMCHECK=OFF -DENABLE_EXPORT_API=ON
    make -sj 8
else
    make clean
    make BUILD_TYPE=${version_mode} -sj 8
fi

mkdir -p ${binarylib_dir}/kernel/component/${OUT_PACKAGE}/include
mkdir -p ${binarylib_dir}/kernel/component/${OUT_PACKAGE}/lib
mkdir -p ${binarylib_dir}/kernel/component/${OUT_PACKAGE}/bin
cp ./src/client/interface/clt_interface.h   ${binarylib_dir}/kernel/component/${OUT_PACKAGE}/include
cp ./src/interface/dcc_interface.h          ${binarylib_dir}/kernel/component/${OUT_PACKAGE}/include
cp ./output/bin/*                           ${binarylib_dir}/kernel/component/${OUT_PACKAGE}/bin
cp ./output/lib/*.so                        ${binarylib_dir}/kernel/component/${OUT_PACKAGE}/lib
cp $COPT_LIB_PATH/dcf/lib/libdcf.so         ${binarylib_dir}/kernel/component/${OUT_PACKAGE}/lib
echo "build DCC SUCCESS"