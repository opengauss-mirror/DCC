#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# version V1.0
#
# used for build dcc entry
#
set -e
SCRIPTPATH=$(cd "$(dirname "$0")"; pwd)
cd ${SCRIPTPATH}/build/linux/opengauss
chmod +x build.sh
./build.sh "$@"