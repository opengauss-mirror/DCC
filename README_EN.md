# Distributed Configuration Center

Distributed Configuration Center (DCC) is a state machine based on Distributed Consensus Framework (DCF) and is used to manage cluster configuration information.
openGauss Cluster Manager (CM) depends on the DCC component to store and obtain configuration data in a distributed manner, implementing high availability of cluster configuration management.

## 1. Project Description

### 1. Programming language: C

### 2. Compilation project: CMake (recommended) or Make

### 3. Directories

- `DCC`: the main directory. The `CMakeLists.txt` file is the main project entry.
- `src`: the source code directory, where modules are decoupled by subdirectory.
- `test`: the test project
- `build`: the project building script

## 2. Compilation Guide

### 1. Overview

DCC compilation depends on the `CBB`, `DCF`, and `binarylibs` components.

- `CBB`: common function code, which can be obtained from the open-source community.
- `DCF`: the distributed consensus framework, which can be obtained from the open-source community.
- `binarylibs`: third-party open-source software. Run code in `openGauss-third_party` to obtain it, or download the compiled software from the open-source community.

### 2. OS and Software Requirements

The following OSs are supported:

- CentOS 7.6 (x86)
- openEuler 20.03 LTS
- openEuler 22.03 LTS
- openEuler 24.03 LTS

For details about how to adapt to other OSs, see the openGauss compilation guide.
Currently, DCC depends on the following third-party software: SecureC, zlib, LZ4, zstd, OpenSSL, and cJSON.
The requirements for the third-party software on which DCC compilation depends are the same as those for compiling openGauss.

### 3. Downloading DCC and Its Required Components

Access `DCC`, `CBB`, `DCF`, and `openGauss-third_party` from the open-source community.
Download compiled `binarylibs` from the following website:
<https://opengauss.obs.cn-south-1.myhuaweicloud.com/2.0.0/openGauss-third_party_binarylibs.tar.gz>

### 4. Compiling Third-Party Software

Before compiling DCC, compile the open-source and third-party software on which DCC depends. Open-source and third-party software is stored in the `openGauss-third_party` code repository and usually needs to be built only once. If the open-source software is updated, you need to rebuild the software.
Alternatively, obtain the compiled open-source software from `binarylibs`.

### 5. Compiling Code

Use `DCC/build/linux/opengauss/build.sh` to compile the code. The following table describes the parameters.<br>

| Option| Parameter              | Description                                  |
| ---  |:---              | :---                                   |
| -3rd | [binarylibs path] | Specifies the `binarylibs` path, which must be an absolute path.|
| -m | [version_mode] | Specifies the target version to be compiled, which can be `Debug` or `Release` (default).|
| -t   | [build_tool]      | Specifies the compilation tool, which can be `cmake` (default) or `make`.|

Run the following command to perform compilation:<br>
`[user@linux dcc]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake`<br>
After the compilation is complete, the dynamic library is generated under the `DCC/output/lib` directory.

## 3. APIs and Usage Examples

### 1. APIs

Reference: `DCC/src/interface/dcc_interface.h`

### 2. Demos

Reference: `DCC/test/test_main`<br>
The demo demonstrates the procedure for performing simple key-value operations in a DCC cluster.<br>
Main steps in the example:<br>

1. Set and start DCC parameters.<br>
srv_set_param("NODE_ID", ...   -- Set the `node_id` of the current DCC node.<br>
srv_set_param("DATA_PATH", ...   -- Set the DCC data path.<br>
srv_set_param("ENDPOINT_LIST", ...   -- Set the DCC cluster configuration.<br>
srv_dcc_register_status_notify()  -- Register the callback function for DCC role change notification.<br>
srv_dcc_start() -- Start the DCC instance.<br>
2. Create a DCC session and perform operations.<br>
srv_dcc_alloc_handle(&handle); -- Create a DCC session.<br>
srv_dcc_put(handle, &key, &val, &option) -- Insert a key-value pair.<br>
3. End the DCC session and exit.<br>
srv_dcc_free_handle(handle); -- End the current session.<br>
srv_dcc_stop(); -- Stop the current DCC instance.<br>
