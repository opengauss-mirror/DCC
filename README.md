# Distributed Configuration Center
分布式配置中心，基于DCF实现的一个状态机，用于实现集群中配置信息管理；
openGauss CM依赖DCC组件对配置数据分布式存取，实现集群配置管理高可用能力；

#### 一、工程说明
##### 1、编程语言：C
##### 2、编译工程：cmake或make，建议使用cmake
##### 3、目录说明：
-   DCC：主目录，CMakeLists.txt为主工程入口；
-   src: 源代码目录，按子目录划分模块解耦；
-   test：测试工程
-   build：工程构建脚本

#### 二、编译指导
##### 1、概述
编译DCC需要依赖CBB、DCF和binarylibs三个组件。
-   CBB：DCC依赖的公共函数代码。可以从开源社区获取。
-   DCF：DCC依赖的分布式一致性框架能力。可以从开源社区获取。
-   binarylibs：依赖的第三方开源软件，你可以直接编译openGauss-third_party代码获取，也可以从开源社区下载已经编译好的并上传的一个副本。

##### 2、操作系统和软件依赖要求
支持以下操作系统：
-   CentOS 7.6（x86）
-   openEuler-20.03-LTS
-   openEuler-22.03-LTS
-   openEuler-24.03-LTS

适配其他系统，可参照openGauss数据库编译指导
当前DCC依赖第三方软件有securec、zlib、lz4、zstd、openssl、cjson;
编译DCC依赖的第三方软件要求与编译opengauss对依赖的第三方软件要求一致。
##### 3、下载DCC及依赖组件
可以从开源社区下载DCC、CBB、DCF和openGauss-third_party。
可以通过以下网站获取编译好的binarylibs。
https://opengauss.obs.cn-south-1.myhuaweicloud.com/2.0.0/openGauss-third_party_binarylibs.tar.gz
##### 4、编译第三方软件
在编译DCC之前，需要先编译DCC依赖的开源及第三方软件。这些开源及第三方软件存储在openGauss-third_party代码仓库中，通常只需要构建一次。如果开源软件有更新，需要重新构建软件。
用户也可以直接从binarylibs库中获取开源软件编译和构建的输出文件。
##### 5、代码编译
使用DCC/build/linux/opengauss/build.sh编译代码, 参数说明请见以下表格。<br>
| 选项 | 参数               | 说明                                   |
| ---  |:---              | :---                                   |
| -3rd | [binarylibs path] | 指定binarylibs路径。该路径必须是绝对路径。|
| -m | [version_mode] | 编译目标版本，Debug或者Release。默认Release|
| -t   | [build_tool]      | 指定编译工具，cmake或者make。默认cmake。|

现在只需使用如下命令即可编译：<br>
[user@linux dcc]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake<br>
完成编译后，动态库生成在DCC/output/lib目录中

#### 三、接口与使用示例
#####1. 接口说明

参见：DCC/src/interface/dcc_interface.h

#####2. DEMO示例

参见：DCC/test/test_main<br>
demo示例主要演示了一个dcc集群场景，进行简单的键值操作步骤与流程；<br>
示例中主要步骤说明：<br>
1. dcc参数设置与启动<br>
srv_set_param("NODE_ID", ...   -- 设置当前dcc节点node_id<br>
srv_set_param("DATA_PATH", ...   -- 设置dcc数据路径<br>
srv_set_param("ENDPOINT_LIST", ...   -- 设置dcc集群配置信息<br>
srv_dcc_register_status_notify()  -- 注册dcc角色变更通告回调函数<br>
srv_dcc_start() -- 启动dcc实例<br>
2. dcc创建会话并操作<br>
srv_dcc_alloc_handle(&handle); -- 创建一个dcc会话<br>
srv_dcc_put(handle, &key, &val, &option) -- 插入一个key/value键值对数据<br>
3. dcc结束会话与退出<br>
srv_dcc_free_handle(handle); -- 结束当前已创建的会话<br>
srv_dcc_stop(); -- 停止当前dcc实例<br>
