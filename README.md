# ebpf_monitor
> 基于ebpf的Linux资源监控

## 实现功能


## 架构图

## 使用说明

1. kafka容器

   ```shell
   sudo docker-compose up -d
   ```

2. cJSON库

   将ebpf程序采集到的元数据序列化。

   ```shell
   # 1. 下载源码
   git clone git@github.com:DaveGamble/cJSON.git
   # 2. 编译，安装
   mkdir build
   cd build
   cmake ..
   make
   make install
   # 此时头文件被安装至/usr/local/include/cjson路径中，库文件被安装至/usr/local/lib。
   # 3. 使用：在C语言代码中引入头文件<cjson/cJSON.h>，在编译参数中加上-lcjson链接
   
   # 踩坑：凡是对路径上含有 lib* 的文件进行写入修改的，关闭文件后都要在终端输入：`sudo ldconfig`，让这个 library 能被找到。
   ```

   