---
title: 'QEMU-user(1)'
date: 2026-09-08 10:41:08
categories:
  - 固件分析
tags:
  - QEMU
  - binwalk
  - 固件提取
---
## 扫描固件结构
运行
```
binwalk /home/kali/Desktop/DCS-930L_Ax_v1.15.04.bin
```
![](/images/Pasted%20image%2020260908104108.png)
- 固件包含 Linux 内核。
- CPU 是 MIPS。
- `0x50040` 是跳过 64 字节 uImage 头后的 LZMA 内核数据
## 提取内核
创建目录
```
mkdir -p ~/Desktop/dcs930l-lab/firmware
cd ~/Desktop/dcs930l-lab/firmware
```
根据 uImage 头给出的数据长度，从 `0x50040` 提取 LZMA 流：
```
dd if=~/Desktop/DCS-930L_Ax_v1.15.04.bin \
   of=kernel.lzma \
   bs=1 skip=327744 count=3791604 status=progress
```
![](/images/Pasted%20image%2020260908104842.png)
解压一下
```
xz --format=lzma --decompress --stdout kernel.lzma > kernel.unpacked
```
得到kernel.unpacked，即内核数据
```
file kernel.unpacked
```
binwalk，查看内核数据，找到内核里嵌入的 rootfs 压缩流
![](/images/Pasted%20image%2020260908105531.png)
## 提取 rootfs
```
dd if=kernel.unpacked of=rootfs.lzma \
   bs=1 skip=$((0x3da000)) status=progress
```
解压
```
xz --format=lzma --decompress --stdout rootfs.lzma > rootfs.cpio
file rootfs.cpio
```
补充:
`.cpio` 文件本质上是一种**归档文件格式**（Archive Format），它的作用类似于 **`.tar`** 文件——**只负责将多个文件和目录打包成一个大文件，本身并不进行数据压缩**

当然来问题了，通常不是直接解压文件吗，怎么这次解压到.cpio归档
### 1. 这是构建系统的“标准中间态”
在 Buildroot、OpenWrt 等嵌入式构建系统中，编译流程是严格分步的：

- **第一步（打包）**：先把所有文件（脚本、库、设备节点）打包成 `rootfs.cpio`（保留权限和结构）。
    
- **第二步（压缩）**：为了节省 Flash 空间和传输时间，再把 `rootfs.cpio` 压缩成 `rootfs.lzma`（最终固件）。

当解压 `rootfs.lzma` 时，系统**只能还原到第一步结束时的状态**，也就是 `rootfs.cpio`。这个 `.cpio` 文件是构建系统识别和重新打包的**唯一标准入口**。

### 2. 为了保留“特殊文件属性”不被损坏

根文件系统里包含大量**设备节点**（如 `/dev/console`，主设备号 5，次设备号 1）和**硬链接**。

- 如果你直接把 `rootfs.lzma` 一步解压到 **普通文件夹**（比如用 `xz -d | cpio -id`），虽然也能做到，但文件夹里的文件会占用硬盘 inode，且权限容易受你当前 umask 影响。
    
- 如果**只解压到 `.cpio` 文件**，则不会在硬盘上展开实体文件，所有设备号、硬链接关系都被完整封存在这个归档包里，**零损耗**。当你需要重新打包时，从这个 `.cpio` 生成固件，不会丢失任何底层元数据。

![](/images/Pasted%20image%2020260908105819.png)
接着提取cpio
```
mkdir -p rootfs
cd rootfs
cpio -idmu --no-absolute-filenames < ../rootfs.cpio
```
![](/images/Pasted%20image%2020260908111750.png)
## 找 Web 服务和原厂页面
Web 服务程序：/bin/alphapd
页面根目录：  /etc_ro/web
启动脚本：    /sbin/web.sh
![](/images/Pasted%20image%2020260908112304.png)![](/images/Pasted%20image%2020260908112326.png)![](/images/Pasted%20image%2020260908112350.png)
确认程序架构和动态链接器：需要确定大小端序
`file` 显示 `LSB`，因此使用 `qemu-mipsel`；若显示 `MSB`，通常使用 `qemu-mips`
```
file bin/alphapd
readelf -l bin/alphapd | grep interpreter
readelf -d bin/alphapd | grep NEEDED
```
ELF 32-bit LSB executable, MIPS, MIPS-II
interpreter /lib/ld-uClibc.so.0
NEEDED libc.so.0
NEEDED libnvram.so.0
![](/images/Pasted%20image%2020260908112655.png)

```
cd ~/Desktop/dcs930l-lab/firmware
qemu-mipsel -L rootfs rootfs/bin/alphapd
```
试运行
```
qemu-mipsel -strace -L rootfs rootfs/bin/alphapd
```
![](/images/Pasted%20image%2020260908144045.png)
`errno=2` 通常表示路径不存在，因为alphapd中写死了绝对路径，此时使用 bubblewrap
[Bubblewrap：轻量级非特权容器运行时Bubblewrap是一个专注于非特权用户使用的沙箱和容器运行时工具。](https://juejin.cn/post/7601069677567361070)
使用真实 `chroot` 通常需要 root 权限。`bubblewrap` 可以为当前进程建立一个非特权的临时根目录：
```
bwrap \
    --bind "$PWD/rootfs" / \
    --dev /dev \
    --proc /proc \
    --tmpfs /var \
    --dir /var/run \
    --tmpfs /tmp \
    --ro-bind "$HOME/Desktop/m3-qemu/tools/runtime/usr/bin/qemu-mipsel-static" /qemu-mipsel \
    --unshare-pid \
    --die-with-parent \
    --chdir / \
    /qemu-mipsel /bin/alphapd

```
![](/images/Pasted%20image%2020260908145908.png)
### 编译 MIPS little-endian 共享库
...

最终报错还是太多了，受不了了，ai5分钟完成...
![](/images/Pasted%20image%2020260908160514.png)