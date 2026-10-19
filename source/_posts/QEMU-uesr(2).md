---
title: 'QEMU-uesr(2)'
date: 2026-10-13 09:55:19
categories:
  - 固件分析
tags:
  - QEMU
  - Squashfs
  - 固件提取
---
binwalk看到Squashfs，直接dd切割下来
![](/images/Pasted%20image%2020261013095519.png)
sasquatch工具解压镜像，这里`unsquashfs` 报错
```
sasquatch -d rootfs rootfs.squashfs
```
同样可以解压镜像的工具还有unsquashfs，这里说说区别：
`unsquashfs` 是“标准工具”，而 `sasquatch` 是它的“**定制补丁版**”，一般来说先使用`unsquashfs` 去解压，失败转用`sasquatch`（`sasquatch`目标是尽最大可能支持各种被“魔改”过的厂商特定）
![](/images/Pasted%20image%2020261013100844.png)
一眼看到web文件夹
![](/images/Pasted%20image%2020261013101201.png)
一堆的asp
![](/images/Pasted%20image%2020261013101218.png)
但是仔细翻找，web服务在/bin/webs，和/bin/axhttpd中
在webs中找到路由表注册函数
![](/images/Pasted%20image%2020261013101752.png)`/goform/setWAN` 接口中，`wanMode=2/3/6` 分支把 `pppUserName`、`pptpUserName`、`L2TPUserName` 直接 `sprintf` 到命令字符串，并调用 `system()`
wanMod=2
![](/images/Pasted%20image%2020261013102506.png)
wanMod=3
![](/images/Pasted%20image%2020261013102633.png)
wanMod=6同理
漏洞点分析至此
模拟
### 1  
用 Linux 用户命名空间把自己“伪装”成 root，再配合 mount / pid / ipc 等命名空间，造一个隔离的“假 root”环境，用来 chroot 进固件 rootfs、跑 webs、调试漏洞
```
unshare -r -m -p -f -i --mount-proc bash
```
用 Linux 用户命名空间把自己“伪装”成 root，再配合 mount / pid / ipc 等命名空间，造一个隔离的“假 root”环境，用来 chroot 进固件 rootfs、跑 webs、调试漏洞

![](/images/Pasted%20image%2020261013110202.png)
### 2
chroot 前，把固件程序需要的宿主设备节点 bind 到 rootfs/dev 下
（固件中的程序会经常访问/dev-随机数-丢弃输出等）
```
#设置一个变量，方便
R=/home/jianbinggouzi/Desktop/BR6428NC_work/rootfs

for d in null zero urandom random full tty; do
    rm -f "$R/dev/$d"; touch "$R/dev/$d"
    mount --bind "/dev/$d" "$R/dev/$d"
done
```
### 3
给 chroot 后的 rootfs 补齐运行时目录，并在 rootfs 内部重新挂一次 /proc
```
mkdir -p "$R/dev/pts" "$R/var/run" "$R/var/tmp" "$R/proc"
mount -t proc proc "$R/proc"
```
### 4
chroot 进去，启动
```
exec chroot "$R" /bin/webs -c /etc/boa -d
```
![](/images/Pasted%20image%2020261013112319.png)


binwalk + sasquatch 解包，unshare/chroot 起环境，/usr/bin/qemu-mips 做用户态翻译