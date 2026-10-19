---
title: '工控天行PLC'
date: 2026-09-29 14:59:12
categories:
  - 固件分析
tags:
  - PLC
  - 工控安全
  - SWUpdate
---
固件下载地址
https://baosky.baosight.com/#/ProductDownload/latest/plc/t4
参考连接
https://mp.weixin.qq.com/s/Lsy9SixDDzK58t4PRyDceQ
![](/images/Pasted%20image%2020260929145912.png)
.swu 文件是 SWUpdate 所使用的软件更新包格式。本质上是一个"ASCII十六进制编码头 + cpio 归档"的组合体。每个 CPIO 条目的头部是一段110字符的ASCII十六进制串，cpio归档魔数070701也以文本形式出现在头部中，而非通常的二进制偏移处。
此文件魔数：070702
![](/images/Pasted%20image%2020260929150945.png)

| 字段           | 长度  |     值      |
| ------------ | --- | ---------- |
| `c_magic`    | 6   | `070702`   |
| `c_ino`      | 8   | `00300005` |
| `c_mode`     | 8   | `000081A4` |
| `c_uid`      | 8   | `000003E9` |
| `c_gid`      | 8   | `000003E9` |
| `c_nlink`    | 8   | `00000001` |
| `c_mtime`    | 8   | `6AB39DB6` |
| `c_filesize` | 8   | `00000768` |
| `c_dev_maj`  | 8   | `00000008` |
| `c_dev_min`  | 8   | `00000003` |
| `c_rdev_maj` | 8   | `00000000` |
| `c_rdev_min` | 8   | `00000000` |
| `c_namesize` | 8   | `0000000F` |
| `c_chksum`   | 8   | `0001C0BC` |
![](/images/Pasted%20image%2020260929151339.png)![](/images/Pasted%20image%2020260929151404.png)
后面很多cpio，所以binwalk对边界进行定位
![](/images/Pasted%20image%2020260929161751.png)
解压后的文件夹
脚本
```
#!/usr/bin/env python3
import os, sys

MAGICS = (b'070701', b'070702', b'070707', b'\x71\xc7', b'\xc7\x71')


def walk(data):
    """遍历 cpio，yield (pos, name, mode, size, body_off)。"""
    pos = 0
    while pos < len(data):
        if data[pos:pos + 6] in MAGICS[:3]:          # ASCII 头
            h = data[pos:pos + 6]
            base, w, align = pos + 6, 8, 4
            if h == b'070707':
                w, align = 6, 2
            try:
                mode = int(data[base + 1*w:base + 2*w], 16 if w == 8 else 8)
                size = int(data[base + (6 if w == 8 else 9)*w:
                                base + (7 if w == 8 else 10)*w], 16 if w == 8 else 8)
                nsz  = int(data[base + (11 if w == 8 else 8)*w:
                                base + (12 if w == 8 else 9)*w], 16 if w == 8 else 8)
            except ValueError:
                pos += 1; continue
            hdr = 6 + 13*w
        elif data[pos:pos + 2] in MAGICS[3:]:        # 二进制头
            le  = data[pos:pos + 2] == b'\x71\xc7'
            u16 = lambda o: int.from_bytes(data[pos+o:pos+o+2], 'little' if le else 'big')
            mode = u16(6); size = (u16(22) << 16) | u16(24); nsz = u16(20)
            hdr, align = 26, 2
        else:
            pos += 1; continue

        name = data[pos + hdr: pos + hdr + nsz - 1].decode('utf-8', 'replace')
        body = pos + hdr + nsz
        body += (-body) % align

        yield pos, name, mode, size, body
        if name == 'TRAILER!!!':
            return
        pos = body + size + (-size) % align


def probe(path):
    data = open(path, 'rb').read()
    print(f'{path}  ({len(data)} 字节)')
    for pos, name, mode, size, _ in walk(data):
        print(f'@{pos:#010x}  {name:<30} size={size:<10} mode={mode:o}')


def extract(path, outdir='out'):
    data = open(path, 'rb').read()
    root = os.path.realpath(outdir)
    for _, name, mode, size, off in walk(data):
        if name == 'TRAILER!!!':
            continue
        tgt = os.path.realpath(os.path.join(outdir, name))
        if not tgt.startswith(root + os.sep):
            print(f'跳过越界: {name}'); continue
        if (mode & 0o170000) == 0o040000:
            os.makedirs(tgt, exist_ok=True)
        elif (mode & 0o170000) == 0o100000:
            os.makedirs(os.path.dirname(tgt) or outdir, exist_ok=True)
            open(tgt, 'wb').write(data[off:off + size])
            print(f'写出 {name} ({size} 字节)')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'用法: {sys.argv[0]} <file> [-x [dir]]'); sys.exit(1)
    if len(sys.argv) > 2 and sys.argv[2] == '-x':
        extract(sys.argv[1], sys.argv[3] if len(sys.argv) > 3 else 'out')
    else:
        probe(sys.argv[1])
```
![](/images/Pasted%20image%2020260929170959.png)
#### 签名机制与信任链
        固件的完整性保护依赖SWUpdate的CMS（PKCS#7）签名机制：SWUpdate 以 "built for signed images" 模式编译，升级时必须提供可被公钥验证的sw-description.sig，验证通过后才允许进入安装流程。验证流程如下：
![](/images/0b180ffe-174b-4237-99fa-cf55d54e863e.png)

binwalk看到多zilp，其实是gzip中的压缩数据 78 DA / 78 9C / 78 01 /被binwalk识别成了zlib的两字节魔数
![](/images/Pasted%20image%2020260929173224.png)
所以脚本来解压：
把多个 gzip 成员拼接成一个文件。每个成员有独立的 gzip 头和 CRC32/ISIZE，用 zlib逐段解压：
```
python3 gunzip.py bootloader.img u-boot.bin
python3 gunzip.py rootfs.img rootfs.raw
```
![](/images/Pasted%20image%2020260930101433.png)
```
#!/usr/bin/env python3
import sys, zlib

def gunzip_multi(comp):
    out, pos = b'', 0
    while pos < len(comp):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        chunk = comp[pos:]
        out += d.decompress(chunk) + d.flush()
        consumed = len(chunk) - len(d.unused_data)
        if consumed == 0:
            break
        pos += consumed
    return out

if __name__ == '__main__':
    data = open(sys.argv[1], 'rb').read()
    raw = gunzip_multi(data)
    open(sys.argv[2], 'wb').write(raw)
    print(f"{sys.argv[1]} -> {sys.argv[2]}, {len(raw)} bytes")
```
解压得到1 GB 的ext4镜像和14.7 MB的U-Boot镜像
![](/images/Pasted%20image%2020260930101747.png)
完整流程
![](/images/3d7ec548-6075-4213-a340-5fa98cbd06a9.png)
挂载ext4镜像（root）
```
mkdir -p /mnt/rootfs
mount -o loop,ro rootfs.raw /mnt/rootfs
```
![](/images/Pasted%20image%2020260930102311.png)
复制进来，卸载挂载
```
mkdir -p ~/Desktop/PLC/out/rootfs_dir
sudo cp -a /mnt/rootfs/. ~/Desktop/PLC/out/rootfs_dir/
#  卸载
sudo umount /mnt/rootfs
```
这里也可以直接进行7z解压镜像，但是元数据（metadata）的保留程度不如挂载
至此解包完成
### 固件初步分析
分析文件
产品类型（/ext/issue）
![](/images/Pasted%20image%2020260930103439.png)
厂商：baosight
文件boot/fsl-t426.dtb 字符串
![](/images/Pasted%20image%2020260930141327.png)
主控 SoC：NXP/Freescale LS1043A（Layerscape，ARMv8-A，4×Cortex-A53）
文件：boot/ls1043ardb_boot.scr（脚本名），boot/fsl-ls1043a-rdb-sdk.dtb

CPU 分配： 4 核，isolcpus=2,3 隔离给实时任务
文件：boot/ls1043ardb_boot.scr
![](/images/Pasted%20image%2020260930143417.png)
内核：Linux 5.10.35-rt39
文件：boot/Image
![](/images/Pasted%20image%2020260930143749.png)
或者是boot/modules文件名也显示了版本号
![](/images/Pasted%20image%2020260930143850.png)
Bootloader：U-Boot 2021.04.01
文件：u-boot.bin 字符串 U-Boot 2021.04.01
![](/images/Pasted%20image%2020260930144856.png)
构建信息：
![](/images/Pasted%20image%2020260930145215.png)
![](/images/Pasted%20image%2020260930145039.png)
分析汇总

| 项目         | 识别结果                                                                                                                                                                                                            | 识别来源（文件/证据）                                                                                                                                                                                                                            |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 产品类型       | 工业 PLC（可编程逻辑控制器），型号 T426-XEP-10，属 T4 系列                                                                                                                                                                         | /etc/build-release                                                                                                                                                                                                                     |
| 厂商         | 上海宝信软件（BAOSIGHT）                                                                                                                                                                                                | boot/fsl-t426.dtb 字符串 Baosight MPOC3；                                                                                                                                                                                                  |
| 主控 SoC     | NXP/Freescale LS1043A（Layerscape，ARMv8-A，4×Cortex-A53）                                                                                                                                                          | boot/ls1043ardb_boot.scr（板级启动脚本名）                                                                                                                                                                                                      |
| CPU 分配     | 4 核，isolcpus=2,3 隔离给实时任务                                                                                                                                                                                        | boot/ls1043ardb_boot.scr → cpuargs isolcpus=2,3；etc/init.d/onboot-config.sh（QMan portal 3 IRQ 亲和性绑核）                                                                                                                                   |
| 内核         | Linux 5.10.35-rt39（PREEMPT_RT 实时内核）                                                                                                                                                                             | boot/Image 字符串 Linux version 5.10.35-rt39；boot/config-5.10.35-rt39                                                                                                                                                                     |
| Bootloader | U-Boot 2021.04.01                                                                                                                                                                                               | u-boot.bin 字符串 U-Boot 2021.04.01                                                                                                                                                                                                       |
| 构建信息       | Buildroot 2023.02；版本 2.00.07_646-2611.2；构建时间 2026-09-23 16:43:57；构建机 Ubuntu 20.04.6 LTS@app-virtual-machine；工具链 aarch64-linux-gnu-gcc 9.4.0                                                                     | /etc/os-release（VERSION_ID=2023.02）；/etc/build-release（BUILD_VERSION / BUILD_TIME / BUILD_SERVER）；u-boot.bin 字符串中的 gcc 版本                                                                                                              |
| 升级机制       | SWUpdate v2022.12 + A/B 双槽冗余：.swu 包内含 bootloader.img / rootfs.img（zlib 压缩、raw 写入、SHA-256 校验）＋安装脚本；写 mmcblk0p1(slot-0) / mmcblk0p2(slot-1)，bootloader 写 mmcblk0 偏移 1M/32M；postinstall 用 bootcfg -s 切槽并 fw_setenv | usr/bin/swupdate 字符串 SWUpdate v2022.12 (Buildroot BaoSky 1.0 (T4 Series PLC))；根目录 sw-description（slot-0/slot-1 定义）；sw_install_script.sh（preinst 拒绝覆盖当前活动槽）                                                                             |
| 升级服务端口     | SWUpdate 内置 mongoose Web 服务，监听 :8080，文档根 /var/www/swupdate                                                                                                                                                      | usr/lib/swupdate/conf.d/10-mongoose-args（-r /var/www/swupdate -p 8080）；usr/lib/swupdate/swupdate.sh                                                                                                                                    |
| 分区与根文件系统   | mmcblk0p1=rootfs(slot0)，p2=rootfs(slot1)，p3=data；根分区只读 + overlayfs（upper/work 落在 data 分区，switch-root 到 /media）                                                                                                  | boot/ls1043ardb_boot.scr（root=PARTUUID=$partuuidr、data=PARTUUID、devpart_boot=1/devpart_data=3）；etc/init.d/overlay.sh（OVERLAY_UPPERDIR_DIR=/mnt/data/base）；usr/lib/systemd/system/overlay-rootfs.service（switch-root /media /sbin/init） |
| 安全启动       | 已启用 NXP CST 2.0 / ESBC 签名校验链（内核 + DTB 头签名，SRK 哈希）                                                                                                                                                               | boot/ls1043ardb_boot.scr（esbc_validate 逻辑、secureboot_validate）；boot/secboot_hdrs/ls1043ardb/；boot/srk_hash.txt（CST (Code Signing Tool) Version 2.0）                                                                                    |
| 系统组件栈      | systemd 252 体系（非 BusyBox init）；BusyBox 仅作工具集；运行时为 BaoskyRuntime（TXRuntime / Plc.Execution / pn_dcpd / DDSAgent）                                                                                                 | usr/lib/systemd/systemd；etc/systemd/system/default.target.wants/BaoSky.service；usr/BaoskyRuntime/bin/                                                                                                                                  |
| 默认账户       | 仅 root 可登录（/bin/sh），密码为 SHA-256 crypt（$5$）非空、非锁定；无 sudoers、无 securetty、未安装 SSH 服务（无 dropbear/openssh daemon）                                                                                                    | etc/passwd；etc/shadow（root:$5$y5isdQrk55rYG$...）；未发现 sshd/dropbear 可执行体                                                                                                                                                                |
| 控制台        | 串口 ttyS0,115200，earlycon=uart8250,mmio,0x21c0500                                                                                                                                                                | boot/ls1043ardb_boot.scr（内核 cmdline）                                                                                                                                                                                                   |
| 设备家族覆盖     | 单固件覆盖多机型：T426 / T426EH / T4 / MPOC3 / LS1043A-RDB，并区分 PVT / PVT2 硬件版本                                                                                                                                           | boot/*.dtb（fsl-t426.dtb、fsl-t426eh.dtb、fsl-t4.dtb、fsl-mpoc3*.dtb）；ls1043ardb_boot.scr 中按 $family$model 选 DTB 的逻辑                                                                                                                       |
设备采用eMMC A/B双槽位 + ext4 数据分区overlayfs的典型工业设计：系统层只读基座、用户数据层可写分离，配合SWUpdate的签名校验，构成了防御的安全基础。但内核配置中CONFIG_DEVMEM=y、CONFIG_DEBUG_FS_ALLOW_ALL=y、CONFIG_KALLSYMS=y全开，为提权后的攻击者打开了物理内存直读的大门——这些配置项都来自 /boot/config-5.10.35-rt39，静态分析即可确认。


## 组件识别
第一步 · 关键文件探测

| 组件 | 版本 | 来源文件 |
| --- | --- | --- |
| 发行版 | Buildroot 2023.02 | /etc/os-release |
| 构建信息 | 2.00.07_646-2611.2 @ 2026-09-23 | /etc/build-release |
| 内核 | 5.10.35-rt39 | /boot/Image、/boot/config-5.10.35-rt39 |
| 运行时组件版本 | 见 TXRuntime-T426-XEP-10-release（sp2611.2_2.00.07.2611.2，arm64，附 deb 的 MD5） | /etc/TXRuntime-T426-XEP-10-release |
| 实时版本号 | VersionSP=2.00 | /etc/rt-version |
第二步：二进制版本字符串

| 组件 | 版本 | 位置 | 版本串证据 |
| --- | --- | --- | --- |
| glibc | 2.35 | usr/lib/libc.so.6 | GNU C Library (Arm) stable release version 2.35. |
| BusyBox | 1.36.0 | usr/bin/busybox | BusyBox v1.36.0 |
| systemd | 252 | usr/lib/systemd/systemd | systemd 252 |
| NetworkManager | 1.40.10 | usr/sbin/NetworkManager | NetworkManager (version 1.40.10) ←括号形式 |
| SWUpdate | v2022.12 | usr/bin/swupdate | SWUpdate v2022.12 (Buildroot BaoSky 1.0 (T4 Series PLC)) |
| OpenSSL #1 | 1.1.1t | usr/lib/libcrypto.so.1.1（系统库，2.48 MB） | OpenSSL 1.1.1t |
| OpenSSL #2 | 1.1.1f | usr/BaoskyRuntime/lib/libcrypto.so.1.1（私有旧库，2.59 MB） | OpenSSL 1.1.1f |
| OpenSSL #3 | 3.4.1 | usr/BaoskyRuntime/lib/libcrypto.so.3（较新，6.25 MB） | OpenSSL 3.4.1 |
| libstdc++ | 6.0.29（GCC 11 系，最高符号 GLIBCXX_3.4.29） | usr/lib/libstdc++.so.6.0.29 | GLIBCXX_3.4.29 |
| util-linux | 2.38 | usr/bin/mount | util-linux 2.38 |
| Python | 3.11 | usr/bin/python3.11 | 目标文件与软链 python3 -> python3.11 |
| Xerces-C | 3.2 | usr/BaoskyRuntime/lib/libxerces-c-3.2.so | 文件名 libxerces-c-3.2.so |
| tinyxml2 | 6.2.0 | usr/BaoskyRuntime/lib/libtinyxml2.so.6.2.0 | SONAME libtinyxml2.so.6.2.0 |
| libmodbus | 3.1.11 | usr/BaoskyRuntime/lib/libmodbus.so.3.1.11 | SONAME libmodbus.so.3.1.11 |
| sdbus-c++ | 2.1.0 | usr/BaoskyRuntime/lib/libsdbus-c++.so.2.1.0 | SONAME libsdbus-c++.so.2.1.0 |
| CRoaring | 18 | usr/BaoskyRuntime/lib/libroaring.so.18 | SONAME libroaring.so.18 |
| open62541（OPC UA） | 1.3.5 / 1.3.9 两套串并存 | usr/BaoskyRuntime/lib/libTXOPCUA.so | 内嵌 1.3.5、1.3.9 |
| SOEM（EtherCAT 主站） | 存在（版本串未内嵌） | usr/BaoskyRuntime/lib/libsoem.so | 符号/字符串 soem |
| ruckig（轨迹规划） | 存在 | usr/BaoskyRuntime/lib/libruckig.so | 文件名 |
| NXP FMC | usr/local/fmc/init-ls104xa | DPAA 帧管理器配置工具 | — |
第三步：行为侧写

| 服务/进程                           | 作用                                                           | 启动方式                                                                                     | 端口/接口                                                |
| ------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| TXRuntime                       | 软 PLC 运行时主进程（Plc.Execution 执行引擎、TXLogHandler 日志、DumpFile 转储） | BaoSky.service → ExecStart=/usr/BaoskyRuntime/bin/TXRuntime，Restart=on-failure，User=root | 内部服务 127.0.0.1:60000（ThreadNum=4）——仅回环               |
| DDSAgent                        | 数据代理（Data Distribution Service）                              | BaoskyRuntime 内部拉起                                                                       | TCP 60001（Platform.ini [DDSAgent] TCPPort=60001）——对外 |
| pn_dcpd                         | PROFINET DCP 发现与配置协议守护进程                                     | BaoskyRuntime 内部                                                                         | 链路层（PROFINET DCP，eth0）                               |
| swupdate                        | Web 固件升级（mongoose）                                           | swupdate.service.wants（已 enable）；swupdate.sh                                             | TCP 8080，/var/www/swupdate                           |
| SystemManager                   | 系统管理（读取 build-release / device-tree 序列号），taskset -c 0 绑核     | system-manager.service → /etc/init.d/SystemManager.sh                                    | —                                                    |
| fmc                             | NXP Frame Manager 配置（DPAA 网络加速）                              | fmc.service → /usr/local/fmc/init-ls104xa                                                | —                                                    |
| onboot-config                   | 启动期 IRQ/进程亲和性调优（QMan portal 3 → mask 7）                      | onboot-config.service                                                                    | —                                                    |
| overlay-rootfs                  | 只读根 + data 分区 overlay，switch-root 到 /media                   | overlay-rootfs.service（local-fs.target.wants）                                            | —                                                    |
| NetworkManager                  | 网络管理                                                         | multi-user.target.wants/NetworkManager.service                                           | D-Bus                                                |
| polkitd / udisks2 / dbus-broker | 权限代理、磁盘、消息总线                                                 | systemd                                                                                  | D-Bus 系统总线                                           |
| display                         | 面板指示灯/LED 控制（.SMHardWare.conf 定义 run/error LED）              | display.service                                                                          | /dev/input/event*、sysfs LED                          |

风险概括

| 组件                  | 识别版本                    | 主要风险                                        |
| ------------------- | ----------------------- | ------------------------------------------- |
| Linux 内核            | 5.10.35-rt39 (2021 基线)  | Dirty Pipe、nf_tables 系列等提权 CVE 数百个          |
| glibc               | 2.35                    | Looney Tunables (CVE-2023-4911)、iconv RCE 链 |
| OpenSSL             | 1.1.1t + 1.1.1f + 3.4.1 | 1.1.1 分支已 EOL，DH/X.509/PKCS12 解析 DoS 族      |
| BusyBox             | 1.36.0                  | CVE-2023-42363~42366 (unzip/awk 内存破坏)       |
| SWUpdate + Mongoose | 2022.12 + 7.8           | Web 界面无认证属设计面风险                             |
| NetworkManager      | 1.40.10                 | 低风险                                         |
| systemd             | 252                     | 低风险                                         |