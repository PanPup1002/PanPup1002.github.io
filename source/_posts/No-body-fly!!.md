---
title: 'No-body-fly!!'
date: 2026-09-20 11:19:31
categories:
  - 固件分析
tags:
  - STM32
  - MCU
  - 逆向工程
---
**无文件头的 MCU 原始应用镜像，不是 Linux 固件/文件系统，`binwalk` 没有识别出嵌入文件**
“原始镜像”表示文件中直接保存了将被写入 Flash 的机器码和常量，没有 ELF、PE 等可执行文件头，也没有节表帮助分析器确定装载地址。“应用镜像”表示它从应用程序自己的向量表开始，而不是从 MCU 整片 Flash 的默认起点开始。

文件开头 16 字节为：
![](/images/Pasted%20image%2020260920111931.png)
```text
文件偏移  原始字节       小端 DWORD   含义
0x0000    A0 66 01 20    0x200166A0   初始 MSP，位于 STM32 SRAM
0x0004    CD 01 02 08    0x080201CD   Reset Handler，bit0=1 表示 Thumb
0x0008    F7 5B 02 08    0x08025BF7   NMI Handler
0x000C    8D 44 02 08    0x0802448D   HardFault Handler
```

判断过程：

1. `0x200166A0` 落在 Cortex-M/STM32 的 SRAM 地址空间 `0x20000000...`，非常符合向量表第 0 项“复位后初始栈顶”。
2. `0x080201CD` 落在 STM32 Flash 地址空间，最低位为 1，符合 Cortex-M Thumb 入口规则。清除最低位后实际代码地址为 `0x080201CC`。
3. 后续 DWORD 大量指向 `0x0802xxxx–0x0806xxxx`。把文件映射到 `0x08020000` 后，这些地址都落回本文件内部，并能反汇编成有效 Thumb-2 函数。
4. `0x080201CC` 的复位代码首先调用 `0x08028910`，后者访问 RCC/SCB 并把 `SCB_VTOR` 设置成 `0x08020000`。固件自己再次确认了向量表基址。
5. 文件没有 ELF 魔数 `7F 45 4C 46`、分区表、Linux 内核头或文件系统；`file` 仅识别为 `data`，`binwalk` 也没有发现可解包对象。
6. 镜像含 Cortex-M 向量表、外设寄存器初始化、uC/OS-II 和直接 SRAM 地址访问，不存在 Linux 引导、MMU、设备树及用户空间结构。

文件大小为 `0x4B478`。以 `0x08020000` 装载时，末地址为 `0x0806B478`，与内部 Flash 指针范围吻合。因此 IDA 导入参数应为“ARM Little-endian raw binary，加载地址 `0x08020000`”。

STM32 的物理 Flash 通常从 `0x08000000` 开始，而本镜像从 `0x08020000` 开始，相差 `0x20000`（128 KiB）。这强烈表明它是由 Bootloader 跳转进入的应用部分，文件本身不包含前面的 Bootloader；因此不能把它称为“整片 Flash dump”。


idapython恢复一下结构体
```

import re

import ida_bytes
import ida_entry
import ida_funcs
import ida_idp
import ida_kernwin
import ida_name
import ida_nalt
import ida_offset
import ida_segment
import ida_segregs
import ida_typeinf
import idc


ROM_BASE = 0x08020000
ROM_END = 0x0806B478
SRAM_BASE = 0x20000000
SRAM_END = 0x20020000
CCMRAM_BASE = 0x10000000
CCMRAM_END = 0x10010000
VARIABLE_TABLE = 0x08067974
VARIABLE_COUNT = 163

# IDAPython moved some constants/functions between modules over time.
# Prefer the modern location and fall back to older compatibility exports.
STRTYPE_C = getattr(ida_nalt, "STRTYPE_C", getattr(idc, "STRTYPE_C", 0))
PT_SILENT = getattr(idc, "PT_SILENT", getattr(ida_typeinf, "PT_SILENT", 0))

CORE_VECTORS = [
    "Initial_SP", "Reset_Handler", "NMI_Handler", "HardFault_Handler",
    "MemManage_Handler", "BusFault_Handler", "UsageFault_Handler",
    "Reserved_7", "Reserved_8", "Reserved_9", "Reserved_10",
    "SVC_Handler", "DebugMon_Handler", "Reserved_13",
    "PendSV_Handler", "SysTick_Handler",
]

STM32F427_IRQS = [
    "WWDG", "PVD", "TAMP_STAMP", "RTC_WKUP", "FLASH", "RCC", "EXTI0",
    "EXTI1", "EXTI2", "EXTI3", "EXTI4", "DMA1_Stream0", "DMA1_Stream1",
    "DMA1_Stream2", "DMA1_Stream3", "DMA1_Stream4", "DMA1_Stream5",
    "DMA1_Stream6", "ADC", "CAN1_TX", "CAN1_RX0", "CAN1_RX1", "CAN1_SCE",
    "EXTI9_5", "TIM1_BRK_TIM9", "TIM1_UP_TIM10", "TIM1_TRG_COM_TIM11",
    "TIM1_CC", "TIM2", "TIM3", "TIM4", "I2C1_EV", "I2C1_ER", "I2C2_EV",
    "I2C2_ER", "SPI1", "SPI2", "USART1", "USART2", "USART3", "EXTI15_10",
    "RTC_Alarm", "OTG_FS_WKUP", "TIM8_BRK_TIM12", "TIM8_UP_TIM13",
    "TIM8_TRG_COM_TIM14", "TIM8_CC", "DMA1_Stream7", "FMC", "SDIO", "TIM5",
    "SPI3", "UART4", "UART5", "TIM6_DAC", "TIM7", "DMA2_Stream0",
    "DMA2_Stream1", "DMA2_Stream2", "DMA2_Stream3", "DMA2_Stream4", "ETH",
    "ETH_WKUP", "CAN2_TX", "CAN2_RX0", "CAN2_RX1", "CAN2_SCE", "OTG_FS",
    "DMA2_Stream5", "DMA2_Stream6", "DMA2_Stream7", "USART6", "I2C3_EV",
    "I2C3_ER", "OTG_HS_EP1_OUT", "OTG_HS_EP1_IN", "OTG_HS_WKUP", "OTG_HS",
    "DCMI", "CRYP", "HASH_RNG", "FPU", "UART7", "UART8", "SPI4", "SPI5",
    "SPI6", "SAI1", "LTDC", "LTDC_ER", "DMA2D",
]


def add_segment(start, end, name, seg_class="DATA"):
    if ida_segment.getseg(start):
        return
    seg = ida_segment.segment_t()
    seg.start_ea = start
    seg.end_ea = end
    seg.bitness = 1  # 32-bit
    if not ida_segment.add_segm_ex(seg, name, seg_class, ida_segment.ADDSEG_NOSREG):
        raise RuntimeError("cannot add segment %s" % name)


def clean_name(value):
    value = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not value or value[0].isdigit():
        value = "v_" + value
    return value


def c_string(ea, limit=96):
    raw = bytearray()
    for index in range(limit):
        value = ida_bytes.get_byte(ea + index)
        if value in (0, 0xFF):
            break
        raw.append(value)
    return raw.decode("ascii", errors="replace")


def set_thumb(start, end):
    treg = ida_idp.str2reg("T")
    if treg >= 0:
        ida_segregs.split_sreg_range(start, treg, 1, ida_segregs.SR_user)
        ida_segregs.split_sreg_range(end, treg, 1, ida_segregs.SR_user)


def label_function(ea, name, force=False):
    ea &= ~1
    if ROM_BASE <= ea < ROM_END:
        ida_funcs.add_func(ea)
        if force or not ida_name.get_name(ea):
            flags = ida_name.SN_NOCHECK | ida_name.SN_NOWARN
            if force:
                flags |= ida_name.SN_FORCE
            ida_name.set_name(ea, name, flags)


def recover_vectors():
    names = CORE_VECTORS + [name + "_IRQHandler" for name in STM32F427_IRQS]
    for index, name in enumerate(names):
        entry = ROM_BASE + index * 4
        value = ida_bytes.get_dword(entry)
        ida_bytes.del_items(entry, ida_bytes.DELIT_SIMPLE, 4)
        ida_bytes.create_dword(entry, 4)
        ida_bytes.set_cmt(entry, "%d: %s" % (index, name), False)
        if index != 0 and (value & 1) and ROM_BASE <= (value & ~1) < ROM_END:
            ida_offset.op_plain_offset(entry, 0, 0)
            label_function(value, name)


def recover_variable_dictionary():
    type_names = {
        0: "u8/bool", 1: "u16", 2: "i16", 3: "u32?",
        4: "float", 5: "i32", 6: "u64/timestamp",
    }
    for index in range(VARIABLE_COUNT):
        entry = VARIABLE_TABLE + index * 12
        string_ea = ida_bytes.get_dword(entry)
        ram_ea = ida_bytes.get_dword(entry + 4)
        type_id = ida_bytes.get_dword(entry + 8)
        name = c_string(string_ea)
        for field in (entry, entry + 4, entry + 8):
            ida_bytes.del_items(field, ida_bytes.DELIT_SIMPLE, 4)
            ida_bytes.create_dword(field, 4)
        ida_offset.op_plain_offset(entry, 0, 0)
        ida_offset.op_plain_offset(entry + 4, 0, 0)
        ida_bytes.create_strlit(string_ea, len(name) + 1, STRTYPE_C)
        safe = clean_name(name)
        ida_name.set_name(string_ea, "str_" + safe,
                          ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
        ida_name.set_name(ram_ea, "g_" + safe,
                          ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
        comment = "%s @ 0x%08X, type %d (%s)" % (
            name, ram_ea, type_id, type_names.get(type_id, "unknown"))
        ida_bytes.set_cmt(entry, comment, False)


def recover_usart_information():
    ports = {
        "USART1": 0x40011000,
        "USART2": 0x40004400,
        "USART3": 0x40004800,
        "USART6": 0x40011400,
        "UART7":  0x40007800,
    }
    registers = [
        (0x00, "SR"), (0x04, "DR"), (0x08, "BRR"),
        (0x0C, "CR1"), (0x10, "CR2"), (0x14, "CR3"),
        (0x18, "GTPR"),
    ]
    for port, base in ports.items():
        add_segment(base, base + 0x400, port + "_MMIO", "IO")
        for offset, register in registers:
            ea = base + offset
            ida_name.set_name(ea, port + "_" + register,
                              ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
            ida_bytes.set_cmt(ea, "%s register +0x%02X" % (port, offset), True)

    declarations = r"""
typedef struct FW_USART_InitTypeDef {
    unsigned int   USART_BaudRate;
    unsigned short USART_WordLength;
    unsigned short USART_StopBits;
    unsigned short USART_Parity;
    unsigned short USART_Mode;
    unsigned short USART_HardwareFlowControl;
} FW_USART_InitTypeDef;
"""
    try:
        idc.parse_decls(declarations, PT_SILENT)
        prototypes = {
            0x08029038: "int __fastcall USART_SendBuffer_Blocking(void *uart, const void *buffer, unsigned int length);",
            0x08029060: "void __fastcall USART1_Init_8N1(unsigned int baud);",
            0x0802909C: "void __fastcall USART2_Init_8N1(unsigned int baud);",
            0x08029104: "void __fastcall USART3_Init_8N1(unsigned int baud);",
            0x08029168: "void __fastcall UART7_Init_8N1(unsigned int baud);",
            0x080291C8: "void __fastcall USART_ResetAndClockEnable(void *uart);",
            0x08029284: "void __fastcall USART_ApplyConfig(void *uart, const FW_USART_InitTypeDef *config);",
            0x0805E87C: "int __fastcall UART7_SendBuffer(const void *buffer, unsigned int length);",
            0x0806518C: "unsigned int __fastcall Serial_BaudCodeToValue(unsigned char code);",
        }
        set_type = getattr(idc, "set_type", None) or getattr(idc, "SetType", None)
        if set_type is None:
            raise RuntimeError("this IDAPython build has no set_type/SetType")
        for ea, prototype in prototypes.items():
            set_type(ea, prototype)
    except Exception as error:
        print("USART type import warning: %s" % error)

    comments = {
        0x08021FFC: "USART1 init: 115200 baud, 8N1, RX+TX",
        0x08022002: "USART2 init: 115200 << 2 = 460800 baud, 8N1, RX+TX",
        0x08022008: "USART3 init: 115200 baud, 8N1, RX+TX",
        0x08022010: "USART6 base 0x40011400; following config is 100000 baud, 8E2, RX-only (SBUS signature)",
        0x08022038: "Apply USART6 config: baud=100000, word=9b, stop=2, even parity, RX-only",
        0x08022046: "UART7 init: 115200 baud, 8N1, RX+TX",
    }
    for ea, comment in comments.items():
        ida_bytes.set_cmt(ea, comment, True)


add_segment(SRAM_BASE, SRAM_END, "SRAM", "DATA")
add_segment(CCMRAM_BASE, CCMRAM_END, "CCMRAM", "DATA")
set_thumb(ROM_BASE, ROM_END - 1)
recover_vectors()

important = {
    0x080201AC: "__runtime_entry",
    0x080201CC: "Reset_Handler",
    0x080201E6: "Default_Handler",
    0x08027460: "SystemClock_Config_168MHz",
    0x08028910: "SystemInit",
    0x0802A40C: "Flight_Init_Task",
    0x0804C7D8: "main",
    0x08029038: "USART_SendBuffer_Blocking",
    0x08029060: "USART1_Init_8N1",
    0x0802909C: "USART2_Init_8N1",
    0x08029104: "USART3_Init_8N1",
    0x08029168: "UART7_Init_8N1",
    0x080291C8: "USART_ResetAndClockEnable",
    0x08029284: "USART_ApplyConfig",
    0x08057000: "UART7_Send_EB90_Frame",
    0x0805E87C: "UART7_SendBuffer",
    0x0806518C: "Serial_BaudCodeToValue",
    0x080651C8: "Serial_ReconfigurePorts",
}
for address, name in important.items():
    label_function(address, name, force=True)

ida_entry.add_entry(0x080201CC, 0x080201CC, "Reset_Handler", 1)
recover_variable_dictionary()
recover_usart_information()
ida_kernwin.info("1.bin recovery complete: vectors, startup, RAM, 163 variables, and USART data labeled.")
```
**变量基址**

| 名称            | RAM 地址       | 类型号/推测类型         | 作用                                                                 |
| ------------- | ------------ | ---------------- | ------------------------------------------------------------------ |
| `flight_mode` | `0x200000F5` | `0 / u8`         | 当前飞行模式编号。用于决定执行悬停、定点、航线、固定翼或模式转换等控制逻辑。具体数值与模式的对应关系还需要恢复状态机。        |
| `is_flying`   | `0x20000D6B` | `0 / bool`       | 飞行状态标志。通常用于区分地面与空中状态，控制积分器、传感器校准、失控保护、日志和落地判断。它不一定等同于“已解锁”。        |
| `motor_out1`  | `0x20002930` | `1 / u16`        | 1 号电机最终输出，位于混控器之后、PWM/电调驱动之前。很可能是 PWM 微秒值或定时器比较值。                  |
| `motor_out2`  | `0x20002932` | `1 / u16`        | 2 号电机最终输出，作用与 `motor_out1` 相同。                                     |
| `roll_PID_P`  | `0x20003C50` | `4 / float`      | 横滚控制器的比例增益 P。横滚误差越大，由它产生的即时修正量越大。                                  |
| `pitch_PID_P` | `0x20003C94` | `4 / float`      | 俯仰控制器的比例增益 P。决定俯仰误差对应的即时控制强度。                                      |
| `gps_lat`     | `0x20003E37` | `5 / i32`（注意未对齐） | GPS 纬度。大概率采用 度 × 10^7，例如 `399123456` 表示约 39.9123456°，但需要从解析函数确认比例。 |
| `gps_lon`     | `0x20003E3B` | `5 / i32`（注意未对齐） | GPS 经度，通常和 `gps_lat` 使用相同的 1e-7° 缩放。                               |
| `gps_alt`     | `0x20003E3F` | `4 / 32-bit 值`   | GPS 高度。可能是海拔、椭球高或相对高度，单位可能为米；需要追踪 GPS 协议解析和坐标转换函数确认。较可能为 `float`。  |
| `rtk_lat`     | `0x20008C19` | `5 / i32`        | RTK 定位结果纬度，通常精度和优先级高于普通 GPS。大概率也是 度 × 10^7。                        |
| `gyro_bias_x` | `0x2000C8A4` | `4 / float`      | X 轴陀螺仪零偏估计。姿态解算前会从原始 X 轴角速度中减掉该值，避免姿态随时间漂移。

`flight_mode`![](/images/Pasted%20image%2020260920104748.png)
`is_flying`
![](/images/Pasted%20image%2020260920105521.png)
`gps_lat`，`gps_lon`，`gps_alt`
![](/images/Pasted%20image%2020260920105616.png)
串口
函数地址：Code:08021EF0      sub_8021EF0()

|外设|基址|上电初始化波特率|格式|方向/实现线索|
|---|---|---|---|---|
|USART1|`0x40011000`|115200|8N1|RX+TX；TX 使用 DMA2 Stream7|
|USART2|`0x40004400`|460800|8N1|RX+TX；TX 使用 DMA1 Stream6|
|USART3|`0x40004800`|115200|8N1|RX+TX；TX 使用 DMA1 Stream4|
|USART6|`0x40011400`|100000|8E2|仅 RX；高度符合 SBUS 接收口|
|UART7|`0x40007800`|115200|8N1|RX+TX；发现固定二进制帧发送代码|

基址
![](/images/Pasted%20image%2020260920112524.png)
UART4、UART5 和 UART8 的基址只出现在通用 STM32 串口库的“按外设开关时钟”分派函数中
各个串口波特率：
![](/images/3589c0f2725e2977ad3e477d7d29bd1b.png)

### 168 MHz STM32F4系列芯片
由外设地址和指令集确定 MCU 家族：
- `SystemInit @ 0x08028910` 访问 `RCC 0x40023800`、`PWR 0x40007000`、`FLASH 0x40023C00`，这些地址符合 STM32F4 的内存映射。
- 代码向 `SCB_CPACR 0xE000ED88` 的 CP10/CP11 位写 1，并大量执行 `VFP` 单精度浮点指令，因此内核是 Cortex-M4F，而不是 Cortex-M3。
- 向量表保留到扩展 IRQ 90（DMA2D），符合 STM32F427/429 启动模板。确切芯片型号仍是高可信推断，单凭该应用镜像不能区分封装和具体料号。

系统时钟配置函数位于 `0x08027460`。在 `0x080274C4–0x080274C6`，代码把常量 `0x07405408` 写入 `RCC_PLLCFGR (0x40023804)`：

```asm
080274C4  LDR  R3, =0x07405408
080274C6  STR  R3, [R4]          ; R4 = 0x40023804, RCC_PLLCFGR
```

按照 STM32F4 的 `RCC_PLLCFGR` 位域拆分：

|位域|提取方式|结果|
|---|---|---|
|PLLM `[5:0]`|`0x07405408 & 0x3F`|8|
|PLLN `[14:6]`|`(value >> 6) & 0x1FF`|336|
|PLLP `[17:16]`|编码 0 对应除以 2|2|
|PLLSRC `[22]`|1 表示 HSE|HSE|
|PLLQ `[27:24]`|`(value >> 24) & 0xF`|7|

HSE 的 8 MHz 也能在固件中交叉验证。时钟查询函数 `0x08026BE4` 加载 `0x00F42400`（16,000,000 Hz，HSI），再右移一位得到 8,000,000 Hz；当 `PLLSRC=1` 时，该函数选择这个 8 MHz 值参与 PLL 计算：

```asm
08026BEA  LDR   R4, =0x00F42400  ; 16 MHz HSI
08026BF2  ASRS  R6, R4, #1       ; 8 MHz HSE
08026C0A  UBFX  R5, R1, #22, #1  ; PLLSRC
08026C16  UDIV  R1, R6, R1       ; HSE / PLLM
```

代入 STM32F4 PLL 公式：

```text
PLL 输入 = HSE / PLLM        = 8 MHz / 8   = 1 MHz
VCO      = PLL输入 × PLLN    = 1 MHz × 336 = 336 MHz
SYSCLK   = VCO / PLLP        = 336 MHz / 2 = 168 MHz
PLL48CLK = VCO / PLLQ        = 336 MHz / 7 = 48 MHz
```

同一函数还把 AHB 设为 `/1`、APB1 设为 `/4`、APB2 设为 `/2`，因此最终时钟树为：

|时钟|频率|
|---|---|
|SYSCLK/HCLK|168 MHz|
|APB1/PCLK1|42 MHz|
|APB2/PCLK2|84 MHz|
|APB1 定时器时钟|84 MHz|
|APB2 定时器时钟|168 MHz|
|USB/SDIO/RNG PLL48CLK|48 MHz|

`FLASH_ACR` 随后被写成 `0x705`，包含 5 个 Flash 等待周期以及预取/Cache 设置，也与 168 MHz 运行配置一致。综上，“STM32F4”由外设映射、FPU 和向量表确定，“168 MHz”则由固件中的 HSE/PLL 参数精确计算得到，而不是根据常见开发板配置猜测。