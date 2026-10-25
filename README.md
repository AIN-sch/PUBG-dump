# PUBG 内存镜像 dump 与 UE 反射分析

TslGame.exe 运行时镜像提取、UE 4.16.3 反射结构、BattlEye 打包结构。

关键词 `PUBG` `TslGame` `BattlEye` `BEService` `UE4` `GNames` `GObjects` `内存dump`

---

## 文件

| 路径 | 说明 |
|---|---|
| `release/tsl_fixed.exe.xz.part.a` | 镜像分卷 1，99,614,720 B |
| `release/tsl_fixed.exe.xz.part.b` | 镜像分卷 2，49,352,924 B |
| `driver/bebypass.c` | 句柄提权驱动，164 行 |
| `tools/dump_process.py` | 从活进程提镜像 |
| `tools/fix_pe.py` | 修节表 |
| `tools/check_ci_options.py` | 读运行时 CodeIntegrityOptions |
| `logs/` | 取证原始输出 |

原始镜像 454,993,920 B
sha256 `4a90639ac012c8530d63c7f013758774c1b61901bdc70fae3e67493f79cff768`

还原：

```bash
cat release/tsl_fixed.exe.xz.part.a release/tsl_fixed.exe.xz.part.b > tsl_fixed.exe.xz
sha256sum tsl_fixed.exe.xz
# a28ad1e661402ca5ac39efcd952dd50c73a54c2dff75fd9f7d9f438f6c38ceb6

xz -d tsl_fixed.exe.xz
sha256sum tsl_fixed.exe
# 4a90639ac012c8530d63c7f013758774c1b61901bdc70fae3e67493f79cff768
```

---

## 磁盘 TslGame.exe

```
<Steam>\steamapps\common\PUBG\TslGame\Binaries\Win64\TslGame.exe
```

237,399,936 B。`.text` 磁盘 70 MB，虚拟 258 MB，膨胀 3.68 倍，熵 8.000。`ImageBase 0x140000000`。

磁盘上拿不到可用代码。

---

## 提镜像

运行时基址要现查，磁盘那个基址是死的。ASLR 每次不同，实测落在 `0x7FF6D7570000`。

```python
import ctypes, ctypes.wintypes as wt

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

class MODULEINFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', ctypes.c_void_p),
                ('SizeOfImage', wt.DWORD),
                ('EntryPoint', ctypes.c_void_p)]

pid = 0   # TslGame
h = k32.OpenProcess(0x0410, False, pid)

needed = wt.DWORD(0)
psapi.EnumProcessModulesEx(h, None, 0, ctypes.byref(needed), 0x03)
count = needed.value // ctypes.sizeof(ctypes.c_void_p)
buf = (ctypes.c_void_p * count)()
psapi.EnumProcessModulesEx(h, buf, needed.value, ctypes.byref(needed), 0x03)

for i in range(count):
    mi = MODULEINFO()
    psapi.GetModuleInformation(h, buf[i], ctypes.byref(mi), ctypes.sizeof(mi))
    nm = ctypes.create_unicode_buffer(260)
    k32.GetModuleBaseNameW(h, buf[i], nm, 260)
    if nm.value.lower() == 'tslgame.exe':
        print(hex(mi.lpBaseOfDll), hex(mi.SizeOfImage))
```

分块读，4 MB 一块。读失败的页补零，别中断，BattlEye 会保护部分页：

```python
CHUNK = 4 * 1024 * 1024
buf = ctypes.create_string_buffer(CHUNK)
read = ctypes.c_size_t(0)

with open('tsl_raw.bin', 'wb') as f:
    for off in range(0, size, CHUNK):
        n = min(CHUNK, size - off)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(read))
        f.write(buf.raw[:read.value] if ok else b'\x00' * n)
```

dump 出来是纯内存布局，`RawOff == VA`。节表里 `PointerToRawData` 还是磁盘旧值，要改成 `VirtualAddress`：

```python
import struct

d = bytearray(open('tsl_raw.bin', 'rb').read())
e = struct.unpack_from('<I', d, 0x3C)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
secoff = e + 24 + struct.unpack_from('<H', d, e + 20)[0]

for i in range(nsec):
    p = secoff + i * 40
    vsz, va, rawsz, rawptr = struct.unpack_from('<IIII', d, p + 8)
    struct.pack_into('<I', d, p + 16, va)
    struct.pack_into('<I', d, p + 20, max(vsz, 1))

open('tsl_fixed.exe', 'wb').write(d)
```

ImageBase 别动。`.data` 里全是 `0x7FF6...` 硬编码指针，改基址不跑 reloc 会让整个镜像的指针报废。IDA 载入时选不重定位。

---

## .pubg0

86 MB，`ch = 0x68000060`（X|R|IDATA|CODE）。

八种压缩/加密都试过，全部落空：

| 算法 | 结果 |
|---|---|
| zlib | 300 处命中，0 成功 |
| LZMA | 1 处过严格校验，解压 Corrupt |
| zstd | 0 |
| gzip | 5 |
| bzip2 | 2 |
| XOR 重复密钥 | 自相关 0.0038~0.0095，无周期 |
| AES-ECB | 32 字节块重复 0 |

字节分布 `FF` 高出 114.75%，`00` 高出 105.64%，256 种字节全覆盖。磁盘和内存 91% 块一致。

代码密度对比很说明问题：`48 89 5C 24` 这个序言在 `.text` 里 748 处每 MB，在 `.pubg0` 里 0 处每 MB。不是代码。

磁盘节表偏移抄 `0x758EC00` 是错的，那是异常结构表。真值 `0x758F400`，差 `0x800`。

## .pubg0 挡不住 SDK dump

258 MB 明文 `.text` 里翻遍了，对 `.pubg0` 的引用：

| 引用方式 | 命中 |
|---|---|
| RVA 直接引用 | 0 |
| `lea` 指令 | 0 |
| ±2 MB 范围扫描 | 0 |

SDK dump 要的三样东西都在明文段：`.rdata` 反射名、`.data` 的 GNames/GObjects 槽、运行时堆。加密段可以当不存在。

---

## BattlEye 文件布局

实际文件在三个地方，都是 18.9 MB 的同一个 `BEService.exe`：

```
<ProgramFilesX86>\Common Files\BattlEye\BEService.exe
<ProgramFilesX86>\Common Files\BattlEye\BEService_pubg.exe
<Steam>\steamapps\common\PUBG\TslGame\Binaries\Win64\BattlEye\BEService_x64.exe
```

服务注册：

```
HKLM\SYSTEM\CurrentControlSet\Services\BEService
  ImagePath    "<ProgramFilesX86>\Common Files\BattlEye\BEService.exe"
  Type         16     (服务，不是内核驱动)
  Start        3
```

`BEDaisy.sys` 全盘扫 247,607 个目录，零命中。已加载的 247 个内核模块里也没有。游戏没启动。

`BEService.exe` 的节表暴露了驱动的藏身处：

```
.be0   VA=0x00050000  VSize=0x0075C4DE (7.7MB)  RawPtr=0          RawSize=0
.be2   VA=0x007AE000  VSize=0x012196D8 (19MB)   RawPtr=0x600      RawSize=0x1219800  ch=0x68000060
.rsrc  VA=0x019C8000  VSize=0x009A4058 (10MB)   RawPtr=0x1219E00  RawSize=0x200
```

`.be0` 虚拟 7.7 MB、磁盘 0 字节。`.rsrc` 虚拟 10 MB、磁盘 512 字节。两个都是运行时才填的空节。`.be2` 19 MB，权限带 X 和 CODE 标记。

文件里搜 `BEDaisy` 字符串是空的，`.sys` 路径也是空的。驱动名运行时拼出来的。

和 TslGame 的 `.pubg0` 同一套思路：磁盘留空壳，内存里才有真东西。

---

## UE 反射结构

4.16.3。这个版本用 `FFixedUObjectArray`，名字表是旧的 `TNameEntryArray`，不是 4.23 之后那个 `FNamePool`。

| 项 | 偏移 |
|---|---|
| Objects | +0x000 |
| MaxObjects | +0x008 |
| NumObjects | +0x00C |

反射名是 UTF-16LE，放 `.rdata`。按 ASCII 搜全 0 命中，这点容易踩。

锚点：

| 项 | 地址 |
|---|---|
| FName 解析函数 | `sub_7FF6D7EA2A24`，size `0x60e` |
| 同时引用 | `"None"` @ `0x7FF6E883A5D8`、`"ByteProperty"` @ `0x7FF6E883A5E8` |
| 名字表起止 | `0x7FF6E883A5D8` ~ `0x7FF6E883A8D8` |
| 全局槽候选 | `0x7FF6EA33C500` ~ `0x7FF6EA33D000` |

那个槽区间里有 147 个 QWORD 指向镜像外（`0x7FF9...` / `0x7FFA...`），是堆指针，GNames/GObjects 从这里找。

版本可以靠 `"AssetObjectProperty"` 判。4.16 独有，4.17 改成 `SoftObjectProperty`。

---

## 句柄剥离

`ObRegisterCallbacks` 按 altitude 降序跑，高的先执行。

BattlEye 挂在 `363220`（PUBG 的具体值没实测过）。它先跑，把进程和线程句柄权限剥掉。找个低 altitude 注册，后跑，把 `DesiredAccess` 改回去。

`driver/bebypass.c` 就是这么干的，altitude 写 `1000`。

`OB_PRE_OPERATION_PARAMETERS` 是 union，`CreateHandleInformation` 和 `DuplicateHandleInformation` 前两个字段同偏移，两个都得处理。

`PsGetProcessImageFileName` 不在任何 WDK 头里，但 ntoskrnl 导出。不显式声明的话默认按 int 返回，x64 下指针截一半：

```c
NTSYSAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
```

编译用 EWDK。`SetupBuildEnv.cmd` 的参数是 `amd64`，填 `x64` 会落到 ARM64 分支。这个脚本不设 `INCLUDE` 和 `LIB`，得自己补：

```bat
call "%EWDK%\BuildEnv\SetupBuildEnv.cmd" amd64

set "W10=%WDKContentRoot%Include%\%WindowsTargetPlatformVersion%"
set "L10=%WDKContentRoot%Lib%\%WindowsTargetPlatformVersion%"
set "INCLUDE=%INCLUDE%;%W10%\km;%W10%\shared;%W10%\ucrt;%W10%\um"
set "LIB=%LIB%;%L10%\km\x64;%L10%\ucrt\x64"

cl /nologo /c /W4 /O2 /kernel /GS- /Zl /D_AMD64_ /DAMD64 /DWIN32_LEAN_AND_MEAN=1 /Fo:bebypass.obj bebypass.c
link /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /OUT:bebypass.sys bebypass.obj ntoskrnl.lib BufferOverflowK.lib
```

出包后 `Subsystem` 必须是 1（NATIVE），是 2 或 3 内核不认。

---

## 调试

单机 `kd -kl` 能直连，断点命中整机冻死，有锁死风险，只能硬重启。不需要第二台机器。

VMware 走命名管道好一些，断点只冻 guest：

```
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "\\.\pipe\kd_lab"
serial0.pipe.endPoint = "server"
```

guest 里 `bcdedit /dbgsettings serial debugport:1 baudrate:115200`，宿主挂上去：

```powershell
kd.exe -k com:pipe,port=\\.\pipe\kd_lab,baud=115200,reconnect
```

BattlEye 查 CPUID leaf 1 的 ECX bit 31，还有 leaf `0x40000000` 的 vendor 字符串。VMware 能挡：

```
hypervisor.cpuid.v0 = "FALSE"
monitor_control.restrict_backdoor = "TRUE"
```

Hyper-V 挡不住这一位，Client Hyper-V 没这个配置项。

VMware Workstation 没有 GPU 分区，也没有 PCIe 直通，3D 是共享渲染，guest 的调用转给宿主 GPU：

```
mks.enable3D = "TRUE"
mks.enable3dRenderer = "dx11"
mks.vramSize = "2048"
svga.vramSize = "268435456"
svga.autodetect = "FALSE"
mks.forceDiscreteGPU = "TRUE"
```

双显卡机器不写 `mks.forceDiscreteGPU` 会走核显。`svga.autodetect` 不关掉会覆盖手设的 vram。

guest 里得装 VMware Tools，设备管理器出现 `VMware SVGA 3D` 才算成。

guest 看到的卡就是 `VMware SVGA 3D`，PCI 厂商 ID `0x15AD`。这一项藏不住，联机跑游戏必被认出来。但驱动加载和断点跟帧数没关系。

---

## 踩过的坑

| 现象 | 原因 |
|---|---|
| `sc start` 报 `5 拒绝访问`，`SERVICE_EXIT_CODE = 0` | SCM 层就拒了，DriverEntry 没跑 |
| `NtLoadDriver = 0xC0000061` | 令牌里 `SeLoadDriverPrivilege` 没启用 |
| `NtLoadDriver = 0xC0000034` | 服务键或文件找不到，可以拿来当对照 |
| `NtLoadDriver = 0xC0000022` | 特权没问题，被策略或签名挡了 |
| `NtLoadDriver = 0xC0000010` | 驱动没写 `DriverUnload`，卸不掉 |
| x64dbg attach 后进程 2 秒自杀 | 反调试。改 ReadProcessMemory |
| pd64 报 256 MiB 限制 | 尺寸超了，自己写 dump |
| `no MZ at 0x140000000` | ASLR，那不是真实基址 |
| IDA 载入后 `.text` 全 unknown | 节表 `RawOff` 还是磁盘值 |
| `.pubg0` 节表偏移 `0x758EC00` | 错值，真值 `0x758F400` |
| `PsGetProcessImageFileName` 报 implicit int | 没显式声明，x64 截断 |
| `SetupBuildEnv.cmd x64` | 落到 ARM64 分支，参数用 `amd64` |
| `SetupBuildEnv.cmd` 被引号包住 | 整串当路径了，写 `call "path" amd64` |
| `Split-Path -ResolveError` | 没这个参数 |
| GBK 控制台 `UnicodeEncodeError` | 文件写 utf-8，控制台转 ascii |
| `ida_segment.getn_segm` | 正确名 `getnseg` |
| `survey_binary` 超时 | 内部遍历全部字符串，大文件跑不动 |
| `py_eval` 60s 超时 | 改离线 Python |

---

## 哈希

```
镜像
  454,993,920 B
  4a90639ac012c8530d63c7f013758774c1b61901bdc70fae3e67493f79cff768
  base 0x7FF6D7570000

xz
  148,967,644 B
  ratio 0.3274
  a28ad1e661402ca5ac39efcd952dd50c73a54c2dff75fd9f7d9f438f6c38ceb6
```

镜像每次 dump 哈希都不一样。ASLR 换基址，SECURITY_COOKIE、堆指针、时间戳也都在变。上面的哈希只对应这一次 dump，拿它验下载完整性，别拿它判断游戏版本。

版本看 `.rdata` 里有没有 `"AssetObjectProperty"`。

---

仅供逆向工程学习与方法研究。不提供成品，不提供技术支持。
