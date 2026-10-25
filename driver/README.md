# 句柄提权驱动

`bebypass.c`，164 行，只用文档化 WDK API。

## 原理

`ObRegisterCallbacks` 按 altitude 降序执行，高的先跑。

BattlEye 挂 `363220`，先跑，剥掉进程和线程句柄权限。
本驱动挂 `1000`，后跑，把 `DesiredAccess` 改回 `0x1FFFFF`。

只对指定 caller 开放，不向任何人交权限：

```c
#define TARGET_IMAGE_PREFIX "TslGame"
#define CALLER_IMAGE_PREFIX "pubg"
```

`CALLER_IMAGE_PREFIX` 是 `"pubg"`，测试程序必须叫 `pubg*.exe`。
`python.exe` 匹配不上，驱动不触发。

## 未文档化函数

```c
NTSYSAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
```

ntoskrnl 导出，但任何 WDK 头里都没有。不显式声明的话默认按 `int` 返回，
x64 下 `PCHAR` 截成 32 位。

## 编译

EWDK `<EWDK>`，
MSVC 14.50.35717，WDK 10.0.28000.0。

`SetupBuildEnv.cmd` 的参数是 `amd64`，填 `x64` 会落到 ARM64 分支。
这个脚本不设 `INCLUDE` 和 `LIB`，得自己补。

```bat
@echo off
setlocal

set "EWDK=<EWDK>"
call "%EWDK%\BuildEnv\SetupBuildEnv.cmd" amd64

set "W10=%WDKContentRoot%Include%\%WindowsTargetPlatformVersion%"
set "L10=%WDKContentRoot%Lib%\%WindowsTargetPlatformVersion%"

set "INCLUDE=%INCLUDE%;%W10%\km;%W10%\shared;%W10%\ucrt;%W10%\um"
set "LIB=%LIB%;%L10%\km\x64;%L10%\ucrt\x64"

cl /nologo /c /W4 /O2 /kernel /GS- /Zl /D_AMD64_ /DAMD64 /DWIN32_LEAN_AND_MEAN=1 /Fo:bebypass.obj bebypass.c
if errorlevel 1 exit /b 1

link /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /OUT:bebypass.sys bebypass.obj ntoskrnl.lib BufferOverflowK.lib
if errorlevel 1 exit /b 1

echo BUILD_OK
```

出包后核这几项：

```
Machine             = 0x8664
OptMagic            = 0x020B
Subsystem           = 1
AddressOfEntryPoint = 0x1000
```

`Subsystem` 不是 1 内核不认。

## 加载

自签驱动在这台机器上过不去，`NtLoadDriver` 返回 `0xC0000022`。
对照实验在根目录 README 第 7 节。

三个开关都对这条链路无效：`testsigning`、`nointegritychecks`、
`VulnerableDriverBlocklistEnable`。它们只管 DSE 层。

## 卸载

`DriverUnload` 里调 `ObUnRegisterCallbacks`。

不是所有驱动都能热卸。没写 `DriverUnload` 的驱动，
`NtUnloadDriver` 返回 `0xC0000010`，`sc query` 显示 `NOT_STOPPABLE`，只能重启。
