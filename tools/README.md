# 工具

三个脚本，纯标准库，无依赖。

## dump_process.py

从活进程读指定模块的完整镜像。

```bash
python dump_process.py --name TslGame.exe --out tsl_raw.bin
python dump_process.py --pid 1234 --out tsl_raw.bin
```

4 MB 一块，读失败的页补零不中断，末尾报失败块数。
输出是纯内存布局，节表 `PointerToRawData` 还是磁盘旧值。

`OpenProcess` 报 `err=5` 是句柄被剥离了，需要先提权。

## fix_pe.py

节表 `PointerToRawData` 改成 `VirtualAddress`。

```bash
python fix_pe.py --in tsl_raw.bin --out tsl_fixed.exe
```

`ImageBase` 不动。内存里 `.data` 全是运行时基址开头的硬编码指针，
改基址不跑 reloc 会全部报废。IDA 载入时选不重定位。

## check_ci_options.py

读运行时 `CodeIntegrityOptions`。

```bash
python check_ci_options.py
```

`bcdedit` 的 `testsigning` 只是 BCD 存储值。内核采纳与否看运行时位。
实测见过显示 `Yes` 但 `options = 0x00000000` 的机器。

`options & 0x0002` 非零才算生效。

## 串起来

```bash
python dump_process.py --name TslGame.exe --out tsl_raw.bin
python fix_pe.py --in tsl_raw.bin --out tsl_fixed.exe
python -c "import struct;d=open('tsl_fixed.exe','rb').read(0x1000);e=struct.unpack_from('<I',d,0x3c)[0];print(hex(e),d[e:e+4])"
```
