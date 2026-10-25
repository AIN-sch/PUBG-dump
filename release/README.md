# 镜像分卷

原始镜像 454,993,920 B，xz 压缩后 148,967,644 B，压缩率 0.3274。
GitHub 单文件上限 100 MB，故切两卷。

## 文件

| 文件 | 大小 | sha256 |
|---|---|---|
| `tsl_fixed.exe.xz.part.a` | 99,614,720 B | `a1b87eafc9d3473a0b625c7f95c970022dbafc84a7efe79595fff5d13faccdf5` |
| `tsl_fixed.exe.xz.part.b` | 49,352,924 B | `49ac409b85dbda0c4ba03e66585a3003a30236c52ef4424b427e7cd7b52df259` |

合并后 `tsl_fixed.exe.xz` sha256 = `a28ad1e661402ca5ac39efcd952dd50c73a54c2dff75fd9f7d9f438f6c38ceb6`

解压后 `tsl_fixed.exe` sha256 = `4a90639ac012c8530d63c7f013758774c1b61901bdc70fae3e67493f79cff768`

## 合并

Linux / macOS:

```bash
cat tsl_fixed.exe.xz.part.a tsl_fixed.exe.xz.part.b > tsl_fixed.exe.xz
sha256sum tsl_fixed.exe.xz
xz -d tsl_fixed.exe.xz
sha256sum tsl_fixed.exe
```

Windows cmd:

```bat
copy /b tsl_fixed.exe.xz.part.a+tsl_fixed.exe.xz.part.b tsl_fixed.exe.xz
certutil -hashfile tsl_fixed.exe.xz SHA256
```

Windows PowerShell:

```powershell
cmd /c copy /b tsl_fixed.exe.xz.part.a+tsl_fixed.exe.xz.part.b tsl_fixed.exe.xz
Get-FileHash tsl_fixed.exe.xz -Algorithm SHA256

# 解压（需 7-Zip 或 xz）
7z x tsl_fixed.exe.xz
```

## 镜像特征

```
大小    454,993,920 B
基址    0x7FF6D7570000
布局    RawOff == VA
节表    PointerToRawData 已改写为 VirtualAddress
```

载入 IDA 会提示基址不符，选「不重定位」或手动指定 `0x7FF6D7570000`。
不要用 rebase，`.data` 里全是 `0x7FF6...` 硬编码指针。

## 为什么是这个哈希

镜像每次 dump 出来的哈希都不同。ASLR 让基址随机，
且 SECURITY_COOKIE、堆指针、时间戳每次不同。

上面的哈希对应一次具体 dump。用它验证下载完整性，
不要用它判断「是不是同一个版本的游戏」。

版本判定看 `.rdata` 里有没有 `"AssetObjectProperty"`（4.16 独有）。
