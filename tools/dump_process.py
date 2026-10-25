#!/usr/bin/env python3
"""从活进程读指定模块的完整内存镜像。

    python dump_process.py --name TslGame.exe --out tsl_raw.bin
    python dump_process.py --pid 1234 --out tsl_raw.bin

读失败页补零不中断，末尾报失败页数。输出是纯内存布局，
节表 PointerToRawData 还是磁盘旧值，要再跑 fix_pe.py。
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import sys

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wt.BOOL
k32.CloseHandle.argtypes = [wt.HANDLE]

psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_void_p),
                                       wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]
psapi.GetModuleInformation.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                       ctypes.c_void_p, wt.DWORD]

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03


class MODULEINFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', ctypes.c_void_p),
                ('SizeOfImage', wt.DWORD),
                ('EntryPoint', ctypes.c_void_p)]


def find_pid(target):
    TH32CS_SNAPPROCESS = 0x00000002

    class PE32(ctypes.Structure):
        _fields_ = [('dwSize', wt.DWORD),
                    ('cntUsage', wt.DWORD),
                    ('th32ProcessID', wt.DWORD),
                    ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                    ('th32ModuleID', wt.DWORD),
                    ('cntThreads', wt.DWORD),
                    ('th32ParentProcessID', wt.DWORD),
                    ('pcPriClassBase', ctypes.c_long),
                    ('dwFlags', wt.DWORD),
                    ('szExeFile', ctypes.c_char * 260)]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return 0
    e = PE32()
    e.dwSize = ctypes.sizeof(PE32)
    pid = 0
    want = target.lower()
    ok = k32.Process32First(snap, ctypes.byref(e))
    while ok:
        if e.szExeFile.decode('mbcs', 'replace').lower() == want:
            pid = e.th32ProcessID
            break
        ok = k32.Process32Next(snap, ctypes.byref(e))
    k32.CloseHandle(snap)
    return pid


def find_module(h, want):
    needed = wt.DWORD(0)
    psapi.EnumProcessModulesEx(h, None, 0, ctypes.byref(needed), LIST_MODULES_ALL)
    if not needed.value:
        return 0, 0
    n = needed.value // ctypes.sizeof(ctypes.c_void_p)
    buf = (ctypes.c_void_p * n)()
    if not psapi.EnumProcessModulesEx(h, buf, needed.value, ctypes.byref(needed), LIST_MODULES_ALL):
        return 0, 0

    low = want.lower()
    for i in range(n):
        mi = MODULEINFO()
        if not psapi.GetModuleInformation(h, buf[i], ctypes.byref(mi), ctypes.sizeof(mi)):
            continue
        nm = ctypes.create_unicode_buffer(260)
        if not k32.GetModuleBaseNameW(h, buf[i], nm, 260):
            continue
        if nm.value.lower() == low:
            return mi.lpBaseOfDll, mi.SizeOfImage
    return 0, 0


def dump(h, base, size, out, chunk=4 * 1024 * 1024):
    buf = ctypes.create_string_buffer(chunk)
    read = ctypes.c_size_t(0)
    failed = 0
    with open(out, 'wb') as f:
        off = 0
        while off < size:
            n = min(chunk, size - off)
            ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(read))
            if ok and read.value == n:
                f.write(buf.raw[:n])
            else:
                if ok and read.value:
                    f.write(buf.raw[:read.value])
                    f.write(b'\x00' * (n - read.value))
                else:
                    f.write(b'\x00' * n)
                failed += 1
            off += n
    return failed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, default=0)
    ap.add_argument('--name', default='')
    ap.add_argument('--module', default='')
    ap.add_argument('--out', default='tsl_raw.bin')
    a = ap.parse_args()

    pid = a.pid or (find_pid(a.name) if a.name else 0)
    if not pid:
        print('process not found')
        return 1

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print('OpenProcess err=%d' % ctypes.get_last_error())
        print('句柄被剥离了，需要先提权，见 driver/bebypass.c')
        return 1

    mod = a.module or a.name or 'TslGame.exe'
    base, size = find_module(h, mod)
    if not base:
        print('module not found: %s' % mod)
        k32.CloseHandle(h)
        return 1

    print('pid    %d' % pid)
    print('module %s' % mod)
    print('base   0x%X' % base)
    print('size   0x%X (%.1f MB)' % (size, size / 1048576.0))

    failed = dump(h, base, size, a.out)
    k32.CloseHandle(h)

    print('written %s' % a.out)
    print('unread blocks %d' % failed)
    return 0


if __name__ == '__main__':
    sys.exit(main())
