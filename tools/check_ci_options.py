#!/usr/bin/env python3
"""读运行时 CodeIntegrityOptions，看 TESTSIGN 位到底有没有置上。

bcdedit 里那个 testsigning 只是 BCD 存储值，内核可能没采纳。
实测见过 testsigning 显示 Yes 而 options 是 0x00000000 的机器。

    python check_ci_options.py
"""

import ctypes
import sys

ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtQuerySystemInformation.restype = ctypes.c_long

SystemCodeIntegrityInformation = 103

BITS = [
    (0x0001, 'ENABLED'),
    (0x0002, 'TESTSIGN'),
    (0x0004, 'UMCI_ENABLED'),
    (0x0008, 'UMCI_AUDITMODE'),
    (0x0010, 'UMCI_EXCLUSIONPATHS'),
    (0x0020, 'TEST_BUILD'),
    (0x0040, 'PREPRODUCTION_BUILD'),
    (0x0080, 'DEBUGMODE'),
    (0x0100, 'FLIGHT_BUILD'),
    (0x0200, 'FLIGHTING'),
    (0x0400, 'HVCI_KMCI'),
    (0x0800, 'HVCI_KMCI_AUDITMODE'),
    (0x1000, 'HVCI_KMCI_STRICTMODE'),
    (0x2000, 'HVCI_IUM'),
]


def query():
    buf = ctypes.create_string_buffer(16)
    ctypes.memset(buf, 0, 16)
    struct_len = ctypes.c_ulong(8)
    ctypes.memmove(buf, ctypes.byref(struct_len), 4)
    ret = ctypes.c_ulong(0)
    st = ntdll.NtQuerySystemInformation(SystemCodeIntegrityInformation, buf, 16, ctypes.byref(ret))
    arr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))
    return st & 0xFFFFFFFF, arr[1], arr[2]


def main():
    st, options, secureboot = query()

    print('ntstatus  0x%08X' % st)
    print('options   0x%08X' % options)
    print('secureboot %d' % secureboot)
    print('')

    if st == 0xC0000004:
        print('STATUS_INFO_LENGTH_MISMATCH，结构体布局跟本版本对不上，')
        print('但 options 字段读到了，下面照样能用。')
        print('')

    print('set bits:')
    n = 0
    for bit, name in BITS:
        if options & bit:
            print('  0x%04X  %s' % (bit, name))
            n += 1
    if not n:
        print('  none')

    print('')
    print('TESTSIGN %s' % ('ACTIVE' if options & 0x0002 else 'INACTIVE'))
    print('')
    print('TESTSIGN 只管 DSE 层。策略白名单是另一层，')
    print('这一位是 1 也不代表自签驱动过得去。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
