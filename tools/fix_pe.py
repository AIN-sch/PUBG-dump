#!/usr/bin/env python3
"""把内存 dump 的节表 PointerToRawData 改成 VirtualAddress，使 RawOff == VA。

    python fix_pe.py --in tsl_raw.bin --out tsl_fixed.exe

不改 ImageBase。内存里 .data 全是运行时基址开头的硬编码指针，
改基址不跑 reloc 会让全部指针失效。
"""

import argparse
import os
import struct
import sys


def fix(inp, out):
    d = bytearray(open(inp, 'rb').read())

    if d[:2] != b'MZ':
        print('no MZ in %s' % inp)
        return 1

    e = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e:e + 4] != b'PE\x00\x00':
        print('no PE sig at 0x%X' % e)
        return 1

    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from('<H', d, opt)[0]

    if magic == 0x20B:
        base = struct.unpack_from('<Q', d, opt + 24)[0]
    elif magic == 0x10B:
        base = struct.unpack_from('<I', d, opt + 28)[0]
    else:
        print('bad optional header magic 0x%X' % magic)
        return 1

    print('imagebase 0x%X' % base)
    print('sections  %d' % nsec)
    print('')
    print('%-10s %10s %10s %14s %14s' % ('name', 'VA', 'VSize', 'oldRawPtr', 'newRawPtr'))

    secoff = opt + optsz
    fixed = 0
    for i in range(nsec):
        p = secoff + i * 40
        nm = d[p:p + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vsz, va, rawsz, rawptr = struct.unpack_from('<IIII', d, p + 8)
        if va + max(vsz, rawsz) > len(d):
            print('%-10s skip, VA 0x%X past EOF' % (nm, va))
            continue
        struct.pack_into('<I', d, p + 16, va)
        struct.pack_into('<I', d, p + 20, max(vsz, 1))
        print('%-10s 0x%08X 0x%08X   0x%08X     0x%08X' % (nm, va, vsz, rawptr, va))
        fixed += 1

    open(out, 'wb').write(d)
    print('')
    print('patched %d sections, wrote %s (%d B)' % (fixed, out, len(d)))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', required=True)
    ap.add_argument('--out', dest='out', required=True)
    a = ap.parse_args()

    if not os.path.exists(a.inp):
        print('missing %s' % a.inp)
        return 1
    return fix(a.inp, a.out)


if __name__ == '__main__':
    sys.exit(main())
