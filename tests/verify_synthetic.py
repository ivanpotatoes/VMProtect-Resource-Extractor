"""Independent format fixtures: arbitrary keys, unaligned tables, Unicode and ambiguity."""
import json
from pathlib import Path
import struct
from verify_samples import run, work_directory

def rol(key, i):
    i &= 31
    return ((key << i) | (key >> ((32-i) & 31))) & 0xffffffff

def image(x64, tables):
    data = bytearray(0x2200)
    def w16(p, v): struct.pack_into('<H', data, p, v)
    def w32(p, v): struct.pack_into('<I', data, p, v)
    data[:2] = b'MZ'
    w32(0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    w16(0x84, 0x8664 if x64 else 0x14c)
    w16(0x86, 1)
    w16(0x94, 0xf0 if x64 else 0xe0)
    opt = 0x98
    w16(opt, 0x20b if x64 else 0x10b)
    w32(opt+60, 0x200)
    sec = opt + (0xf0 if x64 else 0xe0)
    data[sec:sec+8] = b'.private'
    for off, value in [(8,0x2000),(12,0x1000),(16,0x2000),(20,0x200)]:
        w32(sec+off, value)
    for table_offset, key, named in tables:
        base = 0x200 + table_offset
        def enc(offset, value): w32(base+offset, value ^ key)
        # type -> name -> language -> leaf, deliberately unrelated to research IDs.
        for offset, value in {0:int(named),4:int(not named),8:0x80000060 if named else 123,
                              12:0x80000010,16:0,20:1,24:543,28:0x80000020,
                              32:0,36:1,40:1041,44:48,
                              48:0x1000+table_offset+0xc0,52:7,56:65001,60:0}.items():
            enc(offset,value)
        name = '資料_İ'.encode('utf-16-le') + b'\0\0'
        for j in range(len(name)//2):
            value = struct.unpack_from('<H',name,j*2)[0] ^ ((rol(key,j)+j)&0xffff)
            w16(base+0x60+j*2,value)
        for i,c in enumerate(b'abc\0xyz'):
            data[base+0xc0+i] = c ^ ((rol(key,i)+i)&255)
    return data

def main():
    with work_directory(prefix='vmp-synthetic-') as tmp:
        tmp = Path(tmp)
        for index,(x64,key,named) in enumerate([(True,0,False),(False,0xffffffff,True),(True,0x12345678,True),(False,0x890abcde,False)]):
            src = tmp / f'test-{index}.exe'
            src.write_bytes(image(x64,[(0x137,key,named)]))
            out = tmp / f'out-{index}'
            run(src,'-o',out)
            m = json.loads((out/'manifest.json').read_text(encoding='utf-8'))
            assert m['key'] == hex(key)
            assert m['table_rva'] == '0x1137'
            assert m['architecture'] == ('x64' if x64 else 'x32')
            assert len(m['resources']) == 1
            r = m['resources'][0]
            assert r['type'] == ('資料_İ' if named else 123)
            assert (r['name'],r['language'],r['codepage']) == (543,1041,65001)
            assert (out/r['file']).read_bytes() == b'abc\0xyz'
        src = tmp/'multiple.exe'
        src.write_bytes(image(True,[(0x137,0x12345678,True),(0x737,0xabcd1234,False)]))
        result = run(src,'-o',tmp/'ambiguous',ok=False)
        assert 'Multiple valid tables' in result.stderr
        assert not (tmp/'ambiguous').exists()
        run(src,'--table-rva','0x1737','--key','0xabcd1234','-o',tmp/'explicit')
        broken = image(True,[(0x137,0x12345678,False)])
        struct.pack_into('<I',broken,0x200+0x137+12,0x80000000 ^ 0x12345678)
        src.write_bytes(broken)
        run(src,'--table-rva','0x1137','--key','0x12345678','--list',ok=False)
    print('PASS: PE32/PE32+, Unicode names, arbitrary keys, unaligned tables, ambiguity and cyclic tree rejection')

if __name__ == '__main__':
    main()
