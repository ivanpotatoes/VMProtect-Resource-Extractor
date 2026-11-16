"""Native coverage callback boundary, ABI, and live Unicorn equivalence tests."""
import ctypes as c
from pathlib import Path
import random
import struct

import unicorn as u
from unicorn.unicorn_py3.unicorn import uclib

ROOT = Path(__file__).resolve().parents[1]

def library():
    lib = c.CDLL(str(ROOT / 'dist/vmp-native-tracker.dll'))
    lib.vmp_tracker_abi_version.restype = c.c_uint
    lib.vmp_tracker_state_size.restype = c.c_size_t
    lib.vmp_tracker_callback.restype = c.c_void_p
    lib.vmp_tracker_init.argtypes = [c.c_void_p, c.c_size_t, c.c_uint64, c.c_uint64, c.c_void_p, c.c_size_t]
    lib.vmp_tracker_init.restype = c.c_int
    lib.vmp_tracker_stats.argtypes = [c.c_void_p, c.c_void_p, c.c_size_t]
    lib.vmp_tracker_stats.restype = c.c_int
    assert lib.vmp_tracker_abi_version() == 1
    return lib

def tracker(lib, base, size):
    bitmap = bytearray(size)
    view = (c.c_uint8 * size).from_buffer(bitmap)
    storage = c.create_string_buffer(lib.vmp_tracker_state_size())
    assert lib.vmp_tracker_init(storage, len(storage), base, size, view, size)
    return bitmap, view, storage

def boundary_test(lib):
    bitmap, view, storage = tracker(lib, 0x1000, 64)
    callback = c.CFUNCTYPE(None,c.c_void_p,c.c_int,c.c_uint64,c.c_int,c.c_int64,c.c_void_p)(lib.vmp_tracker_callback())
    reference = bytearray(64)
    accepted = rejected = count = length = 0
    cases = [(0x1000,1,u.UC_MEM_WRITE),(0x1038,8,u.UC_MEM_WRITE),
             (0xfff,2,u.UC_MEM_WRITE),(0x103f,2,u.UC_MEM_WRITE),
             (0x1000,0,u.UC_MEM_WRITE),(0x1000,-1,u.UC_MEM_WRITE),
             (0xffffffffffffffff,8,u.UC_MEM_WRITE),(0x1004,4,u.UC_MEM_READ)]
    rng = random.Random(112)
    cases += [(rng.randrange(0xff0,0x1050),rng.randrange(-2,25),u.UC_MEM_WRITE) for _ in range(1000)]
    for address,size,access in cases:
        callback(None,access,address,size,0,storage)
        count += 1
        offset = address - 0x1000
        if access == u.UC_MEM_WRITE and size > 0 and 0 <= offset and offset + size <= 64:
            reference[offset:offset+size] = b'\1' * size
            accepted += 1
            length += size
        else:
            rejected += 1
        assert bitmap == reference
    stats = (c.c_uint64 * 5)()
    assert lib.vmp_tracker_stats(storage,stats,5)
    assert list(stats) == [count,accepted,length,accepted,rejected]
    assert not lib.vmp_tracker_init(storage,len(storage),0,65,view,64)
    assert not lib.vmp_tracker_init(storage,len(storage),0xffffffffffffffff,2,view,64)
    assert not lib.vmp_tracker_init(storage,len(storage)-1,0,64,view,64)
    assert not lib.vmp_tracker_init(None,len(storage),0,64,view,64)
    # Last address of the 64-bit address space is valid for a one-byte range.
    assert lib.vmp_tracker_init(storage,len(storage),0xffffffffffffffff,1,view,64)
    callback(None,u.UC_MEM_WRITE,0xffffffffffffffff,1,0,storage)
    assert bitmap[0] == 1

def unicorn_test(lib):
    base = 0x400000
    native, view, storage = tracker(lib,base,4096)
    reference = bytearray(4096)
    uc = u.Uc(u.UC_ARCH_X86,u.UC_MODE_64)
    uc.mem_map(0x100000,4096)
    uc.mem_map(base,4096)
    # MOV RDI, base+3; MOV RCX, 257; MOV AL,0; REP STOSB; MOV [RDI],RDI.
    # Zero-valued writes count as initialized bytes, as do overlapping writes.
    code = b'\x48\xbf'+struct.pack('<Q',base+3)+b'\x48\xc7\xc1\x01\x01\0\0\xb0\0\xf3\xaa\x48\x89\x3f'
    uc.mem_write(0x100000,code)
    native_hook = c.c_size_t()
    error = uclib.uc_hook_add(uc._uch,c.byref(native_hook),u.UC_HOOK_MEM_WRITE,
                             lib.vmp_tracker_callback(),c.cast(storage,c.c_void_p),
                             c.c_uint64(base),c.c_uint64(base+4095))
    assert error == 0,error
    def python_write(uc,access,address,size,value,data):
        offset = address-base
        if 0 <= offset and offset+size <= len(reference):
            reference[offset:offset+size] = b'\1'*size
    python_hook = uc.hook_add(u.UC_HOOK_MEM_WRITE,python_write,begin=base,end=base+4095)
    try:
        uc.emu_start(0x100000,0x100000+len(code),count=1000)
        assert native == reference
        assert native[:3] == b'\0'*3
        assert native[3:268] == b'\1'*265
        assert native[268:] == b'\0'*(4096-268)
        stats = (c.c_uint64*5)()
        assert lib.vmp_tracker_stats(storage,stats,5)
        assert stats[1] == 258 and stats[2] == 265 and stats[4] == 0
    finally:
        uc.hook_del(python_hook)
        assert uclib.uc_hook_del(uc._uch,native_hook.value) == 0

def main():
    lib = library()
    boundary_test(lib)
    unicorn_test(lib)
    print('PASS: native ABI, randomized byte coverage, overflow/bounds rejection, live Unicorn callback equivalence')

if __name__ == '__main__': main()
