"""Host-backed main-image coherence, native scheduler lifetime and restore tests."""
import ctypes as c
import gc
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
import weakref
import zipfile

import unicorn as u
from unicorn import x86_const as x

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'standalone'))
from native_support import HostImage, BlockBudget
from emulate import Emulator, Unsupported
from work_files import work_directory

BASE=0x400000
SIZE=8192
OUTSIDE=0x800000

class HostImageTests(unittest.TestCase):
    def setUp(self):
        self.uc=u.Uc(u.UC_ARCH_X86,u.UC_MODE_64)
        self.image=HostImage(self.uc,BASE,SIZE)
        self.image.map_region(BASE,SIZE)
        self.uc.mem_map(OUTSIDE,4096)

    def make_budget(self):
        budget=BlockBudget(self.uc,10000,image=self.image)
        self.addCleanup(budget.close)
        return budget

    def run_guest(self,budget,start,end):
        budget.begin(10000,1000)
        self.uc.emu_start(start,end,count=0)
        self.assertEqual(budget.get('reason'),0)

    def test_guest_smc_and_host_api_writes_keep_backing_and_cache_coherent(self):
        code=b'\xb8\x01\0\0\0\x90\x90\x90'
        self.uc.mem_write(BASE,code)
        self.assertEqual(c.string_at(self.image.pointer,8),code)
        budget=self.make_budget()
        self.run_guest(budget,BASE,BASE+8)
        self.assertEqual(self.uc.reg_read(x.UC_X86_REG_EAX),1)
        self.assertEqual(budget.get('total'),4)
        # The writer executes outside the host image and uses fallback reads.
        writer=b'\x48\xbf'+struct.pack('<Q',BASE+1)+b'\xc7\x07\x02\0\0\0'
        writer+=b'\xe9'+struct.pack('<i',BASE-(OUTSIDE+len(writer)+5))
        self.uc.mem_write(OUTSIDE,writer)
        self.run_guest(budget,OUTSIDE,BASE+8)
        self.assertEqual(self.uc.reg_read(x.UC_X86_REG_EAX),2)
        self.assertEqual(c.string_at(self.image.pointer+1,4),b'\x02\0\0\0')
        changed=b'\x31\xc0'+b'\x90'*6
        self.uc.mem_write(BASE,changed)
        before=budget.get('total')
        self.run_guest(budget,BASE,BASE+8)
        self.assertEqual(budget.get('total')-before,7)
        self.assertEqual(c.string_at(self.image.pointer,8),changed)

    def test_cross_boundary_block_uses_fallback(self):
        self.uc.mem_map(BASE+SIZE,4096)
        self.uc.mem_write(BASE+SIZE-4,b'\x90'*8)
        budget=self.make_budget()
        self.run_guest(budget,BASE+SIZE-4,BASE+SIZE+4)
        self.assertEqual(budget.get('total'),8)

    def test_snapshot_header_normalization_never_mutates_live_backing(self):
        live=b'\x55'*SIZE
        self.uc.mem_write(BASE,live)
        emu=self.emulator_shell()
        emu.base=BASE; emu.size=SIZE
        section=SimpleNamespace(Misc_VirtualSize=100,VirtualAddress=4096,get_file_offset=lambda:64)
        emu.pe=SimpleNamespace(sections=[section])
        snapshot=emu.image()
        self.assertEqual(struct.unpack_from('<II',snapshot,80),(4096,4096))
        snapshot[0]=0
        self.assertEqual(bytes(self.uc.mem_read(BASE,SIZE)),live)
        self.assertEqual(c.string_at(self.image.pointer,SIZE),live)

    def test_engine_and_budget_pin_original_aligned_allocation(self):
        self.assertEqual(self.image.pointer%4096,0)
        raw=c.addressof(self.image._buffer)
        self.assertGreaterEqual(self.image.pointer,raw)
        self.assertLessEqual(self.image.pointer+SIZE,raw+len(self.image._buffer))
        backing_ref=weakref.ref(self.image._buffer)
        image_ref=weakref.ref(self.image)
        budget=self.make_budget()
        del self.image
        gc.collect()
        self.assertIsNotNone(image_ref())
        self.assertIsNotNone(backing_ref())
        self.uc.mem_write(BASE,b'\x90')
        self.run_guest(budget,BASE,BASE+1)
        budget.close()
        budget.image=None
        gc.collect()
        self.assertIsNone(image_ref())
        self.assertIsNotNone(backing_ref())
        # Keeping only UC remains safe: its backing reference has no UC cycle.
        self.uc.mem_write(BASE,b'\x90')
        self.uc.emu_start(BASE,BASE+1,count=1)

    def checkpoint(self,directory,regions):
        path=Path(directory)/'state.zip'
        state={'regions':regions,'registers':{},'handles':{}}
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('state.json',json.dumps(state))
            archive.writestr('written.bin',b'\1'*SIZE)
            for begin,end,perm in regions:
                payload=bytearray(end-begin+1)
                if begin==BASE: payload[:8]=b'\xb8\x03\0\0\0\x90\x90\x90'
                archive.writestr(hex(begin),payload)
        return path

    def emulator_shell(self):
        emu=Emulator.__new__(Emulator)
        emu.uc=self.uc
        emu.host_image=self.image
        emu.written=bytearray(SIZE)
        return emu

    def test_split_checkpoint_restore_preserves_pointer_permissions_and_execution(self):
        self.uc.mem_write(BASE,b'old bytes')
        pointer=self.image.pointer
        regions=[(BASE,BASE+4095,u.UC_PROT_READ|u.UC_PROT_EXEC),
                 (BASE+4096,BASE+SIZE-1,u.UC_PROT_READ|u.UC_PROT_WRITE),
                 (OUTSIDE,OUTSIDE+4095,u.UC_PROT_ALL)]
        emu=self.emulator_shell()
        with work_directory(prefix='vmp-host-image-') as directory:
            emu.restore(self.checkpoint(directory,regions))
        self.assertEqual(self.image.pointer,pointer)
        self.assertEqual(list(self.uc.mem_regions()),regions)
        self.assertEqual(c.string_at(pointer,SIZE),bytes(self.uc.mem_read(BASE,SIZE)))
        self.assertEqual(emu.written,b'\1'*SIZE)
        # Scheduler attaches after restore, as in the CLI.
        budget=self.make_budget()
        self.run_guest(budget,BASE,BASE+8)
        self.assertEqual(self.uc.reg_read(x.UC_X86_REG_EAX),3)
        self.uc.mem_write(BASE+4096,b'restored')
        self.assertEqual(c.string_at(pointer+4096,8),b'restored')

    def test_restore_rejects_cross_boundary_and_missing_image_before_unmapping(self):
        self.uc.mem_write(BASE,b'original')
        invalid=[[(BASE-4096,BASE+4095,u.UC_PROT_ALL)],
                 [(BASE,BASE+4095,u.UC_PROT_ALL)]]
        emu=self.emulator_shell()
        for regions in invalid:
            with work_directory(prefix='vmp-host-image-') as directory:
                with self.assertRaises((ValueError,Unsupported)):
                    emu.restore(self.checkpoint(directory,regions))
            self.assertEqual(bytes(self.uc.mem_read(BASE,8)),b'original')
            self.assertEqual(emu.written,bytes(SIZE))

    def test_ranges_and_engine_mismatch_are_rejected(self):
        self.assertEqual(self.image.offset(BASE+4096,4096),4096)
        self.assertIsNone(self.image.offset(OUTSIDE,4096))
        for base,size in [(BASE-4096,8192),(BASE+4096,8192),(-1,4096),(BASE,0),(2**64-1,2)]:
            with self.assertRaises(ValueError): self.image.offset(base,size)
        for base,size in [(BASE+1,4096),(BASE,4095),(BASE,0),(2**64-4096,8192)]:
            with self.assertRaises(ValueError): HostImage(self.uc,base,size)
        with self.assertRaises(ValueError): self.image.map_region(OUTSIDE,4096)
        other=u.Uc(u.UC_ARCH_X86,u.UC_MODE_64)
        with self.assertRaises(ValueError): BlockBudget(other,100,image=self.image)

if __name__=='__main__': unittest.main()
