"""Coverage adapter lifetime, checkpoint bitmap, and native hook cleanup checks."""
import ctypes as c
import gc
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock
import weakref

import unicorn as u

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'standalone'))
from native_support import Coverage, uclib

BASE=0x400000
CODE=0x100000

class Bitmap(bytearray):
    pass

class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.uc=u.Uc(u.UC_ARCH_X86,u.UC_MODE_64)
        self.uc.mem_map(BASE,4096)
        self.uc.mem_map(CODE,4096)
        self.code=b''.join(b'\x48\xbf'+struct.pack('<Q',BASE+offset)+b'\xc7\x07\0\0\0\0'
                           for offset in (0x10,0x20,0x30))
        self.uc.mem_write(CODE,self.code)
        self.bitmap=Bitmap(4096)
        self.coverage=Coverage(self.uc,BASE,self.bitmap)
        self.addCleanup(self.coverage.close)

    def run_guest(self):
        self.uc.emu_start(CODE,CODE+len(self.code),count=100)

    def test_disjoint_hooks_and_in_place_checkpoint_restore(self):
        self.coverage.attach(BASE+0x10,BASE+0x1f)
        self.coverage.attach(BASE+0x30,BASE+0x3f)
        self.bitmap[:8]=b'\1'*8
        # Host API writes are deliberately not guest initialization evidence.
        self.uc.mem_write(BASE+0x10,b'host')
        self.assertEqual(self.coverage.stats()['writes'],0)
        pointer=c.addressof(self.coverage.view)
        self.run_guest()
        expected=bytearray(4096)
        expected[:8]=b'\1'*8
        expected[0x10:0x14]=expected[0x30:0x34]=b'\1'*4
        self.assertEqual(self.bitmap,expected)
        self.assertEqual(self.coverage.stats(),dict(callbacks=2,writes=2,bytes=8,generation=2,rejected=0))
        self.bitmap[:]=b'\0'*4096
        self.assertEqual(c.addressof(self.coverage.view),pointer)
        self.run_guest()
        expected[:8]=b'\0'*8
        self.assertEqual(self.bitmap,expected)
        self.assertEqual(self.coverage.stats()['writes'],4)

    def test_view_pins_bitmap_and_close_removes_callbacks(self):
        self.coverage.attach(BASE,BASE+4095)
        bitmap_ref=weakref.ref(self.bitmap)
        del self.bitmap
        gc.collect()
        self.assertIsNotNone(bitmap_ref())
        with self.assertRaises(BufferError): bitmap_ref().append(0)
        self.run_guest()
        self.assertEqual(self.coverage.stats()['writes'],3)
        self.coverage.close()
        self.coverage.close()
        self.run_guest()
        self.assertEqual(self.coverage.stats()['writes'],3)
        self.assertFalse(self.coverage.hooks)
        with self.assertRaises(RuntimeError): self.coverage.attach(BASE,BASE+1)

    def test_failed_attach_removes_previous_hooks(self):
        self.coverage.attach(BASE,BASE+4095)
        with mock.patch.object(uclib,'uc_hook_add',return_value=u.UC_ERR_ARG):
            with self.assertRaises(u.UcError): self.coverage.attach(BASE,BASE+15)
        self.assertTrue(self.coverage.closed)
        self.assertFalse(self.coverage.hooks)
        self.run_guest()
        self.assertEqual(self.coverage.stats()['writes'],0)

    def test_failed_cleanup_retains_only_live_handles_for_retry(self):
        self.coverage.attach(BASE+0x10,BASE+0x1f)
        self.coverage.attach(BASE+0x30,BASE+0x3f)
        retained=self.coverage.hooks[-1]
        delete=uclib.uc_hook_del
        def fail_last(uc,handle):
            return u.UC_ERR_ARG if handle==retained else delete(uc,handle)
        with mock.patch.object(uclib,'uc_hook_del',side_effect=fail_last):
            with self.assertRaises(u.UcError): self.coverage.close()
        self.assertEqual(self.coverage.hooks,[retained])
        self.assertFalse(self.coverage.closed)
        self.run_guest()
        self.assertEqual(self.coverage.stats()['writes'],1)
        self.coverage.close()
        self.assertTrue(self.coverage.closed)
        self.run_guest()
        self.assertEqual(self.coverage.stats()['writes'],1)

    def test_invalid_ranges_never_become_global_hooks(self):
        for begin,end in [(BASE+1,BASE),(BASE-1,BASE),(BASE,BASE+4096)]:
            with self.assertRaises(ValueError): self.coverage.attach(begin,end)
        for base,bitmap in [(0,bytearray()),(-1,bytearray(1)),(2**64-1,bytearray(2))]:
            with self.assertRaises(ValueError): Coverage(self.uc,base,bitmap)
        self.assertFalse(self.coverage.hooks)

if __name__=='__main__': unittest.main()
