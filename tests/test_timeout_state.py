"""A Unicorn timeout must never produce resumable execution state."""
from collections import Counter, deque
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'standalone'))
import emulate
from work_files import work_directory


class FakeUnicorn:
    def __init__(self,timeout=True,raises=False):
        self.timeout=timeout
        self.raises=raises
        self.starts=0

    def emu_start(self,*args,**kwargs):
        self.starts+=1
        if self.raises:
            raise emulate.u.UcError(emulate.u.UC_ERR_EXCEPTION)

    def query(self,query):
        assert query==emulate.u.UC_QUERY_TIMEOUT
        return self.timeout

    def emu_stop(self): pass
    def mem_read(self,address,size): return bytes(size)


class FakeBudget:
    def __init__(self,*args): self.closed=False
    def begin(self,*args): pass
    def get(self,name): return 1000000 if name=='total' else 0
    def stats(self): return {'total':1000000}
    def close(self): self.closed=True


def machine(timeout=True,raises=False):
    # Isolate scheduling from PE setup, native libraries and resource scanning.
    emu=emulate.Emulator.__new__(emulate.Emulator)
    emu.uc=FakeUnicorn(timeout,raises)
    emu.reason=None
    emu.nonresumable_reason=None
    emu.ready=False
    emu.steps=0
    emu.scanner=None
    emu.native_coverage=None
    emu.calls=Counter()
    emu.events=[]
    emu.blocks=deque()
    emu.metrics={'emulation_seconds':0.0,'scan_seconds':0.0,'snapshot_seconds':0.0,'scans':0}
    emu.reg=lambda name: 0x100000
    emu.md=SimpleNamespace(disasm=lambda *args: [])
    emu.dump=lambda path: Path(path).write_bytes(b'diagnostic guest memory')
    return emu


class TimeoutStateTests(unittest.TestCase):
    def test_timeout_is_terminal_even_when_emu_start_raises(self):
        for scheduler in ['stock','block']:
            for raises in [False,True]:
                with self.subTest(scheduler=scheduler,raises=raises), work_directory(root=ROOT/'build') as tmp:
                    emu=machine(raises=raises)
                    budget=FakeBudget()
                    with patch.object(emulate,'BlockBudget',return_value=budget), redirect_stdout(io.StringIO()):
                        result=emu.run(1000000,1,Path(tmp)/'memory.exe',scheduler)
                    self.assertEqual(emu.uc.starts,1)
                    self.assertFalse(result['resumable'])
                    self.assertIn('Unicorn execution timeout',result['nonresumable_reason'])
                    self.assertFalse(emu.ready)
                    if raises:
                        self.assertIn(str(emulate.u.UcError(emulate.u.UC_ERR_EXCEPTION)),result['stop'])
                    if scheduler=='block': self.assertTrue(budget.closed)
                    checkpoint=Path(tmp)/'unsafe.checkpoint.zip'
                    with self.assertRaisesRegex(emulate.Unsupported,'Checkpoint refused'):
                        emu.checkpoint(checkpoint)
                    self.assertFalse(checkpoint.exists())
                    # Clearing a stop reason must not bypass the terminal flag.
                    emu.reason=None
                    with self.assertRaisesRegex(emulate.Unsupported,'Cannot resume emulation'):
                        emu.run(1000000,1,Path(tmp)/'again.exe',scheduler)
                    self.assertEqual(emu.uc.starts,1)

    def test_synchronous_budget_stop_remains_resumable(self):
        emu=machine(timeout=False)
        with work_directory(root=ROOT/'build') as tmp, redirect_stdout(io.StringIO()):
            result=emu.run(1000000,1,Path(tmp)/'memory.exe')
        self.assertTrue(result['resumable'])
        self.assertIsNone(result['nonresumable_reason'])

    def test_cli_skips_checkpoint_but_publishes_diagnostics(self):
        for raises in [False,True]:
            with self.subTest(raises=raises), work_directory(root=ROOT/'build') as tmp:
                folder=Path(tmp)
                source=folder/'sample.exe'
                source.write_bytes(b'fixture input')
                snapshot=folder/'memory.exe'
                emu=machine(raises=raises)
                stderr=io.StringIO()
                argv=['emulate.py',str(source),'--snapshot',str(snapshot),'--checkpoint','--scheduler','stock']
                with patch.object(sys,'argv',argv), patch.object(emulate,'Emulator',return_value=emu), redirect_stderr(stderr), redirect_stdout(io.StringIO()):
                    status=emulate.main()
                self.assertEqual(status,1)
                self.assertEqual(emu.uc.starts,1)
                self.assertEqual(snapshot.read_bytes(),b'diagnostic guest memory')
                report=json.loads(snapshot.with_suffix('.json').read_text(encoding='utf-8'))
                self.assertFalse(report['resumable'])
                self.assertIn('Unicorn execution timeout',report['checkpoint_skipped'])
                self.assertTrue(report['input_unchanged'])
                self.assertFalse(snapshot.with_suffix('.checkpoint.zip').exists())
                self.assertIn('Checkpoint skipped:',stderr.getvalue())


if __name__=='__main__': unittest.main()
