"""Regression tests for the API semantics exercised by the packed fixture."""
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'standalone'))
from emulate import Emulator, x
from verify_samples import SAMPLES

def main():
    path=SAMPLES/'originals/x64/ResourcePaths-x64.vmp.exe'
    e=Emulator(path)
    scratch=e.alloc(0x1000)
    sp=e.stack+0x180000
    def call(name,args):
        e.reason=None
        e.uc.reg_write(x.UC_X86_REG_RSP,sp)
        e.q(sp,e.base)
        for register,value in zip(['rcx','rdx','r8','r9'],list(args)+[0]*4):
            e.uc.reg_write(getattr(x,'UC_X86_REG_'+register.upper()),value)
        for i in range(4,10): e.q(sp+0x28+(i-4)*8,args[i] if i<len(args) else 0)
        address=next(a for a,n in e.apis.items() if n==name)
        e.api(e.uc,address,1,None)
        assert not e.reason,e.reason
        return e.reg('rax')
    e.q(scratch,0xfeed)
    assert call('NtQueryInformationProcess',[-1,30,scratch,8,scratch])==0xc0000353
    assert e.readq(scratch)==8,'ReturnLength must be written last; failed query must retain buffer'
    assert call('NtQueryInformationProcess',[-1,30,scratch+1,8,0])==0x80000002
    assert call('NtQueryInformationProcess',[-1,30,scratch,8,1])==0xc0000005
    assert e.readq(scratch)==8
    assert call('NtQueryInformationProcess',[-1,7,scratch,8,0])==0
    assert e.readq(scratch)==0
    assert call('NtSetInformationThread',[-2,17,0,0])==0
    assert call('NtQueryInformationThread',[-2,17,scratch,1,0])==0
    assert bytes(e.uc.mem_read(scratch,1))==b'\1'
    assert call('NtCreateDebugObject',[scratch,8,0,0])==0
    handle=e.readq(scratch)
    assert call('NtQueryObject',[handle,2,0,0,scratch+0x100])==0xc0000004
    assert struct.unpack('<I',e.uc.mem_read(scratch+0x100,4))[0]==0x80
    assert call('NtQueryObject',[handle,2,scratch+0x200,0x80,scratch+0x208])==0
    assert struct.unpack('<I',e.uc.mem_read(scratch+0x208,4))[0]==0x80
    assert call('NtClose',[handle])==0
    assert call('NtClose',[handle])==0xc0000008
    filehandle=e.handle('input-file')
    assert call('NtCreateSection',[scratch,4,0,0,2,0x8000000,filehandle])==0
    section=e.readq(scratch)
    assert e.handles[section]=='input-raw-section'
    e.q(scratch+0x100,0); e.q(scratch+0x108,0)
    assert call('NtMapViewOfSection',[section,-1,scratch+0x100,0,0,0,scratch+0x108,1,0,2])==0
    address=e.readq(scratch+0x100)
    assert bytes(e.uc.mem_read(address,0x1000))==path.read_bytes()[:0x1000]
    assert len(e.written)==e.size
    print('PASS: overlapping outputs, alignment, invalid pointers, thread state, object lifetime and raw file mappings')
    dll_path=path.with_name('pawdResourceFixture-x64.dll')
    if dll_path.exists():
        dll=Emulator(dll_path)
        assert dll.reg('rcx')==dll.base and dll.reg('rdx')==1 and dll.reg('r8')==0
        for address in dll.modules.values():
            assert not dll.base<=address<dll.base+dll.size
        assert dll.modules['ntdll.dll']!=dll.base
        print('PASS: DLL_PROCESS_ATTACH arguments and DLL/system-module address collision')

if __name__=='__main__': main()
