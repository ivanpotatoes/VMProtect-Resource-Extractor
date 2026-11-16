"""Experimental native block scheduling: parity, bounds, SMC and synchronous exits."""
import ctypes as C
from pathlib import Path
import struct
import time
import capstone
import unicorn as U
from unicorn import x86_const as X
from unicorn.unicorn_py3.unicorn import uclib

ROOT=Path(__file__).resolve().parents[1]
BASE=0x100000

class BlockBudget:
    def __init__(self,uc,total,read=None):
        self.uc=uc
        self.dll=C.CDLL(str(ROOT/'dist/block_budget.dll'))
        self.dll.bb_create.argtypes=[C.c_wchar_p,C.c_void_p,C.c_void_p,C.c_uint64]
        self.dll.bb_create.restype=C.c_void_p
        self.dll.bb_destroy.argtypes=[C.c_void_p]
        self.dll.bb_begin.argtypes=[C.c_void_p,C.c_uint64,C.c_uint32]
        self.dll.bb_begin.restype=C.c_int
        self.dll.bb_set_image.argtypes=[C.c_void_p,C.c_uint64,C.c_uint64,C.c_void_p]
        self.dll.bb_set_image.restype=C.c_int
        for name in ['bb_reason','bb_total','bb_slice','bb_blocks','bb_decodes','bb_hits']:
            method=getattr(self.dll,name);method.argtypes=[C.c_void_p]
            method.restype=C.c_uint32 if name=='bb_reason' else C.c_uint64
        self.read=read or uclib.uc_mem_read
        self.state=self.dll.bb_create(str(Path(capstone.__file__).parent/'lib/capstone.dll'),
                                     C.cast(self.read,C.c_void_p),C.cast(uclib.uc_emu_stop,C.c_void_p),total)
        assert self.state
        self.hook=C.c_uint64()
        error=uclib.uc_hook_add(uc._uch,C.byref(self.hook),U.UC_HOOK_BLOCK,C.cast(self.dll.bb_callback,C.c_void_p),self.state,1,0)
        assert error==0,error
    def begin(self,limit,ms=10000):
        assert self.dll.bb_begin(self.state,limit,ms)
    def get(self,name): return getattr(self.dll,'bb_'+name)(self.state)
    def close(self):
        uclib.uc_hook_del(self.uc._uch,self.hook)
        self.dll.bb_destroy(self.state)
        self.state=None

def machine(code,backing=None):
    uc=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    if backing is None: uc.mem_map(BASE,0x2000)
    else: uc.mem_map_ptr(BASE,0x2000,U.UC_PROT_ALL,C.addressof(backing))
    uc.mem_write(BASE,code)
    uc.reg_write(X.UC_X86_REG_RSP,BASE+0x1f00)
    uc.reg_write(X.UC_X86_REG_EFLAGS,0x202)
    return uc

def registers(uc):
    return tuple(uc.reg_read(r) for r in [X.UC_X86_REG_RAX,X.UC_X86_REG_RCX,X.UC_X86_REG_RSP,X.UC_X86_REG_EFLAGS,X.UC_X86_REG_RIP])

def run_bounded(uc,budget,end,slice_limit):
    pc=uc.reg_read(X.UC_X86_REG_RIP) or BASE
    while pc!=end:
        budget.begin(slice_limit)
        uc.emu_start(pc,end,timeout=0,count=0)
        assert not uc.query(U.UC_QUERY_TIMEOUT),'Emergency timeout: do not resume this state'
        assert budget.get('reason') in [0,1],budget.get('reason')
        pc=uc.reg_read(X.UC_X86_REG_RIP)

def main():
    count=1000
    loop=b'\xb9'+struct.pack('<I',count)+b'\x31\xc0\x83\xc0\x03\xff\xc9\x75\xf9\x90'
    stock=machine(loop); stock.emu_start(BASE,BASE+14,count=1000000)
    for chunk in [1,7,4096]:
        uc=machine(loop); b=BlockBudget(uc,1000000)
        run_bounded(uc,b,BASE+14,chunk)
        assert registers(uc)==registers(stock),(chunk,registers(uc),registers(stock))
        assert b.get('total')==count*3+2,b.get('total')
        b.close()
    # Stop before a block that would exceed the total, without executing it.
    uc=machine(b'\x90\x90\xeb\xfc'); b=BlockBudget(uc,4); b.begin(100)
    uc.emu_start(BASE,BASE+0x100,timeout=1000000)
    assert b.get('reason')==2 and b.get('total')==3
    assert uc.reg_read(X.UC_X86_REG_RIP)==BASE
    b.close()
    # Unicorn presents each REP iteration as a block; preserve its count/semantics.
    rep=b'\x48\xc7\xc1'+struct.pack('<I',500)+b'\x48\xc7\xc7'+struct.pack('<I',BASE+0x1000)+b'\xb0\x55\xf3\xaa\x90'
    stock=machine(rep); stock.emu_start(BASE,BASE+len(rep)-1,count=10000)
    uc=machine(rep); b=BlockBudget(uc,10000)
    run_bounded(uc,b,BASE+len(rep)-1,20)
    assert registers(uc)==registers(stock)
    assert bytes(uc.mem_read(BASE+0x1000,500))==b'\x55'*500
    assert b.get('total')==504
    b.close()
    # Deadline is checked synchronously, never changing a guest register.
    uc=machine(b'\xeb\xfe'); b=BlockBudget(uc,10**12); b.begin(10**12,10)
    start=time.perf_counter(); uc.emu_start(BASE,BASE+0x100,timeout=1000000)
    assert b.get('reason')==3 and time.perf_counter()-start<1
    b.close()
    for direct in [False,True]:
        # Same address and size, changed bytes/count: never reuse a stale cache.
        backing=C.create_string_buffer(0x2000) if direct else None
        uc=machine(b'\xb8\x01\0\0\0\xeb\0',backing); b=BlockBudget(uc,100)
        if direct: assert b.dll.bb_set_image(b.state,BASE,len(backing),C.addressof(backing))
        run_bounded(uc,b,BASE+7,100); assert b.get('total')==2
        uc.mem_write(BASE,b'\x90'*5+b'\xeb\0'); uc.reg_write(X.UC_X86_REG_RIP,BASE)
        run_bounded(uc,b,BASE+7,100)
        assert b.get('total')==8 and b.get('decodes')==2
        b.close()
        # Actual guest SMC, compare with stock count using both read paths.
        smc=b'\xc6\x05\x02\0\0\0\x04\x83\xc0\x01\x90'
        stock=machine(smc); stock.emu_start(BASE,BASE+10,count=100)
        backing=C.create_string_buffer(0x2000) if direct else None
        uc=machine(smc,backing); b=BlockBudget(uc,100)
        if direct: assert b.dll.bb_set_image(b.state,BASE,len(backing),C.addressof(backing))
        run_bounded(uc,b,BASE+10,100)
        assert registers(uc)==registers(stock) and uc.reg_read(X.UC_X86_REG_RAX)==4
        if direct: assert backing[9]==b'\x04'
        b.close()
    # Direct reads require whole-block containment. Count fallback reads instead
    # of inferring the selected path from equivalent output bytes.
    read_type=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
    for view_offset,view_size,clear,expected_reads in [(0x100,2,False,0),(0x101,1,False,1),
            (0x100,1,False,1),(0x110,2,False,1),(0x100,2,True,1)]:
        backing=C.create_string_buffer(0x2000)
        uc=machine(b'',backing); uc.mem_write(BASE+0x100,b'\x90\x90')
        reads=[]
        @read_type
        def read(engine,address,destination,size):
            reads.append((address,size))
            return uclib.uc_mem_read(engine,address,C.cast(destination,C.POINTER(C.c_char)),size)
        b=BlockBudget(uc,100,read)
        assert b.dll.bb_set_image(b.state,BASE+view_offset,view_size,C.addressof(backing)+view_offset)
        # Invalid updates must reject and preserve the existing borrowed view.
        for base,size,pointer in [(BASE,0,C.addressof(backing)),(BASE,2,None),
                (2**64-1,2,C.addressof(backing)),(BASE,2,2**64-1)]:
            assert not b.dll.bb_set_image(b.state,base,size,pointer)
        assert not b.dll.bb_set_image(None,BASE,2,C.addressof(backing))
        if clear: assert b.dll.bb_set_image(b.state,0,0,None)
        uc.reg_write(X.UC_X86_REG_RIP,BASE+0x100)
        run_bounded(uc,b,BASE+0x102,100)
        assert len(reads)==expected_reads,(view_offset,view_size,clear,reads)
        assert b.get('total')==2
        b.close()
    # External API hook can stop mid-block. Charge remains conservative.
    uc=machine(b'\x90\x90\x90\xeb\x00'); b=BlockBudget(uc,100)
    def stop_api(uc,address,size,data): uc.emu_stop()
    hook=uc.hook_add(U.UC_HOOK_CODE,stop_api,begin=BASE+1,end=BASE+1)
    b.begin(100); uc.emu_start(BASE,BASE+5,count=0)
    assert uc.reg_read(X.UC_X86_REG_RIP)==BASE+1 and b.get('total')>=1
    uc.hook_del(hook); run_bounded(uc,b,BASE+5,100);b.close()
    # Invalid dependencies fail closed before attaching a callback.
    assert not b.dll.bb_create('capstone.dll',C.cast(uclib.uc_mem_read,C.c_void_p),C.cast(uclib.uc_emu_stop,C.c_void_p),100)
    assert not b.dll.bb_create('C:/Windows/System32/kernel32.dll',C.cast(uclib.uc_mem_read,C.c_void_p),C.cast(uclib.uc_emu_stop,C.c_void_p),100)
    print('PASS: stock register/flag parity, REP, bounds, deadlines, SMC, direct image boundaries, API stops and dependencies')

if __name__=='__main__': main()
