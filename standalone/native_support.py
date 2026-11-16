"""Checked ctypes adapters for the optional local accelerators."""
import ctypes as c
import json
from pathlib import Path
import sys
import capstone
import unicorn as u
from unicorn.unicorn_py3.unicorn import uclib

def library_path(name):
    return (Path(sys._MEIPASS) if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[1]/'dist')/name

class HostImage:
    """Fixed backing for the main image. Mutate guest bytes through uc.mem_write."""
    def __init__(self,uc,base,size):
        if not 0 <= base < 2**64 or not 0 < size <= min(2**64-base,sys.maxsize-4095):
            raise ValueError('Invalid host image range')
        if base%4096 or size%4096: raise ValueError('Host image must be page aligned')
        self.uc=uc
        self.base=base
        self.size=size
        self._buffer=(c.c_uint8*(size+4095))()
        self._pointer=(c.addressof(self._buffer)+4095)&~4095
        # Unicorn does not retain the Python allocation passed to mem_map_ptr.
        # Pin the raw buffer on the engine too, without an engine reference cycle.
        if not hasattr(uc,'_vmp_image_backings'): uc._vmp_image_backings=[]
        uc._vmp_image_backings.append(self._buffer)
    @property
    def pointer(self): return self._pointer
    def offset(self,begin,size):
        if not 0 <= begin < 2**64 or not 0 < size <= 2**64-begin:
            raise ValueError('Invalid guest mapping range')
        end=begin+size
        if self.base <= begin and end <= self.base+self.size: return begin-self.base
        if end <= self.base or begin >= self.base+self.size: return None
        raise ValueError('Guest mapping crosses the host image boundary')
    def map_region(self,begin,size,perms=u.UC_PROT_ALL):
        offset=self.offset(begin,size)
        if offset is None: raise ValueError('Mapping is outside the host image')
        self.uc.mem_map_ptr(begin,size,perms,self.pointer+offset)

class Coverage:
    """Pin the bitmap until close removes every native hook; never resize it."""
    def __init__(self,uc,base,written):
        if not written or not 0 <= base <= 0xffffffffffffffff or len(written)-1 > 0xffffffffffffffff-base:
            raise ValueError('Invalid native coverage image range')
        self.uc=uc
        self.base=base
        self.size=len(written)
        self.hooks=[]
        self.closed=False
        self.lib=c.CDLL(str(library_path('vmp-native-tracker.dll')))
        self.lib.vmp_tracker_abi_version.restype=c.c_uint
        self.lib.vmp_tracker_state_size.restype=c.c_size_t
        self.lib.vmp_tracker_callback.restype=c.c_void_p
        self.lib.vmp_tracker_init.argtypes=[c.c_void_p,c.c_size_t,c.c_uint64,c.c_uint64,c.c_void_p,c.c_size_t]
        self.lib.vmp_tracker_init.restype=c.c_int
        self.lib.vmp_tracker_stats.argtypes=[c.c_void_p,c.c_void_p,c.c_size_t]
        self.lib.vmp_tracker_stats.restype=c.c_int
        if self.lib.vmp_tracker_abi_version()!=1: raise RuntimeError('Unsupported coverage ABI')
        self.view=(c.c_uint8*len(written)).from_buffer(written)
        self.storage=c.create_string_buffer(self.lib.vmp_tracker_state_size())
        if not self.lib.vmp_tracker_init(self.storage,len(self.storage),base,len(written),self.view,len(written)):
            raise RuntimeError('Native coverage initialization failed')
    def attach(self,begin,end):
        if self.closed: raise RuntimeError('Native coverage is closed')
        if not self.base <= begin <= end < self.base+self.size:
            raise ValueError('Native coverage hook is outside the image')
        handle=c.c_size_t()
        error=uclib.uc_hook_add(self.uc._uch,c.byref(handle),u.UC_HOOK_MEM_WRITE,
            self.lib.vmp_tracker_callback(),c.cast(self.storage,c.c_void_p),c.c_uint64(begin),c.c_uint64(end))
        if error:
            failure=u.UcError(error)
            try: self.close()
            except Exception as cleanup_error:
                failure.add_note('Native hook cleanup failed: '+str(cleanup_error))
            raise failure
        self.hooks.append(handle.value)
    def close(self):
        # Keep failed handles and their backing objects alive so cleanup can be
        # retried. The caller must keep this adapter alive while hooks remain.
        remaining=[]; errors=[]
        for handle in self.hooks:
            error=uclib.uc_hook_del(self.uc._uch,handle)
            if error:
                remaining.append(handle); errors.append(error)
        self.hooks=remaining
        self.closed=not remaining
        if errors: raise u.UcError(errors[0])
    def stats(self):
        values=(c.c_uint64*5)()
        if not self.lib.vmp_tracker_stats(self.storage,values,5): raise RuntimeError('Native coverage stats failed')
        return dict(zip(['callbacks','writes','bytes','generation','rejected'],values))

class Scanner:
    def __init__(self):
        self.last_issue=None
        self.lib=c.CDLL(str(library_path('resource_scanner.dll')))
        self.lib.resource_scanner_scan.argtypes=[c.c_void_p,c.c_size_t,c.c_int,c.c_uint32,c.c_uint32,c.POINTER(c.c_void_p),c.POINTER(c.c_size_t)]
        self.lib.resource_scanner_scan.restype=c.c_int
        self.lib.resource_scanner_free.argtypes=[c.c_void_p]
        self.lib.resource_scanner_free.restype=None
        if self.lib.resource_scanner_abi()!=1: raise RuntimeError('Unsupported scanner ABI')
    def scan(self,image,hint=None):
        view=(c.c_uint8*len(image)).from_buffer(image)
        out=c.c_void_p(); size=c.c_size_t()
        try:
            status=self.lib.resource_scanner_scan(view,len(image),int(hint is not None),*(hint or (0,0)),c.byref(out),c.byref(size))
            result=json.loads(c.string_at(out,size.value).decode('utf-8')) if out else {}
            self.last_issue=result if status==2 else None
            # Unpacking can temporarily leave headers incomplete. Match the file
            # scanner's retry behavior, retaining the diagnostic for the report.
            if status==2: return []
            if status not in (0,1):
                label={3:'allocation failure',4:'internal error',5:'time limit'}.get(status,'unknown status')
                raise RuntimeError(f'Native scan failed ({status}: {label}): {result}')
            return result.get('candidates',[])
        finally:
            if out: self.lib.resource_scanner_free(out)

class BlockBudget:
    """Synchronous block boundaries; asynchronous timeout is terminal to callers."""
    def __init__(self,uc,total,image=None):
        if image is not None and image.uc is not uc:
            raise ValueError('Block budget image belongs to another Unicorn engine')
        self.uc=uc
        self.image=image
        self.lib=c.CDLL(str(library_path('block_budget.dll')))
        self.lib.bb_create.argtypes=[c.c_wchar_p,c.c_void_p,c.c_void_p,c.c_uint64]
        self.lib.bb_create.restype=c.c_void_p
        self.lib.bb_destroy.argtypes=[c.c_void_p]
        self.lib.bb_destroy.restype=None
        self.lib.bb_begin.argtypes=[c.c_void_p,c.c_uint64,c.c_uint32]
        self.lib.bb_begin.restype=c.c_int
        for name in ['reason','total','slice','blocks','decodes','hits']:
            method=getattr(self.lib,'bb_'+name)
            method.argtypes=[c.c_void_p]
            method.restype=c.c_uint32 if name=='reason' else c.c_uint64
        self.state=self.lib.bb_create(str(Path(capstone.__file__).parent/'lib/capstone.dll'),
            c.cast(uclib.uc_mem_read,c.c_void_p),c.cast(uclib.uc_emu_stop,c.c_void_p),total)
        if not self.state: raise RuntimeError('Native block scheduler initialization failed')
        if image is not None:
            try:
                self.lib.bb_set_image.argtypes=[c.c_void_p,c.c_uint64,c.c_uint64,c.c_void_p]
                self.lib.bb_set_image.restype=c.c_int
                if not self.lib.bb_set_image(self.state,image.base,image.size,image.pointer):
                    raise RuntimeError('Native block scheduler image binding failed')
            except Exception:
                self.lib.bb_destroy(self.state); self.state=None
                raise
        self.hook=c.c_size_t()
        error=uclib.uc_hook_add(uc._uch,c.byref(self.hook),u.UC_HOOK_BLOCK,
            c.cast(self.lib.bb_callback,c.c_void_p),self.state,c.c_uint64(1),c.c_uint64(0))
        if error:
            self.lib.bb_destroy(self.state); self.state=None
            raise u.UcError(error)
    def begin(self,limit,milliseconds):
        if not self.lib.bb_begin(self.state,limit,milliseconds):
            raise RuntimeError('Invalid native block budget')
    def get(self,name): return getattr(self.lib,'bb_'+name)(self.state)
    def stats(self): return {name:self.get(name) for name in ['total','blocks','decodes','hits']}
    def close(self):
        if self.state:
            error=uclib.uc_hook_del(self.uc._uch,self.hook)
            if error: raise u.UcError(error)
            self.lib.bb_destroy(self.state); self.state=None
