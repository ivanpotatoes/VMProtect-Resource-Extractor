"""Offline Unicorn execution harness. Guest code never calls host Windows APIs."""
import argparse
from collections import Counter, deque
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import zipfile
import hashlib
import sys
import os
import pefile
import unicorn as u
from unicorn import x86_const as x
import capstone
from native_support import Coverage, Scanner, BlockBudget, HostImage, library_path
from work_files import work_directory

def align(n): return (n + 4095) & ~4095
class Unsupported(RuntimeError): pass

def atomic_snapshot(path,image):
    path=Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent,prefix=path.name+'.',suffix='.writing',delete=False) as f:
        temporary=Path(f.name)
        f.write(image)
    try:
        for attempt in range(20):
            try:
                os.replace(temporary,path)
                return
            except OSError:
                if attempt==19: raise
                time.sleep(0.1)
    finally:
        temporary.unlink(missing_ok=True)

def scanner_path():
    if getattr(sys,'frozen',False): return Path(sys._MEIPASS)/'vmp-resource-extractor.exe'
    return Path(__file__).resolve().parents[1]/'dist/vmp-resource-extractor.exe'

def scan_run(*args):
    return subprocess.run([str(scanner_path()),*map(str,args)],capture_output=True,text=True,
                          encoding='utf-8',errors='replace',timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)

class Emulator:
    def __init__(self, path, reference=False):
        print('Loading PE image...',flush=True)
        self.path = Path(path)
        if not 64<=self.path.stat().st_size<=1024*1024*1024: raise Unsupported('Input size must be 64 bytes to 1 GiB')
        self.pe = pefile.PE(str(path))
        if self.pe.FILE_HEADER.Machine != 0x8664: raise Unsupported('Emulation currently requires x64')
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size = align(self.pe.OPTIONAL_HEADER.SizeOfImage)
        if not 0<self.size<=256*1024*1024: raise Unsupported('Image size must be 1 byte to 256 MiB')
        if self.pe.OPTIONAL_HEADER.SizeOfHeaders>self.size: raise Unsupported('Headers extend beyond image')
        mapped=self.pe.get_memory_mapped_image()
        if len(mapped)>self.size: raise Unsupported('Mapped data extends beyond image')
        self.uc = u.Uc(u.UC_ARCH_X86, u.UC_MODE_64)
        self.host_image=None if reference else HostImage(self.uc,self.base,self.size)
        if self.host_image: self.host_image.map_region(self.base,self.size)
        else: self.uc.mem_map(self.base,self.size)
        self.uc.mem_write(self.base,mapped)
        self.written=bytearray(self.size)
        self.written[:self.pe.OPTIONAL_HEADER.SizeOfHeaders]=b'\1'*self.pe.OPTIONAL_HEADER.SizeOfHeaders
        self.native_coverage=None
        self.scanner=None
        self.scan_hint=None
        self.metrics={'emulation_seconds':0.0,'scan_seconds':0.0,'snapshot_seconds':0.0,'scans':0}
        if not reference and library_path('vmp-native-tracker.dll').exists():
            self.native_coverage=Coverage(self.uc,self.base,self.written)
        if not reference and library_path('resource_scanner.dll').exists():
            self.scanner=Scanner()
        for section in self.pe.sections:
            start=section.VirtualAddress
            if start+max(section.SizeOfRawData,section.Misc_VirtualSize)>self.size:
                raise Unsupported('Section extends beyond image')
            if section.SizeOfRawData:
                self.written[start:start+section.SizeOfRawData]=b'\1'*section.SizeOfRawData
            elif section.Misc_VirtualSize:
                if self.native_coverage: self.native_coverage.attach(self.base+start,self.base+start+section.Misc_VirtualSize-1)
                else: self.uc.hook_add(u.UC_HOOK_MEM_WRITE,self.image_write,begin=self.base+start,end=self.base+start+section.Misc_VirtualSize-1)
        self.stack=0x10000000; self.teb=0x70000000; self.peb=self.teb+0x2000
        self.uc.mem_map(self.stack,0x200000)
        self.uc.mem_map(self.teb,0x20000)
        self.uc.mem_map(0x7ffe0000,0x1000)
        self.uc.mem_write(0x7ffe0260,struct.pack('<I',10))
        self.uc.reg_write(x.UC_X86_REG_GS_BASE,self.teb)
        self.q(self.teb+0x08,self.stack+0x200000); self.q(self.teb+0x10,self.stack)
        self.q(self.teb+0x30,self.teb); self.q(self.teb+0x60,self.peb)
        self.q(self.teb+0x40,1000); self.q(self.teb+0x48,1001)
        self.q(self.peb+0x10,self.base); self.q(self.peb+0x18,self.peb+0x100)
        self.q(self.peb+0x30,self.teb+0x10000)
        self.uc.mem_write(self.teb+0x10070,struct.pack('<II',2,0))
        self.uc.mem_write(self.peb+0x118,struct.pack('<III',10,0,19045))
        self.uc.reg_write(x.UC_X86_REG_RSP,self.stack+0x1fff00-8)
        self.uc.reg_write(x.UC_X86_REG_RIP,self.base+self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        self.uc.reg_write(x.UC_X86_REG_EFLAGS,0x202)
        if self.pe.FILE_HEADER.Characteristics & 0x2000:
            self.uc.reg_write(x.UC_X86_REG_RCX,self.base)
            self.uc.reg_write(x.UC_X86_REG_RDX,1)  # DLL_PROCESS_ATTACH
            self.uc.reg_write(x.UC_X86_REG_R8,0)
        self.modules={}; self.apis={}; self.calls=Counter(); self.blocks=deque(maxlen=16)
        self.heap=0x40000000; self.reason=None; self.steps=0; self.allocations=0
        self.handles={}; self.syscalls={}
        self.events=[]
        self.thread_hidden=False; self.function_tables=[]
        self.next_handle=0x100
        self.last_api_context=None
        self.api_failed=False
        self.nonresumable_reason=None
        self.load_modules()
        print('Guest image and Windows API models ready.',flush=True)
        self.uc.hook_add(u.UC_HOOK_MEM_INVALID,self.bad_memory)
        self.uc.hook_add(u.UC_HOOK_INTR,self.interrupt)
        # Per-block Python tracing makes virtualized startup disproportionately slow.
        # API events and the final instruction are sufficient for normal diagnostics.
        self.uc.hook_add(u.UC_HOOK_INSN,self.syscall,None,1,0,x.UC_X86_INS_SYSCALL)
        self.md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)

    def q(self,a,v): self.uc.mem_write(a,struct.pack('<Q',v & 0xffffffffffffffff))
    def image_write(self,uc,access,address,size,value,data):
        offset=address-self.base
        if 0<=offset and offset+size<=self.size: self.written[offset:offset+size]=b'\1'*size
    def readq(self,a): return struct.unpack('<Q',self.uc.mem_read(a,8))[0]
    def reg(self,n): return self.uc.reg_read(getattr(x,'UC_X86_REG_'+n.upper()))
    def text(self,a,wide=False):
        out=bytearray(); size=2 if wide else 1
        for i in range(4096):
            b=bytes(self.uc.mem_read(a+i*size,size))
            if not any(b): return out.decode('utf-16-le' if wide else 'ascii',errors='replace')
            out.extend(b)
        raise Unsupported('Unterminated guest string')
    def alloc(self,size):
        size=align(max(size,1))
        if self.allocations+size>256*1024*1024: raise Unsupported('Guest allocation budget exceeded')
        a=self.heap; self.heap+=size+0x1000; self.allocations+=size
        self.uc.mem_map(a,size); return a
    def handle(self,value):
        h=self.next_handle; self.next_handle+=4; self.handles[h]=value; return h
    def load_modules(self):
        exports={}; forwards={}
        modules=['ntdll.dll','kernel32.dll','kernelbase.dll']
        imports={entry.dll.decode().lower() for entry in getattr(self.pe,'DIRECTORY_ENTRY_IMPORT',[])}
        if 'user32.dll' in imports: modules.append('user32.dll')
        next_base=0x180000000
        for name in modules:
            pe=pefile.PE(str(Path('C:/Windows/System32')/name))
            size=align(pe.OPTIONAL_HEADER.SizeOfImage)
            base=next_base
            while any(base<=end and begin<base+size for begin,end,_ in self.uc.mem_regions()):
                base+=0x10000000
            next_base=base+0x10000000
            self.uc.mem_map(base,size)
            self.uc.mem_write(base,pe.get_memory_mapped_image())
            self.modules[name]=base
            for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                key=(name,e.name.decode() if e.name else '#'+str(e.ordinal))
                exports[key]=base+e.address
                if e.forwarder: forwards[key]=e.forwarder.decode()
                else: self.apis.setdefault(base+e.address,key[1])
                if name=='ntdll.dll' and key[1].startswith('Nt') and not e.forwarder:
                    stub=pe.get_data(e.address,8)
                    if stub[:4]==b'\x4c\x8b\xd1\xb8': self.syscalls[struct.unpack('<I',stub[4:])[0]]=key[1]
            self.uc.hook_add(u.UC_HOOK_CODE,self.api,begin=base,end=base+pe.OPTIONAL_HEADER.SizeOfImage-1)
            pe.close()
        for key,target in forwards.items():
            module,symbol=target.rsplit('.',1)
            resolved=exports.get((module.lower()+'.dll',symbol))
            if resolved:
                # Forwarded export strings remain intact for guest export walkers.
                exports[key]=resolved
        self.exports=exports
        for imp in getattr(self.pe,'DIRECTORY_ENTRY_IMPORT',[]):
            for entry in imp.imports:
                key=(imp.dll.decode().lower(),entry.name.decode() if entry.name else '#'+str(entry.ordinal))
                if key not in exports: raise Unsupported('Unmodeled import '+str(key))
                self.q(entry.address,exports[key])
        # Minimal loader lists, including the image and mapped system modules.
        entries=[]
        for i,(name,base) in enumerate([(self.path.name,self.base),*self.modules.items()]):
            e=self.peb+0x400+i*0x200; entries.append(e)
            self.q(e+0x30,base)
            text=name.encode('utf-16-le'); ptr=e+0x100
            self.uc.mem_write(ptr,text+b'\0\0')
            for offset in [0x48,0x58]:
                self.uc.mem_write(e+offset,struct.pack('<HHIQ',len(text),len(text)+2,0,ptr))
        for offset,head_offset in [(0,0x10),(0x10,0x20),(0x20,0x30)]:
            head=self.peb+0x100+head_offset
            nodes=[head]+[e+offset for e in entries]
            for i,node in enumerate(nodes): self.q(node,nodes[(i+1)%len(nodes)]); self.q(node+8,nodes[i-1])
    def stop(self,reason): self.reason=reason; self.uc.emu_stop()
    def bad_memory(self,uc,access,address,size,value,data):
        self.stop(f'unmapped memory access={access} address={address:#x} size={size} rip={self.reg("rip"):#x}')
        return False
    def interrupt(self,uc,number,data): self.stop(f'unsupported CPU exception {number} at {self.reg("rip"):#x}')
    def block(self,uc,address,size,data): self.blocks.append(address)
    def ret(self,value):
        if getattr(self,'in_syscall',False):
            self.uc.reg_write(x.UC_X86_REG_RAX,value & 0xffffffffffffffff); return
        sp=self.reg('rsp'); target=self.readq(sp)
        self.uc.reg_write(x.UC_X86_REG_RAX,value & 0xffffffffffffffff)
        self.uc.reg_write(x.UC_X86_REG_RSP,sp+8); self.uc.reg_write(x.UC_X86_REG_RIP,target)
        self.uc.emu_stop()
    def api(self,uc,address,size,data):
        self.last_api_context=self.uc.context_save()
        name=self.syscalls.get(self.reg('rax')) if getattr(self,'in_syscall',False) else self.apis.get(address)
        if not name: self.stop(f'unsupported system module instruction {address:#x}'); return
        self.calls[name]+=1
        a,b,c,d=[self.reg(n) for n in ['r10' if getattr(self,'in_syscall',False) else 'rcx','rdx','r8','r9']]
        self.events.append({'name':name,'args':[hex(v) for v in [a,b,c,d]]})
        try:
            if name in ['GetLastError','RtlGetLastWin32Error']: self.ret(0)
            elif name in ['RtlAllocateHeap','HeapAlloc']: self.ret(self.alloc(c))
            elif name in ['RtlFreeHeap','HeapFree']: self.ret(1)
            elif name=='GetProcessHeap': self.ret(self.readq(self.peb+0x30))
            elif name=='NtOpenSection':
                string=self.readq(c+16); label=self.text(self.readq(string+8),True)
                module=label.rsplit('\\',1)[-1].lower()
                if module not in self.modules: raise Unsupported('Section not modeled: '+label)
                self.q(a,self.handle(module)); self.ret(0)
            elif name=='NtOpenFile':
                string=self.readq(c+16); label=self.text(self.readq(string+8),True)
                if label.lower() in ['\\device\\titanhide','\\??\\titanhide']:
                    self.q(a,0); self.uc.mem_write(d,struct.pack('<QQ',0xc0000034,0)); self.ret(0xc0000034)
                elif label.rsplit('\\',1)[-1].lower()==self.path.name.lower():
                    self.q(a,self.handle('input-file')); self.uc.mem_write(d,struct.pack('<QQ',0,1)); self.ret(0)
                else: raise Unsupported('File not modeled: '+label)
            elif name=='NtCreateSection':
                filehandle=self.readq(self.reg('rsp')+0x38)
                if self.handles.get(filehandle)!='input-file': raise Unsupported('Section backing file not modeled')
                attributes=self.readq(self.reg('rsp')+0x30)&0xffffffff
                self.q(a,self.handle('input-section' if attributes&0x1000000 else 'input-raw-section')); self.ret(0)
            elif name=='NtMapViewOfSection':
                module=self.handles.get(a)
                if not module: raise Unsupported('Invalid section handle')
                if module=='input-raw-section': image=self.path.read_bytes()
                else:
                    pe=pefile.PE(str(self.path if module=='input-section' else Path('C:/Windows/System32')/module))
                    image=pe.get_memory_mapped_image(); pe.close()
                addr=self.alloc(len(image))
                self.uc.mem_write(addr,image); self.q(c,addr)
                sizeptr=self.readq(self.reg('rsp')+0x38)
                if sizeptr: self.q(sizeptr,align(len(image)))
                self.ret(0)
            elif name=='NtUnmapViewOfSection': self.ret(0)
            elif name=='NtClose':
                self.ret(0 if self.handles.pop(a,None) is not None else 0xc0000008)
            elif name=='NtCreateDebugObject':
                self.q(a,self.handle('debug-object')); self.ret(0)
            elif name=='NtReadFile':
                if self.handles.get(a)!='input-file': raise Unsupported('Read handle not modeled')
                sp=self.reg('rsp'); ios=self.readq(sp+0x28); buf=self.readq(sp+0x30)
                size=self.readq(sp+0x38)&0xffffffff; offsetptr=self.readq(sp+0x40)
                offset=self.readq(offsetptr) if offsetptr else 0
                blob=self.path.read_bytes()[offset:offset+size]
                self.uc.mem_write(buf,blob); self.uc.mem_write(ios,struct.pack('<QQ',0,len(blob))); self.ret(0)
            elif name=='NtQueryObject':
                if self.handles.get(a)!='debug-object' or b!=2: raise Unsupported('Object query not modeled')
                length=self.readq(self.reg('rsp')+0x28)
                if d<0x80 or not c:
                    if length: self.uc.mem_write(length,struct.pack('<I',0x80))
                    self.ret(0xc0000004)
                else:
                    value=bytearray(0x80); text='DebugObject'.encode('utf-16-le')
                    struct.pack_into('<HHIQII',value,0,len(text),len(text)+2,0,c+0x68,1,1)
                    value[0x68:0x68+len(text)]=text
                    self.uc.mem_write(c,bytes(value))
                    if length: self.uc.mem_write(length,struct.pack('<I',0x80))
                    self.ret(0)
            elif name=='NtProtectVirtualMemory':
                old=self.readq(self.reg('rsp')+0x28)
                self.uc.mem_write(old,struct.pack('<I',0x40)); self.ret(0)
            elif name=='NtSetInformationProcess':
                if b==40:
                    # ProcessInstrumentationCallback is not supported by this environment.
                    self.ret(0xc0000003)
                else: raise Unsupported(f'NtSetInformationProcess class {b}')
            elif name=='NtQueryInformationProcess':
                length=self.readq(self.reg('rsp')+0x28)
                if c&3: self.ret(0x80000002)
                elif length and length<0x10000: self.ret(0xc0000005)
                elif b in [7,30,31]:
                    needed=4 if b==31 else 8
                    if d!=needed: self.ret(0xc0000004)
                    else:
                        if b==7: self.q(c,0)
                        elif b==31: self.uc.mem_write(c,struct.pack('<I',1))
                        # Failed DebugObject queries leave the output unchanged.
                        # ReturnLength is written last, including overlapping buffers.
                        if length: self.uc.mem_write(length,struct.pack('<I',needed))
                        self.ret(0xc0000353 if b==30 else 0)
                else: raise Unsupported(f'NtQueryInformationProcess class {b}')
            elif name=='NtSetInformationThread':
                if b==17: self.thread_hidden=True; self.ret(0)
                else: raise Unsupported(f'NtSetInformationThread class {b}')
            elif name=='NtQueryInformationThread':
                if b==17 and d==1: self.uc.mem_write(c,bytes([self.thread_hidden])); self.ret(0)
                else: raise Unsupported(f'NtQueryInformationThread class {b}')
            elif name=='NtQuerySystemInformation':
                if a==35 and c>=2: self.uc.mem_write(b,b'\0\1'); self.ret(0)
                elif a==11 and c>=8: self.q(b,0); self.ret(0)
                else: raise Unsupported(f'NtQuerySystemInformation class {a}')
            elif name=='RtlAddFunctionTable': self.function_tables.append((a,b,c)); self.ret(1)
            elif name=='NtRaiseHardError':
                params=[self.readq(d+i*8) for i in range(min(b,8))]
                labels=[]
                for i,value in enumerate(params):
                    if c & (1<<i): labels.append(self.text(self.readq(value+8),True))
                raise Unsupported('Guest hard error: '+str(labels)+' status='+hex(a))
            elif name in ['GetModuleHandleW','GetModuleHandleA']:
                self.ret(self.modules.get(self.text(a,name.endswith('W')).lower(),0) if a else self.base)
            elif name in ['LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW']:
                module=self.text(a,name.endswith('W')).lower()
                if module not in self.modules: raise Unsupported('Module not modeled: '+module)
                self.ret(self.modules[module])
            elif name=='GetProcAddress':
                module=next((k for k,v in self.modules.items() if v==a),None)
                symbol=self.text(b) if b>65535 else '#'+str(b)
                target=self.exports.get((module,symbol))
                if not target: raise Unsupported('Export not modeled: '+str((module,symbol)))
                self.ret(target)
            elif name=='VirtualAlloc':
                if a: raise Unsupported('Fixed-address VirtualAlloc not modeled')
                self.ret(self.alloc(b))
            elif name=='VirtualProtect':
                self.uc.mem_write(d,struct.pack('<I',0x40)); self.ret(1)
            else: raise Unsupported('API not modeled: '+name)
        except (Unsupported,u.UcError) as error:
            self.api_failed=True; self.stop(str(error))
    def syscall(self,uc,data):
        self.in_syscall=True
        try: self.api(uc,self.reg('rip'),2,None)
        finally: self.in_syscall=False
    def image(self):
        image=self.uc.mem_read(self.base,self.size)
        for s in self.pe.sections:
            offset=s.get_file_offset(); size=align(s.Misc_VirtualSize)
            struct.pack_into('<I',image,offset+16,size)
            struct.pack_into('<I',image,offset+20,s.VirtualAddress)
        return image
    def dump(self,path):
        atomic_snapshot(path,self.image())
    def resources_ready(self,records):
        for r in records:
            start=r['data_rva']; size=r['size']
            if start<0 or start>self.size or size>self.size-start: return False
            if self.written.find(b'\0',start,start+size)!=-1: return False
        return True
    def scan_memory(self):
        image=self.image()
        candidates=self.scanner.scan(image,self.scan_hint)
        if len(candidates)!=1: self.scan_hint=None; return False
        table=candidates[0]; self.scan_hint=(table['table_rva'],table['key'])
        if not self.resources_ready(table['resources']): return False
        # A second table can appear as unpacking proceeds. Never let a hint hide it.
        candidates=self.scanner.scan(image)
        if len(candidates)!=1 or not self.resources_ready(candidates[0]['resources']): return False
        self.ready=True
        self.stop('Resource table and payloads available')
        return True
    def checkpoint(self,path):
        if getattr(self,'nonresumable_reason',None):
            raise Unsupported('Checkpoint refused: '+self.nonresumable_reason)
        # JSON register state and guest memory only; no executable pickle data.
        names=['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15','rip','eflags','gs_base','fs_base','mxcsr']+[f'xmm{i}' for i in range(16)]
        ctx=self.last_api_context if self.api_failed else self.uc.context_save()
        regs={name:ctx.reg_read(getattr(x,'UC_X86_REG_'+name.upper())) for name in names}
        state={key:getattr(self,key) for key in ['heap','allocations','next_handle','handles','thread_hidden','function_tables','events']}
        state['registers']=regs; state['regions']=list(self.uc.mem_regions())
        with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1) as z:
            z.writestr('state.json',json.dumps(state))
            z.writestr('written.bin',self.written)
            for begin,end,perm in state['regions']: z.writestr(hex(begin),self.uc.mem_read(begin,end-begin+1))
    def restore(self,path):
        with zipfile.ZipFile(path) as z:
            state=json.loads(z.read('state.json'))
            bitmap=z.read('written.bin')
            if len(bitmap)!=len(self.written): raise Unsupported('Checkpoint coverage size mismatch')
            regions=state.pop('regions')
            image=getattr(self,'host_image',None)
            # Reject a partial overlap before changing the existing mappings.
            # Protection changes can split the image into several valid regions.
            if image:
                image_regions=[]
                for begin,end,perm in regions:
                    if image.offset(begin,end-begin+1) is not None: image_regions.append((begin,end+1))
                cursor=image.base
                for begin,end in sorted(image_regions):
                    if begin!=cursor: raise Unsupported('Checkpoint image mappings overlap or are incomplete')
                    cursor=end
                if cursor!=image.base+image.size: raise Unsupported('Checkpoint image mappings are incomplete')
            self.written[:]=bitmap
            for begin,end,perm in list(self.uc.mem_regions()): self.uc.mem_unmap(begin,end-begin+1)
            for begin,end,perm in regions:
                size=end-begin+1
                if image and image.offset(begin,size) is not None: image.map_region(begin,size,perm)
                else: self.uc.mem_map(begin,size,perm)
                self.uc.mem_write(begin,z.read(hex(begin)))
            for name,value in state.pop('registers').items(): self.uc.reg_write(getattr(x,'UC_X86_REG_'+name.upper()),value)
            state['handles']={int(k):v for k,v in state['handles'].items()}
            for k,v in state.items(): setattr(self,k,v)
    def run(self,limit,seconds,snapshot,scheduler='stock'):
        if getattr(self,'nonresumable_reason',None):
            raise Unsupported('Cannot resume emulation: '+self.nonresumable_reason)
        print('Starting Unicorn emulation...',flush=True)
        start=time.monotonic(); batch=1000000; next_scan=100000000
        budget=BlockBudget(self.uc,limit,image=getattr(self,'host_image',None)) if scheduler=='block' else None
        budget_stats=None
        try:
            while self.steps<limit and not self.reason:
                remaining=seconds-(time.monotonic()-start)
                if remaining<=0: self.stop('Wall-clock budget exceeded'); break
                tick=time.monotonic()
                if budget:
                    budget.begin(batch,max(1,min(0xffffffff,int(remaining*1000))))
                    self.uc.emu_start(self.reg('rip'),0,timeout=max(1,int(remaining*1000000)),count=0)
                    self.steps=budget.get('total')
                    reason=budget.get('reason')
                    if not self.reason and reason>=2:
                        self.stop({2:'Instruction budget exceeded',3:'Wall-clock budget exceeded'}.get(reason,
                            f'Native block scheduler failed (reason {reason})'))
                else:
                    charged=min(batch,limit-self.steps)
                    self.uc.emu_start(self.reg('rip'),0,timeout=max(1,min(5_000_000,int(remaining*1000000))),count=charged)
                    self.steps+=charged
                self.metrics['emulation_seconds']+=time.monotonic()-tick
                # A timeout can interrupt native translation. Never resume that state.
                if self.uc.query(u.UC_QUERY_TIMEOUT):
                    self.stop('Unicorn execution timeout; state will not be resumed')
                    break
                if self.reason: break
                scan_due=self.steps>=next_scan
                if scan_due:
                    next_scan=self.steps+100000000
                    tick=time.monotonic(); self.metrics['scans']+=1
                    if self.scanner:
                        self.scan_memory()
                        scan=None
                    else:
                        self.dump(snapshot)
                        scan=scan_run(snapshot,'--list')
                    if scan is not None and scan.returncode==0:
                        with work_directory(prefix='resource-candidate-') as tmp:
                            out=Path(tmp)/'resources'
                            extract=scan_run(snapshot,'-o',out)
                            if extract.returncode==0:
                                metadata=json.loads((out/'manifest.json').read_text(encoding='utf-8'))
                                ready=all(all(self.written[int(r['data_rva'],16):int(r['data_rva'],16)+r['size']]) for r in metadata['resources'])
                                if ready:
                                    self.ready=True
                                    self.stop('Resource table and payloads available: '+scan.stdout.strip())
                    self.metrics['scan_seconds']+=time.monotonic()-tick
                if scan_due or self.reason:
                    print(f'budget={self.steps} rip={self.reg("rip"):#x} elapsed={time.monotonic()-start:.1f}s',flush=True)
            if not self.reason: self.reason='Instruction budget exceeded'
        except u.UcError as error:
            if not self.reason: self.reason=str(error)
        finally:
            # Also check raised emu_start paths: these skip the normal query.
            # Timed-out state remains diagnostic only, including across runs.
            if self.uc.query(u.UC_QUERY_TIMEOUT):
                self.nonresumable_reason='Unicorn execution timeout; state will not be resumed'
                self.ready=False
                if not self.reason: self.reason=self.nonresumable_reason
                elif self.nonresumable_reason not in self.reason:
                    self.reason+='; '+self.nonresumable_reason
            if budget:
                budget_stats=budget.stats()
                budget.close()
        tick=time.monotonic(); self.dump(snapshot); self.metrics['snapshot_seconds']+=time.monotonic()-tick
        rip=self.reg('rip')
        try: disasm=[f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in self.md.disasm(bytes(self.uc.mem_read(rip,32)),rip)]
        except u.UcError: disasm=[]
        return {'stop':self.reason,'rip':hex(rip),'calls':dict(self.calls),'events':self.events[-50:],'recent_blocks':[hex(a) for a in self.blocks],'disassembly':disasm,'elapsed':time.monotonic()-start,'metrics':self.metrics,'native_coverage':self.native_coverage.stats() if self.native_coverage else None,'scheduler':scheduler,'block_budget':budget_stats,'resumable':not getattr(self,'nonresumable_reason',None),'nonresumable_reason':getattr(self,'nonresumable_reason',None)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path); p.add_argument('--snapshot',type=Path,help='Keep a diagnostic memory image and report')
    p.add_argument('-o','--output',type=Path,help='New output directory; default: INPUT.resources')
    p.add_argument('--instructions',type=int,default=5000000000,help='Positive instruction budget')
    p.add_argument('--seconds',type=int,default=240)
    p.add_argument('--resume',type=Path,help='Development checkpoint created by this tool')
    p.add_argument('--checkpoint',action='store_true',help='Save development state beside --snapshot')
    p.add_argument('--reference',action='store_true',help='Use the Python coverage and file-based scanner for comparison')
    p.add_argument('--scheduler',choices=['stock','block'],help='Instruction budget scheduler (default: native blocks when available)')
    args=p.parse_args()
    if not 0<args.instructions<2**64 or args.seconds<=0: p.error('Budgets must be positive; instruction budget must fit uint64')
    if args.checkpoint and not args.snapshot: p.error('--checkpoint requires --snapshot')
    output=(args.output or Path(str(args.input)+'.resources')).resolve()
    if output.exists() or not output.parent.is_dir(): p.error('Output must be a new directory with an existing parent')
    if args.snapshot:
        for path in [args.snapshot,args.snapshot.with_suffix('.json'),args.snapshot.with_suffix('.checkpoint.zip')]:
            if path.exists(): p.error('Diagnostic path already exists: '+str(path))
    emu=None
    try:
        before=hashlib.sha256(args.input.read_bytes()).hexdigest()
        with work_directory(prefix='vmp-emulation-') as tmp:
            # Only the reference path uses periodic disk scans. Keep its working
            # image private and publish diagnostics after emulation ends.
            snapshot=Path(tmp)/'memory.exe'
            emu=Emulator(args.input,reference=args.reference)
            if args.resume: emu.restore(args.resume)
            scheduler=args.scheduler or ('block' if not args.reference and library_path('block_budget.dll').exists() else 'stock')
            result=emu.run(args.instructions,args.seconds,snapshot,scheduler=scheduler)
            result['input_sha256']=before
            result['input_unchanged']=hashlib.sha256(args.input.read_bytes()).hexdigest()==before
            if not result['input_unchanged']: raise Unsupported('Input changed during extraction')
            if args.checkpoint:
                if result['resumable']:
                    emu.checkpoint(args.snapshot.with_suffix('.checkpoint.zip'))
                else:
                    result['checkpoint_skipped']=result['nonresumable_reason']
                    print('Checkpoint skipped: '+result['checkpoint_skipped'],file=sys.stderr)
            if args.snapshot:
                atomic_snapshot(args.snapshot,snapshot.read_bytes())
                args.snapshot.with_suffix('.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
            if not getattr(emu,'ready',False):
                print('Extraction stopped: '+result['stop'],file=sys.stderr)
                return 1
            extracted=scan_run(snapshot,'-o',output)
            if extracted.returncode: raise Unsupported(extracted.stderr)
            manifest=output/'manifest.json'
            data=json.loads(manifest.read_text(encoding='utf-8'))
            data.update(input=args.input.name,input_sha256=before,method='unicorn-emulation',emulation_seconds=result['elapsed'],
                        payload_readiness='file-backed bytes or observed writes to initially empty image sections')
            manifest.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            print(f'Extracted {len(data["resources"])} resources in {result["elapsed"]:.1f}s.\nOutput: {output}')
            return 0
    except (RuntimeError,u.UcError,pefile.PEFormatError,OSError,ValueError,subprocess.TimeoutExpired) as error:
        print('error: '+str(error),file=sys.stderr); return 1
    finally:
        if emu and emu.native_coverage: emu.native_coverage.close()

if __name__=='__main__': raise SystemExit(main())
