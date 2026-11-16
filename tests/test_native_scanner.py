"""Native metadata scanner parity, stale hints and malformed-input checks."""
import ctypes as c
import json
from pathlib import Path
import random
import struct
import subprocess
from contextlib import contextmanager
import shutil
import uuid
import time

from verify_samples import ROOT, SAMPLES, VERSIONS, NAMES
from verify_synthetic import image


class Scanner:
    def __init__(self,path=None):
        self.dll=c.CDLL(str(path or ROOT/'dist/resource_scanner.dll'))
        self.dll.resource_scanner_abi.restype=c.c_uint
        assert self.dll.resource_scanner_abi()==1
        self.dll.resource_scanner_scan.argtypes=[c.c_void_p,c.c_size_t,c.c_int,c.c_uint32,c.c_uint32,c.POINTER(c.c_void_p),c.POINTER(c.c_size_t)]
        self.dll.resource_scanner_scan.restype=c.c_int
        self.dll.resource_scanner_scan_timed.argtypes=self.dll.resource_scanner_scan.argtypes[:5]+[c.c_uint32]+self.dll.resource_scanner_scan.argtypes[5:]
        self.dll.resource_scanner_scan_timed.restype=c.c_int
        self.dll.resource_scanner_free.argtypes=[c.c_void_p]
        self.dll.resource_scanner_free.restype=None

    def scan(self,blob,hint=None,timeout_ms=None):
        output=c.c_void_p()
        length=c.c_size_t()
        buffer=c.create_string_buffer(bytes(blob))
        rva,key=hint or (0,0)
        if timeout_ms is None:
            status=self.dll.resource_scanner_scan(buffer,len(blob),bool(hint),rva,key,c.byref(output),c.byref(length))
        else:
            status=self.dll.resource_scanner_scan_timed(buffer,len(blob),bool(hint),rva,key,timeout_ms,c.byref(output),c.byref(length))
        try:
            result=json.loads(c.string_at(output,length.value).decode('utf-8')) if output.value else None
        finally:
            self.dll.resource_scanner_free(output)
        return status,result


@contextmanager
def workspace_temp():
    directory=ROOT/'build'/('native-scanner-test-'+uuid.uuid4().hex)
    directory.mkdir()
    try:
        yield directory
    finally:
        assert directory.resolve().is_relative_to((ROOT/'build').resolve())
        shutil.rmtree(directory)


def cli_manifest(path,tmp,index):
    out=tmp/str(index)
    result=subprocess.run([str(ROOT/'dist/vmp-resource-extractor.exe'),str(path),'-o',str(out)],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
    manifest=json.loads((out/'manifest.json').read_text(encoding='utf-8'))
    return {'table_rva':int(manifest['table_rva'],16),'key':int(manifest['key'],16),
            'total':sum(r['size'] for r in manifest['resources']),
            'resources':[{**{k:r[k] for k in ['type','name','language','size','codepage']},
                          'data_rva':int(r['data_rva'],16)} for r in manifest['resources']]}


def main(scanner=None):
    scanner=scanner or Scanner()
    inputs=[SAMPLES/'protected'/version/'x64'/name for version in VERSIONS for name in NAMES]
    snapshots=[ROOT/'build'/name for name in ['packaged-final-memory.exe','resource-sample-packaged-memory.exe','pawd-dll-stable-memory.exe']]
    inputs += [path for path in snapshots if path.exists()]
    with workspace_temp() as temp:
        temp=Path(temp)
        assert temp.resolve().is_relative_to((ROOT/'build').resolve())
        for index,path in enumerate(inputs):
            blob=path.read_bytes()
            status,response=scanner.scan(blob)
            assert status==0 and response['hint_used'] is False,(path,status,response)
            expected=cli_manifest(path,temp,index)
            assert response['candidates']==[expected],path
            hint=(expected['table_rva'],expected['key'])
            status,selected=scanner.scan(blob,hint)
            assert status==0 and selected['hint_used'] is True
            assert selected['candidates']==[expected]
            status,fallback=scanner.scan(blob,(hint[0],hint[1]^0x1234abcd))
            assert status==0 and fallback['hint_used'] is False
            assert fallback['candidates']==[expected]
        # Full discovery must retain all candidates; a valid hint is a selection.
        multiple=image(True,[(0x137,0x12345678,True),(0x737,0xabcd1234,False)])
        status,response=scanner.scan(multiple)
        assert status==0 and len(response['candidates'])==2
        status,response=scanner.scan(multiple,(0x1737,0xabcd1234))
        assert status==0 and len(response['candidates'])==1 and response['hint_used']
        assert response['candidates'][0]['table_rva']==0x1737
        # Names and values stay typed across the native JSON boundary.
        status,response=scanner.scan(image(False,[(0x137,0xffffffff,True)]))
        assert status==0 and response['candidates'][0]['resources'][0]['type']=='資料_İ'
        original=(SAMPLES/'originals/x64'/NAMES[0]).read_bytes()
        status,response=scanner.scan(original)
        assert status==1 and response['candidates']==[]
        malformed=[b'',b'MZ',original[:256],bytes(64)]
        rng=random.Random(451)
        malformed += [rng.randbytes(n) for n in [64,128,1024,4096]]
        started=time.perf_counter()
        for blob in malformed:
            status,response=scanner.scan(blob)
            assert status==2 and 'error' in response
        assert time.perf_counter()-started<5
        output=c.c_void_p(123)
        length=c.c_size_t(123)
        assert scanner.dll.resource_scanner_scan(None,1<<40,0,0,0,c.byref(output),c.byref(length))==2
        scanner.dll.resource_scanner_free(output)
        assert scanner.dll.resource_scanner_scan(None,0,0,0,0,None,c.byref(length))==2
        # Deterministic expired deadline, including the hinted path. A timeout
        # response is owned exactly like other results and must not poison reuse.
        valid=image(True,[(0x137,0x12345678,True)])
        started=time.perf_counter()
        for hint in [None,(0x1137,0x12345678)]:
            status,response=scanner.scan(valid,hint,timeout_ms=0)
            assert status==5 and 'time limit' in response['error']
        assert time.perf_counter()-started<1
        # Candidate-heavy contents exercise checks during discovery, not just
        # the immediate-expiry entry guard. The full scan would be much longer.
        heavy=bytearray(valid[:0x200])
        heavy.extend(struct.pack('<IIII',0,0,0,0x80001000)*65536)
        struct.pack_into('<I',heavy,0x188+8,0x100000)
        struct.pack_into('<I',heavy,0x188+16,0x100000)
        started=time.perf_counter()
        status,response=scanner.scan(heavy,timeout_ms=5)
        assert status==5 and 'time limit' in response['error']
        assert time.perf_counter()-started<2
        status,response=scanner.scan(valid)
        assert status==0 and len(response['candidates'])==1
    print(f'PASS: {len(inputs)} CLI/native metadata matches, valid/stale hints, ambiguity, Unicode, malformed inputs, deadlines and ABI ownership')


if __name__=='__main__': main()
