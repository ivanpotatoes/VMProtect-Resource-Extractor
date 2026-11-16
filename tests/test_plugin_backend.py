"""Exercise runtime extraction through the plugin's exact backend and a memory reader."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import pefile
from verify_samples import ROOT, SAMPLES, VERSIONS, NAMES, original, work_directory
from verify_synthetic import image

EXE=ROOT/'build/plugin-backend-tests.exe'

def mapped(blob):
    pe=pefile.PE(data=blob)
    result=bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
    data=pe.get_memory_mapped_image()
    result[:len(data)]=data
    pe.close()
    return result

def synthetic(tables):
    blob=image(True,tables)
    struct.pack_into('<I',blob,0x98+56,0x3000)
    return mapped(blob)

def run(memory,output,mode='normal',value=0,ok=True,base=0x7ff612340000):
    result=subprocess.run([str(EXE),str(memory),str(output),hex(base),mode,str(value)],
                          text=True,capture_output=True,timeout=30)
    assert (result.returncode==0)==ok,result.stdout+result.stderr
    return result

def extracted(directory):
    metadata=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    assert metadata['method']=='x64dbg-memory'
    actual={}
    for resource in metadata['resources']:
        key=(resource['type'],resource['name'],resource['language'])
        assert key not in actual
        actual[key]=((directory/resource['file']).read_bytes(),resource['codepage'])
    return metadata,actual

def main():
    count=0
    with work_directory(prefix='plugin-backend-',root=ROOT/'build') as temp:
        temp=Path(temp)
        memory=temp/'memory.bin'
        for version in VERSIONS:
            for name in NAMES:
                input=SAMPLES/'protected'/version/'x64'/name
                before=hashlib.sha256(input.read_bytes()).digest()
                memory.write_bytes(mapped(input.read_bytes()))
                output=temp/(version+'-'+name)
                run(memory,output,'freeze')
                metadata,actual=extracted(output)
                expected={k:v for k,v in original(SAMPLES/'originals/x64'/name).items() if k[0]!=24}
                assert actual==expected,(version,name)
                assert metadata['module_base']=='0x7ff612340000'
                assert hashlib.sha256(input.read_bytes()).digest()==before
                count+=len(actual)
        # The snapshot owns its bytes: freeze mode destroys the reader's source
        # before extraction, and all 126 resources above still match originals.
        fixture=synthetic([(0x137,0x12345678,True)])
        memory.write_bytes(fixture)
        output=temp/'unicode'
        run(memory,output)
        metadata,actual=extracted(output)
        assert actual=={('資料_İ',543,1041):(b'abc\0xyz',65001)}
        saved={p.name:p.read_bytes() for p in output.iterdir()}
        run(memory,output,ok=False)
        assert {p.name:p.read_bytes() for p in output.iterdir()}==saved
        empty=temp/'empty'; empty.mkdir()
        run(memory,empty,ok=False)
        assert empty.is_dir() and not list(empty.iterdir())
        for mode,value,part in [('blocked',0x1000,'Cannot read'),('cancel',2,'state changed'),
                                ('changed',0,'headers changed'),('early-change',0,'headers changed'),
                                ('select',99,'Select a resource table')]:
            target=temp/mode
            result=run(memory,target,mode,value,ok=False)
            assert part in result.stderr,result.stderr
            assert not target.exists()
        run(memory,temp/'overflow',ok=False,base=0xfffffffffffff000)
        # All candidates are preserved, including explicit selection of a second tree.
        memory.write_bytes(synthetic([(0x137,0x12345678,True),(0x737,0xabcd1234,False)]))
        assert 'candidates=2' in run(memory,temp/'multiple','list').stdout
        run(memory,temp/'selected','select',1)
        assert extracted(temp/'selected')[0]['table_rva']=='0x1737'
        bad=bytearray(fixture)
        struct.pack_into('<H',bad,0x84,0x14c)
        memory.write_bytes(bad)
        assert 'x64 modules only' in run(memory,temp/'x32',ok=False).stderr
        assert not list(temp.glob('*.partial-vre-*'))
    print(f'PASS: 21 mapped fixtures / {count} resources, immutable snapshots, Unicode, candidate selection, inaccessible pages, cancellation, changed headers, overflow, overwrite and cleanup')

if __name__=='__main__': main()
