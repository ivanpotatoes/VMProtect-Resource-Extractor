"""Verify an emulated extraction against the original fixture, independently of the extractor."""
import hashlib
import json
import argparse
from pathlib import Path
from verify_samples import SAMPLES, original

def main():
    root=Path(__file__).resolve().parents[1]
    parser=argparse.ArgumentParser()
    parser.add_argument('name',nargs='?',default='ResourcePaths-x64',choices=['ResourcePaths-x64','ResourceSample-x64','pawdResourceFixture-x64'])
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    is_dll=args.name=='pawdResourceFixture-x64'
    sample=SAMPLES/'originals/x64'/(args.name+('.dll' if is_dll else '.vmp.exe'))
    output=args.output or Path(str(sample)+'.resources')
    m=json.loads((output/'manifest.json').read_text(encoding='utf-8'))
    original_name='ResourceFixture-x64.dll' if is_dll else args.name+'.exe'
    expected={k:v for k,v in original(sample.with_name(original_name)).items() if k[0]!=24}
    actual={(r['type'],r['name'],r['language']):((output/r['file']).read_bytes(),r['codepage']) for r in m['resources']}
    assert actual==expected
    assert m['method']=='unicorn-emulation'
    assert m['input_sha256']==hashlib.sha256(sample.read_bytes()).hexdigest()
    report={'input':sample.name,'input_sha256':m['input_sha256'],'resources':len(actual),
            'bytes':sum(len(v[0]) for v in actual.values()),'matches_original':True,
            'elapsed_seconds':m['emulation_seconds'],
            'files':{r['file']:hashlib.sha256((output/r['file']).read_bytes()).hexdigest() for r in m['resources']}}
    (root/'build'/('packed-verification-'+args.name+'.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__': main()
