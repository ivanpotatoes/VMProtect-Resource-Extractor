"""Sequential packed-fixture benchmarks with independent resource verification.

Examples:
  py tests/benchmark_emulation.py --mode source --samples paths
  py tests/benchmark_emulation.py --mode source --reference
  py tests/benchmark_emulation.py --mode packaged

All generated files stay in a new build/optimization directory. Inputs and
original fixtures are only read; timings include verification-free process time.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

import unicorn
from verify_samples import SAMPLES as FIXTURE_ROOT, original

ROOT=Path(__file__).resolve().parents[1]
SAMPLE_DIR=FIXTURE_ROOT/'originals/x64'
SAMPLES={
    'paths':('ResourcePaths-x64.vmp.exe','ResourcePaths-x64.exe'),
    'sample':('ResourceSample-x64.vmp.exe','ResourceSample-x64.exe'),
    'fixture':('pawdResourceFixture-x64.dll','ResourceFixture-x64.dll'),
}

def sha256(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): digest.update(block)
    return digest.hexdigest()

def verify(sample,source,output,input_sha256):
    metadata=json.loads((output/'manifest.json').read_text(encoding='utf-8'))
    expected={key:value for key,value in original(source).items() if key[0]!=24}
    actual={}; hashes={}
    for resource in metadata['resources']:
        key=(resource['type'],resource['name'],resource['language'])
        if key in actual: raise ValueError('Duplicate extracted resource: '+str(key))
        path=(output/resource['file']).resolve()
        if not path.is_relative_to(output.resolve()): raise ValueError('Resource escaped output directory')
        payload=path.read_bytes()
        actual[key]=(payload,resource['codepage'])
        hashes[resource['file']]=hashlib.sha256(payload).hexdigest()
    if actual!=expected: raise ValueError('Extracted resource bytes or metadata do not match original fixture')
    if metadata['method']!='unicorn-emulation': raise ValueError('Unexpected extraction method')
    if metadata['input_sha256']!=input_sha256: raise ValueError('Manifest input hash does not match sample')
    return {'matches_original':True,'resource_count':len(actual),
            'resource_bytes':sum(len(value[0]) for value in actual.values()),
            'emulation_seconds':metadata['emulation_seconds'],'resource_sha256':hashes}

def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--mode',choices=['source','packaged'],default='source')
    parser.add_argument('--executable',type=Path,help='Packaged executable override')
    parser.add_argument('--reference',action='store_true')
    parser.add_argument('--scheduler',choices=['stock','block'],default='stock')
    parser.add_argument('--samples',nargs='+',choices=list(SAMPLES),default=list(SAMPLES))
    parser.add_argument('--repeats',type=int,default=1)
    parser.add_argument('--seconds',type=int,default=600)
    parser.add_argument('--instructions',type=int,default=15000000000)
    args=parser.parse_args()
    if min(args.repeats,args.seconds,args.instructions)<=0: parser.error('Budgets and repeats must be positive')
    if args.executable and args.mode!='packaged': parser.error('--executable requires --mode packaged')
    executable=(args.executable or ROOT/'dist/vmp-resource-emulator.exe').resolve()
    target=ROOT/'standalone/emulate.py' if args.mode=='source' else executable
    if not target.is_file(): parser.error('Missing emulator: '+str(target))
    for name in args.samples:
        for filename in SAMPLES[name]:
            if not (SAMPLE_DIR/filename).is_file(): parser.error('Missing sample: '+filename)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
    output_root=ROOT/'build/optimization'/stamp
    output_root.mkdir(parents=True)
    artifacts=[target]
    if args.mode=='source':
        artifacts+=list((ROOT/'standalone').glob('*.py'))+list((ROOT/'dist').glob('*.dll'))
        artifacts.append(ROOT/'dist/vmp-resource-extractor.exe')
    summary={'started_utc':datetime.now(timezone.utc).isoformat(),'mode':args.mode,
             'reference':args.reference,'scheduler':args.scheduler,'python':sys.version,
             'unicorn':unicorn.__version__,'instructions':args.instructions,'seconds':args.seconds,
             'artifacts':{str(path):sha256(path) for path in dict.fromkeys(artifacts) if path.is_file()},'runs':[]}
    summary_path=output_root/'summary.json'
    failed=False
    for repeat in range(1,args.repeats+1):
        for name in args.samples:
            directory=output_root/f'{name}-{repeat}'
            directory.mkdir()
            sample,source=(SAMPLE_DIR/filename for filename in SAMPLES[name])
            before={str(path):sha256(path) for path in (sample,source)}
            output=directory/'resources'; snapshot=directory/'memory.exe'
            command=[sys.executable,str(target)] if args.mode=='source' else [str(target)]
            command += [str(sample),'-o',str(output),'--snapshot',str(snapshot),
                        '--instructions',str(args.instructions),'--seconds',str(args.seconds)]
            command += ['--scheduler',args.scheduler]
            if args.reference: command.append('--reference')
            run={'sample':sample.name,'repeat':repeat,'command':command,'input_sha256':before[str(sample)],
                 'original_sha256':before[str(source)],'directory':str(directory)}
            print(f'Running {name} #{repeat}: {args.mode}, {args.scheduler}, reference={args.reference}',flush=True)
            started=time.perf_counter()
            try:
                with (directory/'stdout.log').open('wb') as stdout,(directory/'stderr.log').open('wb') as stderr:
                    process=subprocess.run(command,cwd=ROOT,stdout=stdout,stderr=stderr,timeout=args.seconds+180)
                run['returncode']=process.returncode
                run['wall_seconds']=time.perf_counter()-started
                if process.returncode: raise RuntimeError('Emulator failed; see stderr.log and diagnostic report')
                run.update(verify(sample,source,output,before[str(sample)]))
            except (OSError,RuntimeError,ValueError,KeyError,subprocess.TimeoutExpired) as error:
                run['wall_seconds']=time.perf_counter()-started
                run['error']=str(error); failed=True
            after={str(path):sha256(path) for path in (sample,source)}
            run['inputs_unchanged']=after==before
            if not run['inputs_unchanged']:
                run['error']='Sample or original fixture changed during benchmark'; failed=True
            diagnostic=snapshot.with_suffix('.json')
            if diagnostic.exists():
                run['diagnostic']=json.loads(diagnostic.read_text(encoding='utf-8'))
            summary['runs'].append(run)
            (directory/'result.json').write_text(json.dumps(run,indent=2)+'\n',encoding='utf-8')
            summary_path.write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
            print(f'{name}: {run["wall_seconds"]:.3f}s; '+('FAIL '+run['error'] if 'error' in run else 'verified'),flush=True)
            if not run['inputs_unchanged']:
                print('Stopped because an input changed.',file=sys.stderr)
                print(summary_path)
                return 1
    print(summary_path)
    return int(failed)

if __name__=='__main__': raise SystemExit(main())
