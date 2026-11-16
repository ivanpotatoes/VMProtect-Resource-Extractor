"""Integration checks against the local research fixtures. Requires pefile."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import pefile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'standalone'))
from work_files import work_directory
EXE = ROOT / 'dist/vmp-resource-extractor.exe'
SAMPLES = Path(os.environ.get('VRE_SAMPLES', str(ROOT.parent / 'samples/resource_protection')))
VERSIONS = ['3.3.1', '3.4.0', '3.5.0', '3.6.0', '3.8.0', '3.9.4', '3.10.1']
NAMES = ['ResourceSample-x64.exe', 'ResourcePaths-x64.exe', 'ResourceFixture-x64.dll']

def original(path):
    pe = pefile.PE(str(path))
    out = {}
    def walk(directory, keys=()):
        for entry in directory.entries:
            ident = str(entry.name) if entry.name is not None else entry.id
            current = keys + (ident,)
            if hasattr(entry, 'directory'):
                walk(entry.directory, current)
            else:
                leaf = entry.data.struct
                out[current] = (pe.get_data(leaf.OffsetToData, leaf.Size), leaf.CodePage)
    walk(pe.DIRECTORY_ENTRY_RESOURCE)
    pe.close()
    return out

def run(*args, ok=True):
    result = subprocess.run([str(EXE), *map(str, args)], capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == ok, result.stdout + result.stderr
    return result

def main():
    total = 0
    with work_directory(prefix='vmp-resource-tests-') as tmp:
        tmp = Path(tmp)
        for version in VERSIONS:
            start = time.perf_counter()
            count = 0
            for name in NAMES:
                src = SAMPLES / 'protected' / version / 'x64' / name
                expected = original(SAMPLES / 'originals/x64' / name)
                # The normal PE manifest remains outside VMProtect's private tree.
                expected = {k: v for k, v in expected.items() if k[0] != 24}
                before = hashlib.sha256(src.read_bytes()).digest()
                dest = tmp / (version + '-' + name)
                run(src, '-o', dest)
                manifest = json.loads((dest / 'manifest.json').read_text(encoding='utf-8'))
                actual = {}
                for item in manifest['resources']:
                    key = (item['type'], item['name'], item['language'])
                    data = (dest / item['file']).read_bytes()
                    assert len(data) == item['size']
                    actual[key] = (data, item['codepage'])
                assert actual == expected, (version, name)
                assert hashlib.sha256(src.read_bytes()).digest() == before
                snapshot = {p.name: p.read_bytes() for p in dest.iterdir()}
                run(src, '-o', dest, ok=False)
                assert snapshot == {p.name: p.read_bytes() for p in dest.iterdir()}
                count += len(actual)
            total += count
            print(f'{version}: 3 files, {count} resources verified ({time.perf_counter()-start:.3f}s)')
        plain = SAMPLES / 'originals/x64' / NAMES[0]
        run(plain, '-o', tmp / 'plain', ok=False)
        assert not (tmp / 'plain').exists()
        broken = tmp / 'truncated.exe'
        broken.write_bytes(plain.read_bytes()[:256])
        run(broken, ok=False)
        src = SAMPLES / 'protected/3.3.1/x64' / NAMES[0]
        run(src, '--table-rva', '0x81ddb', '--key', '0', ok=False)
        run(src, '--table-rva', '0x81ddb', ok=False)
    print(f'PASS: 21 protected files, {total} resources; overwrite, input integrity and invalid-input checks')

if __name__ == '__main__':
    main()
