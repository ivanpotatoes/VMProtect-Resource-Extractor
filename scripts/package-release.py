"""Package existing Windows x64 builds without running protected inputs."""
import argparse
import hashlib
from pathlib import Path
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPO = 'https://github.com/ivanpotatoes/VMProtect-Resource-Extractor'
SOURCES = {
    'unicorn-2.1.4.tar.gz': '00567a70e323f749b419cd86bee4f9115beab7ebba32194581c090cbb7c59cff',
    'pyinstaller-6.22.3.tar.gz': '05eb2f5615503e72939a7224d68b4aff572c6b0438ee4a17d0a4b481f399362d',
}


def executable(name):
    path = ROOT / 'dist' / name
    data = path.read_bytes()
    if data[:2] != b'MZ' or len(data) < 64:
        raise ValueError(f'Not a PE binary: {path}')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if data[nt:nt + 4] != b'PE\0\0' or struct.unpack_from('<H', data, nt + 4)[0] != 0x8664:
        raise ValueError(f'Not an x64 PE binary: {path}')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True, help='Release version, e.g. 1.0.0')
    args = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+', args.version):
        parser.error('Use a three-part numeric version')
    version = args.version
    title = f'VMProtect Resource Extractor v{version}'
    footer = f'\nSource and documentation: {REPO}/tree/v{version}\n\nIvan Kozlovsky\nivankozlovsky.com\ncontact@ivankozlovsky.com\n'
    static_readme = f'''{title} - Static CLI

Extract this ZIP, then run from a command prompt:
  vmp-resource-extractor.exe protected.exe
  vmp-resource-extractor.exe protected.dll --output extracted
  vmp-resource-extractor.exe protected.exe --list

Windows x64. No Python, debugger or driver required.
Output: numbered raw resource files and manifest.json.
Use a new output folder beneath an existing parent directory.
The input file is unchanged. This does not rebuild .rsrc.
If packing hides the resource table or payloads, use the emulator
or scan the initialized module with the x64dbg plugin.
''' + footer
    emulator_readme = f'''{title} - Emulation CLI

Extract this ZIP, then run:
  vmp-resource-emulator.exe protected.exe --output extracted
  vmp-resource-emulator.exe protected.dll --seconds 600 --instructions 15000000000

Windows x64. Python, Unicorn and Capstone are bundled.
Protected startup code runs inside Unicorn, not as a Windows process.
Default budgets: 240 seconds and five billion instructions.
Unsupported APIs, exceptions and exhausted budgets stop with an error.
This models tested startup paths, not a complete Windows environment.

Output: numbered raw resources and manifest.json. Existing output
folders are never overwritten. The input file is unchanged.
The static extractor is also included for direct extraction.

Third-party license texts and source links are included in this ZIP.
''' + footer
    common = {'LICENSE': (ROOT / 'LICENSE').read_bytes()}
    packages = {
        'static': {**common, 'vmp-resource-extractor.exe': executable('vmp-resource-extractor.exe'),
                   'README.txt': static_readme.encode('utf-8')},
        'emulation': {**common, 'vmp-resource-emulator.exe': executable('vmp-resource-emulator.exe'),
                      'vmp-resource-extractor.exe': executable('vmp-resource-extractor.exe'),
                      'README.txt': emulator_readme.encode('utf-8'),
                      'THIRD-PARTY-NOTICES.md': (ROOT / 'THIRD-PARTY-NOTICES.md').read_bytes(),
                      **{f'licenses/{p.name}': p.read_bytes() for p in sorted((ROOT / 'licenses').glob('*.txt'))}},
        'x64dbg': {**common, 'VMPResourceExtractor.dp64': executable('VMPResourceExtractor.dp64'),
                   'README.txt': (ROOT / 'plugin/README.txt').read_bytes()},
    }
    source_files = {}
    for name, expected in SOURCES.items():
        data = (ROOT / 'build/vendor' / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'Dependency source hash mismatch: {name}')
        source_files[name] = data
    source_files['SHA256SUMS.txt'] = ''.join(f'{digest}  {name}\n' for name, digest in SOURCES.items()).encode('ascii')
    source_files['README.txt'] = f'''{title} - Emulation dependency sources

Unmodified upstream source archives matching the bundled Unicorn 2.1.4
and PyInstaller 6.22.3 components. Their license texts are in the archives.
The archive hashes were checked against the official PyPI release metadata.

Unicorn source and build instructions: https://github.com/unicorn-engine/unicorn/tree/2.1.4
PyInstaller source: https://github.com/pyinstaller/pyinstaller/tree/v6.22.3
The PyInstaller bootloader is built with: py waf all --no-cfg

Project code and full build scripts: {REPO}/tree/v{version}
See build-bootloader.cmd, build-emulation.cmd and docs/BUILDING.md.
'''.encode('utf-8')
    packages['emulation-sources'] = source_files
    output = ROOT / 'dist/releases' / f'v{version}'
    if output.exists():
        raise FileExistsError(f'Release directory already exists: {output}')
    output.mkdir(parents=True)
    hashes = []
    for mode, files in packages.items():
        suffix = '' if mode == 'emulation-sources' else '-x64'
        path = output / f'VMProtect-Resource-Extractor-v{version}-{mode}{suffix}.zip'
        with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(files.items()):
                archive.writestr(name, data)
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise ValueError(f'Invalid ZIP: {path}')
            for name, data in files.items():
                if archive.read(name) != data:
                    raise ValueError(f'Packaging mismatch: {path}/{name}')
        hashes.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}')
        print(f'{path.name}: {path.stat().st_size} bytes, {len(files)} files')
    (output / 'SHA256SUMS.txt').write_text('\n'.join(hashes) + '\n', encoding='ascii')
    print(f'Created {output}')


if __name__ == '__main__':
    main()
