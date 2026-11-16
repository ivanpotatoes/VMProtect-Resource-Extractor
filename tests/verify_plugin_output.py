"""Compare an x64dbg extraction with the original PE resource tree (requires pefile)."""
import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath

from verify_samples import original


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'Duplicate JSON property: {key}')
        result[key] = value
    return result


def verify(original_path, output):
    original_path = Path(original_path).resolve(strict=True)
    output = Path(output).resolve(strict=True)
    manifest_path = output / 'manifest.json'
    require(manifest_path.resolve(strict=True).parent == output,
            'Manifest resolves outside the output directory')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'),
                          object_pairs_hook=unique_object)
    require(manifest.get('method') == 'x64dbg-memory', 'Not an x64dbg memory extraction')
    require(manifest.get('format') == 'vmprotect-resource-extractor-1', 'Unexpected format')
    require(manifest.get('architecture') == 'x64', 'Unexpected module architecture')
    require(isinstance(manifest.get('module_base'), str), 'Missing module base')
    require(0 < int(manifest['module_base'], 16) < 2**64, 'Invalid module base')
    require(isinstance(manifest.get('resources'), list), 'Missing resource records')

    # Ordinary PE manifests are not part of VMProtect's encrypted resource tree.
    expected = {key: value for key, value in original(original_path).items() if key[0] != 24}
    require(expected, 'Original contains no resources to compare')
    actual, files, hashes = {}, set(), {}
    for item in manifest['resources']:
        key = (item['type'], item['name'], item['language'])
        require(all(type(ident) in (int, str) for ident in key), 'Invalid resource identifier')
        require(key not in actual, f'Duplicate resource identifier: {key!r}')
        filename = item['file']
        require(isinstance(filename, str) and filename, 'Invalid resource filename')
        windows_name = PureWindowsPath(filename)
        require(not windows_name.drive and not windows_name.root and
                len(windows_name.parts) == 1 and filename not in ('.', '..') and
                '/' not in filename and '\\' not in filename and ':' not in filename,
                f'Unsafe resource filename: {filename!r}')
        require(filename.casefold() not in files, f'Duplicate resource file: {filename}')
        files.add(filename.casefold())
        resource_path = (output / filename).resolve(strict=True)
        require(resource_path.parent == output and resource_path.is_file(),
                f'Resource resolves outside output or is not a file: {filename}')
        require(type(item['size']) is int and item['size'] >= 0,
                f'Invalid size: {filename}')
        require(type(item['codepage']) is int and 0 <= item['codepage'] <= 0xffffffff,
                f'Invalid codepage: {filename}')
        data = resource_path.read_bytes()
        require(len(data) == item['size'], f'Size mismatch: {filename}')
        actual[key] = (data, item['codepage'])
        hashes[filename] = hashlib.sha256(data).hexdigest()

    require(set(actual) == set(expected),
            f'Resource identifiers differ: missing={set(expected) - set(actual)!r}, '
            f'extra={set(actual) - set(expected)!r}')
    for key, value in expected.items():
        require(actual[key] == value, f'Payload or codepage mismatch for {key!r}')
    return {'original': str(original_path), 'output': str(output),
            'method': manifest['method'], 'module_base': manifest['module_base'],
            'resources': len(actual), 'bytes': sum(len(value[0]) for value in actual.values()),
            'matches_original': True, 'files': hashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path, help='Unprotected original EXE or DLL')
    parser.add_argument('outputs', type=Path, nargs='+', help='One or more extraction directories')
    args = parser.parse_args()
    for output in args.outputs:
        print(json.dumps(verify(args.original, output), indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
