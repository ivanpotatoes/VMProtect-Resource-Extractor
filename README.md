# VMProtect Resource Extractor

Static extractor for VMProtect's encrypted resource table. Finds the table and key, decrypts resource data and writes a JSON manifest with names, IDs, languages and codepages.

## Usage

```text
vmp-resource-extractor.exe protected.exe --output extracted
vmp-resource-extractor.exe protected.dll --list
```

Use a new output folder. The input file is not modified. Output contains raw resource files and `manifest.json`; this does not rebuild `.rsrc` or restore a runnable executable.

## Build

Run `build.cmd` with Visual Studio C++ Build Tools installed, or use CMake from an x64 developer shell:

```text
cmake -S . -B build-cmake -A x64
cmake --build build-cmake --config Release
```

## Tests

```text
py -m pip install pefile==2024.8.26
py tests/verify_synthetic.py
```

The integration test `tests/verify_samples.py` requires the local research fixtures. Set `VRE_SAMPLES` to their resource-protection directory, containing `originals/x64` and `protected/<version>/x64`. Protected test binaries are not included.

Tested research versions: 3.3.1, 3.4.0, 3.5.0, 3.6.0, 3.8.0, 3.9.4 and 3.10.1.

## License

MIT. Copyright 2026 Ivan Kozlovsky.
