# Bundled components

The emulation executable bundles these unmodified libraries and the Python runtime:

- Unicorn Engine 2.1.4 — GPL-2.0, with additional component notices. Source: https://github.com/unicorn-engine/unicorn/tree/2.1.4
- Capstone 5.0.9 — BSD license. Source: https://github.com/capstone-engine/capstone
- pefile 2024.8.26 — MIT license. Source: https://github.com/erocarrera/pefile
- CPython 3.14.0 — Python Software Foundation license. Source: https://github.com/python/cpython/tree/v3.14.0
- PyInstaller 6.22.3 bootloader — GPL with its distribution exception. Source: https://github.com/pyinstaller/pyinstaller/tree/v6.22.3

License texts are in `licenses`. The PyInstaller bootloader is compiled from the upstream source with `--no-cfg` for compatibility with Unicorn. Its source is not modified; the local build commands are in `build-bootloader.cmd` and `build-emulation.cmd`.

The [v1.0.0 release](https://github.com/ivanpotatoes/VMProtect-Resource-Extractor/releases/tag/v1.0.0) also provides `VMProtect-Resource-Extractor-v1.0.0-emulation-sources.zip`, containing the matching Unicorn 2.1.4 and PyInstaller 6.22.3 source archives. SHA-256 values are included. Project source and build scripts are available from the same release tag.
