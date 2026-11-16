# Building and testing

Run commands from the repository root. The build scripts target Windows x64 and use Visual Studio's C++ toolchain with the Windows SDK. They reuse an existing x64 developer shell or find an installed toolchain through `vswhere`.

## Static extractor

```powershell
.\build.cmd
```

Output: `dist/vmp-resource-extractor.exe`. The MSVC runtime is statically linked; the executable does not require Python.

Alternatively, build the static extractor with CMake:

```text
cmake -S . -B build-cmake -A x64
cmake --build build-cmake --config Release
```

CMake writes its executable under the selected build directory. The Python tests expect the command-script output in `dist`.

## x64dbg plugin

Use the x64dbg plugin SDK that contains `_plugins.h`, `x64dbg.lib` and `x64bridge.lib`:

```powershell
.\build-plugin.cmd "C:\tools\x64dbg\pluginsdk"
```

Or set the SDK path for the current shell:

```powershell
$env:VRE_SDK = 'C:\tools\x64dbg\pluginsdk'
.\build-plugin.cmd
```

Output: `dist/VMPResourceExtractor.dp64`. Copy it into the `plugins` directory beside `x64dbg.exe`. The plugin does not need the standalone extractor or Python at runtime.

## Emulator

The packaged build was tested with 64-bit CPython 3.14.0. Install the pinned dependencies and PyInstaller:

```powershell
py -m pip install -r requirements-emulation.txt pyinstaller==6.22.3
.\build-emulation.cmd
```

The build script compiles the static extractor and three native helpers, then creates `dist/vmp-resource-emulator.exe`. Python and the required libraries are bundled in that executable.

The first build downloads the unmodified PyInstaller 6.22.3 source and compiles its bootloader with `--no-cfg`. This is a build setting for compatibility with Unicorn's context switching. The source and generated files stay under `build/vendor`. See [third-party notices](../THIRD-PARTY-NOTICES.md) for component versions and licenses.

To run directly from Python, build the helpers first:

```powershell
.\build.cmd
.\build-native-tracker.cmd
.\build-native-scanner.cmd
.\build-block-budget.cmd
py standalone/emulate.py protected.exe --output extracted
```

## Tests without research fixtures

With the static executable built and dependencies installed:

```powershell
py tests/verify_synthetic.py
py tests/verify_snapshot_io.py
```

After building the native helpers, run:

```powershell
py tests/test_native_tracker.py
py tests/test_native_support.py
py tests/test_host_image.py
py tests/test_block_budget.py
py tests/test_timeout_state.py
```

These cover generated PE layouts, Unicode names, ambiguous or malformed tables, memory tracking, host-image access, execution budgets and timeout handling.

## Research fixture tests

Protected research binaries are not included in this repository. The integration tests expect matching unprotected and protected files in this layout:

```text
resource_protection/
  originals/x64/
    ResourceSample-x64.exe
    ResourcePaths-x64.exe
    ResourceFixture-x64.dll
  protected/<version>/x64/
    ResourceSample-x64.exe
    ResourcePaths-x64.exe
    ResourceFixture-x64.dll
```

Version folders are `3.3.1`, `3.4.0`, `3.5.0`, `3.6.0`, `3.8.0`, `3.9.4` and `3.10.1`. These fixtures use Resource Protection only.

The default fixture root is `../samples/resource_protection`, relative to the repository. Set `VRE_SAMPLES` to use another location for the fixture tests and benchmarks:

```powershell
$env:VRE_SAMPLES = 'C:\research\resource_protection'
py tests/verify_samples.py
py tests/test_native_scanner.py
.\build-plugin-tests.cmd
py tests/test_plugin_backend.py
```

The plugin-backend harness uses the same capture and extraction code as the plugin, with mapped fixture images and a controlled memory reader. Live debugger extraction is checked separately by comparing its output with an original PE:

```text
py tests/verify_plugin_output.py original.exe extracted-folder
```

Packed-fixture tests and benchmarks also use `ResourcePaths-x64.vmp.exe`, `ResourceSample-x64.vmp.exe` and `pawdResourceFixture-x64.dll` under the fixture root's `originals/x64` directory:

```powershell
py tests/verify_emulation_models.py
py tests/benchmark_emulation.py --mode packaged --scheduler block
py tests/benchmark_emulation.py --mode packaged --reference
```

Each benchmark run creates a new directory under `build/optimization`, records budgets and timings, compares every resource against the original and checks that the input hash is unchanged. See [emulation details](EMULATION.md) for the measured results and what the execution budget means.
