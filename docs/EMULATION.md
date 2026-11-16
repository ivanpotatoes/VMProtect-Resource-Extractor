# Emulation mode

`vmp-resource-emulator.exe` executes protected x64 startup code inside Unicorn until the resource table and payloads become available, then uses the shared resource parser to extract them. The target is not launched as a native Windows process.

```text
vmp-resource-emulator.exe protected.exe --output extracted
vmp-resource-emulator.exe protected.exe --seconds 300 --instructions 6000000000
vmp-resource-emulator.exe protected.dll --seconds 600 --instructions 15000000000
```

Defaults are 240 seconds and five billion instructions. The instruction count is a conservative execution budget, not an exact retired-instruction measurement. Unsupported API execution, exceptions and exhausted budgets stop extraction with an error.

DLLs are entered with their image base and `DLL_PROCESS_ATTACH`. Modeled system modules are placed outside the input image's address range.

## Windows model

The emulator reads export information and image bytes from the local Windows `ntdll.dll`, `kernel32.dll` and `kernelbase.dll`, plus `user32.dll` when the input imports it. An export being mapped does not mean that its API is implemented. Unmodeled API execution stops the run.

Supported API behavior is modeled in guest memory. Guest file reads are restricted to the input and those modeled system images; guest API requests are not forwarded to Windows.

The model covers the tested startup paths. It does not provide a complete Windows loader or exception dispatcher, and other protection combinations may need additional API or exception handling.

## Resource readiness

For initially empty PE sections, the extractor tracks bytes written by guest code. Every resource payload byte must be backed by file data or an observed write before extraction is accepted. This prevents a table discovered early in startup from producing zero-filled resources while unpacking is still in progress.

This readiness check is not cryptographic validation. It cannot prove that bytes are authentic or account for every possible later decryption pass. Verification against known originals is used for the research fixtures.

## Native helpers

Three native helpers reduce overhead:

- `vmp-native-tracker.dll` tracks memory writes in C++.
- `resource_scanner.dll` searches the mapped image in memory and reuses a discovered table as a hint. A full scan checks for ambiguity before extraction. Each scan has a 20-second budget.
- `block_budget.dll` stops execution slices at translated-block boundaries. It caches decoded instruction counts and checks the exact code bytes to detect self-modifying code. The cache and execution budgets remain bounded.

The optimized path avoids Python callbacks for each write and repeated intermediate images on disk. It retains the resource-readiness checks and writes the final reconstructed image once for extraction.

`--scheduler stock` uses Unicorn's instruction-count scheduler with the other optimizations. `--reference` uses Python write tracking and file-based scans for comparison. Small-block-heavy inputs may benefit less from the block scheduler.

An asynchronous Unicorn timeout is terminal. The interrupted state is not resumed or saved as a reusable checkpoint.

## Verified packed files

| Fixture | Resources | Bytes | Result |
| --- | ---: | ---: | --- |
| ResourcePaths-x64.vmp.exe | 7 | 152 | Exact match, including names and languages |
| ResourceSample-x64.vmp.exe | 4 | 593 | Exact match: menu, dialog, string table and RCDATA |
| pawdResourceFixture-x64.dll | 7 | 152 | Exact match, including names and languages |

These files had packing and additional protections enabled. All three inputs remained unchanged. The large DLL needs the higher budget shown in the command above. These results describe the tested files, not every VMProtect protection configuration.

## Measurements

| Fixture | Reference | Optimized | Less time |
| --- | ---: | ---: | ---: |
| ResourcePaths-x64.vmp.exe | 132.6 s | 74.4 s | 44% |
| ResourceSample-x64.vmp.exe | 160.5 s | 83.1 s | 48% |
| pawdResourceFixture-x64.dll | 380.0 s | 199.9 s | 47% |

Measured locally on 2026-11-16 using packaged executables, with the same 600-second and 15-billion-instruction limits. Times cover the full command, including startup and extraction. Optimized values are the median of two sequential runs. Every run matched the original resource bytes and metadata; input hashes stayed unchanged. Results depend on the file and machine.

## Diagnostic output

```text
vmp-resource-emulator.exe protected.exe --snapshot memory.exe
```

`--snapshot` keeps a reconstructed memory image and JSON report after emulation ends. This image is an analysis artifact, not a restored executable. Without this option, only the extracted resources and their manifest are kept.

The source, build scripts and dependency versions are documented in [Building and testing](BUILDING.md) and [third-party notices](../THIRD-PARTY-NOTICES.md).
