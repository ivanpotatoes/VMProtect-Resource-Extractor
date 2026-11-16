# VMProtect Resource Extractor

Extract VMProtect's private encrypted resources from an EXE or DLL. The tool discovers the resource table and key, decodes the contents and writes the resource metadata to JSON. You do not need the original file or a fixed address.

There are three ways to use it:

| Mode | When to use it | Output |
| --- | --- | --- |
| **Static CLI** | The encrypted table and payloads are present in the file | Raw resources and a manifest |
| **Emulation CLI** | A supported packed x64 file needs to initialize its resources first | Raw resources and a manifest |
| **x64dbg plugin** | The EXE or DLL is already loaded in a debug session | Raw resources and a manifest |

The input file is left unchanged. The plugin requires no kernel driver, Python installation or emulator executable.

![VMProtect Resource Extractor window](docs/images/plugin.png)

## Static extraction

Build `vmp-resource-extractor.exe`, then run:

```text
vmp-resource-extractor.exe protected.exe
vmp-resource-extractor.exe protected.dll --output extracted
vmp-resource-extractor.exe protected.exe --list
```

The default output is `protected.exe.resources`, beside the input. Choose a **new output folder**; its parent must already exist. Existing folders are never overwritten, even if empty.

If more than one valid table is found, inspect them with `--list` and select one explicitly:

```text
vmp-resource-extractor.exe protected.exe --table-rva 0x12345 --key 0x12345678 --output extracted
```

Use the values reported for your file. Hexadecimal arguments require the `0x` prefix.

## Emulation for packed files

The emulator runs protected startup code inside Unicorn. It models the Windows calls needed by the tested files; the target is not launched as a Windows process.

```text
vmp-resource-emulator.exe protected.exe --output extracted
vmp-resource-emulator.exe protected.dll --seconds 600 --instructions 15000000000
```

The packaged executable includes Python, Unicorn, Capstone and the extractor. Defaults are **240 seconds** and a **five-billion-instruction budget**. Larger files can need more time. Unsupported APIs, exceptions or exhausted budgets produce an error.

Three packed research files were verified against their originals. This does not cover every combination of VMProtect options. See [emulation details and measurements](docs/EMULATION.md).

## x64dbg plugin

### 1. Install

Copy `VMPResourceExtractor.dp64` into the `plugins` folder beside `x64dbg.exe`, then start the debugger. This plugin build supports **x64 targets**.

### 2. Open the extractor

Open **Plugins > VMP Resource Extractor > Extract resources...**

![x64dbg plugin menu](docs/images/menu.png)

### 3. Select and scan

Load or attach to your program and let it finish unpacking. For a DLL, wait until the host has loaded and initialized it.

Select the EXE or DLL in **Module**, then click **Scan**. Use **Refresh** after a new module is loaded. A running target is paused before memory is copied and remains paused afterward.

### 4. Extract

If several tables are found, select the one you want. Choose a new output folder and click **Extract**. **Browse** selects the parent folder and suggests an unused child folder. Use **F9** to continue the target when finished.

The plugin does not patch target code, install guest hooks or change breakpoint settings. Resuming the target or loading/unloading a DLL invalidates the scan; scan again before extracting.

![About VMProtect Resource Extractor](docs/images/about.png)

### Command bar

```text
vre_ui
vre_scan
vre_extract "C:\work\extracted"
vre_dump "C:\work\extracted-next"
vre_status
```

`vre_scan` uses the main EXE by default. `vre_dump` combines scanning and extraction. Both accept an optional address expression for another loaded module:

```text
vre_scan [module-expression]
vre_extract "new output folder"[, candidate-index]
vre_dump "new output folder"[, module-expression][, candidate-index]
```

Square brackets indicate optional arguments; do not type them. Candidate indices are zero-based decimal numbers printed in the log. Commands run in the background. `vre_status` reports the result; scripts can query `vre_busy()`, `vre_ok()` and `vre_candidates()`.

## What gets extracted

The output folder contains numbered files such as `resource-0001.bin` and `manifest.json`. Each record includes the resource type, ID or name, language, codepage, size, payload RVA and output filename. Named and numeric identifiers retain their types.

Resources keep their native format. Dialogs and string tables remain binary resource data; an icon resource does not automatically become a complete ICO file. The plugin also records the loaded module base and capture method.

This tool extracts the private resource tree. It does not rebuild `.rsrc` or produce a restored executable. Ordinary resources left in the PE resource directory, such as the manifest, are not included.

## Tested versions

| VMProtect | Static x64 EXE and DLL | Live x64dbg extraction |
| --- | --- | --- |
| 3.3.1 | Verified | Verified |
| 3.4.0 | Verified | Not yet tested live |
| 3.5.0 | Verified | Not yet tested live |
| 3.6.0 | Verified | Not yet tested live |
| 3.8.0 | Verified | Not yet tested live |
| 3.9.4 | Verified | Not yet tested live |
| 3.10.1 | Verified | Verified |

Static and mapped-image backend tests covered **21 files and 126 resources**, all matching the originals byte for byte. These fixtures used Resource Protection only and included menus, dialogs, string tables, custom data, named resources and multiple languages. Live plugin tests also covered automatic pausing, stale scans, existing output folders, breakpoint preservation and unload/reload.

PE32 parsing has synthetic tests. **Real protected x32 files have not been validated**; emulation and the plugin currently support x64 only.

## Limits

- Static extraction needs the table and payloads to be present in the file. Use emulation or the plugin when they appear only after initialization.
- A valid table is not a payload integrity check. With the plugin, wait until the resources have finished unpacking before scanning.
- The plugin requires readable PE headers and sections. Missing or discarded sections can prevent capture. Its module limit is 256 MiB, with a 20-second capture/scan budget.
- The emulator provides the Windows behavior needed by the tested files, rather than a complete loader or exception dispatcher. Additional protection combinations can fail.

## Build and tests

The C++ tools need Visual Studio C++ build tools and the Windows SDK. The scripts use an existing x64 developer shell or locate Visual Studio through `vswhere`.

```powershell
.\build.cmd
.\build-plugin.cmd "C:\path\to\pluginsdk"
```

Outputs are written to `dist`. The plugin SDK path can also be supplied through `VRE_SDK`. See [build instructions and tests](docs/BUILDING.md) for the emulator, CMake and fixture setup.

## Research and contact

Built from my VMProtect Resource Protection research across versions 3.3.1–3.10.1.

- Research and other projects: [ivankozlovsky.com](https://ivankozlovsky.com)
- Contact: [contact@ivankozlovsky.com](mailto:contact@ivankozlovsky.com)
- PGP: [ivankozlovsky.com/pgp.asc](https://ivankozlovsky.com/pgp.asc)

## License

The original project code is under the [MIT License](LICENSE). Third-party components keep their own licenses. The packaged emulator includes GPL-2.0 Unicorn; see [third-party notices](THIRD-PARTY-NOTICES.md) and [license texts](licenses).

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=ivanpotatoes/VMProtect-Resource-Extractor&type=Date)](https://www.star-history.com/?repos=ivanpotatoes%2FVMProtect-Resource-Extractor&type=date&legend=top-left)
