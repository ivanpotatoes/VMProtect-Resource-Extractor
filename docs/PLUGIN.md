# Plugin commands

The plugin scans the main EXE unless you supply an address expression for another loaded module.

```text
vre_scan [module-expression]
vre_extract "new output folder"[, candidate-index]
vre_dump "new output folder"[, module-expression][, candidate-index]
```

Square brackets mark optional arguments; do not type them. Candidate indices are zero-based decimal numbers shown in the log. When several tables are found, select one explicitly.

Commands queue background work. `vre_status` prints the current status. Scripts can use `vre_busy()`, `vre_ok()` and `vre_candidates()` to read the job state, last result and table count.

## Capture

Scan after unpacking has finished. A table can become readable before its payloads are ready; the plugin does not track earlier memory writes or prove that resource initialization is complete.

The selected module must have readable PE headers and sections. Capture fails on unreadable or discarded sections rather than filling them with zero bytes. The module-image limit is 256 MiB, with a 20-second budget for capture and scanning.

The plugin copies memory while the target is paused, then extracts from that copy. It leaves the target paused. Resuming execution, switching sessions or loading/unloading a DLL invalidates the scan.

## Static table selection

The standalone extractor can also list and select tables:

```text
vmp-resource-extractor.exe protected.exe --list
vmp-resource-extractor.exe protected.exe --table-rva 0x12345 --key 0x12345678 --output extracted
```

Use the values reported for your file. Hexadecimal arguments need the `0x` prefix. The output folder must be new, and its parent directory must already exist.
