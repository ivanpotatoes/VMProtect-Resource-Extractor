VMProtect Resource Extractor - x64dbg plugin

Install
Copy VMPResourceExtractor.dp64 into x64dbg's x64/plugins folder,
then start x64dbg. This build supports x64 targets only.
No kernel driver, Python or emulator installation is needed.

Use
1. Load or attach to the program. Let it finish unpacking first.
2. Open Plugins > VMP Resource Extractor > Extract resources...
3. Select the main EXE or a loaded DLL. Refresh updates the list.
4. Click Scan. A running target is paused and stays paused.
5. Select a table if several were found. Choose a new output
   folder and click Extract. Use F9 to continue the target.

For a DLL, wait until its host has loaded and initialized it.
Browse chooses a parent folder and suggests an unused child folder.
Existing output folders are never overwritten, even if empty.

Output
Numbered .bin files contain the raw resource data. manifest.json
records type, ID or name, language, codepage, size, payload RVA,
module base and capture method. Dialogs, string tables and other
resource types retain their native format.

Commands
vre_ui
vre_scan
vre_extract "C:\work\extracted"
vre_dump "C:\work\extracted-next"
vre_status

Optional arguments (do not type the square brackets):
vre_scan [module-expression]
vre_extract "new output folder"[, candidate-index]
vre_dump "new output folder"[, module-expression][, candidate-index]

The default module is the main EXE. A module expression can specify
an address inside another loaded module. Candidate indices are
zero-based decimal numbers printed in the x64dbg log.

Commands run in the background. vre_status reports the result.
Scripts can query vre_busy(), vre_ok() and vre_candidates().

Notes
The plugin reads target memory without guest hooks, code patches
or breakpoint changes. Resuming the target or changing loaded
modules invalidates a scan; scan again before extracting.

A valid table does not prove unpacking has finished. Scan after
the resources are initialized. Unreadable or discarded sections
and missing PE headers can prevent capture. The module-image limit
is 256 MiB; capture and scanning have a 20-second budget.

This extracts the private encrypted resource tree. It does not
rebuild .rsrc, restore a runnable EXE or bypass anti-debug checks.

Ivan Kozlovsky
ivankozlovsky.com
contact@ivankozlovsky.com
