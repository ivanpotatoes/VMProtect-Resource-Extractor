@echo off
setlocal
cd /d "%~dp0"
call build.cmd
if errorlevel 1 exit /b 1
call build-native-tracker.cmd
if errorlevel 1 exit /b 1
call build-native-scanner.cmd
if errorlevel 1 exit /b 1
call build-block-budget.cmd
if errorlevel 1 exit /b 1
if not exist build\vendor\pyinstaller-6.22.3\PyInstaller\bootloader\Windows-64bit-intel\run.exe call build-bootloader.cmd
if errorlevel 1 exit /b 1
set "PYTHONPATH=%CD%\build\vendor\pyinstaller-6.22.3"
py -m PyInstaller --noconfirm --clean --onefile --name vmp-resource-emulator --distpath dist --workpath build\pyinstaller --specpath build --collect-all unicorn --collect-all capstone --add-binary "%CD%\dist\vmp-resource-extractor.exe;." --add-binary "%CD%\dist\vmp-native-tracker.dll;." --add-binary "%CD%\dist\resource_scanner.dll;." --add-binary "%CD%\dist\block_budget.dll;." standalone\emulate.py
exit /b %errorlevel%
