@echo off
setlocal
call "%~dp0scripts\find-msvc.cmd"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
if not exist dist mkdir dist
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /utf-8 /LD standalone\native_scanner.cpp /Fo:build\native_scanner.obj /Fe:dist\resource_scanner.dll /link /INCREMENTAL:NO /IMPLIB:build\resource_scanner.lib
exit /b %errorlevel%
