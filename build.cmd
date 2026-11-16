@echo off
setlocal
call "%~dp0scripts\find-msvc.cmd"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
if not exist dist mkdir dist
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /utf-8 standalone\main.cpp /Fo:build\extractor.obj /Fe:dist\vmp-resource-extractor.exe /link /INCREMENTAL:NO
exit /b %errorlevel%
