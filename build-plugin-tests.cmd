@echo off
setlocal
cd /d "%~dp0"
call "%~dp0scripts\find-msvc.cmd"
if errorlevel 1 exit /b 1
if not exist build\plugin-tests mkdir build\plugin-tests
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /WX /utf-8 plugin\backend.cpp tests\plugin_backend_harness.cpp /Fo:build\plugin-tests\ /Fe:build\plugin-backend-tests.exe
exit /b %errorlevel%
