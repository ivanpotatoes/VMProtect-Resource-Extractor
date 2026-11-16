@echo off
setlocal
cd /d "%~dp0"
call "%~dp0scripts\find-msvc.cmd"
if errorlevel 1 exit /b 1
for /f "delims=" %%I in ('py -c "import capstone,pathlib; print(pathlib.Path(capstone.__file__).parent / 'include')"') do set "CAPSTONE_INCLUDE=%%I"
if not exist build mkdir build
if not exist dist mkdir dist
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /utf-8 /LD /I"%CAPSTONE_INCLUDE%" standalone\block_budget.cpp /Fo:build\block_budget.obj /Fe:dist\block_budget.dll /link /INCREMENTAL:NO /IMPLIB:build\block_budget.lib
exit /b %errorlevel%
