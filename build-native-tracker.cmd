@echo off
setlocal
call "%~dp0scripts\find-msvc.cmd"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
if not exist dist mkdir dist
py -c "from pathlib import Path; import unicorn; print(Path(unicorn.__file__).parent / 'include')" > build\unicorn-include.txt
if errorlevel 1 exit /b 1
set /p "UNICORN_HEADERS=" < build\unicorn-include.txt
if not exist "%UNICORN_HEADERS%\unicorn\unicorn.h" (
  echo Unicorn headers not found: %UNICORN_HEADERS%
  exit /b 1
)
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /WX /LD /utf-8 /I"%UNICORN_HEADERS%" standalone\native_tracker.cpp /Fo:build\native_tracker.obj /Fe:dist\vmp-native-tracker.dll /link /INCREMENTAL:NO /IMPLIB:build\native_tracker.lib
exit /b %errorlevel%
