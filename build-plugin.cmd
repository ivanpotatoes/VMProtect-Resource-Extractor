@echo off
setlocal
cd /d "%~dp0"
if not "%~1"=="" set "VRE_SDK=%~1"
if not defined VRE_SDK (
  echo Pass the x64dbg pluginsdk path as the first argument or set VRE_SDK.
  exit /b 1
)
if not exist "%VRE_SDK%\_plugins.h" (
  echo The selected SDK has no _plugins.h. Pass the pluginsdk path or set VRE_SDK.
  exit /b 1
)
call "%~dp0scripts\find-msvc.cmd"
if errorlevel 1 exit /b 1
if not exist build\plugin mkdir build\plugin
if not exist dist mkdir dist
rc /nologo /i plugin /fo build\plugin\dialog.res plugin\dialog.rc
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /O2 /MT /W4 /utf-8 /LD /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /I"%VRE_SDK%" /Iplugin plugin\plugin.cpp plugin\ui.cpp plugin\backend.cpp build\plugin\dialog.res /Fo:build\plugin\ /Fe:dist\VMPResourceExtractor.dp64 /link /INCREMENTAL:NO /IMPLIB:build\plugin\VMPResourceExtractor.lib "%VRE_SDK%\x64dbg.lib" "%VRE_SDK%\x64bridge.lib" comctl32.lib shell32.lib ole32.lib uuid.lib user32.lib gdi32.lib
exit /b %errorlevel%
