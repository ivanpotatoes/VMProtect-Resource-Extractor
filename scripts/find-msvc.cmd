@echo off
rem Called by build scripts inside their setlocal scope. Keep the toolchain
rem environment available to the caller.
if /i "%VSCMD_ARG_TGT_ARCH%"=="x64" (
  where cl >nul 2>nul
  if not errorlevel 1 exit /b 0
)

set "VRE_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VRE_VSWHERE%" (
  echo Visual Studio C++ build tools were not found. Install the Desktop development with C++ workload, or run from an x64 Native Tools command prompt.
  exit /b 1
)
set "VRE_VSROOT="
for /f "usebackq delims=" %%I in (`"%VRE_VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VRE_VSROOT=%%I"
if not defined VRE_VSROOT (
  echo No Visual Studio installation with the x64 C++ toolchain was found.
  exit /b 1
)
if not exist "%VRE_VSROOT%\VC\Auxiliary\Build\vcvars64.bat" (
  echo The selected Visual Studio installation has no vcvars64.bat.
  exit /b 1
)
call "%VRE_VSROOT%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
where cl >nul 2>nul
if errorlevel 1 (
  echo The x64 C++ compiler could not be initialized.
  exit /b 1
)
exit /b 0
