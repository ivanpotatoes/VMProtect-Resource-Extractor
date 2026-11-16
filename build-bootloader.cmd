@echo off
setlocal
cd /d "%~dp0"
if not exist build\vendor\pyinstaller-6.22.3\bootloader\waf (
  py -m pip download pyinstaller==6.22.3 --no-binary=pyinstaller --no-deps --dest build\vendor
  if errorlevel 1 exit /b 1
  py -c "import tarfile; tarfile.open('build/vendor/pyinstaller-6.22.3.tar.gz').extractall('build/vendor',filter='data')"
  if errorlevel 1 exit /b 1
)
call "%~dp0scripts\find-msvc.cmd"
if errorlevel 1 exit /b 1
cd build\vendor\pyinstaller-6.22.3\bootloader
py waf all --no-cfg
exit /b %errorlevel%
