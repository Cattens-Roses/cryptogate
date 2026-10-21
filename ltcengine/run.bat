@echo off
setlocal EnableExtensions
cd /d "%~dp0"

rem Default: build, then run.
rem Skip rebuild:  run.bat --no-build [args...]

if /I "%~1"=="--no-build" (
  if not exist "bin\ltcengine.exe" (
    echo error: bin\ltcengine.exe not found — run build.bat first
    exit /b 1
  )
  call :launch %2 %3 %4 %5 %6 %7 %8 %9
  exit /b %ERRORLEVEL%
)

call "%~dp0build.bat"
if errorlevel 1 exit /b 1

call :launch %*
exit /b %ERRORLEVEL%

:launch
echo Starting ltcengine...
"bin\ltcengine.exe" %*
exit /b %ERRORLEVEL%
