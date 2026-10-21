@echo off
setlocal
set "ROOT=%~dp0"
set "EXE=%ROOT%bin\ltcengine.exe"
if not exist "%EXE%" (
  echo ltcengine.exe not found. Build first:
  echo   cmake -B build ^&^& cmake --build build --config Release
  exit /b 1
)
"%EXE%" %*
