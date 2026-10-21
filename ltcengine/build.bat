@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where cmake >nul 2>&1
if errorlevel 1 (
  echo error: cmake not found on PATH
  echo Install CMake or open a "Developer Command Prompt for VS"
  exit /b 1
)

if not exist "build\CMakeCache.txt" (
  echo Configuring...
  cmake -B build -A x64
  if errorlevel 1 exit /b 1
)

echo Building Release...
cmake --build build --config Release --target ltcengine
if errorlevel 1 exit /b 1

if not exist "bin\ltcengine.exe" (
  echo error: bin\ltcengine.exe missing after build
  exit /b 1
)

echo Build OK: bin\ltcengine.exe
exit /b 0
