@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
if not exist "%~dp0internal\Bootstrap.cmd" (
  echo [ERROR] Missing internal bootstrap. Please extract the entire ZIP.
  pause
  exit /b 2
)
call "%~dp0internal\Bootstrap.cmd"
exit /b %ERRORLEVEL%
