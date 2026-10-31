@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul 2>nul
cd /d "%~dp0.."

echo ================================================================
echo OPTIONAL: Official CPython 3.14.10 graphical installer
 echo This is NOT needed to use the C-drive cleaner.
echo For automatic cleaning without system changes use Run_One_Click.bat.
echo Official GUI installer may change your Python installation if you consent.
echo ================================================================
echo.
set /p "ACK=Type INSTALL to download and open official installer: "
if not "%ACK%"=="INSTALL" (
  echo Cancelled. No download or installation performed.
  pause
  exit /b 0
)
set "PY_ARCH=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "PY_ARCH=arm64"
if /i "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "PY_ARCH=arm64"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "PY_ARCH=win32"
set "C_CLEANER_EXPECTED_SHA=92480239264744fe0386a1bd8275786fefa126e3129e56a68e22b52c73329965"
if /i "%PY_ARCH%"=="arm64" set "C_CLEANER_EXPECTED_SHA=5b9547e4edae2f6fb2fbfec5e26cf91b4ea191e3b07f7727d5a2c5c2cca93ed3"
if /i "%PY_ARCH%"=="win32" set "C_CLEANER_EXPECTED_SHA=c8f1a16db9afd76ca74b5f8e28eeaad408bca10894c9d080443bde83def3ed09"
set "C_CLEANER_EXE_NAME=python-3.14.10-%PY_ARCH%.exe"
if /i "%PY_ARCH%"=="win32" set "C_CLEANER_EXE_NAME=python-3.14.10.exe"
set "C_CLEANER_INSTALLER_URL=https://www.python.org/ftp/python/3.14.10/%C_CLEANER_EXE_NAME%"
set "C_CLEANER_INSTALLER_DIR=%~dp0..\Installer_Files"
if not exist "%C_CLEANER_INSTALLER_DIR%\" mkdir "%C_CLEANER_INSTALLER_DIR%" 2>nul
if not exist "%C_CLEANER_INSTALLER_DIR%\" (
  echo Cannot create installer folder.
  pause
  exit /b 1
)
set "C_CLEANER_INSTALLER_PATH=%C_CLEANER_INSTALLER_DIR%\%C_CLEANER_EXE_NAME%"
where powershell.exe >nul 2>nul
if errorlevel 1 (
  echo PowerShell is required to verify publisher and SHA256.
  pause
  exit /b 1
)
if not exist "%C_CLEANER_INSTALLER_PATH%" (
  echo [DOWNLOAD] %C_CLEANER_INSTALLER_URL%
  powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri $env:C_CLEANER_INSTALLER_URL -OutFile $env:C_CLEANER_INSTALLER_PATH; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 41 }"
  if errorlevel 1 (
    echo Download error. No installer launched.
    pause
    exit /b 1
  )
)
echo [VERIFY] Checking official SHA256 and Authenticode publisher.
powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; try { $f=$env:C_CLEANER_INSTALLER_PATH; $actual=(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant(); if ($actual -ne $env:C_CLEANER_EXPECTED_SHA) { throw 'SHA256 mismatch' }; $sig=Get-AuthenticodeSignature -LiteralPath $f; if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') { throw ('Installer signature not valid: '+$sig.Status) }; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 51 }"
if errorlevel 1 (
  echo Verification failed. Do NOT run this installer.
  pause
  exit /b 1
)
echo [OK] Official signed installer verified. Opening its setup UI.
echo Choose Install Now for current user; do not replace your FinGPT Python.
powershell.exe -NoProfile -Command "$ErrorActionPreference='Stop'; try { Start-Process -FilePath $env:C_CLEANER_INSTALLER_PATH -Wait; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 61 }"
set "RC=%ERRORLEVEL%"
echo Installer closed. Check installed Python separately.
pause
exit /b %RC%
