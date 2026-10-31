@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul 2>nul
rem Force reliable Chinese console text on Windows code pages such as cp1252.
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
cd /d "%~dp0.."

rem C: CLEANER v3.3 - Windows 10/11. Default entry opens the local GUI.
rem If Python is missing, downloads/verifies/extracts CPython embedded ZIP.
rem No permanent PATH changes, admin privilege, conda modifications or pip.
set "TOOL_DIR=%~dp0..\"
set "CLEANER_PY=%TOOL_DIR%C_Drive_Cleanup.py"
if not exist "%CLEANER_PY%" (
  echo [ERROR] C_Drive_Cleanup.py missing. Fully extract the kit first.
  pause
  exit /b 2
)

rem v3.3 GUI-only runtime. No legacy automatic deletion CLI modes.
set "CLEAN_MODE=gui"
set "CLEAN_ARGS="
set "CLEANER_PY=%TOOL_DIR%Advanced_Disk_Studio.py"

echo ================================================================
echo C: CLEANER v3.3 ^| %CLEAN_MODE% mode
if /i "%CLEAN_MODE%"=="safe" echo CAUTION: Disposable cache files WILL be deleted automatically.
if /i "%CLEAN_MODE%"=="scan" echo Read-only file scan, NO deletion.
if /i "%CLEAN_MODE%"=="gui" echo Browser GUI: read-only scan first, manual selection + double confirm to delete.
echo Existing Python/Anaconda will be reused; otherwise private CPython.
echo ================================================================

set "PYTHON_EXE="
set "PYTHON_FROM="
set "C_CLEANER_BOOTSTRAP_SOURCE="
set "C_CLEANER_BOOTSTRAP_RUNTIME_ROOT="
if /i "%C_CLEANER_FORCE_PORTABLE%"=="1" goto :Portable
call :FindExistingPython
if defined PYTHON_EXE goto :RunCleaner

:Portable
call :BootstrapPrivatePython
if errorlevel 1 (
  echo.
  echo [ERROR] Bootstrap failed. No cleanup was executed.
  echo A working Internet connection is needed only for the first download.
  echo Alternatively place the official ZIP in Runtime_Offline and retry.
  echo See README.md for details. Your projects were not modified.
  pause
  exit /b 3
)
if not defined PYTHON_EXE (
  echo [ERROR] No working Python after bootstrap. No cleanup was executed.
  pause
  exit /b 4
)

:RunCleaner
echo.
echo [OK] Python: "%PYTHON_EXE%"
echo [OK] Origin: %PYTHON_FROM%
echo [RUN] %CLEAN_MODE% mode; JSON reports in LocalAppData\CDriveCleanupReports
echo ---------------------------------------------------------------
if defined CONDA_EXE if exist "%CONDA_EXE%" set "C_CLEANER_CONDA_EXE=%CONDA_EXE%"
if not exist "%CLEANER_PY%" (
  echo [ERROR] Main Python file not found: "%CLEANER_PY%"
  pause
  exit /b 2
)
"%PYTHON_EXE%" -I "%CLEANER_PY%" %CLEAN_ARGS%
set "CLEAN_RC=%ERRORLEVEL%"
echo.
echo ================================================================
echo Result exit code: %CLEAN_RC%
echo Report folder: "%LOCALAPPDATA%\CDriveCleanupReports"
echo ================================================================
if not "%CLEAN_RC%"=="0" echo [ERROR] Check the text above for error details.
pause
exit /b %CLEAN_RC%

:FindExistingPython
if defined PYTHON_FOR_CLEANUP call :TryPython "%PYTHON_FOR_CLEANUP%" "user override"
if not defined PYTHON_EXE if defined CONDA_PREFIX call :TryPython "%CONDA_PREFIX%\python.exe" "active Conda"
if not defined PYTHON_EXE if defined CONDA_ROOT call :TryPython "%CONDA_ROOT%\python.exe" "Conda root"
if not defined PYTHON_EXE if defined MAMBA_ROOT_PREFIX call :TryPython "%MAMBA_ROOT_PREFIX%\python.exe" "Mamba root"
if not defined PYTHON_EXE if defined CONDA_EXE call :TryCondaExe
if not defined PYTHON_EXE (
  for /f "usebackq delims=" %%P in (`where python.exe 2^>nul`) do (
    if not defined PYTHON_EXE call :TryPython "%%P" "PATH"
  )
)
if not defined PYTHON_EXE (
  for /f "usebackq delims=" %%P in (`where python3.exe 2^>nul`) do (
    if not defined PYTHON_EXE call :TryPython "%%P" "PATH"
  )
)
if not defined PYTHON_EXE (
  for /f "delims=" %%P in ('py -3 -I -c "import sys;print(sys.executable)" 2^>nul') do (
    if not defined PYTHON_EXE call :TryPython "%%P" "Windows py launcher"
  )
)
if not defined PYTHON_EXE (
  for %%K in ("HKCU\Software\Python" "HKLM\Software\Python" "HKLM\Software\WOW6432Node\Python") do (
    for /f "tokens=1,2,*" %%A in ('reg query "%%~K" /s /v ExecutablePath 2^>nul') do (
      if /i "%%A"=="ExecutablePath" if not defined PYTHON_EXE call :TryPython "%%C" "PEP 514 registry"
    )
  )
)
if not defined PYTHON_EXE call :CheckRoot "%LOCALAPPDATA%\Programs\Python"
if not defined PYTHON_EXE call :CheckRoot "%LOCALAPPDATA%\Programs"
if not defined PYTHON_EXE call :CheckRoot "%LOCALAPPDATA%"
if not defined PYTHON_EXE call :CheckRoot "%USERPROFILE%"
if not defined PYTHON_EXE call :CheckRoot "%PROGRAMDATA%"
if not defined PYTHON_EXE call :CheckRoot "%ProgramFiles%"
if not defined PYTHON_EXE call :CheckRoot "%ProgramFiles(x86)%"
if not defined PYTHON_EXE (
  for %%D in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if not defined PYTHON_EXE if exist "%%D:\" (
      call :CheckRoot "%%D:\"
      if not defined PYTHON_EXE call :CheckRoot "%%D:\Tools"
      if not defined PYTHON_EXE call :CheckRoot "%%D:\Dev"
      if not defined PYTHON_EXE call :CheckRoot "%%D:\Programs"
      if not defined PYTHON_EXE call :CheckRoot "%%D:\Software"
      if not defined PYTHON_EXE call :CheckRoot "%%D:\Apps"
    )
  )
)
exit /b 0

:TryCondaExe
for %%Q in ("%CONDA_EXE%") do call :TryPython "%%~dpQ..\python.exe" "Conda executable"
exit /b 0

:TryPython
if defined PYTHON_EXE exit /b 0
if "%~1"=="" exit /b 0
if not exist "%~1" exit /b 0
rem Microsoft Store command aliases are not interpreters and can pop up Store UI.
if /i "%~dp1"=="%LOCALAPPDATA%\Microsoft\WindowsApps\" exit /b 0
"%~1" -I -c "import sys,json,ctypes,pathlib;sys.exit(0 if (3,10) <= sys.version_info[:2] < (4,0) else 1)" >nul 2>nul
if errorlevel 1 exit /b 0
set "PYTHON_EXE=%~1"
set "PYTHON_FROM=%~2"
set "C_CLEANER_BOOTSTRAP_SOURCE=existing"
exit /b 0

:CheckRoot
if defined PYTHON_EXE exit /b 0
if "%~1"=="" exit /b 0
set "CURRENT_ROOT=%~1"
if "%CURRENT_ROOT:~-1%"=="\" set "CURRENT_ROOT=%CURRENT_ROOT:~0,-1%"
if not exist "%CURRENT_ROOT%\" exit /b 0
if exist "%CURRENT_ROOT%\python.exe" call :TryPython "%CURRENT_ROOT%\python.exe" "common location"
if defined PYTHON_EXE exit /b 0
for /d %%P in ("%CURRENT_ROOT%\Python*" "%CURRENT_ROOT%\anaconda*" "%CURRENT_ROOT%\miniconda*" "%CURRENT_ROOT%\miniforge*" "%CURRENT_ROOT%\mambaforge*" "%CURRENT_ROOT%\pypy*") do (
  if not defined PYTHON_EXE if exist "%%~fP\python.exe" call :TryPython "%%~fP\python.exe" "common location"
)
exit /b 0

:BootstrapPrivatePython
rem Avoid Python installation/PATH changes. Official embedded Python is private.
set "PY_VERSION=3.14.10"
set "PY_ARCH=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "PY_ARCH=arm64"
if /i "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "PY_ARCH=arm64"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "PY_ARCH=win32"
set "C_CLEANER_EXPECTED_SHA=90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159"
if /i "%PY_ARCH%"=="arm64" set "C_CLEANER_EXPECTED_SHA=bbe116bb1248820359cbf25127ac5c7794ea161869d83686cfbc9a45203ff836"
if /i "%PY_ARCH%"=="win32" set "C_CLEANER_EXPECTED_SHA=11a28e8c00a6d8f56b0a6164d52546133a9ed015a5b33e04536917e4fd6e306c"
set "ZIP_NAME=python-%PY_VERSION%-embed-%PY_ARCH%.zip"
set "RUNTIME_ROOT=%TOOL_DIR%_runtime"
if defined C_CLEANER_RUNTIME_ROOT set "RUNTIME_ROOT=%C_CLEANER_RUNTIME_ROOT%"
if not exist "%RUNTIME_ROOT%\" mkdir "%RUNTIME_ROOT%" 2>nul
if not exist "%RUNTIME_ROOT%\" (
  echo [WARN] Cannot write next to tool. Using LocalAppData.
  call :TryFallbackRuntime
)
if not exist "%RUNTIME_ROOT%\" exit /b 1
set "RUNTIME_DIR=%RUNTIME_ROOT%\python-%PY_VERSION%-%PY_ARCH%"
set "C_CLEANER_BOOTSTRAP_RUNTIME_ROOT=%RUNTIME_ROOT%"
if exist "%RUNTIME_DIR%\python.exe" (
  "%RUNTIME_DIR%\python.exe" -I -c "import sys,ssl,json,ctypes;sys.exit(0 if sys.version_info[:3] == (3,14,10) else 1)" >nul 2>nul
  if not errorlevel 1 (
    call :TryPython "%RUNTIME_DIR%\python.exe" "verified private runtime"
    if defined PYTHON_EXE (
      set "C_CLEANER_BOOTSTRAP_SOURCE=private_reuse"
      exit /b 0
    )
  )
)
if exist "%RUNTIME_DIR%\" (
  echo [ERROR] Existing private runtime is invalid. Refusing to overwrite it:
  echo "%RUNTIME_DIR%"
  exit /b 1
)
where powershell.exe >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Windows PowerShell is required for verified download/extraction.
  exit /b 1
)
set "OFFLINE_ZIP=%TOOL_DIR%Runtime_Offline\%ZIP_NAME%"
set "CACHE_ROOT=%RUNTIME_ROOT%\downloads"
if not exist "%CACHE_ROOT%\" mkdir "%CACHE_ROOT%" 2>nul
if not exist "%CACHE_ROOT%\" exit /b 1
set "CACHE_ZIP=%CACHE_ROOT%\%ZIP_NAME%"
set "C_CLEANER_ZIP_PATH=%OFFLINE_ZIP%"
if exist "%OFFLINE_ZIP%" (
  echo [INFO] Using pre-downloaded official package: "%OFFLINE_ZIP%"
) else (
  set "C_CLEANER_ZIP_PATH=%CACHE_ZIP%"
  if exist "%CACHE_ZIP%" (
    echo [INFO] Using downloaded package from local cache.
  ) else (
    if /i "%C_CLEANER_ALLOW_DOWNLOAD%"=="0" (
      echo [ERROR] Download disabled and no offline archive found.
      echo Place the official %ZIP_NAME% into Runtime_Offline.
      exit /b 1
    )
    set "C_CLEANER_DOWNLOAD_URL=https://www.python.org/ftp/python/3.14.10/%ZIP_NAME%"
    set "C_CLEANER_ZIP_PATH=%CACHE_ZIP%.part"
    echo [DOWNLOAD] Official Python %PY_VERSION% %PY_ARCH% from python.org ...
    powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri $env:C_CLEANER_DOWNLOAD_URL -OutFile $env:C_CLEANER_ZIP_PATH; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 31 }"
    if errorlevel 1 exit /b 1
    call :VerifyHash
    if errorlevel 1 (
      echo [ERROR] Downloaded ZIP failed pinned SHA256 validation. STOP.
      exit /b 1
    )
    if exist "%CACHE_ZIP%" exit /b 1
    move /y "%CACHE_ZIP%.part" "%CACHE_ZIP%" >nul
    if errorlevel 1 exit /b 1
    set "C_CLEANER_ZIP_PATH=%CACHE_ZIP%"
  )
)
call :VerifyHash
if errorlevel 1 (
  echo [ERROR] Wrong SHA256. Refusing to extract or execute archive.
  exit /b 1
)
set "STAGE=%RUNTIME_ROOT%\_staging_%PY_ARCH%_%RANDOM%_%RANDOM%"
if exist "%STAGE%\" (
  echo [ERROR] Staging directory collision. Retry.
  exit /b 1
)
mkdir "%STAGE%" 2>nul
if not exist "%STAGE%\" exit /b 1
set "C_CLEANER_STAGE=%STAGE%"
echo [EXTRACT] Verified Python ZIP into private folder.
powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; try { Expand-Archive -LiteralPath $env:C_CLEANER_ZIP_PATH -DestinationPath $env:C_CLEANER_STAGE; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 41 }"
if errorlevel 1 (
  echo [ERROR] Extraction failed; partial folder retained for diagnosis.
  exit /b 1
)
if not exist "%STAGE%\python.exe" (
  echo [ERROR] Official ZIP extraction does not contain python.exe.
  exit /b 1
)
"%STAGE%\python.exe" -I -c "import sys,ssl,json,ctypes,pathlib;sys.exit(0 if sys.version_info[:3] == (3,14,10) else 1)" >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Private Python failed startup validation. Runtime not activated.
  exit /b 1
)
if exist "%RUNTIME_DIR%\" (
  echo [ERROR] Runtime directory was created concurrently. Refusing overwrite.
  exit /b 1
)
move "%STAGE%" "%RUNTIME_DIR%" >nul
if errorlevel 1 (
  echo [ERROR] Cannot finalize the private Python directory.
  exit /b 1
)
call :TryPython "%RUNTIME_DIR%\python.exe" "official portable CPython %PY_VERSION%"
if not defined PYTHON_EXE exit /b 1
set "C_CLEANER_BOOTSTRAP_SOURCE=private_new"
echo [OK] Private Python deployed. No system installation or PATH change.
exit /b 0

:TryFallbackRuntime
if not defined LOCALAPPDATA exit /b 1
set "RUNTIME_ROOT=%LOCALAPPDATA%\CDriveCleanupKit\runtime"
if not exist "%RUNTIME_ROOT%\" mkdir "%RUNTIME_ROOT%" 2>nul
exit /b 0

:VerifyHash
powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; try { $actual=(Get-FileHash -LiteralPath $env:C_CLEANER_ZIP_PATH -Algorithm SHA256).Hash.ToLowerInvariant(); if($actual -ne $env:C_CLEANER_EXPECTED_SHA) { [Console]::Error.WriteLine('SHA256 mismatch. Expected: '+$env:C_CLEANER_EXPECTED_SHA+' Actual: '+$actual); exit 51 }; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 52 }"
exit /b %ERRORLEVEL%
