@echo off
rem Resolve the repository root FIRST, before the :scan_args loop runs. That loop
rem calls `shift`, which corrupts %~dp0 (it then resolves to just the drive
rem letter, making ROOT point at the drive root and failing the source check). This script lives in
rem Build\Executors\, so the repo root is two levels up. Do not use "%~dp0.."
rem (one level up resolves to Build\ itself).
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
rem Create.bat - one-shot release builder for the Hypervisor and Client.
rem What: cleans the release and scratch trees, resolves MSBuild, builds both
rem   solutions in Release|x64, stages Hypervisor.sys and Client.exe under
rem   Build\Release, and verifies every shipped artifact. Why one script: the
rem   driver and client share an ABI and must be built from the same tree and
rem   configuration, so a partial or mismatched release is never useful.
rem How: numbered stages below; every gate is fail-closed.
rem
rem Intermediates and native output live in %TEMP%\hypervisor_build, outside
rem the repository. Build\Release is the only generated directory that ships.
rem
rem Environment overrides (all optional):
rem   CREATE_NO_PAUSE=1              do not pause at the end
rem   AMEGER_NO_PAUSE=1              do not pause at the end (takes precedence)
rem   AMEGER_NO_COLOR=1              disable ANSI colour
rem   AMEGER_PLATFORM_TOOLSET        override the detected toolset
rem   AMEGER_WINDOWS_SDK_VERSION     override the Windows SDK version
rem   AMEGER_KEEP_PDB=1              ship the .pdb next to the binaries
rem
rem Command line:
rem   Create.bat [/nopause] [/no-mapper]
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
set "NO_MAPPER=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if defined AMEGER_NO_PAUSE set "NO_PAUSE=%AMEGER_NO_PAUSE%"
rem Scan every command-line argument for the /nopause and /no-mapper flags.
:scan_args
if "%~1"=="" goto :args_done
if /i "%~1"=="/nopause" set "NO_PAUSE=1"
if /i "%~1"=="/no-mapper" set "NO_MAPPER=1"
shift
goto :scan_args
:args_done

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
set "SCRATCH=%TEMP%\hypervisor_build"
set "NATIVE_OUT=%SCRATCH%\bin"
set "NATIVE_INT=%SCRATCH%\obj"
set "HV_SLN=%BUILD_DIR%\Template\Hypervisor\Hypervisor.sln"
set "CLIENT_SLN=%BUILD_DIR%\Template\Client\Client.sln"
set "HV_PROJ=%BUILD_DIR%\Template\Hypervisor\Hypervisor.vcxproj"
set "CLIENT_PROJ=%BUILD_DIR%\Template\Client\Client.vcxproj"
set "MAPPER_SLN=%BUILD_DIR%\Template\Mapper\Mapper.sln"
set "MAPPER_PROJ=%BUILD_DIR%\Template\Mapper\Mapper.vcxproj"
set "HV_ASM=%ROOT%\Hypervisor\Utilities\x64.asm"
set "CLIENT_HEADER=%ROOT%\Client\Library\Hypervisor.h"
set "PLATFORM_HEADER=%ROOT%\Hypervisor\Source\Memory\Definitions.h"
set "CONFIG_NAME=Release"
set "PLATFORM_NAME=x64"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD="
set "TOOLSET="
set "SDK_VERSION="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%5%C_RESET%] Checking MSBuild...
echo.
call :find_msbuild
if errorlevel 1 goto :msbuild_error
call :select_toolset
set "TOOLSET_ARG="
if defined TOOLSET set "TOOLSET_ARG=/p:PlatformToolset=%TOOLSET%"
set "SDK_ARG="
if defined SDK_VERSION set "SDK_ARG=/p:WindowsTargetPlatformVersion=%SDK_VERSION%"
echo   %C_GREEN%[+]%C_RESET% MSBuild: %C_GREEN%%MSBUILD%%C_RESET%
if defined TOOLSET echo   %C_GREEN%[+]%C_RESET% Platform toolset: %C_GREEN%%TOOLSET%%C_RESET%
if defined SDK_VERSION echo   %C_GREEN%[+]%C_RESET% Windows SDK: %C_GREEN%%SDK_VERSION%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%5%C_RESET%] Checking projects...
echo.
if not exist "%HV_SLN%" goto :source_error
if not exist "%CLIENT_SLN%" goto :source_error
if not exist "%HV_PROJ%" goto :source_error
if not exist "%CLIENT_PROJ%" goto :source_error
if not exist "%HV_ASM%" goto :source_error
if not exist "%CLIENT_HEADER%" goto :source_error
if not exist "%PLATFORM_HEADER%" goto :source_error
if "%NO_MAPPER%"=="0" (
  if not exist "%MAPPER_SLN%" goto :source_error
  if not exist "%MAPPER_PROJ%" goto :source_error
)
echo   %C_GREEN%[+]%C_RESET% Solutions, projects, MASM source, shared ABI header and platform header present.
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%5%C_RESET%] Cleaning release and build scratch...
echo.
call :clean_directory "%OUT_ROOT%"
if errorlevel 1 goto :clean_error
call :clean_directory "%SCRATCH%"
if errorlevel 1 goto :clean_error
call :clean_directory "%ROOT%\x64"
if errorlevel 1 goto :clean_error
call :clean_directory "%ROOT%\Hypervisor\x64"
if errorlevel 1 goto :clean_error
call :clean_directory "%ROOT%\Client\x64"
if errorlevel 1 goto :clean_error
call :clean_directory "%ROOT%\Hypervisor\Intermediate"
if errorlevel 1 goto :clean_error
call :clean_directory "%ROOT%\Client\Intermediate"
if errorlevel 1 goto :clean_error
call :prepare_scratch
if errorlevel 1 goto :clean_error
echo   %C_GREEN%[+]%C_RESET% Clean layout prepared in: %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo.

echo [%C_GREEN%4%C_RESET%/%C_GREEN%5%C_RESET%] Building Hypervisor, Mapper and Client...
echo.
call :build_solution "%HV_SLN%" "hypervisor"
if errorlevel 1 goto :build_error
call :build_solution "%CLIENT_SLN%" "client"
if errorlevel 1 goto :build_error
if "%NO_MAPPER%"=="0" (
  call :build_solution "%MAPPER_SLN%" "mapper"
  if errorlevel 1 goto :build_error
)
echo.
echo   %C_GREEN%[+]%C_RESET% Native output: %C_GREEN%%NATIVE_OUT%%C_RESET%
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%5%C_RESET%] Staging and verifying release...
echo.
call :deploy_binaries
if errorlevel 1 goto :deploy_error
call :sweep_artifacts
if errorlevel 1 goto :cleanup_error
echo.
call :verify_release
if errorlevel 1 goto :verify_error
echo.
echo   %C_GREEN%[+]%C_RESET% Release staged in %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.

echo Build completed successfully.
echo.
echo Driver: %C_GREEN%%OUT_ROOT%\Hypervisor.sys%C_RESET%
echo Client: %C_GREEN%%OUT_ROOT%\Client.exe%C_RESET%
if "%NO_MAPPER%"=="0" echo Mapper: %C_GREEN%%OUT_ROOT%\Mapper.sys%C_RESET%
echo.

if "%NO_PAUSE%"=="0" pause
exit /b 0

rem ---------------------------------------------------------------------------
rem Stages
rem ---------------------------------------------------------------------------

:build_solution
rem %~1 = solution, %~2 = log label.
set "SOLUTION=%~1"
set "LOG=%SCRATCH%\build_%~2.log"
echo   %C_GREEN%Building%C_RESET% %SOLUTION% %C_RED%(%PLATFORM_NAME%)%C_RESET%
"%MSBUILD%" "%SOLUTION%" /nologo /m /nodeReuse:false /v:minimal /t:Rebuild /p:IgnoreWarnIntDirInTempDetected=true /p:Configuration=%CONFIG_NAME% /p:Platform=%PLATFORM_NAME% %TOOLSET_ARG% %SDK_ARG% > "%LOG%" 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: build failed. Last 40 lines of %LOG%%C_RESET%
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -Tail 40 -LiteralPath '%LOG%'"
  exit /b 1
)
exit /b 0

:deploy_binaries
call :stage "%NATIVE_OUT%\Hypervisor.sys" "%OUT_ROOT%\Hypervisor.sys"
if errorlevel 1 exit /b 1
call :stage "%NATIVE_OUT%\Client.exe" "%OUT_ROOT%\Client.exe"
if errorlevel 1 exit /b 1
if "%NO_MAPPER%"=="0" (
  call :stage "%NATIVE_OUT%\Mapper.sys" "%OUT_ROOT%\Mapper.sys"
  if errorlevel 1 exit /b 1
)
exit /b 0

:stage
rem %~1 = source, %~2 = destination.
copy /y "%~1" "%~2" >nul
if errorlevel 1 (
  echo   %C_RED%ERROR: unable to deploy %~2%C_RESET%
  exit /b 1
)
for %%A in ("%~2") do if %%~zA LSS 1024 (
  echo   %C_RED%ERROR: deployed %~2 is implausibly small ^(%%~zA bytes^).%C_RESET%
  exit /b 1
)
set "STAGE_SHA="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('%~2'))) -replace '-',''); Write-Output ('STAGE_SHA=' + $h)"`) do set "%%A=%%B"
if not defined STAGE_SHA (
  echo   %C_RED%ERROR: unable to hash %~2%C_RESET%
  exit /b 1
)
for %%F in ("%~2") do echo   %C_GREEN%[+]%C_RESET% %%~nxF     %C_GREEN%%STAGE_SHA%%C_RESET%
set "STAGE_SHA="
exit /b 0

:sweep_artifacts
rem Build PDBs record absolute source paths; keep them only on request.
if not exist "%SCRATCH%" exit /b 0
set "SWEEP_FAILED="
if /i not "%AMEGER_KEEP_PDB%"=="1" (
  for %%F in ("%OUT_ROOT%\*.pdb") do if exist "%%~F" (
    move /y "%%~F" "%SCRATCH%\" >nul
    if exist "%%~F" set "SWEEP_FAILED=1"
  )
) else (
  echo   %C_YELLOW%[!]%C_RESET% PDB sweep skipped ^(AMEGER_KEEP_PDB=1^).
)
if defined SWEEP_FAILED exit /b 1
exit /b 0

:verify_release
call :verify_pe "%OUT_ROOT%\Hypervisor.sys" "Hypervisor.sys"
if errorlevel 1 exit /b 1
call :verify_pe "%OUT_ROOT%\Client.exe" "Client.exe"
if errorlevel 1 exit /b 1
if "%NO_MAPPER%"=="0" (
  call :verify_pe "%OUT_ROOT%\Mapper.sys" "Mapper.sys"
  if errorlevel 1 exit /b 1
)
exit /b 0

:verify_pe
rem %~1 = path, %~2 = label.
if not exist "%~1" (
  echo   %C_RED%ERROR: %~2 is missing from the release folder.%C_RESET%
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$b=[IO.File]::ReadAllBytes('%~1'); if($b.Length -lt 2 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A){exit 1}"
if errorlevel 1 (
  echo   %C_RED%ERROR: %~2 is not a PE image.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%OK%C_RESET% %~2: %C_GREEN%"%~1"%C_RESET%
exit /b 0

rem ---------------------------------------------------------------------------
rem Helpers
rem ---------------------------------------------------------------------------

:find_msbuild
if exist "%VSWHERE%" for /f "usebackq delims=" %%M in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" 2^>nul`) do if not defined MSBUILD if exist "%%M" set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if defined MSBUILD exit /b 0
for /f "delims=" %%M in ('where msbuild.exe 2^>nul') do if not defined MSBUILD set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
exit /b 1

:select_toolset
rem Prefer an explicit override, then a toolset pinned in the project. The
rem projects currently use $(DefaultPlatformToolset), so no override is passed
rem unless the caller asks for one.
if defined AMEGER_PLATFORM_TOOLSET (
  set "TOOLSET=%AMEGER_PLATFORM_TOOLSET%"
  exit /b 0
)
if defined AMEGER_WINDOWS_SDK_VERSION set "SDK_VERSION=%AMEGER_WINDOWS_SDK_VERSION%"
set "TOOLSET="
for /f "usebackq tokens=2 delims=<>" %%T in (`findstr /i /r /c:"PlatformToolset^>v[0-9]*" "%HV_PROJ%" 2^>nul`) do if not defined TOOLSET set "TOOLSET=%%T"
exit /b 0

:clean_directory
if exist "%~1" rmdir /s /q "%~1"
if exist "%~1" exit /b 1
exit /b 0

:prepare_scratch
if not exist "%OUT_ROOT%" mkdir "%OUT_ROOT%"
if not exist "%SCRATCH%" mkdir "%SCRATCH%"
if not exist "%NATIVE_OUT%" mkdir "%NATIVE_OUT%"
if not exist "%NATIVE_INT%" mkdir "%NATIVE_INT%"
if not exist "%OUT_ROOT%" exit /b 1
if not exist "%SCRATCH%" exit /b 1
if not exist "%NATIVE_OUT%" exit /b 1
if not exist "%NATIVE_INT%" exit /b 1
exit /b 0

rem ---------------------------------------------------------------------------
rem Failure paths
rem ---------------------------------------------------------------------------

:msbuild_error
echo %C_RED%ERROR: MSBuild was not found.%C_RESET%
goto :failure

:source_error
echo %C_RED%ERROR: one or more required project files are missing.%C_RESET%
goto :failure

:clean_error
echo %C_RED%ERROR: unable to prepare the release or build scratch directory.%C_RESET%
goto :failure

:build_error
echo %C_RED%ERROR: a project build failed.%C_RESET%
goto :failure

:deploy_error
echo %C_RED%ERROR: unable to deploy the release binaries.%C_RESET%
goto :failure

:verify_error
echo %C_RED%ERROR: one or more expected binaries are missing or are not PE images.%C_RESET%
goto :failure

:cleanup_error
echo %C_RED%ERROR: unable to remove generated build artifacts from the release folder.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1
