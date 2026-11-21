@echo off
setlocal
rem Invoked from src\build.bat under the existing build lock.
if /I "%VSCMD_ARG_TGT_ARCH%"=="x64" goto :build
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :no_tools
set "VSROOT="
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
if not defined VSROOT goto :no_tools
call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b %errorlevel%

:build
pushd "%~dp0..\.."
if errorlevel 1 exit /b %errorlevel%
set "OBJDIR=src\build\msvc\timing"
if not exist "%OBJDIR%" mkdir "%OBJDIR%"
if not exist "%OBJDIR%" goto :build_error
cl /nologo /W4 /WX /std:c11 /D_CRT_SECURE_NO_WARNINGS /O2 /Gy /Gw /I src ^
    /Fe:src\build\m68k_timing_decode.exe /Fo%OBJDIR%\ ^
    @src\tools\timing_decode_sources.rsp /link /INCREMENTAL:NO /OPT:REF bcrypt.lib
set "STATUS=%errorlevel%"
popd
exit /b %STATUS%

:build_error
echo Cannot create %OBJDIR%. 1>&2
popd
exit /b 1

:no_tools
echo Install the MSVC x64 C++ build tools or open an x64 Visual Studio Developer Command Prompt. 1>&2
exit /b 1
