@echo off

setlocal EnableDelayedExpansion

where /Q cl.exe || (
  set __VSCMD_ARG_NO_LOGO=1
  for /f "tokens=*" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -prerelease -requires Microsoft.VisualStudio.Workload.NativeDesktop -property installationPath') do set VS=%%i
  if "!VS!" equ "" (
	echo ERROR: Visual Studio installation not found
	exit /b 1
  )  
  call "!VS!\VC\Auxiliary\Build\vcvarsall.bat" x64 || exit /b 1
)

if "%VSCMD_ARG_TGT_ARCH%" neq "x64" (
  echo ERROR: Please run this script from the MSVC x64 Native Tools command prompt
  exit /b 1
)

set compiler=cl.exe
set build_type=debug
set arch=x64

set build_options= /D_CRT_SECURE_NO_WARNINGS

if "%compiler%"=="clang-cl.exe" (
	set external_flag=/imsvc
) else (
	set external_flag=/external:I
)
set external_includes= %external_flag% ../source/ext/
set common_compile_flags= /utf-8 /TC /Zc:__STDC__ /std:clatest /nologo /Zi /FC /W4 /GR- /EHsc /I ../source/ %external_includes%
if "%build_type%"=="debug" (
	set compile_flags=%common_compile_flags% /MD
) else (
	set compile_flags=%common_compile_flags% /MD /O2
)
if "%compiler%"=="clang-cl.exe" (
	set compile_flags=%compile_flags% -Wno-missing-braces -Wno-unused-function -Wno-missing-declarations -fdiagnostics-absolute-paths -fuse-ld=lld-link
) else (
	set compile_flags=%compile_flags% /experimental:external /external:W0
)

set common_link_flags=User32.lib Shlwapi.lib Psapi.lib -opt:ref
if "%build_type%"=="debug" (
	set link_flags=%common_link_flags% /Debug:full
) else (
	set link_flags=%common_link_flags% /Debug:none
)

if not exist build mkdir build
pushd build
%compiler% %build_options% %compile_flags% ../source/build.c /LD /link %link_flags% /DEF:../source/winmm.def /out:winmm.dll
popd