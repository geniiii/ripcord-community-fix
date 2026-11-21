@echo off
setlocal

pushd "%~dp0source"
for %%f in (*.c *.h) do clang-format -i "%%f"
for /d %%d in (*) do (
    if /i not "%%d"=="ext" (
        for /r "%%d" %%f in (*.c *.h) do clang-format -i "%%f"
    )
)
popd
