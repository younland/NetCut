@echo off
setlocal
REM NetCut packaging: release build + Inno Setup installer.
REM Output: dist\NetCut-<version>-setup.exe
REM Usage: double-click, or run build\package.bat from the project root.
REM (ASCII-only on purpose: cmd decodes .bat with the OEM codepage.)

pushd "%~dp0.."

set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist %ISCC% set ISCC="C:\Program Files\Inno Setup 6\ISCC.exe"
if not exist %ISCC% (
    echo [ERROR] Inno Setup not found. Install it with: winget install JRSoftware.InnoSetup
    popd
    exit /b 1
)

echo === Building release ===
cargo build --release
if errorlevel 1 (
    popd
    exit /b 1
)

echo === Compiling installer ===
%ISCC% "installer\netcut.iss"
if errorlevel 1 (
    popd
    exit /b 1
)

echo.
echo === Done. Artifacts: ===
dir /b dist\*.exe
popd
endlocal
