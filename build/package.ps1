#requires -version 5.1
<#
.SYNOPSIS
    NetCut 一键打包：release 构建 + Inno Setup 生成安装包。
.DESCRIPTION
    产物输出到 dist\NetCut-<版本>-setup.exe。
    与 build\package.bat 等价，供 PowerShell 环境使用。
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build\package.ps1
#>

$ErrorActionPreference = 'Continue'

# 项目根目录（本脚本位于 build\ 下）
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$isccCandidates = @(
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
    'C:\Program Files\Inno Setup 6\ISCC.exe'
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    Write-Host '[错误] 未找到 Inno Setup，请先安装: winget install JRSoftware.InnoSetup' -ForegroundColor Red
    exit 1
}

Write-Host '=== 构建 release ===' -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '=== 编译安装包 ===' -ForegroundColor Cyan
& $iscc 'installer\netcut.iss'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$dist = Join-Path $root 'dist'
$artifacts = Get-ChildItem -Path $dist -Filter '*.exe' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending

Write-Host ''
Write-Host '=== 完成，产物: ===' -ForegroundColor Green
$artifacts | ForEach-Object { Write-Host ("  " + $_.FullName) }
