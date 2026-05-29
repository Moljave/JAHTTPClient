# Builds the native tls-client DLL on Windows (primary target platform).
#
# Prerequisites:
#   1. Go 1.23+            -> https://go.dev/dl/
#   2. A C compiler for CGO. The easiest is tdm-gcc or mingw-w64:
#         - tdm-gcc:    https://jmeubank.github.io/tdm-gcc/
#         - mingw-w64:  via msys2 (pacman -S mingw-w64-x86_64-gcc)
#      Make sure `gcc` is on PATH (run `gcc --version` to verify).
#
# Usage (from the repo's /native folder):
#   ./build-windows.ps1
#
# Result:
#   ../src/JAHTTPClient/runtimes/win-x64/native/tls-client-windows-64.dll
#   which `dotnet build` then copies next to JAHTTPClient.dll automatically.

$ErrorActionPreference = "Stop"

Write-Host "==> Checking toolchain..." -ForegroundColor Cyan
go version
gcc --version | Select-Object -First 1

$OutDir = Join-Path $PSScriptRoot "..\src\JAHTTPClient\runtimes\win-x64\native"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutFile = Join-Path $OutDir "tls-client-windows-64.dll"

Write-Host "==> Restoring Go modules..." -ForegroundColor Cyan
Push-Location $PSScriptRoot
try {
    go mod tidy

    Write-Host "==> Building shared library (CGO, c-shared)..." -ForegroundColor Cyan
    $env:CGO_ENABLED = "1"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    go build -ldflags "-s -w" -buildmode=c-shared -o $OutFile .

    Write-Host "==> Done: $OutFile" -ForegroundColor Green
}
finally {
    Pop-Location
}
