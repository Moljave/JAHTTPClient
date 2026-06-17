# Builds the native tls-client DLL on Windows (primary target platform).
#
# Compiles the local cffi wrapper (main.go, vendored from upstream cffi_dist)
# into a C-shared library that exports exactly the functions the .NET layer
# P/Invokes: request, freeMemory, getCookiesFromSession, addCookiesToSession,
# destroySession, destroyAll.
#
# Prerequisites:
#   1. Go 1.23+            -> https://go.dev/dl/
#   2. A C compiler for CGO (gcc on PATH). The easiest on Windows is tdm-gcc or
#      mingw-w64:
#         - tdm-gcc:    https://jmeubank.github.io/tdm-gcc/
#         - mingw-w64:  via msys2 (pacman -S mingw-w64-x86_64-gcc)
#      Verify with: gcc --version
#   3. Internet access (the first build downloads the Go modules).
#
# Usage (from the repo's /native folder):
#   powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
#
# Result:
#   ../JAHTTPClient/runtimes/win-x64/native/tls-client-windows-64.dll
#   which `dotnet build` then copies next to JAHTTPClient.dll automatically.

$ErrorActionPreference = "Stop"

Write-Host "==> Checking toolchain..." -ForegroundColor Cyan
go version
gcc --version | Select-Object -First 1

$OutDir = Join-Path $PSScriptRoot "..\JAHTTPClient\runtimes\win-x64\native"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutFile = Join-Path $OutDir "tls-client-windows-64.dll"

Push-Location $PSScriptRoot
try {
    Write-Host "==> Restoring Go modules..." -ForegroundColor Cyan
    go mod tidy
    if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed with exit code $LASTEXITCODE" }

    Write-Host "==> Building shared library (CGO, c-shared)..." -ForegroundColor Cyan
    $env:CGO_ENABLED = "1"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    go build -ldflags "-s -w" -buildmode=c-shared -o $OutFile .
    if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }

    if (-not (Test-Path $OutFile)) { throw "Build reported success but $OutFile is missing." }

    Write-Host "==> Done: $OutFile" -ForegroundColor Green
}
finally {
    Pop-Location
}
