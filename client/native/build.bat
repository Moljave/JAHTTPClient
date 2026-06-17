@echo off
REM ===========================================================================
REM  Builds the native tls-client Go library into tls-client-windows-64.dll
REM  RIGHT NEXT TO THIS .bat file.
REM
REM  Just double-click it (or run from cmd). Requirements:
REM    - Go 1.23+        ->  https://go.dev/dl/      (check: go version)
REM    - A C compiler    ->  tdm-gcc or mingw-w64    (check: gcc --version)
REM      tdm-gcc: https://jmeubank.github.io/tdm-gcc/
REM    - Internet access (first build downloads the Go modules)
REM
REM  This .bat must sit in the same folder as main.go and go.mod (the /native
REM  folder of the repo).
REM ===========================================================================

setlocal EnableExtensions

REM Work in the folder where this script lives (must contain main.go + go.mod).
cd /d "%~dp0"

set "OUT=%~dp0tls-client-windows-64.dll"

echo.
echo ==^> Checking sources...
if not exist "%~dp0go.mod"  ( echo [ERROR] go.mod not found next to this .bat. Put build.bat in the repo's \native folder.  & goto :fail )
if not exist "%~dp0main.go" ( echo [ERROR] main.go not found next to this .bat. Put build.bat in the repo's \native folder. & goto :fail )

echo ==^> Checking toolchain...
where go >nul 2>nul || ( echo [ERROR] 'go' not found on PATH. Install Go: https://go.dev/dl/ & goto :fail )
where gcc >nul 2>nul || ( echo [ERROR] 'gcc' not found on PATH. Install tdm-gcc or mingw-w64. & goto :fail )
go version
gcc --version

echo ==^> Restoring Go modules (go mod tidy)...
go mod tidy
if errorlevel 1 ( echo [ERROR] go mod tidy failed. & goto :fail )

echo ==^> Building shared library (CGO, c-shared)...
set CGO_ENABLED=1
set GOOS=windows
set GOARCH=amd64
go build -ldflags "-s -w" -buildmode=c-shared -o "%OUT%" .
if errorlevel 1 ( echo [ERROR] go build failed. & goto :fail )

if not exist "%OUT%" ( echo [ERROR] Build reported success but DLL is missing. & goto :fail )

echo.
echo ==^> DONE. Created:
echo     %OUT%

REM Convenience: also drop a copy into the .NET project's runtimes folder, if
REM this .bat is run from the repo (so `dotnet build` picks it up automatically).
set "RUNTIME_DIR=%~dp0..\JAHTTPClient\runtimes\win-x64\native"
if exist "%~dp0..\JAHTTPClient\JAHTTPClient.csproj" (
    if not exist "%RUNTIME_DIR%" mkdir "%RUNTIME_DIR%"
    copy /Y "%OUT%" "%RUNTIME_DIR%\tls-client-windows-64.dll" >nul
    echo     (also copied into %RUNTIME_DIR%\)
)

echo.
echo Success.
pause
exit /b 0

:fail
echo.
echo Build FAILED. See the messages above.
pause
exit /b 1
