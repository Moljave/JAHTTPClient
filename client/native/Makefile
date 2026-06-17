# Builds the native tls-client shared library consumed by the .NET P/Invoke layer.
#
# Compiles the local cffi wrapper (main.go, vendored from upstream cffi_dist)
# into a C-shared library exposing request / freeMemory /
# get|addCookiesToSession / destroySession / destroyAll.
#
# Output goes into the managed project's runtimes/<rid>/native folder so that
# `dotnet build` copies it next to the assembly.
#
# Requirements:
#   - Go 1.23+
#   - A C toolchain (CGO_ENABLED=1):
#       * Linux:   gcc
#       * Windows cross build: mingw-w64 (CC=x86_64-w64-mingw32-gcc)
#   - Internet access for the first build (downloads Go modules).
#
# Usage:
#   make deps        # download/tidy Go module dependencies
#   make linux       # -> ../JAHTTPClient/runtimes/linux-x64/native/tls-client-linux-amd64.so
#   make windows     # cross-compile .dll (needs mingw)
#   make all

RUNTIMES := ../JAHTTPClient/runtimes
GOFLAGS  := -ldflags "-s -w" -buildmode=c-shared

.PHONY: all deps linux windows clean

all: linux

deps:
	go mod tidy

linux: deps
	mkdir -p $(RUNTIMES)/linux-x64/native
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
		go build $(GOFLAGS) -o $(RUNTIMES)/linux-x64/native/tls-client-linux-amd64.so .

# Cross-compile a Windows DLL from Linux/macOS (requires mingw-w64).
windows: deps
	mkdir -p $(RUNTIMES)/win-x64/native
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		go build $(GOFLAGS) -o $(RUNTIMES)/win-x64/native/tls-client-windows-64.dll .

clean:
	rm -f $(RUNTIMES)/linux-x64/native/*.so $(RUNTIMES)/linux-x64/native/*.h
	rm -f $(RUNTIMES)/win-x64/native/*.dll  $(RUNTIMES)/win-x64/native/*.h
