# Builds the native tls-client shared library consumed by the .NET P/Invoke layer.
#
# Output is placed directly into the managed project's runtimes/<rid>/native
# folder so that `dotnet build` copies it next to the assembly.
#
# Requirements:
#   - Go 1.23+
#   - A C toolchain (CGO_ENABLED=1):
#       * Linux:   gcc
#       * Windows: mingw-w64 / tdm-gcc (for cross build set CC=x86_64-w64-mingw32-gcc)
#
# Usage:
#   make deps        # download Go module dependencies
#   make linux       # -> ../src/JAHTTPClient/runtimes/linux-x64/native/tls-client-linux-amd64.so
#   make windows     # cross-compile .dll (needs mingw)  -> runtimes/win-x64/native/...
#   make all

RUNTIMES := ../src/JAHTTPClient/runtimes
GOFLAGS  := -ldflags "-s -w" -buildmode=c-shared

.PHONY: all deps linux windows clean

all: linux

deps:
	go mod tidy

linux:
	mkdir -p $(RUNTIMES)/linux-x64/native
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
		go build $(GOFLAGS) -o $(RUNTIMES)/linux-x64/native/tls-client-linux-amd64.so .

# Cross-compile a Windows DLL from Linux/macOS (requires mingw-w64).
windows:
	mkdir -p $(RUNTIMES)/win-x64/native
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		go build $(GOFLAGS) -o $(RUNTIMES)/win-x64/native/tls-client-windows-64.dll .

clean:
	rm -f $(RUNTIMES)/linux-x64/native/*.so $(RUNTIMES)/linux-x64/native/*.h
	rm -f $(RUNTIMES)/win-x64/native/*.dll  $(RUNTIMES)/win-x64/native/*.h
