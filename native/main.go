// Package main builds a C-shared library (.dll / .so / .dylib) that exposes the
// bogdanfinn/tls-client CFFI surface to non-Go callers (here: the .NET
// ChromeHttpClient via P/Invoke).
//
// It is a thin delegation layer over github.com/bogdanfinn/tls-client/cffi_src
// — the same surface the official tls-client release binaries expose — so that
// our .NET interop talks to a well-tested, maintained core (utls under the hood)
// instead of a bespoke fork.
//
// Build (shared library):
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o tls-client.dll   # Windows
//	CGO_ENABLED=1 go build -buildmode=c-shared -o tls-client.so    # Linux
//
// See ../native/Makefile and ../native/build-windows.ps1.
package main

import "C"

import (
	tls_client_cffi_src "github.com/bogdanfinn/tls-client/cffi_src"
)

// request performs an HTTP request described by the JSON payload and returns a
// JSON response. The returned C string is owned by the native side and MUST be
// released by the caller via freeMemory(response.id) once it has been read.
//
//export request
func request(payload *C.char) *C.char {
	return C.CString(tls_client_cffi_src.Request(C.GoString(payload)))
}

// getCookiesFromSession returns the cookies currently stored in the cookie jar
// of the session identified in the JSON payload ({sessionId, url}).
//
//export getCookiesFromSession
func getCookiesFromSession(payload *C.char) *C.char {
	return C.CString(tls_client_cffi_src.GetCookiesFromSession(C.GoString(payload)))
}

// addCookiesToSession inserts/overwrites cookies in the jar of the given
// session. Payload: {sessionId, url, cookies:[{name,value,path,domain,...}]}.
//
//export addCookiesToSession
func addCookiesToSession(payload *C.char) *C.char {
	return C.CString(tls_client_cffi_src.AddCookiesToSession(C.GoString(payload)))
}

// destroySession releases the client/cookie-jar associated with a sessionId.
// Payload: {sessionId}.
//
//export destroySession
func destroySession(payload *C.char) *C.char {
	return C.CString(tls_client_cffi_src.DestroySession(C.GoString(payload)))
}

// destroyAll releases every session held by the library. Useful on process
// shutdown to guarantee no leaks.
//
//export destroyAll
func destroyAll() *C.char {
	return C.CString(tls_client_cffi_src.DestroyAll())
}

// freeMemory releases a C string previously returned by request /
// getCookiesFromSession / addCookiesToSession, identified by the "id" field of
// the corresponding JSON response.
//
//export freeMemory
func freeMemory(responseId *C.char) {
	tls_client_cffi_src.FreeMemory(C.GoString(responseId))
}

func main() {}
