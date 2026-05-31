# Prebuilt binaries

`JAHTTPClient.dll` — managed assembly built in **Release** (`dotnet build -c Release`),
target **net10.0**. Reference it directly instead of building the C# project:

```xml
<Reference Include="JAHTTPClient">
  <HintPath>path\to\dist\JAHTTPClient.dll</HintPath>
</Reference>
```

Files:

| File | Purpose |
|---|---|
| `JAHTTPClient.dll` | the library (this is the "dll") |
| `JAHTTPClient.pdb` | debug symbols (for readable stack traces) |
| `JAHTTPClient.deps.json` | dependency manifest |

## ⚠️ Native dependency still required at runtime

This is only the **managed** layer. At runtime it P/Invokes the native
`tls-client` shared library (`tls-client-*.so` / `.dll`), which is **not** shipped
here (large, platform-specific — see the repo `.gitignore`). Build it from
`native/` (Go 1.23+ and a C compiler) and drop it under
`runtimes/<rid>/native/` next to the assembly:

```bash
cd native && make linux     # → tls-client-linux-amd64.so
# or, on Windows:  ./build-windows.ps1
```

Without the native binary, the first request throws `DllNotFoundException`.

> Note: this prebuilt DLL is a convenience snapshot and can lag behind `src/`.
> When in doubt, rebuild from source: `dotnet build -c Release`.
