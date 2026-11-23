# Windows 7 / Server 2016 compatibility port for opencode v1.19.6

This directory contains the source for the shim DLLs and the binary patcher
that make the upstream opencode.exe load on Windows 7 SP1 and Windows Server
2016 (both of which the upstream binary refuses to even start on, because
Bun requires Windows 10 1809+).

See [README.md in the release](../../releases) for installation instructions
and the full write-up.

## Files

| Path | Purpose |
| --- | --- |
| `src/w7shim.c` | The shim DLL — implements the 13 missing Windows 8+ / Win10+ API functions |
| `src/w7shim.def` | Exports for the shim DLL |
| `src/forward_dll.c` | DllMain for the forwarding DLLs |
| `src/w7kern3l.def` | Generated — forwards 322 KERNEL32 imports, 5 to w7shim |
| `src/w7ntd.def` | Generated — forwards 30 ntdll imports, 4 to w7shim |
| `scripts/gen_forwarding_def.py` | Generates the .def files from opencode.exe's imports |
| `scripts/patch_opencode.py` | Binary-patches opencode.exe to redirect missing-API imports |
| `scripts/verify_imports.py` | Verifies every patched import resolves |

## Build

See [README.md](../../releases) "Build it yourself" section. Requires MinGW-w64
and Python 3 + pefile on a Linux host.

## What this does NOT do

- Does not modify Bun itself. The Bun runtime inside opencode.exe is
  unchanged. We accept the runtime overhead of Bun's existing Win10
  codepaths and only shim the load-time blockers.
- Does not enable the JIT (JavaScriptCore falls back to interpreter).
- Does not enable ConPTY subprocess spawning (stubs return E_NOTIMPL).
- Does not run on Windows Vista or earlier — the shim DLL itself uses
  `CONDITION_VARIABLE` (Vista+) and `BCryptGenRandom` (Vista+).
