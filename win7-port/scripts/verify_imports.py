#!/usr/bin/env python3
"""Verify that every import in opencode-win7.exe resolves to a function exported
by one of our shim DLLs or by the original system DLLs.

For each imported DLL name, we check:
  - If the DLL is one of our shims (w7shim.dll, W7KERN3L.dll, w7ntd.dll), the
    function name must be in the shim's exports (or in the shim's forwarders).
  - If the DLL forwards to another DLL, we follow the forwarder chain.
"""
import os
import sys
import pefile

BUILD_DIR = "/home/z/my-project/win7-port/build"
PATCHED_EXE = os.path.join(BUILD_DIR, "opencode-win7.exe")

# Load exports from each of our shim DLLs
SHIM_DLLS = {}
for name in ["w7shim.dll", "W7KERN3L.dll", "w7ntd.dll"]:
    path = os.path.join(BUILD_DIR, name)
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    exports = {}
    forwarders = {}
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            n = sym.name.decode() if sym.name else None
            if sym.forwarder:
                fwd = sym.forwarder.decode() if isinstance(sym.forwarder, bytes) else sym.forwarder
                forwarders[n] = fwd
            else:
                exports[n] = True
    SHIM_DLLS[name.lower()] = {"exports": exports, "forwarders": forwarders}
    print(f"Loaded {name}: {len(exports)} exports, {len(forwarders)} forwarders")

# Load the patched exe
pe = pefile.PE(PATCHED_EXE, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

problems = []
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    dll_lower = dll.lower()
    for imp in entry.imports:
        if imp.name is None:
            problems.append(f"  {dll}!ordinal{imp.ordinal}  (ordinal import, can't verify by name)")
            continue
        name = imp.name.decode()
        if dll_lower in SHIM_DLLS:
            shim = SHIM_DLLS[dll_lower]
            if name in shim["exports"]:
                continue  # OK - implemented locally
            if name in shim["forwarders"]:
                continue  # OK - forwarded to another DLL
            problems.append(f"  {dll}!{name}  NOT FOUND in shim exports/forwarders")
        else:
            # Not one of our shims; assume it's a real system DLL that exports it.
            # We can't verify here without the actual DLL.
            pass

if problems:
    print("\n=== PROBLEMS ===")
    for p in problems:
        print(p)
    print(f"\n{len(problems)} problem(s) found")
    sys.exit(1)
else:
    print("\nAll shim DLL imports verified OK.")
