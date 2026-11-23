#!/usr/bin/env python3
"""Generate w7kern3l.def and w7ntd.def forwarding files from opencode.exe's imports.

For each function in KERNEL32.dll imports:
  - if it's in MISSING_KERNEL32, forward to w7shim.dll
  - else, forward to KERNEL32.<func>

Same for ntdll.dll imports.
"""
import sys
import pefile

EXE_PATH = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/opencode/packages/opencode/dist/opencode-windows-x64/bin/opencode.exe"

# Functions opencode.exe imports that DON'T exist on Windows 7.
# Reference: MSDN "Minimum supported client" for each API.
MISSING_KERNEL32 = {
    "GetThreadDescription",       # Win10 1607+
    "GetSystemTimePreciseAsFileTime",  # Win8+
    "CreatePseudoConsole",         # Win10 1809+
    "ClosePseudoConsole",           # Win10 1809+
    "ResizePseudoConsole",           # Win10 1809+
}

MISSING_NTDLL = {
    "RtlAddGrowableFunctionTable",  # Win8+
    "RtlWaitOnAddress",             # Win8+
    "RtlWakeAddressAll",            # Win8+
    "RtlWakeAddressSingle",         # Win8+
}

pe = pefile.PE(EXE_PATH, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

kernel32_imports = []
ntdll_imports = []

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode().lower()
    for imp in entry.imports:
        if imp.name is None:
            continue
        name = imp.name.decode()
        if dll == "kernel32.dll":
            kernel32_imports.append(name)
        elif dll == "ntdll.dll":
            ntdll_imports.append(name)

# Generate w7kern3l.def
with open("/home/z/my-project/win7-port/src/w7kern3l.def", "w") as f:
    f.write("LIBRARY W7KERN3L\n")
    f.write("EXPORTS\n")
    for name in sorted(set(kernel32_imports)):
        if name in MISSING_KERNEL32:
            f.write(f"  {name} = w7shim.{name}\n")
        else:
            f.write(f"  {name} = KERNEL32.{name}\n")

# Generate w7ntd.def
with open("/home/z/my-project/win7-port/src/w7ntd.def", "w") as f:
    f.write("LIBRARY w7ntd\n")
    f.write("EXPORTS\n")
    for name in sorted(set(ntdll_imports)):
        if name in MISSING_NTDLL:
            f.write(f"  {name} = w7shim.{name}\n")
        else:
            f.write(f"  {name} = ntdll.{name}\n")

print(f"Generated w7kern3l.def with {len(set(kernel32_imports))} exports")
print(f"Generated w7ntd.def with {len(set(ntdll_imports))} exports")
print(f"  - {len(MISSING_KERNEL32)} kernel32 functions forwarded to w7shim")
print(f"  - {len(MISSING_NTDLL)} ntdll functions forwarded to w7shim")
