#!/usr/bin/env python3
"""Binary-patch opencode.exe to redirect missing-API imports to our shim DLLs.

Renames the following DLL name strings in the import table:
  api-ms-win-core-synch-l1-2-0.dll  ->  w7shim.dll\0... (33 bytes total)
  bcryptprimitives.dll              ->  w7shim.dll\0... (21 bytes total)
  KERNEL32.dll                      ->  W7KERN3L.dll    (13 bytes, same length)
  ntdll.dll                         ->  w7ntd.dll       (10 bytes, same length)

The rename must keep the same total byte length (including null terminator)
because the next byte after the null is the start of the next structure in
.idata. We pad shorter names with nulls.
"""
import sys
import shutil
import pefile

SRC = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/opencode/packages/opencode/dist/opencode-windows-x64/bin/opencode.exe"
DST = sys.argv[2] if len(sys.argv) > 2 else "/home/z/my-project/win7-port/build/opencode-win7.exe"

# Map of: original DLL name (lowercase for compare) -> new DLL name (bytes)
# Each new name is padded with nulls to the same length as original + null terminator.
RENAMES = {
    "api-ms-win-core-synch-l1-2-0.dll": b"w7shim.dll",
    "bcryptprimitives.dll": b"w7shim.dll",
    "kernel32.dll": b"W7KERN3L.dll",
    "ntdll.dll": b"w7ntd.dll",
}

shutil.copy2(SRC, DST)

pe = pefile.PE(DST, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

# Read the file as bytes
with open(DST, "rb") as f:
    data = bytearray(f.read())

patch_count = 0
seen_dlls = set()

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    # The DLL name string is at the RVA stored in entry.struct.Name
    name_rva = entry.struct.Name
    name_offset = pe.get_offset_from_rva(name_rva)
    # Read the null-terminated name at that offset
    end = data.index(b"\x00", name_offset)
    orig_name_bytes = bytes(data[name_offset:end])
    orig_name = orig_name_bytes.decode("ascii", errors="replace")
    orig_name_lower = orig_name.lower()

    if orig_name_lower in RENAMES:
        new_name = RENAMES[orig_name_lower]
        # Length of original (excluding null) + 1 for null terminator
        orig_total_len = len(orig_name_bytes) + 1
        # New name padded with nulls to same total length
        if len(new_name) + 1 > orig_total_len:
            print(f"ERROR: new name {new_name!r} longer than original {orig_name!r}")
            sys.exit(1)
        padded = new_name + b"\x00" * (orig_total_len - len(new_name))
        # Sanity check
        assert len(padded) == orig_total_len
        # Patch
        data[name_offset : name_offset + orig_total_len] = padded
        patch_count += 1
        seen_dlls.add(orig_name_lower)
        print(f"  {orig_name:35s} -> {new_name.decode():15s} (at offset 0x{name_offset:08x}, {orig_total_len} bytes)")

with open(DST, "wb") as f:
    f.write(data)

print(f"\nPatched {patch_count} DLL name(s) in {DST}")
print(f"File size: {len(data)} bytes ({len(data) / 1024 / 1024:.1f} MB)")

# Verify by reloading the patched file
print("\nVerifying patched imports...")
pe2 = pefile.PE(DST, fast_load=True)
pe2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
for entry in pe2.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    n = len(entry.imports)
    print(f"  {dll:35s}  ({n} imports)")
