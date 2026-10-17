"""Read PE headers/imports without loading or executing the program."""
import hashlib, json, pathlib, struct, sys
p = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release/goyo-vault.exe')
b = p.read_bytes()
def u16(at): return struct.unpack_from('<H', b, at)[0]
def u32(at): return struct.unpack_from('<I', b, at)[0]
def u64(at): return struct.unpack_from('<Q', b, at)[0]
pe = u32(0x3c)
assert b[pe:pe+4] == b'PE\0\0'
count, optional_size = u16(pe+6), u16(pe+20)
optional = pe+24
assert u16(optional) == 0x20b
sections = []
for i in range(count):
    at = optional+optional_size+i*40
    sections.append((u32(at+12), max(u32(at+8),u32(at+16)), u32(at+20)))
def offset(rva):
    for start, size, disk in sections:
        if start <= rva < start+size: return disk+rva-start
    raise ValueError(f'Unknown RVA {rva:x}')
def cstring(rva):
    at = offset(rva)
    return b[at:b.index(0, at)].decode('ascii')
imports = {}
at = offset(u32(optional+112+8))
while any(b[at:at+20]):
    dll = cstring(u32(at+12))
    thunk = offset(u32(at) or u32(at+16))
    names = []
    while (entry := u64(thunk)):
        names.append(f'ordinal:{entry & 65535}' if entry >> 63 else cstring(entry+2))
        thunk += 8
    imports[dll] = names
    at += 20
config = offset(u32(optional+112+10*8))
flags = u16(config+78)
report = {'sha256':hashlib.sha256(b).hexdigest(), 'bytes':len(b),
          'machine':hex(u16(pe+4)), 'dll_characteristics':hex(u16(optional+70)),
          'dependent_load_flags':hex(flags), 'imports':imports}
characteristics = u16(optional+70)
assert flags == 0x800, 'Static DLL lookup must use System32'
for bit, name in [(0x20, 'HIGH_ENTROPY_VA'), (0x40, 'DYNAMIC_BASE (ASLR)'), (0x100, 'NX_COMPAT (DEP)'), (0x4000, 'GUARD_CF (CFG)')]:
    assert characteristics & bit, f'{name} flag missing'
# CET shadow stack compatibility lives in the debug directory (type 20).
cet = False
debug_rva, debug_size = u32(optional+112+6*8), u32(optional+112+6*8+4)
for i in range(debug_size // 28 if debug_rva else 0):
    entry = offset(debug_rva) + i*28
    if u32(entry+12) == 20:
        cet = bool(u32(u32(entry+24)) & 1)
assert cet, 'CETCOMPAT flag missing'
assert not u32(optional+112+13*8), 'Delay imports are not expected'
# Only these DLLs may load before main runs; anything else (wtsapi32 pulled
# SspiCli.dll from the exe folder) must be loaded at run time from System32.
allowed = {'user32.dll', 'gdi32.dll', 'kernel32.dll', 'ntdll.dll', 'imm32.dll', 'dwmapi.dll', 'uxtheme.dll', 'comdlg32.dll'}
for dll in imports:
    assert dll.lower() in allowed or dll.lower().startswith('api-ms-win-core-'), f'Unexpected static import {dll}'
report['cet_compat'] = cet
for names in imports.values():
    assert not any(n.startswith(('BCrypt','CryptProtect','CryptUnprotect')) or n in ('ProcessPrng','SystemFunction036') for n in names), 'OS crypto/RNG imported'
output = json.dumps(report, indent=2)
pathlib.Path('docs/binary-inspection.json').write_text(output, encoding='utf-8')
print(json.dumps({'bytes':len(b),'sha256':report['sha256'],'dependent_load_flags':hex(flags),'dlls':list(imports)}, indent=2))
