"""Read PE headers/imports without loading or executing the program.

Usage: python scripts/inspect_pe.py [exe] [--profile vault|sync] [--out FILE]

Profiles (default vault):
- vault: goyo-vault.exe. Only the GUI and system DLLs it was built with, no
  network DLL, no OS crypto or RNG, and nothing that starts a process or
  makes a pipe. Writes docs/binary-inspection.json.
- sync: goyo-sync.exe, the optional helper. kernel32, ntdll and
  api-ms-win-core-*, the settings window's user32, gdi32, comdlg32,
  dwmapi and uxtheme, advapi32 only for its Run value; no socket, HTTP or
  crypto DLL. Writes docs/binary-inspection-sync.json.
Both need ASLR, high-entropy ASLR, DEP, CFG, CET, DependentLoadFlags 0x800
(System32 only), no delay imports, no import by ordinal and the GUI
subsystem.
"""
import argparse, hashlib, json, pathlib, struct, sys

# Every check below is an assert: `python -O` or PYTHONOPTIMIZE would skip
# them all and pass any binary.
if not __debug__:
    sys.exit('inspect_pe.py: run it without -O or PYTHONOPTIMIZE; its checks are asserts.')

DEFAULTS = {
    'vault': ('target/release/goyo-vault.exe', 'docs/binary-inspection.json'),
    'sync': ('target/release/goyo-sync.exe', 'docs/binary-inspection-sync.json'),
}
parser = argparse.ArgumentParser(description='Check the PE flags and imports of a release executable.')
parser.add_argument('exe', nargs='?')
parser.add_argument('--profile', choices=sorted(DEFAULTS), default='vault')
parser.add_argument('--out')
args = parser.parse_args()
p = pathlib.Path(args.exe or DEFAULTS[args.profile][0])
out = pathlib.Path(args.out or DEFAULTS[args.profile][1])
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
# A console subsystem would open a console window with the vault app, and
# with the helper at every sign-in; the helper attaches to one only for CLI use.
assert u16(optional+68) == 2, 'Subsystem must be GUI (2)'
# CET shadow stack compatibility lives in the debug directory (type 20).
cet = False
debug_rva, debug_size = u32(optional+112+6*8), u32(optional+112+6*8+4)
for i in range(debug_size // 28 if debug_rva else 0):
    entry = offset(debug_rva) + i*28
    if u32(entry+12) == 20:
        cet = bool(u32(u32(entry+24)) & 1)
assert cet, 'CETCOMPAT flag missing'
assert not u32(optional+112+13*8), 'Delay imports are not expected'
report['cet_compat'] = cet

# Neither program may talk to the network itself or carry OS crypto/RNG.
# These DLLs are outside both allowlists anyway; naming them keeps the ban
# if an allowlist ever grows.
NETWORK = {'ws2_32.dll', 'wsock32.dll', 'mswsock.dll', 'winhttp.dll', 'wininet.dll', 'dnsapi.dll',
           'iphlpapi.dll', 'urlmon.dll', 'websocket.dll', 'webio.dll', 'httpapi.dll', 'winnsi.dll'}
for dll, names in imports.items():
    assert dll.lower() not in NETWORK, f'Network DLL imported: {dll}'
    # The name rules below cannot see a function imported by number.
    assert not any(n.startswith('ordinal:') for n in names), f'{dll}: import by ordinal'
def crypto(name):
    return name.startswith(('BCrypt', 'CryptProtect', 'CryptUnprotect')) or name == 'SystemFunction036'
if args.profile == 'vault':
    # Only these DLLs may load before main runs; anything else (wtsapi32
    # pulled SspiCli.dll from the exe folder) must be loaded at run time
    # from System32.
    allowed = {'user32.dll', 'gdi32.dll', 'kernel32.dll', 'ntdll.dll', 'imm32.dll', 'dwmapi.dll', 'uxtheme.dll', 'comdlg32.dll'}
    for dll in imports:
        assert dll.lower() in allowed or dll.lower().startswith('api-ms-win-core-'), f'Unexpected static import {dll}'
    # The vault app starts no program and makes no pipe (it also forbids
    # child processes at run time). ProcessPrng would mean std's hashed
    # collections or pipes slipped in: OS randomness the app must not use.
    STARTS = ('CreateProcess', 'ShellExecute', 'CreateNamedPipe', 'NtCreateUserProcess', 'NtCreateProcess', 'RtlCreateUserProcess')
    BANNED = {'WinExec', 'CreatePipe', 'NtCreateNamedPipeFile', 'ProcessPrng'}
    for dll, names in imports.items():
        for n in names:
            assert not n.startswith(STARTS) and n not in BANNED, f'{dll}!{n}: goyo-vault.exe must not start programs, make pipes or use OS randomness'
            assert not crypto(n), f'{dll}!{n}: OS crypto/RNG imported'
else:
    # goyo-sync.exe runs System32\OpenSSH\ssh.exe through std's piped
    # Command, which may need bcryptprimitives!ProcessPrng (older std) and
    # ntdll's pipe calls. Its settings window (no arguments) draws with the
    # vault app's UI DLLs. It never decrypts or opens a socket.
    DENIED = {'crypt32.dll', 'secur32.dll'}
    UI = {'user32.dll', 'gdi32.dll', 'comdlg32.dll', 'dwmapi.dll', 'uxtheme.dll'}
    # The Run value: --autostart on|off, and the window's autostart switch,
    # which reads it to show whether it names this exe.
    ONLY = {'advapi32.dll': {'RegSetKeyValueW', 'RegDeleteKeyValueW', 'RegGetValueW'},
            'bcryptprimitives.dll': {'ProcessPrng'}}
    for dll, names in imports.items():
        lower = dll.lower()
        assert lower not in DENIED, f'goyo-sync.exe must not import {dll}'
        assert lower in ('kernel32.dll', 'ntdll.dll') or lower in UI or lower in ONLY or lower.startswith('api-ms-win-core-'), f'Unexpected static import {dll}'
        if lower in ONLY:
            extra = sorted(set(names) - ONLY[lower])
            assert not extra, f'{dll} may provide only {sorted(ONLY[lower])}, not {extra}'
        for n in names:
            assert not crypto(n), f'{dll}!{n}: OS crypto/RNG imported'
            assert n != 'ProcessPrng' or lower == 'bcryptprimitives.dll', f'{dll}!{n}: unexpected RNG import'
            assert n not in ('WinExec',) and not n.startswith('ShellExecute'), f'{dll}!{n}: only CreateProcessW (ssh.exe, ssh-keygen.exe, its own --background) may start a program'

output = json.dumps(report, indent=2)
out.write_text(output, encoding='utf-8')
print(json.dumps({'profile':args.profile,'bytes':len(b),'sha256':report['sha256'],'dependent_load_flags':hex(flags),'dlls':list(imports)}, indent=2))
