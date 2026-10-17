"""DLL planting regression check (Windows only).

For every system DLL the exe loads at start-up, directly or through other
DLLs, that Windows does not pin as a KnownDLL, put a file with that name next
to a copy of the exe and run `--self-check`, twice:
- a dummy file: if the loader takes it, the program fails to start;
- a real copy from System32: if the loader takes it, the program starts, and
  `--self-check` reports the DLL loaded from its own folder.
The DLLs the app loads itself at run time (System32 only) are planted too.
Loader error pop-ups are switched off for the copies, so a failing build does
not leave a "bad image" dialog on the desktop.

Usage: python scripts/check_dll_planting.py [path\\to\\goyo-vault.exe]
"""
import ctypes, os, pathlib, shutil, struct, subprocess, sys, tempfile, winreg

exe = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release/goyo-vault.exe').resolve()
system32 = pathlib.Path(os.environ['SystemRoot']) / 'System32'
RUNTIME = ['msctf.dll', 'wtsapi32.dll', 'sspicli.dll']


def imports(path):
    """Names in the import table of a PE32+ file ([] if it has none)."""
    b = path.read_bytes()
    u16 = lambda at: struct.unpack_from('<H', b, at)[0]
    u32 = lambda at: struct.unpack_from('<I', b, at)[0]
    pe = u32(0x3c)
    if b[pe:pe + 4] != b'PE\0\0' or u16(pe + 24) != 0x20b:
        return []
    count, optional_size = u16(pe + 6), u16(pe + 20)
    optional = pe + 24
    sections = []
    for i in range(count):
        at = optional + optional_size + i * 40
        sections.append((u32(at + 12), max(u32(at + 8), u32(at + 16)), u32(at + 20)))

    def offset(rva):
        for start, size, disk in sections:
            if start <= rva < start + size:
                return disk + rva - start
        raise ValueError(rva)

    rva = u32(optional + 112 + 8)
    if not rva:
        return []
    names, at = [], offset(rva)
    while any(b[at:at + 20]):
        name_at = offset(u32(at + 12))
        names.append(b[name_at:b.index(0, name_at)].decode('ascii'))
        at += 20
    return names


known = set()
with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs') as key:
    for i in range(winreg.QueryInfoKey(key)[1]):
        value = winreg.EnumValue(key, i)[1]
        if isinstance(value, str) and value.lower().endswith('.dll'):
            known.add(value.lower())

seen, queue = set(), list(imports(exe))
while queue:
    name = queue.pop().lower()
    if name in seen or name.startswith(('api-ms-', 'ext-ms-')):
        continue
    seen.add(name)
    path = system32 / name
    if path.exists():
        queue.extend(imports(path))
candidates = sorted((seen - known) | set(RUNTIME))

# SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX,
# inherited by the copies started below.
ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)

failures = []
for name in candidates:
    real = system32 / name
    for kind in ('dummy', 'real') if real.exists() else ('dummy',):
        with tempfile.TemporaryDirectory() as folder:
            copy = pathlib.Path(folder) / exe.name
            shutil.copyfile(exe, copy)
            planted = pathlib.Path(folder) / name
            if kind == 'real':
                shutil.copyfile(real, planted)
            else:
                planted.write_bytes(b'MZ not a real DLL')
            try:
                run = subprocess.run([str(copy), '--self-check'], capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                failures.append(f'{name} ({kind}): no result within 60 s')
                continue
            if run.returncode != 0 or 'PASS' not in run.stdout:
                failures.append(f'{name} ({kind}): exit {run.returncode:#x} {run.stdout.strip()} {run.stderr.strip()}')

print(f'Planted {len(candidates)} names: {", ".join(candidates)}')
if failures:
    sys.exit('DLL planting check FAILED:\n' + '\n'.join(failures))
print('PASS: no planted DLL was loaded from the program folder')
