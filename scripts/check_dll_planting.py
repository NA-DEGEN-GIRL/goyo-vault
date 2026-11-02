"""DLL planting regression check (Windows only).

For every system DLL an exe loads at start-up, directly or through other
DLLs, that Windows does not pin as a KnownDLL, put a file with that name next
to a copy of the exe and run `--self-check`, twice:
- a dummy file: if the loader takes it, the program fails to start;
- a real copy from System32: if the loader takes it, the program starts, and
  `--self-check` reports the DLL loaded from its own folder.
The DLLs the vault app loads itself at run time (System32 only) are planted
next to every exe too, and next to goyo-sync.exe the ones its background
helper's notification-area icon and menu load at run time. goyo-vault.exe and goyo-sync.exe both print PASS from
`--self-check` when nothing came from their folder. Loader error pop-ups are
switched off for the copies, so a failing build does not leave a "bad image"
dialog on the desktop.

Usage: python scripts/check_dll_planting.py [--webauthn] [exe ...]
(default: target/release/goyo-vault.exe and target/release/goyo-sync.exe)

--webauthn (a security-key build, the manual checklist only; spec v3 §12):
webauthn.dll joins the DLLs loaded at run time, and the import closure of
each of them is planted too, since `--self-check` of that build loads
webauthn.dll and its dependencies.
"""
import ctypes, os, pathlib, shutil, struct, subprocess, sys, tempfile, winreg

webauthn = '--webauthn' in sys.argv[1:]
exes = [pathlib.Path(a).resolve()
        for a in [a for a in sys.argv[1:] if a != '--webauthn']
        or ['target/release/goyo-vault.exe', 'target/release/goyo-sync.exe']]
system32 = pathlib.Path(os.environ['SystemRoot']) / 'System32'
RUNTIME = ['msctf.dll', 'wtsapi32.dll', 'sspicli.dll']
# goyo-sync.exe --background: the tray icon (Shell_NotifyIconW, the icon's
# image) and its menu (TrackPopupMenuEx) load these at run time, found by
# listing a running helper's modules after its menu was opened. Its
# --self-check builds the tray window and menu without adding an icon or
# showing the menu, so it loads only some of them; a planted copy is still
# never taken (SetDefaultDllDirectories(System32) before anything loads).
SYNC_RUNTIME = ['apphelp.dll', 'applicationtargetedfeaturedatabase.dll', 'bcryptprimitives.dll',
                'iconcodecservice.dll', 'kernel.appcore.dll', 'oleacc.dll', 'textinputframework.dll',
                'textshaping.dll', 'twinapi.appcore.dll', 'windows.storage.dll', 'windowscodecs.dll',
                'wintypes.dll']
if webauthn:
    RUNTIME.append('webauthn.dll')


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

# SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX,
# inherited by the copies started below.
ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)

failures = []
for exe in exes:
    seen, queue = set(), list(imports(exe)) + (RUNTIME if webauthn else [])
    while queue:
        name = queue.pop().lower()
        if name in seen or name.startswith(('api-ms-', 'ext-ms-')):
            continue
        seen.add(name)
        path = system32 / name
        if path.exists():
            queue.extend(imports(path))
    runtime = set(RUNTIME) | (set(SYNC_RUNTIME) if exe.name.lower() == 'goyo-sync.exe' else set())
    candidates = sorted((seen - known) | runtime)

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
                    failures.append(f'{exe.name}: {name} ({kind}): no result within 60 s')
                    continue
                if run.returncode != 0 or 'PASS' not in run.stdout:
                    failures.append(f'{exe.name}: {name} ({kind}): exit {run.returncode:#x} {run.stdout.strip()} {run.stderr.strip()}')

    print(f'{exe.name}: planted {len(candidates)} names: {", ".join(candidates)}')
if failures:
    sys.exit('DLL planting check FAILED:\n' + '\n'.join(failures))
print('PASS: no planted DLL was loaded from a program folder')
