"""Build and package only explicitly allowed artifacts; never collects vault data.

Two ZIPs: the main one has goyo-vault.exe and the documents and holds no
network-capable program; the optional sync add-on has goyo-sync.exe, the
server script and the example settings, to be extracted into the same folder.
"""
import hashlib, json, os, pathlib, shutil, subprocess, sys, zipfile
root = pathlib.Path(__file__).resolve().parents[1]
# RUSTFLAGS (or a per-target CARGO_TARGET_<triple>_RUSTFLAGS / CARGO_BUILD_RUSTFLAGS)
# would silently replace the hardening flags in .cargo/config.toml. Set but
# empty counts too: Cargo then uses no flags at all.
for name in os.environ:
    if name.upper() in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS') or (
            name.upper().startswith('CARGO_') and name.upper().endswith('RUSTFLAGS')):
        sys.exit(f'Refusing to package with {name} set: it would drop the hardening flags.')
# Build and ship only committed sources, so a release always matches a commit.
inputs = ['src', 'Cargo.toml', 'Cargo.lock', 'build.rs', '.cargo', 'assets', 'server', 'goyo-sync.conf.example']
if subprocess.check_output(['git', 'status', '--porcelain', '--', *inputs], cwd=root).strip():
    sys.exit('Refusing to package: commit the source changes first (git status).')
# Panic locations embed source paths, e.g. C:\Users\<name>\.cargo\registry\...
# Remap the machine-specific prefixes so the published exe names no user or folder.
cargo_home = pathlib.Path(os.environ.get('CARGO_HOME') or pathlib.Path.home()/'.cargo')
flags = [f'--remap-path-prefix={cargo_home}=cargo', f'--remap-path-prefix={root}=goyo-vault']
config = 'target.x86_64-pc-windows-msvc.rustflags=' + json.dumps(flags)
subprocess.check_call(['cargo', 'build', '--release', '--locked', '--bins', '--config', config], cwd=root)
release = root/'target/release'
for program in ('goyo-vault.exe', 'goyo-sync.exe'):
    binary = (release/program).read_bytes()
    for private in {str(pathlib.Path.home()), str(root), os.environ.get('USERNAME', '')} - {''}:
        for form in (private, private.replace('\\', '/')):
            if form.lower().encode() in binary.lower() or form.lower().encode('utf-16-le') in binary.lower():
                sys.exit(f'Refusing to package: {program} contains a local path or user name ({form!r}).')
subprocess.check_call([sys.executable, 'scripts/inspect_pe.py', '--profile', 'vault', 'target/release/goyo-vault.exe'], cwd=root, stdout=subprocess.DEVNULL)
subprocess.check_call([sys.executable, 'scripts/inspect_pe.py', '--profile', 'sync', 'target/release/goyo-sync.exe'], cwd=root, stdout=subprocess.DEVNULL)
subprocess.check_call([sys.executable, 'scripts/check_dll_planting.py', 'target/release/goyo-vault.exe', 'target/release/goyo-sync.exe'], cwd=root)
# The server script runs on the user's server, so check the shipped copy here:
# it must compile and pass its own selftest (CAS, history, key-file refusal).
server = 'server/goyo-sync-server.py'
subprocess.check_call([sys.executable, '-m', 'py_compile', server], cwd=root)
selftest = subprocess.run([sys.executable, '-I', server, 'selftest'], cwd=root, capture_output=True, text=True)
if selftest.returncode != 0 or selftest.stdout.strip() != 'PASS':
    sys.exit(f'Refusing to package: the server selftest failed: {selftest.stdout.strip()} {selftest.stderr.strip()}')
metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--format-version', '1'], cwd=root))
notices = ['# Third-party notices', 'Dependencies in Cargo.lock; some are target-specific and may not be linked.']
for package in sorted(metadata['packages'], key=lambda p: p['name']):
    if not package['source']: continue
    notices += [f"\n## {package['name']} {package['version']}\n", f"License: {package['license']}\nRepository: {package.get('repository') or ''}\n"]
    directory = pathlib.Path(package['manifest_path']).parent
    files = sorted(p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE', 'COPYRIGHT')))
    if not files: raise RuntimeError(f"Missing license text for {package['name']}")
    for p in files:
        notices += [f'### {p.name}\n', p.read_text(encoding='utf-8', errors='replace')]
        if package['name'] == 'argon2' and p.name == 'LICENSE-APACHE':
            shutil.copyfile(p, root/'LICENSE-APACHE')
(root/'docs/THIRD_PARTY_NOTICES.md').write_text('\n'.join(notices), encoding='utf-8')
version = metadata['packages'][next(i for i,p in enumerate(metadata['packages']) if p['name']=='goyo-vault')]['version']

def stage(folder, exe, files):
    """Copies exactly `exe` and `files` into `folder`; returns the copies."""
    folder.mkdir(parents=True, exist_ok=True)
    staged = []
    for source, name in [(release/exe, exe)] + [(root/name, name) for name in files]:
        destination = folder/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        staged.append(destination)
    return staged
PROGRAMS = ('.exe', '.dll', '.py', '.ps1', '.bat', '.cmd', '.vbs', '.js')
def pack(folder, staged, sums, archive, programs, exact=None):
    """SHA256SUMS file plus a ZIP of `staged` under GoyoVault/, and a
    `<zip>.sha256` line ("<hex>  <name>") for the release page. Every check
    runs before the ZIP is written, so a refused release leaves no ZIP."""
    hashes = '\n'.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(folder).as_posix()}' for p in staged)+'\n'
    checksums = folder/sums
    checksums.write_text(hashes, encoding='utf-8')
    staged = staged + [checksums]
    names = [f'GoyoVault/{p.relative_to(folder).as_posix()}' for p in staged]
    # Explicit lists already keep these out; a slip in a list must not ship
    # the private server settings, logs, vault data, local paths, server data
    # or Python caches.
    for name in names:
        lower = name.lower()
        if lower.endswith(('goyo-sync.conf', '.log', '.log.1', '.pyc', '.goyo', '.goyokey', '.goyosync', '.goyolock', '.goyotmp', 'goyo-vault.paths')) \
                or '/data/' in lower or '__pycache__' in lower or '.goyo.sync/' in lower:
            sys.exit(f'Refusing to package: {name} must never be in a release.')
    found = [n for n in names if n.lower().endswith(PROGRAMS)]
    if found != programs:
        sys.exit(f'Refusing to package: {archive.name} may hold only {programs} as programs, not {found}.')
    if exact is not None and names != exact:
        sys.exit(f'Refusing to package: unexpected {archive.name} contents {names}.')
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for p, name in zip(staged, names): z.write(p, name)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (archive.parent/(archive.name+'.sha256')).write_bytes(f'{digest}  {archive.name}\n'.encode('ascii'))
    return names, digest

# One unversioned folder: extracting a new release over the old one keeps the
# vault and key files that live next to the executable.
docs = ['README.md','README.en.md','시작하기.txt','START-HERE.txt','LICENSE-MIT','LICENSE-APACHE','docs/FORMAT.md','docs/SECURITY_REVIEW.md',
        'docs/SYNC.md','docs/SYNC.en.md','docs/THIRD_PARTY_NOTICES.md','docs/dependency-audit.json','docs/binary-inspection.json']
docs += sorted(p.relative_to(root).as_posix() for p in (root/'docs/images').rglob('*.png'))
if (root/'docs/OPUS_FINAL.md').exists(): docs.append('docs/OPUS_FINAL.md')
main_folder = root/'dist'/'GoyoVault'
main_staged = stage(main_folder, 'goyo-vault.exe', docs)
archive = root/'dist'/f'GoyoVault-{version}-windows-x64.zip'
# The main ZIP must work offline as before: its only program is goyo-vault.exe.
main_names, main_digest = pack(main_folder, main_staged, 'SHA256SUMS.txt', archive, ['GoyoVault/goyo-vault.exe'])

# The add-on stages in its own folder, so its SHA256SUMS never mixes with the
# main one and nothing else from dist/ can slip in.
sync_folder = root/'dist'/'sync'/'GoyoVault'
sync_staged = stage(sync_folder, 'goyo-sync.exe', ['server/goyo-sync-server.py', 'goyo-sync.conf.example'])
sync_archive = root/'dist'/f'GoyoVault-Sync-{version}-windows-x64.zip'
sync_names, sync_digest = pack(sync_folder, sync_staged, 'SHA256SUMS-sync.txt', sync_archive,
                               ['GoyoVault/goyo-sync.exe', 'GoyoVault/server/goyo-sync-server.py'],
                               exact=['GoyoVault/goyo-sync.exe', 'GoyoVault/server/goyo-sync-server.py',
                                      'GoyoVault/goyo-sync.conf.example', 'GoyoVault/SHA256SUMS-sync.txt'])

exe, sync_exe = main_folder/'goyo-vault.exe', sync_folder/'goyo-sync.exe'
report = {'zip':str(archive),'zip_bytes':archive.stat().st_size,'zip_sha256':main_digest,
          'exe':str(exe),'exe_bytes':exe.stat().st_size,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
          'sync_zip':str(sync_archive),'sync_zip_bytes':sync_archive.stat().st_size,'sync_zip_sha256':sync_digest,
          'sync_exe':str(sync_exe),'sync_exe_bytes':sync_exe.stat().st_size,'sync_exe_sha256':hashlib.sha256(sync_exe.read_bytes()).hexdigest()}
(root/'dist/release.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))
