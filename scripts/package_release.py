"""Build and package only explicitly allowed artifacts; never collects vault data."""
import hashlib, json, os, pathlib, shutil, subprocess, sys, zipfile
root = pathlib.Path(__file__).resolve().parents[1]
# RUSTFLAGS (or a per-target CARGO_TARGET_<triple>_RUSTFLAGS / CARGO_BUILD_RUSTFLAGS)
# would silently replace the hardening flags in .cargo/config.toml.
for name, value in os.environ.items():
    if value and (name.upper() in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')
                  or (name.upper().startswith('CARGO_') and name.upper().endswith('RUSTFLAGS'))):
        sys.exit(f'Refusing to package with {name} set: it would drop the hardening flags.')
# Build only committed sources, so a release always matches a commit.
inputs = ['src', 'Cargo.toml', 'Cargo.lock', 'build.rs', '.cargo', 'assets']
if subprocess.check_output(['git', 'status', '--porcelain', '--', *inputs], cwd=root).strip():
    sys.exit('Refusing to package: commit the source changes first (git status).')
# Panic locations embed source paths, e.g. C:\Users\<name>\.cargo\registry\...
# Remap the machine-specific prefixes so the published exe names no user or folder.
cargo_home = pathlib.Path(os.environ.get('CARGO_HOME') or pathlib.Path.home()/'.cargo')
flags = [f'--remap-path-prefix={cargo_home}=cargo', f'--remap-path-prefix={root}=goyo-vault']
config = 'target.x86_64-pc-windows-msvc.rustflags=' + json.dumps(flags)
subprocess.check_call(['cargo', 'build', '--release', '--locked', '--config', config], cwd=root)
binary = (root/'target/release/goyo-vault.exe').read_bytes()
for private in {str(pathlib.Path.home()), str(root), os.environ.get('USERNAME', '')} - {''}:
    for form in (private, private.replace('\\', '/')):
        if form.lower().encode() in binary.lower() or form.lower().encode('utf-16-le') in binary.lower():
            sys.exit(f'Refusing to package: the executable contains a local path or user name ({form!r}).')
subprocess.check_call([sys.executable, 'scripts/inspect_pe.py', 'target/release/goyo-vault.exe'], cwd=root, stdout=subprocess.DEVNULL)
subprocess.check_call([sys.executable, 'scripts/check_dll_planting.py', 'target/release/goyo-vault.exe'], cwd=root)
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
# One unversioned folder: extracting a new release over the old one keeps the
# vault and key files that live next to the executable.
folder = root/'dist'/'GoyoVault'
folder.mkdir(parents=True, exist_ok=True)
files = ['README.md','README.en.md','시작하기.txt','LICENSE-MIT','LICENSE-APACHE','docs/FORMAT.md','docs/SECURITY_REVIEW.md',
         'docs/THIRD_PARTY_NOTICES.md','docs/dependency-audit.json','docs/binary-inspection.json']
files += sorted(p.relative_to(root).as_posix() for p in (root/'docs/images').glob('*.png'))
if (root/'docs/OPUS_FINAL.md').exists(): files.append('docs/OPUS_FINAL.md')
archive_files = []
exe = folder/'goyo-vault.exe'
shutil.copyfile(root/'target/release/goyo-vault.exe', exe)
archive_files.append(exe)
for name in files:
    destination = folder/name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root/name, destination)
    archive_files.append(destination)
hashes = '\n'.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(folder).as_posix()}' for p in archive_files)+'\n'
checksums = folder/'SHA256SUMS.txt'
checksums.write_text(hashes, encoding='utf-8')
archive_files.append(checksums)
archive = root/'dist'/f'GoyoVault-{version}-windows-x64.zip'
with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
    for p in archive_files: z.write(p, f'{folder.name}/{p.relative_to(folder).as_posix()}')
report = {'zip':str(archive),'zip_bytes':archive.stat().st_size,'zip_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
          'exe':str(exe),'exe_bytes':exe.stat().st_size,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest()}
(root/'dist/release.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))
