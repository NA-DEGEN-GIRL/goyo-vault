"""The checks every stage passes in both editions (spec v3 §11.4): rustfmt,
the tests, clippy and the release build of the default build (with
security keys, the release) and of the keyless `--no-default-features`
build (the lib and both binaries), and the server selftest. No network and
no file written unless asked:

    python -X utf8 scripts/run_checks.py            the checks above
    python -X utf8 scripts/run_checks.py --deps     also check_dependencies.py
                                                    (OSV over the network; it
                                                    rewrites docs/dependency-audit.json)
    python -X utf8 scripts/run_checks.py --mutate   also scripts/mutate.py (§14.11)

With an Android NDK, cargo-ndk and the aarch64-linux-android target, the
lib is also checked for the Android app (clippy, both editions); without
them that step is skipped with a note (docs/ANDROID.md).

The release checklist runs it before package_release.py.
"""
import os, pathlib, shutil, subprocess, sys

root = pathlib.Path(__file__).resolve().parents[1]
args = set(sys.argv[1:])
if args - {'--deps', '--mutate'}:
    sys.exit(__doc__)
# The default build has security keys; the keyless edition turns them off.
keyless = ['--no-default-features']
steps = [
    ['cargo', 'fmt', '--check'],
    ['cargo', 'test', '--locked'],
    ['cargo', 'test', '--locked', *keyless],
    ['cargo', 'clippy', '--all-targets', '--locked', '--', '-D', 'warnings'],
    ['cargo', 'clippy', '--all-targets', '--locked', *keyless, '--', '-D', 'warnings'],
    # Code under cfg(not(debug_assertions)) builds only here.
    ['cargo', 'build', '--release', '--locked', '--bins'],
    ['cargo', 'build', '--release', '--locked', '--bins', *keyless],
]


def android_env():
    """The environment for cargo-ndk, or the reason the Android step is
    skipped: an NDK (ANDROID_NDK_HOME, else the newest under the SDK's ndk
    folder), cargo-ndk and the rustup target."""
    ndk = os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT')
    if not ndk:
        sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
        if not sdk and os.environ.get('LOCALAPPDATA'):
            sdk = os.path.join(os.environ['LOCALAPPDATA'], 'Android', 'Sdk')
        found = sorted(pathlib.Path(sdk, 'ndk').glob('*')) if sdk else []
        ndk = str(found[-1]) if found else None
    if not ndk or not pathlib.Path(ndk).is_dir():
        return None, 'no Android NDK (set ANDROID_NDK_HOME)'
    if shutil.which('cargo-ndk') is None:
        return None, 'cargo-ndk is not installed (cargo install cargo-ndk)'
    targets = subprocess.run(['rustup', 'target', 'list', '--installed'],
                             capture_output=True, text=True).stdout.split()
    if 'aarch64-linux-android' not in targets:
        return None, 'no aarch64-linux-android target (rustup target add aarch64-linux-android)'
    return dict(os.environ, ANDROID_NDK_HOME=ndk), None


android, skipped = android_env()
if android is None:
    print(f'NOTE: Android lib check skipped: {skipped}', flush=True)
else:
    ndk = ['cargo', 'ndk', '-t', 'arm64-v8a', '--platform', '28']
    for edition in ([], keyless):
        steps.append((ndk + ['clippy', '--lib', '--locked', *edition, '--', '-D', 'warnings'],
                      android))
if '--deps' in args:
    steps.append([sys.executable, 'scripts/check_dependencies.py'])
if '--mutate' in args:
    if not (root / 'scripts' / 'mutate.py').exists():
        sys.exit('scripts/mutate.py is not in the tree yet.')
    steps.append([sys.executable, '-X', 'utf8', 'scripts/mutate.py'])
for step in steps:
    step, env = step if isinstance(step, tuple) else (step, None)
    print('>', ' '.join(step), flush=True)
    if subprocess.run(step, cwd=root, env=env).returncode != 0:
        sys.exit('FAILED: ' + ' '.join(step))
# The server script runs alone on the server: its own selftest.
selftest = subprocess.run([sys.executable, '-I', 'server/goyo-sync-server.py', 'selftest'],
                          cwd=root, capture_output=True, text=True)
if selftest.returncode != 0 or selftest.stdout.strip() != 'PASS':
    sys.exit(f'FAILED: server selftest: {selftest.stdout.strip()} {selftest.stderr.strip()}')
print('PASS')
