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

The release checklist runs it before package_release.py.
"""
import pathlib, subprocess, sys

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
if '--deps' in args:
    steps.append([sys.executable, 'scripts/check_dependencies.py'])
if '--mutate' in args:
    if not (root / 'scripts' / 'mutate.py').exists():
        sys.exit('scripts/mutate.py is not in the tree yet.')
    steps.append([sys.executable, '-X', 'utf8', 'scripts/mutate.py'])
for step in steps:
    print('>', ' '.join(step), flush=True)
    if subprocess.run(step, cwd=root).returncode != 0:
        sys.exit('FAILED: ' + ' '.join(step))
# The server script runs alone on the server: its own selftest.
selftest = subprocess.run([sys.executable, '-I', 'server/goyo-sync-server.py', 'selftest'],
                          cwd=root, capture_output=True, text=True)
if selftest.returncode != 0 or selftest.stdout.strip() != 'PASS':
    sys.exit(f'FAILED: server selftest: {selftest.stdout.strip()} {selftest.stderr.strip()}')
print('PASS')
