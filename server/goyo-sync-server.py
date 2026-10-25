#!/usr/bin/env python3
"""Goyo Sync server: keeps encrypted Goyo Vault files for goyo-sync.exe.

One run per SSH connection, like git-upload-pack: one request frame on stdin,
one response frame on stdout, then exit. No daemon, no port, no shell, no eval
and nothing outside the Python 3.8+ standard library. It never sees a key
file, a password or plaintext: it stores only GOYOVA02 files whose header
names the requested vault, so a key file (GOYOKE01/02) is refused before
anything is written.

  python3 -I goyo-sync-server.py serve [--root DIR]   answer one request
  python3 -I goyo-sync-server.py selftest            test this copy; prints PASS

Install, the forced-command key and uninstalling: docs/SYNC.md.

Storage, under <script dir>/data (--root DIR is for tests), 0700/0600:
  <32 hex of the raw vault id>/v/000000000001.goyo   immutable versions;
                                                      head = highest number
  <32 hex of the raw vault id>/tmp-<pid>-<ns>-<n>    a PUT in progress
  slot-0 .. slot-7                                    empty lock files, one per
                                                      running connection (POSIX)
"""
import errno, hashlib, itertools, os, re, signal, stat, struct, sys, time
import io, shutil, subprocess, tempfile, threading  # selftest only
try:
    import fcntl
except ImportError:  # Windows, which runs this script only for tests
    fcntl = None

# Frames are little endian. A request is the header, blob_len bytes, then EOF;
# a response is the header, its blob, then EOF. blob_sha is the SHA-256 of the
# blob, or 32 zero bytes when there is none (GET puts the client's have_sha
# there instead).
REQUEST = struct.Struct('<8sB16sQI32s')   # magic, op, vault id, version, blob_len, blob_sha (69 B)
RESPONSE = struct.Struct('<8sBQI32s')     # magic, status, version, blob_len, blob_sha (53 B)
REQUEST_MAGIC, RESPONSE_MAGIC, VAULT_MAGIC = b'GOYOSRQ1', b'GOYOSRS1', b'GOYOVA02'
HELLO, GET, PUT, LIST, FETCH = 1, 2, 3, 4, 5
OK, NOT_MODIFIED, CONFLICT, EMPTY, NOT_FOUND = 0, 1, 2, 3, 4
BAD_REQUEST, BAD_BLOB, TOO_LARGE, LIMIT, SERVER_ERROR = 10, 11, 12, 13, 20
PROTOCOL = 1
HELLO_LEN = 512                # 00..FF twice: proves the SSH channel is binary-transparent
MIN_BLOB = 96                  # GOYOVA02 header 48 + empty plaintext 32 + tag 16
MAX_BLOB = 8 * 1024 * 1024     # vault.rs MAX_FILE
MAX_VERSION = 10 ** 12 - 1     # version names have 12 digits
MAX_LIST = 64 * 1024
KEEP = 200                     # newest versions kept as encrypted history
MAX_VAULTS = 64
RESERVE = 256 * 1024 * 1024    # bytes a PUT must leave free on the root's disk
STALE_TMP = 3600               # seconds before a PUT leftover is removed
SLOTS = 8                      # connections served at once per root; more get SERVER_ERROR
# Deadlines, where SIGALRM exists. No deadline runs while a PUT works on the
# disk: the signal kills without cleanup, so it would leave the temp file behind.
HEADER_TIMEOUT = 30            # seconds for the 69-byte header to arrive
TIMEOUT = 600                  # seconds while a PUT blob arrives or a blob is sent: the helper's
                               # longest ssh timeout, so a slow line is never cut short here
REPLY_TIMEOUT = 60             # seconds to send a reply without a blob

# Shims, so the Rust tests on Windows run this same file. Without O_BINARY,
# Windows would turn every \n written into \r\n.
O_BINARY = getattr(os, 'O_BINARY', 0)
O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)
O_DIRECTORY = getattr(os, 'O_DIRECTORY', 0)
REPARSE_POINT = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
# [0-9], not \d: \d also matches non-ASCII digits.
VERSION_NAME = re.compile(r'[0-9]{12}\.goyo')
VAULT_NAME = re.compile(r'[0-9a-f]{32}')
TMP_NAME = re.compile(r'tmp-[0-9]+-[0-9]+-[0-9]+')
# Part of temp names, so two PUTs in one process (the selftest) never collide
# even when the clock has not moved.
SEQUENCE = itertools.count()


class Refused(Exception):
    """A request answered with an error status; the reason goes to stderr."""

    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status


def plain_dir(info):
    """A real directory: not a symlink, and on Windows not a junction."""
    return stat.S_ISDIR(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & REPARSE_POINT


def make_dir(path):
    """Create a 0700 folder if it is missing; refuse one that is a link."""
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    if not plain_dir(os.lstat(path)):
        raise Refused(SERVER_ERROR, 'storage folder is a link or not a directory')


def fsync_dir(path):
    """Make new names in a folder durable before OK is sent. Windows cannot
    open a folder this way; it runs this script only for tests."""
    if os.name == 'nt':
        return
    fd = os.open(path, os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        os.fsync(fd)
    except OSError as e:
        if e.errno != errno.EINVAL:  # EINVAL: this file system cannot sync folders
            raise
    finally:
        os.close(fd)


def remove(path):
    """Best-effort unlink. A leftover temp is removed by a later PUT."""
    try:
        os.unlink(path)
    except OSError:
        pass


def version_path(versions_dir, number):
    return os.path.join(versions_dir, '%012d.goyo' % number)


def list_versions(versions_dir):
    """Version numbers of the plain files in v/, ascending ([] if v/ is missing)."""
    try:
        with os.scandir(versions_dir) as entries:
            found = [int(e.name[:12]) for e in entries
                     if VERSION_NAME.fullmatch(e.name) and e.is_file(follow_symlinks=False)]
    except FileNotFoundError:
        return []
    return sorted(n for n in found if n > 0)


def read_blob(path):
    """One stored version. Links and anything over MAX_BLOB are refused, so a
    planted file cannot make the reply unbounded."""
    fd = os.open(path, os.O_RDONLY | O_BINARY | O_NOFOLLOW | O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BLOB:
            raise Refused(SERVER_ERROR, 'stored version is not a plain file of at most 8 MiB')
        parts, size = [], 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                return b''.join(parts)
            size += len(chunk)
            if size > MAX_BLOB:
                raise Refused(SERVER_ERROR, 'stored version grew over 8 MiB')
            parts.append(chunk)
    finally:
        os.close(fd)


def read_head(versions_dir):
    """(head, blob), or (0, b'') when there are no versions. Looks again if
    the head vanishes between listing and opening (deleted by hand)."""
    for _ in range(3):
        found = list_versions(versions_dir)
        if not found:
            return 0, b''
        try:
            return found[-1], read_blob(version_path(versions_dir, found[-1]))
        except FileNotFoundError:
            continue
    raise Refused(SERVER_ERROR, 'head version keeps disappearing')


def mismatch(versions_dir):
    """The answer when expected is not the head: EMPTY for a wiped vault (the
    client re-seeds with expected 0), else CONFLICT with the head itself."""
    head, blob = read_head(versions_dir)
    return (CONFLICT, head, blob) if head else (EMPTY, 0, b'')


class Store:
    """Every vault under one root.

    Compare-and-swap is os.link of a complete, fsynced temp file onto the next
    version name. link never replaces an existing name, so of two PUTs with
    the same expected version exactly one wins, with no HEAD file and no lock
    on the commit. Version files are never modified, so readers cannot see a
    torn file. flock (POSIX) is used only while a new vault folder is counted
    and made, and for the connection slots."""

    def __init__(self, root):
        self.root = root
        self.slot = None  # the fd holding this process's slot, closed at exit

    def take_slot(self, count=SLOTS):
        """Hold one of count lock files in the root until this process ends;
        False when every one is held, so a stolen key cannot start unbounded
        processes that each pin about 20 MiB. Makes the root. Without fcntl
        (Windows, tests only) there is no cap."""
        if fcntl is None:
            return True
        make_dir(self.root)
        for number in range(count):
            fd = os.open(os.path.join(self.root, 'slot-%d' % number),
                         os.O_RDWR | os.O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                continue
            except BaseException:
                os.close(fd)
                raise
            self.slot = fd
            return True
        return False

    def free_space(self):
        """Bytes this user may still write on the root's disk (its parent's
        while it is missing), or None without os.statvfs (Windows, tests only)."""
        if not hasattr(os, 'statvfs'):
            return None
        info = os.statvfs(self.root if os.path.lexists(self.root) else os.path.dirname(self.root))
        return info.f_bavail * info.f_frsize

    def new_vault(self, vault):
        """Make the folder of a new vault unless MAX_VAULTS exist. Where fcntl
        exists the count and the mkdir run under an exclusive flock on the
        root, so a burst of concurrent seeds cannot all pass the count before
        any of them makes its folder. Windows runs this only for tests."""
        fd = os.open(self.root, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) if fcntl else None
        try:
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            # Again under the lock: a rival may have made this very folder.
            if not os.path.lexists(vault) and len(self.vault_names()) >= MAX_VAULTS:
                raise Refused(LIMIT, 'vault limit reached')
            make_dir(vault)
        finally:
            if fd is not None:
                os.close(fd)  # releases the lock

    def check_root(self):
        """Refuse a root that is a link or not a folder: the vault files would
        go wherever it points. A missing root is created by the first PUT, or
        on POSIX by the first connection, for its slot file."""
        try:
            info = os.lstat(self.root)
        except FileNotFoundError:
            return
        if not plain_dir(info):
            raise Refused(SERVER_ERROR, 'storage root is a link or not a directory')

    def paths(self, vid):
        """Vault and version folders, from the raw id bytes, never client text."""
        vault = os.path.join(self.root, vid.hex())
        return vault, os.path.join(vault, 'v')

    def vault_names(self):
        try:
            with os.scandir(self.root) as entries:
                return sorted(e.name for e in entries
                              if VAULT_NAME.fullmatch(e.name) and e.is_dir(follow_symlinks=False))
        except FileNotFoundError:
            return []

    def link(self, source, target):
        """The commit point, separate so the selftest can lose this race on purpose."""
        os.link(source, target)

    def get(self, vid, have, have_sha):
        head, blob = read_head(self.paths(vid)[1])
        if not head:
            return EMPTY, 0, b''
        if head == have and hashlib.sha256(blob).digest() == have_sha:
            return NOT_MODIFIED, have, b''
        return OK, head, blob

    def put(self, vid, expected, blob, sha):
        if len(blob) < MIN_BLOB:
            raise Refused(BAD_BLOB, 'blob too short for a vault file')
        if hashlib.sha256(blob).digest() != sha:
            raise Refused(BAD_BLOB, 'blob checksum mismatch')
        # The last of three gates: only a vault file of this very vault, never
        # a key file (GOYOKE01/02), an old GOYOVA01 or another vault's file.
        if blob[:8] != VAULT_MAGIC or blob[8:24] != vid:
            raise Refused(BAD_BLOB, 'not a GOYOVA02 file of this vault')
        vault, versions_dir = self.paths(vid)
        new = not os.path.lexists(vault)
        if new and expected != 0:
            return EMPTY, 0, b''
        free = self.free_space()
        if free is not None and free - len(blob) < RESERVE:
            raise Refused(LIMIT, 'less than 256 MiB would stay free on the server disk')
        if new:
            make_dir(self.root)
            self.new_vault(vault)
        make_dir(vault)
        make_dir(versions_dir)
        found = list_versions(versions_dir)
        if (found[-1] if found else 0) != expected:
            return mismatch(versions_dir)
        if expected >= MAX_VERSION:
            raise Refused(LIMIT, 'version numbers exhausted')
        tmp = os.path.join(vault, 'tmp-%d-%d-%d' % (os.getpid(), time.time_ns(), next(SEQUENCE)))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BINARY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try:
            try:
                view = memoryview(blob)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                self.link(tmp, version_path(versions_dir, expected + 1))
            except FileExistsError:
                return mismatch(versions_dir)  # another PUT linked this version first
        finally:
            remove(tmp)
        fsync_dir(versions_dir)
        fsync_dir(vault)
        # A seed: the vault folder (and on the first PUT the root) is new, or
        # was left by an earlier PUT that died before syncing its parent.
        if expected == 0:
            fsync_dir(self.root)
            fsync_dir(os.path.dirname(self.root))
        self.prune(versions_dir)
        return OK, expected + 1, b''

    def prune(self, versions_dir):
        """Keep the newest KEEP versions of this vault and drop PUT leftovers
        older than an hour from every vault folder: a PUT that died (a crash,
        SIGKILL) may leave one where no later PUT comes. Best effort: the new
        version is already committed."""
        try:
            for number in list_versions(versions_dir)[:-KEEP]:
                remove(version_path(versions_dir, number))
            cutoff = time.time() - STALE_TMP
            for name in self.vault_names():
                try:
                    with os.scandir(os.path.join(self.root, name)) as entries:
                        stale = [e.path for e in entries
                                 if TMP_NAME.fullmatch(e.name) and e.is_file(follow_symlinks=False)
                                 and e.stat(follow_symlinks=False).st_mtime < cutoff]
                except OSError:  # removed meanwhile: the other vaults still get swept
                    continue
                for path in stale:
                    remove(path)
        except OSError:
            pass

    def listing(self, limit=MAX_LIST):
        """OK(count, '<id32> <head> <size> <mtime>\\n' per vault), at most 64 KiB."""
        lines, used = [], 0
        for name in self.vault_names():
            versions_dir = os.path.join(self.root, name, 'v')
            found = list_versions(versions_dir)
            head = size = mtime = 0
            if found:
                try:
                    info = os.lstat(version_path(versions_dir, found[-1]))
                    head, size, mtime = found[-1], info.st_size, max(0, int(info.st_mtime))
                except FileNotFoundError:  # deleted in between: listed as empty
                    pass
            line = ('%s %d %d %d\n' % (name, head, size, mtime)).encode('ascii')
            if used + len(line) > limit:
                break
            lines.append(line)
            used += len(line)
        return OK, len(lines), b''.join(lines)

    def fetch(self, vid, number):
        """OK(number, blob) for one stored version (0 = head), else NOT_FOUND."""
        versions_dir = self.paths(vid)[1]
        if number == 0:
            head, blob = read_head(versions_dir)
            return (OK, head, blob) if head else (NOT_FOUND, 0, b'')
        if number > MAX_VERSION:
            return NOT_FOUND, 0, b''
        try:
            return OK, number, read_blob(version_path(versions_dir, number))
        except FileNotFoundError:
            return NOT_FOUND, 0, b''


def read_exact(stream, size):
    """Exactly size bytes, or None if the stream ends first."""
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(min(size - len(data), 1 << 20))
        if not chunk:
            return None
        data += chunk
    return bytes(data)


def handle(inp, store, deadline, slots):
    """Parse one request and run it; returns (status, version, blob)."""
    store.check_root()
    if slots and not store.take_slot(slots):
        # Answered unread, so it cannot depend on the op: SERVER_ERROR is the
        # one status every op accepts, and the helper tries again later.
        raise Refused(SERVER_ERROR, 'busy: %d connections already running' % slots)
    header = read_exact(inp, REQUEST.size)
    if header is None:
        raise Refused(BAD_REQUEST, 'short request header')
    magic, op, vid, version, length, sha = REQUEST.unpack(header)
    zero_id, zero_sha = not any(vid), not any(sha)
    if magic != REQUEST_MAGIC:
        raise Refused(BAD_REQUEST, 'not a goyo-sync request')
    # Every field must be exactly what the op uses: a mismatch means a broken
    # client or a mangled stream, never something to guess about.
    if op == HELLO:
        valid = zero_id and version == PROTOCOL and length == HELLO_LEN
    elif op == GET:
        valid = not zero_id and length == 0
    elif op == PUT:
        valid = not zero_id
        if valid and length > MAX_BLOB:
            raise Refused(TOO_LARGE, 'blob over 8 MiB')  # answered unread: it may claim 4 GiB
    elif op == LIST:
        valid = zero_id and version == 0 and length == 0 and zero_sha
    elif op == FETCH:
        valid = not zero_id and length == 0 and zero_sha
    else:
        valid = False
    if not valid:
        raise Refused(BAD_REQUEST, 'invalid request header')
    if op == PUT:
        deadline(TIMEOUT)  # up to 8 MiB on a slow line
    blob = read_exact(inp, length)
    if blob is None:
        raise Refused(BAD_REQUEST, 'short blob')
    if inp.read(1):
        raise Refused(BAD_REQUEST, 'data after the blob')
    deadline(0)  # all read: nothing may cut the disk work short
    if op == HELLO:
        if hashlib.sha256(blob).digest() != sha:
            raise Refused(BAD_REQUEST, 'HELLO checksum mismatch')
        return OK, PROTOCOL, blob
    if op == GET:
        return store.get(vid, version, sha)
    if op == PUT:
        return store.put(vid, version, blob, sha)
    if op == LIST:
        return store.listing()
    return store.fetch(vid, version)


def send(out, status, version, blob):
    digest = hashlib.sha256(blob).digest() if blob else bytes(32)
    out.write(RESPONSE.pack(RESPONSE_MAGIC, status, version, len(blob), digest))
    if blob:
        out.write(blob)
    out.flush()


def no_deadline(seconds):
    pass


def serve(inp, out, store, err, deadline=no_deadline, slots=0):
    """Answer one request; returns the exit code. err gets one short line per
    refusal and never any blob bytes. A real run passes signal.alarm as
    deadline (seconds, 0 = none), whose signal ends the process, and SLOTS
    as slots (0 = no cap, as in the selftest)."""
    deadline(HEADER_TIMEOUT)
    try:
        status, version, blob = handle(inp, store, deadline, slots)
        note = None
    except Refused as e:
        note = str(e)
        status, version, blob = e.status, 0, b''
    except Exception as e:  # a traceback would leak paths; the type is enough
        code = e.errno if isinstance(e, OSError) else None
        note = 'internal error (%s%s)' % (type(e).__name__, ' errno %d' % code if code else '')
        status, version, blob = SERVER_ERROR, 0, b''
    # Talking to the client again: a reader that stalls is cut off, but a
    # vault file may take a slow line as long as an upload may.
    deadline(TIMEOUT if blob else REPLY_TIMEOUT)
    if note:
        err.write('goyo-sync-server: %s\n' % note)
    err.flush()
    send(out, status, version, blob)
    return 1 if status in (BAD_REQUEST, TOO_LARGE, SERVER_ERROR) else 0


class SelftestFailure(Exception):
    pass


def check(condition, what):
    if not condition:
        raise SelftestFailure(what)


def request(op, vid=bytes(16), version=0, blob=b'', sha=None, length=None):
    """A request frame as goyo-sync.exe builds it; sha and length can be forged."""
    if sha is None:
        sha = hashlib.sha256(blob).digest() if op in (HELLO, PUT) else bytes(32)
    return REQUEST.pack(REQUEST_MAGIC, op, vid, version, len(blob) if length is None else length, sha) + blob


def call(store, data, deadline=no_deadline, slots=0):
    """serve() on raw stdin bytes, checking the response the way the client
    does; returns (status, version, blob, exit code)."""
    out, err = io.BytesIO(), io.StringIO()
    code = serve(io.BytesIO(data), out, store, err, deadline, slots)
    frame = out.getvalue()
    check(len(frame) >= RESPONSE.size, 'response shorter than its header')
    magic, status, version, length, sha = RESPONSE.unpack_from(frame)
    blob = frame[RESPONSE.size:]
    check(magic == RESPONSE_MAGIC and length == len(blob), 'response framing')
    check(sha == (hashlib.sha256(blob).digest() if blob else bytes(32)), 'response checksum')
    text = err.getvalue()
    check(len(text) < 200 and all(32 <= ord(c) < 127 for c in text.rstrip('\n')),
          'stderr is one short ASCII line')
    return status, version, blob, code


def selftest_root(root, base):
    class Roomy(Store):
        """The root lies in the temp folder, which may be a small tmpfs
        (Debian): the free space reserve is tested with Full below."""

        def free_space(self):
            return None

    store = Roomy(root)
    ids = [hashlib.sha256(b'goyo selftest %d' % n).digest()[:16] for n in range(80)]
    a, c, r, m, n = ids[:5]

    def blob(vid, tag, size=160):
        filler = hashlib.sha256(b'blob %d' % tag).digest() * (size // 32 + 1)
        return VAULT_MAGIC + vid + filler[:size - 24]

    def put(vid, expected, data, **forged):
        return call(store, request(PUT, vid, expected, data, **forged))

    def get(vid, have=0, have_sha=bytes(32)):
        return call(store, request(GET, vid, have, sha=have_sha))

    def fetch(vid, number):
        return call(store, request(FETCH, vid, number))

    def tree(path):
        """Every name with its size and time, to prove nothing was written."""
        found = []
        for folder, dirs, files in os.walk(path):
            for name in dirs + files:
                info = os.lstat(os.path.join(folder, name))
                found.append((os.path.relpath(os.path.join(folder, name), path), info.st_size, info.st_mtime_ns))
        return sorted(found)

    def stored(vid, number):
        with open(version_path(store.paths(vid)[1], number), 'rb') as f:
            return f.read()

    def temps(vid):
        return [name for name in os.listdir(store.paths(vid)[0]) if name.startswith('tmp-')]

    empty, bad = (EMPTY, 0, b'', 0), (BAD_REQUEST, 0, b'', 1)

    # An empty server: reads and a PUT that expects a head create nothing.
    check(get(a) == empty, 'GET on an empty server is EMPTY')
    check(call(store, request(LIST)) == (OK, 0, b'', 0), 'LIST on an empty server')
    check(fetch(a, 0)[:2] == (NOT_FOUND, 0) and fetch(a, 3)[:2] == (NOT_FOUND, 0), 'FETCH on an empty server')
    check(put(a, 2, blob(a, 1)) == empty, 'PUT expecting a head on an empty server is EMPTY')
    echo = bytes(range(256)) * 2
    check(call(store, request(HELLO, version=1, blob=echo)) == (OK, 1, echo, 0), 'HELLO echoes 00..FF')
    check(not os.path.lexists(root), 'reads and refusals create no folder')
    check(call(store, request(HELLO, version=2, blob=echo)) == bad, 'HELLO protocol version')
    check(call(store, request(HELLO, version=1, blob=echo[:511])) == bad, 'HELLO length')
    check(call(store, request(HELLO, version=1, blob=echo, sha=bytes(32))) == bad, 'HELLO checksum')
    check(call(store, request(HELLO, a, 1, echo)) == bad, 'HELLO with a vault id')

    # Seed, then GET and NOT_MODIFIED.
    b1, b2, b3 = blob(a, 1), blob(a, 2), blob(a, 3)
    check(put(a, 0, b1) == (OK, 1, b'', 0), 'seed PUT(0) is OK(1)')
    check(stored(a, 1) == b1, 'seed stored byte for byte')
    sha1 = hashlib.sha256(b1).digest()
    check(get(a) == (OK, 1, b1, 0), 'GET returns the head')
    check(get(a, 1, sha1) == (NOT_MODIFIED, 1, b'', 0), 'GET NOT_MODIFIED when version and sha match')
    check(get(a, 1, bytes(32)) == (OK, 1, b1, 0), 'GET with another sha gets the blob')
    check(get(a, 2, sha1) == (OK, 1, b1, 0), 'GET with another version gets the blob')

    # Compare-and-swap.
    check(put(a, 0, b2) == (CONFLICT, 1, b1, 0), 'PUT(0) on a seeded vault is CONFLICT(head)')
    check(put(a, 1, b2) == (OK, 2, b'', 0), 'PUT(head) is OK(head+1)')
    check(put(a, 1, b2) == (CONFLICT, 2, b2, 0), 'a repeated PUT finds its own blob as head (OK was lost)')
    check(put(a, 1, b3) == (CONFLICT, 2, b2, 0), 'a stale PUT is CONFLICT')
    check(put(a, 9, b3) == (CONFLICT, 2, b2, 0), 'a PUT from the future is CONFLICT')
    check(fetch(a, 1) == (OK, 1, b1, 0) and fetch(a, 0) == (OK, 2, b2, 0), 'FETCH by number and head')
    check(fetch(a, 3)[:2] == (NOT_FOUND, 0) and fetch(a, 2 ** 64 - 1)[:2] == (NOT_FOUND, 0), 'FETCH missing')
    check(temps(a) == [], 'no temp file left after PUTs')

    # Two links to one name: the second fails and the first stays.
    scratch = os.path.join(base, 'link')
    os.mkdir(scratch)
    for name, data in (('x', b'first'), ('y', b'second')):
        with open(os.path.join(scratch, name), 'wb') as f:
            f.write(data)
    os.link(os.path.join(scratch, 'x'), os.path.join(scratch, 'v'))
    try:
        os.link(os.path.join(scratch, 'y'), os.path.join(scratch, 'v'))
        check(False, 'os.link replaced an existing name')
    except FileExistsError:
        pass
    with open(os.path.join(scratch, 'v'), 'rb') as f:
        check(f.read() == b'first', 'the first link keeps its content')

    # The same race inside PUT: a rival commits version 3 between our head
    # check and our link, so our link fails and we get CONFLICT(3, rival).
    winner, loser = blob(a, 4), blob(a, 5)

    class Racing(Roomy):
        rival = None

        def link(self, source, target):
            if self.rival is None:
                self.rival = call(Roomy(self.root), request(PUT, a, 2, winner))
            Store.link(self, source, target)

    racing = Racing(root)
    check(call(racing, request(PUT, a, 2, loser)) == (CONFLICT, 3, winner, 0), 'the losing link is CONFLICT')
    check(racing.rival == (OK, 3, b'', 0) and stored(a, 3) == winner, 'the winning link is OK')
    check(temps(a) == [], 'the losing PUT removed its temp file')
    if os.name != 'nt':
        # Real threads as well. Not on Windows: there the winner deleting its
        # temp name can briefly block the loser's read of the same file (a
        # sharing violation), so a round could end in SERVER_ERROR. The race
        # above covers the logic everywhere.
        for round_ in range(10):
            head = list_versions(store.paths(a)[1])[-1]
            gate, results = threading.Barrier(2), [None, None]
            blobs = [blob(a, 1000 + 2 * round_), blob(a, 1001 + 2 * round_)]

            def worker(i):
                gate.wait()
                results[i] = put(a, head, blobs[i])
            workers = [threading.Thread(target=worker, args=(i,)) for i in (0, 1)]
            for t in workers:
                t.start()
            for t in workers:
                t.join()
            check(None not in results, 'threads: both PUTs got a valid response')  # a failed check leaves None
            check(sorted(s[0] for s in results) == [OK, CONFLICT], 'threads: one OK, one CONFLICT')
            won = blobs[[s[0] for s in results].index(OK)]
            check(all(s[1] == head + 1 for s in results) and stored(a, head + 1) == won
                  and results[[s[0] for s in results].index(CONFLICT)][2] == won, 'threads: CONFLICT shows the winner')

    # Deadlines (signal.alarm in a real run): 30 s for the header, 600 s while
    # a PUT blob arrives, none from the end of the request while the PUT is on
    # the disk (the signal would leave its temp file), then 60 s for a reply,
    # or 600 s for one with a blob.
    steps = []

    class Watched(Roomy):
        def free_space(self):  # a PUT's first step on the disk
            steps.append('disk')
            return None

        def link(self, source, target):
            steps.append('link')
            Store.link(self, source, target)

    watched, head, b6 = Watched(root), list_versions(store.paths(a)[1])[-1], blob(a, 6)
    for data, answer, want, what in (
            (request(PUT, a, head, b6), (OK, head + 1, b'', 0),
             [HEADER_TIMEOUT, TIMEOUT, 0, 'disk', 'link', REPLY_TIMEOUT], 'PUT'),
            (request(PUT, a, head, b6), (CONFLICT, head + 1, b6, 0),
             [HEADER_TIMEOUT, TIMEOUT, 0, 'disk', TIMEOUT], 'PUT answered with the head'),
            (request(GET, a, head + 1, sha=hashlib.sha256(b6).digest()), (NOT_MODIFIED, head + 1, b'', 0),
             [HEADER_TIMEOUT, 0, REPLY_TIMEOUT], 'GET NOT_MODIFIED'),
            (request(GET, a), (OK, head + 1, b6, 0), [HEADER_TIMEOUT, 0, TIMEOUT], 'GET'),
            (request(PUT, a, head + 1, blob(a, 7))[:-1], bad, [HEADER_TIMEOUT, TIMEOUT, REPLY_TIMEOUT], 'short blob'),
            (b'', bad, [HEADER_TIMEOUT, REPLY_TIMEOUT], 'empty stdin')):
        del steps[:]
        check(call(watched, data, steps.append) == answer and steps == want, 'deadlines: ' + what)

    # EMPTY rules when the versions or the whole folder are gone (a wiped or
    # restored server): only expected 0 seeds again.
    check(put(c, 0, blob(c, 1)) == (OK, 1, b'', 0), 'seed c')
    remove(version_path(store.paths(c)[1], 1))
    check(get(c) == empty and fetch(c, 0)[:2] == (NOT_FOUND, 0), 'GET with no versions is EMPTY')
    check(('%s 0 0 0\n' % c.hex()).encode('ascii') in call(store, request(LIST))[2],
          'LIST shows a vault with no versions as 0 0 0')
    check(put(c, 1, blob(c, 2)) == empty, 'PUT expecting a vanished head is EMPTY')
    check(put(c, 0, blob(c, 2)) == (OK, 1, b'', 0), 'expected 0 seeds an emptied vault')
    shutil.rmtree(store.paths(c)[0])
    check(put(c, 1, blob(c, 3)) == empty and not os.path.lexists(store.paths(c)[0]),
          'PUT expecting a head of a deleted vault is EMPTY and writes nothing')
    check(put(c, 0, blob(c, 3)) == (OK, 1, b'', 0), 'expected 0 seeds a deleted vault')

    # Retention: 205 PUTs keep the newest 200; stale temps go, in every vault
    # (c gets no PUT here), and fresh ones stay.
    for i in range(204):
        check(put(r, i, blob(r, i)) == (OK, i + 1, b'', 0), 'retention PUT %d' % (i + 1))
    old, fresh = (os.path.join(store.paths(r)[0], name) for name in ('tmp-1-1-1', 'tmp-2-2-2'))
    elsewhere = os.path.join(store.paths(c)[0], 'tmp-3-3-3')
    for path in (old, fresh, elsewhere):
        with open(path, 'wb') as f:
            f.write(b'leftover')
    for path in (old, elsewhere):
        os.utime(path, (time.time() - STALE_TMP - 60,) * 2)
    check(put(r, 204, blob(r, 204)) == (OK, 205, b'', 0), 'retention PUT 205')
    check(list_versions(store.paths(r)[1]) == list(range(6, 206)), '205 PUTs leave versions 6..205')
    check(fetch(r, 5)[:2] == (NOT_FOUND, 0) and fetch(r, 6)[:2] == (OK, 6), 'pruned versions are NOT_FOUND')
    check(fetch(r, 0)[:3] == (OK, 205, blob(r, 204)), 'FETCH head after pruning')
    check(not os.path.exists(old) and os.path.exists(fresh), 'temps older than an hour are removed')
    check(not os.path.exists(elsewhere), 'stale temps of another vault are removed too')
    remove(fresh)

    # Refusals write nothing: key files, other formats, other vaults, size and
    # checksum errors, truncated or extra stdin and malformed headers.
    key01 = b'GOYOKE01' + a + hashlib.sha256(b'key 1').digest() * 3 + b'\x01' * 28  # 148 B, like a key file
    key02 = b'GOYOKE02' + a + hashlib.sha256(b'key 2').digest() * 3 + b'\x02' * 8   # 128 B
    check((len(key01), len(key02)) == (148, 128), 'key file sizes')
    before = tree(root)
    head_a = list_versions(store.paths(a)[1])[-1]
    for expected, vid, data, what in (
            (head_a, a, key01, 'GOYOKE01 key file'), (0, n, key01[:8] + n + key01[24:], 'GOYOKE01 for a new vault'),
            (head_a, a, key02, 'GOYOKE02 key file'), (0, n, key02[:8] + n + key02[24:], 'GOYOKE02 for a new vault'),
            (head_a, a, b'GOYOVA01' + b1[8:], 'GOYOVA01'), (head_a, a, b'GOYOVA03' + b1[8:], 'GOYOVA03'),
            (head_a, a, blob(c, 9), 'another vault id'), (0, n, blob(a, 9), 'another vault id, new vault'),
            (head_a, a, blob(a, 9, 95), '95 bytes'), (head_a, a, b'', 'no blob')):
        check(put(vid, expected, data) == (BAD_BLOB, 0, b'', 0), 'BAD_BLOB: ' + what)
    check(put(a, head_a, blob(a, 9), sha=bytes(32)) == (BAD_BLOB, 0, b'', 0), 'BAD_BLOB: checksum')
    check(call(store, request(PUT, a, head_a, length=MAX_BLOB + 1)) == (TOO_LARGE, 0, b'', 1),
          'TOO_LARGE answered without reading the blob')
    whole = request(PUT, a, head_a, blob(a, 9))
    for data, what in (
            (b'', 'empty stdin'), (whole[:REQUEST.size - 1], 'short header'), (whole[:-1], 'short blob'),
            (whole + b'\0', 'extra byte after the blob'), (request(GET, a) + b'\0', 'extra byte after GET'),
            (b'GOYOSRQ2' + whole[8:], 'request magic'), (request(0, a), 'op 0'), (request(6, a), 'op 6'),
            (request(GET), 'GET without an id'), (request(PUT, bytes(16), 0, blob(bytes(16), 9)), 'PUT without an id'),
            (request(FETCH), 'FETCH without an id'), (request(LIST, a), 'LIST with an id'),
            (request(LIST, version=1), 'LIST with a version'), (request(LIST, sha=b'\1' * 32), 'LIST with a sha'),
            (request(FETCH, a, sha=b'\1' * 32), 'FETCH with a sha'), (request(GET, a, 0, b'x'), 'GET with a blob'),
            (request(FETCH, a, 0, b'x'), 'FETCH with a blob'), (request(LIST, blob=b'x'), 'LIST with a blob')):
        check(call(store, data) == bad, 'BAD_REQUEST: ' + what)
    check(tree(root) == before, 'refused requests wrote nothing')

    # A PUT that would leave less than RESERVE free is LIMIT and writes
    # nothing, for a known vault and a new one.
    class Full(Store):
        free = 0

        def free_space(self):
            return self.free

    full, b10 = Full(root), blob(a, 10)
    full.free = RESERVE + len(b10) - 1
    check(call(full, request(PUT, a, head_a, b10)) == (LIMIT, 0, b'', 0)
          and call(full, request(PUT, n, 0, blob(n, 10))) == (LIMIT, 0, b'', 0), 'LIMIT below the free space reserve')
    check(tree(root) == before, 'the free space LIMIT wrote nothing')
    full.free += 1
    check(call(full, request(PUT, a, head_a, b10)) == (OK, head_a + 1, b'', 0), 'a PUT may leave exactly the reserve')
    if hasattr(os, 'statvfs'):
        check(all(isinstance(Store(path).free_space(), int) for path in (root, os.path.join(base, 'none'))),
              'os.statvfs reads the free space of the root, or of its parent while it is missing')
    else:
        check(Store(root).free_space() is None, 'no reserve without os.statvfs')

    # The largest vault file fits exactly.
    big = VAULT_MAGIC + m + bytes(MAX_BLOB - 24)
    check(put(m, 0, big) == (OK, 1, b'', 0) and fetch(m, 0) == (OK, 1, big, 0), 'an 8 MiB blob round-trips')

    # Version names have 12 digits: after the last one PUT is LIMIT, never a
    # 13-digit name that no reader would see.
    z = ids[-1]
    check(put(z, 0, blob(z, 1)) == (OK, 1, b'', 0), 'seed z')
    os.rename(version_path(store.paths(z)[1], 1), version_path(store.paths(z)[1], MAX_VERSION))
    check(put(z, MAX_VERSION, blob(z, 2)) == (LIMIT, 0, b'', 0), 'the last version number is LIMIT')
    check(list_versions(store.paths(z)[1]) == [MAX_VERSION] and temps(z) == [], 'LIMIT wrote no version')

    # The 64-vault limit refuses only new vaults. With flock, eight seeds
    # racing for the last three places get exactly three: each one's count
    # waits at the gate for the others, so without the lock all eight count
    # before any makes its folder. Windows (tests only) has no lock.
    have = len(store.vault_names())
    fill = ids[5:5 + MAX_VAULTS - have]
    racers = fill[-3:] + ids[5 + len(fill):10 + len(fill)] if fcntl else []
    for vid in fill[:len(fill) - 3] if fcntl else fill:
        check(put(vid, 0, blob(vid, 1)) == (OK, 1, b'', 0), 'seed up to the limit')
    if racers:
        gate, results = threading.Barrier(len(racers), timeout=1), [None] * len(racers)

        class Crowded(Roomy):
            def vault_names(self):
                names = Roomy.vault_names(self)
                try:
                    gate.wait()
                except threading.BrokenBarrierError:  # the lock held the others back
                    pass
                return names

        def seed(i):
            results[i] = call(Crowded(root), request(PUT, racers[i], 0, blob(racers[i], 1)))
        workers = [threading.Thread(target=seed, args=(i,)) for i in range(len(racers))]
        for t in workers:
            t.start()
        for t in workers:
            t.join()
        check(None not in results, 'racing seeds: every PUT got a valid response')
        check(sorted(s[:2] for s in results) == [(OK, 1)] * 3 + [(LIMIT, 0)] * 5
              and len(store.vault_names()) == MAX_VAULTS, 'racing seeds stop at the limit')
    before = tree(root)
    check(put(n, 0, blob(n, 1)) == (LIMIT, 0, b'', 0), 'vault 65 is LIMIT')
    check(tree(root) == before, 'LIMIT wrote nothing')
    check(put(c, 1, blob(c, 4)) == (OK, 2, b'', 0), 'existing vaults still accept PUT at the limit')

    # LIST: one line per vault, sorted, with head, size and time.
    status, count, text, code = call(store, request(LIST))
    lines = text.decode('ascii').splitlines()
    check((status, count, code) == (OK, MAX_VAULTS, 0) and len(lines) == MAX_VAULTS and text.endswith(b'\n'),
          'LIST counts every vault')
    rows = [re.fullmatch(r'([0-9a-f]{32}) ([0-9]+) ([0-9]+) ([0-9]+)', line) for line in lines]
    check(all(rows) and [row.group(1) for row in rows] == sorted(store.vault_names()), 'LIST line format')
    by_id = {row.group(1): row.groups()[1:] for row in rows}
    check(by_id[r.hex()][:2] == ('205', '160') and by_id[m.hex()][:2] == ('1', str(MAX_BLOB)), 'LIST head and size')
    check(abs(int(by_id[r.hex()][2]) - time.time()) < 3600, 'LIST time')

    # The size cap drops whole lines (64 KiB would need about 1700 folders).
    first = ''.join(line + '\n' for line in lines[:3]).encode('ascii')
    check(store.listing(limit=len(first)) == (OK, 3, first), 'LIST cap')

    # Gate 3, end to end: every stored file is a GOYOVA02 file of its own
    # vault and contains no key file bytes.
    for folder, dirs, files in os.walk(root):
        for name in files:
            with open(os.path.join(folder, name), 'rb') as f:
                data = f.read()
            vid = bytes.fromhex(os.path.basename(os.path.dirname(folder)) if name.endswith('.goyo')
                                else os.path.basename(folder))
            check(data[:8] == VAULT_MAGIC and data[8:24] == vid, 'stored file is GOYOVA02 of its vault')
            check(key01[24:] not in data and key02[24:] not in data, 'no key bytes stored')
    check(all(VAULT_NAME.fullmatch(name) for name in os.listdir(root)), 'only vault folders in the root')

    # A root that is a file or a link is refused before anything happens.
    as_file = os.path.join(base, 'file-root')
    with open(as_file, 'wb') as f:
        f.write(b'not a folder')
    check(call(Store(as_file), request(GET, a)) == (SERVER_ERROR, 0, b'', 1), 'a file as root is refused')
    linked = os.path.join(base, 'linked-root')
    try:
        os.symlink(root, linked, target_is_directory=True)
    except (OSError, NotImplementedError):
        try:  # Windows without the symlink privilege: a junction needs none
            import _winapi
            _winapi.CreateJunction(root, linked)
        except (ImportError, AttributeError, OSError):
            linked = None
    if linked:
        before = tree(root)
        for data in (request(GET, a), request(PUT, n, 0, blob(n, 1)), request(HELLO, version=1, blob=echo)):
            check(call(Store(linked), data) == (SERVER_ERROR, 0, b'', 1), 'a linked root is refused')
            check(call(Store(linked), data, slots=SLOTS) == (SERVER_ERROR, 0, b'', 1), 'a linked root gets no slot')
        check(tree(root) == before, 'a linked root wrote nothing')

    # At most SLOTS connections per root (flock): the next is answered at
    # once, without reading its request, until a slot is free again.
    if fcntl:
        crowd = os.path.join(base, 'crowd')
        holders, late = [Store(crowd) for _ in range(SLOTS)], Store(crowd)
        try:
            check(all(h.take_slot() for h in holders), 'every slot can be taken')
            check(sorted(os.listdir(crowd)) == ['slot-%d' % i for i in range(SLOTS)], 'one file per slot')
            inp, out, err = io.BytesIO(request(LIST)), io.BytesIO(), io.StringIO()
            check(serve(inp, out, late, err, slots=SLOTS) == 1 and inp.tell() == 0 and late.slot is None
                  and out.getvalue() == RESPONSE.pack(RESPONSE_MAGIC, SERVER_ERROR, 0, 0, bytes(32))
                  and 'busy' in err.getvalue(), 'no free slot: SERVER_ERROR before reading')
            # The same through a real serve process, as sshd starts it.
            done = subprocess.run([sys.executable, '-I', os.path.abspath(__file__), 'serve', '--root', crowd],
                                  input=request(LIST), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            check(done.returncode == 1 and done.stdout == out.getvalue() and b'busy' in done.stderr,
                  'no free slot: the serve process')
            os.close(holders[0].slot)
            holders[0].slot = None
            check(call(late, request(LIST), slots=SLOTS) == (OK, 0, b'', 0) and late.slot is not None,
                  'a freed slot is taken again')
        finally:
            for h in holders + [late]:
                if h.slot is not None:
                    os.close(h.slot)


def selftest():
    """Every rule against a temporary root; prints PASS, or FAIL: <check>."""
    base = tempfile.mkdtemp(prefix='goyo-sync-selftest-')
    try:
        selftest_root(os.path.join(base, 'data'), base)
    except SelftestFailure as e:
        sys.stderr.write('FAIL: %s\n' % e)
        return 1
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print('PASS')
    return 0


def main(argv):
    os.umask(0o077)
    if argv == ['selftest']:
        return selftest()
    if argv[:1] == ['serve'] and (len(argv) == 1 or (len(argv) == 3 and argv[1] == '--root' and argv[2])):
        # A stalled client cannot keep this process alive (no SIGALRM on Windows).
        deadline = getattr(signal, 'alarm', no_deadline)
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.abspath(argv[2] if len(argv) == 3 else os.path.join(here, 'data'))
        try:
            return serve(sys.stdin.buffer, sys.stdout.buffer, Store(root), sys.stderr, deadline, SLOTS)
        except BrokenPipeError:
            # The client went away. Point stdout at devnull so the exit flush is quiet.
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            return 1
    sys.stderr.write('usage: goyo-sync-server.py serve [--root DIR] | selftest\n')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
