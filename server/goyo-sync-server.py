#!/usr/bin/env python3
"""Goyo Sync server: keeps encrypted Goyo Vault files for goyo-sync.exe.

One run per SSH connection, like git-upload-pack: one request frame on stdin,
one response frame on stdout, then exit. No daemon, no port, no shell, no eval
and nothing outside the Python 3.8+ standard library. It never sees a
password or plaintext. The vault channel stores only GOYOVA02 and GOYOVA04
files (the synced vault formats, the second under a 0.9 key file) whose
header names the requested vault, so a key file (GOYOK...) is never a vault
upload.

  python3 -I goyo-sync-server.py serve [--root DIR] [--key-sync=ID[,ID...]]
                                                      answer one request
  python3 -I goyo-sync-server.py selftest            test this copy; prints PASS

Install, the forced-command key and uninstalling: docs/SYNC.md.

Key-file sync (security-key builds, the default since 0.11.0; docs/SECURITY_KEY.md).
Without --key-sync this script never stores or serves a key file: PUT
refuses every GOYOK* magic, and every key op (PUTKEY, GETKEY, CUTKEY, PRUNE)
is BAD_REQUEST. With --key-sync=<vault id>[,<vault id>...] (32 lower-case
hex digits each, distinct, at most 64, set in the forced command of every
PC that syncs those vaults; anything else, a bare --key-sync included, is a
usage error) it also stores, for the vaults it names only, GOYOKS01 key
files (they open only with the password and a registered security key with
its PIN; never GOYOKE* or GOYOKH*) as numbered records under data/<id>/k/:
the latest record and the previous key file of its generation, never
serving an older one. Turning key-file sync off appends a cut record, which
ends the generation and removes its key files. Every key operation on a
vault runs under an exclusive lock on data/<id>/lock (flock: the data root
must support it). Once a vault has k/, every connection, with or without
the flag, refuses a vault upload (KEY_BEHIND) unless it is GOYOVA04 and,
while the latest record is a key file, carries that key file's epoch,
current key ID and state tag. Vaults without k/ get no lock and no floor.
The admin may remove data/<id>/k/ only while no PC syncs that vault.

Storage, under <script dir>/data (--root DIR is for tests), 0700/0600:
  <32 hex of the raw vault id>/v/000000000001.goyo   immutable versions;
                                                      head = highest number
  <32 hex of the raw vault id>/tmp-<pid>-<ns>-<n>    a PUT in progress
  <32 hex of the raw vault id>/k/<n>-<floor>.rec      key records (20 digits
                                                      each): the newest one,
                                                      and the key file before
                                                      it in its generation
  <32 hex of the raw vault id>/k/tombs                the removed keys' IDs of
                                                      the last key record a
                                                      cut ended (never served)
  <32 hex of the raw vault id>/lock                   the vault lock: key ops,
                                                      and vault PUTs once k/
                                                      exists (flock)
  slot-0 .. slot-7                                    empty lock files, one per
                                                      running connection (POSIX)
"""
import contextlib, errno, hashlib, hmac, itertools, os, re, signal, stat, struct, sys, time
import io, shutil, subprocess, tempfile, threading  # selftest only
try:
    import fcntl
except ImportError:  # Windows, which runs this script only for tests
    fcntl = None
try:
    import msvcrt  # Windows: the vault lock of the selftest
except ImportError:
    msvcrt = None

# Frames are little endian. A request is the header, blob_len bytes, then EOF;
# a response is the header, its blob, then EOF. blob_sha is the SHA-256 of the
# blob, or 32 zero bytes when there is none (GET puts the client's have_sha
# there instead).
REQUEST = struct.Struct('<8sB16sQI32s')   # magic, op, vault id, version, blob_len, blob_sha (69 B)
RESPONSE = struct.Struct('<8sBQI32s')     # magic, status, version, blob_len, blob_sha (53 B)
REQUEST_MAGIC, RESPONSE_MAGIC = b'GOYOSRQ1', b'GOYOSRS1'
# The synced vault formats and the smallest file of each: GOYOVA02 is a 48-byte
# header, a 32-byte empty plaintext and the tag; GOYOVA04, the same contents
# under a 0.9 key file, has a 92-byte header. Everything else is refused:
# GOYOVA01/03 (sync off), newer formats and every key file.
VAULT_MAGICS = {b'GOYOVA02': 96, b'GOYOVA04': 140}
HELLO, GET, PUT, LIST, FETCH = 1, 2, 3, 4, 5
# The key ops: served only for a vault the connection's --key-sync names.
PUTKEY, GETKEY, CUTKEY, PRUNE = 6, 7, 8, 9
KEY_OPS = (PUTKEY, GETKEY, CUTKEY, PRUNE)
OK, NOT_MODIFIED, CONFLICT, EMPTY, NOT_FOUND = 0, 1, 2, 3, 4
BAD_REQUEST, BAD_BLOB, TOO_LARGE, LIMIT, KEY_BEHIND, SERVER_ERROR = 10, 11, 12, 13, 14, 20
PROTOCOL = 1
HELLO_LEN = 512                # 00..FF twice: proves the SSH channel is binary-transparent
MIN_BLOB = 96                  # the smallest synced vault file (GOYOVA02)
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
LOCK_WAIT = 20                 # seconds a request waits for a vault lock; then SERVER_ERROR "busy"
LOCK_POLL = 0.05               # seconds between two tries for it

# The one key file a server may hold: GOYOKS01 (keys with key-file sync),
# 489 bytes at least. Its grammar is the strict parse of the vault app
# (keyfile.rs is_sync_key_file), ported line by line in key_syntax below.
KEY_MAGIC = b'GOYOKS01'
MIN_KEY_FILE, MAX_KEY_FILE = 489, 32768
EPOCH_MAX = 2 ** 48 - 1        # a tombstone keeps its epoch in 48 bits
EPOCH_WINDOW = 2 ** 16         # how far above the stored floor a new key file may lie
MAX_KEYS, TOMB_MAX, MAX_SLOTS, MAX_CRED_ID = 64, 480, 8, 1023
KEY_KINDS = (2, 3, 4, 5, 6, 8, 9)  # the kinds a GOYOKS01 file may carry
WRAP, SEAL_BLOCK = 104, 88     # a committing wrap; the seal block
# A record in k/: a 32-byte header (magic, type, 7 zero bytes, gen, floor),
# then the key file as uploaded (type 1) or nothing (type 2, a cut). The
# magic is spelled in two parts: goyo-sync.exe embeds this script, and its
# release build must not hold the key channel's magics (inspect_pe.py).
RECORD = struct.Struct('<8sB7sQQ')
RECORD_MAGIC = b'GOYOS' b'KR1'
KEY_RECORD, CUT = 1, 2

# Shims, so the Rust tests on Windows run this same file. Without O_BINARY,
# Windows would turn every \n written into \r\n.
O_BINARY = getattr(os, 'O_BINARY', 0)
O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)
O_DIRECTORY = getattr(os, 'O_DIRECTORY', 0)
O_NONBLOCK = getattr(os, 'O_NONBLOCK', 0)
REPARSE_POINT = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
# [0-9], not \d: \d also matches non-ASCII digits.
VERSION_NAME = re.compile(r'[0-9]{12}\.goyo')
VAULT_NAME = re.compile(r'[0-9a-f]{32}')
ZERO_VAULT = '0' * 32
TMP_NAME = re.compile(r'tmp-[0-9]+-[0-9]+-[0-9]+')
RECORD_NAME = re.compile(r'([0-9]{20})-([0-9]{20})\.rec')
# k/tombs: the credhashes (16 bytes each, at most TOMB_MAX) of the
# tombstones of the last key record a CUTKEY ended. Never served; above a
# cut, PUTKEY's honest-server checks run against it, so a cut does not let
# a removed key's holder with a sync SSH key plant a file it authorizes.
TOMBS_NAME = 'tombs'
# Part of temp names, so two PUTs in one process (the selftest) never collide
# even when the clock has not moved.
SEQUENCE = itertools.count()


class Refused(Exception):
    """A request answered with an error status; the reason goes to stderr.
    version is what the reply carries: 0, or for a damaged stored version
    its number, so the helper can name the file to repair."""

    def __init__(self, status, reason, version=0):
        super().__init__(reason)
        self.status = status
        self.version = version


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


def is_version(info):
    """An entry of v/ that counts as a stored version, by its lstat: a plain
    file of at least MIN_BLOB bytes. A link, a folder, a FIFO or a shorter
    file (truncated, a hand edit) is no version: it never becomes the head,
    so it cannot stop GET, and read_blob and put name it as damaged."""
    return stat.S_ISREG(info.st_mode) and info.st_size >= MIN_BLOB


def list_versions(versions_dir):
    """Version numbers of the versions in v/ (is_version), ascending ([] if
    v/ is missing). A file over MAX_BLOB is listed: read_blob names it."""
    found = []
    try:
        with os.scandir(versions_dir) as entries:
            for e in entries:
                if not VERSION_NAME.fullmatch(e.name):
                    continue
                try:
                    if is_version(e.stat(follow_symlinks=False)):
                        found.append(int(e.name[:12]))
                except FileNotFoundError:  # removed meanwhile
                    continue
    except FileNotFoundError:
        return []
    return sorted(n for n in found if n > 0)


def damaged(number, what):
    """SERVER_ERROR naming stored version number, so the helper can say
    which file on the server to remove or repair."""
    return Refused(SERVER_ERROR, 'version %012d on the server is %s: remove or repair it'
                   % (number, what), number)


def read_blob(path, number):
    """Stored version number at path. Anything but a plain file of
    MIN_BLOB..MAX_BLOB bytes is SERVER_ERROR carrying number (damaged), so a
    planted file cannot make the reply unbounded. The entry is checked
    before it is opened, and opened with O_NONBLOCK and without following a
    link, so a FIFO or device put there never blocks this process; the open
    file must be the entry that was checked."""
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise damaged(number, 'not a plain file')
    fd = os.open(path, os.O_RDONLY | O_BINARY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise damaged(number, 'not a plain file')
        if info.st_size > MAX_BLOB:
            raise damaged(number, 'a file of %d bytes, over 8 MiB' % info.st_size)
        parts, size = [], 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BLOB:
                raise damaged(number, 'a file that grew over 8 MiB')
            parts.append(chunk)
        if size < MIN_BLOB:
            raise damaged(number, 'a file of %d bytes, under 96' % size)
        return b''.join(parts)
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
            return found[-1], read_blob(version_path(versions_dir, found[-1]), found[-1])
        except FileNotFoundError:
            continue
    raise Refused(SERVER_ERROR, 'head version keeps disappearing')


def mismatch(versions_dir):
    """The answer when expected is not the head: EMPTY for a wiped vault (the
    client re-seeds with expected 0), else CONFLICT with the head itself."""
    head, blob = read_head(versions_dir)
    return (CONFLICT, head, blob) if head else (EMPTY, 0, b'')


def version_epoch(path):
    """The key-file epoch in a stored version's header: 0 for GOYOVA02, None
    for anything that is not a plain file starting like GOYOVA02/04."""
    fd = os.open(path, os.O_RDONLY | O_BINARY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        head = os.read(fd, 48)
    finally:
        os.close(fd)
    if head[:8] == b'GOYOVA02':
        return 0
    return struct.unpack('<Q', head[40:48])[0] if head[:8] == b'GOYOVA04' and len(head) == 48 else None


# ---- the grammar of GOYOKS01 (gate 3; spec v3 sections 4.1, 4.6, 7.13) ----

def ks_id_zero(vid):
    """The keyset ID of an all-zero keyset secret: HKDF-SHA256 with salt
    goyo-vault/v2/ks-id over 32 zero bytes and info = the vault ID. Public,
    so every parser refuses a file that carries it."""
    prk = hmac.new(b'goyo-vault/v2/ks-id', bytes(32), hashlib.sha256).digest()
    return hmac.new(prk, vid + b'\x01', hashlib.sha256).digest()[:16]


def credhash(cred_id):
    return hashlib.sha256(b'goyo-vault/v2/cred\0' + cred_id).digest()[:16]


def state_tag(region):
    """The state tag of a key file from its bytes [0, W)."""
    return hashlib.sha256(b'goyo-vault/v2/state\0' + hashlib.sha256(region).digest()).digest()[:16]


class Short(Exception):
    """A field read past the end of a key file."""


class Fields:
    """Reads a key file's fields in order; past its end is Short."""

    def __init__(self, data, at):
        self.data, self.at = data, at

    def take(self, size):
        if self.at + size > len(self.data):
            raise Short()
        part = self.data[self.at:self.at + size]
        self.at += size
        return part

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack('<H', self.take(2))[0]

    def u64(self):
        return struct.unpack('<Q', self.take(8))[0]


class KeySyntax:
    """What the server uses of a GOYOKS01 file that passed key_syntax."""

    def __init__(self, epoch, w, key_id, authorizer, tombs, live):
        self.epoch = epoch            # the file's epoch
        self.w = w                    # where its seal block starts: the tag covers [0, W)
        self.key_id = key_id          # key_ids[0], the current data key's ID
        self.authorizer = authorizer  # the credhash of the authorizing key
        self.tombs = tombs            # the credhashes of its tombstones (a frozenset)
        self.live = live              # the credhashes of its live keys


def key_syntax(blob, vid):
    """KeySyntax when blob is a GOYOKS01 key file of vault vid by every rule
    of the strict parse (keyfile.rs parse restricted by is_sync_key_file),
    else None. Public bytes only; the bound sizes are checked before any
    list is read, and the file must end exactly where its layout does."""
    if blob[:8] != KEY_MAGIC or not MIN_KEY_FILE <= len(blob) <= MAX_KEY_FILE or blob[8:24] != vid:
        return None
    try:
        return parse_key(blob, vid)
    except Short:
        return None


def parse_key(blob, vid):
    r = Fields(blob, 24)
    epoch, flags, k, n, nxt, count = r.u64(), r.u8(), r.u8(), r.u8(), r.u8(), r.u16()
    kind, authorizer, present, suspended, p = r.u8(), r.u8(), r.u8(), r.u8(), r.u8()
    reserved, ks_id, pw_id = r.take(5), r.take(16), r.take(16)
    r.take(16)  # written and loss: display only
    # GOYOKS01 is always PIN mode (flags bit1); bit0 is an old OTP vault's TOTP
    # secret in the body (the OTP was removed: no new file sets it).
    if not (1 <= epoch <= EPOCH_MAX and flags in (2, 3) and 1 <= k <= MAX_KEYS and nxt >= 1
            and count <= TOMB_MAX and kind in KEY_KINDS and reserved == bytes(5) and pw_id != bytes(16)):
        return None
    if not (1 <= n <= MAX_SLOTS and p <= n * (n - 1) and (present | suspended) >> n == 0
            and present & suspended == 0 and authorizer < n and present >> authorizer & 1
            and ks_id != bytes(16) and ks_id != ks_id_zero(vid)):
        return None
    key_ids = [r.take(16) for _ in range(k)]
    if len(set(key_ids)) != k:
        return None
    stones = [(r.take(16), r.u64()) for _ in range(count)]
    order = [(removed & EPOCH_MAX, ch) for ch, removed in stones]
    if (len({ch for ch, _ in stones}) != count or any(a >= b for a, b in zip(order, order[1:]))
            or not all(1 <= removed_at <= epoch for removed_at, _ in order)):
        return None
    slots = []  # (number, added_epoch, added_by, cred_id, credhash)
    for _ in range(n):
        slot_kind, slot_flags, number, slot_reserved = r.u8(), r.u8(), r.u8(), r.u8()
        r.u64()  # registered: display only
        added_epoch, added_by = r.u64(), r.take(16)
        r.take(32)  # the hmac seed
        c = r.u16()
        # Every slot of a PIN-mode file is a PIN slot (flags 3).
        if not (slot_kind == 1 and slot_flags == 3 and slot_reserved == 0
                and number > (slots[-1][0] if slots else 0) and 1 <= c <= MAX_CRED_ID
                and 1 <= added_epoch <= epoch):
            return None
        cred_id = r.take(c)
        slots.append((number, added_epoch, added_by, cred_id, credhash(cred_id)))
    dead = {ch for ch, _ in stones}
    hashes = {s[4] for s in slots}
    if len({s[3] for s in slots}) != n or len(hashes) != n or hashes & dead:
        return None
    # Which slots this write added, by the kind of the write.
    new = [i for i in range(n) if slots[i][1] == epoch]
    if kind == 8:    # a re-seed: every key present, none suspended, none new
        ok = present == (1 << n) - 1 and suspended == 0 and not new
    elif kind == 3:  # an addition: exactly one new key, present, added by the authorizer
        ok = len(new) == 1 and present >> new[0] & 1 and slots[authorizer][4] == slots[new[0]][2]
    elif kind == 5:  # pairing: at least two keys present, none new
        ok = bin(present).count('1') >= 2 and not new
    else:
        ok = not new
    if not ok:
        return None
    pairs = []
    for _ in range(p):
        owner, target, pair_reserved = r.u8(), r.u8(), r.take(2)
        if not (pair_reserved == bytes(2) and owner != target and owner < n and target < n):
            return None
        r.take(WRAP)
        pairs.append((owner, target))
    if any(a >= b for a, b in zip(pairs, pairs[1:])):
        return None
    # One S-wrap per live slot that is not suspended, in slot order: through
    # the key itself when it was touched, else through the authorizer and
    # its pair record.
    for j in range(n):
        if suspended >> j & 1:
            continue
        recipient, via = r.u8(), r.u8()
        if recipient != j or not (via == j if present >> j & 1 else
                                  via == authorizer and (authorizer, j) in pairs):
            return None
        r.take(WRAP)
    w = r.at
    r.take(SEAL_BLOCK)
    r.take(32 + 32 * k + (20 if flags & 1 else 0) + 16)  # C_body, then the body and its tag
    r.take(32 * k)  # the chain
    if r.at != len(blob):
        return None
    return KeySyntax(epoch, w, key_ids[0], slots[authorizer][4], frozenset(dead), tuple(s[4] for s in slots))


def honest(new, tombs):
    """The honest-server checks of a new key file against the tombstones of
    the stored latest one (or, above a cut, of the last key record a cut
    ended): it keeps every tombstone, lists no tombstoned key live and is
    not authorized by one. Hygiene only; every PC runs them too."""
    return tombs <= new.tombs and not tombs & set(new.live) and new.authorizer not in tombs


class Record:
    """A record of k/ as read_state reads it; served is what a reply carries."""

    def __init__(self, number, kind, gen, floor, served, syntax=None, damaged=False):
        self.number, self.kind, self.gen, self.floor = number, kind, gen, floor
        self.served, self.syntax, self.damaged = served, syntax, damaged


def record_header(kind, gen, floor, damaged=False):
    return RECORD.pack(RECORD_MAGIC, kind, bytes([damaged]) + bytes(6), gen, floor)


def parse_record(data, number, floor, vid):
    """The record named <number>-<floor>.rec, or None when its contents break
    the grammar: the header (its floor equal to the name's), and a key file
    of this vault at that epoch below its own number, or a bare cut that
    carries its own number."""
    if len(data) < RECORD.size:
        return None
    magic, kind, reserved, gen, head_floor = RECORD.unpack_from(data)
    if magic != RECORD_MAGIC or reserved != bytes(7) or head_floor != floor:
        return None
    if kind == KEY_RECORD:
        syntax = key_syntax(data[RECORD.size:], vid)
        if syntax is None or syntax.epoch != floor or gen >= number:
            return None
        return Record(number, KEY_RECORD, gen, floor, data, syntax)
    if kind == CUT and len(data) == RECORD.size and gen == number:
        return Record(number, CUT, gen, floor, data)
    return None


class Namespace:
    """What read_state found in k/: the records as sorted (number, floor,
    name, regular file), the temps, the top record T (None for none) and
    whether the record below it is kept (the previous key file of T's
    generation)."""

    def __init__(self, records=(), temps=(), top=None, keep=False):
        self.records, self.temps, self.top, self.keep = list(records), list(temps), top, keep


def try_lock(fd):
    """Takes the exclusive lock of fd without waiting; False while another
    descriptor holds it. POSIX: flock, which belongs to the open file
    description, so two descriptors conflict even in one process. Windows
    (the selftest only): one byte with LockFile through msvcrt, which a
    second handle conflicts with too."""
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        except OSError as e:
            if e.errno in (errno.ENOLCK, errno.EOPNOTSUPP, getattr(errno, 'ENOTSUP', errno.EOPNOTSUPP)):
                raise Refused(SERVER_ERROR, 'no file locking here')
            raise
        return True
    if msvcrt is not None:
        os.lseek(fd, 0, 0)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    raise Refused(SERVER_ERROR, 'no file locking here')


class VaultLock:
    """A held vault lock. Released by release() (or leaving a with block),
    and by the kernel when the process dies: no owner record, no takeover."""

    def __init__(self, fd):
        self.fd = fd

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()

    def release(self):
        fd, self.fd = self.fd, None
        if fd is None:
            return
        try:
            if fcntl is None and msvcrt is not None:
                os.lseek(fd, 0, 0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass  # closing releases it as well
        finally:
            os.close(fd)


class Store:
    """Every vault under one root.

    Compare-and-swap is os.link of a complete, fsynced temp file onto the next
    version name. link never replaces an existing name, so of two PUTs with
    the same expected version exactly one wins, with no HEAD file and no lock
    on the commit. Version files are never modified, so readers cannot see a
    torn file. flock (POSIX) is used while a new vault folder is counted and
    made, for the connection slots, and as the vault lock: every key op runs
    under it, and so does a vault PUT once the vault has k/. Lock order:
    slot, root (released before the next step), one vault lock."""

    def __init__(self, root, key_sync=()):
        self.root = root
        self.slot = None  # the fd holding this process's slot, closed at exit
        self.key_sync = frozenset(key_sync)  # raw IDs of the vaults --key-sync names
        self.lock_wait = LOCK_WAIT
        self.note = None  # a line for stderr beside an answer that is not a refusal

    def step(self, name):
        """A named point of a key op (folder, locking, temp, link, unlinked,
        commit): nothing here; the selftest stops (a simulated kill) or
        pauses an op at one."""

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
        """The vault folders. An all-zero name is none: no request may name
        that ID, so LIST never shows a row nobody could fetch."""
        try:
            with os.scandir(self.root) as entries:
                return sorted(e.name for e in entries
                              if VAULT_NAME.fullmatch(e.name) and e.name != ZERO_VAULT
                              and e.is_dir(follow_symlinks=False))
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
        # a key file (GOYOK...), a format that is not synced or another vault's.
        if len(blob) < VAULT_MAGICS.get(blob[:8], MAX_BLOB + 1) or blob[8:24] != vid:
            raise Refused(BAD_BLOB, 'not a GOYOVA02/04 file of this vault')
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

        def behind():
            """The answer when expected is not the head, else None."""
            found = list_versions(versions_dir)
            if (found[-1] if found else 0) != expected:
                return mismatch(versions_dir)
            if expected >= MAX_VERSION:
                raise Refused(LIMIT, 'version numbers exhausted')
            return None
        # Once the vault has k/ (key-file sync named it on some line), the
        # floor, the head check and the link run under its vault lock, on
        # every connection, after the temp is written. Without k/ nothing
        # changes: no lock and no lock file.
        keyed = os.path.lexists(os.path.join(vault, 'k'))
        answer = None if keyed else behind()
        if answer:
            return answer
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
            with self.vault_lock(vid) if keyed else contextlib.nullcontext():
                if keyed:
                    self.floor(vid, blob)
                    answer = behind()
                    if answer:
                        return answer
                target = version_path(versions_dir, expected + 1)
                try:
                    self.link(tmp, target)
                except FileExistsError:
                    # Another PUT linked this version first, or something
                    # that is no version (a link, a folder, a FIFO, a short
                    # file) holds its name: then no PUT can ever commit it,
                    # so that is named, not answered as a CONFLICT the
                    # helper would read as a server holding uploads back.
                    # lstat: a link there is never followed.
                    try:
                        held = is_version(os.lstat(target))
                    except FileNotFoundError:  # removed meanwhile: the head tells
                        held = True
                    if not held:
                        raise damaged(expected + 1, 'a name held by a link, folder or short file')
                    return mismatch(versions_dir)
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
            return OK, number, read_blob(version_path(versions_dir, number), number)
        except FileNotFoundError:
            return NOT_FOUND, 0, b''

    # ---- key-file sync: the vault lock, k/ and ops 6-9 (spec v3 section 7.13) ----

    def vault_lock(self, vid):
        """Holds data/<id>/lock (made if missing; the vault folder must
        exist), polling every LOCK_POLL seconds for at most lock_wait, then
        SERVER_ERROR "busy". A lock file that is a link, has a second name
        or is not a plain file is refused."""
        path = os.path.join(self.paths(vid)[0], 'lock')
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | O_BINARY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise Refused(SERVER_ERROR, 'vault lock is a link or not a plain file')
            raise
        try:
            # After the open, which may have made the file: the name must
            # still be this very file.
            info, named = os.fstat(fd), os.lstat(path)
            if not (stat.S_ISREG(info.st_mode) and stat.S_ISREG(named.st_mode) and info.st_nlink == 1
                    and not getattr(named, 'st_file_attributes', 0) & REPARSE_POINT
                    and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino)):
                raise Refused(SERVER_ERROR, 'vault lock is a link or not a plain file')
            start = time.monotonic()
            while not try_lock(fd):
                if time.monotonic() - start >= self.lock_wait:
                    raise Refused(SERVER_ERROR, 'busy: vault lock held')
                time.sleep(LOCK_POLL)
        except BaseException:
            os.close(fd)
            raise
        return VaultLock(fd)

    def key_folder(self, vid):
        """(vault folder, k/, whether k/ exists). A vault folder or a k/
        that is a link or not a directory is refused."""
        vault = self.paths(vid)[0]
        keys = os.path.join(vault, 'k')
        for path in (vault, keys):
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                return vault, keys, False
            if not plain_dir(info):
                raise Refused(SERVER_ERROR, 'k/ or its vault folder is a link or not a directory')
        return vault, keys, True

    def make_vault(self, vault):
        """The vault folder, made as a vault PUT makes it when it is missing
        (the 64-vault limit applies)."""
        self.step('folder')
        if not os.path.lexists(vault):
            make_dir(self.root)
            self.new_vault(vault)
        make_dir(vault)

    def scan_keys(self, keys):
        """The records of k/ as sorted (number, floor, name, regular file)
        and the names of the temps. A record name that is a link or a
        directory, or a file with a second name, is refused (the one second
        name allowed is a temp of k/: a key op killed between its link and
        its temp's removal); so are two names with one number. Any other
        name is ignored, a record name numbered 0 or past EPOCH_MAX
        included, so no answer carries such a number."""
        with os.scandir(keys) as entries:
            names = [e.name for e in entries]
        temps, inodes = [], {}
        for name in names:
            if TMP_NAME.fullmatch(name):
                temps.append(name)
                try:
                    info = os.lstat(os.path.join(keys, name))
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(info.st_mode):
                    inode = (info.st_dev, info.st_ino)
                    inodes[inode] = inodes.get(inode, 0) + 1
        records = []
        for name in names:
            match = RECORD_NAME.fullmatch(name)
            if not match:
                continue
            number, floor = int(match.group(1)), int(match.group(2))
            if not (1 <= number <= EPOCH_MAX and floor <= EPOCH_MAX):
                continue
            info = os.lstat(os.path.join(keys, name))
            regular = stat.S_ISREG(info.st_mode)
            if (stat.S_ISLNK(info.st_mode) or stat.S_ISDIR(info.st_mode)
                    or getattr(info, 'st_file_attributes', 0) & REPARSE_POINT
                    or regular and info.st_nlink - 1 != inodes.get((info.st_dev, info.st_ino), 0)):
                raise Refused(SERVER_ERROR, 'link in k/')
            records.append((number, floor, name, regular))
        records.sort()
        if any(a[0] == b[0] for a, b in zip(records, records[1:])):
            raise Refused(SERVER_ERROR, 'duplicate record')
        return records, temps

    def read_record(self, path):
        """A record's bytes (at most one byte past the largest record, which
        then fails the grammar), or None when it is not a plain file."""
        fd = os.open(path, os.O_RDONLY | O_BINARY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            limit, parts, size = RECORD.size + MAX_KEY_FILE + 1, [], 0
            while size < limit:
                chunk = os.read(fd, limit - size)
                if not chunk:
                    break
                parts.append(chunk)
                size += len(chunk)
            return b''.join(parts)
        finally:
            os.close(fd)

    def load(self, vid, keys, entry):
        """One record; a damaged one (not a plain file, or its contents break
        the grammar) reads as a cut at its own number, flagged damaged
        (header byte 9 = 1), with the floor in its name. Other read errors
        are raised."""
        number, floor, name, regular = entry
        data = self.read_record(os.path.join(keys, name)) if regular else None
        record = parse_record(data, number, floor, vid) if data is not None else None
        if record is None:
            record = Record(number, CUT, number, floor, record_header(CUT, number, floor, True), damaged=True)
        return record

    def read_state(self, vid, keys, exists, previous=True):
        """The namespace of k/ under the vault lock: its top record T as
        served; with previous, whether tidy() keeps the record below it.
        Writes nothing. A top that cannot be read for another reason than
        damage (EIO, EACCES, ...) is SERVER_ERROR: read as damage it would
        begin a new generation."""
        if not exists:
            return Namespace()
        records, temps = self.scan_keys(keys)
        if not records:
            return Namespace(records, temps)
        try:
            top = self.load(vid, keys, records[-1])
        except OSError as e:
            raise Refused(SERVER_ERROR, 'cannot read the top key record (%s)' % type(e).__name__)
        if top.damaged:
            self.note = 'damaged key record read as a cut'
        keep = False
        if previous and top.kind == KEY_RECORD and len(records) > 1 and records[-2][0] == top.number - 1:
            try:
                below = self.load(vid, keys, records[-2])
            except OSError:
                below = None  # never served: it only goes
            keep = below is not None and below.kind == KEY_RECORD and below.gen == top.gen
        return Namespace(records, temps, top, keep)

    def tidy(self, keys, state):
        """Removes every temp of k/ (the lock proves its writer is gone) and
        every record but the top and, while both are key records of one
        generation, the one below it (the previous key file). It removes
        only what read_state ignores and never the top name, so it changes
        no answer and record numbers are never reused."""
        kept = {state.records[-1][2]} if state.records else set()
        if state.keep:
            kept.add(state.records[-2][2])
        gone = [name for name in state.temps] + [r[2] for r in state.records if r[2] not in kept]
        removed = False
        for name in gone:
            try:
                os.unlink(os.path.join(keys, name))
                removed = True
            except OSError:
                pass  # best effort: no answer reads it
        if removed:
            fsync_dir(keys)

    def read_tombs(self, keys):
        """The tombstones k/tombs keeps (a frozenset); none when it is
        missing, not a plain file or malformed (hygiene only: every PC runs
        the same checks)."""
        try:
            fd = os.open(os.path.join(keys, TOMBS_NAME), os.O_RDONLY | O_BINARY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        except OSError:
            return frozenset()
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return frozenset()
            data = os.read(fd, 16 * TOMB_MAX + 1)
        except OSError:
            return frozenset()
        finally:
            os.close(fd)
        if len(data) % 16 or len(data) > 16 * TOMB_MAX:
            return frozenset()
        return frozenset(data[i:i + 16] for i in range(0, len(data), 16))

    def write_tombs(self, keys, tombs):
        """Replaces k/tombs with tombs, durably: a temp of k/ (which tidy()
        removes after a kill), fsync, one rename, fsync of k/."""
        tmp = os.path.join(keys, 'tmp-%d-%d-%d' % (os.getpid(), time.time_ns(), next(SEQUENCE)))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BINARY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try:
            try:
                view = memoryview(b''.join(sorted(tombs)))
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, os.path.join(keys, TOMBS_NAME))
        except BaseException:
            remove(tmp)
            raise
        fsync_dir(keys)

    def tidy_after(self, vid, keys):
        """tidy() after a commit, best effort: the record is committed."""
        try:
            self.tidy(keys, self.read_state(vid, keys, True))
        except (OSError, Refused):
            pass

    def append(self, keys, number, floor, record):
        """Commits a record as <number>-<floor>.rec: a temp in k/, fsync, one
        os.link (the commit point), the temp's removal, fsync of k/. A kill
        before the link leaves the before-state and a temp that the next key
        op's tidy() removes; one after it, the after-state."""
        if number > EPOCH_MAX:
            raise Refused(SERVER_ERROR, 'record numbers exhausted')
        tmp = os.path.join(keys, 'tmp-%d-%d-%d' % (os.getpid(), time.time_ns(), next(SEQUENCE)))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BINARY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try:
            try:
                view = memoryview(record)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            self.step('temp')
            try:
                self.link(tmp, os.path.join(keys, '%020d-%020d.rec' % (number, floor)))
            except FileExistsError:  # cannot happen under the lock
                raise Refused(SERVER_ERROR, 'internal: record name taken')
            self.step('link')
        except Exception:
            remove(tmp)
            raise
        remove(tmp)
        self.step('unlinked')
        fsync_dir(keys)
        self.step('commit')

    def make_keys(self, vault, keys):
        """k/, made inside the lock, and its name made durable together with
        the vault folder's, which this op may have made."""
        make_dir(keys)
        fsync_dir(vault)
        fsync_dir(self.root)
        fsync_dir(os.path.dirname(self.root))

    def floor(self, vid, blob):
        """The vault floor, under the vault lock (KEY_BEHIND): below a key
        record a vault upload must be GOYOVA04 with that key file's epoch,
        current key ID and state tag; below a cut (a damaged top included)
        any GOYOVA04; a k/ with no record is no floor."""
        top = self.read_state(vid, *self.key_folder(vid)[1:], previous=False).top
        if top is None:
            return
        if top.kind == KEY_RECORD:
            payload = top.served[RECORD.size:]
            ok = (blob[:8] == b'GOYOVA04' and blob[40:48] == struct.pack('<Q', top.floor)
                  and blob[24:40] == top.syntax.key_id and blob[48:64] == state_tag(payload[:top.syntax.w]))
        else:
            ok = blob[:8] == b'GOYOVA04'
        if not ok:
            raise Refused(KEY_BEHIND, 'vault file does not match the stored key file')

    def put_key(self, vid, base, blob, sha):
        """PUTKEY: stores a GOYOKS01 file as record base + 1 when base is the
        top record (the epoch CAS) and its epoch lies above the top's floor
        by at most EPOCH_WINDOW."""
        if hashlib.sha256(blob).digest() != sha:
            raise Refused(BAD_BLOB, 'blob checksum mismatch')
        new = key_syntax(blob, vid)
        if new is None:
            raise Refused(BAD_BLOB, 'not a GOYOKS01 key file of this vault')
        vault, keys, exists = self.key_folder(vid)
        if not exists and base != 0:
            return EMPTY, 0, b''  # nothing created, no lock
        free = self.free_space()
        if free is not None and free - len(blob) < RESERVE:
            raise Refused(LIMIT, 'less than 256 MiB would stay free on the server disk')
        self.make_vault(vault)
        self.step('locking')
        with self.vault_lock(vid):
            vault, keys, exists = self.key_folder(vid)
            state = self.read_state(vid, keys, exists)
            self.tidy(keys, state)
            top = state.top
            number = top.number if top else 0
            if number == 0 and base != 0:
                return EMPTY, 0, b''
            if number != base:
                return CONFLICT, number, top.served
            floor = top.floor if top else 0
            if not floor < new.epoch <= floor + EPOCH_WINDOW:
                raise Refused(BAD_BLOB, 'epoch window')
            # Above a cut (a damaged top included), against the tombstones of
            # the last key record a cut ended.
            if top and not honest(new, top.syntax.tombs if top.kind == KEY_RECORD else self.read_tombs(keys)):
                raise Refused(BAD_BLOB, 'tombstone or authorizer check')
            # A generation is named by the cut that began it (0 before any).
            header = record_header(KEY_RECORD, top.gen if top and top.kind == KEY_RECORD else number, new.epoch)
            if not exists:
                self.make_keys(vault, keys)
            self.append(keys, number + 1, new.epoch, header + blob)
            self.tidy_after(vid, keys)
        return OK, number + 1, header

    def get_key(self, vid, have, have_sha):
        """GETKEY: the top record as served, never an older one."""
        if not self.key_folder(vid)[2]:
            return EMPTY, 0, b''  # no lock
        with self.vault_lock(vid):
            vault, keys, exists = self.key_folder(vid)
            state = self.read_state(vid, keys, exists)
            self.tidy(keys, state)
        top = state.top
        if top is None:
            return EMPTY, 0, b''
        if have == top.number and hashlib.sha256(top.served).digest() == have_sha:
            return NOT_MODIFIED, have, b''
        return OK, top.number, top.served

    def cut_key(self, vid, base):
        """CUTKEY: ends the generation that holds record base. A no-op when
        the top is an undamaged cut numbered above base, or a key record of a
        later generation; otherwise a cut is appended (on the cut numbered
        base, or on nothing, a fence that a PUTKEY built on base meets as
        CONFLICT)."""
        vault = self.key_folder(vid)[0]
        self.make_vault(vault)
        self.step('locking')
        with self.vault_lock(vid):
            vault, keys, exists = self.key_folder(vid)
            if not exists:
                self.make_keys(vault, keys)
            state = self.read_state(vid, keys, True)
            self.tidy(keys, state)
            top = state.top
            if top and not top.damaged and (top.number > base if top.kind == CUT else top.gen > base):
                return OK, top.number, top.served
            number, floor = (top.number, top.floor) if top else (0, 0)
            # The ended key file's tombstones stay for PUTKEY's checks above
            # the cut; a cut on a cut (or on a damaged top) keeps them.
            if top and top.kind == KEY_RECORD and not top.damaged:
                self.write_tombs(keys, top.syntax.tombs)
            cut = record_header(CUT, number + 1, floor)
            self.append(keys, number + 1, floor, cut)
            self.tidy_after(vid, keys)
        return OK, number + 1, cut

    def prune_below(self, vid, epoch):
        """PRUNE: removes the stored versions whose header epoch is below
        epoch (GOYOVA02 counts as 0), never the head; NOT_FOUND while the
        head is below it. Takes no lock and never reads k/."""
        versions_dir = self.paths(vid)[1]
        for _ in range(3):
            found = list_versions(versions_dir)
            if not found:
                return NOT_FOUND, 0, b''
            try:
                head = version_epoch(version_path(versions_dir, found[-1]))
                break
            except FileNotFoundError:
                continue
        else:
            raise Refused(SERVER_ERROR, 'head version keeps disappearing')
        if head is None or head < epoch:
            return NOT_FOUND, 0, b''
        count = 0
        for number in found[:-1]:
            path = version_path(versions_dir, number)
            try:
                old = version_epoch(path)
                if old is not None and old < epoch:
                    os.unlink(path)
                    count += 1
            except FileNotFoundError:  # pruned meanwhile by a PUT's retention
                continue
        if count:
            fsync_dir(versions_dir)
        return OK, count, b''


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
    # The key ops exist only for the vaults this connection's --key-sync
    # names; for any other vault they create nothing.
    if op in KEY_OPS and not store.key_sync:
        raise Refused(BAD_REQUEST, 'key sync is off on this server')
    if op in KEY_OPS and vid not in store.key_sync:
        raise Refused(BAD_REQUEST, 'key sync is off for this vault on this connection')
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
    elif op == PUTKEY:  # version: the record this upload builds on
        valid = not zero_id
        if valid and length > MAX_KEY_FILE:
            raise Refused(TOO_LARGE, 'key file over 32 KiB')  # answered unread
    elif op == GETKEY:  # version and sha: the record held and its SHA-256
        valid = not zero_id and length == 0
    elif op == CUTKEY:  # version: the record whose generation to end
        valid = not zero_id and length == 0 and zero_sha and version <= EPOCH_MAX
    elif op == PRUNE:   # version: the lowest epoch to keep
        valid = not zero_id and length == 0 and zero_sha and version >= 1
    else:
        valid = False
    if not valid:
        raise Refused(BAD_REQUEST, 'invalid request header')
    if op in (PUT, PUTKEY):
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
    if op == FETCH:
        return store.fetch(vid, version)
    if op == PUTKEY:
        return store.put_key(vid, version, blob, sha)
    if op == GETKEY:
        return store.get_key(vid, version, sha)
    if op == CUTKEY:
        return store.cut_key(vid, version)
    return store.prune_below(vid, version)


def send(out, status, version, blob):
    digest = hashlib.sha256(blob).digest() if blob else bytes(32)
    out.write(RESPONSE.pack(RESPONSE_MAGIC, status, version, len(blob), digest))
    if blob:
        out.write(blob)
    out.flush()


def no_deadline(seconds):
    pass


def serve(inp, out, store, err, deadline=no_deadline, slots=0):
    """Answer one request; returns the exit code. err gets at most one short
    line (a refusal's reason, or a note such as a damaged key record read as
    a cut) and never any blob bytes. A real run passes signal.alarm as
    deadline (seconds, 0 = none), whose signal ends the process, and SLOTS
    as slots (0 = no cap, as in the selftest)."""
    deadline(HEADER_TIMEOUT)
    store.note = None
    try:
        status, version, blob = handle(inp, store, deadline, slots)
        note = store.note  # at most one line: a refusal's own note replaces it
    except Refused as e:
        note = str(e)
        status, version, blob = e.status, e.version, b''
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
        sha = hashlib.sha256(blob).digest() if op in (HELLO, PUT, PUTKEY) else bytes(32)
    return REQUEST.pack(REQUEST_MAGIC, op, vid, version, len(blob) if length is None else length, sha) + blob


def call(store, data, deadline=no_deadline, slots=0, notes=None):
    """serve() on raw stdin bytes, checking the response the way the client
    does; returns (status, version, blob, exit code), and appends what went
    to stderr to notes when given."""
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
    if notes is not None:
        notes.append(text)
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

    def blob(vid, tag, size=160, magic=b'GOYOVA02'):
        filler = hashlib.sha256(b'blob %d' % tag).digest() * (size // 32 + 1)
        return magic + vid + filler[:size - 24]

    def keyed(vid, tag, size=160):
        """GOYOVA04: a vault under a 0.9 key file."""
        return blob(vid, tag, size, b'GOYOVA04')

    def put(vid, expected, data, **forged):
        return call(store, request(PUT, vid, expected, data, **forged))

    def get(vid, have=0, have_sha=bytes(32)):
        return call(store, request(GET, vid, have, sha=have_sha))

    def fetch(vid, number):
        return call(store, request(FETCH, vid, number))

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

    # GOYOVA04, a vault under a 0.9 key file, is stored and served like
    # GOYOVA02, from its 140 bytes up.
    head = list_versions(store.paths(a)[1])[-1]
    smallest, larger = keyed(a, 8, 140), keyed(a, 9)
    check(put(a, head, smallest) == (OK, head + 1, b'', 0) and stored(a, head + 1) == smallest,
          'GOYOVA04 of 140 bytes is stored')
    check(put(a, head + 1, larger) == (OK, head + 2, b'', 0) and get(a) == (OK, head + 2, larger, 0)
          and fetch(a, head + 1) == (OK, head + 1, smallest, 0), 'GOYOVA04 is served')
    check(put(n, 0, keyed(n, 1)) == (OK, 1, b'', 0), 'GOYOVA04 seeds a new vault')
    shutil.rmtree(store.paths(n)[0])

    # An entry at a version name that is no version (a short or empty file,
    # a folder, a link, a FIFO) never becomes the head, so reads go on, and
    # the PUT and FETCH that meet it answer SERVER_ERROR carrying its number
    # (with it in the stderr line): the helper names the file to repair.
    # An oversize file is the head, named the same way. A FIFO is answered
    # at once: read_blob checks before it opens and never blocks.
    shapes = Roomy(os.path.join(base, 'shapes'))
    seeded = [blob(a, 40 + i) for i in range(3)]
    for i, data in enumerate(seeded):
        check(call(shapes, request(PUT, a, i, data)) == (OK, i + 1, b'', 0), 'shapes: seed')
    slot4 = version_path(shapes.paths(a)[1], 4)
    named = (SERVER_ERROR, 4, b'', 1)

    def answers(what):
        notes = []
        check(call(shapes, request(GET, a)) == (OK, 3, seeded[2], 0), what + ': GET still serves version 3')
        listed = call(shapes, request(LIST))[2]
        check(listed.startswith(('%s 3 160 ' % a.hex()).encode('ascii')) and listed.count(b'\n') == 1,
              what + ': LIST shows version 3')
        check(call(shapes, request(PUT, a, 3, blob(a, 43)), notes=notes) == named,
              what + ': PUT onto it is SERVER_ERROR(4), not CONFLICT')
        check(call(shapes, request(FETCH, a, 4), notes=notes) == named, what + ': FETCH 4 is SERVER_ERROR(4)')
        check(all('000000000004' in note for note in notes), what + ': the stderr line names version 4')
        check(list_versions(shapes.paths(a)[1]) == [1, 2, 3], what + ': no version 4 was made')

    for size in (0, 10, MIN_BLOB - 1):
        with open(slot4, 'wb') as f:
            f.write(blob(a, 44, MIN_BLOB)[:size])
        answers('a %d-byte file' % size)
        os.unlink(slot4)
    os.mkdir(slot4)
    answers('a folder')
    os.rmdir(slot4)
    try:
        os.symlink(version_path(shapes.paths(a)[1], 3), slot4)
    except (OSError, NotImplementedError):  # Windows without the symlink privilege
        pass
    else:
        answers('a link to version 3')
        os.unlink(slot4)
    if hasattr(os, 'mkfifo'):
        os.mkfifo(slot4)
        done = []
        worker = threading.Thread(target=lambda: done.append(answers('a FIFO')), daemon=True)
        worker.start()
        worker.join(30)
        if worker.is_alive():  # an open that blocks: a writer releases it
            os.close(os.open(slot4, os.O_WRONLY | O_NONBLOCK))
            worker.join(30)
        check(done == [None], 'a FIFO at a version name is answered at once')
        os.unlink(slot4)
    with open(slot4, 'wb') as f:
        f.write(seeded[2][:MIN_BLOB])
        f.truncate(MAX_BLOB + 1)
    notes = []
    check(call(shapes, request(GET, a), notes=notes) == named
          and call(shapes, request(PUT, a, 3, blob(a, 43)), notes=notes) == named
          and call(shapes, request(FETCH, a, 0), notes=notes) == named
          and call(shapes, request(FETCH, a, 4), notes=notes) == named
          and all('000000000004' in note for note in notes), 'an oversize head is SERVER_ERROR(4)')
    check(call(shapes, request(FETCH, a, 3)) == (OK, 3, seeded[2], 0), 'versions below it are served')
    os.unlink(slot4)
    check(call(shapes, request(PUT, a, 3, blob(a, 43))) == (OK, 4, b'', 0), 'once removed, version 4 commits')

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
    # 0.9 key files: password only (312 B at least), and with security keys,
    # local or synced (489 B at least). None of them is ever a vault upload.
    kf2 = [blob(a, 20 + i, size, magic) for i, (magic, size) in
           enumerate(((b'GOYOKE03', 312), (b'GOYOKH01', 489), (b'GOYOKS01', 489), (b'GOYOKS01', 2048)))]
    before = tree(root)
    head_a = list_versions(store.paths(a)[1])[-1]
    for expected, vid, data, what in (
            (head_a, a, key01, 'GOYOKE01 key file'), (0, n, key01[:8] + n + key01[24:], 'GOYOKE01 for a new vault'),
            (head_a, a, key02, 'GOYOKE02 key file'), (0, n, key02[:8] + n + key02[24:], 'GOYOKE02 for a new vault'),
            (head_a, a, kf2[0], 'GOYOKE03 key file'), (head_a, a, kf2[1], 'GOYOKH01 key file'),
            (head_a, a, kf2[2], 'GOYOKS01 key file'), (0, n, kf2[3][:8] + n + kf2[3][24:], 'GOYOKS01 for a new vault'),
            (head_a, a, b'GOYOVA01' + b1[8:], 'GOYOVA01'), (head_a, a, b'GOYOVA03' + b1[8:], 'GOYOVA03'),
            (head_a, a, b'GOYOVA05' + b1[8:], 'GOYOVA05'), (head_a, a, keyed(a, 9, 139), 'GOYOVA04 of 139 bytes'),
            (head_a, a, keyed(c, 9), 'GOYOVA04 of another vault'),
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
    big = b'GOYOVA02' + m + bytes(MAX_BLOB - 24)
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

    # LIST: one line per vault, sorted, with head, size and time. A folder
    # with the all-zero name (made by hand) is no vault: never listed.
    os.mkdir(os.path.join(root, ZERO_VAULT))
    status, count, text, code = call(store, request(LIST))
    os.rmdir(os.path.join(root, ZERO_VAULT))
    check(ZERO_VAULT.encode('ascii') not in text, 'LIST shows no all-zero vault ID')
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

    # Gate 3, end to end: every stored file is a GOYOVA02 or GOYOVA04 file of
    # its own vault, never one starting like a key file, and contains no key
    # file bytes.
    for folder, dirs, files in os.walk(root):
        for name in files:
            with open(os.path.join(folder, name), 'rb') as f:
                data = f.read()
            vid = bytes.fromhex(os.path.basename(os.path.dirname(folder)) if name.endswith('.goyo')
                                else os.path.basename(folder))
            check(data[:8] in VAULT_MAGICS and data[8:24] == vid, 'stored file is GOYOVA02/04 of its vault')
            check(not data.startswith(b'GOYOK'), 'no stored file starts like a key file')
            check(all(key[24:] not in data for key in [key01, key02] + kf2), 'no key bytes stored')
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


def filler(seed, size):
    """Deterministic bytes for what no grammar reads (wraps, the seal block,
    the body, the chain) and for the contents of test vault files."""
    block = hashlib.sha256(b'goyo selftest filler ' + seed).digest()
    return (block * (size // 32 + 1))[:size]


class KeyFile(bytes):
    """A key file the selftest built; w is where its seal block starts."""


def key_fields(vid, epoch, tag=0):
    """The fields of a GOYOKS01 file (kind 6) with three keys numbered 1, 2
    and 4: the first present and the authorizer, the second reached through
    the first's pair record, the third suspended; two tombstones, one with a
    loss mark. tag varies the data key and the keyset ID."""
    def h(text):
        return hashlib.sha256(text).digest()
    slots = [{'kind': 1, 'flags': 3, 'number': number, 'reserved': 0, 'registered': 1767225600 + number,
              'added_epoch': 1, 'added_by': bytes(16), 'seed': h(b'seed %d' % number),
              'cred': b'credential %d' % number} for number in (1, 2, 4)]
    tombs = sorted([(credhash(b'gone 1'), 1), (credhash(b'gone 2'), 1 | 9 << 48)],
                   key=lambda t: (t[1] & EPOCH_MAX, t[0]))
    return {'magic': KEY_MAGIC, 'vid': vid, 'epoch': epoch, 'flags': 2, 'next': 5, 'kind': 6,
            'keys': [h(b'data key %d' % tag)[:16], h(b'id key')[:16]], 'tombs': tombs,
            'authorizer': 0, 'present': 0b001, 'suspended': 0b100, 'reserved': bytes(5),
            'ks_id': h(b'keyset %d' % tag)[:16], 'pw_id': h(b'password')[:16],
            'written': 1767225600, 'loss': 0, 'slots': slots,
            'pairs': [(0, 1, bytes(2)), (1, 0, bytes(2))], 'wraps': [(0, 0), (1, 0)], 'extra': b''}


def build_key(f):
    """The file the fields describe, in the layout of spec v3 section 4.1;
    k, n, the tombstone count and p come from the lists unless set."""
    k, otp = len(f['keys']), f['flags'] & 1
    out = f['magic'] + f['vid'] + struct.pack(
        '<QBBBBHBBBBB', f['epoch'], f['flags'], f.get('k', k), f.get('n', len(f['slots'])), f['next'],
        f.get('count', len(f['tombs'])), f['kind'], f['authorizer'], f['present'], f['suspended'],
        f.get('p', len(f['pairs'])))
    out += f['reserved'] + f['ks_id'] + f['pw_id'] + struct.pack('<QQ', f['written'], f['loss'])
    out += b''.join(f['keys']) + b''.join(ch + struct.pack('<Q', removed) for ch, removed in f['tombs'])
    for s in f['slots']:
        out += struct.pack('<BBBBQQ', s['kind'], s['flags'], s['number'], s['reserved'], s['registered'],
                           s['added_epoch'])
        out += s['added_by'] + s['seed'] + struct.pack('<H', len(s['cred'])) + s['cred']
    for owner, target, reserved in f['pairs']:
        out += bytes([owner, target]) + reserved + filler(b'pair', WRAP)
    for recipient, via in f['wraps']:
        out += bytes([recipient, via]) + filler(b'wrap', WRAP)
    w = len(out)
    out += filler(b'tail', SEAL_BLOCK + 32 + 32 * k + 20 * otp + 16 + 32 * k) + f['extra']
    built = KeyFile(out)
    built.w = w
    return built


def key_cases(vid):
    """(name, file, valid) for gate 3's grammar: a valid file of each kind
    and of each size bound, then each syntax rule broken once on a valid
    base. The script runs alone on the server (setup.rs), so its table
    lives here; the Rust side is held to it by a differential test."""
    def h(text):
        return hashlib.sha256(text).digest()

    def by_order(tombs):
        return sorted(tombs, key=lambda t: (t[1] & EPOCH_MAX, t[0]))

    def base(**changes):
        f = key_fields(vid, 10)
        f.update(changes)
        return f

    def kind3():
        f = base(kind=3, present=0b011, wraps=[(0, 0), (1, 1)])
        f['slots'][1].update(added_epoch=10, added_by=credhash(f['slots'][0]['cred']))
        return f

    def kind5():
        return base(kind=5, present=0b011, wraps=[(0, 0), (1, 1)])

    def kind8():
        return base(kind=8, present=0b111, suspended=0, wraps=[(0, 0), (1, 1), (2, 2)])

    def smallest():
        f = base(keys=[h(b'only key')[:16]], tombs=[], pairs=[], wraps=[(0, 0)], suspended=0)
        f['slots'] = [dict(f['slots'][0], cred=b'x')]
        return f

    def largest():
        f = base(flags=3, kind=8, present=0xFF, suspended=0, keys=[h(b'key %d' % i)[:16] for i in range(MAX_KEYS)],
                 tombs=by_order((h(b'gone %d' % i)[:16], 1 + i % 10) for i in range(TOMB_MAX)),
                 pairs=[(o, t, bytes(2)) for o in range(8) for t in range(8) if o != t],
                 wraps=[(j, j) for j in range(8)])
        f['slots'] = [dict(f['slots'][0], number=j + 1, cred=bytes([j]) * MAX_CRED_ID) for j in range(8)]
        return f

    def eight():
        f = base(present=0b1, suspended=0b11111110, pairs=[], wraps=[(0, 0)])
        f['slots'] = [dict(f['slots'][0], number=j + 1, cred=b'key %d' % j) for j in range(8)]
        return f

    def ninth(f):
        """A ninth key, past what the masks can address."""
        f['slots'].append(dict(f['slots'][0], number=9, cred=b'key 8'))
        f.update(pairs=[(0, 8, bytes(2))], wraps=[(0, 0), (8, 0)])

    def upd(**changes):
        return lambda f: f.update(changes)

    def slot(i, **changes):
        return lambda f: f['slots'][i].update(changes)

    def tomb(i, removed):
        return lambda f: f['tombs'].__setitem__(i, (f['tombs'][i][0], removed))

    def pair(i, record):
        return lambda f: f['pairs'].__setitem__(i, record)

    def wrap(i, record):
        return lambda f: f['wraps'].__setitem__(i, record)

    valid = [('kind 6: a key through a pair record, a suspended key', base()),
             ('kind 2', base(kind=2)), ('kind 4', base(kind=4)), ('kind 9', base(kind=9)),
             ('kind 3', kind3()), ('kind 5', kind5()), ('kind 8', kind8()), ('an OTP vault', base(flags=3)),
             ('eight keys', eight()), ('the smallest file', smallest()), ('the largest file', largest())]
    rules = [
        (base, 'magic GOYOKS02', upd(magic=b'GOYOKS02')), (base, 'magic GOYOKH01', upd(magic=b'GOYOKH01')),
        (base, 'magic GOYOKE03', upd(magic=b'GOYOKE03')), (base, 'magic GOYOKE01', upd(magic=b'GOYOKE01')),
        (base, 'magic GOYOVA04', upd(magic=b'GOYOVA04')), (base, 'another vault', upd(vid=h(b'another')[:16])),
        (base, 'epoch 0', upd(epoch=0)), (base, 'epoch 2^48', upd(epoch=EPOCH_MAX + 1)),
        (base, 'epoch 2^48 + 1', upd(epoch=EPOCH_MAX + 2)), (base, 'epoch 2^64 - 1', upd(epoch=2 ** 64 - 1)),
        (base, 'flags 0: not PIN mode', upd(flags=0)), (base, 'flags 1', upd(flags=1)),
        (base, 'flag bit 2', upd(flags=6)), (base, 'flag bit 7', upd(flags=0x82)),
        (base, 'no data key', upd(keys=[])), (base, '65 data keys', upd(keys=[h(b'key %d' % i)[:16] for i in range(65)])),
        (base, 'next 0', upd(next=0)),
        (base, '481 tombstones', upd(tombs=by_order((h(b'gone %d' % i)[:16], 1) for i in range(TOMB_MAX + 1)))),
        (base, 'kind 0', upd(kind=0)), (base, 'kind 1', upd(kind=1)), (base, 'kind 7', upd(kind=7)),
        (base, 'kind 10', upd(kind=10)), (base, 'kind 11', upd(kind=11)),
        (base, 'authorizer at n', upd(authorizer=3)),
        (base, 'authorizer outside the present mask', upd(present=0b010, suspended=0b101, wraps=[(1, 1)])),
        (base, 'a suspended authorizer', upd(present=0b010, suspended=0b001, wraps=[(1, 1), (2, 0)])),
        (base, 'present bit at n', upd(present=0b1001)), (base, 'suspended bit at n', upd(suspended=0b1100)),
        (base, 'present and suspended', upd(present=0b101)),
        (base, 'p above n(n-1)', upd(pairs=[(o, t, bytes(2)) for o in range(3) for t in range(3) if o != t]
                                     + [(2, 1, bytes(2))])),
    ] + [(base, 'reserved byte %d' % (43 + i), upd(reserved=bytes(i) + b'\x01' + bytes(4 - i))) for i in range(5)] + [
        (base, 'ks_id zero', upd(ks_id=bytes(16))), (base, 'ks_id of an all-zero secret', upd(ks_id=ks_id_zero(vid))),
        (base, 'pw_id zero', upd(pw_id=bytes(16))),
        (base, 'duplicate data key IDs', lambda f: f['keys'].__setitem__(1, f['keys'][0])),
        (base, 'tombstones out of order', lambda f: f['tombs'].reverse()),
        (base, 'duplicate tombstone', lambda f: f['tombs'].__setitem__(1, (f['tombs'][0][0], 2))),
        (base, 'tombstone at epoch 0', tomb(0, 0)), (base, 'tombstone at epoch 0 with a loss mark', tomb(0, 1 << 48)),
        (base, 'tombstone above the epoch', tomb(1, 11 | 1 << 48)),
        (base, 'a live key tombstoned', lambda f: f.update(tombs=by_order(f['tombs'] + [(credhash(b'credential 2'), 2)]))),
        (base, 'slot kind 0', slot(1, kind=0)), (base, 'slot kind 2', slot(1, kind=2)),
        (base, 'slot flags 2: not a PIN slot', slot(1, flags=2)), (base, 'slot flags 1', slot(1, flags=1)),
        (base, 'slot flags 4', slot(1, flags=4)), (base, 'slot reserved byte', slot(1, reserved=1)),
        (base, 'key number 0', slot(0, number=0)), (base, 'key numbers out of order', slot(1, number=9)),
        (base, 'duplicate key number', slot(1, number=1)), (base, 'empty credential ID', slot(1, cred=b'')),
        (base, 'credential ID of 1024 bytes', slot(1, cred=b'\x22' * 1024)),
        (base, 'duplicate credential ID', slot(1, cred=b'credential 1')),
        (base, 'added at epoch 0', slot(1, added_epoch=0)), (base, 'added above the epoch', slot(1, added_epoch=11)),
        (base, 'a key added in a write of kind 6', slot(1, added_epoch=10)),
        (base, 'no key', upd(slots=[], present=0, suspended=0, pairs=[], wraps=[])),
        (eight, 'nine keys', ninth),
        (kind8, 'kind 8 with a key not present', upd(present=0b011)),
        (kind8, 'kind 8 with a suspended key', upd(present=0b011, suspended=0b100, wraps=[(0, 0), (1, 1)])),
        (kind8, 'kind 8 with a new key', slot(1, added_epoch=10)),
        (kind3, 'kind 3 with no new key', slot(1, added_epoch=1)),
        (kind3, 'kind 3 with two new keys', slot(0, added_epoch=10)),
        (kind3, 'kind 3 whose new key is not present', upd(present=0b001, wraps=[(0, 0), (1, 0)])),
        (kind3, 'kind 3 not added by its authorizer', slot(1, added_by=credhash(b'credential 4'))),
        (kind5, 'kind 5 with one key present', upd(present=0b001, wraps=[(0, 0), (1, 0)])),
        (base, 'pair records out of order', lambda f: f['pairs'].reverse()),
        (base, 'duplicate pair record', lambda f: f['pairs'].insert(0, (0, 1, bytes(2)))),
        (base, 'pair record to itself', lambda f: f['pairs'].append((2, 2, bytes(2)))),
        (base, 'pair record owner at n', lambda f: f['pairs'].append((3, 0, bytes(2)))),
        (base, 'pair record target at n', lambda f: f['pairs'].append((2, 3, bytes(2)))),
        (base, 'pair record reserved byte 2', pair(1, (1, 0, b'\x01\x00'))),
        (base, 'pair record reserved byte 3', pair(1, (1, 0, b'\x00\x01'))),
        (base, 'missing S-wrap', lambda f: f['wraps'].pop()),
        (base, 'S-wrap for a suspended key', lambda f: f['wraps'].append((2, 0))),
        (base, 'S-wraps out of order', lambda f: f['wraps'].reverse()),
        (base, 'via neither recipient nor authorizer', wrap(1, (1, 2))),
        (base, 'via without its pair record', lambda f: f['pairs'].pop(0)),
        (base, 'a key not present through itself', wrap(1, (1, 1))),
        (kind5, 'a present key through the authorizer', wrap(1, (1, 0))),
        (base, 'one byte appended', upd(extra=b'\x00')),
    ]
    cases = [(name, build_key(f), True) for name, f in valid]
    for make, name, change in rules:
        f = make()
        check(key_syntax(build_key(f), vid) is not None, 'the base of %s is valid' % name)
        change(f)
        cases.append((name, build_key(f), False))
    file = build_key(base())
    largest_file = build_key(largest())
    check((len(build_key(smallest())), len(largest_file)) == (MIN_KEY_FILE, 32532), 'the bounds of the layout')
    cases += [('one byte short', file[:-1], False),
              ('the OTP bit without an OTP secret', file[:32] + b'\x03' + file[33:], False),
              ('32769 bytes', largest_file + bytes(MAX_KEY_FILE + 1 - len(largest_file)), False),
              ('GOYOVA02', b'GOYOVA02' + vid + filler(b'vault', 72), False)]
    return cases


def tree(path):
    """Every name with its size and time, to prove nothing was written."""
    found = []
    for folder, dirs, files in os.walk(path):
        for name in dirs + files:
            info = os.lstat(os.path.join(folder, name))
            found.append((os.path.relpath(os.path.join(folder, name), path), info.st_size, info.st_mtime_ns))
    return sorted(found)


# The child of selftest row 4 (b): holds a vault lock until it is killed.
HOLDER = ('import importlib.util, sys, time\n'
          'spec = importlib.util.spec_from_file_location("goyo_sync_server", sys.argv[1])\n'
          'server = importlib.util.module_from_spec(spec)\n'
          'spec.loader.exec_module(server)\n'
          'held = server.Store(sys.argv[2]).vault_lock(bytes.fromhex(sys.argv[3]))\n'
          'print("held", flush=True)\n'
          'time.sleep(600)\n')


class Killed(BaseException):
    """A simulated kill at a point of a key op: no cleanup of the op runs,
    only the lock's release (the kernel's, on a real kill)."""


def selftest_keys(base):
    """Key-file sync (spec v3 section 7.13, selftest rows 1-12), each case
    on a fresh root under base."""
    ids = [hashlib.sha256(b'goyo key selftest %d' % n).digest()[:16] for n in range(80)]
    a, b, c = ids[:3]
    roots, scanned = itertools.count(), []
    bad = (BAD_REQUEST, 0, b'', 1)

    class Roomy(Store):
        """The root lies in the temp folder, which may be a small tmpfs."""

        def free_space(self):
            return None

    class Paused(Roomy):
        """Stops a key op at one of its points until go is set."""

        def __init__(self, root, named, at):
            Roomy.__init__(self, root, named)
            self.at, self.inside, self.go = at, threading.Event(), threading.Event()

        def step(self, name):
            if name == self.at:
                self.inside.set()
                self.go.wait(60)

    class Rival(Roomy):
        """Runs another request once, at a point of this op before its lock."""
        point, data, answer = 'locking', None, None

        def step(self, name):
            if name == self.point and self.answer is None:
                self.answer = call(Roomy(self.root, self.key_sync), self.data)

    class Crashing(Roomy):
        at = None

        def step(self, name):
            if name == self.at:
                raise Killed(name)

    class Unreadable(Roomy):
        """Reading the top record fails with error (not damage)."""
        error, top = None, None

        def read_record(self, path):
            if os.path.basename(path) == self.top:
                raise self.error
            return Roomy.read_record(self, path)

    def fresh(*named):
        store = Roomy(os.path.join(base, 'keys-%d' % next(roots)), named)
        scanned.append(store)
        return store

    def ks(vid, epoch, tag=0, **changes):
        f = key_fields(vid, epoch, tag)
        f.update(changes)
        return build_key(f)

    def key(gen, data):
        """The key record of data in generation gen."""
        return record_header(KEY_RECORD, gen, struct.unpack('<Q', data[24:32])[0]) + data

    def sealed(vid, key_file, seed, epoch=None, key_id=None, state=None):
        """A GOYOVA04 file written under key_file's state, or with one field
        of its header changed."""
        epoch = struct.unpack('<Q', key_file[24:32])[0] if epoch is None else epoch
        head = (b'GOYOVA04' + vid + (key_file[96:112] if key_id is None else key_id) + struct.pack('<Q', epoch)
                + (state_tag(key_file[:key_file.w]) if state is None else state) + b'\x03\x00\x00\x00')
        return head + filler(b'vault %d' % seed, 140 - len(head))

    def anywhere(vid, seed, epoch):
        """A GOYOVA04 file under some key state at epoch."""
        return sealed(vid, ks(vid, 2, 1000 + seed), seed, epoch=epoch)

    def plain(vid, seed):
        return b'GOYOVA02' + vid + filler(b'vault %d' % seed, 72)

    def in_thread(run):
        got = []
        worker = threading.Thread(target=lambda: got.append(run()))
        worker.start()
        return worker, got

    def putkey(store, vid, on, data, **forged):
        return call(store, request(PUTKEY, vid, on, data, **forged))

    def getkey(store, vid, have=0, have_sha=bytes(32)):
        return call(store, request(GETKEY, vid, have, sha=have_sha))

    def cutkey(store, vid, on):
        return call(store, request(CUTKEY, vid, on))

    def put(store, vid, expected, data):
        return call(store, request(PUT, vid, expected, data))

    def noted(store, data, want, words):
        """The answer, with exactly one stderr line holding words."""
        notes = []
        answer = call(store, data, notes=notes)
        return answer == want and len(notes[0].splitlines()) == 1 and words in notes[0]

    def kdir(store, vid):
        return os.path.join(store.paths(vid)[0], 'k')

    def numbers(store, vid):
        """The record numbers in k/, and whether a temp is there."""
        names = os.listdir(kdir(store, vid))
        return sorted(int(n[:20]) for n in names if RECORD_NAME.fullmatch(n)), any(TMP_NAME.fullmatch(n) for n in names)

    def payloads(store, vid):
        """How many records in k/ carry a key file."""
        count = 0
        for name in os.listdir(kdir(store, vid)):
            if RECORD_NAME.fullmatch(name):
                with open(os.path.join(kdir(store, vid), name), 'rb') as f:
                    count += f.read(9)[8:9] == bytes([KEY_RECORD])
        return count

    def record_path(store, vid, number):
        names = [n for n in os.listdir(kdir(store, vid)) if n.startswith('%020d-' % number)]
        check(len(names) == 1, 'one record numbered %d' % number)
        return os.path.join(kdir(store, vid), names[0])

    f2, f3, f4 = ks(a, 2, 1), ks(a, 3, 2), ks(a, 4, 3)

    # Row 1: without --key-sync every key op is BAD_REQUEST and creates
    # nothing; a vault without k/ takes GOYOVA04 at any epoch and gets no
    # lock file.
    store = fresh()
    for data in (request(PUTKEY, a, 0, f2), request(GETKEY, a), request(CUTKEY, a, 0), request(PRUNE, a, 1)):
        check(noted(store, data, bad, 'key sync is off on this server'), 'key ops without --key-sync')
    check(not os.path.lexists(store.root), 'key ops without --key-sync create nothing')
    check(put(store, a, 0, anywhere(a, 1, 7)) == (OK, 1, b'', 0) and put(store, a, 1, anywhere(a, 2, 3)) == (OK, 2, b'', 0)
          and put(store, a, 2, plain(a, 3)) == (OK, 3, b'', 0), 'a vault without k/ has no floor')
    check(sorted(os.listdir(store.paths(a)[0])) == ['v'], 'a vault without k/ gets no lock file and no k/')
    # With --key-sync=<A>, the key ops of vault B create nothing.
    store = fresh(a)
    for data in (request(PUTKEY, b, 0, ks(b, 2)), request(GETKEY, b), request(CUTKEY, b, 0), request(PRUNE, b, 1)):
        check(noted(store, data, bad, 'key sync is off for this vault on this connection'), 'key ops of an unnamed vault')
    check(not os.path.lexists(store.paths(b)[0]), 'key ops of an unnamed vault create nothing')
    # The floor binds every connection once k/ exists.
    check(putkey(store, a, 0, f2)[:2] == (OK, 1), 'PUTKEY(0) stores the first key file')
    check(put(Roomy(store.root), a, 0, sealed(a, f2, 1)) == (OK, 1, b'', 0)
          and put(Roomy(store.root), a, 1, anywhere(a, 2, 2)) == (KEY_BEHIND, 0, b'', 0)
          and put(Roomy(store.root, (b,)), a, 1, anywhere(a, 3, 2)) == (KEY_BEHIND, 0, b'', 0),
          'the floor applies on a connection without --key-sync, or naming another vault')
    # A k/ holding nothing, or only a temp, is no floor.
    store = fresh(c)
    check(put(store, c, 0, plain(c, 1)) == (OK, 1, b'', 0), 'seed c')
    os.mkdir(kdir(store, c))
    check(put(store, c, 1, plain(c, 2)) == (OK, 2, b'', 0), 'an empty k/ is no floor')
    check(putkey(store, c, 3, ks(c, 2)) == (EMPTY, 0, b'', 0), 'PUTKEY on a record of an empty k/: EMPTY')
    with open(os.path.join(kdir(store, c), 'tmp-1-1-1'), 'wb') as f:
        f.write(record_header(KEY_RECORD, 0, 2) + f2)
    check(put(store, c, 2, plain(c, 3)) == (OK, 3, b'', 0), 'a k/ with only a temp is no floor')
    os.unlink(os.path.join(kdir(store, c), 'tmp-1-1-1'))
    # The command line: exactly serve [--root DIR] [--key-sync=ID[,ID...]].
    r = os.path.join(base, 'r')
    for argv in (['serve', '--key-sync'], ['serve', '--key-sync='], ['serve', '--key-sync', a.hex()],
                 ['serve', '--key-sync=' + a.hex().upper()], ['serve', '--key-sync=' + a.hex()[:-1]],
                 ['serve', '--key-sync=%s,%s' % (a.hex(), a.hex())], ['serve', '--key-sync=' + a.hex() + ','],
                 ['serve', '--key-sync=' + ','.join(i.hex() for i in ids[:65])],
                 ['serve', '--key-sync=' + a.hex(), '--root', r], ['serve', '--root', r, '--key-sync=' + a.hex(), 'x'],
                 ['serve', '--root'], ['serve', '--root', ''], ['serve', '--keysync=' + a.hex()]):
        check(serve_args(argv) is None, 'refused: %s' % ' '.join(argv)[:60])
    check(serve_args(['serve']) == (None, ()) and serve_args(['serve', '--root', r]) == (r, ())
          and serve_args(['serve', '--root', r, '--key-sync=%s,%s' % (a.hex(), b.hex())]) == (r, (a, b))
          and serve_args(['serve', '--key-sync=' + ','.join(i.hex() for i in ids[:64])]) == (None, tuple(ids[:64])),
          'the forms of serve')
    script, r = os.path.abspath(__file__), os.path.join(base, 'keys-%d' % next(roots))
    done = subprocess.run([sys.executable, '-I', script, 'serve', '--root', r, '--key-sync'],
                          input=request(GETKEY, a), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    check(done.returncode == 2 and done.stdout == b'' and b'usage' in done.stderr, 'main() refuses a bare --key-sync')
    done = subprocess.run([sys.executable, '-I', script, 'serve', '--root', r, '--key-sync=' + a.hex()],
                          input=request(GETKEY, a), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    check(done.returncode == 0 and done.stdout == RESPONSE.pack(RESPONSE_MAGIC, EMPTY, 0, 0, bytes(32)),
          'serve --key-sync=<id> answers a key op')

    # Malformed key-op requests, and the deadlines of PUTKEY and GETKEY.
    store = fresh(a)
    for data, what in ((request(PUTKEY, bytes(16), 0, f2), 'PUTKEY without an id'),
                       (request(GETKEY, a, 0, b'x'), 'GETKEY with a blob'),
                       (request(CUTKEY, a, 0, sha=b'\1' * 32), 'CUTKEY with a sha'),
                       (request(CUTKEY, a, 0, b'x'), 'CUTKEY with a blob'),
                       (request(CUTKEY, a, EPOCH_MAX + 1), 'CUTKEY above EPOCH_MAX'),
                       (request(PRUNE, a, 0), 'PRUNE of epoch 0'), (request(PRUNE, a, 1, b'x'), 'PRUNE with a blob'),
                       (request(PRUNE, a, 1, sha=b'\1' * 32), 'PRUNE with a sha'),
                       (request(PUTKEY, a, 0, f2)[:-1], 'short PUTKEY blob'), (request(10, a), 'op 10')):
        check(call(store, data) == bad, 'BAD_REQUEST: ' + what)
    check(call(store, request(PUTKEY, a, 0, length=MAX_KEY_FILE + 1)) == (TOO_LARGE, 0, b'', 1),
          'TOO_LARGE answered without reading the key file')
    check(putkey(store, a, 0, f2, sha=bytes(32)) == (BAD_BLOB, 0, b'', 0), 'BAD_BLOB: PUTKEY checksum')
    check(getkey(store, a) == (EMPTY, 0, b'', 0) and putkey(store, a, 1, f2) == (EMPTY, 0, b'', 0)
          and not os.path.lexists(store.root), 'GETKEY, and PUTKEY on a record, with nothing stored: EMPTY')
    steps = []
    check(call(store, request(PUTKEY, a, 0, f2), steps.append)[:2] == (OK, 1)
          and steps == [HEADER_TIMEOUT, TIMEOUT, 0, TIMEOUT], 'deadlines: PUTKEY')
    del steps[:]
    check(call(store, request(GETKEY, a, 1, sha=hashlib.sha256(key(0, f2)).digest()), steps.append)
          == (NOT_MODIFIED, 1, b'', 0) and steps == [HEADER_TIMEOUT, 0, REPLY_TIMEOUT], 'deadlines: GETKEY')

    # Row 2: PUT takes no key file, also where a floor stands.
    for data, what in ((f3, 'GOYOKS01'), (b'GOYOKH01' + f3[8:], 'GOYOKH01'), (b'GOYOKE03' + f3[8:], 'GOYOKE03'),
                       (record_header(KEY_RECORD, 0, 3) + f3, 'a key record')):
        check(put(store, a, 0, data) == (BAD_BLOB, 0, b'', 0), 'PUT refuses %s below a floor' % what)

    # Row 3: gate 3's grammar. A valid file of each kind and size is stored;
    # each rule broken once is BAD_BLOB with the grammar's reason, and
    # writes nothing.
    for name, data, valid in key_cases(a):
        store = fresh(a)
        if valid:
            check(putkey(store, a, 0, data) == (OK, 1, record_header(KEY_RECORD, 0, 10), 0), 'stored: ' + name)
            continue
        check(key_syntax(data, a) is None, 'grammar: ' + name)
        if len(data) > MAX_KEY_FILE:
            refusal, words = (TOO_LARGE, 0, b'', 1), 'key file over 32 KiB'
        else:
            refusal, words = (BAD_BLOB, 0, b'', 0), 'not a GOYOKS01 key file of this vault'
        check(noted(store, request(PUTKEY, a, 0, data), refusal, words) and not os.path.lexists(store.root),
              'refused: ' + name)
    key01 = b'GOYOKE01' + a + hashlib.sha256(b'key 1').digest() * 3 + b'\x01' * 28
    key02 = b'GOYOKE02' + a + hashlib.sha256(b'key 2').digest() * 3 + b'\x02' * 8
    store = fresh(a)
    for data, what in ((key01, 'GOYOKE01'), (key02, 'GOYOKE02'), (anywhere(a, 1, 10), 'GOYOVA04'),
                       (plain(a, 1), 'GOYOVA02'), (ks(b, 10), "another vault's GOYOKS01")):
        check(noted(store, request(PUTKEY, a, 0, data), (BAD_BLOB, 0, b'', 0), 'not a GOYOKS01 key file'),
              'PUTKEY refuses ' + what)
    check(not os.path.lexists(store.root), 'refused key files wrote nothing')
    check(noted(store, request(PUTKEY, a, 0, ks(a, EPOCH_MAX)), (BAD_BLOB, 0, b'', 0), 'epoch window')
          and not os.path.lexists(kdir(store, a)), 'a valid file at EPOCH_MAX on an empty namespace is outside the window')
    # The window and the honest-server checks against the stored key file.
    store = fresh(a)
    check(putkey(store, a, 0, ks(a, 10, 1))[:2] == (OK, 1), 'PUTKEY(0) at epoch 10')
    for data, what in ((ks(a, 10, 2), 'the same epoch'), (ks(a, 9, 2), 'a lower epoch'),
                       (ks(a, 10 + EPOCH_WINDOW + 1, 2), 'more than 2^16 above')):
        check(noted(store, request(PUTKEY, a, 1, data), (BAD_BLOB, 0, b'', 0), 'epoch window'), 'window: ' + what)
    tombs = key_fields(a, 11)['tombs']
    relisted = key_fields(a, 11, 2)
    relisted['slots'][1]['cred'], relisted['tombs'] = b'gone 1', [t for t in tombs if t[0] != credhash(b'gone 1')]
    authorized = key_fields(a, 11, 2)
    authorized['slots'][0]['cred'], authorized['tombs'] = b'gone 2', [t for t in tombs if t[0] != credhash(b'gone 2')]
    for data, what in ((ks(a, 11, 2, tombs=tombs[:1]), 'drops a tombstone'),
                       (build_key(relisted), 're-lists a tombstoned key'),
                       (build_key(authorized), 'is authorized by a tombstoned key')):
        check(noted(store, request(PUTKEY, a, 1, data), (BAD_BLOB, 0, b'', 0), 'tombstone or authorizer check'),
              'honest-server check: ' + what)
    top = 10 + EPOCH_WINDOW
    check(putkey(store, a, 1, ks(a, top, 2)) == (OK, 2, record_header(KEY_RECORD, 0, top), 0),
          'exactly 2^16 above is stored')
    check(cutkey(store, a, 2) == (OK, 3, record_header(CUT, 3, top), 0), 'a cut keeps the floor')
    for data, what in ((ks(a, top, 3), "the cut's floor"), (ks(a, top + EPOCH_WINDOW + 1, 3), 'more than 2^16 above it')):
        check(noted(store, request(PUTKEY, a, 3, data), (BAD_BLOB, 0, b'', 0), 'epoch window'), 'window: ' + what)
    check(putkey(store, a, 3, ks(a, top + 1, 3)) == (OK, 4, record_header(KEY_RECORD, 3, top + 1), 0),
          'above the cut: a new generation')
    # Above a cut the same checks run against the tombstones of the key
    # record a cut ended (k/tombs, never served; a fence keeps them), so a
    # removed key's holder with a sync SSH key cannot cut and then store a
    # file that key authorizes.
    store = fresh(a)
    check(putkey(store, a, 0, ks(a, 10, 1))[:2] == (OK, 1) and cutkey(store, a, 1)[:2] == (OK, 2)
          and cutkey(store, a, 2)[:2] == (OK, 3) and numbers(store, a) == ([3], False),
          'seed: a key record ended by a cut, then a fence')
    with open(os.path.join(kdir(store, a), TOMBS_NAME), 'rb') as f:
        check(f.read() == b''.join(sorted(t[0] for t in tombs)), "k/tombs holds the ended file's tombstones")
    for data, what in ((ks(a, 11, 2, tombs=tombs[:1]), 'drops a tombstone'),
                       (build_key(relisted), 're-lists a tombstoned key'),
                       (build_key(authorized), 'is authorized by a tombstoned key')):
        check(noted(store, request(PUTKEY, a, 3, data), (BAD_BLOB, 0, b'', 0), 'tombstone or authorizer check'),
              'honest-server check above a cut: ' + what)
    check(putkey(store, a, 3, ks(a, 11, 2)) == (OK, 4, record_header(KEY_RECORD, 3, 11), 0)
          and getkey(store, a) == (OK, 4, key(3, ks(a, 11, 2)), 0), 'above a cut a file that keeps them lands')

    # Row 4 (a): mutual exclusion in one process.
    store = fresh(a, c)
    check(putkey(store, a, 0, f2)[:2] == (OK, 1) and put(store, a, 0, sealed(a, f2, 1)) == (OK, 1, b'', 0)
          and put(store, c, 0, plain(c, 1)) == (OK, 1, b'', 0), 'seed the lock test')
    holder, held, release = Roomy(store.root, (a,)), threading.Event(), threading.Event()

    def keep():
        with holder.vault_lock(a):
            held.set()
            release.wait(60)
    worker = threading.Thread(target=keep)
    worker.start()
    try:
        check(held.wait(60), 'a second Store holds the vault lock')
        store.lock_wait = 0.2
        for data, what in ((request(PUTKEY, a, 1, f3), 'PUTKEY'), (request(GETKEY, a), 'GETKEY'),
                           (request(CUTKEY, a, 1), 'CUTKEY'), (request(PUT, a, 1, sealed(a, f2, 2)), 'vault PUT')):
            started = time.monotonic()
            check(noted(store, data, (SERVER_ERROR, 0, b'', 1), 'busy: vault lock held')
                  and time.monotonic() - started < 10, 'busy while another holds the lock: ' + what)
        check(put(store, c, 1, plain(c, 2)) == (OK, 2, b'', 0), 'a vault without k/ takes no lock')
    finally:
        release.set()
        worker.join()
    store.lock_wait = LOCK_WAIT
    check(putkey(store, a, 1, f3)[:2] == (OK, 2) and getkey(store, a)[:2] == (OK, 2)
          and put(store, a, 1, sealed(a, f3, 2)) == (OK, 2, b'', 0) and cutkey(store, a, 2)[:2] == (OK, 3),
          'released, the same requests land')
    check(sorted(os.listdir(store.paths(c)[0])) == ['v'], 'a vault without k/ has no lock file')
    # (b) the kernel frees the lock of a killed process.
    store = fresh(a)
    check(putkey(store, a, 0, f2)[:2] == (OK, 1), 'seed the kill test')
    child = subprocess.Popen([sys.executable, '-I', '-c', HOLDER, os.path.abspath(__file__), store.root, a.hex()],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        check(child.stdout.readline().strip() == b'held', 'a child process holds the vault lock')
        store.lock_wait = 0.2
        check(noted(store, request(GETKEY, a), (SERVER_ERROR, 0, b'', 1), 'busy'), 'busy while the child holds it')
    finally:
        child.kill()
        child.wait()
        child.stdout.close()
    # Windows frees a dead process's range after a while: the full LOCK_WAIT.
    store.lock_wait = LOCK_WAIT
    check(putkey(store, a, 1, f3)[:2] == (OK, 2), "a killed process's lock is free again")
    # (c) the record CAS: the second of two PUTKEYs on one base waits for the
    # first, which holds the lock, and gets CONFLICT carrying the winner.
    paused = Paused(store.root, (a,), 'temp')
    first, won = in_thread(lambda: putkey(paused, a, 2, f4))
    check(paused.inside.wait(60), 'the first PUTKEY holds the lock')
    second, lost = in_thread(lambda: putkey(Roomy(store.root, (a,)), a, 2, ks(a, 4, 9)))
    time.sleep(0.3)
    waited = second.is_alive()
    paused.go.set()
    first.join()
    second.join()
    check(waited, 'the second PUTKEY waits for the lock')
    check(won == [(OK, 3, record_header(KEY_RECORD, 0, 4), 0)] and lost == [(CONFLICT, 3, key(0, f4), 0)],
          'CAS: one OK, one CONFLICT carrying the winner')
    check(putkey(store, a, 2, f4) == (CONFLICT, 3, key(0, f4), 0), 'a resend of the winner gets its own file')
    store = fresh(a)
    check(putkey(store, a, 2, f4) == (EMPTY, 0, b'', 0) and not os.path.lexists(store.root),
          'EMPTY(0) on an empty namespace creates neither the vault folder nor a lock file')

    # Row 5: a kill at each point of PUTKEY and CUTKEY leaves the before- or
    # the after-state; the next key op's tidy() leaves no temp and at most two
    # key files; a resend after the link gets its own file, or its cut.
    for point in ('temp', 'link', 'unlinked', 'commit'):
        after = point != 'temp'
        for op in (PUTKEY, CUTKEY):
            store = fresh(a)
            check(putkey(store, a, 0, f2)[:2] == (OK, 1) and putkey(store, a, 1, f3)[:2] == (OK, 2), 'seed')
            crash = Crashing(store.root, (a,))
            crash.at = point
            data = request(PUTKEY, a, 2, f4) if op == PUTKEY else request(CUTKEY, a, 2)
            try:
                call(crash, data)
                check(False, 'the kill at %s happened' % point)
            except Killed:
                pass
            check(numbers(store, a)[1] == (point in ('temp', 'link')), 'a kill at %s leaves its temp' % point)
            if point == 'link':
                check(put(store, a, 0, sealed(a, f4, 1) if op == PUTKEY else anywhere(a, 1, 50)) == (OK, 1, b'', 0),
                      'a record whose second name is its temp does not stop a vault PUT')
            done = (key(0, f4) if op == PUTKEY else record_header(CUT, 3, 3)) if after else key(0, f3)
            check(getkey(store, a) == (OK, 3 if after else 2, done, 0), 'GETKEY after a kill at %s' % point)
            check(not numbers(store, a)[1] and payloads(store, a) <= 2, 'tidy() after a kill at %s' % point)
            resent = call(store, data)
            if op == PUTKEY:
                check(resent == ((CONFLICT, 3, key(0, f4), 0) if after else (OK, 3, record_header(KEY_RECORD, 0, 4), 0)),
                      'a resent PUTKEY after a kill at %s' % point)
            else:
                check(resent == (OK, 3, record_header(CUT, 3, 3), 0) and numbers(store, a) == ([3], False),
                      'a resent CUTKEY after a kill at %s' % point)

    # Row 6: retention.
    store = fresh(a)
    files = [ks(a, 2 + i, i) for i in range(3)]
    for i, data in enumerate(files):
        check(putkey(store, a, i, data) == (OK, i + 1, record_header(KEY_RECORD, 0, 2 + i), 0), 'PUTKEY %d' % i)
    newest = key(0, files[2])
    check(numbers(store, a) == ([2, 3], False), 'after 3 PUTKEYs records 2 and 3 remain')
    check(getkey(store, a) == (OK, 3, newest, 0) and getkey(store, a, 2, hashlib.sha256(key(0, files[1])).digest())
          == (OK, 3, newest, 0), 'GETKEY serves the newest record only')
    check(getkey(store, a, 3, hashlib.sha256(newest).digest()) == (NOT_MODIFIED, 3, b'', 0)
          and getkey(store, a, 3, bytes(32)) == (OK, 3, newest, 0), 'NOT_MODIFIED needs the number and the SHA-256')
    check(cutkey(store, a, 3)[:2] == (OK, 4) and numbers(store, a) == ([4], False)
          and putkey(store, a, 4, ks(a, 6, 4))[:2] == (OK, 5) and numbers(store, a) == ([5], False)
          and putkey(store, a, 5, ks(a, 7, 5))[:2] == (OK, 6) and numbers(store, a) == ([5, 6], False),
          'record numbers only grow')

    # Row 7: the vault floor.
    store = fresh(a)
    f5 = ks(a, 5, 1)
    check(putkey(store, a, 0, f5)[:2] == (OK, 1) and put(store, a, 0, sealed(a, f5, 1)) == (OK, 1, b'', 0),
          "GOYOVA04 at the key record's epoch, key ID and state tag lands")
    other = ks(a, 5, 2)
    v = store.paths(a)[1]
    for data, what in ((sealed(a, f5, 2, key_id=other[96:112]), 'another key ID'),
                       (sealed(a, f5, 3, state=state_tag(other[:other.w])), 'another state tag'),
                       (sealed(a, f5, 4, epoch=6), 'a higher epoch'), (sealed(a, f5, 5, epoch=4), 'a lower epoch'),
                       (plain(a, 6), 'GOYOVA02')):
        before = tree(v)
        check(noted(store, request(PUT, a, 1, data), (KEY_BEHIND, 0, b'', 0), 'does not match the stored key file')
              and tree(v) == before, 'KEY_BEHIND: ' + what)
    check(put(store, a, 1, sealed(a, f5, 7)) == (OK, 2, b'', 0), 'the matching state lands again')
    # Exactness: vault PUTs that wait for the lock while a PUTKEY commits
    # see the new key state.
    f6 = ks(a, 6, 2)
    paused = Paused(store.root, (a,), 'temp')
    first, landed = in_thread(lambda: putkey(paused, a, 1, f6))
    check(paused.inside.wait(60), 'the PUTKEY holds the lock')
    new, at_new = in_thread(lambda: put(Roomy(store.root), a, 2, sealed(a, f6, 8)))
    old, at_old = in_thread(lambda: put(Roomy(store.root), a, 2, sealed(a, f5, 9)))
    time.sleep(0.3)
    waited = new.is_alive() and old.is_alive()
    paused.go.set()
    for worker in (first, new, old):
        worker.join()
    check(waited and landed[0][:2] == (OK, 2) and at_new == [(OK, 3, b'', 0)] and at_old == [(KEY_BEHIND, 0, b'', 0)],
          'the floor is exact: a waiting vault PUT sees the key record committed before it')
    check(cutkey(store, a, 2)[:2] == (OK, 3) and put(store, a, 3, anywhere(a, 10, 999)) == (OK, 4, b'', 0)
          and put(store, a, 4, plain(a, 11)) == (KEY_BEHIND, 0, b'', 0), 'after a cut: any GOYOVA04, no GOYOVA02')

    # Row 8: CUTKEY.
    store = fresh(a)
    check(putkey(store, a, 0, f2)[:2] == (OK, 1) and putkey(store, a, 1, f3)[:2] == (OK, 2), 'seed')
    cut3 = record_header(CUT, 3, 3)
    check(cutkey(store, a, 2) == (OK, 3, cut3, 0) and numbers(store, a) == ([3], False) and payloads(store, a) == 0
          and getkey(store, a) == (OK, 3, cut3, 0), 'CUTKEY on a key record: a cut, and no key file left')
    before = tree(kdir(store, a))
    check(cutkey(store, a, 2) == (OK, 3, cut3, 0) and cutkey(store, a, 0) == (OK, 3, cut3, 0)
          and tree(kdir(store, a)) == before, 'CUTKEY below a cut: no change')
    cut4 = record_header(CUT, 4, 3)
    check(cutkey(store, a, 3) == (OK, 4, cut4, 0) and numbers(store, a) == ([4], False), 'CUTKEY on its cut: a fence')
    check(putkey(store, a, 3, ks(a, 4, 3)) == (CONFLICT, 4, cut4, 0), 'a PUTKEY built on the fenced cut: CONFLICT')
    before = tree(kdir(store, a))
    check(cutkey(store, a, 3) == (OK, 4, cut4, 0) and tree(kdir(store, a)) == before, 'a replayed CUTKEY: no change')
    check(noted(store, request(PUTKEY, a, 4, ks(a, 3, 3)), (BAD_BLOB, 0, b'', 0), 'epoch window'),
          "PUTKEY at the cut's floor")
    f5 = ks(a, 5, 4)
    check(putkey(store, a, 4, f5) == (OK, 5, record_header(KEY_RECORD, 4, 5), 0), 'PUTKEY above a cut: gen = the cut')
    before = tree(kdir(store, a))
    check(cutkey(store, a, 3) == (OK, 5, key(4, f5), 0) and cutkey(store, a, 2) == (OK, 5, key(4, f5), 0)
          and tree(kdir(store, a)) == before, 'a CUTKEY replayed after a re-enable: no change')
    check(cutkey(store, a, 4) == (OK, 6, record_header(CUT, 6, 5), 0) and payloads(store, a) == 0,
          'CUTKEY of the later generation')
    # A PUTKEY on the cut c lands first, then CUTKEY(c) ends it.
    store = fresh(a)
    check(putkey(store, a, 0, f2)[:2] == (OK, 1) and cutkey(store, a, 1)[:2] == (OK, 2)
          and putkey(store, a, 2, f3) == (OK, 3, record_header(KEY_RECORD, 2, 3), 0)
          and cutkey(store, a, 2) == (OK, 4, record_header(CUT, 4, 3), 0) and payloads(store, a) == 0,
          'a PUTKEY on the cut, then CUTKEY on it: a cut on top and no key file')
    # CUTKEY(0) in a vault folder without k/ makes k/ with cut 1.
    store = fresh(a)
    check(put(store, a, 0, plain(a, 1)) == (OK, 1, b'', 0), 'seed a vault folder')
    cut1 = record_header(CUT, 1, 0)
    check(cutkey(store, a, 0) == (OK, 1, cut1, 0) and numbers(store, a) == ([1], False)
          and putkey(store, a, 0, f2) == (CONFLICT, 1, cut1, 0), 'CUTKEY(0) without k/: cut 1, then PUTKEY(0) CONFLICT')
    # PUTKEY and CUTKEY in both orders.
    for rival_op, want, rival_want in ((CUTKEY, (CONFLICT, 2, record_header(CUT, 2, 2), 0),
                                        (OK, 2, record_header(CUT, 2, 2), 0)),
                                       (PUTKEY, (OK, 3, record_header(CUT, 3, 3), 0),
                                        (OK, 2, record_header(KEY_RECORD, 0, 3), 0))):
        store = fresh(a)
        check(putkey(store, a, 0, f2)[:2] == (OK, 1), 'seed')
        rival = Rival(store.root, (a,))
        rival.data = request(rival_op, a, 1, *([f3] if rival_op == PUTKEY else []))
        mine = request(CUTKEY, a, 1) if rival_op == PUTKEY else request(PUTKEY, a, 1, f3)
        check(call(rival, mine) == want and rival.answer == rival_want and payloads(store, a) == 0,
              'PUTKEY and CUTKEY in either order: the cut ends on top')
    # No vault folder: CUTKEY makes it, k/ and cut 1, also while a PUTKEY(0)
    # that started first waits before it makes the folder.
    store = fresh(a)
    check(cutkey(store, a, 0) == (OK, 1, cut1, 0) and os.path.isdir(kdir(store, a))
          and putkey(store, a, 0, f2) == (CONFLICT, 1, cut1, 0), 'CUTKEY with no vault folder makes it')
    store = fresh(a)
    rival = Rival(store.root, (a,))
    rival.point, rival.data = 'folder', request(CUTKEY, a, 0)
    check(call(rival, request(PUTKEY, a, 0, f2)) == (CONFLICT, 1, cut1, 0) and rival.answer == (OK, 1, cut1, 0)
          and numbers(store, a) == ([1], False), 'a PUTKEY(0) held before its folder meets the cut')
    # The 64-vault limit.
    store = fresh(a)
    os.mkdir(store.root)
    for vid in ids[10:10 + MAX_VAULTS]:
        os.mkdir(store.paths(vid)[0])
    before = tree(store.root)
    check(cutkey(store, a, 0) == (LIMIT, 0, b'', 0) and putkey(store, a, 0, f2) == (LIMIT, 0, b'', 0)
          and tree(store.root) == before, 'no vault folder past the limit: LIMIT, nothing created')
    scanned.remove(store)

    # Row 9: PRUNE removes lower epochs only, never the head, and never
    # touches k/.
    store = fresh(a, c)
    for i, data in enumerate((plain(c, 1), anywhere(c, 2, 3), anywhere(c, 3, 6), anywhere(c, 4, 4), anywhere(c, 5, 5))):
        check(put(store, c, i, data) == (OK, i + 1, b'', 0), 'seed PRUNE %d' % i)
    check(call(store, request(PRUNE, c, 6)) == (NOT_FOUND, 0, b'', 0)
          and list_versions(store.paths(c)[1]) == [1, 2, 3, 4, 5], 'PRUNE above the head: NOT_FOUND')
    check(call(store, request(PRUNE, c, 5)) == (OK, 3, b'', 0) and list_versions(store.paths(c)[1]) == [3, 5],
          'PRUNE removes the lower epochs and keeps the head')
    check(call(store, request(PRUNE, c, 5)) == (OK, 0, b'', 0) and call(store, request(PRUNE, a, 1)) == (NOT_FOUND, 0, b'', 0),
          'PRUNE again, and of a vault with no versions')
    check(put(store, a, 0, plain(a, 1)) == (OK, 1, b'', 0) and putkey(store, a, 0, f2)[:2] == (OK, 1)
          and put(store, a, 1, sealed(a, f2, 2)) == (OK, 2, b'', 0), 'seed a vault with k/')
    before = tree(kdir(store, a))
    check(call(store, request(PRUNE, a, 2)) == (OK, 1, b'', 0) and tree(kdir(store, a)) == before
          and sorted(os.listdir(store.paths(c)[0])) == ['v'], 'PRUNE never touches k/ or makes a lock file')

    # Row 10: links in the key namespace are refused, as in v/.
    outside = os.path.join(base, 'outside')
    os.mkdir(outside)
    with open(os.path.join(outside, 'file'), 'wb') as f:
        f.write(key(0, f3))
    store = fresh(a)
    check(putkey(store, a, 0, f2)[:2] == (OK, 1) and put(store, a, 0, sealed(a, f2, 1)) == (OK, 1, b'', 0), 'seed')
    k, lock = kdir(store, a), os.path.join(store.paths(a)[0], 'lock')
    linked = '%020d-%020d.rec' % (2, 3)

    def refused(what):
        for data in (request(GETKEY, a), request(PUTKEY, a, 1, f3), request(CUTKEY, a, 1),
                     request(PUT, a, 1, sealed(a, f2, 2))):
            check(call(store, data)[0] == SERVER_ERROR, 'refused: ' + what)
    for make, what in ((lambda: os.link(os.path.join(outside, 'file'), os.path.join(k, linked)), 'a hard-linked record'),
                       (lambda: os.symlink(os.path.join(outside, 'file'), os.path.join(k, linked)), 'a symlinked record'),
                       (lambda: os.mkdir(os.path.join(k, linked)), 'a directory with a record name')):
        try:
            make()
        except (OSError, NotImplementedError):
            check(what == 'a symlinked record', 'made ' + what)
            continue
        refused(what)
        (os.rmdir if os.path.isdir(os.path.join(k, linked)) and not os.path.islink(os.path.join(k, linked))
         else os.unlink)(os.path.join(k, linked))
    check(getkey(store, a) == (OK, 1, key(0, f2), 0), 'the record links are gone')
    twin = os.path.join(k, '%020d-%020d.rec' % (1, 9))
    with open(twin, 'wb') as f:
        f.write(key(0, f2))
    check(noted(store, request(GETKEY, a), (SERVER_ERROR, 0, b'', 1), 'duplicate record'), 'two names with one number')
    os.unlink(twin)
    junk = ['%020d-%020d.rec' % (0, 2), '%020d-%020d.rec' % (EPOCH_MAX + 1, 2), '%020d-%020d.rec' % (2, EPOCH_MAX + 1),
            '%019d-%020d.rec' % (2, 2), 'notes.txt']
    for name in junk:
        with open(os.path.join(k, name), 'wb') as f:
            f.write(key(0, f3))
    check(getkey(store, a) == (OK, 1, key(0, f2), 0) and putkey(store, a, 1, f3)[:2] == (OK, 2)
          and all(os.path.exists(os.path.join(k, name)) for name in junk), 'other names in k/ are ignored and kept')
    for name in junk:
        os.unlink(os.path.join(k, name))
    with open(os.path.join(outside, 'lock'), 'wb'):
        pass
    for make, what in ((lambda: os.link(os.path.join(outside, 'lock'), lock), 'a hard-linked lock'),
                       (lambda: os.symlink(os.path.join(outside, 'lock'), lock), 'a symlinked lock')):
        os.unlink(lock)
        try:
            make()
        except (OSError, NotImplementedError):
            check(what == 'a symlinked lock', 'made ' + what)
            continue
        refused(what)
    if os.path.lexists(lock):
        os.unlink(lock)
    check(getkey(store, a) == (OK, 2, key(0, f3), 0), 'a plain lock file is made again')
    store = fresh(a)
    os.makedirs(store.paths(a)[0])
    target = os.path.join(outside, 'k')
    os.mkdir(target)
    k = kdir(store, a)
    try:
        os.symlink(target, k, target_is_directory=True)
    except (OSError, NotImplementedError):
        try:  # Windows without the symlink privilege: a junction needs none
            import _winapi
            _winapi.CreateJunction(target, k)
        except (ImportError, AttributeError, OSError):
            k = None
    if k:
        refused('a k/ that is a link')
        check(os.listdir(target) == [], 'a linked k/ wrote nothing')
    scanned.remove(store)

    # Row 12: a damaged top reads as a cut at its own number, with the floor
    # in its name; the vault floor is off; each op writes one stderr line.
    for name, change in (('truncated to 0 bytes', lambda d: b''), ('truncated to 20 bytes', lambda d: d[:20]),
                         ('a flipped payload byte', lambda d: d[:40] + bytes([d[40] ^ 1]) + d[41:]),
                         ('a flipped header byte', lambda d: bytes([d[0] ^ 1]) + d[1:])):
        for end in (PUTKEY, CUTKEY):
            store = fresh(a)
            f5, f7 = ks(a, 5, 1), ks(a, 7, 2)
            check(putkey(store, a, 0, f5)[:2] == (OK, 1) and putkey(store, a, 1, f7)[:2] == (OK, 2)
                  and put(store, a, 0, sealed(a, f7, 1)) == (OK, 1, b'', 0), 'seed')
            path = record_path(store, a, 2)
            with open(path, 'rb') as f:
                data = f.read()
            with open(path, 'wb') as f:
                f.write(change(data))
            flagged = record_header(CUT, 2, 7, True)
            check(noted(store, request(GETKEY, a), (OK, 2, flagged, 0), 'damaged key record read as a cut'),
                  'GETKEY of a damaged top: %s' % name)
            check(noted(store, request(PUTKEY, a, 2, ks(a, 7, 3)), (BAD_BLOB, 0, b'', 0), 'epoch window')
                  and noted(store, request(PUTKEY, a, 1, ks(a, 8, 3)), (CONFLICT, 2, flagged, 0), 'damaged'),
                  'a damaged top keeps its floor: %s' % name)
            check(put(store, a, 1, anywhere(a, 3, 99)) == (OK, 2, b'', 0) and
                  noted(store, request(PUT, a, 2, plain(a, 4)), (KEY_BEHIND, 0, b'', 0), 'does not match'),
                  'below a damaged top the floor is that of a cut: %s' % name)
            before = tree(kdir(store, a))
            check(put(Roomy(store.root), a, 2, anywhere(a, 5, 5)) == (OK, 3, b'', 0)
                  and put(Roomy(store.root, (b,)), a, 3, anywhere(a, 6, 5)) == (OK, 4, b'', 0)
                  and tree(kdir(store, a)) == before, 'connections without the capability leave k/ as it is')
            if end == PUTKEY:
                check(putkey(store, a, 2, ks(a, 8, 3)) == (OK, 3, record_header(KEY_RECORD, 2, 8), 0)
                      and numbers(store, a) == ([3], False), 'PUTKEY on a damaged top: %s' % name)
            else:
                check(cutkey(store, a, 1) == (OK, 3, record_header(CUT, 3, 7), 0)
                      and numbers(store, a) == ([3], False), 'CUTKEY on a damaged top: %s' % name)
    # The first key record of a generation, damaged after tidy() removed the
    # cut below it, keeps its floor through its name.
    store = fresh(a)
    check(putkey(store, a, 0, ks(a, 5, 1))[:2] == (OK, 1) and cutkey(store, a, 1)[:2] == (OK, 2)
          and putkey(store, a, 2, ks(a, 7, 2))[:2] == (OK, 3) and numbers(store, a) == ([3], False), 'seed')
    with open(record_path(store, a, 3), 'r+b') as f:
        f.truncate(20)
    check(getkey(store, a) == (OK, 3, record_header(CUT, 3, 7, True), 0), 'a damaged first key record')
    for data in (ks(a, 5, 1), ks(a, 6, 3), ks(a, 7, 3)):
        check(putkey(store, a, 3, data) == (BAD_BLOB, 0, b'', 0), 'no older key file below a damaged first record')
    # A read error that is not damage is SERVER_ERROR and commits nothing.
    store = fresh(a)
    check(putkey(store, a, 0, f2)[:2] == (OK, 1) and putkey(store, a, 1, f3)[:2] == (OK, 2), 'seed')
    for error in (OSError(errno.EIO, 'I/O error'), PermissionError(errno.EACCES, 'denied')):
        broken = Unreadable(store.root, (a,))
        broken.error, broken.top = error, os.path.basename(record_path(store, a, 2))
        before = tree(store.root)
        for data in (request(GETKEY, a), request(PUTKEY, a, 2, f4), request(CUTKEY, a, 2)):
            check(noted(broken, data, (SERVER_ERROR, 0, b'', 1), 'cannot read the top key record'),
                  'a read error on the top: %s' % type(error).__name__)
        check(tree(store.root) == before, 'a read error commits nothing')

    # Row 11: a final scan. No stored file is a password-only or local key
    # file; GOYOKS01 lies only in k/; once a key op has tidied, a vault keeps
    # at most two key files and none under a cut.
    for store in scanned:
        for folder, dirs, files in os.walk(store.root):
            for name in files:
                with open(os.path.join(folder, name), 'rb') as f:
                    data = f.read()
                check(not data.startswith((b'GOYOKE', b'GOYOKH')), 'no stored file starts like GOYOKE/GOYOKH')
                check(KEY_MAGIC not in data or os.path.basename(folder) == 'k', 'GOYOKS01 only in k/')
        for name in store.vault_names():
            vid = bytes.fromhex(name)
            if not os.path.isdir(os.path.join(store.root, name, 'k')):
                continue
            answer = getkey(Roomy(store.root, (vid,)), vid)
            check(answer[0] in (OK, EMPTY), 'final scan: GETKEY')
            check(not numbers(store, vid)[1] and payloads(store, vid) <= 2
                  and (answer[2][8:10] != bytes([CUT, 0]) or payloads(store, vid) == 0), 'final scan: retention')


def probe_data_root():
    """Row 13: one exclusive flock on a probe file in the default data root
    (POSIX), which every connection of the forced command uses; setup.rs
    refuses the install on a root without working locks."""
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    try:
        make_dir(root)
        path = os.path.join(root, 'lockprobe-%d' % os.getpid())
        fd = os.open(path, os.O_RDWR | os.O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try:
            check(stat.S_ISREG(os.fstat(fd).st_mode), 'the lock probe is a plain file')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
            remove(path)
    except (OSError, Refused) as e:
        raise SelftestFailure('no working flock in the data root (%s)' % type(e).__name__)


def selftest():
    """Every rule against temporary roots, and where flock exists one lock
    on the default data root; prints PASS, or FAIL: <check>."""
    base = tempfile.mkdtemp(prefix='goyo-sync-selftest-')
    try:
        selftest_root(os.path.join(base, 'data'), base)
        selftest_keys(base)
        if fcntl:
            probe_data_root()
    except SelftestFailure as e:
        sys.stderr.write('FAIL: %s\n' % e)
        return 1
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print('PASS')
    return 0


def serve_args(argv):
    """(root or None, the raw vault IDs of --key-sync) for exactly
    serve [--root DIR] [--key-sync=ID[,ID...]], with 1 to 64 distinct IDs of
    32 lower-case hex digits; None for anything else, a bare --key-sync
    included."""
    if argv[:1] != ['serve']:
        return None
    rest, root = argv[1:], None
    if rest[:1] == ['--root']:
        if len(rest) < 2 or not rest[1]:
            return None
        root, rest = rest[1], rest[2:]
    if not rest:
        return root, ()
    if len(rest) != 1 or not rest[0].startswith('--key-sync='):
        return None
    names = rest[0][len('--key-sync='):].split(',')
    if len(names) > MAX_VAULTS or len(set(names)) != len(names) or not all(VAULT_NAME.fullmatch(n) for n in names):
        return None
    return root, tuple(bytes.fromhex(n) for n in names)


def main(argv):
    os.umask(0o077)
    if argv == ['selftest']:
        return selftest()
    args = serve_args(argv)
    if args is not None:
        # A stalled client cannot keep this process alive (no SIGALRM on Windows).
        deadline = getattr(signal, 'alarm', no_deadline)
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.abspath(args[0] if args[0] is not None else os.path.join(here, 'data'))
        try:
            return serve(sys.stdin.buffer, sys.stdout.buffer, Store(root, args[1]), sys.stderr, deadline, SLOTS)
        except BrokenPipeError:
            # The client went away. Point stdout at devnull so the exit flush is quiet.
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            return 1
    sys.stderr.write('usage: goyo-sync-server.py serve [--root DIR] [--key-sync=ID[,ID...]] | selftest\n')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
