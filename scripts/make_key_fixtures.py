"""Independent encoder and decoder of Goyo Vault key files (spec v3 §3.2-§3.4,
§4.1, §4.6, §14.1-3). Not shipped.

Every file is derived from recorded inputs only, never from fresh randomness,
and the inputs are recorded beside the files (ke03_fixtures.json,
hw_fixtures.json), so the Rust unit tests of src/vault/keyfile.rs reproduce
the bytes exactly: they feed the same draws (in seal's order: the Argon2
salt, the body nonce, then the nonce of every new pair record in file order
and of every S-wrap in slot order) through crypto::queue_random and the same
`written` through crypto::set_test_now. The decoder below opens every file
this script writes before it is kept, a security-key file through every key
that has an S-wrap there.

GOYOKE03 (password only) is sealed with the Test KDF profile (m 64 KiB, t 1,
p 1), and one with the Real profile, which pins the Argon2 constants across
both implementations. GOYOKH01 (two keys, both paired, a loss) and GOYOKS01
(four keys: two touched and paired, one reached through the authorizer, one
suspended; tombstones with loss marks) use the Test profile. Their security
keys are recorded fake authenticators: a credential ID, CredRandomWithUV,
CredRandomWithoutUV, the credProtect level and the UV bit per key, so a fake
that imports them answers with the same hmac-secret output (stage 4). Damaged
copies of both (one byte cut, one byte appended, a reserved byte set) and
newer magics (GOYOKH02, GOYOKS02) are for the refusal tests of the build
without security-key support.

    python -X utf8 scripts/make_key_fixtures.py          write tests/fixtures/
    python -X utf8 scripts/make_key_fixtures.py --check  compare, write nothing

Needs `cryptography` (Argon2id and the IETF ChaCha20-Poly1305) and nothing
else: HMAC and HKDF are the standard library's, and XChaCha20 is HChaCha20,
written out below, in front of the IETF AEAD.
"""
import hashlib, hmac, json, pathlib, struct, sys
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

root = pathlib.Path(__file__).resolve().parents[1]
out_dir = root / 'tests' / 'fixtures'
PROFILES = {'test': {'m': 64, 't': 1, 'p': 1}, 'real': {'m': 262_144, 't': 3, 'p': 1}}
EPOCH_MAX = (1 << 48) - 1
KEY_FILE_LIMIT = 32_768
KINDS = {'keys-on': 1, 'password': 2, 'add-key': 3, 'remove': 4, 'pair': 5, 'sync-on': 6,
         'sync-off': 7, 're-seed': 8, 'union': 9, 'keys-off': 10}
# The kinds each KF2 magic may carry (spec §4.1).
ALLOWED = {b'GOYOKE03': {2, 9, 10}, b'GOYOKH01': {1, 2, 3, 4, 5, 7, 8, 9},
           b'GOYOKS01': {2, 3, 4, 5, 6, 8, 9}}
WRAP, SEAL_BLOCK = 104, 88


def sha256(*parts):
    return hashlib.sha256(b''.join(parts)).digest()


def mac(key, *parts):
    return hmac.new(key, b''.join(parts), hashlib.sha256).digest()


def extract(salt, *ikm):
    return mac(salt, *ikm)


def expand(prk, length, *info):
    """HKDF-SHA256 expand (RFC 5869 §2.3)."""
    info, out, block, i = b''.join(info), b'', b'', 1
    while len(out) < length:
        block = mac(prk, block, info, bytes([i]))
        out, i = out + block, i + 1
    return out[:length]


def hchacha20(key, nonce):
    """HChaCha20 (draft-irtf-cfrg-xchacha §2.2): the XChaCha20 subkey."""
    def rotl(v, c):
        return (v << c | v >> (32 - c)) & 0xFFFFFFFF

    def quarter(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] = rotl(s[b] ^ s[c], 7)
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, *struct.unpack('<8I', key),
         *struct.unpack('<4I', nonce)]
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            quarter(s, a, b, c, d)
    return struct.pack('<8I', *s[:4], *s[12:])


# draft-irtf-cfrg-xchacha-03 §2.2.1.
assert hchacha20(bytes(range(32)), bytes.fromhex('000000090000004a0000000031415927')) == bytes.fromhex(
    '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc')


def aead_seal(key, nonce, aad, plain):
    """XChaCha20-Poly1305 (24-byte nonce), as crypto::seal."""
    return ChaCha20Poly1305(hchacha20(key, nonce[:16])).encrypt(bytes(4) + nonce[16:], plain, aad)


def aead_open(key, nonce, aad, sealed):
    return ChaCha20Poly1305(hchacha20(key, nonce[:16])).decrypt(bytes(4) + nonce[16:], sealed, aad)


def argon2id(password, salt, profile):
    p = PROFILES[profile]
    return Argon2id(salt=salt, length=32, iterations=p['t'], lanes=p['p'],
                    memory_cost=p['m']).derive(password.encode('utf-8'))


def key_id(vault_id, dk):
    return expand(extract(b'goyo-vault/v2/key-id', dk), 16, vault_id)


def ks_id(vault_id, s):
    return expand(extract(b'goyo-vault/v2/ks-id', s), 16, vault_id)


def credhash(cred_id):
    return sha256(b'goyo-vault/v2/cred\0', cred_id)[:16]


def chain(vault_id, dk, end_hash):
    ck = expand(extract(b'goyo-vault/v2/chain', dk), 32, vault_id)
    return mac(ck, b'goyo-vault/v2/chain-msg\0', end_hash)


def body_keys(pw_key, s, hh):
    prk = extract(b'goyo-vault/v2/body', pw_key, s)
    return expand(prk, 32, b'key\0', hh), expand(prk, 32, b'commit\0', hh)


def state_tag(region):
    return sha256(b'goyo-vault/v2/state\0', sha256(region))[:16]


def key_code(vault_id, dk, epoch, tag):
    kc = expand(extract(b'goyo-vault/v2/key-code', dk), 32, vault_id)
    return mac(kc, b'goyo key state\0', struct.pack('<Q', epoch), tag)[:8]


# ---- security keys (spec §3.2): a fake authenticator per slot ----

def hmac_output(vault_id, slot):
    """H_j: what the key answers for its slot's seed. Windows hashes the PRF
    input p_j with this prefix; the authenticator uses the CredRandom of the
    slot's UV state."""
    salt = sha256(b'WebAuthn PRF\0', b'goyo-vault/v2/hmac-salt\0', vault_id, slot['seed'])
    return mac(slot['cred_random_uv'] if slot['flags'] & 1 else slot['cred_random_nouv'], salt)


def key_root(h):
    return extract(b'goyo-vault/v2/key', h)


def own_base(vault_id, slot, h):
    return expand(key_root(h), 32, b'self\0', vault_id, credhash(slot['cred_id']), slot['seed'])


def pair_seal(vault_id, slot, h):
    return expand(key_root(h), 32, b'pair-seal\0', vault_id, credhash(slot['cred_id']), slot['seed'])


def inbox(vault_id, target, h_target, writer):
    """IK(target <- writer): a function of the target's hardware output."""
    return expand(key_root(h_target), 32, b'inbox\0', vault_id, credhash(target['cred_id']),
                  target['seed'], credhash(writer['cred_id']))


def pair_ctx(vault_id, owner, target):
    return vault_id + credhash(owner['cred_id']) + credhash(target['cred_id']) + owner['seed'] + target['seed']


def wrap_ctx(vault_id, epoch, recipient, via, head_hash):
    return vault_id + struct.pack('<Q', epoch) + credhash(recipient['cred_id']) + credhash(via['cred_id']) + head_hash


def wrap_keys(base, use, ctx):
    prk = extract(b'goyo-vault/v2/' + use, base)
    return expand(prk, 32, b'key\0', ctx), expand(prk, 32, b'commit\0', ctx)


def wrap(base, use, ctx, plain, nonce):
    """The committing wrap: nonce, commitment, ciphertext and tag (104 B)."""
    kek, commit = wrap_keys(base, use, ctx)
    return nonce + commit + aead_seal(kek, nonce, b'goyo-vault/v2/' + use + b'-aad\0' + ctx, plain)


def unwrap(base, use, ctx, record):
    kek, commit = wrap_keys(base, use, ctx)
    assert record[24:56] == commit, 'wrap commitment'
    return aead_open(kek, record[:24], b'goyo-vault/v2/' + use + b'-aad\0' + ctx, record[56:])


def bits(indexes):
    return sum(1 << i for i in indexes)


# ---- the encoder (spec §3.3) ----

def head_of(f):
    """[0, H): the fixed header, key IDs, tombstones, slots, pair records."""
    vid, slots = f['vault_id'], f.get('slots', [])
    hardware = f['magic'] != b'GOYOKE03'
    tombstones = sorted(f['tombstones'], key=lambda t: (t[1] & EPOCH_MAX, t[0]))
    pairs = sorted(f.get('pairs', []), key=lambda p: (p['owner'], p['target']))
    flags = (1 if f['otp'] else 0) | (2 if f.get('pin') else 0)
    head = f['magic'] + vid + struct.pack('<Q', f['epoch'])
    head += bytes([flags, len(f['keys']), len(slots), f['next']]) + struct.pack('<H', len(tombstones))
    head += bytes([KINDS[f['kind']], f['authorizer'] if hardware else 0xFF, bits(f.get('present', [])),
                   bits(f.get('suspended', [])), len(pairs)]) + bytes(5)
    head += (ks_id(vid, f['s']) if hardware else bytes(16)) + f['pw_id']
    head += struct.pack('<QQ', f['written'], f['loss'])
    head += b''.join(key_id(vid, dk) for dk in f['keys'])
    head += b''.join(ch + struct.pack('<Q', removed) for ch, removed in tombstones)
    for s in slots:
        added_by = bytes(16) if s['added_by'] is None else credhash(slots[s['added_by']]['cred_id'])
        head += bytes([1, s['flags'], s['number'], 0]) + struct.pack('<QQ', s['registered'], s['added_epoch'])
        head += added_by + s['seed'] + struct.pack('<H', len(s['cred_id'])) + s['cred_id']
    outputs = [hmac_output(vid, s) for s in slots]
    for p in pairs:
        o, t = slots[p['owner']], slots[p['target']]
        ik = inbox(vid, t, outputs[p['target']], o)
        head += bytes([p['owner'], p['target'], 0, 0])
        head += wrap(pair_seal(vid, o, outputs[p['owner']]), b'pair', pair_ctx(vid, o, t), ik, p['nonce'])
    return head


def s_wraps(f, head):
    """W: one S-wrap per live slot that is not suspended, in slot order,
    through the key itself when it was touched, else through the authorizer."""
    vid, slots, a = f['vault_id'], f.get('slots', []), f.get('authorizer')
    live = [j for j in range(len(slots)) if j not in f.get('suspended', [])]
    assert len(live) == len(f.get('wrap_nonces', []))
    head_hash, out = sha256(head), b''
    for j, nonce in zip(live, f.get('wrap_nonces', [])):
        via = j if j in f['present'] else a
        h_j = hmac_output(vid, slots[j])
        base = own_base(vid, slots[j], h_j) if via == j else inbox(vid, slots[j], h_j, slots[a])
        ctx = wrap_ctx(vid, f['epoch'], slots[j], slots[via], head_hash)
        out += bytes([j, via]) + wrap(base, b's-wrap', ctx, f['s'], nonce)
    return out


def tail(w_part, f, salt, nonce, profile):
    """The seal block, C_body, the body and the chain after `w_part` = [0, W)."""
    pw_key = argon2id(f['password'], salt, profile)
    out = w_part + f['resume'] + salt + nonce
    k_body, c_body = body_keys(pw_key, f.get('s', bytes(32)), sha256(out))
    out += c_body
    out += aead_seal(k_body, nonce, out, b''.join(f['keys']) + (f['otp'] or b''))
    end = sha256(out)
    return out + b''.join(chain(f['vault_id'], dk, end) for dk in f['keys'])


def encode(f):
    head = head_of(f)
    return tail(head + s_wraps(f, head), f, f['salt'], f['body_nonce'], f['kdf'])


def seal_draws(f):
    """What seal draws, in its order (spec §3.1): the salt, the body nonce,
    the nonce of every new pair record in file order, of every S-wrap."""
    pairs = sorted(f.get('pairs', []), key=lambda p: (p['owner'], p['target']))
    return ([f['salt'], f['body_nonce']] + [p['nonce'] for p in pairs if p['new']]
            + list(f.get('wrap_nonces', [])))


# ---- the decoder: the strict parse of spec §4.6, then the open of §3.4 ----

class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, n):
        assert self.at + n <= len(self.data), 'short'
        part = self.data[self.at:self.at + n]
        self.at += n
        return part

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack('<H', self.take(2))[0]

    def u64(self):
        return struct.unpack('<Q', self.take(8))[0]


def parse(data):
    """Every rule of spec §4.6; public bytes only. Fails with AssertionError."""
    magic = data[:8]
    assert magic in ALLOWED and len(data) <= KEY_FILE_LIMIT, 'magic or size'
    r = Reader(data)
    r.take(8)
    vid, epoch, flags, k, n, nxt = r.take(16), r.u64(), r.u8(), r.u8(), r.u8(), r.u8()
    count, kind, authorizer, present, suspended, p = r.u16(), r.u8(), r.u8(), r.u8(), r.u8(), r.u8()
    reserved, ks, pw_id, written, loss = r.take(5), r.take(16), r.take(16), r.u64(), r.u64()
    pin = flags & 2 != 0
    assert 1 <= epoch <= EPOCH_MAX and flags & ~3 == 0 and 1 <= k <= 64 and nxt >= 1, 'header'
    assert count <= 480 and kind in ALLOWED[magic] and reserved == bytes(5) and pw_id != bytes(16), 'header'
    if magic == b'GOYOKE03':
        assert (n, p, pin, authorizer, present, suspended, ks) == (0, 0, False, 0xFF, 0, 0, bytes(16)), 'KE03'
    else:
        assert 1 <= n <= 8 and (magic == b'GOYOKH01' or pin) and p <= n * (n - 1), 'counts'
        assert (present | suspended) >> n == 0 and present & suspended == 0, 'masks'
        assert authorizer < n and present >> authorizer & 1, 'authorizer'
        assert ks not in (bytes(16), ks_id(vid, bytes(32))), 'ks_id'
    ids = [r.take(16) for _ in range(k)]
    assert len(set(ids)) == k, 'key IDs'
    stones = [(r.take(16), r.u64()) for _ in range(count)]
    order = [(t[1] & EPOCH_MAX, t[0]) for t in stones]
    assert order == sorted(set(order)) and len({t[0] for t in stones}) == count, 'tombstone order'
    assert all(1 <= e <= epoch for e, _ in order), 'tombstone epoch'
    slots = []
    for _ in range(n):
        kind_, sflags, number, res = r.take(4)
        registered, added_epoch, added_by, seed = r.u64(), r.u64(), r.take(16), r.take(32)
        c = r.u16()
        assert kind_ == 1 and sflags <= 3 and (not pin or sflags == 3) and res == 0, 'slot'
        assert number > (slots[-1]['number'] if slots else 0) and 1 <= c <= 1023 and 1 <= added_epoch <= epoch, 'slot'
        slots.append({'flags': sflags, 'number': number, 'registered': registered, 'added_epoch': added_epoch,
                      'added_by': added_by, 'seed': seed, 'cred_id': r.take(c)})
    hashes = {credhash(s['cred_id']) for s in slots}
    assert len({s['cred_id'] for s in slots}) == n and len(hashes) == n, 'credentials'
    assert not hashes & {t[0] for t in stones}, 'a live key is tombstoned'
    new = [i for i, s in enumerate(slots) if s['added_epoch'] == epoch]
    every = (1 << n) - 1
    if kind == 1:
        assert present == every and suspended == 0 and len(new) == n
        assert all(s['added_by'] == bytes(16) for s in slots), 'kind 1'
    elif kind == 8:
        assert present == every and suspended == 0 and not new, 'kind 8'
    elif kind == 3:
        assert len(new) == 1 and present >> new[0] & 1, 'kind 3'
        assert slots[new[0]]['added_by'] == credhash(slots[authorizer]['cred_id']), 'kind 3'
    else:
        assert not new and (kind != 5 or bin(present).count('1') >= 2), 'kind'
    pairs = []
    for _ in range(p):
        o, t, res = r.u8(), r.u8(), r.take(2)
        assert res == bytes(2) and o != t and o < n and t < n, 'pair record'
        pairs.append((o, t, r.take(WRAP)))
    assert [x[:2] for x in pairs] == sorted({x[:2] for x in pairs}), 'pair order'
    h = r.at
    wraps = []
    for j in (j for j in range(n) if not suspended >> j & 1):
        recipient, via = r.u8(), r.u8()
        assert recipient == j, 'S-wrap order'
        if present >> j & 1:
            assert via == j, 'S-wrap via'
        else:
            assert via == authorizer and (authorizer, j) in {x[:2] for x in pairs}, 'S-wrap via'
        wraps.append((j, via, r.take(WRAP)))
    w = r.at
    resume, salt, nonce = r.take(32), r.take(32), r.take(24)
    b = r.at
    r.take(32 + 32 * k + (20 if flags & 1 else 0) + 16)
    e = r.at
    r.take(32 * k)
    assert r.at == len(data), 'length'
    return {'magic': magic, 'vault_id': vid, 'epoch': epoch, 'flags': flags, 'k': k, 'kind': kind,
            'authorizer': authorizer, 'present': present, 'suspended': suspended, 'ks_id': ks,
            'pw_id': pw_id, 'written': written, 'loss': loss, 'key_ids': ids, 'tombstones': stones,
            'slots': slots, 'pairs': pairs, 'wraps': wraps, 'resume': resume, 'salt': salt,
            'nonce': nonce, 'h': h, 'w': w, 'b': b, 'e': e, 'tag': state_tag(data[:w])}


def open_body(data, x, password, profile, s):
    """Steps 3, 5 and 6 of spec §3.4 with the keyset secret S (zero without
    security keys): C_body, the body, every key ID and every chain entry."""
    k_body, c_body = body_keys(argon2id(password, x['salt'], profile), s, sha256(data[:x['b']]))
    assert data[x['b']:x['b'] + 32] == c_body, 'C_body'
    plain = aead_open(k_body, x['nonce'], data[:x['b'] + 32], data[x['b'] + 32:x['e']])
    k = x['k']
    assert len(plain) == 32 * k + (20 if x['flags'] & 1 else 0), 'body length'
    dks = [plain[32 * i:32 * i + 32] for i in range(k)]
    assert [key_id(x['vault_id'], dk) for dk in dks] == x['key_ids'], 'key IDs'
    end = sha256(data[:x['e']])
    assert all(data[x['e'] + 32 * i:x['e'] + 32 * i + 32] == chain(x['vault_id'], dk, end)
               for i, dk in enumerate(dks)), 'chain'
    return {'keys': dks, 'otp': plain[32 * k:] or None}


def decode(data, password, profile, keys=()):
    """The parse, then the open. A security-key file is opened once through
    each key in `keys` (fake authenticators, by slot index) that has an
    S-wrap, and at least one must. Every pair record whose owner is among
    them must open with the owner's seal base, and carry the inbox key its
    target's output gives when the target is among them too."""
    x = parse(data)
    vid, slots = x['vault_id'], x['slots']
    if x['magic'] == b'GOYOKE03':
        return {**x, **open_body(data, x, password, profile, bytes(32))}
    outputs = {j: hmac_output(vid, {**slots[j], **keys[j]}) for j in keys}
    for o, t, record in x['pairs']:
        if o in outputs:
            ik = unwrap(pair_seal(vid, slots[o], outputs[o]), b'pair', pair_ctx(vid, slots[o], slots[t]), record)
            assert t not in outputs or ik == inbox(vid, slots[t], outputs[t], slots[o]), 'pair record'
    head_hash, opened = sha256(data[:x['h']]), None
    for j, via, record in x['wraps']:
        if j not in outputs:
            continue
        h_j = outputs[j]
        base = own_base(vid, slots[j], h_j) if via == j else inbox(vid, slots[j], h_j, slots[via])
        s = unwrap(base, b's-wrap', wrap_ctx(vid, x['epoch'], slots[j], slots[via], head_hash), record)
        assert ks_id(vid, s) == x['ks_id'] and s != bytes(32), 'ks_id'
        body = {**open_body(data, x, password, profile, s), 's': s}
        assert opened is None or opened == body, 'every key opens the same body'
        opened = body
    assert opened is not None, 'no key with an S-wrap'
    return {**x, **opened}


def seq(start, length):
    return bytes((start + i) & 0xFF for i in range(length))


def mixed(byte, length):
    return bytes(byte ^ i for i in range(length))


# The recorded inputs. src/vault/keyfile.rs builds the same ones from the
# same seq()/mixed() patterns.
WRITTEN = 1_767_225_600  # 2026-01-01T00:00:00Z
FIXTURES = [
    {'file': 'goyoke03-test.goyokey', 'magic': b'GOYOKE03', 'kdf': 'test',
     'password': 'goyo fixture passphrase, KE03',
     'vault_id': seq(0x10, 16), 'epoch': 7, 'kind': 'password', 'next': 3, 'pw_id': seq(0x30, 16),
     'loss': 0, 'written': WRITTEN, 'resume': seq(0xc0, 32),
     'tombstones': [(bytes([0xa2]) * 16, 5 | 20_455 << 48), (bytes([0xa1]) * 16, 2)],
     'keys': [seq(0x40, 32), seq(0x60, 32)], 'otp': seq(0x80, 20),
     'salt': mixed(0x5a, 32), 'body_nonce': mixed(0xa5, 24)},
    {'file': 'goyoke03-keysoff.goyokey', 'magic': b'GOYOKE03', 'kdf': 'test',
     'password': 'another fixture passphrase',
     'vault_id': seq(0x90, 16), 'epoch': EPOCH_MAX, 'kind': 'keys-off', 'next': 5,
     'pw_id': seq(0x01, 16), 'loss': 0, 'written': WRITTEN + 1, 'resume': bytes(32),
     'tombstones': [(bytes([0xb3]) * 16, EPOCH_MAX | 1 << 48), (bytes([0xb1]) * 16, EPOCH_MAX),
                    (bytes([0xb2]) * 16, 4)],
     'keys': [seq(0x21, 32), seq(0x42, 32), seq(0x63, 32)], 'otp': None,
     'salt': mixed(0x3c, 32), 'body_nonce': mixed(0xc3, 24)},
    {'file': 'goyoke03-real.goyokey', 'magic': b'GOYOKE03', 'kdf': 'real',
     'password': 'goyo real-profile fixture passphrase',
     'vault_id': seq(0xf0, 16), 'epoch': 1, 'kind': 'password', 'next': 1, 'pw_id': seq(0x71, 16),
     'loss': 0, 'written': WRITTEN, 'resume': bytes(32), 'tombstones': [],
     'keys': [seq(0x20, 32)], 'otp': None, 'salt': mixed(0x11, 32), 'body_nonce': mixed(0x22, 24)},
]
# The same-epoch re-seal of the first file: [0, W) byte for byte, a new seal block.
RESEAL = {'file': 'goyoke03-test-reseal.goyokey', 'source': 'goyoke03-test.goyokey',
          'resume': seq(0xe0, 32), 'draws': [mixed(0x66, 32), mixed(0x99, 24)]}

# A loss on 2025-12-31 (UTC): the `loss` field holds its Unix seconds, and a
# tombstone's loss mark the day counted from 1970-01-01, plus 2.
LOSS = 1_767_139_200
LOSS_MARK = LOSS // 86_400 + 2
DAY = 86_400


def key(number, flags, added_epoch, added_by, seed, cred_id, random_uv, random_nouv, registered):
    """A registered security key: its slot record and the fake
    authenticator behind it (credProtect 3 with a PIN slot, else 1)."""
    return {'number': number, 'flags': flags, 'registered': registered, 'added_epoch': added_epoch,
            'added_by': added_by, 'seed': seed, 'cred_id': cred_id, 'cred_random_uv': random_uv,
            'cred_random_nouv': random_nouv, 'cred_protect': 3 if flags & 2 else 1, 'uv': flags & 1 == 1}


HARDWARE = [
    # Two keys without PIN mode, one registered with UV and one without,
    # touched together to remove a lost third (kind 4 with its loss date),
    # each pair record new. OTP vault.
    {'file': 'goyokh01.goyokey', 'magic': b'GOYOKH01', 'kdf': 'test',
     'password': 'goyo security-key fixture, KH',
     'vault_id': seq(0x31, 16), 'epoch': 6, 'kind': 'remove', 'next': 4, 'pin': False,
     'pw_id': seq(0x51, 16), 'loss': LOSS, 'written': WRITTEN + 2, 'resume': seq(0x71, 32),
     'tombstones': [(credhash(seq(0x40, 24)), 6 | LOSS_MARK << 48), (credhash(seq(0x60, 20)), 3)],
     'keys': [seq(0xa1, 32), seq(0xc1, 32)], 'otp': seq(0x91, 20), 's': mixed(0x3d, 32),
     'slots': [key(1, 1, 1, None, mixed(0x13, 32), seq(0x02, 16), mixed(0x41, 32), mixed(0x42, 32),
                   WRITTEN - 90 * DAY),
               key(3, 0, 4, 0, mixed(0x17, 32), seq(0x80, 64), mixed(0x43, 32), mixed(0x44, 32),
                   WRITTEN - 30 * DAY)],
     'authorizer': 1, 'present': [0, 1], 'suspended': [],
     'pairs': [{'owner': 0, 'target': 1, 'new': True, 'nonce': mixed(0x55, 24)},
               {'owner': 1, 'target': 0, 'new': True, 'nonce': mixed(0x56, 24)}],
     'wrap_nonces': [mixed(0x57, 24), mixed(0x58, 24)],
     'salt': mixed(0x59, 32), 'body_nonce': mixed(0x5b, 24)},
    # Four keys in PIN mode with key-file sync, after two removals whose
    # tombstones keep their loss marks (one on an unknown date): keys 2 and
    # 4 touched and paired (kind 5), key 5 reached through the authorizer's
    # pair record, key 6 suspended (it owns a record, but no present key
    # reaches it). The other pair records are carried from the last file.
    {'file': 'goyoks01.goyokey', 'magic': b'GOYOKS01', 'kdf': 'test',
     'password': 'goyo security-key fixture, KS',
     'vault_id': seq(0x3a, 16), 'epoch': 9, 'kind': 'pair', 'next': 7, 'pin': True,
     'pw_id': seq(0x5a, 16), 'loss': 0, 'written': WRITTEN + 3, 'resume': bytes(32),
     'tombstones': [(credhash(seq(0xd0, 16)), 2), (credhash(seq(0xe0, 16)), 8 | 1 << 48),
                    (credhash(seq(0xf0, 16)), 8 | LOSS_MARK << 48)],
     'keys': [seq(0x0b, 32), seq(0x2b, 32), seq(0x4b, 32)], 'otp': None, 's': mixed(0x6d, 32),
     'slots': [key(2, 3, 1, None, mixed(0x21, 32), seq(0x10, 32), mixed(0x61, 32), mixed(0x62, 32),
                   WRITTEN - 120 * DAY),
               key(4, 3, 3, 0, mixed(0x22, 32), seq(0x30, 48), mixed(0x63, 32), mixed(0x64, 32),
                   WRITTEN - 100 * DAY),
               key(5, 3, 5, 0, mixed(0x23, 32), seq(0x60, 64), mixed(0x65, 32), mixed(0x66, 32),
                   WRITTEN - 60 * DAY),
               key(6, 3, 7, 1, mixed(0x24, 32), seq(0xa0, 80), mixed(0x67, 32), mixed(0x68, 32),
                   WRITTEN - 20 * DAY)],
     'authorizer': 0, 'present': [0, 1], 'suspended': [3],
     'pairs': [{'owner': 0, 'target': 1, 'new': True, 'nonce': mixed(0x71, 24)},
               {'owner': 0, 'target': 2, 'new': False, 'nonce': mixed(0x72, 24)},
               {'owner': 1, 'target': 0, 'new': True, 'nonce': mixed(0x73, 24)},
               {'owner': 2, 'target': 0, 'new': False, 'nonce': mixed(0x74, 24)},
               {'owner': 3, 'target': 0, 'new': False, 'nonce': mixed(0x75, 24)}],
     'wrap_nonces': [mixed(0x76, 24), mixed(0x77, 24), mixed(0x78, 24)],
     'salt': mixed(0x79, 32), 'body_nonce': mixed(0x7b, 24)},
]
# What the build without security-key support refuses on the magic family
# alone, with the damaged wording: copies that are not a well-formed
# GOYOKH01/GOYOKS01, and newer magics of the family.
VARIANTS = [
    ('goyokh01-truncated.goyokey', 'goyokh01.goyokey', 'the last byte cut off', lambda d: d[:-1]),
    ('goyokh01-appended.goyokey', 'goyokh01.goyokey', 'one zero byte appended', lambda d: d + b'\0'),
    ('goyokh01-reserved.goyokey', 'goyokh01.goyokey', 'reserved byte 43 set to 1',
     lambda d: d[:43] + b'\1' + d[44:]),
    ('goyoks01-truncated.goyokey', 'goyoks01.goyokey', 'the last byte cut off', lambda d: d[:-1]),
    ('goyoks01-appended.goyokey', 'goyoks01.goyokey', 'one zero byte appended', lambda d: d + b'\0'),
    ('goyoks01-reserved.goyokey', 'goyoks01.goyokey', 'reserved byte 43 set to 1',
     lambda d: d[:43] + b'\1' + d[44:]),
    ('goyokh02.goyokey', 'goyokh01.goyokey', 'the magic GOYOKH02', lambda d: b'GOYOKH02' + d[8:]),
    ('goyoks02.goyokey', 'goyoks01.goyokey', 'the magic GOYOKS02', lambda d: b'GOYOKS02' + d[8:]),
]


def hexed(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [hexed(v) for v in value]
    if isinstance(value, dict):
        return {k: hexed(v) for k, v in value.items()}
    return value


def build_password_only(files):
    record = {'kdf_profiles': PROFILES, 'draw_order': ['salt (32)', 'body nonce (24)'], 'fixtures': []}
    for f in FIXTURES:
        data = encode(f)
        opened = decode(data, f['password'], f['kdf'])
        assert opened['keys'] == f['keys'] and opened['otp'] == f['otp']
        files[f['file']] = data
        code = key_code(f['vault_id'], f['keys'][0], f['epoch'], opened['tag'])
        kept = {k: v for k, v in f.items() if k not in ('magic', 'salt', 'body_nonce')}
        record['fixtures'].append(hexed({**kept, 'draws': seal_draws(f), 'size': len(data),
                                         'tag': opened['tag'], 'key_code': code}))
    source = next(f for f in FIXTURES if f['file'] == RESEAL['source'])
    old = files[RESEAL['source']]
    w = parse(old)['w']
    data = tail(old[:w], {**source, 'resume': RESEAL['resume']}, *RESEAL['draws'], source['kdf'])
    opened = decode(data, source['password'], source['kdf'])
    assert opened['keys'] == source['keys'] and data[:w] == old[:w] and data != old
    files[RESEAL['file']] = data
    record['reseal'] = hexed({**RESEAL, 'size': len(data)})
    files['ke03_fixtures.json'] = (json.dumps(record, indent=1) + '\n').encode()


def build_hardware(files):
    record = {'kdf_profiles': PROFILES,
              'draw_order': ['salt (32)', 'body nonce (24)', 'nonce (24) of every new pair record, in file order',
                             'nonce (24) of every S-wrap, in slot order'],
              'hmac_output': 'HMAC-SHA256(cred_random_uv if uv else cred_random_nouv, '
                             'SHA-256("WebAuthn PRF" 00 "goyo-vault/v2/hmac-salt" 00 vault_id seed))',
              'fixtures': [], 'variants': []}
    def fails(data, password, profile, keys):
        try:
            decode(data, password, profile, keys)
        except (AssertionError, ValueError, InvalidTag):
            return True
        return False

    for f in HARDWARE:
        data = encode(f)
        randoms = [{k: s[k] for k in ('cred_random_uv', 'cred_random_nouv')} for s in f['slots']]
        everyone = dict(enumerate(randoms))
        opened = decode(data, f['password'], f['kdf'], everyone)
        assert opened['keys'] == f['keys'] and opened['otp'] == f['otp'] and opened['s'] == f['s']
        # Nothing opens with a suspended key alone (it has no S-wrap), with a
        # key whose authenticator was reset, or with a wrong password.
        reset = {'cred_random_uv': mixed(0xee, 32), 'cred_random_nouv': mixed(0xef, 32)}
        for j, r in enumerate(randoms):
            assert fails(data, f['password'], f['kdf'], {j: r if j in f['suspended'] else reset})
        assert fails(data, f['password'] + '!', f['kdf'], everyone)
        files[f['file']] = data
        slots = [{**s, 'credhash': credhash(s['cred_id']), 'hmac_output': hmac_output(f['vault_id'], s)}
                 for s in f['slots']]
        kept = {k: v for k, v in f.items() if k not in ('salt', 'body_nonce', 'slots')}
        record['fixtures'].append(hexed({
            **kept, 'magic': f['magic'].decode(), 'slots': slots, 'ks_id': opened['ks_id'],
            'draws': seal_draws(f), 'size': len(data), 'h': opened['h'], 'w': opened['w'],
            'b': opened['b'], 'e': opened['e'], 'tag': opened['tag'],
            'key_code': key_code(f['vault_id'], f['keys'][0], f['epoch'], opened['tag'])}))
    for name, source, change, make in VARIANTS:
        data = make(files[source])
        try:
            parse(data)
            raise SystemExit('%s parses' % name)
        except AssertionError:
            pass
        files[name] = data
        record['variants'].append({'file': name, 'from': source, 'change': change, 'size': len(data)})
    files['hw_fixtures.json'] = (json.dumps(record, indent=1) + '\n').encode()


def main():
    check = sys.argv[1:] == ['--check']
    if sys.argv[1:] and not check:
        sys.exit(__doc__)
    files = {}
    build_password_only(files)
    build_hardware(files)
    stale = []
    for name, data in files.items():
        path = out_dir / name
        if check:
            if not path.exists() or path.read_bytes() != data:
                stale.append(name)
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    if stale:
        sys.exit('differs: ' + ', '.join(stale))
    print('checked' if check else f'wrote {out_dir}')


if __name__ == '__main__':
    main()
