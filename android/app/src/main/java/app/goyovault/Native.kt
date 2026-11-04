package app.goyovault

/**
 * The Rust bridge (android/rust, libgoyo_android.so). Every call may throw
 * [GoyoException] with a Korean text for the user. Byte arrays that carry a
 * password, a field or an hmac-secret output are zeroed by the Rust side
 * after it copied them; callers zero their own copies too.
 */
object Native {
    init {
        System.loadLibrary("goyo_android")
    }

    /** The app's private files folder; the anchor lives in `<root>/GoyoVault`. */
    external fun setAnchorRoot(path: String)

    /** The lib's HKDF and security-key self tests and one RNG draw. */
    external fun selfTest()

    /** The vault's public tag, or null when the file is no vault. */
    external fun vaultTag(path: String): String?

    /** Phase 1 of a login: a pending login's handle. */
    external fun prepare(vaultPath: String, keyPath: String): Long

    /** The security-key request of a pending login, or null (password only). */
    external fun request(pending: Long): ByteArray?

    /**
     * Phase 3: uses the pending login up and returns a session handle.
     * For a key file with security keys, the assertion fields are exactly
     * what the YubiKey returned; `transport` is 1 (USB) or 2 (NFC).
     */
    external fun unlock(
        pending: Long,
        password: ByteArray,
        credId: ByteArray?,
        authData: ByteArray?,
        first: ByteArray?,
        second: ByteArray?,
        transport: Int,
    ): Long

    /** Drops a pending login or locks a session. */
    external fun close(handle: Long)

    /** Locks every session and drops every pending login. */
    external fun closeAll()

    /** Bit 1: TOFU (read-only until the PC's key code is typed); bit 2: gate pending. */
    external fun status(session: Long): Int

    /** Confirms the key file on this device: the PC's key code, or null (no code, after a yes). */
    external fun tofuConfirm(session: Long, code: String?)

    /** Title and kind of every entry, interleaved. */
    external fun titles(session: Long): Array<String>

    /** One field as UTF-8 (0 title, 1 kind, 2 secret, 3 notes). */
    external fun field(session: Long, index: Int, which: Int): ByteArray

    /** Stores a new entry (index -1) or replaces one, and saves. */
    external fun put(
        session: Long,
        index: Int,
        title: ByteArray,
        kind: ByteArray,
        secret: ByteArray,
        notes: ByteArray,
    )

    external fun delete(session: Long, index: Int)

    // ---- sync (stage 3); `root` is the app's files folder ----

    /** Checks and stores the sync settings; throws with the bad field's text. */
    external fun syncSettingsSave(root: String, host: String, port: String, user: String, remote: String, python: String)

    /** host, port, user, remote, python; or null. */
    external fun syncSettingsLoad(root: String): Array<String>?

    /** A new ed25519 seed (32 bytes) for [SyncKey] to wrap at once. */
    external fun syncNewSeed(): ByteArray

    /** The base64 public key of `seed` (zeroed). */
    external fun syncPublic(seed: ByteArray): String

    /** The server's authorized_keys line for this phone. */
    external fun syncLine(root: String, blob: String, model: String): String

    /**
     * One run of the sync engine (moves encrypted files only; never opens
     * the vault): state, text, fingerprint. `seed` is zeroed.
     */
    external fun syncRun(root: String, seed: ByteArray?, force: Boolean): Array<String>

    /** Whether a run would do anything now (no key needed). */
    external fun syncDue(root: String): Boolean

    /** '연결 확인': HELLO and LIST. `seed` is zeroed. */
    external fun syncCheck(root: String, seed: ByteArray?): Array<String>

    /** The last run's state, text, fingerprint; or null. */
    external fun syncLastResult(root: String): Array<String>?

    /** Pins the host key the last unknown host showed, if this is its fingerprint. */
    external fun syncPinHost(root: String, fingerprint: String)

    /** host:port and fingerprint of the pinned host key; or null. */
    external fun syncPinned(root: String): Array<String>?

    external fun syncForgetPin(root: String)

    external fun syncCancel()

    /** Removes the vault's sync folder (a new import resets sync). */
    external fun syncReset(root: String)

    /** The open vault's sync poll: badge code, list changed ("1"), notice, warning ("1"). */
    external fun sessionSyncPoll(session: Long): Array<String>

    /** The line after unlocking (text, warning "1"), once; or null. */
    external fun sessionUnlockNotice(session: Long): Array<String>?

    /** -1 not synced, 0 synced, 1 uploading, 2 not run lately, 3 offline, 4 warning. */
    external fun sessionBadge(session: Long): Int

    external fun sessionSyncOffer(session: Long): Boolean

    external fun sessionEnableSync(session: Long)

    const val STATUS_TOFU = 1
    const val STATUS_GATE_PENDING = 2
}

/** A refusal or failure of the vault core, with its text for the user. */
class GoyoException(message: String) : Exception(message)
