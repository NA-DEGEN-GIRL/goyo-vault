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

    const val STATUS_TOFU = 1
    const val STATUS_GATE_PENDING = 2
}

/** A refusal or failure of the vault core, with its text for the user. */
class GoyoException(message: String) : Exception(message)
