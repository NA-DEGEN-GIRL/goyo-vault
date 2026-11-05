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

    /** One field as UTF-8 (0 title, 1 kind, 2 secret, 3 notes); an OTP entry's secret is empty. */
    external fun field(session: Long, index: Int, which: Int): ByteArray

    /**
     * Stores a new entry (index -1) or replaces one, and saves. `otp` is the
     * editor's OTP field (a Base32 key or an otpauth URI, parsed in Rust);
     * empty keeps the edited entry's OTP secret, or drops it with `removeOtp`.
     */
    external fun put(
        session: Long,
        index: Int,
        title: ByteArray,
        kind: ByteArray,
        secret: ByteArray,
        notes: ByteArray,
        otp: ByteArray,
        removeOtp: Boolean,
    )

    // ---- an entry's OTP secret (0.12.0); the code is made in Rust ----

    /** Whether the entry is an OTP entry (0.12.1): the OTP kind, shown without 비밀정보. */
    external fun otpEntry(session: Long, index: Int): Boolean

    /** Whether the editor's kind is the OTP kind (the lib's own rule). */
    external fun isOtpKind(kind: String): Boolean

    /** Issuer, account and unusual settings ("" for SHA1 · 6 digits · 30 s); null without OTP. */
    external fun otpInfo(session: Long, index: Int): Array<String>?

    /** The code of this moment and the seconds until it changes. */
    external fun otpCode(session: Long, index: Int): Array<String>

    /** The secret in Base32 (UTF-8), only for "시크릿 복사"; zero it after use. */
    external fun otpSecret(session: Long, index: Int): ByteArray

    /**
     * The QR code of the otpauth URI, only for "QR 보기": side (u16 big-endian),
     * then one byte per module, row-major, 1 dark; zero it after drawing.
     */
    external fun otpQr(session: Long, index: Int): ByteArray

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

    // ---- stage 4: a new vault, the Keys screen, gates, the server import ----

    /** The PC's password policy; throws its text. `password` is zeroed. */
    external fun passwordCheck(password: ByteArray)

    /** A new vault's flow (ID and data key drawn, the password kept in Rust); `password` is zeroed. */
    external fun createBegin(password: ByteArray): Long

    external fun createTag(flow: Long): String

    /** Writes the new vault (with the keys registered, or password-only); its session. */
    external fun createFinish(flow: Long, vaultPath: String, keyPath: String, withKeys: Boolean): Long

    /** Drops a flow (cancelled). */
    external fun flowClose(flow: Long)

    /** The next registration's MakeCredential request ([MakeRequest.parse]). */
    external fun regStart(flow: Long): ByteArray

    /** MakeCredential's authenticator data as the key returned it; the check request ([AssertRequest.parse]). */
    external fun regMade(flow: Long, authData: ByteArray, transport: Int): ByteArray

    /** The check's answer (outputs zeroed); the number of keys the flow holds. */
    external fun regChecked(
        flow: Long,
        credId: ByteArray,
        authData: ByteArray,
        first: ByteArray,
        second: ByteArray?,
        transport: Int,
    ): Int

    /** What holds a key change now, as a question (default no), or null. */
    external fun keyAddGate(session: Long): String?

    /** [키 추가]'s flow; `password` is zeroed. */
    external fun keyAddBegin(session: Long, password: ByteArray, overrideGate: Boolean): Long

    /** The flow's Reauth touch request ([AssertRequest.parse]). */
    external fun flowTouchRequest(flow: Long): ByteArray

    external fun keyAddReauth(
        flow: Long,
        credId: ByteArray,
        authData: ByteArray,
        first: ByteArray,
        second: ByteArray?,
        transport: Int,
    )

    /** The write: the text, then "1" when the app must lock now. */
    external fun keyAddFinish(flow: Long): Array<String>

    /** State line, key code (""), backup due ("1"), full keys line, then one row per key. */
    external fun keysInfo(session: Long): Array<String>

    /** A copy of the key file at `path` (a new file), read back; recorded as backed up. */
    external fun keyBackup(session: Long, path: String)

    /** -1 unreadable, 0 password-only, else the number of security keys. */
    external fun loginKeys(keyPath: String): Int

    /** "G1" or "G2", the epoch, then for G2 "number|date[|1 opened]"; null without a gate. */
    external fun gateInfo(session: Long): Array<String>?

    /** The gate's answer: a code (G1) or the lost keys' numbers (G2). */
    external fun gatePass(session: Long, code: String?, picks: IntArray?)

    /** "none"/"G1"/"G2", the epoch, then for G2 "number|date"; null when no key change waits. */
    external fun takeInfo(session: Long): Array<String>?

    /** "needpass" + its text, or "ok" + the lines of what [받기] does. `otherPassword` is zeroed. */
    external fun takePreview(session: Long, code: String?, picks: IntArray?, otherPassword: ByteArray?): Array<String>

    /** [받기]: the lines, then "1" when the app must lock now. */
    external fun takeAccept(session: Long): Array<String>

    external fun takeDrop(session: Long)

    /** "id|tag|head|size|mtime|key" per vault on the server. `seed` is zeroed. */
    external fun serverList(root: String, seed: ByteArray?): Array<String>

    /** The head of vault `id` as the phone's vault, then its key file: version, size, key result. */
    external fun serverFetch(root: String, seed: ByteArray?, id: String): Array<String>

    /** The server's key file of the phone's vault into its sync folder: the key result. */
    external fun serverFetchKey(root: String, seed: ByteArray?): String

    /** 0 no key file from the server next to the vault, 1 one that needs a security key, 2 one without. */
    external fun fetchedState(vaultPath: String): Int

    /** Phase 1 of opening a vault from the server with the server's key file. */
    external fun prepareFetched(vaultPath: String): Long

    /** The server's key file confirmed (the other device's code, or null) and saved at `keyPath`. */
    external fun fetchedSave(session: Long, code: String?, keyPath: String)

    const val STATUS_TOFU = 1
    const val STATUS_GATE_PENDING = 2
    /** The key file came from the server and is not saved on this phone yet. */
    const val STATUS_FETCHED = 4
    /** Another device's key change waits to be taken with this unlock's touch. */
    const val STATUS_TAKE = 8
}

/** A refusal or failure of the vault core, with its text for the user. */
class GoyoException(message: String) : Exception(message)
