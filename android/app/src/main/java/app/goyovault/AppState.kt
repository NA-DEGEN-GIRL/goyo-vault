package app.goyovault

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface Screen {
    /**
     * The start: the welcome screen without a vault, the login with one,
     * "서버에서 가져온 금고" for a vault from the server whose key file is
     * not saved yet, or the key-file step for a vault without one
     * ([AppState.home]).
     */
    data object Home : Screen
    /** "새 금고 만들기". */
    data object Create : Screen
    /** "서버에서 가져오기": the server, this phone's key, the check, the server's vaults. */
    data object ServerImport : Screen
    data object List : Screen
    data class Detail(val index: Int) : Screen
    /** index -1: a new entry. */
    data class Edit(val index: Int) : Screen
    /** The sync settings (from the login, or from the open vault's list). */
    data object Settings : Screen
    /** "열쇠 관리": the keys, the key code, [키 추가], the key backup. */
    data object Keys : Screen
}

/** What is on the phone, which decides the start screen (as the PC's welcome or login). */
enum class Home {
    /** No vault: 서버에서 가져오기 · 새 금고 만들기 · 파일에서 가져오기. */
    Welcome,
    /** A vault and its key file: the login. */
    Login,
    /** A vault from the server with the server's key file not saved yet: "서버에서 가져온 금고". */
    Fetched,
    /** A vault without a key file: the key file comes from the PC (or the server). */
    NeedKey,
}

/** One row of the entry list: never the secret or the notes. */
data class Row(val title: String, val kind: String)

/**
 * The app's state, process-wide so that an activity re-created (rotation,
 * dark mode) finds it as it was. The session itself lives in Rust; this
 * keeps only its handle.
 */
object AppState {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    /** A failure at start (the lib's self test): the app shows only this. */
    var fatal: String? by mutableStateOf(null)
    var screen: Screen by mutableStateOf(Screen.Home)
    var home: Home by mutableStateOf(Home.Welcome)
    var rows: List<Row> by mutableStateOf(emptyList())
    var status: Int by mutableStateOf(0)
    /** What runs now ("YubiKey를 대거나 꽂으세요", ...); null when idle. */
    var busy: String? by mutableStateOf(null)
    var message: String? by mutableStateOf(null)
    /** The login's keys (-1 unknown, 0 password only, else the count). */
    var loginKeys: Int by mutableStateOf(-1)
    /** The vault from the server's key file needs a YubiKey. */
    var fetchedNeedsKey: Boolean by mutableStateOf(true)
    /** The tag of the vault on the phone, or null. */
    var tag: String? by mutableStateOf(null)
    /** Bumped when the open vault's keys or banners should be read again. */
    var keysVersion: Int by mutableStateOf(0)

    var session = 0L
        private set
    /** Counts locks: an unlock that finishes after a lock closes its session at once. */
    var lockCount = 0
        private set
    private var idle: Job? = null

    /** Locks after this long without a touch on the screen. */
    private const val IDLE_MS = 3 * 60 * 1000L

    /**
     * No edit before the key file is confirmed (TOFU, a gate, a key file
     * from the server not saved yet). A key change waiting on the server
     * holds only sync, as on a PC.
     */
    fun readOnly(): Boolean =
        status and (Native.STATUS_TOFU or Native.STATUS_GATE_PENDING or Native.STATUS_FETCHED) != 0

    /** Reads what is on the phone: the tag and the start screen. */
    fun refreshHome(context: Context) {
        val vault = VaultFiles.vault(context)
        tag = if (vault.isFile) {
            try {
                Native.vaultTag(vault.path)
            } catch (e: GoyoException) {
                null
            }
        } else {
            null
        }
        home = when {
            !vault.isFile -> Home.Welcome
            VaultFiles.key(context).isFile -> Home.Login
            else -> {
                val state = try {
                    Native.fetchedState(vault.path)
                } catch (e: GoyoException) {
                    0
                }
                fetchedNeedsKey = state != 2
                if (state == 0) Home.NeedKey else Home.Fetched
            }
        }
        loginKeys = if (home == Home.Login) {
            try {
                Native.loginKeys(VaultFiles.key(context).path)
            } catch (e: GoyoException) {
                -1
            }
        } else {
            -1
        }
    }

    fun opened(handle: Long) {
        session = handle
        reload()
        screen = Screen.List
        touched()
    }

    fun reload() {
        if (session == 0L) return
        try {
            val t = Native.titles(session)
            rows = List(t.size / 2) { Row(t[2 * it], t[2 * it + 1]) }
            status = Native.status(session)
            keysVersion++
        } catch (e: GoyoException) {
            lock(e.message)
        }
    }

    /** Locks the session (background, timeout or the user) and forgets every row. */
    fun lock(why: String? = null) {
        lockCount++
        idle?.cancel()
        idle = null
        Native.closeAll()
        Sync.stopLoop()
        session = 0L
        rows = emptyList()
        status = 0
        busy = null
        if (screen != Screen.Home && screen != Screen.ServerImport && screen != Screen.Create) {
            screen = Screen.Home
        }
        // Whatever the last screen said (a copy, a save) goes with it.
        message = why
    }

    /** A touch on the screen: restarts the idle timer of an open session. */
    fun touched() {
        if (session == 0L) return
        idle?.cancel()
        idle = scope.launch {
            delay(IDLE_MS)
            lock("오래 쓰지 않아 잠갔습니다.")
        }
    }

    /** Runs `block` off the main thread; a GoyoException becomes the message. */
    fun <T> work(label: String, block: suspend () -> T, done: (T) -> Unit) {
        busy = label
        message = null
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) { block() }
                busy = null
                done(result)
            } catch (e: GoyoException) {
                busy = null
                message = e.message
            } catch (e: Exception) {
                busy = null
                message = "작업 실패: ${e.javaClass.simpleName}"
            }
        }
    }
}

/** UTF-8 bytes of `chars` without making a String; the caller zeroes them. */
fun utf8(chars: CharSequence): ByteArray {
    val buf = java.nio.CharBuffer.allocate(chars.length)
    for (i in chars.indices) buf.put(chars[i])
    buf.flip()
    val encoded = Charsets.UTF_8.newEncoder().encode(buf)
    val out = ByteArray(encoded.remaining())
    encoded.get(out)
    // Wipe the encoder's and the char buffer's copies.
    if (encoded.hasArray()) encoded.array().fill(0)
    buf.array().fill('\u0000')
    return out
}

fun chars(seq: CharSequence): CharArray = CharArray(seq.length) { seq[it] }
