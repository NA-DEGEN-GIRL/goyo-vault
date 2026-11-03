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
    data object Home : Screen
    data object Unlock : Screen
    data object List : Screen
    data class Detail(val index: Int) : Screen
    /** index -1: a new entry. */
    data class Edit(val index: Int) : Screen
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
    var rows: List<Row> by mutableStateOf(emptyList())
    var status: Int by mutableStateOf(0)
    /** What runs now ("YubiKey를 대거나 꽂으세요", ...); null when idle. */
    var busy: String? by mutableStateOf(null)
    var message: String? by mutableStateOf(null)
    /** Whether the imported key file needs a YubiKey (checked before the unlock screen). */
    var needsKey: Boolean by mutableStateOf(false)
    /** The tag of the imported vault, or null. */
    var tag: String? by mutableStateOf(null)

    var session = 0L
        private set
    /** Counts locks: an unlock that finishes after a lock closes its session at once. */
    var lockCount = 0
        private set
    private var idle: Job? = null

    /** Locks after this long without a touch on the screen. */
    private const val IDLE_MS = 3 * 60 * 1000L

    fun refreshTag(context: Context) {
        tag = if (VaultFiles.present(context)) {
            try {
                Native.vaultTag(VaultFiles.vault(context).path)
            } catch (e: GoyoException) {
                null
            }
        } else {
            null
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
        session = 0L
        rows = emptyList()
        status = 0
        busy = null
        if (screen != Screen.Home) screen = Screen.Home
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
