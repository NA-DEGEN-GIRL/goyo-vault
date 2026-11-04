package app.goyovault

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Sync on the phone (docs/ANDROID.md '동기화'): only over Tailscale, to the
 * user's own server, with the Windows helper's engine (in Rust). A run
 * moves encrypted files between the server and the vault's sync folder and
 * never opens the vault; the open vault merges and uploads through its own
 * poll, every 2 s while the list is shown. Runs happen at unlock, after
 * each save, on "지금 동기화", while the vault is open whenever the engine
 * says one is due (its 60 s poll, its heartbeat, a retry), and every 15
 * minutes in the background (WorkManager, network connected).
 */
object Sync {
    private const val WORK = "goyo-sync-periodic"
    /** The open vault's poll, as goyo-vault.exe's 2 s timer. */
    private const val POLL_MS = 2_000L

    /** The last run's or check's state word (syncrun.rs `Shown`), text and host-key fingerprint. */
    var state: String? by mutableStateOf(null)
    var text: String by mutableStateOf("")
    var fingerprint: String by mutableStateOf("")
    /** The open vault's badge: -1 not synced, 0 synced, 1 uploading, 2 not run lately, 3 offline, 4 warning. */
    var badge: Int by mutableStateOf(-1)
    var running: Boolean by mutableStateOf(false)
    /** Ask whether to turn sync on for the open vault (an older format, the folder exists). */
    var offer: Boolean by mutableStateOf(false)

    private val lock = Mutex()
    private var loop: Job? = null

    fun root(context: Context): String = context.filesDir.absolutePath

    /** Settings saved and a key made: sync is set up on this phone. */
    fun configured(context: Context): Boolean =
        SyncKey.present(context) && Native.syncSettingsLoad(root(context)) != null

    /**
     * Whether a VPN network (Tailscale on Android is one) is up. The Rust
     * side refuses every address that is not a Tailscale address anyway;
     * this keeps a run from even resolving the name on a carrier network.
     */
    fun vpnUp(context: Context): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        @Suppress("DEPRECATION")
        return cm.allNetworks.any { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }

    fun loadLast(context: Context) {
        val last = try {
            Native.syncLastResult(root(context))
        } catch (e: GoyoException) {
            null
        }
        if (last != null) show(last)
    }

    private fun show(r: Array<String>) {
        state = r[0]
        text = r[1]
        fingerprint = r[2]
    }

    /**
     * One run (off the main thread). `force` polls the server; without it
     * only what the engine says is due runs, and the key is unwrapped only
     * then. Never opens the vault.
     */
    suspend fun run(context: Context, force: Boolean) {
        val app = context.applicationContext
        lock.withLock {
            withContext(Dispatchers.IO) {
                val root = root(app)
                if (!configured(app)) return@withContext
                if (!force && !Native.syncDue(root)) return@withContext
                if (!vpnUp(app)) {
                    withContext(Dispatchers.Main) {
                        state = "tailnet"
                        text = "Tailscale(VPN)이 켜져 있지 않아 동기화하지 않았습니다. 휴대폰에서 Tailscale을 켜세요. 동기화는 Tailscale로만 합니다."
                        fingerprint = ""
                    }
                    return@withContext
                }
                withContext(Dispatchers.Main) { running = true }
                val seed = SyncKey.unwrap(app)
                val result = try {
                    Native.syncRun(root, seed, force)
                } catch (e: GoyoException) {
                    arrayOf("server", e.message ?: "", "")
                } finally {
                    seed?.fill(0)
                }
                withContext(Dispatchers.Main) {
                    running = false
                    show(result)
                }
            }
        }
    }

    /** '연결 확인' (HELLO and LIST); an unknown host key is offered for pinning. */
    suspend fun check(context: Context) {
        val app = context.applicationContext
        lock.withLock {
            withContext(Dispatchers.IO) {
                val root = root(app)
                if (!vpnUp(app)) {
                    withContext(Dispatchers.Main) {
                        state = "tailnet"
                        text = "Tailscale(VPN)이 켜져 있지 않습니다. 휴대폰에서 Tailscale을 켜세요."
                        fingerprint = ""
                    }
                    return@withContext
                }
                withContext(Dispatchers.Main) { running = true }
                val seed = SyncKey.unwrap(app)
                val result = try {
                    Native.syncCheck(root, seed)
                } catch (e: GoyoException) {
                    arrayOf("server", e.message ?: "", "")
                } finally {
                    seed?.fill(0)
                }
                withContext(Dispatchers.Main) {
                    running = false
                    show(result)
                }
            }
        }
    }

    /** A save: run now so the change goes up, then the vault's poll. */
    fun afterSave(context: Context) {
        val app = context.applicationContext
        AppState.scope.launch {
            pollSession()
            run(app, force = true)
            pollSession()
        }
    }

    /** "지금 동기화". */
    fun now(context: Context) {
        val app = context.applicationContext
        AppState.scope.launch {
            pollSession()
            run(app, force = true)
            pollSession()
        }
    }

    /**
     * While a vault is open: a forced run at once (the unlock), then the
     * vault's poll every 2 s and a run whenever one is due. Stops with the
     * session.
     */
    fun startLoop(context: Context) {
        val app = context.applicationContext
        loop?.cancel()
        loop = AppState.scope.launch {
            // The unlock's own line (a merge, a halt), once.
            val session = AppState.session
            val line = try {
                withContext(Dispatchers.IO) { Native.sessionUnlockNotice(session) }
            } catch (e: GoyoException) {
                null
            }
            if (line != null && AppState.message == null) AppState.message = line[0]
            run(app, force = true)
            pollSession()
            if (AppState.session != 0L) {
                offer = try {
                    withContext(Dispatchers.IO) { Native.sessionSyncOffer(AppState.session) }
                } catch (e: GoyoException) {
                    false
                } && configured(app)
            }
            var tick = 0
            while (isActive && AppState.session != 0L) {
                delay(POLL_MS)
                pollSession()
                if (++tick % 3 == 0) run(app, force = false)
            }
        }
    }

    fun stopLoop() {
        loop?.cancel()
        loop = null
        badge = -1
        offer = false
    }

    /** The open vault's poll: merges a server copy, writes its upload, reads the status. */
    suspend fun pollSession() {
        val session = AppState.session
        if (session == 0L) return
        val r = try {
            withContext(Dispatchers.IO) { Native.sessionSyncPoll(session) }
        } catch (e: GoyoException) {
            return
        }
        if (session != AppState.session) return
        badge = r[0].toIntOrNull() ?: -1
        if (r[1] == "1") AppState.reload()
        if (r[2].isNotEmpty()) AppState.message = r[2]
    }

    /** Turns sync on for the open vault after the user's yes. */
    fun enable(context: Context) {
        val app = context.applicationContext
        val session = AppState.session
        offer = false
        AppState.work("동기화 켜는 중…", { Native.sessionEnableSync(session) }) {
            AppState.message = "동기화를 켰습니다. 서버에 올라가면 '동기화됨'이 표시됩니다."
            now(app)
        }
    }

    /** The 15-minute background work, when sync is set up; removed otherwise. */
    fun schedule(context: Context) {
        val wm = WorkManager.getInstance(context)
        if (!configured(context)) {
            wm.cancelUniqueWork(WORK)
            return
        }
        val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
        val request = PeriodicWorkRequestBuilder<SyncWorker>(15, TimeUnit.MINUTES)
            .setConstraints(constraints)
            .build()
        wm.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.KEEP, request)
    }

    /** The badge's words (the open vault's and the last run's). */
    fun label(): String {
        when (state) {
            "tailnet" -> return "Tailscale 아님"
            "hostkey-unknown" -> return "호스트 키 확인 필요"
            "hostkey-changed" -> return "호스트 키 바뀜 · 연결 안 함"
            "auth" -> return "인증 실패"
            "nokey" -> return "키 없음"
            "oldserver" -> return "서버 스크립트 오래됨"
            "keyfile" -> return "열쇠: 서버와 상태 다름"
            "nokeys" -> return "열쇠: 서버가 허용 안 함"
            "refused" -> return "업로드 거부됨"
            "update" -> return "새 형식"
        }
        return when (badge) {
            0 -> "동기화됨"
            1 -> "올리는 중"
            2 -> if (state == "offline") "오프라인" else "동기화 대기"
            3 -> "오프라인"
            4 -> "확인 필요"
            else -> when (state) {
                "ok" -> "정상"
                "offline" -> "오프라인"
                "server" -> "서버 오류"
                null, "nosettings" -> "설정 전"
                else -> "확인 필요"
            }
        }
    }

    /** Whether the badge is a warning (red). */
    fun warning(): Boolean =
        state in setOf("tailnet", "hostkey-unknown", "hostkey-changed", "auth", "nokey", "oldserver",
            "keyfile", "nokeys", "refused", "update", "server") || badge == 4
}

/**
 * The periodic background run: moves encrypted files only, with the
 * vault locked. Never opens the vault or the key file.
 */
class SyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        if (!Sync.configured(applicationContext)) return Result.success()
        // WorkManager stopping the work cancels this coroutine; the
        // exchange in Rust is told to stop too.
        kotlin.coroutines.coroutineContext[Job]?.invokeOnCompletion { cause ->
            if (cause is kotlinx.coroutines.CancellationException) Native.syncCancel()
        }
        try {
            Sync.run(applicationContext, force = true)
        } catch (e: Exception) {
            // The engine keeps its own backoff; the next period tries again.
        }
        return Result.success()
    }
}
