package app.goyovault

import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.fido.ctap.Ctap2Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private lateinit var yubikit: YubiKitManager
    private var keyWait: KeyWait<*>? = null
    /** The vault file picked in the first step of an import. */
    private var pickedVault: Uri? = null

    private val pickVault = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@registerForActivityResult
        pickedVault = uri
        AppState.message = "이제 열쇠 파일(.goyokey)을 고르세요."
        pickKey.launch(arrayOf("*/*"))
    }
    private val pickKey = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val vault = pickedVault
        pickedVault = null
        if (uri == null || vault == null) {
            AppState.message = "가져오기를 취소했습니다."
            return@registerForActivityResult
        }
        importFiles(vault, uri)
    }
    /** The key file alone, for the vault already on the phone. */
    private val pickKeyOnly = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            AppState.message = "가져오기를 취소했습니다."
            return@registerForActivityResult
        }
        AppState.work("가져오는 중…", { VaultFiles.importKey(this, uri) }) {
            AppState.refreshHome(this)
            AppState.message = "열쇠 파일을 가져왔습니다. 비밀번호와 YubiKey로 여세요. 가져온 뒤 Download 등의 사본은 지우세요."
        }
    }
    /** Where the key backup goes (SAF); the copy was written before the picker opened. */
    private val saveBackup = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val temp = VaultFiles.backupTemp(this)
        if (uri == null) {
            temp.delete()
            AppState.message = "열쇠 백업을 저장하지 않았습니다."
            return@registerForActivityResult
        }
        AppState.work("열쇠 파일 저장 중…", {
            try {
                VaultFiles.copyOut(this, temp, uri)
            } finally {
                temp.delete()
            }
        }) {
            AppState.message = "열쇠 파일을 백업했습니다. 금고와 따로, 안전한 곳에 보관하세요. (저장할 곳을 고르는 동안 금고를 잠갔습니다.)"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no screen recording, no preview in the recent apps.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // No autofill service (a password manager) sees, fills or offers to
        // save the vault password, the PIN or a secret.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        yubikit = YubiKitManager(this)
        AppState.refreshHome(this)
        Sync.loadLast(this)
        Sync.schedule(this)
        setContent {
            val dark = isSystemInDarkTheme()
            MaterialTheme(colorScheme = if (dark) darkColorScheme() else lightColorScheme()) {
                GoyoUi(this)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        keyWait?.startNfc(this)
    }

    override fun onStop() {
        super.onStop()
        // Leaving the app (home, another app, screen off) locks the vault.
        if (!isChangingConfigurations) lockNow(null)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        AppState.touched()
    }

    fun lockNow(why: String?) {
        keyWait?.stop(this)
        keyWait = null
        Ask.cancel()
        AppState.lock(why)
        AppState.refreshHome(this)
    }

    fun cancelKey() {
        keyWait?.stop(this)
    }

    // ---- files ----

    fun startImport() {
        if (AppState.session != 0L) lockNow(null)
        AppState.message = "먼저 금고 파일(.goyo)을 고르세요."
        pickVault.launch(arrayOf("*/*"))
    }

    fun startKeyImport() {
        AppState.message = "PC에서 옮겨 온 이 금고의 열쇠 파일(.goyokey)을 고르세요."
        pickKeyOnly.launch(arrayOf("*/*"))
    }

    private fun importFiles(vault: Uri, key: Uri) {
        AppState.work("가져오는 중…", {
            Native.syncReset(Sync.root(this))
            VaultFiles.remove(this)
            VaultFiles.import(this, vault, key)
            Native.vaultTag(VaultFiles.vault(this).path)
                ?: run {
                    VaultFiles.remove(this)
                    throw GoyoException("고른 금고 파일이 고요 금고 파일이 아닙니다.")
                }
        }) { tag ->
            AppState.refreshHome(this)
            AppState.screen = Screen.Home
            AppState.message = "금고 $tag 를 가져왔습니다. 가져온 뒤 Download 등의 사본은 지우세요."
        }
    }

    /** Removes the vault from the phone (after the user's yes): the welcome screen follows. */
    fun removeVault() {
        lockNow(null)
        Native.syncReset(Sync.root(this))
        VaultFiles.remove(this)
        AppState.refreshHome(this)
        AppState.screen = Screen.Home
        AppState.message = "이 휴대폰의 금고 파일과 열쇠 파일을 지웠습니다. PC와 서버의 파일은 그대로입니다."
    }

    // ---- the YubiKey ----

    /**
     * Runs one ceremony on the first YubiKey that comes (USB-C or NFC),
     * with `label` on the screen; `pin` is wiped whatever happens.
     */
    private suspend fun <T> withKey(
        label: String,
        pin: CharArray?,
        discard: (T) -> Unit,
        op: (Ctap2Session, Int, CommandState, CharArray?) -> T,
    ): T {
        val wait = KeyWait(yubikit, pin, { note -> runOnUiThread { AppState.message = note } }, op, discard)
        keyWait = wait
        try {
            wait.start(this)
            AppState.busy = if (wait.nfc) label else "$label\n(NFC가 꺼져 있어 USB-C만 됩니다)"
            return wait.result.await()
        } finally {
            wait.stop(this)
            if (keyWait === wait) keyWait = null
        }
    }

    private suspend fun assertion(label: String, request: ByteArray, pin: CharArray?): Assertion {
        val req = AssertRequest.parse(request)
        return withKey(label, pin, Assertion::wipe) { ctap, transport, state, p ->
            Ceremony.run(ctap, req, p, transport, state)
        }
    }

    /** One registration of `flow` (MakeCredential, then its check); the keys it holds now. */
    private suspend fun register(flow: Long, what: String, pin: CharArray?): Int {
        val make = MakeRequest.parse(withContext(Dispatchers.IO) { Native.regStart(flow) })
        val a = withKey(
            "$what: YubiKey를 대거나 꽂으세요. 등록 1번, 확인 1번 터치합니다(NFC는 댄 채로 기다리세요).",
            pin,
            Assertion::wipe,
        ) { ctap, transport, state, p ->
            Registrar.run(ctap, make, p, transport, state) { auth -> Native.regMade(flow, auth, transport) }
        }
        try {
            AppState.busy = "확인 중…"
            return withContext(Dispatchers.IO) {
                Native.regChecked(flow, a.credId, a.authData, a.first, a.second, a.transport)
            }
        } finally {
            a.wipe()
        }
    }

    /** Runs a flow on the app's scope: a GoyoException becomes the message. */
    private fun flow(block: suspend () -> Unit) {
        val myLock = AppState.lockCount
        AppState.message = null
        AppState.scope.launch {
            try {
                block()
            } catch (e: GoyoException) {
                if (myLock == AppState.lockCount) AppState.message = e.message
            } catch (e: Exception) {
                if (myLock == AppState.lockCount) AppState.message = "작업 실패: ${e.javaClass.simpleName}"
            } finally {
                AppState.busy = null
            }
        }
    }

    // ---- the unlock ----

    /**
     * The unlock (the login, or "서버에서 가져온 금고"): phase 1, the YubiKey
     * ceremony when the key file has security keys, then phase 3 in Rust.
     * `password` and `pin` are wiped here whatever happens.
     */
    fun unlock(password: ByteArray, pin: CharArray?) {
        val fetched = AppState.home == Home.Fetched
        val v = VaultFiles.vault(this).path
        val k = VaultFiles.key(this).path
        val myLock = AppState.lockCount
        AppState.message = null
        AppState.busy = "파일 확인 중…"
        AppState.scope.launch {
            var pending = 0L
            var assertion: Assertion? = null
            try {
                pending = withContext(Dispatchers.IO) {
                    if (fetched) Native.prepareFetched(v) else Native.prepare(v, k)
                }
                val request = withContext(Dispatchers.IO) { Native.request(pending) }
                if (request != null) {
                    assertion = assertion("YubiKey를 대거나 꽂으세요", request, pin?.copyOf())
                }
                AppState.busy = "금고 여는 중… (몇 초 걸립니다)"
                val a = assertion
                val p = pending
                pending = 0L
                val session = withContext(Dispatchers.IO) {
                    Native.unlock(p, password, a?.credId, a?.authData, a?.first, a?.second, a?.transport ?: 0)
                }
                if (myLock != AppState.lockCount) {
                    Native.close(session)
                } else {
                    AppState.busy = null
                    AppState.opened(session)
                    if (fetched) {
                        AppState.message = "② 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 아래에 입력하세요."
                    }
                    Sync.startLoop(this@MainActivity)
                }
            } catch (e: GoyoException) {
                AppState.busy = null
                if (myLock == AppState.lockCount) AppState.message = e.message
            } catch (e: Exception) {
                AppState.busy = null
                AppState.message = "열기 실패: ${e.javaClass.simpleName}"
            } finally {
                if (pending != 0L) Native.close(pending)
                password.fill(0)
                pin?.fill('\u0000')
                assertion?.wipe()
            }
        }
    }

    // ---- 새 금고 만들기 ----

    /**
     * "새 금고 만들기" (spec §9.2 "Create", "Create with keys"): the password
     * checked against the PC's policy, then with security keys one
     * registration after the other (S-SPARE asks for each next one, with
     * that key's PIN), the files written, and the key backup offered.
     */
    fun createVault(password: ByteArray, withKeys: Boolean, pin: CharArray?) = flow {
        val v = VaultFiles.vault(this).path
        val k = VaultFiles.key(this).path
        AppState.busy = "준비 중…"
        val flow = try {
            withContext(Dispatchers.IO) { Native.createBegin(password) }
        } finally {
            password.fill(0)
        }
        var done = false
        var keys = 0
        try {
            if (withKeys) {
                var nextPin = pin
                while (true) {
                    try {
                        keys = register(flow, "보안 키 ${keys + 1} 등록", nextPin)
                    } catch (e: GoyoException) {
                        // A failed first key ends the flow; a later one goes
                        // back to S-SPARE with the keys so far.
                        if (keys == 0) throw e
                        AppState.message = e.message
                    }
                    AppState.busy = null
                    if (keys >= 8) break
                    var text = "보안 키 ${keys}개를 등록했습니다. 등록한 키를 모두 잃으면 누구도(만든 사람도) 이 금고를 열 수 없고 복구 방법도 없습니다.\n" +
                        "예비 키를 지금 등록할까요? (강력 권장) 지금 함께 등록한 키끼리 짝을 맺어, 나중에 하나를 잃어도 남은 키 하나로 바로 뺄 수 있습니다.\n\n" +
                        "등록할 다음 YubiKey를 준비하세요. USB-C로 꽂아 둔 키는 먼저 빼세요."
                    if (keys == 1) {
                        text += "\n\n키마다 다른 PIN을 쓰세요. 모든 키에 같은 PIN을 쓰면, 잃어버린 키와 그 PIN을 아는 사람이 다른 키를 잠깐 손에 넣는 것만으로 그 키를 복제할 수 있습니다."
                    }
                    var next: CharArray?
                    while (true) {
                        next = Ask.ask(
                            Question("예비 키", text, "예비 키 등록", "그만 등록하고 만들기", field = "다음 키의 PIN", digits = true),
                        )
                        // S-NOSPARE before going on with one key.
                        if (next != null || keys > 1 || Ask.yes(
                                "예비 키 없이",
                                "예비 키 없이 계속할까요? 나중에 '열쇠 관리 › 키 추가'로 등록할 수 있습니다.",
                                "계속",
                                "예비 키 등록으로",
                                danger = true,
                            )
                        ) {
                            break
                        }
                    }
                    if (next == null) break
                    nextPin = next
                }
            }
            AppState.busy = "금고 만드는 중… (몇 초 걸립니다)"
            val session = withContext(Dispatchers.IO) { Native.createFinish(flow, v, k, withKeys) }
            done = true
            AppState.refreshHome(this)
            AppState.opened(session)
            AppState.busy = null
            AppState.message = when {
                !withKeys -> "새 금고를 만들었습니다. '열쇠 관리 › 열쇠 백업'으로 열쇠 파일 사본을 따로 두세요."
                keys == 1 -> "새 금고를 만들었습니다. 보안 키 1개가 등록되었습니다. 보안 키가 1개뿐입니다. 이 키를 잃거나 초기화하면 비밀번호와 열쇠 파일이 있어도 누구도 이 금고를 열 수 없습니다. '열쇠 관리'에서 예비 키를 추가하세요."
                else -> "새 금고를 만들었습니다. 보안 키 ${keys}개가 등록되었고 서로 짝을 맺었습니다."
            }
            Sync.startLoop(this)
            offerBackup("열쇠 파일을 지금 백업할까요? 열쇠 파일을 잃으면 보안 키와 비밀번호가 있어도 열 수 없습니다. 휴대폰 밖(USB 메모리, PC 등)에 두세요.")
        } finally {
            if (!done) Native.flowClose(flow)
        }
    }

    // ---- 열쇠 관리 ----

    /** S-BACKUP: asks, then writes the copy and opens the save picker. */
    private suspend fun offerBackup(text: String) {
        if (AppState.session == 0L) return
        if (!Ask.yes("열쇠 백업", text, "열쇠 백업…", "나중에")) return
        backupKey()
    }

    /** [열쇠 백업…]: the copy is written (and read back) before the picker opens, which locks the vault. */
    fun backupKey() {
        val session = AppState.session
        val temp = VaultFiles.backupTemp(this)
        val tag = AppState.tag ?: "vault"
        AppState.work("열쇠 파일 준비 중…", {
            temp.delete()
            Native.keyBackup(session, temp.path)
        }) {
            saveBackup.launch("goyo-$tag.goyokey")
        }
    }

    /**
     * [키 추가] (spec §9.2 "Add key"): what holds a key change asked first;
     * the Reauth with the current password and a touch of a key that
     * reaches every other; the registration of the new key; the write;
     * S-BACKUP-SHORT. The PINs are wiped here.
     */
    fun addKey(password: ByteArray, pin: CharArray, newPin: CharArray) = flow {
        val session = AppState.session
        var flow = 0L
        try {
            val gate = withContext(Dispatchers.IO) { Native.keyAddGate(session) }
            val override = gate != null
            if (gate != null && !Ask.yes("열쇠 변경", gate, "계속", danger = true)) return@flow
            flow = withContext(Dispatchers.IO) { Native.keyAddBegin(session, password, override) }
            val request = withContext(Dispatchers.IO) { Native.flowTouchRequest(flow) }
            val a = assertion("지금 등록된 YubiKey를 대거나 꽂으세요 (확인 1번)", request, pin.copyOf())
            try {
                AppState.busy = "확인 중… (몇 초 걸립니다)"
                withContext(Dispatchers.IO) {
                    Native.keyAddReauth(flow, a.credId, a.authData, a.first, a.second, a.transport)
                }
            } finally {
                a.wipe()
            }
            AppState.busy = null
            if (!Ask.yes(
                    "새 보안 키",
                    "확인했습니다. 이제 등록할 새 YubiKey를 준비하세요. USB-C로 꽂아 둔 키는 먼저 빼세요. 준비되면 [등록]을 누르세요.",
                    "등록",
                )
            ) {
                return@flow
            }
            register(flow, "새 보안 키 등록", newPin.copyOf())
            AppState.busy = "저장 중… (몇 초 걸립니다)"
            val f = flow
            flow = 0L
            val r = withContext(Dispatchers.IO) { Native.keyAddFinish(f) }
            AppState.busy = null
            AppState.message = r[0]
            if (r[1] == "1") {
                lockNow(r[0])
                return@flow
            }
            AppState.reload()
            Sync.afterSave(this)
            offerBackup("새 열쇠 파일을 지금 백업할까요?")
        } finally {
            password.fill(0)
            pin.fill('\u0000')
            newPin.fill('\u0000')
            if (flow != 0L) Native.flowClose(flow)
        }
    }

    // ---- gates and the server's key file ----

    /** The gate of a changed key file (gate-pending mode): a code (G1) or the lost keys (G2). */
    fun passGate(code: String?, picks: IntArray?) {
        val session = AppState.session
        AppState.work("확인 중…", { Native.gatePass(session, code, picks) }) {
            AppState.reload()
            AppState.message = "바뀐 열쇠 파일을 확인했습니다. 이제 항목을 고치고 저장할 수 있습니다."
            Sync.now(this)
        }
    }

    /**
     * Another device's key change, taken with this unlock's touch: the
     * gate's answer, the other device's new password when needed, the
     * preview, [받기].
     */
    fun takeChange(code: String?, picks: IntArray?) = flow {
        val session = AppState.session
        var other: ByteArray? = null
        try {
            var lines: List<String>
            while (true) {
                AppState.busy = "확인 중… (몇 초 걸립니다)"
                val r = withContext(Dispatchers.IO) { Native.takePreview(session, code, picks, other?.copyOf()) }
                AppState.busy = null
                if (r[0] == "needpass") {
                    val typed = Ask.ask(Question("새 비밀번호", r[1], "확인", "취소", field = "그 기기에서 바꾼 새 비밀번호"))
                        ?: return@flow
                    other?.fill(0)
                    other = utf8(java.nio.CharBuffer.wrap(typed))
                    typed.fill('\u0000')
                    continue
                }
                lines = r.drop(1)
                break
            }
            if (!Ask.yes("다른 기기의 열쇠 변경 받기", lines.joinToString("\n"), "받기")) return@flow
            AppState.busy = "받는 중… (몇 초 걸립니다)"
            val r = withContext(Dispatchers.IO) { Native.takeAccept(session) }
            AppState.busy = null
            val text = r.dropLast(1).joinToString("\n")
            if (r.last() == "1") {
                lockNow(text)
                return@flow
            }
            AppState.reload()
            AppState.message = text
            Sync.now(this)
        } finally {
            other?.fill(0)
        }
    }

    fun dropTake() {
        val session = AppState.session
        try {
            Native.takeDrop(session)
        } catch (e: GoyoException) {
            // Nothing waited.
        }
        AppState.reload()
        AppState.message = "받지 않았습니다. 다음에 금고를 열 때 다시 묻습니다. 그때까지 이 휴대폰은 올리지도 합치지도 않습니다."
    }

    /**
     * "서버에서 가져온 금고" step ③: the key file from the server, confirmed
     * with the other device's code (or none after the user's yes), saved
     * on the phone; sync starts.
     */
    fun saveFetched(code: String?, how: String) {
        val session = AppState.session
        val key = VaultFiles.key(this).path
        AppState.work("열쇠 파일 저장 중…", { Native.fetchedSave(session, code, key) }) {
            AppState.refreshHome(this)
            AppState.reload()
            AppState.message = "$how 열쇠 파일을 이 휴대폰에 저장했습니다. 이제 항목을 고치고 저장할 수 있고, 다음부터는 이 열쇠 파일로 엽니다. 동기화도 지금 시작했습니다."
            Sync.schedule(this)
            Sync.now(this)
        }
    }
}
