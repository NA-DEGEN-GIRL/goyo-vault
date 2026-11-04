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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private lateinit var yubikit: YubiKitManager
    private var keyWait: KeyWait? = null
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no screen recording, no preview in the recent apps.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // No autofill service (a password manager) sees, fills or offers to
        // save the vault password, the PIN or a secret.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        yubikit = YubiKitManager(this)
        AppState.refreshTag(this)
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
        AppState.lock(why)
    }

    fun startImport() {
        if (AppState.session != 0L) lockNow(null)
        AppState.message = "먼저 금고 파일(.goyo)을 고르세요."
        pickVault.launch(arrayOf("*/*"))
    }

    private fun importFiles(vault: Uri, key: Uri) {
        AppState.work("가져오는 중…", {
            VaultFiles.import(this, vault, key)
            // Another vault at the same path: its sync starts afresh, as
            // deleting `vault.goyo.sync` on a PC resets it.
            Native.syncReset(Sync.root(this))
            Native.vaultTag(VaultFiles.vault(this).path)
                ?: run {
                    VaultFiles.remove(this)
                    throw GoyoException("고른 금고 파일이 고요 금고 파일이 아닙니다.")
                }
        }) { tag ->
            AppState.tag = tag
            AppState.message = "금고 $tag 를 가져왔습니다."
        }
    }

    fun removeImported() {
        lockNow(null)
        Native.syncReset(Sync.root(this))
        VaultFiles.remove(this)
        AppState.refreshTag(this)
        AppState.message = "가져온 금고 파일과 열쇠 파일을 이 기기에서 지웠습니다."
    }

    /** Whether the imported key file needs a security key (prepare, then drop). */
    fun checkNeedsKey(done: (Boolean) -> Unit) {
        val v = VaultFiles.vault(this).path
        val k = VaultFiles.key(this).path
        AppState.work("파일 확인 중…", {
            val pending = Native.prepare(v, k)
            try {
                Native.request(pending) != null
            } finally {
                Native.close(pending)
            }
        }, done)
    }

    /**
     * The unlock: phase 1, the YubiKey ceremony when the key file has
     * security keys, then phase 3 in Rust. `password` and `pin` are wiped
     * here whatever happens.
     */
    fun unlock(password: ByteArray, pin: CharArray?) {
        val v = VaultFiles.vault(this).path
        val k = VaultFiles.key(this).path
        val myLock = AppState.lockCount
        AppState.message = null
        AppState.busy = "파일 확인 중…"
        AppState.scope.launch {
            var pending = 0L
            var assertion: Assertion? = null
            try {
                pending = withContext(Dispatchers.IO) { Native.prepare(v, k) }
                val request = withContext(Dispatchers.IO) { Native.request(pending) }
                if (request != null) {
                    val req = AssertRequest.parse(request)
                    val wait = KeyWait(yubikit, req, pin?.copyOf()) { note ->
                        runOnUiThread { AppState.message = note }
                    }
                    keyWait = wait
                    wait.start(this@MainActivity)
                    AppState.busy = if (wait.nfc) {
                        "YubiKey를 대거나 꽂으세요"
                    } else {
                        "YubiKey를 꽂으세요 (NFC가 꺼져 있어 USB-C만 됩니다)"
                    }
                    assertion = try {
                        wait.result.await()
                    } finally {
                        wait.stop(this@MainActivity)
                        if (keyWait === wait) keyWait = null
                    }
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

    fun cancelKey() {
        keyWait?.stop(this)
    }
}
