package app.goyovault

import android.app.Activity
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.ctap.Ctap2Session
import kotlinx.coroutines.CompletableDeferred
import java.io.IOException
import kotlin.concurrent.thread

/**
 * Waits for a YubiKey over USB-C or NFC and runs one ceremony ([op]: an
 * unlock's or Reauth's assertion, or a registration) on the first one that
 * comes. A key pulled away mid-ceremony (NFC) is waited for again; a wrong
 * PIN, an unregistered key or a cancel ends the wait.
 */
class KeyWait<T>(
    private val manager: YubiKitManager,
    private val pin: CharArray?,
    private val note: (String) -> Unit,
    private val op: (Ctap2Session, Int, CommandState, CharArray?) -> T,
    /** Wipes a result nobody took (a second answer after the first). */
    private val discard: (T) -> Unit = {},
) {
    val result = CompletableDeferred<T>()
    private val state = CommandState()
    @Volatile
    private var running = false
    /** Whether NFC could be turned on; false: USB-C only. */
    var nfc = false
        private set

    fun start(activity: Activity) {
        manager.startUsbDiscovery(UsbConfiguration()) { device -> onDevice(device, Ceremony.USB) }
        startNfc(activity)
    }

    /** NFC reader mode ends whenever the activity pauses; resume turns it on again. */
    fun startNfc(activity: Activity) {
        if (result.isCompleted) return
        nfc = try {
            manager.startNfcDiscovery(
                NfcConfiguration().handleUnavailableNfc(false),
                activity,
            ) { device -> onDevice(device, Ceremony.NFC) }
            true
        } catch (e: NfcNotAvailable) {
            false
        }
    }

    fun stop(activity: Activity) {
        manager.stopUsbDiscovery()
        manager.stopNfcDiscovery(activity)
        state.cancel()
        if (!result.isCompleted) result.completeExceptionally(GoyoException("보안 키 확인을 취소했습니다."))
        pin?.fill('\u0000')
    }

    private fun onDevice(device: YubiKeyDevice, transport: Int) {
        if (result.isCompleted || running) return
        running = true
        thread(name = "goyo-yubikey") {
            try {
                val answer = if (transport == Ceremony.USB) {
                    device.openConnection(FidoConnection::class.java).use {
                        op(Ctap2Session(it), transport, state, pin)
                    }
                } else {
                    device.openConnection(SmartCardConnection::class.java).use {
                        op(Ctap2Session(it), transport, state, pin)
                    }
                }
                if (!result.complete(answer)) discard(answer)
            } catch (e: CtapException) {
                result.completeExceptionally(GoyoException(Ceremony.text(e)))
            } catch (e: GoyoException) {
                result.completeExceptionally(e)
            } catch (e: IOException) {
                // The tag left the field or the key was pulled: wait again.
                note("연결이 끊겼습니다. YubiKey를 다시 대거나 꽂으세요.")
            } catch (e: Exception) {
                result.completeExceptionally(GoyoException("보안 키 작업 실패: ${e.javaClass.simpleName}"))
            } finally {
                running = false
            }
        }
    }
}
