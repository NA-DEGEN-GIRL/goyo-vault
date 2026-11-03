package app.goyovault

import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.ctap.ClientPin
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
import com.yubico.yubikit.fido.webauthn.AuthenticatorData
import java.nio.ByteBuffer

/**
 * The unlock's security-key request as the core states it (spec §8.3): the
 * allow list, each credential with the salt(s) the key gets as they are
 * (hmac-secret, no PRF hashing on this side), the client data hash and
 * whether user verification (the PIN) is required.
 */
class AssertRequest(
    val rpId: String,
    val uvRequired: Boolean,
    val clientDataHash: ByteArray,
    val allow: List<Allowed>,
) {
    class Allowed(val credId: ByteArray, val salt1: ByteArray, val salt2: ByteArray?)

    companion object {
        /** The wire format of the Rust bridge (encode_request), version 1. */
        fun parse(bytes: ByteArray): AssertRequest {
            val b = ByteBuffer.wrap(bytes)
            fun take(n: Int) = ByteArray(n).also { b.get(it) }
            if (b.get().toInt() != 1) throw GoyoException("앱과 코어의 버전이 맞지 않습니다.")
            val uv = b.get().toInt() == 1
            val rpId = String(take(b.get().toInt() and 0xff), Charsets.US_ASCII)
            val hash = take(32)
            val count = b.get().toInt() and 0xff
            val allow = List(count) {
                val id = take(b.short.toInt() and 0xffff)
                val salt1 = take(32)
                val salt2 = if (b.get().toInt() == 1) take(32) else null
                Allowed(id, salt1, salt2)
            }
            return AssertRequest(rpId, uv, hash, allow)
        }
    }
}

/** What the key returned, handed to the core unchanged. */
class Assertion(
    val credId: ByteArray,
    val authData: ByteArray,
    val first: ByteArray,
    val second: ByteArray?,
    /** 1 USB, 2 NFC (the core's fido::USB and fido::NFC). */
    val transport: Int,
) {
    fun wipe() {
        first.fill(0)
        second?.fill(0)
    }
}

/**
 * One CTAP2 ceremony on a connected YubiKey: the PIN token (the PIN typed
 * in the app), a silent pre-flight (up=false) to find which allowed
 * credential this key holds (credProtect 3 credentials show only with UV),
 * then one GetAssertion for that credential with the hmac-secret extension
 * and that credential's raw salts. The outputs are decrypted with the
 * shared secret of this ceremony; nothing is checked here that the core
 * does not check again (fido::check_assertion).
 */
object Ceremony {
    const val USB = 1
    const val NFC = 2

    fun run(
        ctap: Ctap2Session,
        req: AssertRequest,
        pin: CharArray?,
        transport: Int,
        state: CommandState,
    ): Assertion {
        val info = ctap.cachedInfo
        if (!info.extensions.contains("hmac-secret")) {
            throw GoyoException("이 보안 키는 hmac-secret(FIDO2 확장)을 지원하지 않습니다.")
        }
        val protocol: PinUvAuthProtocol =
            if (info.pinUvAuthProtocols.contains(2)) PinUvAuthProtocolV2() else PinUvAuthProtocolV1()
        val clientPin = ClientPin(ctap, protocol)
        var token: ByteArray? = null
        var shared: ByteArray? = null
        try {
            if (req.uvRequired) {
                if (pin == null || pin.isEmpty()) throw GoyoException("YubiKey PIN을 입력하세요.")
                if (!ClientPin.isSupported(info)) throw GoyoException("이 보안 키에는 PIN이 설정되어 있지 않습니다.")
                token = clientPin.getPinToken(pin, ClientPin.PIN_PERMISSION_GA, req.rpId)
            }
            val selected = select(ctap, req, protocol, token)
                ?: throw GoyoException("이 YubiKey는 이 금고에 등록되어 있지 않습니다. 등록한 다른 키를 쓰세요.")

            // hmac-secret input (CTAP2 §12.5): keyAgreement, saltEnc, saltAuth.
            val agreement = clientPin.sharedSecret
            shared = agreement.second
            val salts = if (selected.salt2 != null) selected.salt1 + selected.salt2 else selected.salt1.copyOf()
            val saltEnc = protocol.encrypt(shared, salts)
            salts.fill(0)
            val saltAuth = protocol.authenticate(shared, saltEnc)
            val hmacInput = HashMap<Int, Any>()
            hmacInput[1] = agreement.first
            hmacInput[2] = saltEnc
            hmacInput[3] = saltAuth
            hmacInput[4] = protocol.version
            val extensions = mapOf("hmac-secret" to hmacInput)

            val pinUvAuthParam = token?.let { protocol.authenticate(it, req.clientDataHash) }
            val assertions = ctap.getAssertions(
                req.rpId,
                req.clientDataHash,
                listOf(descriptor(selected.credId)),
                extensions,
                null, // up stays true: the touch (USB) or the tap (NFC)
                pinUvAuthParam,
                if (token != null) protocol.version else null,
                state,
            )
            val a = assertions.firstOrNull() ?: throw GoyoException("보안 키 응답이 없습니다.")
            val credId = (a.credential?.get("id") as? ByteArray) ?: selected.credId
            val authData = a.authenticatorData
            val parsed = AuthenticatorData.parseFrom(ByteBuffer.wrap(authData))
            val encrypted = parsed.extensions?.get("hmac-secret") as? ByteArray
                ?: throw GoyoException("보안 키가 hmac-secret 값을 돌려주지 않았습니다.")
            val outputs = protocol.decrypt(shared, encrypted)
            try {
                if (outputs.size != 32 && outputs.size != 64) {
                    throw GoyoException("보안 키 응답이 올바르지 않습니다.")
                }
                val first = outputs.copyOfRange(0, 32)
                val second = if (outputs.size == 64) outputs.copyOfRange(32, 64) else null
                return Assertion(credId, authData, first, second, transport)
            } finally {
                outputs.fill(0)
            }
        } finally {
            token?.fill(0)
            shared?.fill(0)
        }
    }

    private fun descriptor(id: ByteArray): Map<String, Any> = mapOf("type" to "public-key", "id" to id)

    /**
     * The allowed credential this key holds: a pre-flight GetAssertion with
     * up=false per chunk of the allow list (what yubikit's own client does).
     * None when the key holds none of them.
     */
    private fun select(
        ctap: Ctap2Session,
        req: AssertRequest,
        protocol: PinUvAuthProtocol,
        token: ByteArray?,
    ): AssertRequest.Allowed? {
        val zeroHash = ByteArray(32)
        val pinAuth = token?.let { protocol.authenticate(it, zeroHash) }
        var max = ctap.cachedInfo.maxCredentialCountInList ?: 1
        var rest = req.allow
        while (rest.isNotEmpty()) {
            val chunk = rest.take(max)
            try {
                val found = ctap.getAssertions(
                    req.rpId,
                    zeroHash,
                    chunk.map { descriptor(it.credId) },
                    null,
                    mapOf("up" to false),
                    pinAuth,
                    if (token != null) protocol.version else null,
                    null,
                )
                if (chunk.size == 1) return chunk[0]
                val id = found.firstOrNull()?.credential?.get("id") as? ByteArray ?: return null
                return chunk.firstOrNull { it.credId.contentEquals(id) }
            } catch (e: CtapException) {
                when (e.ctapError) {
                    CtapException.ERR_NO_CREDENTIALS -> rest = rest.drop(chunk.size)
                    CtapException.ERR_REQUEST_TOO_LARGE -> {
                        max -= 1
                        if (max == 0) throw e
                    }
                    else -> throw e
                }
            }
        }
        return null
    }

    /** The text for a CTAP error of a ceremony. */
    fun text(e: CtapException): String = when (e.ctapError) {
        CtapException.ERR_PIN_INVALID -> "YubiKey PIN이 틀렸습니다. 여러 번 틀리면 키가 잠깁니다."
        CtapException.ERR_PIN_BLOCKED -> "YubiKey PIN이 잠겼습니다. 키를 초기화해야 합니다(이 금고의 등록도 지워집니다)."
        CtapException.ERR_PIN_AUTH_BLOCKED -> "PIN을 여러 번 틀렸습니다. 키를 뺐다가 다시 꽂거나 다시 댄 뒤 하세요."
        CtapException.ERR_PIN_NOT_SET -> "이 YubiKey에는 PIN이 설정되어 있지 않습니다."
        CtapException.ERR_NO_CREDENTIALS -> "이 YubiKey는 이 금고에 등록되어 있지 않습니다."
        CtapException.ERR_KEEPALIVE_CANCEL -> "보안 키 확인을 취소했습니다."
        CtapException.ERR_USER_ACTION_TIMEOUT, CtapException.ERR_ACTION_TIMEOUT ->
            "YubiKey 터치를 기다리다 시간이 지났습니다."
        CtapException.ERR_OPERATION_DENIED -> "YubiKey가 요청을 거부했습니다."
        else -> "보안 키 작업 실패 (CTAP 0x%02X).".format(e.ctapError.toInt() and 0xff)
    }
}
