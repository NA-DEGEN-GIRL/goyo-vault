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
        CtapException.ERR_CREDENTIAL_EXCLUDED -> "이 보안 키는 이미 이 금고에 등록되어 있습니다. 다른 키를 대세요."
        CtapException.ERR_KEY_STORE_FULL -> "이 보안 키에 등록할 자리가 다 찼을 수 있습니다. 쓰지 않는 등록(뺀 키, 실패한 등록, 쓰지 않는 웹사이트 패스키)을 키 제조사의 관리 도구로 지우거나 다른 키를 쓰세요."
        CtapException.ERR_PIN_POLICY_VIOLATION -> "이 PIN은 키가 받지 않습니다(보통 4자 이상, 키에 따라 더 길게)."
        CtapException.ERR_UNSUPPORTED_EXTENSION, CtapException.ERR_UNSUPPORTED_OPTION ->
            "이 보안 키는 고요 금고에 필요한 기능(hmac-secret, credProtect, 상주 자격 증명)을 지원하지 않습니다."
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

/**
 * A registration's MakeCredential request as the core states it (spec
 * §8.3, the lib's `fido::Registration`): fresh user ID, the
 * `goyo-<TAG>-<N>-<STAMP>` names, PIN required, credProtect 3 required,
 * a resident credential, and the credentials the key must not register
 * again.
 */
class MakeRequest(
    val rpId: String,
    val rpName: String,
    val userId: ByteArray,
    val name: String,
    val displayName: String,
    val clientDataHash: ByteArray,
    val uvRequired: Boolean,
    val credProtect: Int,
    val credProtectRequired: Boolean,
    val exclude: List<ByteArray>,
) {
    companion object {
        /** The wire format of the Rust bridge (reg::encode_make), version 1. */
        fun parse(bytes: ByteArray): MakeRequest {
            val b = ByteBuffer.wrap(bytes)
            fun take(n: Int) = ByteArray(n).also { b.get(it) }
            fun text() = String(take(b.get().toInt() and 0xff), Charsets.UTF_8)
            if (b.get().toInt() != 1) throw GoyoException("앱과 코어의 버전이 맞지 않습니다.")
            val rpId = text()
            val rpName = text()
            val userId = take(32)
            val name = text()
            val display = text()
            val hash = take(32)
            val uv = b.get().toInt() == 1
            val cp = b.get().toInt() and 0xff
            val cpRequired = b.get().toInt() == 1
            val count = b.get().toInt() and 0xff
            val exclude = List(count) { take(b.short.toInt() and 0xffff) }
            return MakeRequest(rpId, rpName, userId, name, display, hash, uv, cp, cpRequired, exclude)
        }
    }
}

/**
 * One registration on a connected YubiKey (spec §8.3): MakeCredential with
 * hmac-secret, credProtect 3 and a resident credential under the PIN (set
 * first with the typed PIN on a key that has none, as Windows makes the
 * user do), then, on the same connection, the core's check GetAssertion
 * ([Ceremony.run]). `made` hands the authenticator data to Rust, which
 * reads the credential ID out of it, holds the extensions to hmac-secret
 * and credProtect 3, runs the core's checks and states the check request.
 */
object Registrar {
    private val ALGORITHMS = listOf(-7, -8)

    fun run(
        ctap: Ctap2Session,
        make: MakeRequest,
        pin: CharArray?,
        transport: Int,
        state: CommandState,
        made: (authData: ByteArray) -> ByteArray,
    ): Assertion {
        val info = ctap.cachedInfo
        if (!info.extensions.contains("hmac-secret")) {
            throw GoyoException("이 보안 키는 hmac-secret(FIDO2 확장)을 지원하지 않습니다.")
        }
        if (make.credProtectRequired && !info.extensions.contains("credProtect")) {
            throw GoyoException("이 보안 키는 PIN 필수 보호(credProtect)를 지원하지 않습니다. 다른 키를 쓰세요.")
        }
        if (pin == null || pin.isEmpty()) throw GoyoException("YubiKey PIN을 입력하세요.")
        if (!ClientPin.isSupported(info)) throw GoyoException("이 보안 키는 PIN을 지원하지 않습니다.")
        val protocol: PinUvAuthProtocol =
            if (info.pinUvAuthProtocols.contains(2)) PinUvAuthProtocolV2() else PinUvAuthProtocolV1()
        val clientPin = ClientPin(ctap, protocol)
        // A key without a PIN gets the one typed (Windows asks for it in
        // its first window on a PC).
        if (info.options["clientPin"] != true) clientPin.setPin(pin)
        var token: ByteArray? = null
        try {
            token = clientPin.getPinToken(pin, ClientPin.PIN_PERMISSION_MC, make.rpId)
            val pinUvAuthParam = protocol.authenticate(token, make.clientDataHash)
            val rp = mapOf("id" to make.rpId, "name" to make.rpName)
            val user = mapOf("id" to make.userId, "name" to make.name, "displayName" to make.displayName)
            val params = ALGORITHMS.map { mapOf("type" to "public-key", "alg" to it) }
            val exclude = make.exclude.map { mapOf("type" to "public-key", "id" to it) }.ifEmpty { null }
            val extensions = mapOf("hmac-secret" to true, "credProtect" to make.credProtect)
            val credential = ctap.makeCredential(
                make.clientDataHash,
                rp,
                user,
                params,
                exclude,
                extensions,
                mapOf("rk" to true),
                pinUvAuthParam,
                protocol.version,
                null,
                state,
            )
            token.fill(0)
            token = null
            val check = AssertRequest.parse(made(credential.authenticatorData))
            return Ceremony.run(ctap, check, pin, transport, state)
        } finally {
            token?.fill(0)
        }
    }
}
