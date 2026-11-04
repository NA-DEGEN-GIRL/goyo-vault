package app.goyovault

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** One vault on the server, as LIST shows it (and GETKEY for the first few). */
data class ServerVault(
    val id: String,
    val tag: String,
    val head: Long,
    val size: Long,
    val mtime: Long,
    /** held, missing, notallowed, unknown. */
    val key: String,
) {
    fun keyText(): String = when (key) {
        "held" -> "열쇠: 서버에 있음"
        "missing" -> "열쇠: 서버에 없음 (PC에서 파일로)"
        "notallowed" -> "열쇠: 이 휴대폰 줄에 허용 안 됨"
        else -> "열쇠: 알 수 없음"
    }

    fun sizeText(): String = if (size >= 1024) "%.1f KB".format(size / 1024.0) else "${size}바이트"

    companion object {
        fun parse(line: String): ServerVault? {
            val f = line.split('|')
            if (f.size != 6) return null
            return ServerVault(f[0], f[1], f[2].toLongOrNull() ?: 0, f[3].toLongOrNull() ?: 0, f[4].toLongOrNull() ?: 0, f[5])
        }
    }
}

/**
 * "서버에서 가져오기" (the phone's "이 PC로 가져오기"): the server's vaults
 * and the fetch of one, over the sync settings, key and pinned host key
 * (only over Tailscale, as every sync exchange). The checks are Rust's.
 */
object Server {
    private suspend fun <T> withSeed(context: Context, block: (String, ByteArray?) -> T): T =
        withContext(Dispatchers.IO) {
            val app = context.applicationContext
            if (!Sync.vpnUp(app)) {
                throw GoyoException("Tailscale(VPN)이 켜져 있지 않습니다. 휴대폰에서 Tailscale을 켜세요. 서버와는 Tailscale로만 연결합니다.")
            }
            if (!SyncKey.present(app)) throw GoyoException("이 휴대폰의 동기화 키가 없습니다. 먼저 키를 만드세요.")
            val seed = SyncKey.unwrap(app)
            try {
                block(Sync.root(app), seed)
            } finally {
                seed?.fill(0)
            }
        }

    suspend fun list(context: Context): List<ServerVault> = withSeed(context) { root, seed ->
        Native.serverList(root, seed).mapNotNull(ServerVault::parse)
    }

    /** Version, size, key result (written, nokeys, empty, bad, write, failed). */
    suspend fun fetch(context: Context, id: String): Array<String> = withSeed(context) { root, seed ->
        Native.serverFetch(root, seed, id)
    }

    suspend fun fetchKey(context: Context): String = withSeed(context) { root, seed ->
        Native.serverFetchKey(root, seed)
    }

    /** What came of the server's key file, for the message after a fetch. */
    fun keyText(word: String): String = when (word) {
        "written" -> "서버의 열쇠 파일도 함께 받았습니다(아직 확인 전)."
        "nokeys" -> "이 휴대폰의 서버 줄이 이 금고의 열쇠 파일 요청을 허용하지 않아 서버에 열쇠 파일이 있는지 알 수 없습니다. " +
            "PC의 goyo-sync에서 'Android 기기 추가…'를 다시 하면(그 PC의 목록에 이 금고가 있어야 함) 줄에 들어갑니다. 그 뒤 '서버에서 열쇠 파일 받기'를 누르세요. 아니면 열쇠 파일을 PC에서 파일로 가져오세요."
        "empty" -> "서버에 이 금고의 열쇠 파일이 없습니다(열쇠 파일 동기화를 쓰지 않는 금고). 열쇠 파일은 PC에서 파일로 가져와야 합니다(USB 케이블로 옮긴 뒤 '열쇠 파일 가져오기')."
        "bad" -> "서버의 열쇠 파일이 이 금고의 것이 아니거나 손상되어 받지 않았습니다. 열쇠 파일은 PC에서 파일로 가져오세요."
        "write" -> "서버의 열쇠 파일을 이 휴대폰에 저장하지 못했습니다."
        else -> "서버의 열쇠 파일을 받지 못했습니다(연결 문제). '서버에서 열쇠 파일 받기'로 다시 하거나 PC에서 파일로 가져오세요."
    }
}
