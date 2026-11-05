package app.goyovault

import android.graphics.Bitmap
import android.graphics.Color
import android.os.SystemClock
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

/** The QR panel hides itself after this long, as on the PC. */
private const val QR_SHOWN_MS = 60_000L

/** "123456" as "123 456", as the PC app shows a code. */
private fun grouped(code: String): String {
    val half = code.length / 2
    return if (half == 0) code else code.substring(0, half) + " " + code.substring(half)
}

/**
 * The QR modules of [Native.otpQr] as a bitmap, one pixel per module with
 * a four-module quiet zone (drawn scaled without filtering). Mutable, so
 * that [hide] can wipe its pixels.
 */
private fun qrBitmap(m: ByteArray): Bitmap {
    val n = ((m[0].toInt() and 0xff) shl 8) or (m[1].toInt() and 0xff)
    require(n > 0 && m.size == 2 + n * n)
    val side = n + 8
    val px = IntArray(side * side) { Color.WHITE }
    for (y in 0 until n) {
        for (x in 0 until n) {
            if (m[2 + y * n + x].toInt() != 0) px[(y + 4) * side + x + 4] = Color.BLACK
        }
    }
    val bmp = Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888)
    bmp.setPixels(px, 0, side, 0, 0, side, side)
    px.fill(0)
    return bmp
}

/** Wipes a QR bitmap's pixels before it is dropped. */
private fun hide(bmp: Bitmap?) {
    if (bmp != null && !bmp.isRecycled) bmp.eraseColor(Color.WHITE)
}

/**
 * An entry's OTP in the entry view (without one nothing, or [missing] for an
 * OTP entry, which shows nothing else): the code of the
 * moment and its seconds, made in Rust each second; [복사] (sensitive,
 * cleared after 15 seconds); [QR 보기] (hidden after 60 seconds, on leaving
 * the entry, on a lock or when the app goes to the background, which
 * locks); [시크릿 복사] after a yes. FLAG_SECURE keeps all of it out of
 * screenshots.
 */
@Composable
fun OtpSection(index: Int, missing: String? = null) {
    val context = LocalContext.current
    val session = AppState.session
    val info = remember(index) {
        try {
            Native.otpInfo(session, index)
        } catch (e: GoyoException) {
            AppState.message = e.message
            null
        }
    }
    if (info == null) {
        if (missing != null) Text(missing)
        return
    }
    var code by remember(index) { mutableStateOf("") }
    var left by remember(index) { mutableIntStateOf(0) }
    var qr by remember(index) { mutableStateOf<Bitmap?>(null) }
    var qrLeft by remember(index) { mutableIntStateOf(0) }
    var confirmSecret by remember(index) { mutableStateOf(false) }
    fun hideQr() {
        hide(qr)
        qr = null
    }
    LaunchedEffect(index) {
        while (true) {
            try {
                val r = Native.otpCode(session, index)
                code = grouped(r[0])
                left = r[1].toInt()
            } catch (e: GoyoException) {
                AppState.message = e.message
                code = ""
                break
            }
            delay(1000 - System.currentTimeMillis() % 1000)
        }
    }
    val shown = qr
    LaunchedEffect(shown) {
        if (shown == null) return@LaunchedEffect
        val until = SystemClock.elapsedRealtime() + QR_SHOWN_MS
        while (true) {
            val rest = until - SystemClock.elapsedRealtime()
            if (rest <= 0) break
            qrLeft = ((rest + 999) / 1000).toInt()
            delay(minOf(rest, 250L))
        }
        hideQr()
    }
    // Leaving the entry (another screen, a lock, the background) takes it away.
    DisposableEffect(index) { onDispose { hideQr() } }

    HorizontalDivider()
    val names = listOf(info[0], info[1]).filter { it.isNotEmpty() }.joinToString(" · ")
    Text(if (names.isEmpty()) "OTP" else "OTP · $names", style = MaterialTheme.typography.labelLarge)
    if (info[2].isNotEmpty()) Text(info[2], style = MaterialTheme.typography.bodySmall)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            code,
            style = MaterialTheme.typography.headlineMedium,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(1f),
        )
        if (code.isNotEmpty()) Text("${left}초 뒤 바뀜", style = MaterialTheme.typography.bodySmall)
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = {
            try {
                val r = Native.otpCode(session, index)
                Clip.copySecret(context, r[0], Clip.OTP_CLEAR_MS)
                AppState.message = "OTP 코드를 복사했습니다 · 15초 뒤 클립보드에서 지웁니다."
            } catch (e: GoyoException) {
                AppState.message = e.message
            }
        }) { Text("복사") }
        OutlinedButton(onClick = {
            if (qr != null) {
                hideQr()
                return@OutlinedButton
            }
            try {
                val m = Native.otpQr(session, index)
                try {
                    qr = qrBitmap(m)
                } finally {
                    m.fill(0)
                }
            } catch (e: GoyoException) {
                AppState.message = e.message
            }
        }) { Text(if (qr != null) "QR 숨기기" else "QR 보기") }
        TextButton(onClick = { confirmSecret = true }) { Text("시크릿 복사") }
    }
    if (shown != null) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                "QR 코드 · 다른 기기의 인증 앱으로 스캔하세요 · ${qrLeft}초 뒤 숨김",
                style = MaterialTheme.typography.bodySmall,
            )
            Image(
                bitmap = shown.asImageBitmap(),
                contentDescription = "OTP QR 코드",
                filterQuality = FilterQuality.None,
                modifier = Modifier.fillMaxWidth().aspectRatio(1f),
            )
        }
    }
    if (confirmSecret) {
        AlertDialog(
            onDismissRequest = { confirmSecret = false },
            properties = secureDialog,
            title = { Text("OTP 시크릿 복사") },
            text = {
                Text(
                    "OTP 시크릿을 클립보드에 복사합니다. 클립보드를 읽는 다른 앱이 볼 수 있으니 " +
                        "인증 앱에 바로 붙여넣으세요. 15초 뒤 클립보드에서 지웁니다.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmSecret = false
                    try {
                        val bytes = Native.otpSecret(session, index)
                        try {
                            Clip.copySecret(context, String(bytes, Charsets.UTF_8), Clip.OTP_CLEAR_MS)
                        } finally {
                            bytes.fill(0)
                        }
                        AppState.message = "OTP 시크릿을 복사했습니다 · 15초 뒤 클립보드에서 지웁니다."
                    } catch (e: GoyoException) {
                        AppState.message = e.message
                    }
                }) { Text("복사") }
            },
            dismissButton = { TextButton(onClick = { confirmSecret = false }) { Text("취소") } },
        )
    }
}
