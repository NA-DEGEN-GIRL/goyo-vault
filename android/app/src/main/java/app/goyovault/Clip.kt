package app.goyovault

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies a secret marked sensitive (Android 13+ hides it from the copy
 * preview and keyboard suggestions; older versions ignore the mark) and
 * clears the clipboard `clearMs` later (30 seconds; an OTP code or secret
 * 15, as the PC app).
 */
object Clip {
    private const val CLEAR_MS = 30_000L
    const val OTP_CLEAR_MS = 15_000L
    private const val LABEL = "goyo-vault"
    private val handler = Handler(Looper.getMainLooper())
    private var pending: Runnable? = null

    fun copySecret(context: Context, text: String, clearMs: Long = CLEAR_MS) {
        val cm = context.getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(LABEL, text)
        val extras = PersistableBundle()
        val key = if (Build.VERSION.SDK_INT >= 33) {
            ClipDescription.EXTRA_IS_SENSITIVE
        } else {
            "android.content.extra.IS_SENSITIVE"
        }
        extras.putBoolean(key, true)
        clip.description.extras = extras
        cm.setPrimaryClip(clip)
        pending?.let { handler.removeCallbacks(it) }
        val app = context.applicationContext
        val clear = Runnable { clear(app) }
        pending = clear
        handler.postDelayed(clear, clearMs)
    }

    /**
     * Clears the clipboard if it still holds this app's copy. In the
     * background Android 10+ does not let the app read the clipboard, so
     * there it is cleared without the check (a newer copy of another app
     * before the clear is cleared too).
     */
    private fun clear(context: Context) {
        pending = null
        val cm = context.getSystemService(ClipboardManager::class.java) ?: return
        val current = try {
            cm.primaryClipDescription
        } catch (e: SecurityException) {
            null
        }
        if (current == null || current.label == LABEL) {
            cm.clearPrimaryClip()
        }
    }
}
