package app.goyovault

import android.app.Application
import android.util.Log

class GoyoApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // The anchor (this device's record of each vault's key file state)
        // lives in the app's private storage, like %LOCALAPPDATA% on a PC.
        try {
            Native.setAnchorRoot(filesDir.absolutePath)
            Native.selfTest()
            Log.i(TAG, "self test passed")
        } catch (e: GoyoException) {
            AppState.fatal = e.message
            Log.w(TAG, "self test failed: ${e.message}")
        } catch (e: UnsatisfiedLinkError) {
            AppState.fatal = "네이티브 라이브러리를 불러오지 못했습니다."
            Log.w(TAG, "native library missing")
        }
    }

    private companion object {
        /** Only start-up results are logged; never a field, path or secret. */
        const val TAG = "GoyoVault"
    }
}
