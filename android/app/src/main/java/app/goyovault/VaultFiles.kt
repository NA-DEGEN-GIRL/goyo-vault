package app.goyovault

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.IOException

/**
 * The imported vault and key file, copied into the app's private storage
 * (no other app can read it; backups are off). Stage 1 keeps one vault.
 */
object VaultFiles {
    private const val DIR = "vault"
    const val VAULT = "vault.goyo"
    const val KEY = "vault.goyokey"
    /** Larger than any vault or key file the core accepts. */
    private const val MAX_BYTES = 64L * 1024 * 1024

    fun dir(context: Context): File = File(context.filesDir, DIR)
    fun vault(context: Context): File = File(dir(context), VAULT)
    fun key(context: Context): File = File(dir(context), KEY)
    fun present(context: Context): Boolean = vault(context).isFile && key(context).isFile

    /**
     * Copies the picked vault and key file in, each through a temp file
     * renamed into place, so a failed copy leaves no half file. The files
     * of a previous import are replaced. The caller has locked every
     * session first.
     */
    @Throws(IOException::class)
    fun import(context: Context, vaultUri: Uri, keyUri: Uri) {
        val dir = dir(context)
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("folder")
        val vaultTmp = copyIn(context, vaultUri, File(dir, "$VAULT.import"))
        val keyTmp = try {
            copyIn(context, keyUri, File(dir, "$KEY.import"))
        } catch (e: IOException) {
            vaultTmp.delete()
            throw e
        }
        if (!vaultTmp.renameTo(vault(context)) || !keyTmp.renameTo(key(context))) {
            vaultTmp.delete()
            keyTmp.delete()
            throw IOException("rename")
        }
    }

    /**
     * Copies the picked key file in for the vault already here (a vault
     * from the server whose key file comes from the PC). Never over a key
     * file that is there.
     */
    @Throws(IOException::class)
    fun importKey(context: Context, keyUri: Uri) {
        val dir = dir(context)
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("folder")
        if (key(context).exists()) throw IOException("exists")
        val temp = copyIn(context, keyUri, File(dir, "$KEY.import"))
        if (!temp.renameTo(key(context))) {
            temp.delete()
            throw IOException("rename")
        }
    }

    /** Copies `file` to the place the user picked (a key backup), then fsyncs it. */
    @Throws(IOException::class)
    fun copyOut(context: Context, file: File, uri: Uri) {
        val out = context.contentResolver.openOutputStream(uri, "wt") ?: throw IOException("open")
        out.use { dst ->
            file.inputStream().use { it.copyTo(dst) }
            (dst as? java.io.FileOutputStream)?.fd?.sync()
        }
    }

    /** The key backup's temporary copy (app-private, deleted once copied out). */
    fun backupTemp(context: Context): File = File(context.noBackupFilesDir, "key-backup.goyokey")

    private fun copyIn(context: Context, uri: Uri, temp: File): File {
        temp.delete()
        val input = context.contentResolver.openInputStream(uri) ?: throw IOException("open")
        input.use { src ->
            java.io.FileOutputStream(temp).use { out ->
                val buf = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val n = src.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > MAX_BYTES) {
                        out.close()
                        temp.delete()
                        throw IOException("too large")
                    }
                    out.write(buf, 0, n)
                }
                out.fd.sync()
            }
        }
        return temp
    }

    /**
     * Removes the vault and its key file (the anchor stays, as on a PC).
     * The caller removes the sync folder first (syncReset, in Rust, which
     * never follows a link).
     */
    fun remove(context: Context) {
        dir(context).listFiles()?.forEach { if (!it.isDirectory) it.delete() }
        backupTemp(context).delete()
    }
}
