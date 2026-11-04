package app.goyovault

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The phone's sync key: an ed25519 key made on the phone, whose 32-byte
 * private seed is stored only wrapped with an Android Keystore AES-256-GCM
 * key (StrongBox when the phone has one, else the TEE). The Keystore key
 * never leaves the Keystore and needs no user authentication, so the
 * background worker can sync with the screen locked; the seed is never
 * exported, shown or backed up (backups are off). It is unwrapped for one
 * run at a time and handed to Rust, which copies it into zeroized memory
 * and zeroes the Java array; this side zeroes its own copies.
 *
 * Files in `<files>/sync`: `client_key.enc` (`GSK1`, the 12-byte IV, the
 * ciphertext and tag; the AAD names the format) and `client_key.pub` (the
 * public key's base64, for the server line).
 */
object SyncKey {
    const val ALIAS = "goyo-sync-ssh-key-wrap"
    private const val MAGIC = "GSK1"
    private val AAD = "goyo-sync ssh ed25519 seed v1".toByteArray(Charsets.US_ASCII)
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    fun dir(context: Context): File = File(context.filesDir, "sync")
    private fun wrappedFile(context: Context) = File(dir(context), "client_key.enc")
    private fun publicFile(context: Context) = File(dir(context), "client_key.pub")

    fun present(context: Context): Boolean = wrappedFile(context).isFile && publicFile(context).isFile

    /** The public key's base64 (what follows `ssh-ed25519`), or null. */
    fun publicBlob(context: Context): String? =
        try {
            publicFile(context).readText(Charsets.US_ASCII).trim().takeIf { it.isNotEmpty() }
        } catch (e: IOException) {
            null
        }

    /** Whether the wrapping key lives in StrongBox (for the settings screen). */
    var strongBox: Boolean? = null
        private set

    /**
     * Makes a new key pair (replacing any old one): the seed comes from the
     * Rust lib's RNG, is wrapped and written, then zeroed. Returns the
     * public key's base64.
     */
    @Throws(IOException::class)
    fun create(context: Context): String {
        val dir = dir(context)
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("folder")
        val seed = Native.syncNewSeed()
        try {
            val wrapped = wrap(seed)
            writeAtomically(wrappedFile(context), wrapped)
            // syncPublic zeroes the array it gets: give it a copy.
            val blob = Native.syncPublic(seed.copyOf())
            writeAtomically(publicFile(context), blob.toByteArray(Charsets.US_ASCII))
            return blob
        } finally {
            seed.fill(0)
        }
    }

    /** The seed for one run, or null without a key; the caller hands it to Rust (which zeroes it). */
    fun unwrap(context: Context): ByteArray? {
        val file = wrappedFile(context)
        if (!file.isFile) return null
        return try {
            unwrapBytes(file.readBytes())
        } catch (e: Exception) {
            null
        }
    }

    /** Removes the key pair and the wrapping key. */
    fun delete(context: Context) {
        wrappedFile(context).delete()
        publicFile(context).delete()
        try {
            keyStore().deleteEntry(ALIAS)
        } catch (e: Exception) {
            // Nothing to delete.
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun spec(strong: Boolean): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(strong)
            .build()

    /** The wrapping key, made on first use: StrongBox if the phone has one. */
    private fun secretKey(): SecretKey {
        val ks = keyStore()
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            gen.init(spec(true))
            gen.generateKey().also { strongBox = true }
        } catch (e: StrongBoxUnavailableException) {
            gen.init(spec(false))
            gen.generateKey().also { strongBox = false }
        } catch (e: java.security.ProviderException) {
            // Some phones report StrongBox trouble this way.
            gen.init(spec(false))
            gen.generateKey().also { strongBox = false }
        }
    }

    /** `GSK1` | IV | AES-GCM(seed) with the format's AAD. */
    fun wrap(seed: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        cipher.updateAAD(AAD)
        val ct = cipher.doFinal(seed)
        val iv = cipher.iv
        require(iv.size == IV_LEN)
        return MAGIC.toByteArray(Charsets.US_ASCII) + iv + ct
    }

    fun unwrapBytes(blob: ByteArray): ByteArray {
        val magic = MAGIC.toByteArray(Charsets.US_ASCII)
        require(blob.size == magic.size + IV_LEN + 32 + TAG_BITS / 8)
        require(blob.copyOfRange(0, magic.size).contentEquals(magic))
        val iv = blob.copyOfRange(magic.size, magic.size + IV_LEN)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = keyStore().getKey(ALIAS, null) as SecretKey
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(AAD)
        return cipher.doFinal(blob, magic.size + IV_LEN, blob.size - magic.size - IV_LEN)
    }

    private fun writeAtomically(file: File, bytes: ByteArray) {
        val temp = File(file.parentFile, file.name + ".tmp")
        temp.delete()
        java.io.FileOutputStream(temp).use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        if (!temp.renameTo(file)) {
            temp.delete()
            throw IOException("rename")
        }
    }
}
