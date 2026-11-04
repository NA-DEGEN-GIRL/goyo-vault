package app.goyovault

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom

/**
 * Sync on the phone itself (docs/ANDROID.md '동기화'): the Keystore-wrapped
 * client key round trip, and the bridge's sync entries in the app's own
 * sandbox. Nothing here reaches a server: every host is refused before a
 * connection (not a Tailscale address), which is itself the check.
 */
@RunWith(AndroidJUnit4::class)
class SyncTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** A private root for the bridge's sync files, apart from the app's own. */
    private fun root(): String {
        val dir = File(context.cacheDir, "sync-test")
        dir.deleteRecursively()
        dir.mkdirs()
        return dir.absolutePath
    }

    @Test
    fun theKeystoreWrapsAndUnwrapsASeed() {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val wrapped = SyncKey.wrap(seed)
        assertEquals(4 + 12 + 32 + 16, wrapped.size)
        assertArrayEquals(seed, SyncKey.unwrapBytes(wrapped))
        // A fresh IV each time: the same seed never wraps alike.
        assertFalse(wrapped.contentEquals(SyncKey.wrap(seed)))
        // Any changed byte (the IV, the ciphertext, the tag) is refused.
        for (at in listOf(4, 20, wrapped.size - 1)) {
            val bad = wrapped.copyOf()
            bad[at] = (bad[at].toInt() xor 1).toByte()
            try {
                SyncKey.unwrapBytes(bad)
                fail("byte $at changed and still unwrapped")
            } catch (e: Exception) {
                // expected
            }
        }
        // The Keystore key is not exportable.
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(SyncKey.ALIAS, null) as javax.crypto.SecretKey
        assertNull(key.encoded)
    }

    @Test
    fun aNewKeyIsStoredWrappedAndItsLineIsTheWindowsFormat() {
        SyncKey.delete(context)
        assertFalse(SyncKey.present(context))
        val blob = SyncKey.create(context)
        assertTrue(SyncKey.present(context))
        assertEquals(blob, SyncKey.publicBlob(context))
        assertEquals(68, blob.length)
        assertTrue(blob.startsWith("AAAAC3NzaC1lZDI1NTE5AAAAI"))
        // The file holds no plain seed: unwrapping gives 32 bytes whose
        // public key is the stored one.
        val seed = SyncKey.unwrap(context)
        assertNotNull(seed)
        assertEquals(32, seed!!.size)
        val stored = File(File(context.filesDir, "sync"), "client_key.enc").readBytes()
        assertFalse(String(stored, Charsets.ISO_8859_1).contains(String(seed, Charsets.ISO_8859_1)))
        val copy = seed.copyOf()
        assertEquals(blob, Native.syncPublic(copy))
        assertTrue("the bridge zeroes the array it got", copy.all { it == 0.toByte() })
        seed.fill(0)
        // The line: the default forced command, this key, the model.
        val line = Native.syncLine(root(), blob, "LM-G710N")
        assertEquals(
            "restrict,command=\"python3 -I .local/share/goyo-sync/goyo-sync-server.py serve\" " +
                "ssh-ed25519 $blob goyo-sync android-LM-G710N",
            line,
        )
        SyncKey.delete(context)
        assertFalse(SyncKey.present(context))
        assertNull(SyncKey.unwrap(context))
    }

    @Test
    fun settingsAreCheckedAndStored() {
        val root = root()
        assertNull(Native.syncSettingsLoad(root))
        try {
            Native.syncSettingsSave(root, "-oProxyCommand=x", "22", "me", "", "")
            fail("a host starting with - was taken")
        } catch (e: GoyoException) {
            assertTrue(e.message!!.contains("서버"))
        }
        Native.syncSettingsSave(root, "box.tail1234.ts.net", "", "me", "", "")
        val s = Native.syncSettingsLoad(root)!!
        assertEquals(listOf("box.tail1234.ts.net", "22", "me", ".local/share/goyo-sync/goyo-sync-server.py", "python3"), s.toList())
        assertNull(Native.syncPinned(root))
        val noVault = Native.syncRun(root, null, true)
        assertEquals("novault", noVault[0])
    }

    @Test
    fun aHostOffTailscaleIsRefusedBeforeAnyConnection() {
        val root = root()
        for (host in listOf("192.168.1.20", "10.0.0.1", "100.128.0.1", "8.8.8.8")) {
            Native.syncSettingsSave(root, host, "22", "me", "", "")
            val seed = ByteArray(32) { 7 }
            val r = Native.syncCheck(root, seed)
            assertEquals(host, "tailnet", r[0])
            assertTrue(r[1], r[1].contains("Tailscale"))
            assertTrue("the seed array is zeroed", seed.all { it == 0.toByte() })
        }
        // Without a key: refused as a missing key, before any lookup.
        Native.syncSettingsSave(root, "100.64.0.1", "22", "me", "", "")
        assertEquals("nokey", Native.syncCheck(root, null)[0])
    }
}
