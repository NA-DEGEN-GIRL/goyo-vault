package app.goyovault

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The bridge and the lib on the phone, in the app's own sandbox and
 * SELinux domain: a password-only TEST vault written on the PC by
 * `cargo run --release --example make_test_vault` (android/rust) opens,
 * reads, edits, saves and opens again. No YubiKey is needed; the
 * security-key path is tested by hand (docs/ANDROID.md).
 */
@RunWith(AndroidJUnit4::class)
class VaultTest {
    private val password = "android stage one test password"

    private fun copyFixture(): Pair<File, File>? {
        val instr = InstrumentationRegistry.getInstrumentation()
        val assets = instr.context.assets
        if (assets.list("")?.contains("vault.goyo") != true) return null
        val dir = File(instr.targetContext.filesDir, "vault-test")
        dir.deleteRecursively()
        dir.mkdirs()
        for (name in listOf("vault.goyo", "vault.goyokey")) {
            assets.open(name).use { input -> File(dir, name).outputStream().use { input.copyTo(it) } }
        }
        return File(dir, "vault.goyo") to File(dir, "vault.goyokey")
    }

    private fun text(session: Long, i: Int, which: Int): String {
        val b = Native.field(session, i, which)
        return String(b, Charsets.UTF_8).also { b.fill(0) }
    }

    @Test
    fun selfTestPasses() {
        Native.selfTest()
    }

    @Test
    fun aTestVaultOpensEditsAndOpensAgain() {
        val (vault, key) = copyFixture()
            ?: return assumeTrue("no test vault (run make_test_vault first)", false)
        assertTrue(Native.vaultTag(vault.path) != null)

        // A wrong password: the core's refusal, and the pending login is gone.
        var pending = Native.prepare(vault.path, key.path)
        assertNull(Native.request(pending))
        try {
            Native.unlock(pending, "wrong password!!".toByteArray(), null, null, null, null, 0)
            fail("a wrong password opened the vault")
        } catch (e: GoyoException) {
            assertTrue(e.message!!.isNotEmpty())
        }
        try {
            Native.request(pending)
            fail("a used pending login answered")
        } catch (e: GoyoException) {
        }

        pending = Native.prepare(vault.path, key.path)
        val pw = password.toByteArray()
        val session = Native.unlock(pending, pw, null, null, null, null, 0)
        // The bridge zeroed the password array.
        assertArrayEquals(ByteArray(pw.size), pw)
        val titles = Native.titles(session)
        assertEquals(listOf("테스트 항목 1", "웹", "Test entry 2", ""), titles.toList())
        assertEquals("synthetic-secret-1", text(session, 0, 2))
        assertEquals("메모 1", text(session, 0, 3))

        // A password-only vault with no trace of security keys needs no TOFU.
        assertEquals(0, Native.status(session))
        val fields = listOf("Added on Android", "모바일", "synthetic-secret-3", "").map { it.toByteArray() }
        Native.put(session, -1, fields[0], fields[1], fields[2], fields[3])
        fields.forEach { assertArrayEquals(ByteArray(it.size), it) }
        Native.delete(session, 1)
        Native.close(session)
        try {
            Native.titles(session)
            fail("a locked session answered")
        } catch (e: GoyoException) {
        }

        // Saved through the Unix publish (rename(2), fsync), it opens again.
        pending = Native.prepare(vault.path, key.path)
        val again = Native.unlock(pending, password.toByteArray(), null, null, null, null, 0)
        val after = Native.titles(again).toList()
        assertEquals(listOf("테스트 항목 1", "웹", "Added on Android", "모바일"), after)
        assertEquals("synthetic-secret-3", text(again, 1, 2))
        Native.closeAll()
    }

    @Test
    fun aRequestForAKeyFileWithSecurityKeysIsWellFormed() {
        // AssertRequest.parse on a request built like encode_request.
        val id = byteArrayOf(1, 2, 3)
        val bytes = byteArrayOf(1, 1, 3) + "a.b".toByteArray() + ByteArray(32) { 7 } +
            byteArrayOf(1, 0, 3) + id + ByteArray(32) { 9 } + byteArrayOf(0)
        val r = AssertRequest.parse(bytes)
        assertEquals("a.b", r.rpId)
        assertTrue(r.uvRequired)
        assertEquals(1, r.allow.size)
        assertArrayEquals(id, r.allow[0].credId)
        assertNull(r.allow[0].salt2)
    }
}
