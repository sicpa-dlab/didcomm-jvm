package org.didcommx.didcomm.secret

import org.didcommx.secret.generateEd25519Keys
import org.didcommx.secret.jwkToSecret
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SecretResolverDemoTest {

    fun createSecret() = jwkToSecret(generateEd25519Keys().private)

    @Test
    fun testAddGetKeys(@TempDir secretsFolder: Path) {
        val secret1 = createSecret()
        val secret2 = createSecret()
        val secretsResolver = SecretResolverDemo(secretsFolder.resolve("secrets.json").toString())

        secretsResolver.addKey(secret1)
        secretsResolver.addKey(secret2)

        assertEquals(secret1, secretsResolver.findKey(secret1.kid).get())
        assertEquals(secret2, secretsResolver.findKey(secret2.kid).get())
        assertTrue(secretsResolver.findKey("unknown-kid").isEmpty)

        assertEquals(listOf(secret1.kid, secret2.kid), secretsResolver.getKids())

        assertEquals(setOf(secret1.kid), secretsResolver.findKeys(listOf(secret1.kid)))
        assertEquals(setOf(secret2.kid), secretsResolver.findKeys(listOf(secret2.kid)))
        assertEquals(setOf(secret1.kid, secret2.kid), secretsResolver.findKeys(listOf(secret1.kid, secret2.kid)))
        assertEquals(setOf(), secretsResolver.findKeys(listOf("unknown-kid")))
    }

    @Test
    fun testLoadPreservesKeys(@TempDir secretsFolder: Path) {
        val secret1 = createSecret()
        val secret2 = createSecret()
        var secretsResolver = SecretResolverDemo(secretsFolder.resolve("secrets.json").toString())

        secretsResolver.addKey(secret1)
        secretsResolver.addKey(secret2)

        secretsResolver = SecretResolverDemo(secretsFolder.resolve("secrets.json").toString())

        assertEquals(secret1, secretsResolver.findKey(secret1.kid).get())
        assertEquals(secret2, secretsResolver.findKey(secret2.kid).get())
        assertTrue(secretsResolver.findKey("unknown-kid").isEmpty)

        assertEquals(listOf(secret1.kid, secret2.kid), secretsResolver.getKids())

        assertEquals(setOf(secret1.kid), secretsResolver.findKeys(listOf(secret1.kid)))
        assertEquals(setOf(secret2.kid), secretsResolver.findKeys(listOf(secret2.kid)))
        assertEquals(setOf(secret1.kid, secret2.kid), secretsResolver.findKeys(listOf(secret1.kid, secret2.kid)))
        assertEquals(setOf(), secretsResolver.findKeys(listOf("unknown-kid")))
    }
}