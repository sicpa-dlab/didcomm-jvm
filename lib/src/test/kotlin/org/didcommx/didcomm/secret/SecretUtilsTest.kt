package org.didcommx.didcomm.secret

import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.secret.generateEd25519Keys
import org.didcommx.secret.generateX25519Keys
import org.didcommx.secret.jwkToSecret
import org.didcommx.secret.secretToJwk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SecretUtilsTest {

    @Test
    fun testGenerateKeysEd25519() {
        val keys = generateEd25519Keys()
        assertEquals("Ed25519", keys.private["crv"])
        assertEquals("Ed25519", keys.public["crv"])
        assertEquals("OKP", keys.private["kty"])
        assertEquals("OKP", keys.public["kty"])
        assertTrue(keys.private.contains("x"))
        assertTrue(keys.private.contains("d"))
        assertTrue(keys.public.contains("x"))
        assertFalse(keys.public.contains("d"))
    }

    @Test
    fun testGenerateKeysX25519() {
        val keys = generateX25519Keys()
        assertEquals("X25519", keys.private["crv"])
        assertEquals("X25519", keys.public["crv"])
        assertEquals("OKP", keys.private["kty"])
        assertEquals("OKP", keys.public["kty"])
        assertTrue(keys.private.contains("x"))
        assertTrue(keys.private.contains("d"))
        assertTrue(keys.public.contains("x"))
        assertFalse(keys.public.contains("d"))
    }

    @Test
    fun testJwkToSecret() {
        val keys = generateEd25519Keys()
        val secret = jwkToSecret(keys.private)
        assertEquals(VerificationMethodType.JSON_WEB_KEY_2020, secret.type)
        assertEquals(keys.private["kid"], secret.kid)
        assertEquals(VerificationMaterialFormat.JWK, secret.verificationMaterial.format)
    }

    @Test
    fun testSecretToJwk() {
        val keys = generateEd25519Keys()
        val secret = jwkToSecret(keys.private)
        val jwk = secretToJwk(secret)
        assertEquals(keys.private, jwk)
    }
}