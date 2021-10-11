package org.didcommx.didcomm.crypto.key

import com.nimbusds.jose.jwk.Curve
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.VerificationMethod
import org.didcommx.didcomm.secret.Secret
import kotlin.test.Test
import kotlin.test.assertEquals

class ExtractKeyTest {
    @Test
    fun `Test_extract_OKP_key_from_JsonWebKey2020_verification_method`() {
        val key = Key.fromVerificationMethod(
            VerificationMethod(
                id = "did:example:alice#key-x25519-1",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    format = VerificationMaterialFormat.JWK,
                    value = """
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
                        }
                    """.trimIndent(),
                ),
                controller = "did:example:alice#key-x25519-1",
            )
        )

        assertEquals("did:example:alice#key-x25519-1", key.id)
        assertEquals(Curve.X25519, key.curve)
        assertEquals(
            mapOf(
                "kty" to "OKP",
                "crv" to "X25519",
                "x" to "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
            ),
            key.jwk.toJSONObject(),
        )
    }

    @Test
    fun `Test_extract_EC_key_from_JsonWebKey2020_verification_method`() {
        val key = Key.fromVerificationMethod(
            VerificationMethod(
                id = "did:example:alice#key-p256-1",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    format = VerificationMaterialFormat.JWK,
                    value = """
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                            "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
                        }
                    """.trimIndent(),
                ),
                controller = "did:example:alice#key-p256-1",
            )
        )

        assertEquals("did:example:alice#key-p256-1", key.id)
        assertEquals(Curve.P_256, key.curve)
        assertEquals(
            mapOf(
                "kty" to "EC",
                "crv" to "P-256",
                "x" to "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                "y" to "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
            ),
            key.jwk.toJSONObject(),
        )
    }

    @Test
    fun `Test_extract_OKP_key_from_JsonWebKey2020_secret`() {
        val key = Key.fromSecret(
            Secret(
                kid = "did:example:alice#key-ed25519-2",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    format = VerificationMaterialFormat.JWK,
                    value = """
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                            "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY"
                        }
                    """.trimIndent(),
                ),
            )
        )

        assertEquals("did:example:alice#key-ed25519-2", key.id)
        assertEquals(Curve.Ed25519, key.curve)
        assertEquals(
            mapOf(
                "kty" to "OKP",
                "crv" to "Ed25519",
                "x" to "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                "d" to "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
            ),
            key.jwk.toJSONObject(),
        )
    }

    @Test
    fun `Test_extract_EC_key_from_JsonWebKey2020_secret`() {
        val key = Key.fromSecret(
            Secret(
                kid = "did:example:alice#key-p256-2",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    format = VerificationMaterialFormat.JWK,
                    value = """
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                            "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
                            "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A"
                        }
                    """.trimIndent(),
                ),
            )
        )

        assertEquals("did:example:alice#key-p256-2", key.id)
        assertEquals(Curve.P_256, key.curve)
        assertEquals(
            mapOf(
                "kty" to "EC",
                "crv" to "P-256",
                "x" to "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                "y" to "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
                "d" to "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
            ),
            key.jwk.toJSONObject(),
        )
    }

    @Test
    fun `Test_extract_key_from_X25519KeyAgreementKey2019_verification_method`() {
        val key = Key.fromVerificationMethod(
            VerificationMethod(
                id = "did:example:dave#key-x25519-1",
                type = VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019,
                verificationMaterial = VerificationMaterial(
                    format = VerificationMaterialFormat.BASE58,
                    value = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
                ),
                controller = "did:example:dave#key-x25519-1",
            )
        )

        assertEquals("did:example:dave#key-x25519-1", key.id)
        assertEquals(Curve.X25519, key.curve)
        assertEquals(
            mapOf(
                "kty" to "OKP",
                "crv" to "X25519",
                "x" to "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
            ),
            key.jwk.toJSONObject(),
        )
    }

    @Test
    fun `Test_extract_key_from_Ed25519VerificationKey2018_verification_method`() {
        val key = Key.fromVerificationMethod(
            VerificationMethod(
                id = "did:example:dave#key-ed25519-1",
                type = VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
                verificationMaterial = VerificationMaterial(
                    format = VerificationMaterialFormat.BASE58,
                    value = "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
                ),
                controller = "did:example:dave#key-ed25519-1",
            )
        )

        assertEquals("did:example:dave#key-ed25519-1", key.id)
        assertEquals(Curve.Ed25519, key.curve)
        assertEquals(
            mapOf(
                "kty" to "OKP",
                "crv" to "Ed25519",
                "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
            ),
            key.jwk.toJSONObject(),
        )
    }

    @Test
    fun `Test_extract_key_from_X25519KeyAgreementKey2020_verification_method`() {
        val key = Key.fromVerificationMethod(
            VerificationMethod(
                id = "did:example:dave#key-x25519-2",
                type = VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    format = VerificationMaterialFormat.MULTIBASE,
                    value = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
                ),
                controller = "did:example:dave#key-x25519-2",
            )
        )

        assertEquals("did:example:dave#key-x25519-2", key.id)
        assertEquals(Curve.X25519, key.curve)
        assertEquals(
            mapOf(
                "kty" to "OKP",
                "crv" to "X25519",
                "x" to "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
            ),
            key.jwk.toJSONObject(),
        )
    }

    @Test
    fun `Test_extract_key_from_Ed25519VerificationKey2020_verification_method`() {
        val key = Key.fromVerificationMethod(
            VerificationMethod(
                id = "did:example:dave#key-ed25519-2",
                type = VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    format = VerificationMaterialFormat.MULTIBASE,
                    value = "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
                ),
                controller = "did:example:dave#key-ed25519-2",
            )
        )

        assertEquals("did:example:dave#key-ed25519-2", key.id)
        assertEquals(Curve.Ed25519, key.curve)
        assertEquals(
            mapOf(
                "kty" to "OKP",
                "crv" to "Ed25519",
                "x" to "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
            ),
            key.jwk.toJSONObject(),
        )
    }
}
