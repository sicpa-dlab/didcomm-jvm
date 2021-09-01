package org.dif.mock

import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMaterialFormat
import org.dif.common.VerificationMethodType
import org.dif.secret.Secret
import org.dif.secret.SecretResolver
import org.dif.secret.SecretResolverInMemory
import java.util.Optional

class AliceSecretResolverMock : SecretResolver {
    private val secretResolver = SecretResolverInMemory(
        listOf(
            Secret(
                kid = "did:example:alice#key-1",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    """
                        {
                           "kty":"OKP",
                           "d":"pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                           "crv":"Ed25519",
                           "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                        }
                    """.trimIndent()
                )
            ),

            Secret(
                kid = "did:example:alice#key-2",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    """
                        {
                           "kty":"EC",
                           "d":"7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
                           "crv":"P-256",
                           "x":"2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                           "y":"BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
                        }
                    """.trimIndent()
                )
            ),

            Secret(
                kid = "did:example:alice#key-3",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    """
                        {
                           "kty":"EC",
                           "d":"N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
                           "crv":"secp256k1",
                           "x":"aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                           "y":"JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
                        }
                    """.trimIndent()
                )
            ),

            Secret(
                kid = "did:example:alice#key-x25519-1",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    """
                        {
                           "kty":"OKP",
                           "d":"D6F_LyXr88XBUIZzLW2HW4Yu_1fUQXB0VPun6roTqKc",
                           "crv":"X25519",
                           "x":"MQOV3AyIjJ_1azcXNa2TznwGFVABxnreQXyCHkAOezw"
                        }
                    """.trimIndent()
                )
            )
        )
    )

    override fun findKey(kid: String): Optional<Secret> =
        secretResolver.findKey(kid)

    override fun findKeys(kids: List<String>): List<Secret> =
        secretResolver.findKeys(kids)
}
