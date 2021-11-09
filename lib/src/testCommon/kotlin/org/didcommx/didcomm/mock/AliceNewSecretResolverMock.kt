package org.didcommx.didcomm.mock

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolverInMemory
import java.util.Optional

class AliceNewSecretResolverMock : SecretResolverInMemoryMock {
    private val secrets = listOf(
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
                           "d":"r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
                           "crv":"X25519",
                           "x":"avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
                        }
                """.trimIndent()
            )
        ),

        Secret(
            kid = "did:example:alice#key-p256-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                VerificationMaterialFormat.JWK,
                """
                        {
                           "kty":"EC",
                           "d":"sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
                           "crv":"P-256",
                           "x":"L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                           "y":"SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
                        }
                """.trimIndent()
            )
        ),

        Secret(
            kid = "did:example:alice#key-p521-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                VerificationMaterialFormat.JWK,
                """
                        {
                           "kty":"EC",
                           "d":"AQCQKE7rZpxPnX9RgjXxeywrAMp1fJsyFe4cir1gWj-8t8xWaM_E2qBkTTzyjbRBu-JPXHe_auT850iYmE34SkWi",
                           "crv":"P-521",
                           "x":"AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
                           "y":"AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk"
                        }
                """.trimIndent()
            )
        ),
        Secret(
            kid = "did:example:charlie#key-x25519-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                VerificationMaterialFormat.JWK,
                """
                        {
                           "kty":"OKP",
                           "d":"Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
                           "crv":"X25519",
                           "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                        }
                """.trimIndent()
            )
        ),

        Secret(
            kid = "did:example:charlie#key-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                VerificationMaterialFormat.JWK,
                """
                        {
                           "kty":"OKP",
                           "d":"T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
                           "crv":"Ed25519",
                           "x":"VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE"
                        }
                """.trimIndent()
            )
        )
    )
    val secretResolver = SecretResolverInMemory(
        secrets
    )

    override fun getSecrets(): List<Secret> {
        return secrets
    }

    override fun getSecretKids(): List<String> {
        return secrets.map { secret -> secret.kid }
    }

    override fun findKey(kid: String): Optional<Secret> =
        secretResolver.findKey(kid)

    override fun findKeys(kids: List<String>): Set<String> =
        secretResolver.findKeys(kids)
}
