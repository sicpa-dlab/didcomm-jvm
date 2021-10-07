package org.didcommx.didcomm.mock

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolver
import org.didcommx.didcomm.secret.SecretResolverInMemory
import java.util.Optional

class CharlieSecretResolverMock : SecretResolver {
    private val secretResolver = SecretResolverInMemory(
        listOf(
            Secret(
                kid = "did:example:charlie#key-ed25519-1",
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
                kid = "did:example:charlie#key-x25519-3",
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
        )
    )

    override fun findKey(kid: String): Optional<Secret> =
        secretResolver.findKey(kid)

    override fun findKeys(kids: List<String>): Set<String> =
        secretResolver.findKeys(kids)
}
