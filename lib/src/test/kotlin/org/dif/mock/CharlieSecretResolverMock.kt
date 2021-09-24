package org.dif.mock

import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMaterialFormat
import org.dif.common.VerificationMethodType
import org.dif.secret.Secret
import org.dif.secret.SecretResolver
import org.dif.secret.SecretResolverInMemory
import java.util.Optional

class CharlieSecretResolverMock : SecretResolver {
    private val secretResolver = SecretResolverInMemory(
        listOf(
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
