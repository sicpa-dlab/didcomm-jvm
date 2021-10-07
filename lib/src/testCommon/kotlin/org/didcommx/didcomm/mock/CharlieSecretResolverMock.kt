package org.didcommx.didcomm.mock

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolverInMemory
import java.util.Optional

class CharlieSecretResolverMock : SecretResolverInMemoryMock {
    private val secrets = listOf(
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
    private val secretResolver = SecretResolverInMemory(
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
