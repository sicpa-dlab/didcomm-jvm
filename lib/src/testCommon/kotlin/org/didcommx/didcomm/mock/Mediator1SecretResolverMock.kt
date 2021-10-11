package org.didcommx.didcomm.mock

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolverInMemory
import java.util.Optional

class Mediator1SecretResolverMock : SecretResolverInMemoryMock {
    private val secrets = listOf(
        Secret(
            kid = "did:example:mediator1#key-x25519-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                format = VerificationMaterialFormat.JWK,
                value = """
                        {
                            "kty": "OKP",
                            "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
                            "crv": "X25519",
                            "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                        }
                    """
            ),
        ),

        Secret(
            kid = "did:example:mediator1#key-p256-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                format = VerificationMaterialFormat.JWK,
                value = """
                        {
                            "kty": "EC",
                            "d": "PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ",
                            "crv": "P-256",
                            "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                            "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
                        }
                    """
            ),
        ),

        Secret(
            kid = "did:example:mediator1#key-p384-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                format = VerificationMaterialFormat.JWK,
                value = """
                        {
                            "kty": "EC",
                            "d": "ajqcWbYA0UDBKfAhkSkeiVjMMt8l-5rcknvEv9t_Os6M8s-HisdywvNCX4CGd_xY",
                            "crv": "P-384",
                            "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                            "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
                        }
                    """
            ),
        ),

        Secret(
            kid = "did:example:mediator1#key-p521-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                format = VerificationMaterialFormat.JWK,
                value = """
                        {
                            "kty": "EC",
                            "d": "AV5ocjvy7PkPgNrSuvCxtG70NMj6iTabvvjSLbsdd8OdI9HlXYlFR7RdBbgLUTruvaIRhjEAE9gNTH6rWUIdfuj6",
                            "crv": "P-521",
                            "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                            "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
                        }
                    """
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
