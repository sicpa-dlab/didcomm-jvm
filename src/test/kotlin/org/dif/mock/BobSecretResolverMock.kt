package org.dif.mock

import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMaterialFormat
import org.dif.common.VerificationMethodType
import org.dif.secret.Secret
import org.dif.secret.SecretResolver
import org.dif.secret.SecretResolverInMemory
import java.util.Optional

class BobSecretResolverMock : SecretResolver {
    private val secretResolver = SecretResolverInMemory(
        listOf(
            Secret(
                kid = "did:example:bob#key-x25519-1",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    """
                        {
                           "kty":"OKP",
                           "d":"N7TYPU-m2QkGwSOKNmezn_fAULSyjaQvkIwH4qvPDJo",
                           "crv":"X25519",
                           "x":"8VUvYUsQU9VvLGhq9rzQXf7j4jQv2k4o0b10naykdEw"
                        }
                    """.trimIndent()
                )
            ),

            Secret(
                kid = "did:example:bob#key-x25519-2",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    """
                        {
                           "kty":"OKP",
                           "d":"j79M5MKnrNmaoQT_PY_JLb2oE4Hhs3CkfaBdCZ-5UrM",
                           "crv":"X25519",
                           "x":"_hGwmO_Uaqaf_PDVxlh4BK354fYocC9Ut9VZjKZphTg"
                        }
                    """.trimIndent()
                )
            ),

            Secret(
                kid = "did:example:bob#key-x25519-3",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    """
                        {
                           "kty":"OKP",
                           "d":"D89JUUz9wKFZ8dNJat3MYObtxgPFh3OJJpibVloMOqs",
                           "crv":"X25519",
                           "x":"_cqvyjqdaZVAvCnQCbfJ8rhpDoi2F1uWmAgwGZf11Q4"
                        }
                    """.trimIndent()
                )
            ),

            Secret(
                kid = "did:example:bob#key-p256-1",
                type = VerificationMethodType.JSON_WEB_KEY_2020,
                verificationMaterial = VerificationMaterial(
                    VerificationMaterialFormat.JWK,
                    """
                        {
                           "kty":"EC",
                           "d":"WI1q-lIWtVfVgVLY5egjPq8xyPvUIxq4-tf-SFCBWhM",
                           "crv":"P-256",
                           "x":"DK14eQzIfr4QlobBwJHsWdyneea8T7jV5befZoP8XRs",
                           "y":"UJDoME9cMag_afBFonNfJ2GDyaAF1wv6P4uJwCrk3V8"
                        }
                    """.trimIndent()
                )
            )
        )
    )

    override fun findKey(kid: String): Optional<Secret> =
        secretResolver.findKey(kid)

    override fun findKeys(kids: List<String>): Set<String> =
        secretResolver.findKeys(kids)
}
