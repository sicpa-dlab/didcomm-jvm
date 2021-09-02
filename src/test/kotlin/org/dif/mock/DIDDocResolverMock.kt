package org.dif.mock

import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMaterialFormat
import org.dif.common.VerificationMethodType
import org.dif.diddoc.DIDDoc
import org.dif.diddoc.DIDDocResolver
import org.dif.diddoc.DIDDocResolverInMemory
import org.dif.diddoc.VerificationMethod
import java.util.Optional

class DIDDocResolverMock : DIDDocResolver {
    private val didDocResolver = DIDDocResolverInMemory(
        listOf(
            DIDDoc(
                did = "did:example:alice",
                authentications = listOf(
                    "did:example:alice#key-1",
                    "did:example:alice#key-2",
                    "did:example:alice#key-3"
                ),
                keyAgreements = listOf(
                    "did:example:alice#key-x25519-1",
                ),
                didCommServices = listOf(),
                verificationMethods = listOf(
                    VerificationMethod(
                        id = "did:example:alice#key-x25519-1",
                        controller = "did:example:alice#key-x25519-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"OKP",
                                   "crv":"X25519",
                                   "x":"MQOV3AyIjJ_1azcXNa2TznwGFVABxnreQXyCHkAOezw"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:alice#key-1",
                        controller = "did:example:alice#key-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"OKP",
                                   "crv":"Ed25519",
                                   "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:alice#key-2",
                        controller = "did:example:alice#key-2",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-256",
                                   "x":"2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                                   "y":"BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:alice#key-3",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        controller = "did:example:alice#key-3",
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"secp256k1",
                                   "x":"aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                                   "y":"JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
                                }
                            """.trimIndent()
                        )
                    )
                )
            ),

            DIDDoc(
                did = "did:example:bob",
                authentications = listOf(),
                keyAgreements = listOf(
                    "did:example:bob#key-x25519-1",
                    "did:example:bob#key-x25519-2",
                    "did:example:bob#key-x25519-3",
                    "did:example:bob#key-p256-1",
                ),
                didCommServices = listOf(),
                verificationMethods = listOf(
                    VerificationMethod(
                        id = "did:example:bob#key-x25519-1",
                        controller = "did:example:bob#key-x25519-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"OKP",
                                   "crv":"X25519",
                                   "x":"8VUvYUsQU9VvLGhq9rzQXf7j4jQv2k4o0b10naykdEw"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:bob#key-x25519-2",
                        controller = "did:example:bob#key-x25519-2",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"OKP",
                                   "crv":"X25519",
                                   "x":"_hGwmO_Uaqaf_PDVxlh4BK354fYocC9Ut9VZjKZphTg"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:bob#key-x25519-3",
                        controller = "did:example:bob#key-x25519-3",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"OKP",
                                   "crv":"X25519",
                                   "x":"_cqvyjqdaZVAvCnQCbfJ8rhpDoi2F1uWmAgwGZf11Q4"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:bob#key-p256-1",
                        controller = "did:example:bob#key-p256-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-256",
                                   "x":"DK14eQzIfr4QlobBwJHsWdyneea8T7jV5befZoP8XRs",
                                   "y":"UJDoME9cMag_afBFonNfJ2GDyaAF1wv6P4uJwCrk3V8"
                                }
                            """.trimIndent()
                        )
                    )
                )
            ),

            DIDDoc(
                did = "did:example:charlie",
                authentications = listOf(),
                keyAgreements = listOf(
                    "did:example:charlie#key-1",
                ),
                didCommServices = listOf(),
                verificationMethods = listOf(
                    VerificationMethod(
                        id = "did:example:charlie#key-x25519-1",
                        controller = "did:example:charlie#key-x25519-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"OKP",
                                   "crv":"X25519",
                                   "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                                }
                            """.trimIndent()
                        )
                    )
                )
            ),

            DIDDoc(
                did = "did:example:ellie",
                authentications = listOf(),
                keyAgreements = listOf(),
                didCommServices = listOf(),
                verificationMethods = listOf()
            )
        )
    )

    override fun resolve(did: String): Optional<DIDDoc> =
        didDocResolver.resolve(did)
}
