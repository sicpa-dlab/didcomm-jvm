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
                keyAgreements = listOf(),
                didCommServices = listOf(),
                verificationMethods = listOf(
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
            )
        )
    )

    override fun resolve(did: String): Optional<DIDDoc> =
        didDocResolver.resolve(did)
}
