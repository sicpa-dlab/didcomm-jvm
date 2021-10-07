package org.didcommx.didcomm.mock

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.diddoc.DIDDocResolverInMemory
import org.didcommx.didcomm.diddoc.VerificationMethod
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
                    "did:example:alice#key-p256-1",
                    "did:example:alice#key-p521-1",
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
                                   "x":"avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:alice#key-p256-1",
                        controller = "did:example:alice#key-p256-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-256",
                                   "x":"L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                                   "y":"SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:alice#key-p521-1",
                        controller = "did:example:alice#key-p521-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-521",
                                   "x":"AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
                                   "y":"AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk"
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
                    "did:example:bob#key-p256-2",
                    "did:example:bob#key-p384-1",
                    "did:example:bob#key-p384-2",
                    "did:example:bob#key-p521-1",
                    "did:example:bob#key-p521-2",
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
                                   "x":"GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"
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
                                   "x":"UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
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
                                   "x":"82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
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
                                   "x":"FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                                   "y":"6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:bob#key-p256-2",
                        controller = "did:example:bob#key-p256-2",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-256",
                                   "x":"n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                                   "y":"ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:bob#key-p384-1",
                        controller = "did:example:bob#key-p384-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-384",
                                   "x":"MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                                   "y":"X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:bob#key-p384-2",
                        controller = "did:example:bob#key-p384-2",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-384",
                                   "x":"2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                                   "y":"W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:bob#key-p521-1",
                        controller = "did:example:bob#key-p521-1",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-521",
                                   "x":"Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                                   "y":"ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH"
                                }
                            """.trimIndent()
                        )
                    ),

                    VerificationMethod(
                        id = "did:example:bob#key-p521-2",
                        controller = "did:example:bob#key-p521-2",
                        type = VerificationMethodType.JSON_WEB_KEY_2020,
                        verificationMaterial = VerificationMaterial(
                            VerificationMaterialFormat.JWK,
                            """
                                {
                                   "kty":"EC",
                                   "crv":"P-521",
                                   "x":"ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                                   "y":"AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
                                }
                            """.trimIndent()
                        )
                    )
                )
            ),

            DIDDoc(
                did = "did:example:charlie",
                authentications = listOf(
                    "did:example:charlie#key-ed25519-1"
                ),
                keyAgreements = listOf(
                    "did:example:charlie#key-x25519-1",
                    "did:example:charlie#key-x25519-2",
                    "did:example:charlie#key-x25519-3",
                ),
                didCommServices = listOf(),
                verificationMethods = listOf(
                    VerificationMethod(
                        id = "did:example:charlie#key-ed25519-1",
                        controller = "did:example:charlie#key-ed25519-1",
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
                    ),

                    VerificationMethod(
                        id = "did:example:charlie#key-x25519-2",
                        controller = "did:example:charlie#key-x25519-2",
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
                    ),

                    VerificationMethod(
                        id = "did:example:charlie#key-x25519-3",
                        controller = "did:example:charlie#key-x25519-3",
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
