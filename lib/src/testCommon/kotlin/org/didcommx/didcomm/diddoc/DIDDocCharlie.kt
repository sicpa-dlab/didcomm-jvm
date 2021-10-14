package org.didcommx.didcomm.diddoc

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType

val CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_1 = VerificationMethod(
    id = "did:example:charlie#key-x25519-1",
    controller = "did:example:charlie#key-x25519-1",
    type = VerificationMethodType.JSON_WEB_KEY_2020,
    verificationMaterial = VerificationMaterial(
        format = VerificationMaterialFormat.JWK,
        value = """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
            }
            """
    ),
)

val CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_2 = VerificationMethod(
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
)

val CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_3 = VerificationMethod(
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

val CHARLIE_AUTH_METHOD_25519 = VerificationMethod(
    id = "did:example:charlie#key-1",
    controller = "did:example:charlie#key-1",
    type = VerificationMethodType.JSON_WEB_KEY_2020,
    verificationMaterial = VerificationMaterial(
        format = VerificationMaterialFormat.JWK,
        value = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            }
            """
    ),
)

val DID_DOC_CHARLIE = DIDDoc(
    did = "did:example:charlie",
    authentications = listOf("did:example:charlie#key-1"),
    keyAgreements = listOf(
        "did:example:charlie#key-x25519-1",
        "did:example:charlie#key-x25519-2",
        "did:example:charlie#key-x25519-3",
    ),
    didCommServices = listOf(
        DIDCommService(
            id = "did:example:123456789abcdefghi#didcomm-1",
            serviceEndpoint = "did:example:mediator2",
            accept = listOf(PROFILE_DIDCOMM_V2, PROFILE_DIDCOMM_AIP2_ENV_RFC587),
            routingKeys = listOf("did:example:mediator1#key-x25519-1"),
        )
    ),
    verificationMethods = listOf(
        CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
        CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
        CHARLIE_AUTH_METHOD_25519,
    ),
)
