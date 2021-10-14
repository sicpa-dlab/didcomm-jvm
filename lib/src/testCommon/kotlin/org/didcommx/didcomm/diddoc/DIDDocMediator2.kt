package org.didcommx.didcomm.diddoc

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType

val MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1 = VerificationMethod(
    id = "did:example:mediator2#key-x25519-1",
    controller = "did:example:mediator2#key-x25519-1",
    type = VerificationMethodType.JSON_WEB_KEY_2020,
    verificationMaterial = VerificationMaterial(
        format = VerificationMaterialFormat.JWK,
        value = """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
            }
        """
    ),
)
val MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1 = VerificationMethod(
    id = "did:example:mediator2#key-p256-1",
    controller = "did:example:mediator2#key-p256-1",
    type = VerificationMethodType.JSON_WEB_KEY_2020,
    verificationMaterial = VerificationMaterial(
        format = VerificationMaterialFormat.JWK,
        value = """
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
            }   
        """
    ),
)
val MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1 = VerificationMethod(
    id = "did:example:mediator2#key-p384-1",
    controller = "did:example:mediator2#key-p384-1",
    type = VerificationMethodType.JSON_WEB_KEY_2020,
    verificationMaterial = VerificationMaterial(
        format = VerificationMaterialFormat.JWK,
        value = """
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
            }
        """
    ),
)
val MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1 = VerificationMethod(
    id = "did:example:mediator2#key-p521-1",
    controller = "did:example:mediator2#key-p521-1",
    type = VerificationMethodType.JSON_WEB_KEY_2020,
    verificationMaterial = VerificationMaterial(
        format = VerificationMaterialFormat.JWK,
        value = """
        {
            "kty": "EC",
            "crv": "P-521",
            "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
            "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
        }
        """
    ),
)

val DID_DOC_MEDIATOR2_SPEC_TEST_VECTORS = DIDDoc(
    did = "did:example:mediator2",
    authentications = listOf(),
    keyAgreements = listOf(
        "did:example:mediator2#key-x25519-1",
        "did:example:mediator2#key-p256-1",
        "did:example:mediator2#key-p384-1",
        "did:example:mediator2#key-p521-1",
    ),
    didCommServices = listOf(),
    verificationMethods = listOf(
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
    ),
)

val DID_DOC_MEDIATOR2 = DIDDoc(
    did = "did:example:mediator2",
    authentications = listOf(),
    keyAgreements = listOf(
        "did:example:mediator2#key-x25519-1",
        "did:example:mediator2#key-p256-1",
        "did:example:mediator2#key-p384-1",
        "did:example:mediator2#key-p521-1",
    ),
    didCommServices = listOf(
        DIDCommService(
            id = "did:example:123456789abcdefghi#didcomm-1",
            serviceEndpoint = "http://example.com/path",
            accept = listOf(PROFILE_DIDCOMM_V2, PROFILE_DIDCOMM_AIP2_ENV_RFC587),
            routingKeys = listOf("did:example:mediator1#key-x25519-1"),
        )
    ),
    verificationMethods = listOf(
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
    ),
)
