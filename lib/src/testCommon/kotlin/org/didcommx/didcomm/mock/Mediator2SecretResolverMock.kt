package org.didcommx.didcomm.mock

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolverInMemory
import java.util.Optional

class Mediator2SecretResolverMock : SecretResolverInMemoryMock {
    private val secrets = listOf(
        Secret(
            kid = "did:example:mediator2#key-x25519-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                format = VerificationMaterialFormat.JWK,
                value = """
                    {
                        "kty": "OKP",
                        "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
                        "crv": "X25519",
                        "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                    }
                """
            ),
        ),
        Secret(
            kid = "did:example:mediator2#key-p256-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                format = VerificationMaterialFormat.JWK,
                value = """
                        {
                            "kty": "EC",
                            "d": "agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU",
                            "crv": "P-256",
                            "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                            "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
                        }
                    """
            ),
        ),
        Secret(
            kid = "did:example:mediator2#key-p384-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                format = VerificationMaterialFormat.JWK,
                value = """
                        {
                            "kty": "EC",
                            "d": "OiwhRotK188BtbQy0XBO8PljSKYI6CCD-nE_ZUzK7o81tk3imDOuQ-jrSWaIkI-T",
                            "crv": "P-384",
                            "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                            "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
                        }
                    """
            ),
        ),

        Secret(
            kid = "did:example:mediator2#key-p521-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                format = VerificationMaterialFormat.JWK,
                value = """
                        {
                            "kty": "EC",
                            "d": "ABixMEZHsyT7SRw-lY5HxdNOofTZLlwBHwPEJ3spEMC2sWN1RZQylZuvoyOBGJnPxg4-H_iVhNWf_OtgYODrYhCk",
                            "crv": "P-521",
                            "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                            "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH",
                        }
                    """
            ),
        )
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
