package org.dif.crypto.key

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.CurveBasedJWK
import com.nimbusds.jose.jwk.JWK
import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMethodType
import org.dif.diddoc.VerificationMethod
import org.dif.exceptions.UnsupportedJWKException
import org.dif.exceptions.UnsupportedSecretTypeException
import org.dif.secret.Secret

sealed interface Key {
    val id: String
    val jwk: JWK
    val curve: Curve

    companion object {
        fun wrapVerificationMethod(method: VerificationMethod) =
            wrap(method.id, method.type, method.verificationMaterial)

        fun wrapSecret(secret: Secret): Key =
            wrap(secret.kid, secret.type, secret.verificationMaterial)

        private fun wrap(kid: String, type: VerificationMethodType, verificationMaterial: VerificationMaterial): Key = when (type) {
            VerificationMethodType.JSON_WEB_KEY_2020 -> JsonWebKey(kid, verificationMaterial)
            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019 -> TODO()
            VerificationMethodType.ED25519_VERIFICATION_KEY_2018 -> TODO()
            VerificationMethodType.ECDSA_SECP_256K1_VERIFICATION_KEY_2019 -> TODO()
            VerificationMethodType.OTHER -> throw UnsupportedSecretTypeException(type.name)
        }
    }

    private class JsonWebKey(override val id: String, private val verificationMaterial: VerificationMaterial) : Key {
        override lateinit var jwk: JWK
            private set

        override lateinit var curve: Curve
            private set

        init {
            val jwk = JWK.parse(verificationMaterial.value)

            if (jwk !is CurveBasedJWK)
                throw UnsupportedJWKException(jwk::class.java.name)

            this.jwk = jwk
            this.curve = jwk.curve
        }
    }

    private class Base58Key(id: String, curve: Curve, private val encrypted: String) : Key {
        override val id: String
            get() = TODO("Not yet implemented")

        override val jwk: JWK
            get() = TODO("Not yet implemented")

        override val curve: Curve
            get() = TODO("Not yet implemented")
    }
}
