package org.dif.crypto.key

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import org.dif.common.VerificationMethodType
import org.dif.exceptions.UnsupportedSecretTypeException
import org.dif.secret.Secret

sealed interface Key {
    val id: String
    fun toJWK(): JWK

    companion object {
        fun wrapSecret(secret: Secret): Key = when (secret.type) {
            VerificationMethodType.JSON_WEB_KEY_2020 -> JsonWebKey(secret)
            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019 -> TODO()
            VerificationMethodType.ED25519_VERIFICATION_KEY_2018 -> TODO()
            VerificationMethodType.ECDSA_SECP_256K1_VERIFICATION_KEY_2019 -> TODO()
            VerificationMethodType.OTHER -> throw UnsupportedSecretTypeException(secret.type.name)
        }
    }

    private class JsonWebKey(private val secret: Secret) : Key {
        override val id: String
            get() = secret.kid

        override fun toJWK(): JWK =
            JWK.parse(secret.verificationMaterial.value)
    }

    private class Base58Key(override val id: String, private val curve: Curve, private val encrypted: String) : Key {
        override fun toJWK(): JWK =
            TODO("Not implemented yet!")
    }
}
