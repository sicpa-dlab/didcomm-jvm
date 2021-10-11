package org.didcommx.didcomm.crypto.key

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.CurveBasedJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.VerificationMethod
import org.didcommx.didcomm.exceptions.UnsupportedCurveException
import org.didcommx.didcomm.exceptions.UnsupportedJWKException
import org.didcommx.didcomm.exceptions.UnsupportedSecretMaterialFormatException
import org.didcommx.didcomm.exceptions.UnsupportedSecretTypeException
import org.didcommx.didcomm.exceptions.UnsupportedVerificationMethodMaterialFormatException
import org.didcommx.didcomm.exceptions.UnsupportedVerificationMethodTypeException
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.utils.Codec
import org.didcommx.didcomm.utils.fromMulticodec

sealed interface Key {
    val id: String
    val jwk: JWK
    val curve: Curve

    companion object {
        private const val X25519 = "X25519"
        private const val ED25519 = "Ed25519"

        fun fromVerificationMethod(method: VerificationMethod): Key = when (method.type) {
            VerificationMethodType.JSON_WEB_KEY_2020 -> {
                if (method.verificationMaterial.format != VerificationMaterialFormat.JWK)
                    throw UnsupportedVerificationMethodMaterialFormatException(
                        method.verificationMaterial.format, method.type
                    )
                JsonWebKey(method.id, method.verificationMaterial.value)
            }

            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019,
            VerificationMethodType.ED25519_VERIFICATION_KEY_2018 -> {
                if (method.verificationMaterial.format != VerificationMaterialFormat.BASE58)
                    throw UnsupportedVerificationMethodMaterialFormatException(
                        method.verificationMaterial.format, method.type
                    )
                val curve =
                    when (method.type) {
                        VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019 -> X25519
                        VerificationMethodType.ED25519_VERIFICATION_KEY_2018 -> ED25519
                        else -> throw UnsupportedVerificationMethodTypeException(method.type)
                    }
                Base58Key(method.id, curve, method.verificationMaterial.value)
            }

            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
            VerificationMethodType.ED25519_VERIFICATION_KEY_2020 -> {
                if (method.verificationMaterial.format != VerificationMaterialFormat.MULTIBASE)
                    throw UnsupportedVerificationMethodMaterialFormatException(
                        method.verificationMaterial.format, method.type
                    )
                val curve =
                    when (method.type) {
                        VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020 -> X25519
                        VerificationMethodType.ED25519_VERIFICATION_KEY_2020 -> ED25519
                        else -> throw UnsupportedVerificationMethodTypeException(method.type)
                    }
                MultibaseKey(method.id, curve, method.verificationMaterial.value)
            }

            else -> {
                throw UnsupportedVerificationMethodTypeException(method.type)
            }
        }

        fun fromSecret(secret: Secret): Key = when (secret.type) {
            VerificationMethodType.JSON_WEB_KEY_2020 -> {
                if (secret.verificationMaterial.format != VerificationMaterialFormat.JWK)
                    throw UnsupportedSecretMaterialFormatException(
                        secret.verificationMaterial.format, secret.type
                    )
                JsonWebKey(secret.kid, secret.verificationMaterial.value)
            }

            else -> {
                throw UnsupportedSecretTypeException(secret.type)
            }
        }
    }

    private class JsonWebKey(override val id: String, materialValue: String) : Key {
        override lateinit var jwk: JWK
            private set

        override lateinit var curve: Curve
            private set

        init {
            val jwk = JWK.parse(materialValue)

            if (jwk !is CurveBasedJWK)
                throw UnsupportedJWKException(jwk::class.java.name)

            this.jwk = jwk
            this.curve = jwk.curve
        }
    }

    private class Base58Key(override val id: String, curve: String, materialValue: String) : Key {
        override lateinit var jwk: JWK
            private set

        override lateinit var curve: Curve
            private set

        init {
            val rawValue = Base58.decode(materialValue)
            val base64URLValue = Base64URL.encode(rawValue).toString()

            val jwkJson: Map<String, Any> = mapOf(
                "kty" to "OKP",
                "crv" to curve,
                "x" to base64URLValue
            )

            val jwk = JWK.parse(jwkJson)

            if (jwk !is CurveBasedJWK)
                throw UnsupportedJWKException(jwk::class.java.name)

            this.jwk = jwk
            this.curve = jwk.curve
        }
    }

    private class MultibaseKey(override val id: String, curve: String, materialValue: String) : Key {
        override lateinit var jwk: JWK
            private set

        override lateinit var curve: Curve
            private set

        init {
            val prefixedRawValue = Multibase.decode(materialValue)
            val (codec, rawValue) = fromMulticodec(prefixedRawValue)

            val expectedCodec = when (curve) {
                X25519 -> Codec.X25519_PUB
                ED25519 -> Codec.ED25519_PUB
                else -> throw UnsupportedCurveException(curve)
            }

            if (codec != expectedCodec) {
                throw IllegalArgumentException(
                    "Multicoded prefix ${codec.prefix} is not valid for publicKeyMultibase and $curve curve"
                )
            }

            val base64URLValue = Base64URL.encode(rawValue).toString()

            val jwkJson: Map<String, Any> = mapOf(
                "kty" to "OKP",
                "crv" to curve,
                "x" to base64URLValue
            )

            val jwk = JWK.parse(jwkJson)

            if (jwk !is CurveBasedJWK)
                throw UnsupportedJWKException(jwk::class.java.name)

            this.jwk = jwk
            this.curve = jwk.curve
        }
    }
}
