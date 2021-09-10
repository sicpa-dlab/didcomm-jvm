package org.dif.crypto.key

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.CurveBasedJWK
import com.nimbusds.jose.jwk.JWK
import io.ipfs.multibase.Base58
import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMaterialFormat
import org.dif.common.VerificationMethodType
import org.dif.diddoc.VerificationMethod
import org.dif.exceptions.UnsupportedException
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
            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019 -> Base58Key(kid, Curve.X25519, verificationMaterial)
            VerificationMethodType.ED25519_VERIFICATION_KEY_2018 -> Base58Key(kid, Curve.Ed25519, verificationMaterial)
            VerificationMethodType.ECDSA_SECP_256K1_VERIFICATION_KEY_2019 -> JsonWebKey(kid, verificationMaterial)
            VerificationMethodType.OTHER -> throw UnsupportedException.VerificationMethodType(type)
        }
    }

    private class JsonWebKey(override val id: String, verificationMaterial: VerificationMaterial) : Key {
        companion object {
            val supportedCurves = setOf(
                Curve.P_256,
                Curve.P_384,
                Curve.P_521,
                Curve.SECP256K1,
                Curve.Ed25519,
                Curve.X25519
            )
        }

        override lateinit var jwk: JWK
            private set

        override lateinit var curve: Curve
            private set

        init {
            if (verificationMaterial.format !== VerificationMaterialFormat.JWK)
                throw UnsupportedException.VerificationMaterial(verificationMaterial.format)

            val jwk = JWK.parse(verificationMaterial.value)

            if (jwk !is CurveBasedJWK)
                throw UnsupportedException.JWK(jwk::class.java.name)

            if (jwk.curve !in supportedCurves)
                throw UnsupportedException.Curve(jwk.curve.name)

            this.jwk = jwk
            this.curve = jwk.curve
        }
    }

    private class Base58Key(override val id: String, override val curve: Curve, verificationMaterial: VerificationMaterial) : Key {
        override lateinit var jwk: JWK
            private set

        init {
            if (verificationMaterial.format !== VerificationMaterialFormat.BASE58)
                throw UnsupportedException.VerificationMaterial(verificationMaterial.format)

            if (curve !in JsonWebKey.supportedCurves)
                throw UnsupportedException.Curve(curve.name)

            val bytes = Base58.decode(verificationMaterial.value)
            TODO()
        }
    }
}
