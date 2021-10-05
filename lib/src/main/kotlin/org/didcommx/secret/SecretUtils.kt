package org.didcommx.secret

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.utils.toJSONString

fun jwkToSecret(jwk: Map<String, Any>): Secret =
    Secret(
        kid = jwk["kid"]?.toString() ?: "",
        type = VerificationMethodType.JSON_WEB_KEY_2020,
        verificationMaterial = VerificationMaterial(
            format = VerificationMaterialFormat.JWK,
            value = jwk.toJSONString()
        )
    )

fun secretToJwk(secret: Secret): Map<String, Any> =
    JSONObjectUtils.parse(secret.verificationMaterial.value)

data class KeyPair(val private: Map<String, Any>, val public: Map<String, Any>)

fun generateEd25519Keys(): KeyPair {
    val keys = OctetKeyPairGenerator(Curve.Ed25519).keyIDFromThumbprint(true).generate()
    return KeyPair(keys.toJSONObject(), keys.toPublicJWK().toJSONObject())
}

fun generateX25519Keys(): KeyPair {
    val keys = OctetKeyPairGenerator(Curve.X25519).keyIDFromThumbprint(true).generate()
    return KeyPair(keys.toJSONObject(), keys.toPublicJWK().toJSONObject())
}
