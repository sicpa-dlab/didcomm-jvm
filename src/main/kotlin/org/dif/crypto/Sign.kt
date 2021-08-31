package org.dif.crypto

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.Payload
import com.nimbusds.jose.UnprotectedHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import org.dif.common.Typ
import org.dif.crypto.key.Key
import org.dif.exceptions.UnsupportedAlgorithm
import org.dif.exceptions.UnsupportedCurveException
import org.dif.exceptions.UnsupportedJWKException
import org.dif.utils.asKey

fun sign(payload: String, key: Key): String {
    val jwk = key.jwk

    val alg = when (jwk) {
        is ECKey -> when (jwk.curve) {
            Curve.P_256 -> JWSAlgorithm.ES256
            Curve.SECP256K1 -> JWSAlgorithm.ES256K
            else -> throw UnsupportedCurveException(jwk.curve.name)
        }
        is OctetKeyPair -> JWSAlgorithm.EdDSA
        else -> throw UnsupportedJWKException(jwk.javaClass.name)
    }

    val signer = when (alg) {
        JWSAlgorithm.ES256 -> ECDSASigner(jwk.asKey<ECKey>())
        JWSAlgorithm.ES256K -> ECDSASigner(jwk.asKey<ECKey>())
        JWSAlgorithm.EdDSA -> Ed25519Signer(jwk.asKey())
        else -> throw UnsupportedAlgorithm(alg.name)
    }

    val jwsHeader = JWSHeader.Builder(alg)
        .type(JOSEObjectType(Typ.Signed.typ))
        .build()

    val jws = JWSObjectJSON(jwsHeader, Payload(Base64URL.encode(payload)))
    jws.sign(UnprotectedHeader.Builder(key.id).build(), signer)
    return jws.serialize()
}
