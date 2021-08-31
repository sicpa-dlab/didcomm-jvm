package org.dif.crypto

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetKeyPair
import org.dif.crypto.key.Key
import org.dif.exceptions.MalformedMessageException
import org.dif.exceptions.UnsupportedAlgorithm
import org.dif.exceptions.UnsupportedCurveException
import org.dif.exceptions.UnsupportedJWKException
import org.dif.message.Message
import org.dif.utils.asKey

fun verify(jws: JWSObjectJSON, key: Key): Message {
    val jwk = key.toJWK()

    val alg = when (jwk) {
        is ECKey -> when (jwk.curve) {
            Curve.P_256 -> JWSAlgorithm.ES256
            Curve.SECP256K1 -> JWSAlgorithm.ES256K
            else -> throw UnsupportedCurveException(jwk.curve.name)
        }
        is OctetKeyPair -> JWSAlgorithm.EdDSA
        else -> throw UnsupportedJWKException(jwk.javaClass.name)
    }

    val verifier = when (alg) {
        JWSAlgorithm.ES256 -> ECDSAVerifier(jwk.asKey<ECKey>())
        JWSAlgorithm.ES256K -> ECDSAVerifier(jwk.asKey<ECKey>())
        JWSAlgorithm.EdDSA -> Ed25519Verifier(jwk.asKey())
        else -> throw UnsupportedAlgorithm(alg.name)
    }

    if (!jws.verify(verifier))
        throw MalformedMessageException("Invalid signature")

    return Message.parse(jws.payload.toJSONObject())
}
