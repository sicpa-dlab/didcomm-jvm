package org.didcommx.didcomm.crypto

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.Payload
import com.nimbusds.jose.UnprotectedHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import org.didcommx.didcomm.common.SignAlg
import org.didcommx.didcomm.common.Typ
import org.didcommx.didcomm.crypto.key.Key
import org.didcommx.didcomm.exceptions.DIDCommException
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.exceptions.UnsupportedAlgorithm
import org.didcommx.didcomm.exceptions.UnsupportedCurveException
import org.didcommx.didcomm.exceptions.UnsupportedJWKException
import org.didcommx.didcomm.utils.asKey
import java.security.SignatureException

fun sign(payload: String, key: Key): String {
    val jwk = key.jwk
    val alg = getJWSAlgorithm(jwk)

    val signer = try {
        when (alg) {
            JWSAlgorithm.ES256 -> ECDSASigner(jwk.asKey<ECKey>())
            JWSAlgorithm.ES256K -> ECDSASigner(jwk.asKey<ECKey>())
            JWSAlgorithm.EdDSA -> Ed25519Signer(jwk.asKey())
            else -> throw UnsupportedAlgorithm(alg.name)
        }
    } catch (e: JOSEException) {
        throw UnsupportedAlgorithm(alg.name)
    }

    val jwsProtectedHeader = JWSHeader.Builder(alg)
        .type(JOSEObjectType(Typ.Signed.typ))
        .build()

    val jwsUnprotectedHeader = UnprotectedHeader.Builder().keyID(key.id).build()
    return JWSObjectJSON(Payload(Base64URL.encode(payload)))
        .apply {
            try {
                sign(jwsProtectedHeader, jwsUnprotectedHeader, signer)
            } catch (e: JOSEException) {
                // this can be thrown if the signature type is not supported
                // example: curve256k1 is not supported in JDK >= 15
                if (e.cause is SignatureException) {
                    throw UnsupportedAlgorithm("Unsupported signature algorithm", e.cause)
                }
                throw DIDCommException("JWS cannot be signed", e)
            }
        }
        .serializeGeneral()
}

fun verify(signature: JWSObjectJSON.Signature, signAlg: SignAlg, key: Key) {
    val jwk = key.jwk

    val verifier = try {
        when (signAlg) {
            SignAlg.ES256 -> ECDSAVerifier(jwk.asKey<ECKey>())
            SignAlg.ES256K -> ECDSAVerifier(jwk.asKey<ECKey>())
            SignAlg.ED25519 -> Ed25519Verifier(jwk.asKey())
        }
    } catch (e: JOSEException) {
        throw UnsupportedAlgorithm(signAlg.name)
    }

    try {
        if (!signature.verify(verifier))
            throw MalformedMessageException("Invalid signature")
    } catch (e: JOSEException) {
        // this can be thrown if the signature type is not supported
        // example: curve256k1 is not supported in JDK >= 15
        if (e.cause is SignatureException) {
            throw UnsupportedAlgorithm("Unsupported signature algorithm", e.cause)
        }
        throw DIDCommException("JWS signature cannot be verified", e)
    }
}

fun getCryptoAlg(signature: JWSObjectJSON.Signature): SignAlg {
    return when (val alg = signature.header.algorithm) {
        JWSAlgorithm.ES256 -> SignAlg.ES256
        JWSAlgorithm.ES256K -> SignAlg.ES256K
        JWSAlgorithm.EdDSA -> SignAlg.ED25519
        else -> throw UnsupportedAlgorithm(alg.name)
    }
}

fun getJWSAlgorithm(jwk: JWK) = when (jwk) {
    is ECKey -> when (jwk.curve) {
        Curve.P_256 -> JWSAlgorithm.ES256
        Curve.SECP256K1 -> JWSAlgorithm.ES256K
        else -> throw UnsupportedCurveException(jwk.curve.name)
    }
    is OctetKeyPair -> JWSAlgorithm.EdDSA
    else -> throw UnsupportedJWKException(jwk.javaClass.name)
}
