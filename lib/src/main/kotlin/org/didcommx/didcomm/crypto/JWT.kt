package org.didcommx.didcomm.crypto

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.didcommx.didcomm.common.SignAlg
import org.didcommx.didcomm.crypto.key.Key
import org.didcommx.didcomm.exceptions.DIDCommException
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.exceptions.UnsupportedAlgorithm
import org.didcommx.didcomm.utils.asKey
import java.text.ParseException

fun signJwt(jwtClaimsSet: JWTClaimsSet, key: Key): String {
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

    val jwsHeader = JWSHeader.Builder(alg)
        .keyID(key.id)
        .build()

    return SignedJWT(jwsHeader, jwtClaimsSet)
        .apply {
            try {
                sign(signer)
            } catch (e: JOSEException) {
                throw DIDCommException("JWT cannot be signed", e)
            }
        }
        .serialize()
}

fun verifyJwt(serializedJwt: String, key: Key): JWTClaimsSet {
    val signedJWT: SignedJWT

    try {
        signedJWT = SignedJWT.parse(serializedJwt)
    } catch (e: ParseException) {
        throw MalformedMessageException("JWT cannot be deserialized", e)
    }

    val signAlg = getCryptoAlg(signedJWT)
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

    if (!signedJWT.verify(verifier))
        throw MalformedMessageException("JWT has an invalid signature")

    try {
        return signedJWT.jwtClaimsSet
    } catch (e: ParseException) {
        throw MalformedMessageException("JWT payload cannot be parsed", e)
    }
}

fun getCryptoAlg(jws: JWSObject): SignAlg =
    when (val alg = jws.header.algorithm) {
        JWSAlgorithm.ES256 -> SignAlg.ES256
        JWSAlgorithm.ES256K -> SignAlg.ES256K
        JWSAlgorithm.EdDSA -> SignAlg.ED25519
        else -> throw UnsupportedAlgorithm(alg.name)
    }
