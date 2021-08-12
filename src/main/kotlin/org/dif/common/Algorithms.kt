package org.dif.common

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm

/**
 * Algorithms for anonymous encryption.
 */
enum class AnonCryptAlg(alg: JWEAlgorithm, enc: EncryptionMethod) {
    /**
     * A256CBC_HS512_ECDH_ES_A256KW: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
     * ECDH-ES key agreement with A256KW key wrapping
     */
    A256CBC_HS512_ECDH_ES_A256KW(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512),

    /**
     * XC20P_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
     * ECDH-ES key agreement with A256KW key wrapping
     */
    XC20P_ECDH_ES_A256KW(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.XC20P),

    /**
     * A256GCM_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
     * ECDH-ES key agreement with A256KW key wrapping
     */
    A256GCM_ECDH_ES_A256KW(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM)
}

/**
 * Algorithms for authentication encryption.
 */
enum class AuthCryptAlg(alg: JWEAlgorithm, enc: EncryptionMethod) {
    /**
     * A256CBC_HS512_ECDH_1PU_A256KW: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
     * ECDH-1PU key agreement with A256KW key wrapping
     */
    A256CBC_HS512_ECDH_1PU_A256KW(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256CBC_HS512)
}

/**
 * Algorithms for signature (non-repudiation)
 */
enum class SignAlg(alg: JWSAlgorithm) {
    /**
     * Elliptic curve digital signature with edwards curves Ed25519 and SHA-512
     */
    ED25519(JWSAlgorithm.EdDSA),

    /**
     * Elliptic curve digital signature with NIST p-256 curve and SHA-256
     */
    ES256(JWSAlgorithm.ES256),

    /**
     * Elliptic curve digital signature with Secp256k1 keys
     */
    ES256K(JWSAlgorithm.ES256K)
}