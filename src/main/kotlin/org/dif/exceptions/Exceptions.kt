package org.dif.exceptions

import org.dif.common.VerificationMaterialFormat as Format
import org.dif.common.VerificationMethodType as Type

/**
 * The base class for all DIDComm errors and exceptions.
 *
 * @param message - the detail message.
 * @param cause - the cause of this.
 */
open class DIDCommException(message: String, cause: Throwable? = null) : Throwable(message, cause)

/**
 * The base exception for DID Doc errors
 *
 * @param message - the detail message.
 */
open class DIDDocException(message: String) : DIDCommException(message)

/**
 * This exception SHOULD be raised if DID Doc can not be resolved.
 *
 * @param did The did.
 */
class DIDDocNotResolvedException(did: String) : DIDDocException("The DID Doc '$did' not resolved")

/**
 * This exception SHOULD be raised if DID URL not founded.
 *
 * @param didUrl The did url.
 */
class DIDUrlNotFoundException(didUrl: String) : DIDDocException("The DID URL '$didUrl' not found")

/**
 * This exception SHOULD be raised if Secret can not be found.
 *
 * @param kid The Key Identifier.
 */
class SecretNotFoundException(kid: String) : DIDCommException("The Secret '$kid' not found")

/**
 * Signals that packed message is malformed.
 *
 * @param message - the detail message.
 * @param cause - the cause of this.
 */
class MalformedMessageException(message: String, cause: Throwable? = null) : DIDCommException(message, cause)

/**
 * Signals that crypto is incompatible
 *
 * @param message - the detail message.
 */
class IncompatibleCryptoException(message: String) : DIDCommException(message)

/**
 * The base exception for unsupported exceptions.
 */
sealed class UnsupportedException(message: String) : DIDCommException(message) {
    /**
     * This exception SHOULD be raises if algorithm is not supported.
     *
     * @param alg JWA
     */
    class Algorithm(alg: String) : UnsupportedException("The algorithm $alg is unsupported")

    /**
     * This exception SHOULD be raised if JWK is not supported.
     * For example, if JWK is RSA Key.
     *
     * @param jwk The JWK.
     */
    class JWK(jwk: String) : UnsupportedException("The JWK $jwk is unsupported")

    /**
     * This exception SHOULD be raised if curve is not supported.
     *
     * @param curve The curve.
     */
    class Curve(curve: String) : UnsupportedException("The curve $curve is unsupported")

    /**
     * This exception SHOULD be raised if verification method type is unsupported.
     *
     * @param type The verification method type.
     */
    class VerificationMethodType(type: Type) : UnsupportedException("The verification method type ${type.name} is unsupported")

    /**
     * This exception SHOULD be raised if verification material is unsupported.
     *
     * @param format The verification material.
     */
    class VerificationMaterial(format: Format) : UnsupportedException("The verification material ${format.name} is unsupported")
}
