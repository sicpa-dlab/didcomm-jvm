package org.dif.exceptions

/**
 * The base class for all DIDComm errors and exceptions.
 *
 * @param message - the detail message.
 * @param cause - the cause of this.
 */
open class DIDCommException(message: String, cause: Throwable? = null) : Throwable(message, cause)

/**
 * This exception SHOULD be raised if secret can not be converted to JWK format.
 *
 * @param type The secret type.
 */
class UnsupportedSecretTypeException(type: String) : DIDCommException("The secret type $type is unsupported")

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
 * This exception SHOULD be raised if Secret can not be found.
 *
 * @param kid The Key Identifier.
 */
class SecretNotFoundException(kid: String) : DIDCommException("The Secret '$kid' not found")

/**
 * This exception SHOULD be raised if curve is not supported.
 *
 * @param curve The curve.
 */
class UnsupportedCurveException(curve: String) : DIDCommException("The curve $curve is unsupported")

/**
 * This exception SHOULD be raised if JWK is not supported.
 * For example, if JWK is RSA Key.
 *
 * @param jwk The JWK.
 */
class UnsupportedJWKException(jwk: String) : DIDCommException("The JWK $jwk is unsupported")

/**
 * This exception SHOULD be raises if algorithm is not supported.
 *
 * @param alg JWA
 */
class UnsupportedAlgorithm(alg: String) : DIDCommException("The algorithm $alg is unsupported")

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
