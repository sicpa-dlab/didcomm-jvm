package org.dif.exceptions

/**
 * The base class for all DIDComm errors and exceptions.
 *
 * @param message - the detail message string.
 * @param cause - the cause of this throwable.
 */
open class DIDCommException(message: String, cause: Throwable? = null) : Throwable(message, cause)

/**
 * This exception SHOULD be raised if secret can not be converted to JWK format.
 *
 * @param type The secret type.
 */
class UnsupportedSecretTypeException(type: String) : DIDCommException("The secret type $type is unsupported")
