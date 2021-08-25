package org.dif.secret

/**
 * A secret (private key) abstraction.
 *
 * @property kid    The key ID identifying a secret (private key).
 *                  Must have the same value, as key ID ('id' field)
 *                  of the corresponding method in DID Doc containing a public key.
 * @property type   The secret (private key) type.
 *                  Must have the same value, as type ('type' field) of
 *                  the corresponding method in DID Doc containing a public key.
 * @property value  The value of the secret (private key) as a string.
 *                  The value is type-specific, and has the same format
 *                  as the corresponding public key value from the DID Doc.
 *                  For example, for 'JsonWebKey2020' type it will be a JWK JSON string.
 *                  For 'X25519KeyAgreementKey2019' type it will be a base58-encoded string.
 */
data class Secret(val kid: String, val type: String, val value: String)