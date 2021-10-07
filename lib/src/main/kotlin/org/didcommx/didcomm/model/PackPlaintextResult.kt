package org.didcommx.didcomm.model

/**
 * Result of pack plaintext message operation.
 *
 * @property packedMessage       A packed message as a JSON string
 * @property fromPriorIssuerKid  Identifier (DID URL) of FromPrior issuer key
 */
data class PackPlaintextResult(
    val packedMessage: String,
    val fromPriorIssuerKid: String? = null
)
