package org.didcommx.didcomm.model

/**
 * Result of pack plaintext message operation.
 *
 * @property packedMessage A packed message as a JSON string
 */
data class PackPlaintextResult(
    val packedMessage: String
)
