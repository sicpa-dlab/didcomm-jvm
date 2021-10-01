package org.didcommx.didcomm.model

/**
 * Result of pack signed message operation.
 *
 * @property packedMessage  A packed message as a JSON string
 * @property signFromKid    Identifier (DID URL) of sender key used for message signing
 */
data class PackSignedResult(
    val packedMessage: String,
    val signFromKid: String
)
