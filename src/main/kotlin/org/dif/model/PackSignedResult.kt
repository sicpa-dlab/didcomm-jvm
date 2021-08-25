package org.dif.model

import org.dif.common.JSON

/**
 * Result of pack signed message operation.
 *
 * @property packedMessage  A packed message as a JSON string
 * @property signFromKid    Identifier (DID URL) of sender key used for message signing
 */
data class PackSignedResult(
    val packedMessage: JSON,
    val signFromKid: String
)