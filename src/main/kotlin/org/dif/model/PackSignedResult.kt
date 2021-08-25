package org.dif.model

import org.dif.common.JSON

/**
 * Result of pack signed message operation.
 *
 * @property json        A packed message as a JSON string
 * @property signFromKid Identifier (DID URL) of sender key used for message signing
 */
data class PackSignedResult(
    val json: JSON,
    val signFromKid: String
)