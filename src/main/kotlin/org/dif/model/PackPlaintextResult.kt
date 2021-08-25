package org.dif.model

import org.dif.common.JSON

/**
 * Result of pack plaintext message operation.
 *
 * @property json A packed message as a JSON string
 */
data class PackPlaintextResult(
    val json: JSON
)