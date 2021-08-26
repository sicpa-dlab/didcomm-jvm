package org.dif.model

import org.dif.common.AnonCryptAlg
import org.dif.common.AuthCryptAlg
import org.dif.common.JSONObject
import org.dif.common.SignAlg
import org.dif.message.Message

/**
 * Result of unpack operation.
 *
 * @property message  The unpacked message consisting of headers
 *                    and application/protocol specific data (body)
 * @property metadata The metadata with details about the packed messaged.
 *                    Can be used for MTC (message trust context) analysis.
 */
data class UnpackResult(val message: Message, val metadata: Metadata)

/**
 * Metadata with details about the packed messaged. Can be used for MTC (message trust context) analysis.
 *
 * @property encrypted          Whether the message has been encrypted.
 * @property authenticated      Whether the message has been authenticated.
 * @property nonRepudiation     Whether the message has been signed.
 * @property anonymousSender    Whether the sender ID was protected.
 * @property reWrappedInForward Whether the message was re-wrapped in a forward message by a mediator.
 * @property encryptedFrom      Key ID of the sender used for authentication encryption
 *                              if the message has been authenticated and encrypted.
 * @property encryptedTo        Target key IDS for encryption if the message has been encrypted.
 * @property signFrom           Key ID used for signature if the message has been signed.
 * @property encAlgAuth         Algorithm used for authentication encryption if the message has been authenticated and encrypted.
 * @property encAlgAnon         Algorithm used for anonymous encryption if the message has been encrypted but not authenticated.
 * @property signAlg            Signature algorithm in case of non-repudiation.
 * @property signedMessage      If the message has been signed, the JWS is returned for non-repudiation purposes.
 */
data class Metadata(
    val encrypted: Boolean,
    val authenticated: Boolean,
    val nonRepudiation: Boolean,
    val anonymousSender: Boolean,
    val reWrappedInForward: Boolean,
    val encryptedFrom: Boolean?,
    val encryptedTo: List<String>,
    val signFrom: String?,
    val encAlgAuth: AuthCryptAlg?,
    val encAlgAnon: AnonCryptAlg?,
    val signAlg: SignAlg?,
    val signedMessage: JSONObject?,
)