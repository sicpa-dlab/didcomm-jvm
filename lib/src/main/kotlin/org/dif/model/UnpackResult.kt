package org.didcommx.didcomm.model

import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.common.AuthCryptAlg
import org.didcommx.didcomm.common.SignAlg
import org.didcommx.didcomm.message.Message

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
    val encrypted: Boolean = false,
    val authenticated: Boolean = false,
    val nonRepudiation: Boolean = false,
    val anonymousSender: Boolean = false,
    val reWrappedInForward: Boolean = false,
    val encryptedTo: List<String>? = null,
    val encryptedFrom: String? = null,
    val signFrom: String? = null,
    val encAlgAuth: AuthCryptAlg? = null,
    val encAlgAnon: AnonCryptAlg? = null,
    val signAlg: SignAlg? = null,
    val signedMessage: Map<String, Any>? = null
) {
    constructor(builder: Builder) : this(
        builder.encrypted,
        builder.authenticated,
        builder.nonRepudiation,
        builder.anonymousSender,
        builder.reWrappedInForward,
        builder.encryptedTo,
        builder.encryptedFrom,
        builder.signFrom,
        builder.encAlgAuth,
        builder.encAlgAnon,
        builder.signAlg,
        builder.signedMessage
    )

    class Builder {
        var encrypted: Boolean = false
            private set

        var authenticated: Boolean = false
            private set

        var nonRepudiation: Boolean = false
            private set

        var anonymousSender: Boolean = false
            private set

        var reWrappedInForward: Boolean = false
            private set

        var encryptedTo: List<String>? = null
            private set

        var encryptedFrom: String? = null
            private set

        var signFrom: String? = null
            private set

        var encAlgAuth: AuthCryptAlg? = null
            private set

        var encAlgAnon: AnonCryptAlg? = null
            private set

        var signAlg: SignAlg? = null
            private set

        var signedMessage: Map<String, Any>? = null
            private set

        fun encrypted(encrypted: Boolean) = apply { this.encrypted = encrypted }
        fun authenticated(authenticated: Boolean) = apply { this.authenticated = authenticated }
        fun nonRepudiation(nonRepudiation: Boolean) = apply { this.nonRepudiation = nonRepudiation }
        fun anonymousSender(anonymousSender: Boolean) = apply { this.anonymousSender = anonymousSender }
        fun reWrappedInForward(reWrappedInForward: Boolean) = apply { this.reWrappedInForward = reWrappedInForward }
        fun encryptedTo(encryptedTo: List<String>) = apply { this.encryptedTo = encryptedTo }
        fun encryptedFrom(encryptedFrom: String?) = apply { this.encryptedFrom = encryptedFrom }
        fun signFrom(signFrom: String?) = apply { this.signFrom = signFrom }
        fun encAlgAuth(encAlgAuth: AuthCryptAlg) = apply { this.encAlgAuth = encAlgAuth }
        fun encAlgAnon(encAlgAnon: AnonCryptAlg) = apply { this.encAlgAnon = encAlgAnon }
        fun signAlg(signAlg: SignAlg) = apply { this.signAlg = signAlg }
        fun signedMessage(signedMessage: Map<String, Any>) = apply { this.signedMessage = signedMessage }

        fun build() = Metadata(this)
    }
}
