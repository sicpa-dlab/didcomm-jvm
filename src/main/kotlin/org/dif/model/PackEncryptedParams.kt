package org.dif.model

import org.dif.common.AnonCryptAlg
import org.dif.common.AuthCryptAlg
import org.dif.diddoc.DIDDocResolver
import org.dif.message.Message
import org.dif.secret.SecretResolver

/**
 * Pack Encrypted Message Parameters
 */
data class PackEncryptedParams(
    val message: Message,
    val to: String,
    val from: String?,
    val signFrom: String?,
    val encAlgAuth: AuthCryptAlg,
    val encAlgAnon: AnonCryptAlg,
    val protectSenderId: Boolean,
    val forward: Boolean,
    val forwardHeaders: Map<String, Any>?,
    val forwardServiceId: String?,
    val didDocResolver: DIDDocResolver?,
    val secretResolver: SecretResolver?,
) {
    private constructor(builder: Builder) : this(
        builder.message,
        builder.to,
        builder.from,
        builder.signFrom,
        builder.encAlgAuth,
        builder.encAlgAnon,
        builder.protectSenderId,
        builder.forward,
        builder.forwardHeaders,
        builder.forwardServiceId,
        builder.didDocResolver,
        builder.secretResolver
    )

    companion object {
        fun builder(message: Message, to: String) = Builder(message, to)
    }

    /**
     * Creates Pack Encrypted Parameters Builder.
     *
     * @property message The message to be packed into a Encrypted DIDComm message.
     * @property to      Identifiers (DID URLs) of recipient keys used for message encryption.
     */
    class Builder(val message: Message, val to: String) {
        var from: String? = null
            private set

        var signFrom: String? = null
            private set

        var didDocResolver: DIDDocResolver? = null
            private set

        var secretResolver: SecretResolver? = null
            private set

        var encAlgAuth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
            private set

        var encAlgAnon: AnonCryptAlg = AnonCryptAlg.XC20P_ECDH_ES_A256KW
            private set

        var protectSenderId: Boolean = false
            private set

        var forward: Boolean = true
            private set

        var forwardHeaders: Map<String, Any>? = null
            private set

        var forwardServiceId: String? = null
            private set

        /**
         * Sets signing key parameter.
         *
         * @param signFrom Identifier (DID URL) of sender key used for message signing.
         *
         * @return This builder.
         */
        fun signFrom(signFrom: String) = apply { this.signFrom = signFrom }

        /**
         * Sets Optional DIDDoc resolver that can override a default DIDDoc resolver.
         *
         * @param didDocResolver Custom DIDDoc resolver
         * @return This builder.
         */
        fun didDocResolver(didDocResolver: DIDDocResolver) = apply { this.didDocResolver = didDocResolver }

        /**
         * Sets Optional Secret resolver that can override a default Secret resolver.
         *
         * @param secretResolver Custom Secret resolver
         * @return This builder.
         */
        fun secretResolver(secretResolver: SecretResolver) = apply { this.secretResolver = secretResolver }

        /**
         * Sets [from] parameter.
         *
         * @param from Identifier (DID URL) of sender key used for message encryption.
         *             null if anonymous (non-authenticated) encryption is used.
         * @return This builder.
         */
        fun from(from: String) = apply { this.from = from }

        /**
         * Sets [encAlgAuth] parameter.
         *
         * @param encAlgAuth The encryption algorithm to be used for authentication encryption (auth_crypt).
         * @return This builder.
         */
        fun encAlgAuth(encAlgAuth: AuthCryptAlg) = apply { this.encAlgAuth = encAlgAuth }

        /**
         * Sets [encAlgAnon] parameter.
         *
         * @param encAlgAnon The encryption algorithm to be used for anonymous encryption (anon_crypt).
         * @return This builder.
         */
        fun encAlgAnon(encAlgAnon: AnonCryptAlg) = apply { this.encAlgAnon = encAlgAnon }

        /**
         * Sets [protectSenderId] parameter.
         *
         * @param protectSenderId Whether the sender's identity needs to be protected during authentication encryption.
         * @return This builder.
         */
        fun protectSenderId(protectSenderId: Boolean) = apply { this.protectSenderId = protectSenderId }

        /**
         * Sets [forward] parameter.
         *
         * @param forward Whether the packed messages need to be wrapped into Forward messages to be sent to Mediators
         *                as defined by the Forward protocol. True by default.
         * @return This builder.
         */
        fun forward(forward: Boolean) = apply { this.forward = forward }

        /**
         * Sets [forwardHeaders] parameter.
         *
         * @param forwardHeaders  If forward is enabled (true by default),
         *                        optional headers can be passed to the wrapping Forward messages.
         * @return This builder.
         */
        fun forwardHeaders(forwardHeaders: Map<String, Any>) = apply { this.forwardHeaders = forwardHeaders }

        /**
         * Sets [forwardServiceId] parameter.
         *
         * @param forwardServiceId  If forward is enabled (true by default),
         *                          optional service ID from recipient's DID Doc to be used for Forwarding.
         * @return This builder.
         */
        fun forwardServiceId(forwardServiceId: String) = apply { this.forwardServiceId = forwardServiceId }

        /**
         * Builds parameters
         *
         * @return Pack Encrypted Message Parameters
         */
        fun build() = PackEncryptedParams(this)
    }
}
