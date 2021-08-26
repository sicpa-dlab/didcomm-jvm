package org.dif.model

import org.dif.diddoc.DIDDocResolver
import org.dif.message.Attachment
import org.dif.message.Message
import org.dif.secret.SecretResolver

/**
 * Pack Signed Message Parameters
 */
data class PackSignedParams(
    val message: Message,
    val signFrom: String,
    val didDocResolver: DIDDocResolver?,
    val secretResolver: SecretResolver?,
) {
    private constructor(builder: Builder): this(
        builder.message,
        builder.signFrom,
        builder.didDocResolver,
        builder.secretResolver
    )

    companion object {
        fun builder(message: Message, signFrom: String) = Builder(message, signFrom)
    }

    /**
     * Creates Pack Signed Parameters Builder
     *
     * @property message  The message to be packed into a Signed DIDComm message.
     * @property signFrom DID or key ID the sender uses for signing.
     */
    class Builder(val message: Message, val signFrom: String) {
        var didDocResolver: DIDDocResolver? = null
            private set

        var secretResolver: SecretResolver? = null
            private set

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
         * Builds parameters
         *
         * @return Pack Signed Message Parameters
         */
        fun build() = PackSignedParams(this)
    }
}