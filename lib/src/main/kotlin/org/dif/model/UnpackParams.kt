package org.dif.model

import org.dif.diddoc.DIDDocResolver
import org.dif.secret.SecretResolver

/**
 * Unpack Parameters.
 */
data class UnpackParams(
    val packedMessage: String,
    val expectDecryptByAllKeys: Boolean,
    val unwrapReWrappingForward: Boolean,
    val didDocResolver: DIDDocResolver?,
    val secretResolver: SecretResolver?,
) {
    constructor(builder: Builder) : this(
        builder.packedMessage,
        builder.expectDecryptByAllKeys,
        builder.unwrapReWrappingForward,
        builder.didDocResolver,
        builder.secretResolver
    )

    /**
     * Creates Unpack Builder.
     *
     * @property packedMessage packed DIDComm message as JSON string to be unpacked.
     */
    class Builder(val packedMessage: String) {
        var expectDecryptByAllKeys: Boolean = false
            private set

        var unwrapReWrappingForward: Boolean = true
            private set

        var didDocResolver: DIDDocResolver? = null
            private set

        var secretResolver: SecretResolver? = null
            private set

        /**
         * Sets [expectDecryptByAllKeys] parameter.
         *
         * @param expectDecryptByAllKeys Whether the message must be decryptable by all keys
         *                               resolved by the secrets resolver. False by default.
         *
         * @return This builder.
         */
        fun expectDecryptByAllKeys(expectDecryptByAllKeys: Boolean) =
            apply { this.expectDecryptByAllKeys = expectDecryptByAllKeys }

        /**
         * Sets [unwrapReWrappingForward] parameter.
         *
         * @param unwrapReWrappingForward If True (default), and the packed message is a Forward
         *                                wrapping a message packed for the given recipient,
         *                                then both Forward and packed messages are unpacked automatically,
         *                                and the unpacked message will be returned instead of unpacked Forward.
         * @return This builder.
         */
        fun unwrapReWrappingForward(unwrapReWrappingForward: Boolean) =
            apply { this.unwrapReWrappingForward = unwrapReWrappingForward }

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
         * Builds Unpack Parameters.
         *
         * @return parameters for unpack.
         */
        fun build() = UnpackParams(this)
    }
}
