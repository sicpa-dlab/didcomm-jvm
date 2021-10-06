package org.didcommx.didcomm.model

import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.exceptions.DIDCommIllegalArgumentException
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.secret.SecretResolver
import org.didcommx.didcomm.utils.divideDIDFragment
import org.didcommx.didcomm.utils.isDID
import org.didcommx.didcomm.utils.isDIDFragment

/**
 * Pack Signed Message Parameters
 */
data class PackSignedParams(
    val message: Message,
    val signFrom: String,
    val fromPriorIssuerKid: String?,
    val didDocResolver: DIDDocResolver?,
    val secretResolver: SecretResolver?,
) {
    private constructor(builder: Builder) : this(
        builder.message,
        builder.signFrom,
        builder.fromPriorIssuerKid,
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
        var fromPriorIssuerKid: String? = null
            private set

        var didDocResolver: DIDDocResolver? = null
            private set

        var secretResolver: SecretResolver? = null
            private set

        /**
         * Sets Optional FromPrior issuer kid.
         *
         * @param fromPriorIssuerKid FromPrior issuer kid
         * @return This builder.
         */
        fun fromPriorIssuerKid(fromPriorIssuerKid: String) = apply { this.fromPriorIssuerKid = fromPriorIssuerKid }

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
        fun build(): PackSignedParams {
            val didFrom = divideDIDFragment(this.signFrom).first()
            val fromPriorIssuerKid = this.fromPriorIssuerKid

            if (!isDID(this.signFrom))
                throw DIDCommIllegalArgumentException(didFrom)

            if (this.message.from != didFrom)
                throw DIDCommIllegalArgumentException(didFrom)

            if (fromPriorIssuerKid != null && (!isDID(fromPriorIssuerKid) || !isDIDFragment(fromPriorIssuerKid)))
                throw DIDCommIllegalArgumentException(fromPriorIssuerKid)

            if (message.fromPrior != null) {
                if (message.fromPrior.sub == message.fromPrior.iss)
                    throw DIDCommIllegalArgumentException(message.fromPrior.sub)

                if (message.fromPrior.sub != message.from)
                    throw DIDCommIllegalArgumentException(message.fromPrior.sub)

                if (fromPriorIssuerKid != null &&
                    divideDIDFragment(fromPriorIssuerKid).first() != message.fromPrior.iss
                )
                    throw DIDCommIllegalArgumentException(fromPriorIssuerKid)
            }

            return PackSignedParams(this)
        }
    }
}
