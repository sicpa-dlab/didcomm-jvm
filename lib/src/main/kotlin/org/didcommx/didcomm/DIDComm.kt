package org.didcommx.didcomm

import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.common.AuthCryptAlg
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
import org.didcommx.didcomm.crypto.key.SenderKeySelector
import org.didcommx.didcomm.crypto.sign
import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.diddoc.resolveDidServicesChain
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackEncryptedResult
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.PackPlaintextResult
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.PackSignedResult
import org.didcommx.didcomm.model.ServiceMetadata
import org.didcommx.didcomm.model.UnpackForwardResult
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.model.UnpackResult
import org.didcommx.didcomm.operations.encrypt
import org.didcommx.didcomm.operations.packFromPrior
import org.didcommx.didcomm.operations.protectSenderIfNeeded
import org.didcommx.didcomm.operations.signIfNeeded
import org.didcommx.didcomm.operations.unpack
import org.didcommx.didcomm.operations.unpackForward
import org.didcommx.didcomm.operations.wrapInForwardIfNeeded
import org.didcommx.didcomm.secret.SecretResolver

/**
 * DID Comm operations
 */
class DIDComm(private val didDocResolver: DIDDocResolver, private val secretResolver: SecretResolver) {
    /**
     * Produces [DIDComm Plaintext Messages](https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages).
     *
     * A DIDComm message in its plaintext form that
     *  - is not packaged into any protective envelope;
     *  - lacks confidentiality and integrity guarantees;
     *  - repudiable.
     *
     * They are therefore not normally transported across security boundaries.
     * However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
     * and it is the format used in the DIDComm spec to give examples of headers and other internals.
     * Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.
     *
     * @param params Pack Plaintext Parameters.
     * @return Result of Pack Plaintext Operation.
     */
    fun packPlaintext(params: PackPlaintextParams): PackPlaintextResult {
        val didDocResolver = params.didDocResolver ?: this.didDocResolver
        val secretResolver = params.secretResolver ?: this.secretResolver
        val senderKeySelector = SenderKeySelector(didDocResolver, secretResolver)

        val (message, fromPriorIssuerKid) = packFromPrior(params.message, params.fromPriorIssuerKid, senderKeySelector)

        return PackPlaintextResult(message.toString(), fromPriorIssuerKid)
    }

    /**
     * Produces (DIDComm Signed Message)[https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message].
     *
     * The method signs (non-repudiation added) the message keeping it unencrypted.
     * Signed messages are only necessary when
     *  - the origin of plaintext must be provable to third parties;
     *  - or the sender can’t be proven to the recipient by authenticated encryption because the recipient
     *    is not known in advance (e.g., in a broadcast scenario).
     *
     * Adding a signature when one is not needed can degrade rather than enhance security because it
     * relinquishes the sender’s ability to speak off the record.
     *
     * Signing is done as follows:
     *  - Signing is done via the keys from the [DIDDoc.authentications] verification relationship in the DID Doc
     *    for the DID to be used for signing.
     *  - If [PackSignedParams.signFrom] is a DID, then the first sender's [DIDDoc.authentications]
     *    verification method is used for which a private key in the secrets resolver is found
     *  - If [PackSignedParams.signFrom]  is a key ID, then the sender's [DIDDoc.authentications]
     *    verification method identified by the given key ID is used.
     *
     * @param params Pack Signed Parameters.
     * @return Result of Pack Signed Operation.
     */
    fun packSigned(params: PackSignedParams): PackSignedResult {
        val didDocResolver = params.didDocResolver ?: this.didDocResolver
        val secretResolver = params.secretResolver ?: this.secretResolver
        val senderKeySelector = SenderKeySelector(didDocResolver, secretResolver)

        val (message, fromPriorIssuerKid) = packFromPrior(params.message, params.fromPriorIssuerKid, senderKeySelector)
        val signFromKey = senderKeySelector.findSigningKey(params.signFrom)
        val msg = sign(message.toString(), signFromKey)

        return PackSignedResult(msg, signFromKey.id, fromPriorIssuerKid)
    }

    /**
     * Produces [DIDComm Encrypted Message](https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message).
     * The method encrypts and optionally authenticates the message to the given recipient.
     *
     * A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) that
     *  - hides its content from all but authorized recipients;
     *  - (optionally) discloses and proves the sender to only those recipients;
     *  - provides message integrity guarantees.
     *
     * It is important in privacy-preserving routing.
     *
     * It is what normally moves over network transports in DIDComm
     * applications, and is the safest format for storing DIDComm data at rest.
     *
     * Pack is done according to the given [params].
     *
     * The default config performs repudiable encryption
     * ([AuthCryptAlg] if [PackEncryptedParams.from] is set and [AnonCryptAlg] otherwise)
     * and prepares a message for forwarding to the returned endpoint (via Forward protocol).
     *
     * It's possible to add non-repudiation by providing [PackEncryptedParams.signFrom] argument (DID or key ID).
     * Signed messages are only necessary when
     *  - the origin of plaintext must be provable to third parties;
     *  - or the sender can’t be proven to the recipient by authenticated encryption because the recipient
     *    is not known in advance (e.g., in a broadcast scenario).
     *
     * Adding a signature when one is not needed can degrade rather than enhance security because it
     * relinquishes the sender’s ability to speak off the record.
     *
     * Encryption is done as follows:
     *  - encryption is done via the keys from the [DIDDoc.keyAgreements] verification relationship in the DID Doc;
     *  - if [PackEncryptedParams.from] is `null`, then anonymous encryption is done
     *    Otherwise authenticated encryption is done;
     *  - if [PackEncryptedParams.from] is a DID, then the first sender's [DIDDoc.keyAgreements] verification method
     *    is used which can be resolved via secrets resolver and has the same type as any of recipient keys;
     *  - if [PackEncryptedParams.from] is a key ID, then the sender's [DIDDoc.keyAgreements] verification method
     *    identified by the given key ID is used;
     *  - if [PackEncryptedParams.to] is a DID, then multiplex encryption is done for all keys from the receiver's [DIDDoc.keyAgreements]
     *    verification relationship which have the same type as the sender's key;
     *  - if  [PackEncryptedParams.to] is a key ID, then encryption is done for the receiver's [DIDDoc.keyAgreements]
     *    verification method identified by the given key ID.
     *
     * If non-repudiation (signing) is added by specifying a [PackEncryptedParams.signFrom] argument:
     *  - Signing is done via the keys from the [DIDDoc.authentications] verification relationship
     *    in the DID Doc for the DID to be used for signing;
     *  - If [PackEncryptedParams.signFrom] is a DID, then the first sender's [DIDDoc.authentications]
     *    verification method is used for which a private key in the secrets resolver is found;
     *  - If [PackEncryptedParams.signFrom] is a key ID, then the sender's [DIDDoc.authentications]
     *    verification method identified by the given key ID is used.
     *
     * @param params Pack Encrypted Parameters.
     * @return Result of pack encrypted operation.
     */
    fun packEncrypted(params: PackEncryptedParams): PackEncryptedResult {
        val didDocResolver = params.didDocResolver ?: this.didDocResolver
        val secretResolver = params.secretResolver ?: this.secretResolver
        val senderKeySelector = SenderKeySelector(didDocResolver, secretResolver)

        val (message, fromPriorIssuerKid) = packFromPrior(params.message, params.fromPriorIssuerKid, senderKeySelector)
        val (payload, signFromKid) = signIfNeeded(message.toString(), params, senderKeySelector)
        val (encryptedResult, recipientKeys) = encrypt(params, payload, senderKeySelector)
        var (packedMessage) = protectSenderIfNeeded(params, encryptedResult, recipientKeys)

        val didServicesChain = resolveDidServicesChain(
            didDocResolver, params.to, params.forwardServiceId
        )

        val wrapInForwardResult = wrapInForwardIfNeeded(
            params, didServicesChain, senderKeySelector
        )

        if (wrapInForwardResult != null)
            packedMessage = wrapInForwardResult.msg.toString()

        val serviceMetadata = if (didServicesChain.isEmpty()) null else ServiceMetadata(
            didServicesChain.last().id,
            didServicesChain.first().serviceEndpoint
        )

        return PackEncryptedResult(
            packedMessage,
            encryptedResult.toKids,
            encryptedResult.fromKid,
            signFromKid,
            fromPriorIssuerKid,
            serviceMetadata
        )
    }

    /**
     *  Unpacks the packed DIDComm message by doing decryption and verifying the signatures.
     *
     *  @param params Unpack Parameters.
     *  @return Result of Unpack Operation.
     */
    fun unpack(params: UnpackParams): UnpackResult {
        val didDocResolver = params.didDocResolver ?: this.didDocResolver
        val secretResolver = params.secretResolver ?: this.secretResolver
        val recipientKeySelector = RecipientKeySelector(didDocResolver, secretResolver)

        return unpack(params, recipientKeySelector)
    }

    /**
     *  Unpacks the packed DIDComm Forward message by doing decryption and verifying the signatures.
     *
     *  @param params Unpack Parameters.
     *  @return Result of Unpack Forward Operation.
     */
    fun unpackForward(params: UnpackParams): UnpackForwardResult {
        val didDocResolver = params.didDocResolver ?: this.didDocResolver
        val secretResolver = params.secretResolver ?: this.secretResolver
        val recipientKeySelector = RecipientKeySelector(didDocResolver, secretResolver)

        return unpackForward(params, recipientKeySelector)
    }
}
