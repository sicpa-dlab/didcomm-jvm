package org.dif

import org.dif.common.AnonCryptAlg
import org.dif.common.AuthCryptAlg
import org.dif.crypto.ParseResult
import org.dif.crypto.key.RecipientKeySelector
import org.dif.crypto.key.SenderKeySelector
import org.dif.crypto.parse
import org.dif.crypto.sign
import org.dif.crypto.verify
import org.dif.diddoc.DIDDoc
import org.dif.diddoc.DIDDocResolver
import org.dif.exceptions.MalformedMessageException
import org.dif.message.Message
import org.dif.model.Metadata
import org.dif.model.PackEncryptedParams
import org.dif.model.PackEncryptedResult
import org.dif.model.PackPlaintextParams
import org.dif.model.PackPlaintextResult
import org.dif.model.PackSignedParams
import org.dif.model.PackSignedResult
import org.dif.model.UnpackParams
import org.dif.model.UnpackResult
import org.dif.secret.SecretResolver

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
        return PackPlaintextResult("")
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

        val key = senderKeySelector.signKey(params.signFrom)
        val msg = sign(params.message.toString(), key)

        return PackSignedResult(msg, params.signFrom)
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
        return PackEncryptedResult("", listOf(), "")
    }

    /**
     *  Unpacks the packed DIDComm message by doing decryption and verifying the signatures.
     *  If unpack config expects the message to be packed in a particular way (for example that a message is encrypted)
     *  and the packed message doesn't meet the criteria (it's not encrypted), then `UnsatisfiedConstraintError` will be raised.
     *
     *  @param params Unpack Parameters.
     *  @return Result of Unpack Operation.
     */
    fun unpack(params: UnpackParams): UnpackResult {
        val didDocResolver = params.didDocResolver ?: this.didDocResolver
        val secretResolver = params.secretResolver ?: this.secretResolver
        val recipientKeySelector = RecipientKeySelector(didDocResolver, secretResolver)

        return when (val parseResult = parse(params.packedMessage)) {
            is ParseResult.JWS -> let {
                val message = parseResult.message
                val kid = message.unprotectedHeader?.keyID
                    ?: throw MalformedMessageException("JWS Unprotected Per-Signature header must be present")

                val key = recipientKeySelector.verifyKey(kid)

                UnpackResult(
                    verify(message, key),
                    Metadata(encrypted = false, authenticated = false, nonRepudiation = false, anonymousSender = false, reWrappedInForward = false, listOf())
                )
            }

            else -> UnpackResult(
                Message.builder("", mapOf("" to ""), "").build(),
                Metadata(encrypted = false, authenticated = false, nonRepudiation = false, anonymousSender = false, reWrappedInForward = false, listOf())
            )
        }
    }
}
