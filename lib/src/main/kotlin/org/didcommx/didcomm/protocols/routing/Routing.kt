package org.didcommx.didcomm.protocols.routing

import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.crypto.EncryptResult
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
import org.didcommx.didcomm.crypto.key.SenderKeySelector
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.exceptions.DIDCommServiceException
import org.didcommx.didcomm.exceptions.DIDDocException
import org.didcommx.didcomm.exceptions.DIDDocNotResolvedException
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackEncryptedResult
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.operations.encrypt
import org.didcommx.didcomm.operations.unpack
import org.didcommx.didcomm.secret.SecretResolver
import org.didcommx.didcomm.utils.didcommIdGeneratorDefault
import org.didcommx.didcomm.utils.getDid
import org.didcommx.didcomm.utils.isDIDOrDidUrl

/**
 * Result of wrapInForward message operation.
 *
 * @property msg the forward message wrapping the original one
 * @property msgEncrypted the forward message encryption result
 */
data class WrapInForwardResult(
    val msg: ForwardMessage,
    val msgEncrypted: PackEncryptedResult
)

/**
 * Result of unpackForward operation.
 *
 * @property forwardMsg the unpacked forward message
 * @property forwardedMsgEncryptedTo Target key IDs used for encryption
 */
data class UnpackForwardResult(
    val forwardMsg: ForwardMessage,
    val forwardedMsgEncryptedTo: List<String>? = null
)

const val PROFILE_DIDCOMM_AIP1 = "didcomm/aip1"
const val PROFILE_DIDCOMM_AIP2_ENV_RFC19 = "didcomm/aip2;env=rfc19"
const val PROFILE_DIDCOMM_AIP2_ENV_RFC587 = "didcomm/aip2;env=rfc587"
const val PROFILE_DIDCOMM_V2 = "didcomm/v2"

internal fun findDIDCommService(
    didDocResolver: DIDDocResolver,
    to: String,
    serviceId: String? = null
): DIDCommService? {

    val toDid = getDid(to)
    val didDoc = didDocResolver.resolve(toDid).orElseThrow { throw DIDDocNotResolvedException(toDid) }

    if (serviceId != null) {
        val didService = didDoc.findDIDCommService(serviceId)

        if (didService.accept != null && !didService.accept.isEmpty() && PROFILE_DIDCOMM_V2 !in didService.accept) {
            throw DIDCommServiceException(
                toDid, "service '$serviceId' does not accept didcomm/v2 profile"
            )
        }
        return didService
    } else {
        // Find the first service accepting `didcomm/v2` profile because the spec states:
        // > Entries SHOULD be specified in order of receiver preference,
        // > but any endpoint MAY be selected by the sender, typically
        // > by protocol availability or preference.
        // https://identity.foundation/didcomm-messaging/spec/#multiple-endpoints
        return try {
            didDoc.didCommServices.find { it.accept == null || it.accept.isEmpty() || PROFILE_DIDCOMM_V2 in it.accept }
        } catch (e: DIDDocException) {
            null
        }
    }
}

internal fun resolveDIDCommServicesChain(
    didDocResolver: DIDDocResolver,
    to: String,
    serviceId: String? = null,
    didRecursion: Boolean = false
): List<DIDCommService> {

    val toDidService = findDIDCommService(didDocResolver, to, serviceId) ?: return listOf()

    val res = mutableListOf<DIDCommService>()
    var serviceUri = toDidService.serviceEndpoint

    res.add(0, toDidService)

    // alternative endpoints
    while (isDIDOrDidUrl(serviceUri)) {
        val mediatorDid = serviceUri

        if (res.size > 1) {
            // TODO cover possible case of alternative endpoints in mediator's
            //      DID Doc services (it SHOULD NOT be as per spec but ...)
            val errMsg = (
                "mediator '${res.last().serviceEndpoint}' defines alternative" +
                    " endpoint '$serviceUri' recursively"
                )

            if (didRecursion) {
                throw NotImplementedError(errMsg)
            } else {
                throw DIDCommServiceException(res.last().serviceEndpoint, errMsg)
            }
        }

        // TODO check not only first item in mediator services list
        //      (e.g. first one may use alternative endpoint but second - URI)

        // resolve until final URI is reached
        val mediatorDidService = findDIDCommService(didDocResolver, mediatorDid)
            ?: throw DIDCommServiceException(
                mediatorDid, "mediator '$mediatorDid' service doc not found"
            )

        serviceUri = mediatorDidService.serviceEndpoint
        res.add(0, mediatorDidService)
    }

    return res
}

/**
 * Routing protocol operations
 *
 */
class Routing(private val didDocResolver: DIDDocResolver, private val secretResolver: SecretResolver) {

    /**
     * Wraps the given packed DIDComm message in a Forward messages for every routing key.
     *
     * @param packedMsg the message to be wrapped in Forward
     * @param to final recipient's DID (DID URL)
     * @param encAlgAnon The encryption algorithm to be used for anonymous encryption (anon_crypt).
     * @param routingKeys a list of routing keys
     * @param headers optional headers for Forward message
     * @param didDocResolver Sets Optional DIDDoc resolver that can override a default DIDDoc resolver.
     * @param secretResolver Sets Optional Secret resolver that can override a default Secret resolver.
     *
     * @throws DIDCommException if pack can not be done, in particular:
     *  - DIDDocException If a DID or DID URL (for example a key ID) can not be resolved to a DID Doc.
     *  - SecretNotFoundException If there is no secret for the given DID or DID URL (key ID)
     *  - DIDCommIllegalArgumentException If invalid input is provided.
     *  - IncompatibleCryptoException If the sender and target crypto is not compatible (for example, there are no compatible keys for key agreement)
     *
     * @return Result of wrapping operation
     */
    fun wrapInForward(
        packedMsg: Map<String, Any>,
        to: String,
        encAlgAnon: AnonCryptAlg? = null,
        routingKeys: List<String>? = null,
        headers: Map<String, Any?>? = null,
        didDocResolver: DIDDocResolver? = null,
        secretResolver: SecretResolver? = null
    ): WrapInForwardResult? {
        // means forward protocol is not needed
        if (routingKeys == null || routingKeys.isEmpty())
            return null

        val _didDocResolver = didDocResolver ?: this.didDocResolver
        val _secretResolver = secretResolver ?: this.secretResolver
        val keySelector = SenderKeySelector(_didDocResolver, _secretResolver)

        // TODO
        //  - headers validation against ForwardMessage
        //  - logging
        //  - id generator as an argument

        lateinit var fwdMsg: ForwardMessage
        var forwardedMsg = packedMsg
        lateinit var encryptedResult: EncryptResult

        val tos = routingKeys.asReversed()
        val nexts = (routingKeys.drop(1) + to).asReversed()

        // wrap forward msgs in reversed order so the message to final
        // recipient 'to' will be the innermost one
        for ((_to, _next) in tos.zip(nexts)) {

            val fwdMsgBuilder = ForwardMessage.builder(
                didcommIdGeneratorDefault(),
                _next,
                forwardedMsg
            )
            headers?.forEach { (name, value) ->
                fwdMsgBuilder.customHeader(name, value)
            }

            fwdMsg = fwdMsgBuilder.buildForward()

            // TODO improve: do not rebuild each time 'to' is changed
            val packParamsBuilder = PackEncryptedParams.Builder(fwdMsg.message, _to)

            if (encAlgAnon != null)
                packParamsBuilder.encAlgAnon(encAlgAnon)

            encryptedResult = encrypt(
                packParamsBuilder.build(), fwdMsg.message.toString(), keySelector
            ).first

            forwardedMsg = JSONObjectUtils.parse(encryptedResult.packedMessage)
        }

        return WrapInForwardResult(
            fwdMsg,
            PackEncryptedResult(
                encryptedResult.packedMessage,
                encryptedResult.toKids,
                encryptedResult.fromKid,
            )
        )
    }

    /**
     *  Unpacks the packed DIDComm Forward message by doing decryption and verifying the signatures.
     *
     *  @param packedMessage a Forward message as JSON string to be unpacked
     *  @param expectDecryptByAllKeys Whether the message must be decryptable by all keys resolved by the secrets resolver. False by default.
     *  @param didDocResolver Sets Optional DIDDoc resolver that can override a default DIDDoc resolver.
     *  @param secretResolver Sets Optional Secret resolver that can override a default Secret resolver.
     *
     * @throws DIDCommException if unpack can not be done, in particular:
     *   - MalformedMessageException if the message is invalid (can not be decrypted, signature is invalid, the plaintext is invalid, etc.)
     *   - DIDDocException If a DID or DID URL (for example a key ID) can not be resolved to a DID Doc.
     *   - SecretNotFoundException If there is no secret for the given DID or DID URL (key ID)
     *
     *  @return Result of Unpack Forward Operation.
     */
    fun unpackForward(
        packedMessage: String,
        expectDecryptByAllKeys: Boolean = false,
        didDocResolver: DIDDocResolver? = null,
        secretResolver: SecretResolver? = null
    ): UnpackForwardResult {
        val _didDocResolver = didDocResolver ?: this.didDocResolver
        val _secretResolver = secretResolver ?: this.secretResolver
        val recipientKeySelector = RecipientKeySelector(_didDocResolver, _secretResolver)

        val unpackResult = unpack(
            UnpackParams.Builder(packedMessage)
                .expectDecryptByAllKeys(expectDecryptByAllKeys)
                .unwrapReWrappingForward(false)
                .build(),
            recipientKeySelector
        )
        val forwardMessage = ForwardMessage.fromMessage(unpackResult.message)

        return forwardMessage?.let {
            UnpackForwardResult(
                it,
                unpackResult.metadata.encryptedTo
            )
        }
            ?: throw MalformedMessageException("Invalid forward message")
    }
}
