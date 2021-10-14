package org.didcommx.didcomm.protocols.routing

import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.common.DIDCommMessageProtocolTypes
import org.didcommx.didcomm.crypto.EncryptResult
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
import org.didcommx.didcomm.crypto.key.SenderKeySelector
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.exceptions.DIDCommServiceException
import org.didcommx.didcomm.exceptions.DIDDocException
import org.didcommx.didcomm.exceptions.DIDDocNotResolvedException
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackEncryptedResult
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.operations.encrypt
import org.didcommx.didcomm.operations.unpack
import org.didcommx.didcomm.utils.didcommIdGeneratorDefault
import org.didcommx.didcomm.utils.getDid
import org.didcommx.didcomm.utils.isDIDOrDidUrl

/**
 * Result of wrapInForward message operation.
 *
 * TODO docs
 */
data class WrapInForwardResult(
    val msg: Message,
    val msgEncrypted: PackEncryptedResult
)

/**
 * Result of unpackForward operation.
 *
 * TODO docs
 */
data class UnpackForwardResult(
    val forwardMsg: Message,
    val forwardedMsg: Map<String, Any>,
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

        if (PROFILE_DIDCOMM_V2 !in didService.accept) {
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
            didDoc.didCommServices.find { PROFILE_DIDCOMM_V2 in it.accept }
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

fun wrapInForward(
    packedMsg: Map<String, Any>,
    to: String,
    keySelector: SenderKeySelector,
    encAlgAnon: AnonCryptAlg? = null,
    routingKeys: List<String>? = null,
    headers: Map<String, Any?>? = null
): WrapInForwardResult? {
    // means forward protocol is not needed
    if (routingKeys == null)
        return null

    // TODO
    //  - headers validation against ForwardMessage
    //  - logging
    //  - id generator as an argument

    var fwdMsg: Message? = null
    var forwardedMsg = packedMsg
    var encryptedResult: EncryptResult? = null

    val tos = routingKeys.asReversed()
    val nexts = (routingKeys.drop(1) + to).asReversed()

    // wrap forward msgs in reversed order so the message to final
    // recipient 'to' will be the innermost one
    for ((_to, _next) in tos.zip(nexts)) {
        val fwdAttach = Attachment.builder(
            didcommIdGeneratorDefault(), Attachment.Data.Json(forwardedMsg)
        ).build()
        // TODO ??? .mediaType("application/json")

        val fwdMsgBuilder = Message.builder(
            didcommIdGeneratorDefault(),
            mapOf("next" to _next),
            DIDCommMessageProtocolTypes.Forward.typ
        ).attachments(listOf(fwdAttach))

        headers?.forEach { (name, value) ->
            fwdMsgBuilder.customHeader(name, value)
        }

        fwdMsg = fwdMsgBuilder.build()

        // TODO improve: do not rebuild each time 'to' is changed
        val packParamsBuilder = PackEncryptedParams.Builder(fwdMsg, _to)

        if (encAlgAnon != null)
            packParamsBuilder.encAlgAnon(encAlgAnon)

        encryptedResult = encrypt(
            packParamsBuilder.build(), fwdMsg.toString(), keySelector
        ).first

        forwardedMsg = JSONObjectUtils.parse(encryptedResult.packedMessage)
    }

    encryptedResult = encryptedResult!!

    return WrapInForwardResult(
        fwdMsg!!,
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
 *  @param params Unpack Parameters.
 *  @return Result of Unpack Forward Operation.
 */
fun unpackForward(
    packedMessage: String,
    recipientKeySelector: RecipientKeySelector,
    expectDecryptByAllKeys: Boolean = false,
): UnpackForwardResult {
    val unpackResult = unpack(
        UnpackParams.Builder(packedMessage)
            .expectDecryptByAllKeys(expectDecryptByAllKeys)
            .unwrapReWrappingForward(false)
            .build(),
        recipientKeySelector
    )
    val forwardedMsg = unpackResult.message.forwardedMsg

    if (forwardedMsg != null) {
        return UnpackForwardResult(
            unpackResult.message,
            forwardedMsg,
            unpackResult.metadata.encryptedTo
        )
    } else {
        throw MalformedMessageException("Not a Forward message")
    }
}
