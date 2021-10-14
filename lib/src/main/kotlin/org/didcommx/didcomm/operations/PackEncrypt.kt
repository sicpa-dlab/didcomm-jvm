package org.didcommx.didcomm.operations

import org.didcommx.didcomm.crypto.EncryptResult
import org.didcommx.didcomm.crypto.anonEncrypt
import org.didcommx.didcomm.crypto.authEncrypt
import org.didcommx.didcomm.crypto.key.Key
import org.didcommx.didcomm.crypto.key.SenderKeySelector
import org.didcommx.didcomm.crypto.sign
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.protocols.routing.WrapInForwardResult
import org.didcommx.didcomm.protocols.routing.wrapInForward
import org.didcommx.didcomm.utils.fromJsonToMap

fun signIfNeeded(message: String, params: PackEncryptedParams, keySelector: SenderKeySelector) =
    if (params.signFrom != null) {
        val key = keySelector.findSigningKey(params.signFrom)
        Pair(sign(message, key), key.id)
    } else {
        Pair(message, null)
    }

fun encrypt(params: PackEncryptedParams, payload: String, keySelector: SenderKeySelector) =
    if (params.from != null) {
        val (senderKey, recipientKeys) = keySelector.findAuthCryptKeys(params.from, params.to)
        Pair(authEncrypt(payload, params.encAlgAuth, senderKey, recipientKeys), recipientKeys)
    } else {
        val recipientKeys = keySelector.findAnonCryptKeys(params.to)
        Pair(anonEncrypt(payload, params.encAlgAnon, recipientKeys), recipientKeys)
    }

fun protectSenderIfNeeded(params: PackEncryptedParams, encryptResult: EncryptResult, recipientKeys: List<Key>) =
    if (params.protectSenderId && params.from != null) {
        anonEncrypt(encryptResult.packedMessage, params.encAlgAnon, recipientKeys)
    } else {
        encryptResult
    }

fun wrapInForwardIfNeeded(
    packedMessage: String,
    params: PackEncryptedParams,
    didServicesChain: List<DIDCommService>,
    senderKeySelector: SenderKeySelector
): WrapInForwardResult? {

    if (!(params.forward && didServicesChain.size > 0))
        return null

    // last service is for 'to' DID
    var routingKeys = didServicesChain.last().routingKeys

    // TODO test
    if (routingKeys.size == 0)
        return null

    // prepend routing with alternative endpoints
    // starting from the second mediator if any
    // (the first one considered to have URI endpoint)
    // cases:
    //   ==1 usual sender forward process
    //   >1 alternative endpoints
    //   >2 alternative endpoints recursion
    // TODO
    //   - case: a mediator's service has non-empty routing keys
    //     list (not covered by the spec for now)
    if (didServicesChain.size > 1)
        routingKeys = (
            didServicesChain.drop(1).map { it.serviceEndpoint } +
                routingKeys
            )

    return wrapInForward(
        fromJsonToMap(packedMessage),
        params.to,
        senderKeySelector,
        params.encAlgAnon,
        routingKeys,
        params.forwardHeaders
    )
}
