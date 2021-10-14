package org.didcommx.didcomm.operations

import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.common.DIDCommMessageProtocolTypes
import org.didcommx.didcomm.crypto.EncryptResult
import org.didcommx.didcomm.crypto.key.SenderKeySelector
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackEncryptedResult
import org.didcommx.didcomm.utils.didcommIdGeneratorDefault

/**
 * Result of wrapInForward message operation.
 *
 * TODO docs
 */
data class WrapInForwardResult(
    val msg: Message,
    val msgEncrypted: PackEncryptedResult
)

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
