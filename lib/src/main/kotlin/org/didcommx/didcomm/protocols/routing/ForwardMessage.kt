package org.didcommx.didcomm.protocols.routing

import org.didcommx.didcomm.common.DIDCommMessageProtocolTypes
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.didcommx.didcomm.utils.didcommIdGeneratorDefault
import org.didcommx.didcomm.utils.getTyped

class ForwardMessage(
    val message: Message,
    val forwardedMsg: Map<String, Any>,
    val forwardNext: String
) {

    companion object {
        fun builder(id: String, next: String, forwardedMsg: Map<String, Any>) =
            ForwardMessageBuilder(id, next, forwardedMsg)

        fun fromMessage(message: Message): ForwardMessage? {
            val forwardTo = message.body["next"]
                ?: return null
            val forwardedMsg = message.attachments?.let { it[0].data.toJSONObject().getTyped<Map<String, Any>>("json") }
                ?: return null
            if (forwardTo !is String)
                return null

            return ForwardMessage(
                message,
                forwardedMsg = forwardedMsg,
                forwardNext = forwardTo
            )
        }

        fun parse(json: Map<String, Any>) =
            fromMessage(Message.parse(json))
    }
}

class ForwardMessageBuilder(id: String, private val forwardTo: String, private val forwardedMsg: Map<String, Any>) :
    MessageBuilder(id, mapOf("next" to forwardTo), DIDCommMessageProtocolTypes.Forward.typ) {

    fun buildForward() =
        attachments(
            listOf(
                Attachment.builder(
                    didcommIdGeneratorDefault(), Attachment.Data.Json(forwardedMsg)
                ).build()
            )
        ).let {
            ForwardMessage(
                super.build(), forwardedMsg, forwardTo
            )
        }
}
