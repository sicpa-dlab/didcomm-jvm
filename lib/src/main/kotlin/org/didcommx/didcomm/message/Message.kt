package org.didcommx.didcomm.message

import org.didcommx.didcomm.common.Typ
import org.didcommx.didcomm.exceptions.DIDCommException
import org.didcommx.didcomm.exceptions.DIDCommIllegalArgumentException
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.utils.getTyped
import org.didcommx.didcomm.utils.getTypedArray
import org.didcommx.didcomm.utils.isDIDFragment
import org.didcommx.didcomm.utils.toJSONString

data class Message(
    val id: String,
    val body: Map<String, Any?>,
    val type: String,
    val typ: Typ,
    val from: String?,
    val to: List<String>?,
    val createdTime: Long?,
    val expiresTime: Long?,
    val fromPrior: FromPrior?,
    val fromPriorJwt: String?,
    val attachments: List<Attachment>?,
    val pleaseAck: Boolean?,
    val ack: String?,
    val thid: String?,
    val pthid: String?,
    val customHeaders: Map<String, Any?>,
) {

    inline fun <reified T> customHeader(name: String) = customHeaders.getTyped<T>(name)

    inline fun <reified T> customHeaderArray(name: String) = customHeaders.getTypedArray<T>(name)

    internal constructor(builder: MessageBuilder) : this(
        builder.id,
        builder.body,
        builder.type,
        builder.typ,
        builder.from,
        builder.to,
        builder.createdTime,
        builder.expiresTime,
        builder.fromPrior,
        builder.fromPriorJwt,
        builder.attachments,
        builder.pleaseAck,
        builder.ack,
        builder.thid,
        builder.pthid,
        builder.customHeaders.toMap(),
    )

    companion object {

        fun builder(id: String, body: Map<String, Any?>, type: String) = MessageBuilder(id, body, type)

        fun parse(json: Map<String, Any>): Message = let {
            val id = json.getTyped<String>(MessageHeader.Id)
                ?: throw MalformedMessageException("The header \"${MessageHeader.Id}\" is missing")

            val body = json.getTyped<Map<String, Any>>(MessageHeader.Body)
                ?: throw MalformedMessageException("The header \"${MessageHeader.Body}\" is missing")

            val type = json.getTyped<String>(MessageHeader.Type)
                ?: throw MalformedMessageException("The header \"${MessageHeader.Type}\" is missing")

            val builder = builder(id, body, type)

            json.keys.forEach {
                when (it) {
                    MessageHeader.Id, MessageHeader.Typ, MessageHeader.Type, MessageHeader.Body -> {
                    }
                    MessageHeader.From -> builder.from(json.getTyped(it))
                    MessageHeader.To -> builder.to(json.getTyped(it))
                    MessageHeader.CreatedTime -> builder.createdTime(json.getTyped(it))
                    MessageHeader.ExpiresTime -> builder.expiresTime(json.getTyped(it))
                    MessageHeader.Attachments -> builder.attachments(Attachment.parse(json.getTypedArray(MessageHeader.Attachments)))
                    MessageHeader.FromPrior -> builder.fromPriorJwt(json.getTyped(it))
                    MessageHeader.PleaseAck -> builder.pleaseAck(json.getTyped(it))
                    MessageHeader.Ack -> builder.ack(json.getTyped(it))
                    MessageHeader.Thid -> builder.thid(json.getTyped(it))
                    MessageHeader.Pthid -> builder.pthid(json.getTyped(it))
                    else -> builder.customHeader(it, json[it])
                }
            }

            builder.build()
        }
    }

    fun toJSONObject() = mapOf(
        MessageHeader.Id to id,
        MessageHeader.Typ to typ.typ,
        MessageHeader.Type to type,
        MessageHeader.From to from,
        MessageHeader.To to to,
        MessageHeader.CreatedTime to createdTime,
        MessageHeader.ExpiresTime to expiresTime,
        MessageHeader.Body to body,
        MessageHeader.Attachments to attachments?.map { it.toJSONObject() },
        MessageHeader.FromPrior to fromPriorJwt,
        MessageHeader.PleaseAck to pleaseAck,
        MessageHeader.Ack to ack,
        MessageHeader.Thid to thid,
        MessageHeader.Pthid to pthid,
        *customHeaders.entries.map { Pair(it.key, it.value) }.toTypedArray()
    ).filterValues { it != null }

    override fun toString(): String =
        toJSONObject().toJSONString()
}

internal class MessageHeader {
    companion object {
        const val Id = "id"
        const val Typ = "typ"
        const val Type = "type"
        const val From = "from"
        const val To = "to"
        const val CreatedTime = "created_time"
        const val ExpiresTime = "expires_time"
        const val Body = "body"
        const val Attachments = "attachments"
        const val FromPrior = "from_prior"
        const val PleaseAck = "please_ack"
        const val Ack = "ack"
        const val Thid = "thid"
        const val Pthid = "pthid"

        val reservedHeaderNames = setOf(
            Id, Typ, Type, From, To, CreatedTime, ExpiresTime,
            Body, Attachments, FromPrior, PleaseAck, Ack, Thid, Pthid
        )
    }
}

open class MessageBuilder(val id: String, val body: Map<String, Any?>, val type: String) {
    internal var typ: Typ = Typ.Plaintext

    internal var from: String? = null
        private set

    internal var to: List<String>? = null
        private set

    internal var createdTime: Long? = null
        private set

    internal var expiresTime: Long? = null
        private set

    internal var customHeaders: MutableMap<String, Any?> = mutableMapOf()
        private set

    internal var attachments: List<Attachment>? = null
        private set

    internal var fromPrior: FromPrior? = null
        private set

    internal var fromPriorJwt: String? = null
        private set

    internal var pleaseAck: Boolean? = null
        private set

    internal var ack: String? = null
        private set

    internal var thid: String? = null
        private set

    internal var pthid: String? = null
        private set

    fun from(from: String?) = apply {
        if (from != null && isDIDFragment(from))
            throw DIDCommIllegalArgumentException(from)
        this.from = from
    }

    fun to(to: List<String>?) = apply {
        if (to != null && to.any { to -> isDIDFragment(to) })
            throw DIDCommIllegalArgumentException(to.toString())
        this.to = to
    }

    fun createdTime(createdTime: Long?) = apply { this.createdTime = createdTime }
    fun expiresTime(expiresTime: Long?) = apply { this.expiresTime = expiresTime }
    fun fromPrior(fromPrior: FromPrior?) = apply { this.fromPrior = fromPrior }
    fun fromPriorJwt(fromPriorJwt: String?) = apply { this.fromPriorJwt = fromPriorJwt }
    fun attachments(attachments: List<Attachment>?) = apply { this.attachments = attachments }
    fun pleaseAck(pleaseAck: Boolean?) = apply { this.pleaseAck = pleaseAck }
    fun ack(ack: String?) = apply { this.ack = ack }
    fun thid(thid: String?) = apply { this.thid = thid }
    fun pthid(pthid: String?) = apply { this.pthid = pthid }
    fun customHeader(name: String, value: Any?) = apply {
        if (MessageHeader.reservedHeaderNames.contains(name))
            throw DIDCommException("The header name '$name' is reserved")

        customHeaders[name] = value
    }

    fun build() = Message(this)
}
