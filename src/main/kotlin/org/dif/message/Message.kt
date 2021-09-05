package org.dif.message

import org.dif.common.Typ
import org.dif.exceptions.DIDCommException
import org.dif.exceptions.MalformedMessageException
import org.dif.utils.getTyped
import org.dif.utils.getTypedArray
import org.dif.utils.toJSONString

data class Message(
    val id: String,
    val body: Map<String, Any>,
    val type: String,
    val typ: Typ,
    val from: String?,
    val to: List<String>?,
    val createdTime: Long?,
    val expiresTime: Long?,
    val fromPrior: FromPrior?,
    val attachments: List<Attachment>?,
    val pleaseAck: Boolean?,
    val ack: String?,
    val thid: String?,
    val pthid: String?,
    val customHeaders: Map<String, Any?>,
) {
    inline fun <reified T> customHeader(name: String) = customHeaders.getTyped<T>(name)

    private constructor(builder: Builder) : this(
        builder.id,
        builder.body,
        builder.type,
        builder.typ,
        builder.from,
        builder.to,
        builder.createdTime,
        builder.expiresTime,
        builder.fromPrior,
        builder.attachments,
        builder.pleaseAck,
        builder.ack,
        builder.thid,
        builder.pthid,
        builder.customHeaders.toMap(),
    )

    companion object {
        class Header {
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
            }
        }

        val reservedHeaderNames = setOf(
            Header.Id,
            Header.Typ,
            Header.Type,
            Header.From,
            Header.To,
            Header.CreatedTime,
            Header.ExpiresTime,
            Header.Body,
            Header.Attachments,
            Header.FromPrior,
            Header.PleaseAck,
            Header.Ack,
            Header.Thid,
            Header.Pthid
        )

        fun builder(id: String, body: Map<String, Any>, type: String) = Builder(id, body, type)

        fun parse(json: Map<String, Any>): Message = let {
            val id = json.getTyped<String>(Header.Id)
                ?: throw MalformedMessageException("The header \"${Header.Id}\" is missing")

            val body = json.getTyped<Map<String, Any>>(Header.Body)
                ?: throw MalformedMessageException("The header \"${Header.Body}\" is missing")

            val type = json.getTyped<String>(Header.Type)
                ?: throw MalformedMessageException("The header \"${Header.Type}\" is missing")

            val builder = builder(id, body, type)

            json.keys.forEach {
                when (it) {
                    Header.Id, Header.Typ, Header.Type, Header.Body -> {}
                    Header.From -> builder.from(json.getTyped(it))
                    Header.To -> builder.to(json.getTyped(it))
                    Header.CreatedTime -> builder.createdTime(json.getTyped(it))
                    Header.ExpiresTime -> builder.expiresTime(json.getTyped(it))
                    Header.Attachments -> builder.attachments(Attachment.parse(json.getTypedArray(Header.Attachments)))
                    Header.FromPrior -> builder.fromPrior(FromPrior.parse(json.getTyped(it)))
                    Header.PleaseAck -> builder.pleaseAck(json.getTyped(it))
                    Header.Ack -> builder.ack(json.getTyped(it))
                    Header.Thid -> builder.thid(json.getTyped(it))
                    Header.Pthid -> builder.pthid(json.getTyped(it))
                    else -> builder.customHeader(it, json[it])
                }
            }

            builder.build()
        }
    }

    class Builder(val id: String, val body: Map<String, Any>, val type: String) {
        var typ: Typ = Typ.Plaintext

        var from: String? = null
            private set

        var to: List<String>? = null
            private set

        var createdTime: Long? = null
            private set

        var expiresTime: Long? = null
            private set

        var customHeaders: MutableMap<String, Any?> = mutableMapOf()
            private set

        var attachments: List<Attachment>? = null
            private set

        var fromPrior: FromPrior? = null
            private set

        var pleaseAck: Boolean? = null
            private set

        var ack: String? = null
            private set

        var thid: String? = null
            private set

        var pthid: String? = null
            private set

        fun from(from: String?) = apply { this.from = from }
        fun to(to: List<String>?) = apply { this.to = to }
        fun createdTime(createdTime: Long?) = apply { this.createdTime = createdTime }
        fun expiresTime(expiresTime: Long?) = apply { this.expiresTime = expiresTime }
        fun fromPrior(fromPrior: FromPrior?) = apply { this.fromPrior = fromPrior }
        fun attachments(attachments: List<Attachment>?) = apply { this.attachments = attachments }
        fun pleaseAck(pleaseAck: Boolean?) = apply { this.pleaseAck = pleaseAck }
        fun ack(ack: String?) = apply { this.ack = ack }
        fun thid(thid: String?) = apply { this.thid = thid }
        fun pthid(pthid: String?) = apply { this.pthid = pthid }
        fun customHeader(name: String, value: Any?) = apply {
            if (reservedHeaderNames.contains(name))
                throw DIDCommException("The header name '$name' is reserved")

            customHeaders[name] = value
        }

        fun build() = Message(this)
    }

    fun toJSONObject() = mapOf(
        Header.Id to id,
        Header.Typ to typ.typ,
        Header.Type to type,
        Header.From to from,
        Header.To to to,
        Header.CreatedTime to createdTime,
        Header.ExpiresTime to expiresTime,
        Header.Body to body,
        Header.Attachments to attachments?.map { it.toJSONObject() },
        Header.FromPrior to fromPrior,
        Header.PleaseAck to pleaseAck,
        Header.Ack to ack,
        Header.Thid to thid,
        Header.Pthid to pthid,
        Header.FromPrior to fromPrior?.toJSONObject(),
        *customHeaders.entries.map { Pair(it.key, it.value) }.toTypedArray()
    ).filterValues { it != null }

    override fun toString(): String =
        toJSONObject().toJSONString()
}
