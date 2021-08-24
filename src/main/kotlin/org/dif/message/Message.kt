package org.dif.message

import org.dif.common.Json

enum class TYP(typ: String) {
    Encrypted("application/didcomm-encrypted+json"),
    Signed("application/didcomm-signed+json"),
    Plaintext("application/didcomm-plain+json"),
}

class Message(
    val id: String,
    val payload: Json,
    val type: String,
    val typ: TYP,
    val from: String?,
    val to: List<String>?,
    val createdTime: Int?,
    val expiresTime: Int?,
    val headers: Map<String, Any>?,
    val fromPrior: FromPrior?,
    val attachments: List<Attachment>?,
    val pleaseAck: Boolean?,
    val ack: String?,
    val thid: String?,
    val pthid: String?
) {
    private constructor(builder: Builder) : this(
        builder.id,
        builder.payload,
        builder.type,
        builder.typ,
        builder.from,
        builder.to,
        builder.createdTime,
        builder.expiresTime,
        builder.headers,
        builder.fromPrior,
        builder.attachments,
        builder.pleaseAck,
        builder.ack,
        builder.thid,
        builder.pthid
    )

    companion object {
        fun builder() = Builder()
    }

    class Builder {
        lateinit var id: String
        lateinit var payload: Json
        lateinit var type: String
        lateinit var typ: TYP
        var from: String? = null
        var to: List<String>? = null
        var createdTime: Int? = null
        var expiresTime: Int? = null
        var headers: Map<String, Any>? = null
        var attachments: List<Attachment>? = null
        var fromPrior: FromPrior? = null
        var pleaseAck: Boolean? = null
        var ack: String? = null
        var thid: String? = null
        var pthid: String? = null

        fun id(id: String) = apply { this.id = id }
        fun payload(payload: Json) = apply { this.payload = payload }
        fun type(type: String) = apply { this.type = type }
        fun typ(typ: TYP) = apply { this.typ = typ }
        fun from(from: String) = apply { this.from = from }
        fun to(to: List<String>) = apply { this.to = to }
        fun createdTime(createdTime: Int) = apply { this.createdTime = createdTime }
        fun expiresTime(expiresTime: Int) = apply { this.expiresTime = expiresTime }
        fun headers(headers: Map<String, Any>) = apply { this.headers = headers }
        fun fromPrior(fromPrior: FromPrior) = apply { this.fromPrior = fromPrior }
        fun attachments(attachments: List<Attachment>) = apply { this.attachments = attachments }
        fun pleaseAck(pleaseAck: Boolean) = apply { this.pleaseAck = pleaseAck }
        fun ack(ack: String) = apply { this.ack = ack }
        fun thid(thid: String) = apply { this.thid = thid }
        fun pthid(pthid: String) = apply { this.pthid = pthid }

        fun build() = Message(this)
    }

    fun toJSONObject() = mapOf(
        "id" to id,
        "payload" to payload.toJSONObject(),
        "type" to type,
        "typ" to typ.name,
        "from" to from,
        "to" to to,
        "created_time" to createdTime,
        "expires_time" to expiresTime,
        "attachments" to attachments,
        "from_prior" to fromPrior,
        "please_ack" to pleaseAck,
        "ack" to ack,
        "thid" to thid,
        "pthid" to pthid
    )
}