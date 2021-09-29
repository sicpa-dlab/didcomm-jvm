package org.dif.message

import org.dif.exceptions.MalformedMessageException
import org.dif.utils.getTyped
import org.dif.utils.getTypedArray
import org.dif.utils.toJSONString

data class Attachment(
    val id: String,
    val data: Data,
    val description: String?,
    val filename: String?,
    val mediaType: String?,
    val format: String?,
    val lastModTime: Long?,
    val byteCount: Long?,
) {
    sealed interface Data {
        val hash: String?
        val jws: Map<String, Any>?
        fun toJSONObject(): Map<String, Any?>

        companion object {
            fun parse(json: Map<String, Any?>): Data = when {
                json.containsKey(Header.Json) -> Json.parse(json)
                json.containsKey(Header.Links) -> Links.parse(json)
                json.containsKey(Header.Base64) -> Base64.parse(json)
                else -> throw MalformedMessageException("Unknown attachment data")
            }
        }

        data class Links(
            val links: List<String>,
            override val hash: String,
            override val jws: Map<String, Any>? = null,
        ) : Data {
            companion object {
                fun parse(json: Map<String, Any?>): Links {
                    val links = json.getTypedArray<String>(Header.Links)
                        ?.filterNotNull()
                        ?.toList()
                        ?: throw MalformedMessageException("The header \"${Header.Links}\" is missing")

                    val hash = json.getTyped<String>(Header.Hash)
                        ?: throw MalformedMessageException("The header \"${Header.Hash}\" is missing")

                    val jws = json.getTyped<Map<String, Any>>(Header.Jws)

                    return Links(links, hash, jws)
                }
            }

            override fun toJSONObject(): Map<String, Any?> = mapOf(
                Header.Jws to jws,
                Header.Hash to hash,
                Header.Links to links
            )
        }

        data class Base64(
            val base64: String,
            override val hash: String? = null,
            override val jws: Map<String, Any>? = null,
        ) : Data {
            companion object {
                fun parse(json: Map<String, Any?>): Base64 {
                    val base64 = json.getTyped<String>(Header.Base64)
                        ?: throw MalformedMessageException("The header \"${Header.Base64}\" is missing")

                    val hash = json.getTyped<String>(Header.Hash)
                    val jws = json.getTyped<Map<String, Any>>(Header.Jws)

                    return Base64(base64, hash, jws)
                }
            }

            override fun toJSONObject(): Map<String, Any?> = mapOf(
                Header.Jws to jws,
                Header.Hash to hash,
                Header.Base64 to base64
            )
        }

        data class Json(
            val json: Map<String, Any>?,
            override val hash: String? = null,
            override val jws: Map<String, Any>? = null,
        ) : Data {
            companion object {
                fun parse(json: Map<String, Any?>): Json {
                    val jsonData = json.getTyped<Map<String, Any>>(Header.Json)
                        ?: throw MalformedMessageException("The header \"${Header.Json}\" is missing")

                    val hash = json.getTyped<String>(Header.Hash)
                    val jws = json.getTyped<Map<String, Any>>(Header.Jws)

                    return Json(jsonData, hash, jws)
                }
            }

            override fun toJSONObject(): Map<String, Any?> = mapOf(
                Header.Jws to jws,
                Header.Hash to hash,
                Header.Json to json,
            )
        }
    }

    private constructor(builder: Builder) : this(
        builder.id,
        builder.data,
        builder.description,
        builder.filename,
        builder.mediaType,
        builder.format,
        builder.lastModTime,
        builder.byteCount
    )

    companion object {
        class Header {
            companion object {
                const val Id = "id"
                const val Data = "data"
                const val Description = "description"
                const val Filename = "filename"
                const val MediaType = "media_type"
                const val Format = "format"
                const val LastmodTime = "lastmod_time"
                const val ByteCount = "byte_count"
                const val Hash = "hash"
                const val Jws = "jws"
                const val Json = "json"
                const val Base64 = "base64"
                const val Links = "links"
            }
        }

        fun builder(id: String, data: Data) = Builder(id, data)

        fun parse(attachments: Array<Map<String, Any?>?>?): List<Attachment>? =
            attachments?.mapNotNull { parse(it) }

        private fun parse(json: Map<String, Any?>?): Attachment? = json?.let {
            val id = json.getTyped<String>(Header.Id)
                ?: throw MalformedMessageException("The header \"${Header.Id}\" is missing")

            val data = json.getTyped<Map<String, Any>>(Header.Data)
                ?.let { Data.parse(it) }
                ?: throw MalformedMessageException("The header \"${Header.Data}\" is missing")

            val builder = builder(id, data)

            json.keys.forEach {
                when (it) {
                    Header.Id, Header.Data -> {}
                    Header.Description -> builder.description(json.getTyped(it))
                    Header.Filename -> builder.filename(json.getTyped(it))
                    Header.MediaType -> builder.mediaType(json.getTyped(it))
                    Header.Format -> builder.format(json.getTyped(it))
                    Header.LastmodTime -> builder.lastModTime(json.getTyped(it))
                    Header.ByteCount -> builder.byteCount(json.getTyped(it))
                    else -> throw MalformedMessageException("Unknown attachment's header: $it")
                }
            }

            builder.build()
        }
    }

    class Builder(val id: String, val data: Data) {
        var filename: String? = null
            private set

        var format: String? = null
            private set

        var lastModTime: Long? = null
            private set

        var description: String? = null
            private set

        var mediaType: String? = null
            private set

        var byteCount: Long? = null
            private set

        fun filename(filename: String?) = apply { this.filename = filename }
        fun lastModTime(lastModTime: Long?) = apply { this.lastModTime = lastModTime }
        fun format(format: String?) = apply { this.format = format }
        fun description(description: String?) = apply { this.description = description }
        fun mediaType(mediaType: String?) = apply { this.mediaType = mediaType }
        fun byteCount(byteCount: Long?) = apply { this.byteCount = byteCount }

        fun build() = Attachment(this)
    }

    fun toJSONObject(): Map<String, Any?> = mapOf(
        Header.Id to id,
        Header.Data to data.toJSONObject(),
        Header.Description to description,
        Header.Filename to filename,
        Header.MediaType to mediaType,
        Header.Format to format,
        Header.LastmodTime to lastModTime,
        Header.ByteCount to byteCount,
    ).filterValues { it != null }

    override fun toString(): String =
        toJSONObject().toJSONString()
}
