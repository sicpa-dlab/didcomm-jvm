package org.dif.message

import org.dif.common.JSON

interface AttachmentData {
    val hash: String?
    val jws: JSON?
    fun toJSONObject(): Map<String, Any?>
}

data class AttachmentDataLinks(
    val links: List<String>,
    override val hash: String,
    override val jws: JSON? = null,
): AttachmentData {
    override fun toJSONObject(): Map<String, Any?> = mapOf(
        "hash" to hash,
        "jws" to jws?.toString(),
        "links" to links
    )
}

data class AttachmentDataBase64(
    val base64: String,
    override val hash: String? = null,
    override val jws: JSON? = null,
): AttachmentData {
    override fun toJSONObject(): Map<String, Any?> = mapOf(
        "hash" to hash,
        "jws" to jws?.toString(),
        "base64" to base64
    )
}


data class AttachmentDataJson(
    val json: JSON,
    override val hash: String? = null,
    override val jws: JSON? = null,
): AttachmentData {
    override fun toJSONObject(): Map<String, Any?> = mapOf(
        "hash" to hash,
        "jws" to jws?.toString(),
        "json" to jws?.toString(),
    )
}

data class Attachment(
    val id: String,
    val data: AttachmentData,
    val description: String?,
    val filename: String?,
    val mimeType: String?,
    val format: String?,
    val lastModTime: Int?,
    val byteCount: Int?,
) {
    private constructor(builder: Builder) : this(
        builder.id,
        builder.data,
        builder.description,
        builder.filename,
        builder.mimeType,
        builder.format,
        builder.lastModTime,
        builder.byteCount
    )

    companion object {
        fun builder(id: String, data: AttachmentData) = Builder(id, data)
    }

    class Builder(val id: String, val data: AttachmentData) {
        var filename: String? = null
            private set

        var format: String? = null
            private set

        var lastModTime: Int? = null
            private set

        var description: String? = null
            private set

        var mimeType: String? = null
            private set

        var byteCount: Int? = null
            private set

        fun filename(filename: String) = apply { this.filename = filename }
        fun lastModTime(lastModTime: Int) = apply { this.lastModTime = lastModTime }
        fun format(format: String) = apply { this.format = format }
        fun description(description: String) = apply { this.description = description }
        fun mimeType(mimeType: String) = apply { this.mimeType = mimeType }
        fun byteCount(byteCount: Int) = apply { this.byteCount = byteCount }

        fun build() = Attachment(this)
    }

    fun toJSONObject(): Map<String, Any?> = mapOf(
        "id" to id,
        "data" to data,
        "description" to description,
        "filename" to filename,
        "mime_type" to mimeType,
        "format" to format,
        "lastmod_time" to lastModTime,
        "byte_count" to byteCount,
    )
}
