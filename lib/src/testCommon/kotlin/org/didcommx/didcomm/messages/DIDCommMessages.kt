package org.didcommx.didcomm.messages

import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message

fun attachmentMulti1msg(): Message {
    val msg = JWM.PLAINTEXT_MESSAGE.copy(
        attachments = listOf(
            Attachment.builder(
                id = "23",
                data = Attachment.Data.Json(
                    json = mapOf(
                        "foo" to "bar", "links" to listOf(2, 3)
                    )
                )
            ).build(),
            Attachment.builder(id = "24", data = Attachment.Data.Base64.parse(mapOf("base64" to "qwerty"))).build(),
            Attachment.builder(
                id = "25",
                data = Attachment.Data.Links(
                    links = listOf("1", "2", "3"), hash = "qwerty"
                )
            ).build()
        )
    )
    return msg
}

fun attachmentJsonMsg(): Message {
    val msg = JWM.PLAINTEXT_MESSAGE.copy(
        attachments = listOf(
            Attachment.builder(
                id = "23",
                data = Attachment.Data.Json(json = mapOf("foo" to "bar", "links" to "[2, 3]"))
            ).build()
        )
    )
    return msg
}
