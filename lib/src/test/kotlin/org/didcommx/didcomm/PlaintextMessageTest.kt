package org.didcommx.didcomm

import com.fasterxml.jackson.databind.JavaType
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.didcommx.didcomm.exceptions.DIDCommException
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.fixtures.CustomProtocolBody
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.FromPrior
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.utils.getTyped
import org.didcommx.didcomm.utils.getTypedArray
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PlaintextMessageTest {
    @Test
    fun `Test_pack_unpack_plaintext_message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packed = didComm.packPlaintext(
            PackPlaintextParams.builder(JWM.PLAINTEXT_MESSAGE).build()
        )

        assertNotNull(packed.packedMessage)

        val unpacked = didComm.unpack(
            UnpackParams.Builder(packed.packedMessage).build()
        )

        assertEquals(JWM.PLAINTEXT_MESSAGE, unpacked.message)
    }

    @Test
    fun `Test_plaintext_without_body`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val thrown = assertFailsWith<MalformedMessageException> {
            didComm.unpack(
                UnpackParams.Builder(JWM.PLAINTEXT_MESSAGE_WITHOUT_BODY).build()
            )
        }

        assertEquals("The header \"body\" is missing", thrown.message)
    }

    @Test
    fun `Test_plaintext_custom_body_with_jackson`() {
        val mapper = ObjectMapper().registerModule(KotlinModule())
        val protocolMessage = CustomProtocolBody("1", "Name", true, 1970)

        val javaType: JavaType = mapper.constructType(Map::class.java)
        val body = mapper.convertValue<Map<String, Any>>(protocolMessage, javaType)

        val message = Message.builder("1", body, "protocol")
            .createdTime(1)
            .expiresTime(2)
            .build()

        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packed = didComm.packPlaintext(
            PackPlaintextParams.builder(message).build()
        )

        assertNotNull(packed.packedMessage)

        val unpacked = didComm.unpack(
            UnpackParams.Builder(packed.packedMessage).build()
        )

        val unpackedBody = unpacked.message.body
        val unpackedProtocolMessage = mapper.convertValue(unpackedBody, CustomProtocolBody::class.java)
        assertEquals(protocolMessage.toString(), unpackedProtocolMessage.toString())
    }

    @Test
    fun `Test_custom_headers_works`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val message = Message.builder("1", mapOf(), "protocol")
            .customHeader("null", null)
            .customHeader("int", 2)
            .customHeader("string", "Hello, world")
            .customHeader("booleanTrue", true)
            .customHeader("booleanFalse", false)
            .customHeader("object", mapOf("foo" to "bar"))
            .customHeader("array", listOf(1, 2, 3, 4, 5))
            .build()

        val packed = didComm.packPlaintext(
            PackPlaintextParams.builder(message).build()
        )

        val unpacked = didComm.unpack(
            UnpackParams.Builder(packed.packedMessage).build()
        )

        println(packed.packedMessage)

        with(unpacked.message) {
            assertNull(customHeader("null"))
            assertEquals(2L, customHeader("int"))
            assertEquals("Hello, world", customHeader("string"))
            assertTrue(customHeader("booleanTrue") ?: false)
            assertFalse(customHeader("booleanFalse") ?: true)
            assertEquals(mapOf("foo" to "bar"), customHeader("object"))
            assertContentEquals(listOf(1L, 2L, 3L, 4L, 5L), customHeader("array"))
        }
    }

    @Test
    fun `Test_header_reserved_name`() {
        val builder = Message.builder("", mapOf(), "")

        for (header in Message.reservedHeaderNames) {
            val expected = "The header name '$header' is reserved"

            val actual = assertThrows<DIDCommException> {
                builder.customHeader(header, null)
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_parse_when_message_is_empty_json`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val thrown = assertFailsWith<MalformedMessageException> {
            didComm.unpack(
                UnpackParams.Builder("{}").build()
            )
        }

        assertEquals("The header \"id\" is missing", thrown.message)
    }

    @Test
    fun `Test_wrong_attachment_data`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        for (tv in JWM.WRONG_ATTACHMENTS) {
            val thrown = assertFailsWith<MalformedMessageException> {
                didComm.unpack(
                    UnpackParams.Builder(tv.json).build()
                )
            }

            assertEquals(tv.expectedMessage, thrown.message)
        }
    }

    @Test
    fun `Test_correct_attachment_data`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        for (tv in JWM.CORRECT_ATTACHMENTS) {
            val unpack = didComm.unpack(
                UnpackParams.Builder(tv.json).build()
            )

            val actual = unpack.message.attachments
                ?.map { it.data }
                ?.map {
                    JWM.ExpectedAttachmentData(
                        isLinks = it is Attachment.Data.Links,
                        isBase64 = it is Attachment.Data.Base64,
                        isJson = it is Attachment.Data.Json
                    )
                }

            assertContentEquals(tv.expectedAttachmentData, actual)
        }
    }

    @Test
    fun `Test_full_plaintext_message`() {
        val fromPrior = FromPrior.builder("iss", "sub")
            .aud("aud")
            .exp(123456789)
            .nbf(987654321)
            .iat(1234554321)
            .jti("jti")
            .build()

        val attachments = listOf(
            Attachment.builder(
                "1",
                Attachment.Data.Base64(
                    base64 = "qwerty",
                    jws = mapOf(
                        "payload" to "payload",
                        "signature" to "signature"
                    ),
                    hash = "hash"
                )
            )
                .filename("filename")
                .lastModTime(0)
                .format("format")
                .description("some description")
                .mediaType("text/json")
                .byteCount(1L)
                .build()
        )

        val body = linkedMapOf(
            "array" to listOf(
                mapOf("foo" to "bar"),
                2L,
                true,
                false,
                null,
                listOf(1L, 2L, 3L)
            ),
            "first" to "first",
            "second" to null,
            "object" to linkedMapOf(
                "first" to 1L,
                "second" to true
            )
        )

        val message = Message.builder("id1", body, "coolest-protocol")
            .from(JWM.ALICE_DID)
            .to(listOf(JWM.BOB_DID, JWM.ELLIE_DID))
            .createdTime(123)
            .expiresTime(456)
            .fromPrior(fromPrior)
            .attachments(attachments)
            .pleaseAck(true)
            .ack("ack")
            .thid("thid")
            .pthid("pthid")
            .customHeader("foo", "bar")
            .customHeader("array", listOf(1L, 2L, 3L))
            .build()

        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packed = didComm.packPlaintext(
            PackPlaintextParams.builder(message).build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packed.packedMessage).build()
        )

        assertEquals(message.fromPrior, unpack.message.fromPrior)
        assertContentEquals(message.attachments, unpack.message.attachments)

        assertEquals<String?>(
            message.body.getTyped("first"),
            unpack.message.body.getTyped("first")
        )

        assertEquals<String?>(
            message.body.getTyped("second"),
            unpack.message.body.getTyped("second")
        )

        val expectedObject = message.body.getTyped<Map<String, Any?>>("object")
        val actualObject = unpack.message.body.getTyped<Map<String, Any?>>("object")

        assertNotNull(expectedObject)
        assertNotNull(actualObject)

        assertEquals<Long?>(
            expectedObject.getTyped("first"),
            actualObject.getTyped("first"),
        )

        assertEquals<Boolean?>(
            expectedObject.getTyped("second"),
            actualObject.getTyped("second"),
        )

        val expectedArray = message.body.getTyped<List<Any?>>("array")?.toTypedArray()
        val actualArray = unpack.message.body.getTypedArray<Any>("array")
        assertContentEquals(expectedArray, actualArray)

        assertEquals(message.from, unpack.message.from)
        assertEquals(message.createdTime, unpack.message.createdTime)
        assertEquals(message.expiresTime, unpack.message.expiresTime)
        assertEquals(message.pleaseAck, unpack.message.pleaseAck)
        assertEquals(message.ack, unpack.message.ack)
        assertEquals(message.thid, unpack.message.thid)
        assertEquals(message.pthid, unpack.message.pthid)
        assertContentEquals(message.to, unpack.message.to)

        assertEquals<String?>(
            message.customHeader("foo"),
            unpack.message.customHeader("foo")
        )

        assertContentEquals(
            message.customHeader<List<Long?>>("array")?.toTypedArray(),
            unpack.message.customHeaderArray("array")
        )
    }
}
