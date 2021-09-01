package org.dif

import com.fasterxml.jackson.databind.JavaType
import org.dif.exceptions.MalformedMessageException
import org.dif.fixtures.JWM
import org.dif.mock.DIDDocResolverMock
import org.dif.mock.SecretResolverMock
import org.dif.model.PackPlaintextParams
import org.dif.model.UnpackParams
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.dif.fixtures.CustomProtocolBody
import org.dif.message.Message

class PlaintextMessageTest {
    @Test
    fun `Test pack unpack plaintext message`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

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
    fun `Test plaintext without body`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val thrown: MalformedMessageException = assertThrows(MalformedMessageException::javaClass.name) {
            didComm.unpack(
                UnpackParams.Builder(JWM.PLAINTEXT_MESSAGE_WITHOUT_BODY).build()
            )
        }

        assertEquals("The header \"body\" is missing", thrown.message)
    }

    @Test
    fun `Test plaintext custom body with jackson`() {
        val mapper = ObjectMapper().registerModule(KotlinModule())
        val protocolMessage = CustomProtocolBody("1", "Name", true, 1970)

        val javaType: JavaType = mapper.constructType(Map::class.java)
        val body = mapper.convertValue<Map<String, Any>>(protocolMessage, javaType)

        val message = Message.builder("1", body, "protocol")
            .createdTime(1)
            .expiresTime(2)
            .build()

        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

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
}
