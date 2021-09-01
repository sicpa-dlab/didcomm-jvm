package org.dif

import org.dif.common.AnonCryptAlg
import org.dif.common.JSONObject
import org.dif.fixtures.JWM
import org.dif.message.Attachment
import org.dif.message.AttachmentDataBase64
import org.dif.message.AttachmentDataJson
import org.dif.message.Message
import org.dif.mock.DIDDocResolverMock
import org.dif.mock.SecretResolverMock
import org.dif.model.PackEncryptedParams
import org.dif.model.PackPlaintextParams
import org.dif.model.PackSignedParams
import org.junit.jupiter.api.Test

class DIDCommTest {
    @Test
    fun `Test message with attachments message`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val attachments = listOf(
            Attachment.builder("1", AttachmentDataBase64("SGVsbG8sIHdvcmxk"))
                .mediaType("text/plain")
                .build(),

            Attachment.builder("2", AttachmentDataJson(JSONObject(mapOf("foo" to "bar"))))
                .description("The second attachment")
                .mediaType("application/json")
                .build()
        )

        val msg = Message.builder("12345", mapOf("foo" to "bar"), "my-protocol/1.0")
            .attachments(attachments)
            .from(JWM.ALICE_DID)
            .to(listOf(JWM.BOB_DID))
            .build()

        val packedMsg = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, JWM.BOB_DID).build()
        )

        /*val unpack = didComm.unpack(
            UnpackParams.Builder(packedMsg.packedMessage).build()
        )*/

        // TODO: assert attachments
    }

    @Test
    fun `Test repudiable authentication encryption message`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", mapOf("foo" to "bar"), "my-protocol/1.0")
            .from(JWM.ALICE_DID)
            .to(listOf(JWM.BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, JWM.BOB_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        /*val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )*/
    }

    @Test
    fun `Test repudiable non authenticated encryption message`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", mapOf("foo" to "bar"), "my-protocol/1.0")
            .from(JWM.ALICE_DID)
            .to(listOf(JWM.BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, JWM.BOB_DID).build()
        )

        /*val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )*/
    }

    @Test()
    fun `Test non repudiable encryption message`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", mapOf("foo" to "bar"), "my-protocol/1.0")
            .from(JWM.ALICE_DID)
            .to(listOf(JWM.BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, JWM.BOB_DID)
                .signFrom(JWM.ALICE_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        /*val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )*/
    }

    @Test()
    fun `Test signed unencrypted message`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", mapOf("foo" to "bar"), "my-protocol/1.0")
            .from(JWM.ALICE_DID)
            .to(listOf(JWM.BOB_DID))
            .build()

        val packResult = didComm.packSigned(
            PackSignedParams.builder(msg, JWM.ALICE_DID)
                .build()
        )

        /*val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )*/
    }

    @Test()
    fun `Test plaintext message`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", mapOf("foo" to "bar"), "my-protocol/1.0")
            .from(JWM.ALICE_DID)
            .to(listOf(JWM.BOB_DID))
            .build()

        val packResult = didComm.packPlaintext(
            PackPlaintextParams.builder(msg)
                .build()
        )

        /*val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )*/
    }

    @Test()
    fun `Test advanced parameters`() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", mapOf("foo" to "bar"), "my-protocol/1.0")
            .from(JWM.ALICE_DID)
            .to(listOf(JWM.BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, JWM.BOB_DID)
                .signFrom(JWM.ALICE_DID)
                .from(JWM.ALICE_DID)
                .protectSenderId(true)
                .forward(true)
                .encAlgAnon(AnonCryptAlg.XC20P_ECDH_ES_A256KW)
                .forwardHeaders(mapOf("header1" to "header1 value"))
                .forwardServiceId("service-id")
                .build()
        )

        /*val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .expectAuthenticated(true)
                .expectAnonymousSender(true)
                .expectDecryptByAllKeys(true)
                .expectEncrypted(true)
                .expectSignedByEncrypter(true)
                .build()
        )*/
    }
}
