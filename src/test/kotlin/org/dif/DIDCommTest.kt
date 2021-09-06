package org.dif

import org.dif.common.JSONObject
import org.dif.fixtures.JWM
import org.dif.message.Attachment
import org.dif.message.AttachmentDataBase64
import org.dif.message.AttachmentDataJson
import org.dif.message.Message
import org.dif.mock.AliceSecretResolverMock
import org.dif.mock.BobSecretResolverMock
import org.dif.mock.DIDDocResolverMock
import org.dif.model.PackEncryptedParams
import org.dif.model.PackPlaintextParams
import org.dif.model.PackSignedParams
import org.dif.model.UnpackParams
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DIDCommTest {
    @Test
    fun `Test message with attachments message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

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

        /**
         val unpack = didComm.unpack(
         UnpackParams.Builder(packedMsg.packedMessage).build()
         )
         **/
        // TODO: assert attachments
    }

    @Test
    fun `Test repudiable authentication encryption message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )

        with(unpack.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertFalse { nonRepudiation }
            assertFalse { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }

    @Test
    fun `Test repudiable non authenticated encryption message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID).build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )

        with(unpack.metadata) {
            assertTrue { encrypted }
            assertTrue { anonymousSender }
            assertFalse { authenticated }
            assertFalse { nonRepudiation }
            assertFalse { reWrappedInForward }
        }
    }

    @Test
    fun `Test non repudiable encryption message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .signFrom(JWM.ALICE_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )

        with(unpack.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertTrue { nonRepudiation }
            assertFalse { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }

    @Test
    fun `Test non repudiable encryption message for anonymous sender`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .protectSenderId(true)
                .signFrom(JWM.ALICE_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )

        with(unpack.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertTrue { nonRepudiation }
            assertTrue { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }

    @Test
    fun `Test signed unencrypted message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = didComm.packSigned(
            PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.ALICE_DID)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )

        with(unpack.metadata) {
            assertTrue { nonRepudiation }
            assertFalse { encrypted }
            assertFalse { authenticated }
            assertFalse { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }

    @Test
    fun `Test plaintext message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = didComm.packPlaintext(
            PackPlaintextParams.builder(JWM.PLAINTEXT_MESSAGE)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )

        with(unpack.metadata) {
            assertFalse { nonRepudiation }
            assertFalse { encrypted }
            assertFalse { authenticated }
            assertFalse { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }
}
