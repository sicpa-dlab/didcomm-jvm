package org.didcommx.didcomm

import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.CharlieSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DIDCommTest {
    @Test
    fun `Test_encrypt_message_with_attachments`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val attachments = listOf(
            Attachment.builder("1", Attachment.Data.Base64("SGVsbG8sIHdvcmxk"))
                .mediaType("text/plain")
                .build(),

            Attachment.builder("2", Attachment.Data.Json(mapOf("foo" to "bar")))
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

        val unpack = didComm.unpack(
            UnpackParams.Builder(packedMsg.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )

        assertEquals(msg, unpack.message)
    }

    @Test
    fun `Test_repudiable_authentication_encryption_message`() {
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
    fun `Test_repudiable_non_authenticated_encryption_message`() {
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
    fun `Test_non_repudiable_encryption_message`() {
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
    fun `Test_non_repudiable_encryption_message_for_anonymous_sender`() {
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
    fun `Test_signed_unencrypted_message`() {
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
    fun `Test_plaintext_message`() {
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

    @Test
    fun `Test multi recipient support`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResultBob = didComm.packEncrypted(
            PackEncryptedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .protectSenderId(true)
                .signFrom(JWM.ALICE_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        val unpackBob = didComm.unpack(
            UnpackParams.Builder(packResultBob.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )

        with(unpackBob.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertTrue { nonRepudiation }
            assertTrue { anonymousSender }
            assertFalse { reWrappedInForward }
        }

        val message = JWM.PLAINTEXT_MESSAGE.copy(to = listOf(JWM.CHARLIE_DID))

        val packResultCharlie = didComm.packEncrypted(
            PackEncryptedParams.builder(message, JWM.CHARLIE_DID)
                .protectSenderId(true)
                .signFrom(JWM.ALICE_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        val unpackCharlie = didComm.unpack(
            UnpackParams.Builder(packResultCharlie.packedMessage)
                .secretResolver(CharlieSecretResolverMock())
                .build()
        )

        with(unpackCharlie.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertTrue { nonRepudiation }
            assertTrue { anonymousSender }
            assertFalse { reWrappedInForward }
        }

        val unpackMessageBob = unpackBob.message.copy(to = null)
        val unpackMessageCharlie = unpackCharlie.message.copy(to = null)
        val unpackMetadataBob = unpackBob.metadata.copy(encryptedTo = null, signedMessage = null)
        val unpackMetadataCharlie = unpackCharlie.metadata.copy(encryptedTo = null, signedMessage = null)
        assertEquals(unpackMessageBob, unpackMessageCharlie)
        assertEquals(unpackMetadataBob, unpackMetadataCharlie)
    }
}
