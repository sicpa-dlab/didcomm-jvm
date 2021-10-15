package org.didcommx.didcomm

import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.CharlieSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.mock.Mediator1SecretResolverMock
import org.didcommx.didcomm.mock.Mediator2SecretResolverMock
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.protocols.routing.Routing
import org.didcommx.didcomm.utils.toJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DIDCommDemoTest {

    val ALICE_DID = "did:example:alice"
    val BOB_DID = "did:example:bob"
    val CHARLIE_DID = "did:example:charlie"

    @Test
    fun `Test_repudiable_authentication_encryption_message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(message, BOB_DID)
                .from(ALICE_DID)
                .build()
        )
        println("Sending ${packResult.packedMessage} to ${packResult.serviceMetadata?.serviceEndpoint ?: ""}")

        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )
        println("Got ${unpackResult.message} message")

        assertEquals(message, unpackResult.message)
        with(unpackResult.metadata) {
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

        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(message, BOB_DID).build()
        )
        println("Sending ${packResult.packedMessage} to ${packResult.serviceMetadata?.serviceEndpoint ?: ""}")

        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )
        println("Got ${unpackResult.message} message")

        assertEquals(message, unpackResult.message)
        with(unpackResult.metadata) {
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

        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(message, BOB_DID)
                .signFrom(ALICE_DID)
                .from(ALICE_DID)
                .build()
        )
        println("Sending ${packResult.packedMessage} to ${packResult.serviceMetadata?.serviceEndpoint ?: ""}")

        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )
        println("Got ${unpackResult.message} message")

        assertEquals(message, unpackResult.message)
        with(unpackResult.metadata) {
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

        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(message, BOB_DID)
                .protectSenderId(true)
                .signFrom(ALICE_DID)
                .from(ALICE_DID)
                .build()
        )
        println("Sending ${packResult.packedMessage} to ${packResult.serviceMetadata?.serviceEndpoint ?: ""}")

        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )
        println("Got ${unpackResult.message} message")

        assertEquals(message, unpackResult.message)
        with(unpackResult.metadata) {
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

        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val packResult = didComm.packSigned(
            PackSignedParams.builder(message, ALICE_DID)
                .build()
        )
        println("Publishing ${packResult.packedMessage}")

        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )
        println("Got ${unpackResult.message} message")

        assertEquals(message, unpackResult.message)
        with(unpackResult.metadata) {
            assertTrue { nonRepudiation }
            assertTrue { authenticated }
            assertFalse { encrypted }
            assertFalse { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }

    @Test
    fun `Test_plaintext_message`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val packResult = didComm.packPlaintext(
            PackPlaintextParams.builder(message)
                .build()
        )
        println("Publishing ${packResult.packedMessage}")

        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )
        println("Got ${unpackResult.message} message")

        assertEquals(message, unpackResult.message)
        with(unpackResult.metadata) {
            assertFalse { nonRepudiation }
            assertFalse { encrypted }
            assertFalse { authenticated }
            assertFalse { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }

    @Test
    fun `Test_multi_recipient_support`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())
        val routing = Routing(DIDDocResolverMock(), AliceSecretResolverMock())

        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .from(ALICE_DID)
            .to(listOf(BOB_DID, CHARLIE_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val packResultBob = didComm.packEncrypted(
            PackEncryptedParams.builder(message, BOB_DID)
                .protectSenderId(true)
                .signFrom(ALICE_DID)
                .from(ALICE_DID)
                .build()
        )
        println("Sending ${packResultBob.packedMessage} to ${packResultBob.serviceMetadata?.serviceEndpoint ?: ""} for Bob")

        val unpackResultBob = didComm.unpack(
            UnpackParams.Builder(packResultBob.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )
        println("Bob got ${unpackResultBob.message} message")

        with(unpackResultBob.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertTrue { nonRepudiation }
            assertTrue { anonymousSender }
            assertFalse { reWrappedInForward }
        }

        val packResultCharlie = didComm.packEncrypted(
            PackEncryptedParams.builder(message, CHARLIE_DID)
                .protectSenderId(true)
                .signFrom(ALICE_DID)
                .from(ALICE_DID)
                .build()
        )
        println("Sending ${packResultCharlie.packedMessage} to ${packResultCharlie.serviceMetadata?.serviceEndpoint ?: ""} for Charlie")

        // TODO make focused on initial subject (without forward)
        // CHARLIE's first mediator (MEDIATOR2)
        var forwardCharlie = routing.unpackForward(
            packResultCharlie.packedMessage,
            secretResolver = Mediator2SecretResolverMock()
        )

        var forwardedMsg = toJson(forwardCharlie.forwardedMsg)

        // CHARLIE's second mediator (MEDIATOR1)
        forwardCharlie = routing.unpackForward(
            forwardedMsg,
            secretResolver = Mediator1SecretResolverMock()
        )

        forwardedMsg = toJson(forwardCharlie.forwardedMsg)

        val unpackResultCharlie = didComm.unpack(
            UnpackParams.Builder(forwardedMsg)
                .secretResolver(CharlieSecretResolverMock())
                .build()
        )
        println("Charlie got ${unpackResultCharlie.message} message")

        with(unpackResultCharlie.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertTrue { nonRepudiation }
            assertTrue { anonymousSender }
            assertFalse { reWrappedInForward }
        }

        assertEquals(message, unpackResultBob.message)
        assertEquals(message, unpackResultCharlie.message)
        val unpackMessageBob = unpackResultBob.message.copy(to = null)
        val unpackMessageCharlie = unpackResultCharlie.message.copy(to = null)
        val unpackMetadataBob = unpackResultCharlie.metadata.copy(encryptedTo = null, signedMessage = null)
        val unpackMetadataCharlie = unpackResultCharlie.metadata.copy(encryptedTo = null, signedMessage = null)
        assertEquals(unpackMessageBob, unpackMessageCharlie)
        assertEquals(unpackMetadataBob, unpackMetadataCharlie)
    }

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
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, BOB_DID).build()
        )
        println("Sending ${packResult.packedMessage} to ${packResult.serviceMetadata?.serviceEndpoint ?: ""}")

        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .build()
        )
        println("Got ${unpackResult.message} message")

        assertEquals(msg, unpackResult.message)
    }
}
