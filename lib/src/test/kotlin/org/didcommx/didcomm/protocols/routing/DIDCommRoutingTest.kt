package org.didcommx.didcomm.protocols.routing

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.CharlieSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMockWithNoSecrets
import org.didcommx.didcomm.mock.Mediator1SecretResolverMock
import org.didcommx.didcomm.mock.Mediator2SecretResolverMock
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.utils.toJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DIDCommRoutingTest {

    val ALICE_DID = "did:example:alice"
    val BOB_DID = "did:example:bob"
    val CHARLIE_DID = "did:example:charlie"
    val MEDIATOR2_DID = "did:example:mediator2"

    val didDocResolver = DIDDocResolverMockWithNoSecrets()
    val aliceSecretResolver = AliceSecretResolverMock()
    val bobSecretResolver = BobSecretResolverMock()
    val charlieSecretResolver = CharlieSecretResolverMock()
    val mediator1SecretResolver = Mediator1SecretResolverMock()
    val mediator2SecretResolver = Mediator2SecretResolverMock()
    val didComm = DIDComm(didDocResolver, aliceSecretResolver)
    val routing = Routing(didDocResolver, aliceSecretResolver)

    @Test
    fun `Test_single_mediator`() {
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

        // BOB MEDIATOR
        // TODO ??? why do we need the recipients selector (question to 'unpack' actually)
        val forwardBob = routing.unpackForward(
            packResult.packedMessage,
            secretResolver = mediator1SecretResolver
        )

        val forwardedMsg = toJson(forwardBob.forwardMsg.forwardedMsg)

        // BOB
        val unpackResult = didComm.unpack(
            UnpackParams.Builder(forwardedMsg)
                .secretResolver(bobSecretResolver)
                .build()
        )

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
    fun `Test_multiple_mediators`() {
        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .from(ALICE_DID)
            .to(listOf(CHARLIE_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.Builder(message, CHARLIE_DID)
                .from(ALICE_DID)
                .build()
        )

        // TODO make focused on initial subject (without forward)
        // CHARLIE's first mediator (MEDIATOR2)
        var forwardCharlie = routing.unpackForward(
            packResult.packedMessage,
            secretResolver = mediator2SecretResolver
        )

        var forwardedMsg = toJson(forwardCharlie.forwardMsg.forwardedMsg)

        // CHARLIE's second mediator (MEDIATOR1)
        forwardCharlie = routing.unpackForward(
            forwardedMsg,
            secretResolver = mediator1SecretResolver
        )

        forwardedMsg = toJson(forwardCharlie.forwardMsg.forwardedMsg)

        // CHARLIE
        val unpackResult = didComm.unpack(
            UnpackParams.Builder(forwardedMsg)
                .secretResolver(charlieSecretResolver)
                .expectDecryptByAllKeys(true)
                .build()
        )

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
    fun `Test_single_mediator_re_wrap_to_unknown`() {
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

        // BOB's MEDIATOR
        var forwardBob = routing.unpackForward(
            packResult.packedMessage,
            secretResolver = mediator1SecretResolver
        )

        val nextTo = forwardBob.forwardMsg.forwardNext
        assertNotNull(nextTo)

        // re-wrap to unexpected mediator (MEDIATOR2 here)
        val wrapResult = routing.wrapInForward(
            forwardBob.forwardMsg.forwardedMsg,
            nextTo,
            routingKeys = listOf(MEDIATOR2_DID),
            headers = mapOf("somefield" to 99999)
        )

        assertNotNull(wrapResult)

        // MEDIATOR2
        forwardBob = routing.unpackForward(
            wrapResult.msgEncrypted.packedMessage,
            secretResolver = mediator2SecretResolver
        )

        val forwardedMsg = toJson(forwardBob.forwardMsg.forwardedMsg)

        // BOB
        val unpackResult = didComm.unpack(
            UnpackParams.Builder(forwardedMsg)
                .secretResolver(bobSecretResolver)
                .build()
        )

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
    fun `Test_single_mediator_re_wrap_anoncrypt_to_receiver`() {
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

        // BOB's MEDIATOR
        val forwardBob = routing.unpackForward(
            packResult.packedMessage,
            secretResolver = mediator1SecretResolver
        )

        val nextTo = forwardBob.forwardMsg.forwardNext
        assertNotNull(nextTo)

        // re-wrap to the receiver
        val wrapResult = routing.wrapInForward(
            forwardBob.forwardMsg.forwardedMsg,
            nextTo,
            routingKeys = listOf(nextTo),
            headers = mapOf("somefield" to 99999)
        )

        assertNotNull(wrapResult)

        // BOB
        val unpackResult = didComm.unpack(
            UnpackParams.Builder(wrapResult.msgEncrypted.packedMessage)
                .secretResolver(bobSecretResolver)
                .unwrapReWrappingForward(true)
                .build()
        )

        assertEquals(message, unpackResult.message)
        // FIXME here first anon for forward is mixed with inner anon for initial message
        //       in the same metadata
        with(unpackResult.metadata) {
            assertTrue { encrypted }
            assertFalse { authenticated }
            assertFalse { nonRepudiation }
            assertTrue { anonymousSender }
            assertTrue { reWrappedInForward }
        }
    }

    @Test
    fun `Test_single_mediator_re_wrap_authcrypt_to_receiver`() {
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

        // BOB's MEDIATOR
        val forwardBob = routing.unpackForward(
            packResult.packedMessage,
            secretResolver = mediator1SecretResolver
        )

        val nextTo = forwardBob.forwardMsg.forwardNext
        assertNotNull(nextTo)

        // re-wrap to the receiver
        val wrapResult = routing.wrapInForward(
            forwardBob.forwardMsg.forwardedMsg,
            nextTo,
            routingKeys = listOf(nextTo),
            headers = mapOf("somefield" to 99999)
        )

        assertNotNull(wrapResult)

        // BOB
        val unpackResult = didComm.unpack(
            UnpackParams.Builder(wrapResult.msgEncrypted.packedMessage)
                .secretResolver(bobSecretResolver)
                .unwrapReWrappingForward(true)
                .build()
        )

        assertEquals(message, unpackResult.message)
        // FIXME here first anon for forward is mixed with inner auth for initial message
        //       in the same metadata
        with(unpackResult.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertFalse { nonRepudiation }
            assertTrue { anonymousSender }
            assertTrue { reWrappedInForward }
        }
    }

    @Test
    fun `Test_unwrap_re_wrapping_forward_mode_for_no_re_wrapping`() {
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

        // BOB's MEDIATOR
        val unpackResultAtMediator = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(mediator1SecretResolver)
                .unwrapReWrappingForward(true)
                .build()
        )

        val forwardMessage = ForwardMessage.fromMessage(unpackResultAtMediator.message)
        assertNotNull(forwardMessage)
        assertEquals(BOB_DID, forwardMessage.forwardNext)

        with(unpackResultAtMediator.metadata) {
            assertTrue { encrypted }
            assertFalse { authenticated }
            assertFalse { nonRepudiation }
            assertTrue { anonymousSender }
            assertFalse { reWrappedInForward }
        }

        // BOB
        val unpackResult = didComm.unpack(
            UnpackParams.Builder(toJson(forwardMessage.forwardedMsg))
                .secretResolver(bobSecretResolver)
                .unwrapReWrappingForward(true)
                .build()
        )

        assertEquals(message, unpackResult.message)

        with(unpackResult.metadata) {
            assertTrue { encrypted }
            assertFalse { authenticated }
            assertFalse { nonRepudiation }
            assertTrue { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }
}
