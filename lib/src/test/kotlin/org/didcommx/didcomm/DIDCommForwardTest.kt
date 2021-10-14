package org.didcommx.didcomm

import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.mock.*
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.operations.unpackForward
import org.didcommx.didcomm.utils.toJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DIDCommForwardTest {

    val ALICE_DID = "did:example:alice"
    val BOB_DID = "did:example:bob"
    val CHARLIE_DID = "did:example:charlie"

    @Test
    fun `Test_single_mediator`() {
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

        // BOB MEDIATOR
        val forwardBob = didComm.unpackForward(
            UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(Mediator1SecretResolverMock())
                .build()
        )

        val forwardedMsg = toJson(forwardBob.forwardedMsg)
        println("Sending ${forwardedMsg} to Bob")

        // BOB
        val unpackResult = didComm.unpack(
            UnpackParams.Builder(forwardedMsg)
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
}
