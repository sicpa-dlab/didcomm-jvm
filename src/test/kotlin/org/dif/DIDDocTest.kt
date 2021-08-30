package org.dif

import org.dif.common.AnonCryptAlg
import org.dif.common.JSONObject
import org.dif.common.Typ
import org.dif.message.Attachment
import org.dif.message.AttachmentDataBase64
import org.dif.message.AttachmentDataJson
import org.dif.message.Message
import org.dif.mock.DIDDocResolverMock
import org.dif.mock.SecretResolverMock
import org.dif.model.PackEncryptedParams
import org.dif.model.PackPlaintextParams
import org.dif.model.PackSignedParams
import org.dif.model.UnpackParams
import org.junit.Test
import kotlin.test.assertEquals

class DIDDocTest {
    companion object {
        const val ALICE_DID = "did:example:alice"
        const val BOB_DID = "did:example:bob"
    }

    @Test
    fun test_message_with_attachments() {
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

        val msg = Message.builder("12345", JSONObject(mapOf("foo" to "bar")), "my-protocol/1.0", Typ.Plaintext)
            .attachments(attachments)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .build()

        val packedMsg = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, BOB_DID).build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packedMsg.packedMessage).build()
        )

        // TODO: assert attachments
    }

    @Test
    fun test_repudiable_authentication_encryption() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", JSONObject(mapOf("foo" to "bar")), "my-protocol/1.0", Typ.Plaintext)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, BOB_DID)
                .from(ALICE_DID)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )
    }

    @Test
    fun test_repudiable_non_authenticated_encryption() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", JSONObject(mapOf("foo" to "bar")), "my-protocol/1.0", Typ.Plaintext)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, BOB_DID).build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )
    }

    @Test()
    fun test_non_repudiable_encryption() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", JSONObject(mapOf("foo" to "bar")), "my-protocol/1.0", Typ.Plaintext)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, BOB_DID)
                .signFrom(ALICE_DID)
                .from(ALICE_DID)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )
    }

    @Test()
    fun test_signed_unencrypted() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", JSONObject(mapOf("foo" to "bar")), "my-protocol/1.0", Typ.Plaintext)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .build()

        val packResult = didComm.packSigned(
            PackSignedParams.builder(msg, ALICE_DID)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )
    }

    @Test()
    fun test_plaintext() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", JSONObject(mapOf("foo" to "bar")), "my-protocol/1.0", Typ.Plaintext)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .build()

        val packResult = didComm.packPlaintext(
            PackPlaintextParams.builder(msg)
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )
    }

    @Test()
    fun test_advanced_parameters() {
        val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

        val msg = Message.builder("12345", JSONObject(mapOf("foo" to "bar")), "my-protocol/1.0", Typ.Plaintext)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .build()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(msg, BOB_DID)
                .signFrom(ALICE_DID)
                .from(ALICE_DID)
                .protectSenderId(true)
                .forward(true)
                .encAlgAnon(AnonCryptAlg.XC20P_ECDH_ES_A256KW)
                .forwardHeaders(mapOf("header1" to "header1 value"))
                .forwardServiceId("service-id")
                .build()
        )

        val unpack = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage)
                .expectAuthenticated(true)
                .expectAnonymousSender(true)
                .expectDecryptByAllKeys(true)
                .expectEncrypted(true)
                .expectSignedByEncrypter(true)
                .build()
        )
    }
}