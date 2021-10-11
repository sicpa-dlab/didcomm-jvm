package org.didcommx.didcomm

import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.common.SignAlg
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.exceptions.UnsupportedAlgorithm
import org.didcommx.didcomm.fixtures.JWE
import org.didcommx.didcomm.fixtures.JWE.Companion.TEST_VECTORS
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.mock.AliceRotatedToCharlieSecretResolverMock
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.CharlieSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.utils.divideDIDFragment
import org.didcommx.didcomm.utils.isDID
import org.didcommx.didcomm.utils.isDIDFragment
import org.didcommx.didcomm.utils.isJDK15Plus
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class EncryptedMessageTest {

    @Test
    fun `Test_encrypted_message_test_vectors`() {
        for (tv in TEST_VECTORS) {
            // TODO: secp256k1 is not supported with JDK 15+
            if (isJDK15Plus() && tv.expectedMetadata.signAlg == SignAlg.ES256K) {
                continue
            }
            val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())

            val unpacked = didComm.unpack(
                UnpackParams.Builder(tv.message)
                    .expectDecryptByAllKeys(true)
                    .build()
            )

            assertEquals(
                JSONObjectUtils.toJSONString(JWM.PLAINTEXT_MESSAGE.toJSONObject()),
                JSONObjectUtils.toJSONString(unpacked.message.toJSONObject())
            )

            with(unpacked.metadata) {
                assertEquals(tv.expectedMetadata.encrypted, encrypted)
                assertEquals(tv.expectedMetadata.authenticated, authenticated)
                assertEquals(tv.expectedMetadata.anonymousSender, anonymousSender)
                assertEquals(tv.expectedMetadata.nonRepudiation, nonRepudiation)

                assertEquals(tv.expectedMetadata.encAlgAnon, encAlgAnon)
                assertEquals(tv.expectedMetadata.encAlgAuth, encAlgAuth)

                assertEquals(tv.expectedMetadata.encryptedFrom, encryptedFrom)
                assertContentEquals(tv.expectedMetadata.encryptedTo, encryptedTo)

                assertEquals(tv.expectedMetadata.signAlg, signAlg)
                assertEquals(tv.expectedMetadata.signFrom, signFrom)

                val expectedSignedMessage = tv.expectedMetadata.signedMessage?.let { true } ?: false
                val actualSignedMessage = signedMessage?.let { true } ?: false
                assertEquals(expectedSignedMessage, actualSignedMessage)
            }
        }
    }

//    @Test
//    fun `Test_unsupported_exception_es256k_jdk15+`() {
//        if (!isJDK15Plus())
//            return
//        val testVectors = TEST_VECTORS.filter { it.expectedMetadata.signAlg == SignAlg.ES256K }
//        for (tv in testVectors) {
//            val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())
//            assertThrows<UnsupportedAlgorithm> {
//                didComm.unpack(
//                    UnpackParams.Builder(tv.message)
//                        .expectDecryptByAllKeys(true)
//                        .build()
//                )
//            }
//        }
//    }

    @Test
    fun `Test_decrypt_message_for_part_of_the_keys`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val message = JWM.PLAINTEXT_MESSAGE.copy(to = listOf(JWM.CHARLIE_DID))

        val packed = didComm.packEncrypted(
            PackEncryptedParams.Builder(message, JWM.CHARLIE_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        val unpacked = didComm.unpack(
            UnpackParams.Builder(packed.packedMessage)
                .secretResolver(CharlieSecretResolverMock())
                .expectDecryptByAllKeys(true)
                .build()
        )

        val expectedKids = listOf(
            "did:example:charlie#key-x25519-1",
            "did:example:charlie#key-x25519-3"
        )

        assertContentEquals(expectedKids, unpacked.metadata.encryptedTo)
    }

    @Test
    fun `Test_decrypt_with_message_with_damaged_keys_by_all_keys`() {
        val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())
        val expected = "Decrypt is failed"

        val actual = assertThrows<MalformedMessageException> {
            didComm.unpack(
                UnpackParams.Builder(JWE.BOB_DAMAGED_MESSAGE)
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }

        assertEquals(expected, actual.message)
    }

    @Test
    fun `Test_decrypt_with_message_with_damaged_keys_by_one_key`() {
        val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())
        val expected = listOf("did:example:bob#key-x25519-2")

        val unpack = didComm.unpack(
            UnpackParams.Builder(JWE.BOB_DAMAGED_MESSAGE)
                .build()
        )

        assertContentEquals(expected, unpack.metadata.encryptedTo)
    }

    @Test
    fun `Test_decrypt_negative_test_vectors`() {
        for (tv in JWE.NEGATIVE_TEST_VECTORS) {
            val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())

            val actual = assertFailsWith(
                exceptionClass = tv.expectedThrow,
                block = {
                    didComm.unpack(tv.unpackParams)
                }
            )

            assertEquals(tv.expectedMessage, actual.message)
        }
    }

    @Test
    fun `Test_encrypt_decrypt_message_with_from_prior_and_issuer_kid`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceRotatedToCharlieSecretResolverMock())

        for (message in listOf(JWM.PLAINTEXT_MESSAGE_FROM_PRIOR_MINIMAL, JWM.PLAINTEXT_MESSAGE_FROM_PRIOR)) {
            val packResult = didComm.packEncrypted(
                PackEncryptedParams.builder(message, JWM.BOB_DID)
                    .from(JWM.CHARLIE_DID)
                    .fromPriorIssuerKid("did:example:alice#key-2")
                    .build()
            )

            assertNotNull(packResult.packedMessage)
            assertEquals("did:example:alice#key-2", packResult.fromPriorIssuerKid)

            val unpackResult = didComm.unpack(
                UnpackParams.Builder(packResult.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .build()
            )

            assertEquals(message, unpackResult.message)
            assertEquals("did:example:alice#key-2", unpackResult.metadata.fromPriorIssuerKid)
            assertNotNull(unpackResult.metadata.fromPriorJwt)
        }
    }

    @Test
    fun `Test_encrypt_decrypt_message_with_from_prior_and_no_issuer_kid`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceRotatedToCharlieSecretResolverMock())

        for (message in listOf(JWM.PLAINTEXT_MESSAGE_FROM_PRIOR_MINIMAL, JWM.PLAINTEXT_MESSAGE_FROM_PRIOR)) {
            val packResult = didComm.packEncrypted(
                PackEncryptedParams.builder(message, JWM.BOB_DID)
                    .from(JWM.CHARLIE_DID)
                    .build()
            )

            assertNotNull(packResult.packedMessage)
            assertNotNull(packResult.fromPriorIssuerKid)
            assertTrue(isDID(packResult.fromPriorIssuerKid!!))
            assertTrue(isDIDFragment(packResult.fromPriorIssuerKid!!))
            assertEquals(JWM.ALICE_DID, divideDIDFragment(packResult.fromPriorIssuerKid!!).first())

            val unpackResult = didComm.unpack(
                UnpackParams.Builder(packResult.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .build()
            )

            assertEquals(message, unpackResult.message)
            assertEquals(packResult.fromPriorIssuerKid, unpackResult.metadata.fromPriorIssuerKid)
            assertNotNull(unpackResult.metadata.fromPriorJwt)
        }
    }

    @Test
    fun `Test_encrypt_message_with_invalid_from_prior`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceRotatedToCharlieSecretResolverMock())

        for (message in JWM.INVALID_FROM_PRIOR_PLAINTEXT_MESSAGES) {
            assertFails {
                didComm.packPlaintext(PackPlaintextParams.builder(message).build())
            }
        }
    }
}
