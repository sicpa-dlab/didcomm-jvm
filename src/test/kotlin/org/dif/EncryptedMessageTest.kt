package org.dif

import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.exceptions.MalformedMessageException
import org.dif.fixtures.JWE
import org.dif.fixtures.JWE.Companion.TEST_VECTORS
import org.dif.fixtures.JWM
import org.dif.mock.AliceSecretResolverMock
import org.dif.mock.BobSecretResolverMock
import org.dif.mock.CharlieSecretResolverMock
import org.dif.mock.DIDDocResolverMock
import org.dif.model.PackEncryptedParams
import org.dif.model.UnpackParams
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class EncryptedMessageTest {

    @Test
    fun `Test encrypted message test vectors`() {
        for (tv in TEST_VECTORS) {
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

    @Test
    fun `Test decrypt message for part of the keys`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packed = didComm.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.CHARLIE_DID)
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
    fun `Test decrypt with message with damaged keys by all keys`() {
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
    fun `Test decrypt with message with damaged keys by one key`() {
        val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())
        val expected = listOf("did:example:bob#key-x25519-2")

        val unpack = didComm.unpack(
            UnpackParams.Builder(JWE.BOB_DAMAGED_MESSAGE)
                .build()
        )

        assertContentEquals(expected, unpack.metadata.encryptedTo)
    }

    @Test
    fun `Test decrypt negative test vectors`() {
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
}
