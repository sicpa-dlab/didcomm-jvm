package org.dif

import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.fixtures.JWE.Companion.TEST_VECTORS
import org.dif.fixtures.JWM
import org.dif.mock.BobSecretResolverMock
import org.dif.mock.DIDDocResolverMock
import org.dif.model.UnpackParams
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

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
}
