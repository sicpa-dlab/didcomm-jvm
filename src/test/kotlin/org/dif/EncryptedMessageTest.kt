package org.dif

import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.fixtures.JWE.Companion.TEST_VECTORS
import org.dif.fixtures.JWM
import org.dif.mock.BobSecretResolverMock
import org.dif.mock.DIDDocResolverMock
import org.dif.model.UnpackParams
import kotlin.test.Test
import kotlin.test.assertEquals

class EncryptedMessageTest {

    @Test
    fun `Test encrypted message test vectors`() {
        for (test in TEST_VECTORS) {
            val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())

            val unpacked = didComm.unpack(
                UnpackParams.Builder(test)
                    .expectDecryptByAllKeys(true)
                    .build()
            )

            assertEquals(
                JSONObjectUtils.toJSONString(JWM.PLAINTEXT_MESSAGE.toJSONObject()),
                JSONObjectUtils.toJSONString(unpacked.message.toJSONObject())
            )
        }
    }
}
