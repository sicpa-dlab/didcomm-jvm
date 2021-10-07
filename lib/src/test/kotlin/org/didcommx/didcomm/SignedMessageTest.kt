package org.didcommx.didcomm

import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.exceptions.DIDCommIllegalArgumentException
import org.didcommx.didcomm.exceptions.SecretNotFoundException
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.fixtures.JWS
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertEquals

class SignedMessageTest {

    @Test
    fun `Test_signed_message_test_vectors`() {
        for (test in JWS.TEST_VECTORS) {
            val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

            val packed = didComm.packSigned(
                PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, test.from).build()
            )

            val unpacked = didComm.unpack(
                UnpackParams.Builder(packed.packedMessage).build()
            )

            val expected = JWSObjectJSON.parse(test.expected)
            val signed = JWSObjectJSON.parse(packed.packedMessage)

            assertEquals(expected.header.toString(), signed.header.toString())

            assertEquals(
                JSONObjectUtils.toJSONString(JWM.PLAINTEXT_MESSAGE.toJSONObject()),
                JSONObjectUtils.toJSONString(unpacked.message.toJSONObject())
            )
        }
    }

    @Test
    fun `Test_from_is_not_a_did_or_did_url`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packSigned(
                PackSignedParams.builder(
                    JWM.PLAINTEXT_MESSAGE,
                    signFrom = "not-a-did"
                ).build()
            )
        }
    }

    @Test
    fun `Test_from_unknown_did`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packSigned(
                PackSignedParams.builder(
                    JWM.PLAINTEXT_MESSAGE,
                    signFrom = "did:example:unknown"
                ).build()
            )
        }
    }

    @Test
    fun `Test_from_unknown_did_url`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<SecretNotFoundException> {
            didComm.packSigned(
                PackSignedParams.builder(
                    JWM.PLAINTEXT_MESSAGE,
                    signFrom = JWM.ALICE_DID + "#unknown-key"
                ).build()
            )
        }
    }

    @Test
    fun `Test_from_not_in_secrets`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val frm = getAuthMethodsNotInSecrets(Person.ALICE)[0].id
        assertThrows<SecretNotFoundException> {
            didComm.packSigned(
                PackSignedParams.builder(
                    JWM.PLAINTEXT_MESSAGE,
                    signFrom = frm
                ).build()
            )
        }
    }
}
