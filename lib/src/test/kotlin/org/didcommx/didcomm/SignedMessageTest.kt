package org.didcommx.didcomm

import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.common.SignAlg
import org.didcommx.didcomm.exceptions.DIDCommIllegalArgumentException
import org.didcommx.didcomm.exceptions.SecretNotFoundException
import org.didcommx.didcomm.exceptions.UnsupportedAlgorithm
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.fixtures.JWS
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.utils.isJDK15Plus
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertEquals

class SignedMessageTest {

    @Test
    fun `Test_signed_message_test_vectors`() {
        for (test in JWS.TEST_VECTORS) {
            // TODO: secp256k1 is not supported with JDK 15+
            if (isJDK15Plus() && test.expectedMetadata.signAlg == SignAlg.ES256K) {
                continue
            }
            val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

            val packed = didComm.packSigned(
                PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, test.from).build()
            )

            val unpacked = didComm.unpack(
                UnpackParams.Builder(packed.packedMessage).build()
            )

            val expected = JWSObjectJSON.parse(test.expected)
            val signed = JWSObjectJSON.parse(packed.packedMessage)

            assertEquals(expected.signatures.first().header.toString(), signed.signatures.first().header.toString())

            assertEquals(
                JSONObjectUtils.toJSONString(JWM.PLAINTEXT_MESSAGE.toJSONObject()),
                JSONObjectUtils.toJSONString(unpacked.message.toJSONObject())
            )

            assertEquals(false, unpacked.metadata.encrypted)
            assertEquals(true, unpacked.metadata.authenticated)
            assertEquals(true, unpacked.metadata.nonRepudiation)
            assertEquals(false, unpacked.metadata.anonymousSender)
            assertEquals(test.expectedMetadata.signFrom, unpacked.metadata.signFrom)
            assertEquals(test.expectedMetadata.signAlg, unpacked.metadata.signAlg)
        }
    }

    @Test
    fun `Test_unsupported_exception_es256k_jdk15+`() {
        if (!isJDK15Plus())
            return
        val testVectors = JWS.TEST_VECTORS.filter { it.expectedMetadata.signAlg == SignAlg.ES256K }
        for (test in testVectors) {
            val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())
            assertThrows<UnsupportedAlgorithm> {
                didComm.packSigned(
                    PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, test.from).build()
                )
            }
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
