package org.didcommx.didcomm

import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.fixtures.JWS
import org.didcommx.didcomm.mock.AliceRotatedToCharlieSecretResolverMock
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.utils.divideDIDFragment
import org.didcommx.didcomm.utils.isDID
import org.didcommx.didcomm.utils.isDIDFragment
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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
    fun `Test_encrypt_decrypt_message_with_from_prior_and_issuer_kid`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceRotatedToCharlieSecretResolverMock())

        for (message in listOf(JWM.PLAINTEXT_MESSAGE_FROM_PRIOR_MINIMAL, JWM.PLAINTEXT_MESSAGE_FROM_PRIOR)) {
            val packResult = didComm.packSigned(
                PackSignedParams.builder(message, JWM.CHARLIE_DID)
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
            val packResult = didComm.packSigned(
                PackSignedParams.builder(message, JWM.CHARLIE_DID).build()
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
