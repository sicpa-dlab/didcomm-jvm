package org.didcommx.didcomm

import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.exceptions.DIDCommIllegalArgumentException
import org.didcommx.didcomm.exceptions.DIDDocException
import org.didcommx.didcomm.exceptions.DIDDocNotResolvedException
import org.didcommx.didcomm.exceptions.IncompatibleCryptoException
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.exceptions.SecretNotFoundException
import org.didcommx.didcomm.fixtures.JWE
import org.didcommx.didcomm.fixtures.JWE.Companion.TEST_VECTORS
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.mock.AliceNewSecretResolverMock
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.CharlieSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMockWithNoSecrets
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.utils.divideDIDFragment
import org.didcommx.didcomm.utils.isDID
import org.didcommx.didcomm.utils.isDIDFragment
import org.didcommx.didcomm.utils.isJDK15Plus
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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

    @Test
    fun `Test_unsupported_exception_es256k_jdk15+`() {
        if (!isJDK15Plus())
            return
        val testVectors = TEST_VECTORS.filter { it.expectedMetadata.signAlg == SignAlg.ES256K }
        for (tv in testVectors) {
            val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())
            assertThrows<UnsupportedAlgorithm> {
                didComm.unpack(
                    UnpackParams.Builder(tv.message)
                        .expectDecryptByAllKeys(true)
                        .build()
                )
            }
        }
    }

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
    fun `Test_from_is_not_a_did_or_did_url`() {
        val didComm = DIDComm(DIDDocResolverMockWithNoSecrets(), AliceSecretResolverMock())

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from("not-a-did")
                    .build()
            )
        }
    }

    @Test
    fun `Test_to_is_not_a_did_or_did_url`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, "not-a-did")
                    .build()
            )
        }
    }

    @Test
    fun `Test_sign_frm_is_not_a_did_or_did_url`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom("not-a-did")
                    .build()
            )
        }
    }

    @Test
    fun `Test_from_differs_from_msg_from`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(from = JWM.CHARLIE_DID)

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(msg, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }
    }

    @Test
    fun `Test_to_differs_from_msg_to`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(to = listOf(JWM.CHARLIE_DID))

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(msg, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }
    }

    @Test
    fun `Test_to_present_in_msg_to`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(to = listOf(JWM.CHARLIE_DID, JWM.BOB_DID))

        didComm.packEncrypted(
            PackEncryptedParams.Builder(msg, JWM.BOB_DID)
                .from(JWM.ALICE_DID)
                .build()
        )
    }

    @Test
    fun `Test_from_is_not_a_did_or_did_url_in_msg`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(from = "not-a-did")

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(msg, JWM.BOB_DID)
                    .from("not-a-did")
                    .build()
            )
        }
    }

    @Test
    fun `Test_to_is_not_a_did_or_did_url_in_msg`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(to = listOf("not-a-did"))

        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(msg, "not-a-did")
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }
    }

    @Test
    fun `Test_sign_from_differs_from_msg_from_positive`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceNewSecretResolverMock())

        didComm.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .from(JWM.ALICE_DID)
                .signFrom(JWM.CHARLIE_DID)
                .build()
        )
    }

    @Test
    fun `Test_from_unknown_did`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(from = "did:example:unknown")

        assertThrows<DIDDocNotResolvedException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(msg, JWM.BOB_DID)
                    .from("did:example:unknown")
                    .build()
            )
        }
    }

    @Test
    fun `Test_from_unknown_did_url`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<SecretNotFoundException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID + "#unknown-key")
                    .build()
            )
        }
    }

    @Test
    fun `Test_to_unknown_did`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(to = listOf("did:example:unknown"))

        assertThrows<DIDDocNotResolvedException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(msg, "did:example:unknown")
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }
    }

    @Test
    fun `Test_to_unknown_did_url`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<DIDDocException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID + "#unknown-key")
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }
    }

    @Test
    fun `Test_signFrom_unknown_did`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<DIDDocNotResolvedException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom("did:example:unknown")
                    .build()
            )
        }
    }

    @Test
    fun `Test_signFrom_unknown_did_url`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        assertThrows<SecretNotFoundException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(JWM.ALICE_DID + "#unknown-key")
                    .build()
            )
        }
    }

    @Test
    fun `Test_from_not_in_secrets`() {
        val didComm = DIDComm(DIDDocResolverMockWithNoSecrets(), AliceSecretResolverMock())

        val frm = getKeyAgreementMethodsNotInSecrets(Person.ALICE)[0].id
        assertThrows<SecretNotFoundException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(frm)
                    .build()
            )
        }
    }

    @Test
    fun `Test_signFrom_not_in_secrets`() {
        val didComm = DIDComm(DIDDocResolverMockWithNoSecrets(), AliceSecretResolverMock())

        val frm = getKeyAgreementMethodsNotInSecrets(Person.ALICE)[0].id
        assertThrows<SecretNotFoundException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(frm)
                    .build()
            )
        }
    }

    @Test
    fun `Test_to_not_in_secrets_positive`() {
        val didComm = DIDComm(DIDDocResolverMockWithNoSecrets(), AliceSecretResolverMock())

        val to = getKeyAgreementMethodsNotInSecrets(Person.BOB)[0].id
        didComm.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, to)
                .from(JWM.ALICE_DID)
                .build()
        )
    }

    @Test
    fun `Test_from_param_is_did_from_msg_is_did_url`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(from = getKeyAgreementMethodsInSecrets(Person.ALICE)[0].id)
        assertThrows<DIDCommIllegalArgumentException> {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(msg, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }
    }

    @Test
    fun `Test_to_param_is_url_to_msg_is_did_positive`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(to = listOf(JWM.ALICE_DID, JWM.BOB_DID))
        didComm.packEncrypted(
            PackEncryptedParams.Builder(msg, getKeyAgreementMethodsInSecrets(Person.BOB)[0].id)
                .build()
        )
    }

    @Test
    fun `Test_from_param_is_url_from_msg_is_did_positive`() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val msg = JWM.PLAINTEXT_MESSAGE.copy(from = JWM.ALICE_DID)
        didComm.packEncrypted(
            PackEncryptedParams.Builder(msg, JWM.BOB_DID)
                .from(getKeyAgreementMethodsInSecrets(Person.ALICE)[0].id)
                .build()
        )
    }

    data class ToFromDifferentCurvesTestData(
        val curveTypeSender: KeyAgreementCurveType,
        val curveTypeRecipient: KeyAgreementCurveType
    )

    class TestToFromDifferentCurves {

        companion object {

            @JvmStatic
            fun toFromDifferentCurvesData(): Stream<ToFromDifferentCurvesTestData> {
                return Stream.of(
                    ToFromDifferentCurvesTestData(KeyAgreementCurveType.P256, KeyAgreementCurveType.P256),
                    ToFromDifferentCurvesTestData(KeyAgreementCurveType.P256, KeyAgreementCurveType.P521),
                    ToFromDifferentCurvesTestData(KeyAgreementCurveType.P256, KeyAgreementCurveType.X25519),
                    ToFromDifferentCurvesTestData(KeyAgreementCurveType.P521, KeyAgreementCurveType.P521),
                    ToFromDifferentCurvesTestData(KeyAgreementCurveType.P521, KeyAgreementCurveType.X25519),
                    ToFromDifferentCurvesTestData(KeyAgreementCurveType.X25519, KeyAgreementCurveType.X25519),
                )
            }
        }

        @ParameterizedTest
        @MethodSource("toFromDifferentCurvesData")
        fun testToFromDifferentCurves(data: ToFromDifferentCurvesTestData) {
            if (data.curveTypeRecipient == data.curveTypeSender) return

            val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())
            val fromKid = getKeyAgreementMethodsInSecrets(Person.ALICE, data.curveTypeSender)[0].id
            val toKid = getKeyAgreementMethodsInSecrets(Person.BOB, data.curveTypeRecipient)[0].id
            assertThrows<IncompatibleCryptoException> {
                didComm.packEncrypted(
                    PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, toKid)
                        .from(fromKid)
                        .build()
                )
            }
        }
    }
}
