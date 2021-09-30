package org.dif.crypto.key

import org.dif.exceptions.DIDDocException
import org.dif.exceptions.DIDDocNotResolvedException
import org.dif.exceptions.IncompatibleCryptoException
import org.dif.exceptions.SecretNotFoundException
import org.dif.fixtures.JWM
import org.dif.mock.AliceSecretResolverMock
import org.dif.mock.CharlieSecretResolverMock
import org.dif.mock.DIDDocResolverMock
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SenderKeySelectorTest {
    @Test
    fun `Test_find_anon_crypto_keys_by_DID`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val keys = senderKeySelector.findAnonCryptKeys(JWM.BOB_DID)

        val expected = listOf(
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        )

        assertContentEquals(expected, keys.map { it.id })
    }

    @Test
    fun `Test_find_anon_crypto_keys_by_DID_URL`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val keys = senderKeySelector.findAnonCryptKeys("did:example:bob#key-x25519-2")

        val expected = listOf("did:example:bob#key-x25519-2")
        assertContentEquals(expected, keys.map { it.id })
    }

    @Test
    fun `Test_find_signing_key_by_DID`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val key = senderKeySelector.findSigningKey(JWM.ALICE_DID)

        val expected = "did:example:alice#key-1"
        assertEquals(expected, key.id)
    }

    @Test
    fun `Test_find_signing_key_by_DID_URL`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val key = senderKeySelector.findSigningKey("did:example:alice#key-2")

        val expected = "did:example:alice#key-2"
        assertEquals(expected, key.id)
    }

    @Test
    fun `Test_find_auth_crypto_keys_by_DID`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val (from, to) = senderKeySelector.findAuthCryptKeys(JWM.ALICE_DID, JWM.BOB_DID)

        val expected = Pair(
            "did:example:alice#key-x25519-1",
            listOf(
                "did:example:bob#key-x25519-1",
                "did:example:bob#key-x25519-2",
                "did:example:bob#key-x25519-3"
            )
        )

        assertEquals(expected.first, from.id)
        assertContentEquals(expected.second, to.map { it.id })
    }

    @Test
    fun `Test_find_auth_crypto_keys_by_Alice_DID_URL`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val (from, to) = senderKeySelector.findAuthCryptKeys("did:example:alice#key-x25519-1", JWM.BOB_DID)

        val expected = Pair(
            "did:example:alice#key-x25519-1",
            listOf(
                "did:example:bob#key-x25519-1",
                "did:example:bob#key-x25519-2",
                "did:example:bob#key-x25519-3"
            )
        )

        assertEquals(expected.first, from.id)
        assertContentEquals(expected.second, to.map { it.id })
    }

    @Test
    fun `Test_find_auth_crypto_keys_by_Bob_DID_URL`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val (from, to) = senderKeySelector.findAuthCryptKeys(JWM.ALICE_DID, "did:example:bob#key-x25519-3")

        val expected = Pair(
            "did:example:alice#key-x25519-1",
            listOf(
                "did:example:bob#key-x25519-3"
            )
        )

        assertEquals(expected.first, from.id)
        assertContentEquals(expected.second, to.map { it.id })
    }

    @Test
    fun `Test_find_auth_crypto_keys_by_DID_URL`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val (from, to) = senderKeySelector.findAuthCryptKeys("did:example:alice#key-x25519-1", "did:example:bob#key-x25519-3")

        val expected = Pair(
            "did:example:alice#key-x25519-1",
            listOf(
                "did:example:bob#key-x25519-3"
            )
        )

        assertEquals(expected.first, from.id)
        assertContentEquals(expected.second, to.map { it.id })
    }

    @Test
    fun `Test_find_second_type_auth_key`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val expectedSenderKey = "did:example:alice#key-p256-1"
        val expectedRecipientKeys = listOf(
            "did:example:bob#key-p256-1",
            "did:example:bob#key-p256-2"
        )

        val (sender) = senderKeySelector.findAuthCryptKeys(JWM.ALICE_DID, "did:example:bob#key-p256-2")
        assertEquals(expectedSenderKey, sender.id)

        val (_, recipients) = senderKeySelector.findAuthCryptKeys("did:example:alice#key-p256-1", JWM.BOB_DID)
        assertContentEquals(expectedRecipientKeys, recipients.map { it.id })
    }

    @Test
    fun `Test_signing_key_not_found_by_DID`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())

        val actual = assertFailsWith<DIDDocException> {
            senderKeySelector.findSigningKey(JWM.BOB_DID)
        }

        assertEquals("The DID Doc '${JWM.BOB_DID}' does not contain compatible 'authentication' verification methods", actual.message)
    }

    @Test
    fun `Test_key_not_found_by_DID_URL`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val expected = "The Secret 'did:example:alice#key-x25519-3' not found"
        val didUrl = "did:example:alice#key-x25519-3"

        run {
            val actual = assertFailsWith<SecretNotFoundException> {
                senderKeySelector.findSigningKey(didUrl)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<SecretNotFoundException> {
                senderKeySelector.findAuthCryptKeys(didUrl, "did:example:bob#key-x25519-1")
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<SecretNotFoundException> {
                senderKeySelector.findAuthCryptKeys(didUrl, JWM.BOB_DID)
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_verification_method_not_found_by_DID_URL`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val expected = "Verification method 'did:example:bob#key-4' not found in DID Doc 'did:example:bob'"
        val didUrl = "did:example:bob#key-4"

        run {
            val actual = assertFailsWith<DIDDocException> {
                senderKeySelector.findAnonCryptKeys(didUrl)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDDocException> {
                senderKeySelector.findAuthCryptKeys(JWM.ALICE_DID, didUrl)
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_DID_Doc_not_resolved`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())
        val did = JWM.NONA_DID
        val expected = "The DID Doc '$did' not resolved"

        run {
            val actual = assertFailsWith<DIDDocNotResolvedException> {
                senderKeySelector.findSigningKey(did)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDDocNotResolvedException> {
                senderKeySelector.findAnonCryptKeys(did)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDDocNotResolvedException> {
                senderKeySelector.findAuthCryptKeys(JWM.ALICE_DID, did)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDDocNotResolvedException> {
                senderKeySelector.findAuthCryptKeys(did, JWM.ALICE_DID)
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_empty_DID_Doc`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), AliceSecretResolverMock())

        run {
            val actual = assertFailsWith<DIDDocException> {
                senderKeySelector.findSigningKey(JWM.ELLIE_DID)
            }

            assertEquals("The DID Doc '${JWM.ELLIE_DID}' does not contain compatible 'authentication' verification methods", actual.message)
        }

        run {
            val actual = assertFailsWith<DIDDocException> {
                senderKeySelector.findAnonCryptKeys(JWM.ELLIE_DID)
            }

            assertEquals("The DID Doc '${JWM.ELLIE_DID}' does not contain compatible 'keyAgreement' verification methods", actual.message)
        }

        run {
            val actual = assertFailsWith<IncompatibleCryptoException> {
                senderKeySelector.findAuthCryptKeys(JWM.ELLIE_DID, JWM.BOB_DID)
            }

            assertEquals("The DID Docs '${JWM.ELLIE_DID}' and '${JWM.BOB_DID}' do not contain compatible 'keyAgreement' verification methods", actual.message)
        }

        run {
            val actual = assertFailsWith<IncompatibleCryptoException> {
                senderKeySelector.findAuthCryptKeys(JWM.ALICE_DID, JWM.ELLIE_DID)
            }

            assertEquals("The DID Docs '${JWM.ALICE_DID}' and '${JWM.ELLIE_DID}' do not contain compatible 'keyAgreement' verification methods", actual.message)
        }
    }

    @Test
    fun `Test_incompatible_Crypto`() {
        val senderKeySelector = SenderKeySelector(DIDDocResolverMock(), CharlieSecretResolverMock())
        val bobDIDUrl = "did:example:bob#key-p256-1"
        val charlieDIDUrl = "did:example:charlie#key-x25519-1"

        run {
            val actual = assertFailsWith<IncompatibleCryptoException> {
                senderKeySelector.findAuthCryptKeys(JWM.CHARLIE_DID, bobDIDUrl)
            }

            assertEquals("The DID Docs '${JWM.CHARLIE_DID}' and '${JWM.BOB_DID}' do not contain compatible 'keyAgreement' verification methods", actual.message)
        }

        run {
            val actual = assertFailsWith<IncompatibleCryptoException> {
                senderKeySelector.findAuthCryptKeys(charlieDIDUrl, bobDIDUrl)
            }

            assertEquals("The recipient '$bobDIDUrl' curve is not compatible to 'X25519'", actual.message)
        }
    }
}
