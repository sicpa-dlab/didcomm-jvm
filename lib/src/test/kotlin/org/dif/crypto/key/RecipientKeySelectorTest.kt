package org.dif.crypto.key

import org.dif.exceptions.DIDDocException
import org.dif.exceptions.DIDUrlNotFoundException
import org.dif.exceptions.IncompatibleCryptoException
import org.dif.exceptions.SecretNotFoundException
import org.dif.fixtures.JWM
import org.dif.mock.BobSecretResolverMock
import org.dif.mock.DIDDocResolverMock
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RecipientKeySelectorTest {
    @Test
    fun `Test_find_verification_key`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val expected = "did:example:alice#key-2"
        val key = recipientKeySelector.findVerificationKey(expected)
        assertEquals(expected, key.id)
    }

    @Test
    fun `Test_find_anon_crypto_keys`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        val expected = listOf(
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        )

        val keys = recipientKeySelector.findAnonCryptKeys(expected)
        assertContentEquals(expected, keys.toList().map { it.id })
    }

    @Test
    fun `Test_find_second_anon_crypto_key`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        val recipient = listOf(
            "did:example:bob#key-x25519-4",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-5"
        )

        val expected = listOf(
            "did:example:bob#key-x25519-2"
        )

        val keys = recipientKeySelector.findAnonCryptKeys(recipient)
        assertContentEquals(expected, keys.map { it.id }.toList())
    }

    @Test
    fun `Test_find_auth_crypto_keys`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        val sender = "did:example:alice#key-x25519-1"
        val recipient = listOf(
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        )

        val (from, to) = recipientKeySelector.findAuthCryptKeys(sender, recipient)

        val expected = Pair(
            "did:example:alice#key-x25519-1",
            listOf(
                "did:example:bob#key-x25519-1",
                "did:example:bob#key-x25519-2",
                "did:example:bob#key-x25519-3"
            )
        )

        assertEquals(expected.first, from.id)
        assertContentEquals(expected.second, to.toList().map { it.id })
    }

    @Test
    fun `Test_DID_is_passed_to_methods`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        run {
            val actual = assertFailsWith<IllegalStateException> {
                recipientKeySelector.findVerificationKey(JWM.ALICE_DID)
            }

            assertEquals("'DID URL' is expected as a signature verification key. Got: did:example:alice", actual.message)
        }

        run {
            val actual = assertFailsWith<IllegalStateException> {
                recipientKeySelector.findAuthCryptKeys(JWM.ALICE_DID, listOf(JWM.BOB_DID))
            }

            assertEquals("'DID URL' is expected as a sender key. Got: did:example:alice", actual.message)
        }

        run {
            val actual = assertFailsWith<IllegalStateException> {
                recipientKeySelector.findAnonCryptKeys(listOf(JWM.BOB_DID))
            }

            assertEquals("'DID URL' is expected as a recipient key. Got: did:example:bob", actual.message)
        }
    }

    @Test
    fun `Test_key_not_found`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val didUrl = "did:example:bob#key-x25519-4"
        val expected = "The Secret '$didUrl' not found"

        run {
            val actual = assertFailsWith<SecretNotFoundException> {
                recipientKeySelector.findAnonCryptKeys(listOf(didUrl))
                    .also { it.toList() }
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<SecretNotFoundException> {
                recipientKeySelector.findAuthCryptKeys("did:example:alice#key-x25519-1", listOf(didUrl))
                    .also { it.second.toList() }
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_verification_method_not_found`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val expected = "Verification method 'did:example:bob#key-4' not found in DID Doc 'did:example:bob'"
        val didUrl = "did:example:bob#key-4"

        run {
            val actual = assertFailsWith<DIDDocException> {
                recipientKeySelector.findAuthCryptKeys(didUrl, listOf(didUrl))
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDDocException> {
                recipientKeySelector.findVerificationKey(didUrl)
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_DID_Doc_not_resolved`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val did = JWM.NONA_DID
        val didUrl = "$did#key-1"
        val expected = "The DID URL '$did' not found"

        run {
            val actual = assertFailsWith<DIDUrlNotFoundException> {
                recipientKeySelector.findVerificationKey(didUrl)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDUrlNotFoundException> {
                recipientKeySelector.findAuthCryptKeys(didUrl, listOf())
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_empty_DID_Doc`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val didUrl = "${JWM.ELLIE_DID}#key-2"
        val expected = "Verification method '$didUrl' not found in DID Doc 'did:example:ellie'"

        run {
            val actual = assertFailsWith<DIDDocException> {
                recipientKeySelector.findVerificationKey(didUrl)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDDocException> {
                recipientKeySelector.findAuthCryptKeys(didUrl, listOf())
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_incompatible_Crypto`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val bobDIDUrl = "did:example:bob#key-p256-1"
        val charlieDIDUrl = "did:example:charlie#key-x25519-1"

        run {
            val actual = assertFailsWith<IncompatibleCryptoException> {
                recipientKeySelector.findAuthCryptKeys(charlieDIDUrl, listOf(bobDIDUrl)).also { it.second.toList() }
            }

            assertEquals("The recipient '$bobDIDUrl' curve is not compatible to 'X25519'", actual.message)
        }
    }
}
