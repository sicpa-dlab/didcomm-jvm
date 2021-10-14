package org.didcommx.didcomm.pack.encrypted

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.KeyAgreementCurveType
import org.didcommx.didcomm.Person
import org.didcommx.didcomm.cartesianProduct
import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.common.AuthCryptAlg
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
import org.didcommx.didcomm.exceptions.UnsupportedAlgorithm
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.getAuthMethodsInSecrets
import org.didcommx.didcomm.getKeyAgreementMethodsInSecrets
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.messages.attachmentJsonMsg
import org.didcommx.didcomm.messages.attachmentMulti1msg
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.operations.unpack
import org.didcommx.didcomm.utils.isDIDUrl
import org.didcommx.didcomm.utils.isJDK15Plus
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

data class PackAuthEncryptedTestData(
    val msg: Message,
    val authAlg: AuthCryptAlg,
    val anonAlg: AnonCryptAlg,
    var curveType: KeyAgreementCurveType,
    val protectSenderId: Boolean,
    val signedFrom: String
)

class PackAuthEncryptedTest {
    companion object {

        @JvmStatic
        fun packAuthEncryptedTest(): Stream<PackAuthEncryptedTestData> {
            val signedFromList = getAuthMethodsInSecrets(Person.ALICE).map { it.id }.toMutableList()
            signedFromList.add(JWM.ALICE_DID)

            return cartesianProduct(
                listOf(JWM.PLAINTEXT_MESSAGE, attachmentMulti1msg(), attachmentJsonMsg()),
                listOf(
                    AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
                ),
                listOf(
                    AnonCryptAlg.XC20P_ECDH_ES_A256KW,
                    AnonCryptAlg.A256GCM_ECDH_ES_A256KW,
                    AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW
                ),
                listOf(
                    KeyAgreementCurveType.X25519,
                    KeyAgreementCurveType.P256,
                    KeyAgreementCurveType.P521,
                    KeyAgreementCurveType.P384
                ),
                listOf(true, false),
                signedFromList
            ).map {
                PackAuthEncryptedTestData(
                    it[0] as Message,
                    it[1] as AuthCryptAlg,
                    it[2] as AnonCryptAlg,
                    it[3] as KeyAgreementCurveType,
                    it[4] as Boolean,
                    it[5] as String
                )
            }.stream()
        }
    }

    @ParameterizedTest
    @MethodSource("packAuthEncryptedTest")
    fun testAuthcryptSenderDIDRecipientDID(data: PackAuthEncryptedTestData) {
        data.curveType = KeyAgreementCurveType.X25519
        checkAuthcrypt(data, JWM.ALICE_DID, JWM.BOB_DID)
    }

    @ParameterizedTest
    @MethodSource("packAuthEncryptedTest")
    fun testAuthcryptSenderDIDRecipientKid(data: PackAuthEncryptedTestData) {
        val toList =
            getKeyAgreementMethodsInSecrets(Person.BOB, KeyAgreementCurveType.X25519).map { it.id }.toMutableList()
        toList.add(JWM.BOB_DID)
        for (to in toList) {
            data.curveType = KeyAgreementCurveType.X25519
            checkAuthcrypt(data, JWM.ALICE_DID, to)
        }
    }

    @ParameterizedTest
    @MethodSource("packAuthEncryptedTest")
    fun testAuthcryptSenderKidRecipientDID(data: PackAuthEncryptedTestData) {
        val fromList = getKeyAgreementMethodsInSecrets(Person.ALICE, data.curveType).map { it.id }.toMutableList()

        for (from in fromList) {
            checkAuthcrypt(data, from, JWM.BOB_DID)
        }
    }

    @ParameterizedTest
    @MethodSource("packAuthEncryptedTest")
    fun testAuthcryptSenderKidRecipientKid(data: PackAuthEncryptedTestData) {
        val fromList = getKeyAgreementMethodsInSecrets(Person.ALICE, data.curveType).map { it.id }.toMutableList()

        val toList =
            getKeyAgreementMethodsInSecrets(Person.BOB, data.curveType).map { it.id }.toMutableList()

        for (from in fromList) {
            for (to in toList) {
                checkAuthcrypt(data, from, to)
            }
        }
    }

    fun checkAuthcrypt(data: PackAuthEncryptedTestData, from: String, to: String) {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = try {
            didComm.packEncrypted(
                PackEncryptedParams.builder(message = data.msg, to = to)
                    .from(from)
                    .signFrom(data.signedFrom)
                    .protectSenderId(data.protectSenderId)
                    .encAlgAuth(data.authAlg)
                    .encAlgAnon(data.anonAlg)
                    .build()
            )
        } catch (e: UnsupportedAlgorithm) {
            Assumptions.assumeTrue(!isJDK15Plus())
            throw e
        }

        var expectedTo = listOf(to)
        if (!isDIDUrl(to)) {
            expectedTo =
                getKeyAgreementMethodsInSecrets(
                    Person.BOB,
                    data.curveType
                ).map { it.id }
        }

        var expectedFrom = from
        if (!isDIDUrl(from)) {
            expectedFrom =
                getKeyAgreementMethodsInSecrets(
                    Person.ALICE
                )[0].id
        }

        val expectedSignFrm = if (data.signedFrom != JWM.ALICE_DID) {
            data.signedFrom
        } else {
            getAuthMethodsInSecrets(Person.ALICE)[0].id
        }

        assertEquals(packResult.fromKid, expectedFrom)
        assertEquals(packResult.toKids, expectedTo)
        assertEquals(packResult.signFromKid, expectedSignFrm)
        assertNotNull(packResult.packedMessage)

        val recipientKeySelector =
            RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        val unpackResult = unpack(
            keySelector = recipientKeySelector,
            params = UnpackParams.Builder(packResult.packedMessage)
                .expectDecryptByAllKeys(true)
                .build()
        )

        val expectedAnonAlg = if (data.protectSenderId) data.anonAlg else null
        assertEquals(unpackResult.message.toString(), data.msg.toString())
        assertTrue(
            unpackResult.metadata.encAlgAnon == expectedAnonAlg ||
                unpackResult.metadata.encAlgAnon == AnonCryptAlg.XC20P_ECDH_ES_A256KW
        )
        assertTrue(
            unpackResult.metadata.encAlgAuth == data.authAlg ||
                unpackResult.metadata.encAlgAuth == AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
        )
        assertEquals(unpackResult.metadata.anonymousSender, data.protectSenderId)
        assertTrue(unpackResult.metadata.encrypted)
        assertEquals(unpackResult.metadata.nonRepudiation, data.signedFrom != "")
        assertFalse(unpackResult.metadata.reWrappedInForward)
        assertTrue(unpackResult.metadata.authenticated)
    }
}
