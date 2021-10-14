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
    val signedFrom: String,
    val protectSenderId: Boolean,
    var to: String,
    var from: String
)

class PackAuthEncryptedTest {
    companion object {

        @JvmStatic
        fun packAuthEncryptedTest(): Stream<PackAuthEncryptedTestData> {
            val toList =
                getKeyAgreementMethodsInSecrets(Person.BOB, KeyAgreementCurveType.X25519).map { it.id }.toMutableList()
            toList.add(JWM.BOB_DID)

            val fromList = getKeyAgreementMethodsInSecrets(Person.ALICE).map { it.id }.toMutableList()
            fromList.add(JWM.ALICE_DID)

            val signedFromList = getAuthMethodsInSecrets(Person.ALICE).map { it.id }.toMutableList()
            signedFromList.add(JWM.ALICE_DID)

            val cartesianProduct = cartesianProduct(
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
                signedFromList,
                listOf(true, false),
                toList,
                fromList
            )
            var stream = Stream.of<PackAuthEncryptedTestData>()

            for (i in cartesianProduct.indices) {
                stream = Stream.concat(
                    stream,
                    Stream.of(
                        PackAuthEncryptedTestData(
                            cartesianProduct[i][0] as Message,
                            cartesianProduct[i][1] as AuthCryptAlg,
                            cartesianProduct[i][2] as AnonCryptAlg,
                            cartesianProduct[i][3] as KeyAgreementCurveType,
                            cartesianProduct[i][4] as String,
                            cartesianProduct[i][5] as Boolean,
                            cartesianProduct[i][6] as String,
                            cartesianProduct[i][7] as String
                        )
                    )
                )
            }

            return stream
        }
    }

    @ParameterizedTest
    @MethodSource("packAuthEncryptedTest")
    fun testAuthcryptSenderDIDRecipientDID(data: PackAuthEncryptedTestData) {
        data.to = JWM.BOB_DID
        data.curveType = KeyAgreementCurveType.X25519
        data.from = JWM.ALICE_DID
        checkAuthcrypt(data)
    }

    @ParameterizedTest
    @MethodSource("packAuthEncryptedTest")
    fun testAuthcryptSenderDIDRecipientKid(data: PackAuthEncryptedTestData) {
        data.curveType = KeyAgreementCurveType.X25519
        data.from = JWM.ALICE_DID
        checkAuthcrypt(data)
    }

    fun checkAuthcrypt(data: PackAuthEncryptedTestData) {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = try {
            didComm.packEncrypted(
                PackEncryptedParams.builder(message = data.msg, to = data.to)
                    .from(data.from)
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

        var expectedTo = listOf(data.to)
        if (!isDIDUrl(data.to)) {
            expectedTo =
                getKeyAgreementMethodsInSecrets(
                    Person.BOB,
                    data.curveType
                ).map { it.id }
        }

        var expectedFrom = data.from
        if (!isDIDUrl(data.from)) {
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
