package org.didcommx.didcomm.pack.encrypted

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.KeyAgreementCurveType
import org.didcommx.didcomm.Person
import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
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
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

data class PackAnonEncryptedTestData(
    val msgList: List<Message>,
    val algList: List<AnonCryptAlg>,
    val toList: List<String>,
    val signedFromList: List<String>
)

class PackAnonEncryptedTest {
    companion object {

        @JvmStatic
        fun packAnonEncryptedTest(): Stream<PackAnonEncryptedTestData> {
            val toList = getKeyAgreementMethodsInSecrets(Person.BOB).map { it.id }.toMutableList()
            toList.add(JWM.BOB_DID)

            val signedFromList = getAuthMethodsInSecrets(Person.ALICE).map { it.id }.toMutableList()
            signedFromList.add(JWM.ALICE_DID)

            return Stream.of(
                PackAnonEncryptedTestData(
                    listOf(JWM.PLAINTEXT_MESSAGE, attachmentMulti1msg(), attachmentJsonMsg()),
                    listOf(
                        AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW,
                        AnonCryptAlg.A256GCM_ECDH_ES_A256KW,
                        AnonCryptAlg.XC20P_ECDH_ES_A256KW
                    ),
                    toList,
                    signedFromList
                ),
            )
        }
    }

    @ParameterizedTest
    @MethodSource("packAnonEncryptedTest")
    fun testAnoncrypt(data: PackAnonEncryptedTestData) {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        for (msg in data.msgList) {
            for (signFrom in data.signedFromList) {
                for (to in data.toList) {
                    for (alg in data.algList) {
                        val packResult = didComm.packEncrypted(
                            PackEncryptedParams.builder(message = msg, to = to)
                                .signFrom(signFrom)
                                .build()
                        )

                        var expectedTo = listOf(to)
                        if (to == JWM.BOB_DID) {
                            expectedTo = getKeyAgreementMethodsInSecrets(Person.BOB, KeyAgreementCurveType.X25519).map { it.id }
                        }

                        val expectedSignFrm = if (signFrom != JWM.ALICE_DID) {
                            signFrom
                        } else {
                            getAuthMethodsInSecrets(Person.ALICE)[0].id
                        }

                        assertNull(packResult.fromKid)
                        assertEquals(packResult.toKids, expectedTo)
                        assertEquals(packResult.signFromKid, expectedSignFrm)
                        assertNotNull(packResult.packedMessage)

                        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

                        val unpackResult = unpack(
                            keySelector = recipientKeySelector,
                            params = UnpackParams.Builder(packResult.packedMessage)
                                .expectDecryptByAllKeys(true)
                                .build()
                        )
                        assertEquals(unpackResult.message.toString(), msg.toString())
                        assertTrue(
                            unpackResult.metadata.encAlgAnon == alg ||
                                unpackResult.metadata.encAlgAnon == AnonCryptAlg.XC20P_ECDH_ES_A256KW
                        )
                        assertNull(unpackResult.metadata.encAlgAuth)
                        assertTrue(unpackResult.metadata.anonymousSender)
                        assertTrue(unpackResult.metadata.encrypted)
                        assertEquals(unpackResult.metadata.nonRepudiation, signFrom != "")
                        assertEquals(unpackResult.metadata.authenticated, signFrom != "")
                        assertFalse(unpackResult.metadata.reWrappedInForward)
                    }
                }
            }
        }
    }
}
