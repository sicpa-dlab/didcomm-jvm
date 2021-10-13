package org.didcommx.didcomm.pack.signed

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.Person
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.getAuthMethodsInSecrets
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.messages.attachmentJsonMsg
import org.didcommx.didcomm.messages.attachmentMulti1msg
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackSignedParams
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

data class PackSignedTestData(
    val msgList: List<Message>,
    val signedFromList: List<String>
)

class PackSignedTest {
    companion object {

        @JvmStatic
        fun packSignedTest(): Stream<PackSignedTestData> {
            val signedFromList = getAuthMethodsInSecrets(Person.ALICE).map { it.id }.toMutableList()
            signedFromList.add(JWM.ALICE_DID)

            return Stream.of(
                PackSignedTestData(
                    listOf(JWM.PLAINTEXT_MESSAGE, attachmentMulti1msg(), attachmentJsonMsg()),
                    signedFromList
                ),
            )
        }
    }

    @ParameterizedTest
    @MethodSource("packSignedTest")
    fun testAnoncrypt(data: PackSignedTestData) {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        for (msg in data.msgList) {
            for (signFrom in data.signedFromList) {
                val packResult = didComm.packSigned(
                    PackSignedParams.builder(message = msg, signFrom = signFrom).build()
                )

                var expectedSignFrm = getAuthMethodsInSecrets(Person.ALICE)[0].id
                if (signFrom != JWM.ALICE_DID) {
                    expectedSignFrm = signFrom
                }

                assertEquals(packResult.signFromKid, expectedSignFrm)
                assertNotNull(packResult.packedMessage)

                val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

                val unpackResult = unpack(
                    keySelector = recipientKeySelector,
                    params = UnpackParams.Builder(packResult.packedMessage)
                        .secretResolver(BobSecretResolverMock())
                        .expectDecryptByAllKeys(true)
                        .build()
                )
                assertEquals(unpackResult.message.toString(), msg.toString())
                assertTrue(unpackResult.metadata.nonRepudiation)
                assertTrue(unpackResult.metadata.authenticated)
                assertNull(unpackResult.metadata.encAlgAnon)
                assertNull(unpackResult.metadata.encAlgAuth)
                assertFalse(unpackResult.metadata.anonymousSender)
                assertFalse(unpackResult.metadata.encrypted)
                assertFalse(unpackResult.metadata.reWrappedInForward)
            }
        }
    }
}
