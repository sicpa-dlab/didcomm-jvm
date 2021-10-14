package org.didcommx.didcomm.pack.signed

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.Person
import org.didcommx.didcomm.cartesianProduct
import org.didcommx.didcomm.exceptions.UnsupportedAlgorithm
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
import org.didcommx.didcomm.utils.isJDK15Plus
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

data class PackSignedTestData(
    val msg: Message,
    val signedFrom: String
)

class PackSignedTest {
    companion object {

        @JvmStatic
        fun packSignedTest(): Stream<PackSignedTestData> {
            val signedFromList = getAuthMethodsInSecrets(Person.ALICE).map { it.id }.toMutableList()
            signedFromList.add(JWM.ALICE_DID)

            return cartesianProduct(
                listOf(JWM.PLAINTEXT_MESSAGE, attachmentMulti1msg(), attachmentJsonMsg()),
                signedFromList
            ).map {
                PackSignedTestData(
                    it[0] as Message,
                    it[1] as String
                )
            }.stream()
        }
    }

    @ParameterizedTest
    @MethodSource("packSignedTest")
    fun testSigned(data: PackSignedTestData) {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = try {
            didComm.packSigned(
                PackSignedParams.builder(message = data.msg, signFrom = data.signedFrom).build()
            )
        } catch (e: UnsupportedAlgorithm) {
            Assumptions.assumeTrue(!isJDK15Plus())
            throw e
        }

        var expectedSignFrm = getAuthMethodsInSecrets(Person.ALICE)[0].id
        if (data.signedFrom != JWM.ALICE_DID) {
            expectedSignFrm = data.signedFrom
        }

        assertEquals(packResult.signFromKid, expectedSignFrm)
        assertNotNull(packResult.packedMessage)

        val unpackResult = didComm.unpack(
            params = UnpackParams.Builder(packResult.packedMessage)
                .secretResolver(BobSecretResolverMock())
                .expectDecryptByAllKeys(true)
                .build()
        )

        assertEquals(unpackResult.message.toString(), data.msg.toString())
        assertTrue(unpackResult.metadata.nonRepudiation)
        assertTrue(unpackResult.metadata.authenticated)
        assertNull(unpackResult.metadata.encAlgAnon)
        assertNull(unpackResult.metadata.encAlgAuth)
        assertFalse(unpackResult.metadata.anonymousSender)
        assertFalse(unpackResult.metadata.encrypted)
        assertFalse(unpackResult.metadata.reWrappedInForward)
    }
}
