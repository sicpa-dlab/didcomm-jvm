package org.didcommx.didcomm.pack.encrypted

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.KeyAgreementCurveType
import org.didcommx.didcomm.Person
import org.didcommx.didcomm.cartesianProduct
import org.didcommx.didcomm.common.AnonCryptAlg
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
import org.didcommx.didcomm.utils.isJDK15Plus
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

data class PackAnonEncryptedTestData(
    val msg: Message,
    val alg: AnonCryptAlg,
    val to: String,
    val signedFrom: String,
    val protectSenderID: Boolean
)

class PackAnonEncryptedTest {
    companion object {

        @JvmStatic
        fun packAnonEncryptedTest(): Stream<PackAnonEncryptedTestData> {
            val toList = getKeyAgreementMethodsInSecrets(Person.BOB).map { it.id }.toMutableList()
            toList.add(JWM.BOB_DID)

            val signedFromList = getAuthMethodsInSecrets(Person.ALICE).map { it.id }.toMutableList()
            signedFromList.add(JWM.ALICE_DID)

            return cartesianProduct(
                listOf(JWM.PLAINTEXT_MESSAGE, attachmentMulti1msg(), attachmentJsonMsg()),
                listOf(
                    AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW,
                    AnonCryptAlg.A256GCM_ECDH_ES_A256KW,
                    AnonCryptAlg.XC20P_ECDH_ES_A256KW
                ),
                toList, signedFromList,
                listOf(true, false)
            ).map {
                PackAnonEncryptedTestData(
                    it[0] as Message,
                    it[1] as AnonCryptAlg,
                    it[2] as String,
                    it[3] as String,
                    it[4] as Boolean
                )
            }.stream()
        }
    }

    @ParameterizedTest
    @MethodSource("packAnonEncryptedTest")
    fun testAnoncrypt(data: PackAnonEncryptedTestData) {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packResult = try {
            didComm.packEncrypted(
                PackEncryptedParams.builder(message = data.msg, to = data.to)
                    .signFrom(data.signedFrom)
                    .protectSenderId(data.protectSenderID)
                    .build()
            )
        } catch (e: UnsupportedAlgorithm) {
            assumeTrue(!isJDK15Plus())
            throw e
        }

        var expectedTo = listOf(data.to)
        if (data.to == JWM.BOB_DID) {
            expectedTo =
                getKeyAgreementMethodsInSecrets(Person.BOB, KeyAgreementCurveType.X25519).map { it.id }
        }

        val expectedSignFrm = if (data.signedFrom != JWM.ALICE_DID) {
            data.signedFrom
        } else {
            getAuthMethodsInSecrets(Person.ALICE)[0].id
        }

        assertNull(packResult.fromKid)
        assertEquals(packResult.toKids, expectedTo)
        assertEquals(packResult.signFromKid, expectedSignFrm)
        assertNotNull(packResult.packedMessage)

        val didCommUnpack = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())
        val unpackResult = didCommUnpack.unpack(
            params = UnpackParams.Builder(packResult.packedMessage)
                .expectDecryptByAllKeys(true)
                .build()
        )
        assertEquals(unpackResult.message.toString(), data.msg.toString())
        assertTrue(
            unpackResult.metadata.encAlgAnon == data.alg ||
                unpackResult.metadata.encAlgAnon == AnonCryptAlg.XC20P_ECDH_ES_A256KW
        )
        assertNull(unpackResult.metadata.encAlgAuth)
        assertTrue(unpackResult.metadata.anonymousSender)
        assertTrue(unpackResult.metadata.encrypted)
        assertEquals(unpackResult.metadata.nonRepudiation, data.signedFrom != "")
        assertEquals(unpackResult.metadata.authenticated, data.signedFrom != "")
        assertFalse(unpackResult.metadata.reWrappedInForward)
    }
}
