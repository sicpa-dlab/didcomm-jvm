package org.dif

import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.crypto.parse
import org.dif.message.Message
import org.dif.mock.DIDDocResolverMock
import org.dif.mock.SecretResolverMock
import org.dif.model.PackSignedParams
import org.dif.model.UnpackParams
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class SignedMessageTest {
    data class TestVector(val from: String, val expected: String)

    companion object {
        const val ALICE_DID = "did:example:alice"
        const val BOB_DID = "did:example:bob"

        private const val ID = "1234567890"
        private const val TYPE = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        private val BODY = mapOf("messagespecificattribute" to "and its value")

        val PLAINTEXT_MESSAGE = Message.builder(ID, BODY, TYPE)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val TEST_VECTORS = listOf(
            TestVector(
                from = "did:example:alice#key-1",
                expected = """
                    {
                       "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
                       "signatures":[
                          {
                             "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                             "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                             "header":{
                                "kid":"did:example:alice#key-1"
                             }
                          }
                       ]
                    }
                """.trimIndent()
            ),

            TestVector(
                from = "did:example:alice#key-2",
                expected = """
                    {
                       "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
                       "signatures":[
                          {
                             "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
                             "signature":"gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg",
                             "header":{
                                "kid":"did:example:alice#key-2"
                             }
                          }
                       ]
                    }
                """.trimIndent()
            ),

            TestVector(
                from = "did:example:alice#key-3",
                expected = """
                    {
                       "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
                       "signatures":[
                          {
                             "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
                             "signature":"EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw",
                             "header":{
                                "kid":"did:example:alice#key-3"
                             }
                          }
                       ]
                    }
                """.trimIndent()
            )
        )
    }

    @Test
    fun test_signed_message_test_vectors() {
        for (test in TEST_VECTORS) {
            val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

            val packed = didComm.packSigned(
                PackSignedParams.builder(PLAINTEXT_MESSAGE, test.from).build()
            )

            val unpacked = didComm.unpack(
                UnpackParams.Builder(packed.packedMessage).build()
            )

            val expected = parse(test.expected).jws
            val signed = parse(packed.packedMessage).jws

            assertEquals(expected.payload.toBase64URL().toString(), signed.payload.toBase64URL().toString())
            assertEquals(expected.header.toString(), signed.header.toString())

            assertEquals(
                JSONObjectUtils.toJSONStringForWeb(PLAINTEXT_MESSAGE.toJSONObject()),
                JSONObjectUtils.toJSONStringForWeb(unpacked.message.toJSONObject())
            )
        }
    }
}
