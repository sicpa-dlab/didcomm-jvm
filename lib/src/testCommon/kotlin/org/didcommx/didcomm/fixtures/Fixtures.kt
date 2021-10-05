package org.didcommx.didcomm.fixtures

import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.common.AuthCryptAlg
import org.didcommx.didcomm.common.SignAlg
import org.didcommx.didcomm.exceptions.DIDCommException
import org.didcommx.didcomm.exceptions.DIDDocException
import org.didcommx.didcomm.exceptions.IncompatibleCryptoException
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.exceptions.UnsupportedAlgorithm
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.Metadata
import org.didcommx.didcomm.model.UnpackParams
import kotlin.reflect.KClass

class JWM {
    data class WrongMessage(val json: String, val expectedMessage: String)

    data class ExpectedAttachmentData(
        val isJson: Boolean = false,
        val isLinks: Boolean = false,
        val isBase64: Boolean = false,
    )

    data class CorrectAttachment(
        val json: String,
        val expectedAttachmentData: List<ExpectedAttachmentData>
    )

    companion object {
        const val ALICE_DID = "did:example:alice"
        const val BOB_DID = "did:example:bob"
        const val CHARLIE_DID = "did:example:charlie"
        const val NONA_DID = "did:example:nona"
        const val ELLIE_DID = "did:example:ellie"

        private const val ID = "1234567890"
        private const val TYPE = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        private val BODY = mapOf("messagespecificattribute" to "and its value")

        val PLAINTEXT_MESSAGE = Message.builder(ID, BODY, TYPE)
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()

        val PLAINTEXT_MESSAGE_WITHOUT_BODY = """
            {
               "id":"1234567890",
               "typ":"application/didcomm-plain+json",
               "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
               "from":"did:example:alice",
               "to":[
                  "did:example:bob"
               ],
               "created_time":1516269022,
               "expires_time":1516385931
            }
        """.trimIndent()

        val CORRECT_ATTACHMENTS: List<CorrectAttachment> = listOf(
            CorrectAttachment(
                json = """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "links": ["1", "2", "3"],
                                "hash": "qwerty"
                            }
                       }]
                     }
                """.trimIndent(),
                expectedAttachmentData = listOf(
                    ExpectedAttachmentData(isLinks = true)
                )
            ),

            CorrectAttachment(
                json = """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "base64": "qwerty"
                            }
                       }]
                     }
                """.trimIndent(),
                expectedAttachmentData = listOf(
                    ExpectedAttachmentData(isBase64 = true)
                )
            ),

            CorrectAttachment(
                json = """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "json": {
                                    "foo": "bar",
                                    "links": [2, 3]
                                }
                            }
                       }]
                     }
                """.trimIndent(),
                expectedAttachmentData = listOf(
                    ExpectedAttachmentData(isJson = true)
                )
            ),

            CorrectAttachment(
                json = """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{
                          
                       },
                       "attachments":[
                          {
                             "id":"23",
                             "data":{
                                "json":{
                                   "foo":"bar",
                                   "links":[
                                      2,
                                      3
                                   ]
                                }
                             }
                          },
                          {
                             "id":"23",
                             "data":{
                                "base64":"qwerty"
                             }
                          },
                          {
                             "id":"23",
                             "data":{
                                "links":[
                                   "1",
                                   "2",
                                   "3"
                                ],
                                "hash":"qwerty"
                             }
                          }
                       ]
                    }
                """.trimIndent(),
                expectedAttachmentData = listOf(
                    ExpectedAttachmentData(isJson = true),
                    ExpectedAttachmentData(isBase64 = true),
                    ExpectedAttachmentData(isLinks = true)
                )
            ),

            CorrectAttachment(
                json = """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "links": ["1", "2", "3"],
                                "hash": "qwerty"
                            }
                       }, { 
                            "id": "23",
                            "data": {
                                "base64": "qwerty"
                            }
                       }, { 
                            "id": "23",
                            "data": {
                                "links": ["1", "2", "3"],
                                "hash": "qwerty"
                            }
                       }]
                     }
                """.trimIndent(),
                expectedAttachmentData = listOf(
                    ExpectedAttachmentData(isLinks = true),
                    ExpectedAttachmentData(isBase64 = true),
                    ExpectedAttachmentData(isLinks = true)
                )
            )
        )

        val WRONG_ATTACHMENTS: List<WrongMessage> = listOf(
            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{}]
                     }
                """.trimIndent(),
                "The header \"id\" is missing"
            ),

            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23"
                       }]
                     }
                """.trimIndent(),
                "The header \"data\" is missing"
            ),

            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {}
                       }]
                     }
                """.trimIndent(),
                "Unknown attachment data"
            ),

            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "links": ["231", "212"]
                            }
                       }]
                     }
                """.trimIndent(),
                "The header \"hash\" is missing"
            ),

            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": "131"
                     }
                """.trimIndent(),
                "The expected type of header 'attachments' is 'JSONArray'. Got 'String'"
            ),

            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [2131]
                     }
                """.trimIndent(),
                "The expected type of header 'attachments' is 'Map'. Got 'Long'"
            ),

            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{
                           "id": 2 
                       }]
                     }
                """.trimIndent(),
                "The expected type of header 'id' is 'String'. Got 'Long'"
            ),

            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{
                           "id": "1",
                           "data": null
                       }]
                     }
                """.trimIndent(),
                "The header \"data\" is missing"
            ),

            WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{
                           "id": "1",
                           "data": "null"
                       }]
                     }
                """.trimIndent(),
                "The expected type of header 'data' is 'Map'. Got 'String'"
            )
        )
    }
}

class JWS {
    data class TestVector(val from: String, val expected: String)

    companion object {
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
}

class JWE {
    data class TestVector(val message: String, val expectedMetadata: Metadata)
    data class NegativeTestVector<T : Throwable>(
        val packedMessage: String,
        val expectedThrow: KClass<T>,
        val expectedMessage: String,
        val unpackParams: UnpackParams = UnpackParams.Builder(packedMessage).build()
    )

    companion object {
        val TEST_VECTORS = listOf(
            TestVector(
                message =
                """
                {
                   "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
                   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "recipients":[
                      {
                         "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
                         "header":{
                            "kid":"did:example:bob#key-x25519-1"
                         }
                      },
                      {
                         "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
                         "header":{
                            "kid":"did:example:bob#key-x25519-2"
                         }
                      },
                      {
                         "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
                         "header":{
                            "kid":"did:example:bob#key-x25519-3"
                         }
                      }
                   ],
                   "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
                   "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
                }
                """.trimIndent(),
                expectedMetadata = Metadata(
                    encrypted = true,
                    anonymousSender = true,
                    encryptedTo = listOf(
                        "did:example:bob#key-x25519-1",
                        "did:example:bob#key-x25519-2",
                        "did:example:bob#key-x25519-3"
                    ),
                    encAlgAnon = AnonCryptAlg.XC20P_ECDH_ES_A256KW
                )
            ),

            TestVector(
                message = """
                {
                   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "recipients":[
                      {
                         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
                         "header":{
                            "kid":"did:example:bob#key-p256-1"
                         }
                      },
                      {
                         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
                         "header":{
                            "kid":"did:example:bob#key-p256-2"
                         }
                      }
                   ],
                   "tag":"t8ioLvZhsCp7A93jvdf3wA",
                   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
                }
                """.trimIndent(),
                expectedMetadata = Metadata(
                    encrypted = true,
                    anonymousSender = true,
                    encryptedTo = listOf("did:example:bob#key-p256-1", "did:example:bob#key-p256-2"),
                    encAlgAnon = AnonCryptAlg.XC20P_ECDH_ES_A256KW
                )
            ),

            TestVector(
                message = """
                {
                   "ciphertext":"HPnc9w7jK0T73Spifq_dcVJnONbT9MZ9oorDJFEBJAfmwYRqvs1rKue-udrNLTTH0qjjbeuji01xPRF5JiWyy-gSMX4LHdLhPxHxjjQCTkThY0kapofU85EjLPlI4ytbHiGcrPIezqCun4iDkmb50pwiLvL7XY1Ht6zPUUdhiV6qWoPP4qeY_8pfH74Q5u7K4TQ0uU3KP8CVZQuafrkOBbqbqpJV-lWpWIKxil44f1IT_GeIpkWvmkYxTa1MxpYBgOYa5_AUxYBumcIFP-b6g7GQUbN-1SOoP76EzxZU_louspzQ2HdEH1TzXw2LKclN8GdxD7kB0H6lZbZLT3ScDzSVSbvO1w1fXHXOeOzywuAcismmoEXQGbWZm7wJJJ2r",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiIxNjFhZ0dlYWhHZW1IZ25qSG1RX0JfU09OeUJWZzhWTGRoVGdWNVc1NFZiYWJ5bGxpc3NuWjZXNzc5SW9VcUtyIiwieSI6ImNDZXFlRmdvYm9fY1ItWTRUc1pCWlg4dTNCa2l5TnMyYi12ZHFPcU9MeUNuVmdPMmpvN25zQV9JQzNhbnQ5T1gifSwiYXB2IjoiTEpBOUVva3M1dGFtVUZWQmFsTXdCaEo2RGtEY0o4SEs0U2xYWldxRHFubyIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC1FUytBMjU2S1cifQ",
                   "recipients":[
                      {
                         "encrypted_key":"SlyWCiOaHMMH9CqSs2CHpRd2XwbueZ1-MfYgKVepXWpgmTgtsgNOAaYwV5pxK3D67HV51F-vLBFlAHke7RYp_GeGDFYhAf5s",
                         "header":{
                            "kid":"did:example:bob#key-p384-1"
                         }
                      },
                      {
                         "encrypted_key":"5e7ChtaRgIlV4yS4NSD7kEo0iJfFmL_BFgRh3clDKBG_QoPd1eOtFlTxFJh-spE0khoaw8vEEYTcQIg4ReeFT3uQ8aayz1oY",
                         "header":{
                            "kid":"did:example:bob#key-p384-2"
                         }
                      }
                   ],
                   "tag":"bkodXkuuwRbqksnQNsCM2YLy9f0v0xNgnhSUAoFGtmE",
                   "iv":"aE1XaH767m7LY0JTN7RsAA"
                }
                """.trimIndent(),
                expectedMetadata = Metadata(
                    encrypted = true,
                    anonymousSender = true,
                    encryptedTo = listOf("did:example:bob#key-p384-1", "did:example:bob#key-p384-2"),
                    encAlgAnon = AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW
                )
            ),

            TestVector(
                message = """
                {
                   "ciphertext":"mxnFl4s8FRsIJIBVcRLv4gj4ru5R0H3BdvyBWwXV3ILhtl_moqzx9COINGomP4ueuApuY5xdMDvRHm2mLo6N-763wjNSjAibNrqVZC-EG24jjYk7RPZ26fEW4z87LHuLTicYCD4yHqilRbRgbOCT0Db5221Kec0HDZTXLzBqVwC2UMyDF4QT6Uz3fE4f_6BXTwjD-sEgM67wWTiWbDJ3Q6WyaOL3W4ukYANDuAR05-SXVehnd3WR0FOg1hVcNRao5ekyWZw4Z2ekEB1JRof3Lh6uq46K0KXpe9Pc64UzAxEID93SoJ0EaV_Sei8CXw2aJFmZUuCf8YISWKUz6QZxRvFKUfYeflldUm9U2tY96RicWgUhuXgv",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBRWtrc09abW1oZkZYdU90MHMybVdFYlVybVQ3OXc1SFRwUm9TLTZZNXpkYlk5T0I5b2RHb2hDYm1PeGpqY2VhWUU5ZnNaX3RaNmdpTGFBNUFEUnBrWE5VIiwieSI6IkFDaWJnLXZEMmFHVEpHbzlmRUl6Q1dXT2hSVUlObFg3Q1hGSTJqeDlKVDZmTzJfMGZ3SzM2WTctNHNUZTRpRVVSaHlnU1hQOW9TVFczTkdZTXVDMWlPQ3AifSwiYXB2IjoiR09lbzc2eW02TkNnOVdXTUVZZlcwZVZEVDU2Njh6RWhsMnVBSVctRS1IRSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC1FUytBMjU2S1cifQ",
                   "recipients":[
                      {
                         "encrypted_key":"W4KOy5W88iPPsDEdhkJN2krZ2QAeDxOIxW-4B21H9q89SHWexocCrw",
                         "header":{
                            "kid":"did:example:bob#key-p521-1"
                         }
                      },
                      {
                         "encrypted_key":"uxKPkF6-sIiEkdeJcUPJY4lvsRg_bvtLPIn7eIycxLJML2KM6-Llag",
                         "header":{
                            "kid":"did:example:bob#key-p521-2"
                         }
                      }
                   ],
                   "tag":"aPZeYfwht2Nx9mfURv3j3g",
                   "iv":"lGKCvg2xrvi8Qa_D"
                }
                """.trimIndent(),
                expectedMetadata = Metadata(
                    encrypted = true,
                    anonymousSender = true,
                    encryptedTo = listOf("did:example:bob#key-p521-1", "did:example:bob#key-p521-2"),
                    encAlgAnon = AnonCryptAlg.A256GCM_ECDH_ES_A256KW
                )
            ),

            TestVector(
                message = """
                {
                   "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
                   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
                   "recipients":[
                      {
                         "encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                         "header":{
                            "kid":"did:example:bob#key-x25519-1"
                         }
                      },
                      {
                         "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                         "header":{
                            "kid":"did:example:bob#key-x25519-2"
                         }
                      },
                      {
                         "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
                         "header":{
                            "kid":"did:example:bob#key-x25519-3"
                         }
                      }
                   ],
                   "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
                   "iv":"o02OXDQ6_-sKz2PX_6oyJg"
                }
                """.trimIndent(),
                expectedMetadata = Metadata(
                    encrypted = true,
                    authenticated = true,
                    encryptedTo = listOf(
                        "did:example:bob#key-x25519-1",
                        "did:example:bob#key-x25519-2",
                        "did:example:bob#key-x25519-3"
                    ),
                    encryptedFrom = "did:example:alice#key-x25519-1",
                    encAlgAuth = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
                )
            ),

            TestVector(
                message = """
                {
                   "ciphertext":"WCufCs2lMZfkxQ0JCK92lPtLFgwWk_FtRWOMj52bQISa94nEbIYqHDUohIbvLMgbSjRcJVusZO04UthDuOpSSTcV5GBi3O0cMrjyI_PZnTb1yikLXpXma1bT10D2r5TPtzRMxXF3nFsr9y0JKV1TsMtn70Df2fERx2bAGxcflmd-A2sMlSTT8b7QqPtn17Yb-pA8gr4i0Bqb2WfDzwnbfewbukpRmPA2hsEs9oLKypbniAafSpoiQjfb19oDfsYaWWXqsdjTYMflqH__DqSmW52M-SUp6or0xU0ujbHmOkRkcdh9PsR5YsPuIWAqYa2hfjz_KIrGTxvCos0DMiZ4Lh_lPIYQqBufSdFH5AGChoekFbQ1vcyIyYMFugzOHOgZ2TwEzv94GCgokBHQR4_qaU_f4Mva64KPwqOYdm5f4KX16afTJa-IV7ar7__2L-A-LyxmC5KIHeGOedV9kzZBLC7TuzRAuE3vY7pkhLB1jPE6XpTeKXldljaeOSEVcbFUQtsHOSPz9JXuhqZ1fdAx8qV7hUnSAd_YMMDR3S6SXtem8ak2m98WPvKIxhCbcto7W2qoNYMT7MPvvid-QzUvTdKtyovCvLzhyYJzMjZxmn9-EnGhZ5ITPL_xFfLyKxhSSUVz3kSwK9xuOj3KpJnrrD7xrp5FKzEaJVIHWrUW90V_9QVLjriThZ36fA3ipvs8ZJ8QSTnGAmuIQ6Z2u_r4KsjL_mGAgn47qyqRm-OSLEUE4_2qB0Q9Z7EBKakCH8VPt09hTMDR62aYZYwtmpNs9ISu0VPvFjh8UmKbFcQsVrz90-x-r-Q1fTX9JaIFcDy7aqKcI-ai3tVF_HDR60Jaiw",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJObHJ3UHZ0SUluZWNpeUVrYTRzMi00czhPalRidEZFQVhmTC12Z2x5enFvIiwieSI6ImhiMnZkWE5zSzVCQ2U3LVhaQ0dfLTY0R21UT19rNUlNWFBaQ00xdGFUQmcifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktcDI1Ni0xIiwiYXB1IjoiWkdsa09tVjRZVzF3YkdVNllXeHBZMlVqYTJWNUxYQXlOVFl0TVEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImFsZyI6IkVDREgtMVBVK0EyNTZLVyJ9",
                   "recipients":[
                      {
                         "encrypted_key":"ZIL6Leligq1Xps_229nlo1xB_tGxOEVoEEMF-XTOltI0QXjyUoq_pFQBCAnVdcWNH5bmaiuzCYOmZ9lkyXBkfHO90KkGgODG",
                         "header":{
                            "kid":"did:example:bob#key-p256-1"
                         }
                      },
                      {
                         "encrypted_key":"sOjs0A0typIRSshhQoiJPoM4o7YpR5LA8SSieHZzmMyIDdD8ww-4JyyQhqFYuvfS4Yt37VF4z7Nd0OjYVNRL-iqPnoJ3iCOr",
                         "header":{
                            "kid":"did:example:bob#key-p256-2"
                         }
                      }
                   ],
                   "tag":"nIpa3EQ29hgCkA2cBPde2HpKXK4_bvmL2x7h39rtVEc",
                   "iv":"mLqi1bZLz7VwqtVVFsDiLg"
                }
                """.trimIndent(),
                expectedMetadata = Metadata(
                    encrypted = true,
                    authenticated = true,
                    nonRepudiation = true,
                    encryptedTo = listOf("did:example:bob#key-p256-1", "did:example:bob#key-p256-2"),
                    encryptedFrom = "did:example:alice#key-p256-1",
                    signFrom = "did:example:alice#key-1",
                    encAlgAuth = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW,
                    signAlg = SignAlg.ED25519,
                    signedMessage = mapOf()
                )
            ),

            TestVector(
                message = """
                {
                   "ciphertext":"lfYmR7CNas5hOePxWQEkUEwzSRds3t5GkMW4VUZKJWJ7H3y1X8a1RnUg3c0BCqdszzhZk8xE0vfQ67vJAWGdev8OWy7oGY_e1o4iAVj3mPNfnV5N7sjld6yUhrxqDsxtmVAp7LAipbJNhxqBoEXdb8hPbdPeUIov-5X0_cQHpHalSD6zMoyUPb0cCnw8bfmdN3aaVDrzsZRIkvhezZCkaQFMO75XKVEDyTzn8Eqwgpg_tzD_Hr00jHa9mTyTiDA_1ZzqleF-XSe5NEtFc7_BukgjPWMZAouPMWwIP0h-BPULxUzYcWKfC6hiU2ZuxWz8Fs8v9r6MCAaPOG37oA_yfWwE_FWl7x61sl6iZfDVQhOTkdlXNoZ0LiaC4ImXop2wSvKimkGqhysj1OefrUrpHmSx1qNz7vCWqW8Mo7fykXQCVYr6zXmcvWF5-KvXDu6DR3EFlgs6An9tWLv1flDrZWb-lS6RlL6Z8AqmLjP0Yb2r6mTopiulTTpXXpwe-Qs1_DHDGi0DfsZmcYhyra-F8YQ3tGIgy6wWCtyBh7Fq_zRy8RMvV3DkaLHYTekIle0YOoRdZRJBb3ycXHycIi7iT1ewOFlIGjsBg73Hkqa6O1weewS3uIxl4veO6cBOksfDRpC279X9tV1HDqROBolNBsWHQ2UpUD1Bat8UnfJMrwBcZkGQCjhlR9SSlZzEIqP3leRh5e2y2FGTm7wNRNwmgl6s6OUiKD-nbUnnSugGzolbavafHS80XrdfEuUyuPjnpQQQROapFfcjd7dSLd58g9OjOEqb1-Edk4KcW-yYU17_zfIzv1qykEH7F22Nq9HGbReXuao83ItUWgpBDZ-uf-_RbcpW2X1U5QGnI1SF4Trbhx74lnswEF_AlZ4SUh7frcMfKQLYobT1X_wIEY8pwN1AzWf482LJKKsxm0EcY73vf0n3uT_OS3EgBNCVYyF6_snm7MdOV-RM5ZZyQl64BsZ4aL4RVVCOa8bxYGPxvpOf9Ay-aQjwYQfyFxayRJiQWkywk8SRAdLLfSiveqvXAoIIi_XI98CRIaJ6DSKr-TuCDlz4yVP_8emS_S0S7F-Buh-P6nzjdJ04CAm95p6do_q8jk1IRHvubqrPKcpvk4U3p-6obJK9feJPffoe3-ddJvKJ5h8Et3xEKG7oId3NkbbFfYUnkEyC_wUeKtyrXK8uBz5HKhW1S27qsBAnKv5WTCyfrDsfX0eTaqdeJ3O9uR4niBc2sa2t89G5AEKWcOUnJcytAAAuhMZiz2zXXhmffPG5A7QSmZMAl75CP6ulN0KCBE0nTeuvNPueqpF4PV4CCcMfokz0hu5k5oo9FHfkQMVDBTiQUtEezIXiglqhu6VwcDgbbatAKUIYxnoisHKPg17zGMl5VMULVY5WBYPAUylKpWELnMc9BHUHNUxfSVlqdd847v__D1Go17MTsQujVGQQuM61Ay0-z1JwN0fki0M8t20U_sWX5jNMbdZCPBxy7rpZlztaF01j1NCaM3ZPh-_KLy8vQ584R5I5LlE5OejgyLQYMOMzSgUZZEAeTGV_S-kEnt36k-L8Kbyv_LWuiuTQzwLSwlmWOKLdDbmjEjA1JsEaKmorDKz0q7MFIoC-gKKJBjPTJ5PxJLJj4RHOxxDWhx00HjLLE3S1B6uAvKVUhN4ka_wWusVqffrRZm_e7Oz0hbCO8pT4tzlbFWTu0-O44kHkRjfubEi4PnaNzKbGMXTrDo7aY6sgiDB8KlJSsKrNeG0OLjBAYF_zmHlrqctFQidTD_YIDzcSfkCTrMoOYa07nXG6E1nArScOgkNuNkPVhCq_VD6w-pZ1mSUBwKVCnjNueTrB5RvFBydaoWcAAX3OtH8yFeDWGzlRYWJNKEKull_Vah8B7nwwnTPxyeUwnr2txlwDvLx9ASrl5CjwvLc9bL7jCa6SrWt3hPjvjDY4JdFxnCqyyXD11Mpt2kyA4TTBaBbzI5Kja6pKsCUw0QCTCfTBu7bKGTOJKai32c4WRXvpVgIowOzdyjtKD0LgnY2fRTpJWpcTMVAHPfSad0jc23iTwOKcJQ0n_ExfOxzW_PSvAYbakrRwdZdDefb_fLrILxgS7OA9KepGQOJnp0-X_o1bBkXsm_cvVhcprLViUxHR1uCTMXaUl24viekps45aODvfBj5OsG3GrEShqtLb7ukEHEJjLsIe1l-4kFtNp4RlPZlapYgNyMSjnGopw2D51khuOHdJ2yLWASgFJPIa4dan4KTcDhp7qmbijN8JR_s_p1DB4E1nFlQPuncA8lIiuGv2PKHKXQkkuHcKmPMYTjRlam5IBHXQPV_njHMAIV60XU8kxa5G7t-Iwl_6OeRIj_HXdf5mfdTNEYlwbQWHInkS4U32RD9Kf0u6SC1bpRZx6AbFK8xlIgUPhB_sP3kG_ZZIZhcJ1Oy6Q7pAzmKXZYWKMkDWZk7a-WsiA0Z8gOcd7PYA13GRIw0MT_GIRcFRfkp7821j2ArHHo6jagqMdEuCZHzHrfwD0XHzT4FP3-aTaHIqrKx0TiYRfn2k2Q",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBYmxoeVVENUxYNE9zWDhGRTVaODRBX09CYThiOHdhVUhXSFExbTBnczhuSFVERDdySDlJRWRZbzJUSzFQYU5ha05aSk54a1FBWC1aUkxWa1BoNnV4eTJNIiwieSI6IkFQTjh6c0xEZGJpVjN0LTloWTJFQzFVZWEzTm5tMzFtNWowRmNiUWM0Y2ZWQmFNdzVCQ2VpcU9QWkljZTVMNjI4bnVORkxKR2szSjh6SVBPYUlLU0xmaTEifSwiYXB2IjoiR09lbzc2eW02TkNnOVdXTUVZZlcwZVZEVDU2Njh6RWhsMnVBSVctRS1IRSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "recipients":[
                      {
                         "encrypted_key":"iuVx5qAiRtijMfHnkF95_ByjHyiAmRqNTrExrEQK4p7HwW7sit1F0g",
                         "header":{
                            "kid":"did:example:bob#key-p521-1"
                         }
                      },
                      {
                         "encrypted_key":"6OWnv-tY1ZDUBt8uRNpmteoXTVDzRGz2UF04Y2eh2-bp2jiViU8VCw",
                         "header":{
                            "kid":"did:example:bob#key-p521-2"
                         }
                      }
                   ],
                   "tag":"pEh6LS1GCTYQaWR-6vAe_Q",
                   "iv":"ZMHYqq1xV1X81bFzzEH_iAfBcL75fznZ"
                }
                """.trimIndent(),
                expectedMetadata = Metadata(
                    encrypted = true,
                    authenticated = true,
                    nonRepudiation = true,
                    anonymousSender = true,
                    encryptedTo = listOf("did:example:bob#key-p521-1", "did:example:bob#key-p521-2"),
                    encryptedFrom = "did:example:alice#key-p521-1",
                    signFrom = "did:example:alice#key-1",
                    encAlgAuth = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW,
                    encAlgAnon = AnonCryptAlg.XC20P_ECDH_ES_A256KW,
                    signAlg = SignAlg.ED25519,
                    signedMessage = mapOf()
                )
            )
        )

        val BOB_DAMAGED_MESSAGE = """
                {
                   "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
                   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "recipients":[
                      {
                         "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1a",
                         "header":{
                            "kid":"did:example:bob#key-x25519-1"
                         }
                      },
                      {
                         "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
                         "header":{
                            "kid":"did:example:bob#key-x25519-2"
                         }
                      },
                      {
                         "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
                         "header":{
                            "kid":"did:example:bob#key-x25519-3"
                         }
                      }
                   ],
                   "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
                   "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
                }
        """.trimIndent()

        val BOB_MESSAGE_WITHOUT_RECIPIENTS = """
                {
                   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "tag":"t8ioLvZhsCp7A93jvdf3wA",
                   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
                }
        """.trimIndent()

        val BOB_MESSAGE_WITHOUT_PROTECTED_HEADER = """
                {
                   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
                   "recipients":[
                      {
                         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
                         "header":{
                            "kid":"did:example:bob#key-p256-1"
                         }
                      },
                      {
                         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
                         "header":{
                            "kid":"did:example:bob#key-p256-2"
                         }
                      }
                   ],
                   "tag":"t8ioLvZhsCp7A93jvdf3wA",
                   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
                }
        """.trimIndent()

        val BOB_MESSAGE_WITHOUT_CIPHERTEXT = """
                {
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "recipients":[
                      {
                         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
                         "header":{
                            "kid":"did:example:bob#key-p256-1"
                         }
                      },
                      {
                         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
                         "header":{
                            "kid":"did:example:bob#key-p256-2"
                         }
                      }
                   ],
                   "tag":"t8ioLvZhsCp7A93jvdf3wA",
                   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
                }
        """.trimIndent()

        val BOB_MESSAGE_WITHOUT_TAG = """
                {
                   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "recipients":[
                      {
                         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
                         "header":{
                            "kid":"did:example:bob#key-p256-1"
                         }
                      },
                      {
                         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
                         "header":{
                            "kid":"did:example:bob#key-p256-2"
                         }
                      }
                   ],
                   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
                }
        """.trimIndent()

        val BOB_MESSAGE_WITHOUT_IV = """
                {
                   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "recipients":[
                      {
                         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
                         "header":{
                            "kid":"did:example:bob#key-p256-1"
                         }
                      },
                      {
                         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
                         "header":{
                            "kid":"did:example:bob#key-p256-2"
                         }
                      }
                   ],
                   "tag":"t8ioLvZhsCp7A93jvdf3wA"
                }
        """.trimIndent()

        val BOB_MESSAGE_UNSUPPORTED_ALG_HEADER = """
                {
                   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NUtXIn0=",
                   "recipients":[
                      {
                         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
                         "header":{
                            "kid":"did:example:bob#key-p256-1"
                         }
                      },
                      {
                         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
                         "header":{
                            "kid":"did:example:bob#key-p256-2"
                         }
                      }
                   ],
                   "tag":"t8ioLvZhsCp7A93jvdf3wA",
                   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
                }
        """.trimIndent()

        val BOB_MESSAGE_UNSUPPORTED_ENC_HEADER = """
                {
                   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
                   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwMiIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0=",
                   "recipients":[
                      {
                         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
                         "header":{
                            "kid":"did:example:bob#key-p256-1"
                         }
                      },
                      {
                         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
                         "header":{
                            "kid":"did:example:bob#key-p256-2"
                         }
                      }
                   ],
                   "tag":"t8ioLvZhsCp7A93jvdf3wA",
                   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
                }
        """.trimIndent()

        val BOB_ANON_MESSAGE_RECIPIENT_KEY_IS_INVALID = """
                {
                   "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
                   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                   "recipients":[
                      {
                         "encrypted_key":"3n1olyBR3nY7ZGAprOx-\b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
                         "header":{
                            "kid":"did:example:bob#key-x25519-1"
                         }
                      },
                      {
                         "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
                         "header":{
                            "kid":"did:example:bob#key-x25519-2"
                         }
                      },
                      {
                         "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
                         "header":{
                            "kid":"did:example:bob#key-x25519-3"
                         }
                      }
                   ],
                   "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
                   "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
                }
        """.trimIndent()

        val MESSAGE_ALICE_SKID_NOT_FOUND = """
                {
                   "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
                   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTUiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ==",
                   "recipients":[
                      {
                         "encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                         "header":{
                            "kid":"did:example:bob#key-x25519-1"
                         }
                      },
                      {
                         "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                         "header":{
                            "kid":"did:example:bob#key-x25519-2"
                         }
                      },
                      {
                         "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
                         "header":{
                            "kid":"did:example:bob#key-x25519-3"
                         }
                      }
                   ],
                   "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
                   "iv":"o02OXDQ6_-sKz2PX_6oyJg"
                }
        """.trimIndent()

        val MESSAGE_ALICE_AND_BOB_KEYS_FROM_DIFFERENT_CURVES = """
                {
                   "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
                   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ==",
                   "recipients":[
                      {
                         "encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                         "header":{
                            "kid":"did:example:bob#key-p384-1"
                         }
                      },
                      {
                         "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                         "header":{
                            "kid":"did:example:bob#key-p384-2"
                         }
                      },
                      {
                         "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
                         "header":{
                            "kid":"did:example:bob#key-p384-3"
                         }
                      }
                   ],
                   "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
                   "iv":"o02OXDQ6_-sKz2PX_6oyJg"
                }
        """.trimIndent()

        val MESSAGE_PROTECTED_HEADER_IS_NOT_BASE64_ENCODED = """
                    {
                       "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
                       "signatures":[
                          {
                             "protected":"eyJ\\\\0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                             "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                             "header":{
                                "kid":"did:example:alice#key-1"
                             }
                          }
                       ]
                    }
        """.trimIndent()

        val NEGATIVE_TEST_VECTORS = listOf(
            NegativeTestVector(
                packedMessage = "",
                expectedThrow = DIDCommException::class,
                expectedMessage = "Message cannot be parsed"
            ),

            NegativeTestVector(
                packedMessage = "{}",
                expectedThrow = DIDCommException::class,
                expectedMessage = "The header \"id\" is missing"
            ),

            NegativeTestVector(
                packedMessage = BOB_MESSAGE_WITHOUT_RECIPIENTS,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "The header \"id\" is missing",
                unpackParams = UnpackParams
                    .Builder(BOB_MESSAGE_WITHOUT_RECIPIENTS)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = BOB_MESSAGE_WITHOUT_PROTECTED_HEADER,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "The header must not be null",
                unpackParams = UnpackParams
                    .Builder(BOB_MESSAGE_WITHOUT_PROTECTED_HEADER)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = BOB_MESSAGE_WITHOUT_CIPHERTEXT,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "The ciphertext must not be null",
                unpackParams = UnpackParams
                    .Builder(BOB_MESSAGE_WITHOUT_CIPHERTEXT)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = BOB_MESSAGE_WITHOUT_TAG,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "Decrypt is failed",
                unpackParams = UnpackParams
                    .Builder(BOB_MESSAGE_WITHOUT_TAG)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = BOB_MESSAGE_WITHOUT_IV,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "Decrypt is failed",
                unpackParams = UnpackParams
                    .Builder(BOB_MESSAGE_WITHOUT_IV)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = BOB_DAMAGED_MESSAGE,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "Decrypt is failed",
                unpackParams = UnpackParams
                    .Builder(BOB_DAMAGED_MESSAGE)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = BOB_MESSAGE_UNSUPPORTED_ALG_HEADER,
                expectedThrow = UnsupportedAlgorithm::
                class,
                expectedMessage = "The algorithm ECDH-ES+A255KW+XC20P is unsupported",
                unpackParams = UnpackParams
                    .Builder(BOB_MESSAGE_UNSUPPORTED_ALG_HEADER)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = BOB_MESSAGE_UNSUPPORTED_ENC_HEADER,
                expectedThrow = UnsupportedAlgorithm::
                class,
                expectedMessage = "The algorithm ECDH-ES+A256KW+XC202 is unsupported",
                unpackParams = UnpackParams
                    .Builder(BOB_MESSAGE_UNSUPPORTED_ENC_HEADER)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = BOB_ANON_MESSAGE_RECIPIENT_KEY_IS_INVALID,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "Decrypt is failed",
                unpackParams = UnpackParams
                    .Builder(BOB_ANON_MESSAGE_RECIPIENT_KEY_IS_INVALID)
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = MESSAGE_ALICE_SKID_NOT_FOUND,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "apu is not equal to skid",
                unpackParams = UnpackParams
                    .Builder(
                        MESSAGE_ALICE_SKID_NOT_FOUND
                    )
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = MESSAGE_ALICE_AND_BOB_KEYS_FROM_DIFFERENT_CURVES,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "apv is invalid",
                unpackParams = UnpackParams
                    .Builder(
                        MESSAGE_ALICE_AND_BOB_KEYS_FROM_DIFFERENT_CURVES
                    )
                    .expectDecryptByAllKeys(true)
                    .build()
            ),

            NegativeTestVector(
                packedMessage = MESSAGE_PROTECTED_HEADER_IS_NOT_BASE64_ENCODED,
                expectedThrow = MalformedMessageException::
                class,
                expectedMessage = "Invalid signature",
                unpackParams = UnpackParams
                    .Builder(
                        MESSAGE_PROTECTED_HEADER_IS_NOT_BASE64_ENCODED
                    )
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        )
    }
}

data class CustomProtocolBody(val id: String, val name: String, val custom: Boolean, val year: Number)
