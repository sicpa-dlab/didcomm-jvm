package org.didcommx.didcomm.diddoc

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DIDDocEncodingTest {

    @Test
    fun testEncodingDecoding() {

        listOf(
            DID_DOC_ALICE_SPEC_TEST_VECTORS,
            DID_DOC_ALICE_WITH_NO_SECRETS,
            DID_DOC_BOB_SPEC_TEST_VECTORS,
            DID_DOC_BOB_WITH_NO_SECRETS,
            DID_DOC_CHARLIE,
            DID_DOC_ELLIE,
            DID_DOC_MEDIATOR1_SPEC_TEST_VECTORS,
            DID_DOC_MEDIATOR1,
            DID_DOC_MEDIATOR2_SPEC_TEST_VECTORS,
            DID_DOC_MEDIATOR2
        ).forEach { doc ->

            val encoded = doc.encodeJson(true)
            println { encoded }

            val decoded: DIDDoc = DIDDoc.fromJson(encoded)
            assertEquals(doc.encodeJson(), decoded.encodeJson())
        }
    }

    @Test
    fun testEmbeddedVerificationMethods() {

        val diddocJson = """
        {
          "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
          "authentication": [
            {
              "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
              "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
            },
            {
              "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9#6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
              "publicKeyMultibase": "z6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg"
            }
          ],
          "keyAgreement": [
            {
              "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9#6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
              "type": "X25519KeyAgreementKey2020",
              "controller": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9",
              "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            }
          ],
          "service": [
            {
              "id": "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCJ9#didcommmessaging-0",
              "type": "DIDCommMessaging",
              "serviceEndpoint": "https://example.com/endpoint"
            }
          ]
        }            
        """.trimIndent()

        val didDoc: DIDDoc = DIDDoc.fromJson(diddocJson)
        println(didDoc.encodeJson(true))

        assertEquals(2, didDoc.authentications.size)
        assertEquals(1, didDoc.keyAgreements.size)
        assertEquals(3, didDoc.verificationMethods.size)
        assertEquals("https://example.com/endpoint", didDoc.didCommServices[0].serviceEndpoint)

        val vmIds: List<String> = didDoc.verificationMethods.map { vm -> vm.id }
        assertTrue(vmIds.containsAll(didDoc.authentications))
        assertTrue(vmIds.containsAll(didDoc.keyAgreements))
    }
}
