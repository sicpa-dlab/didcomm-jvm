package org.didcommx.didcomm.diddoc

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

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
            DID_DOC_MEDIATOR2).forEach { doc ->

            val encoded = doc.encodeJson(true)
            println { encoded }

            val decoded: DIDDoc = DIDDoc.fromJson(encoded)
            assertEquals(doc.encodeJson(), decoded.encodeJson())
        }
    }
}
