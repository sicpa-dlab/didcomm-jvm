package org.didcommx.didcomm.mock

import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.diddoc.DIDDocResolverInMemory
import org.didcommx.didcomm.diddoc.DID_DOC_ALICE_SPEC_TEST_VECTORS
import org.didcommx.didcomm.diddoc.DID_DOC_BOB_SPEC_TEST_VECTORS
import org.didcommx.didcomm.diddoc.DID_DOC_CHARLIE
import org.didcommx.didcomm.diddoc.DID_DOC_ELLIE
import org.didcommx.didcomm.diddoc.DID_DOC_MEDIATOR1
import org.didcommx.didcomm.diddoc.DID_DOC_MEDIATOR2
import java.util.Optional

class DIDDocResolverMock : DIDDocResolver {
    private val didDocResolver = DIDDocResolverInMemory(
        listOf(
            DID_DOC_ALICE_SPEC_TEST_VECTORS,
            DID_DOC_BOB_SPEC_TEST_VECTORS,
            DID_DOC_CHARLIE,
            DID_DOC_MEDIATOR1,
            DID_DOC_MEDIATOR2,
            DID_DOC_ELLIE
        )
    )

    override fun resolve(did: String): Optional<DIDDoc> =
        didDocResolver.resolve(did)
}
