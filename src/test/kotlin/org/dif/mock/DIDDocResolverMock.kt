package org.dif.mock

import org.dif.diddoc.DIDDoc
import org.dif.diddoc.DIDDocResolver
import java.util.Optional

class DIDDocResolverMock : DIDDocResolver {
    override fun resolve(did: String): Optional<DIDDoc> {
        TODO("Not yet implemented")
    }
}
