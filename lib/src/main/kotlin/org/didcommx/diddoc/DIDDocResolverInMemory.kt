package org.didcommx.didcomm.diddoc

import java.util.Optional

class DIDDocResolverInMemory(private val docs: Map<String, DIDDoc>) : DIDDocResolver {
    constructor(docs: List<DIDDoc>) : this(docs.map { it.did to it }.toMap())

    override fun resolve(did: String): Optional<DIDDoc> =
        Optional.ofNullable(docs[did])
}
