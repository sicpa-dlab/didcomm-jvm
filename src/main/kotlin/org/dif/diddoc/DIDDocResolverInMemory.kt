package org.dif.diddoc

import java.util.Optional

class DIDDocResolverInMemory(private val docs: Map<String, DIDDoc>) : DIDDocResolver {
    constructor(docs: List<DIDDoc>) : this(docs.map { it.did to it }.toMap())

    override fun resolve(did: String): Optional<DIDDoc> =
        docs[did]?.let { Optional.of(it) } ?: Optional.empty()
}
