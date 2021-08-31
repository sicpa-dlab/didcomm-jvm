package org.dif.secret

import java.util.Optional

class SecretResolverInMemory(private val secrets: Map<String, Secret>) : SecretResolver {
    constructor(docs: List<Secret>) : this(docs.map { it.kid to it }.toMap())

    override fun findKey(kid: String): Optional<Secret> =
        secrets[kid]?.let { Optional.of(it) } ?: Optional.empty()

    override fun findKeys(kids: List<String>): List<Secret> =
        kids.map { findKey(it) }.filter { it.isPresent }.map { it.get() }
}
