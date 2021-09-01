package org.dif.secret

import java.util.Optional

class SecretResolverInMemory(private val secrets: Map<String, Secret>) : SecretResolver {
    constructor(docs: List<Secret>) : this(docs.map { it.kid to it }.toMap())

    override fun findKey(kid: String): Optional<Secret> =
        Optional.ofNullable(secrets[kid])

    override fun findKeys(kids: List<String>): List<Secret> =
        kids.mapNotNull { findKey(it).orElse(null) }
}
