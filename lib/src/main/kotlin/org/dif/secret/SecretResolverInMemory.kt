package org.didcommx.didcomm.secret

import java.util.Optional

class SecretResolverInMemory(private val secrets: Map<String, Secret>) : SecretResolver {
    constructor(docs: List<Secret>) : this(docs.map { it.kid to it }.toMap())

    override fun findKey(kid: String): Optional<Secret> =
        Optional.ofNullable(secrets[kid])

    override fun findKeys(kids: List<String>): Set<String> =
        kids.intersect(this.secrets.keys)
}
