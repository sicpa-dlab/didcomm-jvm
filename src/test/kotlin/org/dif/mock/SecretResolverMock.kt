package org.dif.mock

import org.dif.secret.Secret
import org.dif.secret.SecretResolver
import java.util.Optional

class SecretResolverMock : SecretResolver {
    override fun findKey(kid: String): Optional<Secret> =
        Optional.empty()

    override fun findKeys(kids: List<String>): List<Secret> =
        listOf()
}
