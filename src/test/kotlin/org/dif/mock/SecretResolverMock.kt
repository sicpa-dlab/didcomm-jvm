package org.dif.mock

import org.dif.secret.Secret
import org.dif.secret.SecretResolver
import java.util.*

class SecretResolverMock: SecretResolver {
    override fun findKey(kid: String): Optional<Secret> {
        TODO("Not yet implemented")
    }

    override fun findKeys(kids: List<String>): List<Secret> {
        TODO("Not yet implemented")
    }
}