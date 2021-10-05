package org.didcommx.didcomm.secret

import java.util.Optional

interface SecretResolverEditable : SecretResolver {

    fun addKey(secret: Secret)
    fun getKids(): List<String>
}
