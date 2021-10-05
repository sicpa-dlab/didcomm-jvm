package org.didcommx.didcomm.secret

interface SecretResolverEditable : SecretResolver {

    fun addKey(secret: Secret)
    fun getKids(): List<String>
}
