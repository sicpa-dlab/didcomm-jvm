package org.didcommx.didcomm.secret

import org.didcommx.didcomm.utils.fromJsonToList
import org.didcommx.didcomm.utils.toJson
import org.didcommx.secret.jwkToSecret
import org.didcommx.secret.secretToJwk
import java.io.File
import java.util.*
import kotlin.io.path.Path
import kotlin.io.path.exists

class SecretResolverDemo(private val filePath: String = "secrets.json") : SecretResolverEditable {

    private val secrets: MutableMap<String, Secret>

    init {
        if (!Path(filePath).exists()) {
            secrets = mutableMapOf()
            save()
        } else {
            val secretsJson = File(filePath).readText()
            secrets = if (secretsJson.isNotEmpty()) {
                fromJsonToList(secretsJson).map { jwkToSecret(it) }.associate { it.kid to it }.toMutableMap()
            } else {
                mutableMapOf()
            }
        }
    }

    private fun save() {
        val secretJson = toJson(secrets.values.map { secretToJwk(it) })
        File(filePath).writeText(secretJson)
    }

    override fun addKey(secret: Secret) {
        secrets.put(secret.kid, secret)
        save()
    }

    override fun getKids(): List<String> =
        secrets.keys.toList()

    override fun findKey(kid: String): Optional<Secret> =
        Optional.ofNullable(secrets.get(kid))

    override fun findKeys(kids: List<String>): Set<String> =
        kids.intersect(secrets.keys)


}