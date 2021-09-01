package org.dif.crypto.key

import org.dif.diddoc.DIDDocResolver
import org.dif.exceptions.DIDDocException
import org.dif.exceptions.DIDDocNotResolvedException
import org.dif.exceptions.SecretNotFoundException
import org.dif.secret.SecretResolver
import org.dif.utils.isDIDFragment

class SenderKeySelector(private val didDocResolver: DIDDocResolver, private val secretResolver: SecretResolver) {
    fun signKey(selector: String): Key = Key.wrapSecret(
        if (isDIDFragment(selector)) {
            secretResolver.findKey(selector).orElseThrow { throw SecretNotFoundException(selector) }
        } else {
            val didDoc = didDocResolver.resolve(selector).orElseThrow { throw DIDDocNotResolvedException(selector) }

            val authentication = didDoc.authentications.firstOrNull()
                ?: throw DIDDocException("Authentication is not found in DID Doc '$selector'")

            secretResolver.findKey(authentication).orElseThrow { throw SecretNotFoundException(selector) }
        }
    )
}
