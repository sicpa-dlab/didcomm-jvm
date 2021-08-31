package org.dif.crypto.key

import org.dif.diddoc.DIDDocResolver
import org.dif.exceptions.DIDDocException
import org.dif.exceptions.DIDDocNotFoundException
import org.dif.secret.Secret
import org.dif.secret.SecretResolver
import org.dif.utils.divideDIDFragment
import org.dif.utils.isDIDFragment

class RecipientKeySelector(private val didDocResolver: DIDDocResolver, private val secretResolver: SecretResolver) {
    fun verifyKey(selector: String): Key = Key.wrapSecret(
        let {
            val (did) = divideDIDFragment(selector)
            val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotFoundException(did) }

            val verificationMethodId = if (isDIDFragment(selector)) { selector } else {
                didDoc.authentications.firstOrNull()
                    ?: throw DIDDocException("Authentication is not found in DID Doc '$did'")
            }

            val verificationMethod = didDoc.verificationMethods.find { it.id == verificationMethodId }
                ?: throw DIDDocException("Verification method '$verificationMethodId' is not found in DID Doc '$did'")

            Secret(verificationMethod.id, verificationMethod.type, verificationMethod.verificationMaterial)
        }
    )
}
