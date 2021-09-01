package org.dif.crypto.key

import com.nimbusds.jose.jwk.Curve
import org.dif.diddoc.DIDDocResolver
import org.dif.exceptions.DIDDocException
import org.dif.exceptions.DIDDocNotResolvedException
import org.dif.exceptions.IncompatibleCryptoException
import org.dif.exceptions.SecretNotFoundException
import org.dif.secret.SecretResolver
import org.dif.utils.divideDIDFragment
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

    fun authCryptKeys(fromSelector: String, toSelector: String): Pair<Key, List<Key>> {
        val (did) = divideDIDFragment(fromSelector)
        val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

        return if (isDIDFragment(fromSelector)) {
            val sender = secretResolver.findKey(fromSelector)
                .map { Key.wrapSecret(it) }
                .orElseThrow { throw SecretNotFoundException(fromSelector) }

            val recipients = findRecipientKeys(toSelector, sender.curve)
            Pair(sender, recipients)
        } else {
            didDoc.keyAgreements
                .asSequence()
                .map { secretResolver.findKey(it) }
                .filter { it.isPresent }
                .map { it.get() }
                .map { Key.wrapSecret(it) }
                .map { Pair(it, findRecipientKeys(toSelector, it.curve)) }
                .find { it.second.isNotEmpty() }
                ?: throw IncompatibleCryptoException("DID Doc does not contain compatible verification method")
        }
    }

    fun anonCryptKeys(selector: String): List<Key> = findRecipientKeys(selector, null)
        .ifEmpty { throw IncompatibleCryptoException("DID Doc does not contain compatible verification method") }

    private fun findRecipientKeys(selector: String, curve: Curve?): List<Key> {
        val (did) = divideDIDFragment(selector)
        val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

        return if (isDIDFragment(selector)) {
            val method = didDoc.findVerificationMethod(selector)
            val key = Key.wrapVerificationMethod(method)

            if (curve != null && curve != key.curve) {
                throw IncompatibleCryptoException("The recipient `$selector` curve is not compatible to `${curve.name}`")
            }

            listOf(key)
        } else {
            didDoc.keyAgreements
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.wrapVerificationMethod(it) }
                .filter { curve?.equals(it.curve) ?: true }
        }
    }
}
