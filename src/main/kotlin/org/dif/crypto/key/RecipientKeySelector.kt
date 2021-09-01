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

class RecipientKeySelector(private val didDocResolver: DIDDocResolver, private val secretResolver: SecretResolver) {
    fun verifyKey(selector: String): Key = Key.wrapVerificationMethod(
        let {
            val (did) = divideDIDFragment(selector)
            val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

            val verificationMethodId = if (isDIDFragment(selector)) { selector } else {
                didDoc.authentications.firstOrNull()
                    ?: throw DIDDocException("Authentication is not found in DID Doc '$did'")
            }

            didDoc.findVerificationMethod(verificationMethodId)
        }
    )

    fun authCryptKeys(fromSelector: String, toSelector: List<String>): Pair<Key, List<Key>> {
        val (did) = divideDIDFragment(fromSelector)
        val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

        return if (isDIDFragment(fromSelector)) {
            val sender = didDocResolver.resolve(did)
                .map { it.findVerificationMethod(fromSelector) }
                .map { Key.wrapVerificationMethod(it) }
                .orElseThrow { throw SecretNotFoundException(fromSelector) }

            val recipients = findRecipientKeys(toSelector, sender.curve)
            Pair(sender, recipients)
        } else {
            didDoc.keyAgreements
                .asSequence()
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.wrapVerificationMethod(it) }
                .map { Pair(it, findRecipientKeys(toSelector, it.curve)) }
                .find { it.second.isNotEmpty() }
                ?: throw IncompatibleCryptoException("DID Doc does not contain compatible verification method")
        }
    }

    fun anonCryptKeys(selector: List<String>): List<Key> = findRecipientKeys(selector, null)
        .ifEmpty { throw IncompatibleCryptoException("DID Doc does not contain compatible verification method") }

    private fun findRecipientKeys(selector: List<String>, curve: Curve?): List<Key> = selector.flatMap {
        didUrl ->
        val (did) = divideDIDFragment(didUrl)
        val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

        if (isDIDFragment(didUrl)) {
            val secret = secretResolver.findKey(didUrl)
            val key = Key.wrapSecret(secret.orElseThrow { SecretNotFoundException(didUrl) })

            if (curve != null && curve != key.curve) {
                throw IncompatibleCryptoException("The recipient `$selector` curve is not compatible to `${curve.name}`")
            }

            listOf(key)
        } else {
            secretResolver.findKeys(
                didDoc.keyAgreements
                    .map { didDoc.findVerificationMethod(it) }
                    .map { Key.wrapVerificationMethod(it) }
                    .filter { curve?.equals(it.curve) ?: true }
                    .map { it.id }
            ).map { Key.wrapSecret(it) }
        }
    }
}
