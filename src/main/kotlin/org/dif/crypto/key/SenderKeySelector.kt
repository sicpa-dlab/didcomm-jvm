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
    fun findSigningKey(signFrom: String): Key = Key.wrapSecret(
        if (isDIDFragment(signFrom)) {
            secretResolver.findKey(signFrom).orElseThrow { throw SecretNotFoundException(signFrom) }
        } else {
            val didDoc = didDocResolver.resolve(signFrom).orElseThrow { throw DIDDocNotResolvedException(signFrom) }

            val authentication = didDoc.authentications.firstOrNull()
                ?: throw DIDDocException("Authentication is not found in DID Doc '$signFrom'")

            secretResolver.findKey(authentication).orElseThrow { throw SecretNotFoundException(signFrom) }
        }
    )

    fun findAuthCryptKeys(from: String, to: String): Pair<Key, List<Key>> {
        val (did) = divideDIDFragment(from)
        val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

        return if (isDIDFragment(from)) {
            val sender = secretResolver.findKey(from)
                .map { Key.wrapSecret(it) }
                .orElseThrow { throw SecretNotFoundException(from) }

            val recipients = findRecipientKeys(to, sender.curve)
            Pair(sender, recipients)
        } else {
            didDoc.keyAgreements
                .asSequence()
                .map { secretResolver.findKey(it) }
                .filter { it.isPresent }
                .map { it.get() }
                .map { Key.wrapSecret(it) }
                .map { Pair(it, findRecipientKeys(to, it.curve)) }
                .first { it.second.isNotEmpty() }
        }
    }

    fun findAnonCryptKeys(to: String): List<Key> = findRecipientKeys(to, null)

    private fun findRecipientKeys(to: String, curve: Curve?): List<Key> {
        val (did) = divideDIDFragment(to)
        val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

        return if (isDIDFragment(to)) {
            val method = didDoc.findVerificationMethod(to)
            val key = Key.wrapVerificationMethod(method)

            if (curve != null && curve != key.curve) {
                throw IncompatibleCryptoException("The recipient `$to` curve is not compatible to `${curve.name}`")
            }

            listOf(key)
        } else {
            didDoc.keyAgreements
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.wrapVerificationMethod(it) }
                .filter { curve?.equals(it.curve) ?: true }
                .ifEmpty { throw IncompatibleCryptoException("DID Doc does not contain compatible 'keyAgreement' verification methods") }
        }
    }
}
