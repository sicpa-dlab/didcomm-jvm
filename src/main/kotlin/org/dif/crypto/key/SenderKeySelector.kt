package org.dif.crypto.key

import com.nimbusds.jose.jwk.Curve
import org.dif.diddoc.DIDDoc
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
                ?: throw DIDDocException("The DID Doc '${didDoc.did}' does not contain compatible 'authentication' verification methods")

            secretResolver.findKey(authentication).orElseThrow { throw SecretNotFoundException(signFrom) }
        }
    )

    fun findAuthCryptKeys(from: String, to: String): Pair<Key, List<Key>> {
        val (didFrom) = divideDIDFragment(from)
        val (didTo) = divideDIDFragment(to)
        val didDocTo = didDocResolver.resolve(didTo).orElseThrow { throw DIDDocNotResolvedException(didTo) }

        return if (isDIDFragment(from)) {
            val sender = secretResolver.findKey(from)
                .map { Key.wrapSecret(it) }
                .orElseThrow { throw SecretNotFoundException(from) }

            val recipients = findRecipientKeys(didDocTo, to, sender.curve)
                .ifEmpty { throw IncompatibleCryptoException("The recipient '$to' curve is not compatible to '${sender.curve.name}'") }

            Pair(sender, recipients)
        } else {
            val didDocFrom = didDocResolver.resolve(didFrom).orElseThrow { throw DIDDocNotResolvedException(didFrom) }
            didDocFrom.keyAgreements
                .asSequence()
                .map { secretResolver.findKey(it) }
                .filter { it.isPresent }
                .map { it.get() }
                .map { Key.wrapSecret(it) }
                .map { Pair(it, findRecipientKeys(didDocTo, to, it.curve)) }
                .firstOrNull { it.second.isNotEmpty() }
                ?: throw IncompatibleCryptoException("The DID Docs '${didDocFrom.did}' and '${didDocTo.did}' do not contain compatible 'keyAgreement' verification methods")
        }
    }

    fun findAnonCryptKeys(to: String): List<Key> {
        val (did) = divideDIDFragment(to)
        val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

        return if (isDIDFragment(to)) {
            val method = didDoc.findVerificationMethod(to)
            listOf(Key.wrapVerificationMethod(method))
        } else {
            val selectedCurve = didDoc.keyAgreements
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.wrapVerificationMethod(it) }
                .map { it.curve }
                .firstOrNull()

            didDoc.keyAgreements
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.wrapVerificationMethod(it) }
                .filter { selectedCurve == it.curve }
                .ifEmpty { throw DIDDocException("The DID Doc '${didDoc.did}' does not contain compatible 'keyAgreement' verification methods") }
        }
    }

    private fun findRecipientKeys(didDoc: DIDDoc, to: String, curve: Curve): List<Key> {
        return if (isDIDFragment(to)) {
            val method = didDoc.findVerificationMethod(to)
            val key = Key.wrapVerificationMethod(method)

            when (curve != key.curve) {
                true -> listOf()
                false -> listOf(key)
            }
        } else {
            didDoc.keyAgreements
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.wrapVerificationMethod(it) }
                .filter { curve == it.curve }
        }
    }
}
