package org.didcommx.didcomm.crypto.key

import com.nimbusds.jose.jwk.Curve
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.exceptions.DIDDocException
import org.didcommx.didcomm.exceptions.DIDUrlNotFoundException
import org.didcommx.didcomm.exceptions.IncompatibleCryptoException
import org.didcommx.didcomm.exceptions.SecretNotFoundException
import org.didcommx.didcomm.secret.SecretResolver
import org.didcommx.didcomm.utils.divideDIDFragment
import org.didcommx.didcomm.utils.isDIDFragment

class RecipientKeySelector(private val didDocResolver: DIDDocResolver, private val secretResolver: SecretResolver) {
    fun findVerificationKey(signFrom: String): Key = Key.fromVerificationMethod(
        let {
            check(isDIDFragment(signFrom)) { "'DID URL' is expected as a signature verification key. Got: $signFrom" }

            val (did) = divideDIDFragment(signFrom)
            didDocResolver.resolve(did)
                .map { it.findVerificationMethod(signFrom) }
                .orElseThrow { throw DIDUrlNotFoundException(signFrom, did) }
        }
    )

    fun findAuthCryptKeys(from: String, to: List<String>): Pair<Key, Sequence<Key>> {
        check(isDIDFragment(from)) { "'DID URL' is expected as a sender key. Got: $from" }

        val (did) = divideDIDFragment(from)
        return didDocResolver.resolve(did)
            .map { it.findVerificationMethod(from) }
            .map { Key.fromVerificationMethod(it) }
            .map { Pair(it, findRecipientKeys(to, it.curve)) }
            .orElseThrow { DIDUrlNotFoundException(from, did) }
    }

    fun containsKeysForForwardNext(next: String): Boolean {
        val nextKids =
            if (isDIDFragment(next))
                listOf(next)
            else
                didDocResolver.resolve(next)
                    .map { it.keyAgreements }
                    .orElse(emptyList())

        return secretResolver.findKeys(nextKids).isNotEmpty()
    }

    fun findAnonCryptKeys(to: List<String>): Sequence<Key> = to
        .forEach { check(isDIDFragment(it)) { "'DID URL' is expected as a recipient key. Got: $it" } }
        .run { findRecipientKeys(to, null) }

    private fun findRecipientKeys(to: List<String>, curve: Curve?): Sequence<Key> = secretResolver.findKeys(to)
        .ifEmpty { throw SecretNotFoundException(to.joinToString(",")) }
        .asSequence()
        .filter { isDIDFragment(it) }
        .map { secretResolver.findKey(it).orElse(null) }
        .mapNotNull { Key.fromSecret(it) }
        .map {
            if (curve != null && curve != it.curve) {
                throw IncompatibleCryptoException("The recipient '${it.id}' curve is not compatible to '${curve.name}'")
            }

            it
        }
        .ifEmpty { throw DIDDocException("The DID Doc does not contain compatible 'keyAgreement' verification methods") }
}
