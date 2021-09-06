package org.dif.crypto.key

import com.nimbusds.jose.jwk.Curve
import org.dif.diddoc.DIDDocResolver
import org.dif.exceptions.DIDDocException
import org.dif.exceptions.DIDUrlNotFoundException
import org.dif.exceptions.IncompatibleCryptoException
import org.dif.exceptions.SecretNotFoundException
import org.dif.secret.SecretResolver
import org.dif.utils.divideDIDFragment
import org.dif.utils.isDIDFragment

class RecipientKeySelector(private val didDocResolver: DIDDocResolver, private val secretResolver: SecretResolver) {
    fun findVerificationKey(signFrom: String): Key = Key.wrapVerificationMethod(
        let {
            check(isDIDFragment(signFrom)) { "'DID URL' is expected as a signature verification key. Got: $signFrom" }

            val (did) = divideDIDFragment(signFrom)
            didDocResolver.resolve(did)
                .map { it.findVerificationMethod(signFrom) }
                .orElseThrow { throw DIDUrlNotFoundException(did) }
        }
    )

    fun findAuthCryptKeys(from: String, to: List<String>): Pair<Key, Sequence<Key>> {
        check(isDIDFragment(from)) { "'DID URL' is expected as a sender key. Got: $from" }

        val (did) = divideDIDFragment(from)
        return didDocResolver.resolve(did)
            .map { it.findVerificationMethod(from) }
            .map { Key.wrapVerificationMethod(it) }
            .map { Pair(it, findRecipientKeys(to, it.curve)) }
            .orElseThrow { DIDUrlNotFoundException(did) }
    }

    fun findAnonCryptKeys(to: List<String>): Sequence<Key> = to
        .forEach { check(isDIDFragment(it)) { "'DID URL' is expected as a recipient key. Got: $it" } }
        .run { findRecipientKeys(to, null) }

    private fun findRecipientKeys(to: List<String>, curve: Curve?): Sequence<Key> = secretResolver.findKeys(to)
        .ifEmpty { throw SecretNotFoundException(to.joinToString(",")) }
        .asSequence()
        .filter { isDIDFragment(it) }
        .map { secretResolver.findKey(it).orElse(null) }
        .mapNotNull { Key.wrapSecret(it) }
        .map {
            if (curve != null && curve != it.curve) {
                throw IncompatibleCryptoException("The recipient '${it.id}' curve is not compatible to '${curve.name}'")
            }

            it
        }
        .ifEmpty { throw DIDDocException("The DID Doc does not contain compatible 'keyAgreement' verification methods") }
}
