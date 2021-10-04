package org.dif.secret

import java.util.Optional

/**
 * Resolves secrets such as private keys to be used for signing and encryption.
 */
interface SecretResolver {
    /**
     * Finds a private key identified by the given key ID.
     *
     * @param kid   The key ID identifying a private key.
     * @return The private key or {@code null} of there is no key for the given key ID.
     */
    fun findKey(kid: String): Optional<Secret>

    /**
     * Find all private keys that have one of the given key IDs.
     * Return keys only for key IDs for which a key is present.
     *
     * @param kids  The key IDs find private keys for
     * @return A possible empty list of all private keys that have one of the given keyIDs.
     */
    fun findKeys(kids: List<String>): Set<String>
}
