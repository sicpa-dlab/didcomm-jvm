package org.dif.diddoc

import java.util.Optional

/**
 * Represents DID Doc resolver (https://www.w3.org/TR/did-core/#did-resolution).
 */
interface DIDDocResolver {
    /**
     * Resolves a DID document by the given DID.
     * @param did a DID to be resolved.
     *
     * @return An instance of resolved DID DOC or null if DID is not found.
     */
    fun resolve(did: String): Optional<DIDDoc>
}
