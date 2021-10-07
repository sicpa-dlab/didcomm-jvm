package org.didcommx.didcomm.model

/**
 * Result of pack encrypted message operation.
 *
 * @property packedMessage       A packed message as a JSON string.
 * @property toKids              Identifiers (DID URLs) of recipient keys used for message encryption.
 * @property serviceMetadata     An optional service metadata which contains a service endpoint
 *                               to be used to transport the 'packedMessage'.
 * @property fromKid             Identifier (DID URL) of sender key used for message encryption.
 * @property fromPriorIssuerKid  Identifier (DID URL) of FromPrior issuer key
 * @property signFromKid         Identifier (DID URL) of sender key used for message signing.
 */
data class PackEncryptedResult(
    val packedMessage: String,
    val toKids: List<String>,
    val fromKid: String? = null,
    val signFromKid: String? = null,
    val fromPriorIssuerKid: String? = null,
    val serviceMetadata: ServiceMetadata? = null,
)

/**
 * Service Metadata
 *
 * @property id              The Identifier of Service Endpoint
 * @property serviceEndpoint The service endpoint
 */
data class ServiceMetadata(
    val id: String,
    val serviceEndpoint: String,
)
