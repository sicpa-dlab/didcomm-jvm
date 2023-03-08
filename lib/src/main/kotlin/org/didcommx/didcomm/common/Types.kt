package org.didcommx.didcomm.common

enum class Typ(val typ: String) {
    Encrypted("application/didcomm-encrypted+json"),
    Signed("application/didcomm-signed+json"),
    Plaintext("application/didcomm-plain+json");

    companion object {
        fun parse(str: String): Typ = when (str) {
            "application/didcomm-encrypted+json" -> Encrypted
            "application/didcomm-signed+json" -> Signed
            "application/didcomm-plain+json" -> Plaintext
            else -> throw IllegalArgumentException("Unsupported message typ")
        }
    }
}

/**
 * https://www.w3.org/TR/did-spec-registries/#verification-method-types
 */
enum class VerificationMethodType {
    JSON_WEB_KEY_2020,
    X25519_KEY_AGREEMENT_KEY_2019,
    ED25519_VERIFICATION_KEY_2018,
    X25519_KEY_AGREEMENT_KEY_2020,
    ED25519_VERIFICATION_KEY_2020,
//    ECDSA_SECP_256K1_VERIFICATION_KEY_2019, - not supported now
    OTHER
}

data class VerificationMaterial(
    val format: VerificationMaterialFormat,
    val value: String
)

/**
 * https://www.w3.org/TR/did-spec-registries/#verification-method-properties
 */
enum class VerificationMaterialFormat {
    @Deprecated(
        "publicKeyBase58 is deprecated by spec. Use publicKeyMultibase or publicKeyJwk",
        ReplaceWith("publicKeyMultibase or publicKeyJwk")
    )
    BASE58, // https://www.w3.org/TR/did-spec-registries/#publickeybase58
    MULTIBASE,
    JWK,
    OTHER
}

enum class DIDCommMessageProtocolTypes(val typ: String) {
    Forward("https://didcomm.org/routing/2.0/forward");

    companion object {
        fun parse(str: String): DIDCommMessageProtocolTypes = when (str) {
            Forward.typ -> Forward
            else -> throw IllegalArgumentException("Unsupported protocol typ")
        }
    }
}
