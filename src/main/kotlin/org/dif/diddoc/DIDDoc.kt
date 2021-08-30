package org.dif.diddoc

import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMethodType

/**
 * DID DOC (https://www.w3.org/TR/did-core/#dfn-did-documents)
 * @property did                    a DID for the given DID Doc
 * @property keyAgreements          Key IDs (DID URLs) of all verification methods from the 'keyAgreement'
 *                                  verification relationship in this DID DOC.
 *                                  See https://www.w3.org/TR/did-core/#verification-methods.
 * @property authentications        Key IDs (DID URLs) of all verification methods from the 'authentication'
 *                                  verification relationship in this DID DOC.
 See https://www.w3.org/TR/did-core/#authentication.
 * @property verificationMethods    Returns all local verification methods including embedded
 *                                  to key agreement and authentication sections.
 *                                  See https://www.w3.org/TR/did-core/#verification-methods.
 * @property didCommServices        All services of 'DIDCommMessaging' type in this DID DOC.
 *                                  Empty list is returned if there are no services of 'DIDCommMessaging' type.
 *                                  See https://www.w3.org/TR/did-core/#services and https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint.
 */
data class DIDDoc(
    val did: String,
    val keyAgreements: List<String>,
    val authentications: List<String>,
    val verificationMethods: List<VerificationMethod>,
    val didCommServices: List<DIDCommService>
)

/**
 * DID DOC Verification method.
 * It can be used in such verification relationships as Authentication, KeyAgreement, etc.
 * See https://www.w3.org/TR/did-core/#verification-methods.
 */
data class VerificationMethod(
    val id: String,
    val type: VerificationMethodType,
    val controller: String,
    val verificationMaterial: VerificationMaterial,
)

/**
 * DID DOC Service of 'DIDCommMessaging' type.
 * see https://www.w3.org/TR/did-core/#services
 * and https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint.
 *
 * @property id              Service's 'id' field
 * @property serviceEndpoint A service endpoint. It can be either a URI to be used for transport
 *                           or a mediator's DID in case of alternative endpoints.
 * @property routingKeys     A possibly empty ordered array of strings referencing keys
 *                           to be used when preparing the message for transmission.
 * @property accept          A possibly empty ordered array of strings representing
 *                           accepted didcomm specification versions.
 */
data class DIDCommService(
    val id: String,
    val serviceEndpoint: String,
    val routingKeys: List<String>,
    val accept: List<String>
)
