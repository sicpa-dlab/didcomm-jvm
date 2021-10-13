package org.didcommx.didcomm.diddoc

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.exceptions.DIDCommServiceException
import org.didcommx.didcomm.exceptions.DIDDocException
import org.didcommx.didcomm.exceptions.DIDDocNotResolvedException
import org.didcommx.didcomm.exceptions.DIDUrlNotFoundException
import org.didcommx.didcomm.utils.getDid
import org.didcommx.didcomm.utils.isDIDOrDidUrl

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
) {
    fun findVerificationMethod(id: String): VerificationMethod = verificationMethods.find { it.id == id }
        ?: throw DIDUrlNotFoundException(id, did)

    fun findDIDCommService(id: String): DIDCommService = didCommServices.find { it.id == id }
        ?: throw DIDDocException("DIDComm service '$id' not found in DID Doc '$did'")
}

/**
 * DID DOC Verification method.
 * It can be used in such verification relationships as Authentication, KeyAgreement, etc.
 * See https://www.w3.org/TR/did-core/#verification-methods.
 */
data class VerificationMethod(
    val id: String,
    val type: VerificationMethodType,
    val verificationMaterial: VerificationMaterial,
    val controller: String,
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

// not used for now
// const val PROFILE_DIDCOMM_AIP1 = "didcomm/aip1"
// const val PROFILE_DIDCOMM_AIP2_ENV_RFC19 = "didcomm/aip2;env=rfc19"
// const val PROFILE_DIDCOMM_AIP2_ENV_RFC587 = "didcomm/aip2;env=rfc587"

const val PROFILE_DIDCOMM_V2 = "didcomm/v2"

fun findDidService(
    didDocResolver: DIDDocResolver,
    to: String,
    serviceId: String? = null
): DIDCommService? {

    val toDid = getDid(to)
    val didDoc = didDocResolver.resolve(toDid).orElseThrow { throw DIDDocNotResolvedException(toDid) }

    if (serviceId != null) {
        val didService = didDoc.findDIDCommService(serviceId)

        if (PROFILE_DIDCOMM_V2 !in didService.accept) {
            throw DIDCommServiceException(
                toDid, "service '$serviceId' does not accept didcomm/v2 profile"
            )
        }
        return didService
    } else {
        // Find the first service accepting `didcomm/v2` profile because the spec states:
        // > Entries SHOULD be specified in order of receiver preference,
        // > but any endpoint MAY be selected by the sender, typically
        // > by protocol availability or preference.
        // https://identity.foundation/didcomm-messaging/spec/#multiple-endpoints
        return try {
            didDoc.didCommServices.find { PROFILE_DIDCOMM_V2 in it.accept }
        } catch (e: DIDDocException) {
            null
        }
    }
}

fun resolveDidServicesChain(
    didDocResolver: DIDDocResolver,
    to: String,
    serviceId: String? = null,
    didRecursion: Boolean = false
): List<DIDCommService> {

    val toDidService = findDidService(didDocResolver, to, serviceId) ?: return listOf()

    val res = mutableListOf<DIDCommService>()
    var serviceUri = toDidService.serviceEndpoint

    res.add(0, toDidService)

    // alternative endpoints
    while (isDIDOrDidUrl(serviceUri)) {
        val mediatorDid = serviceUri

        if (res.size > 1) {
            // TODO cover possible case of alternative endpoints in mediator's
            //      DID Doc services (it SHOULD NOT be as per spec but ...)
            val errMsg = (
                "mediator '${res.last().serviceEndpoint}' defines alternative" +
                    " endpoint '$serviceUri' recursively"
                )

            if (didRecursion) {
                throw NotImplementedError(errMsg)
            } else {
                throw DIDCommServiceException(res.last().serviceEndpoint, errMsg)
            }
        }

        // TODO check not only first item in mediator services list
        //      (e.g. first one may use alternative endpoint but second - URI)

        // resolve until final URI is reached
        val mediatorDidService = findDidService(didDocResolver, mediatorDid)
            ?: throw DIDCommServiceException(
                mediatorDid, "mediator '$mediatorDid' service doc not found"
            )

        serviceUri = mediatorDidService.serviceEndpoint
        res.add(0, mediatorDidService)
    }

    return res
}
