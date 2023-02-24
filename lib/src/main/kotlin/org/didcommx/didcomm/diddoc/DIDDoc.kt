package org.didcommx.didcomm.diddoc

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.exceptions.DIDDocException
import org.didcommx.didcomm.exceptions.DIDUrlNotFoundException

/**
 * DID DOC (https://www.w3.org/TR/did-core/#dfn-did-documents)
 * @property did                    a DID for the given DID Doc
 * @property authentications        Key IDs (DID URLs) of all verification methods from the 'authentication'
 *                                  verification relationship in this DID DOC.
 *                                  See https://www.w3.org/TR/did-core/#authentication.
 * @property assertionMethods       Key IDs (DID URLs) of all verification methods from the 'assertionMethod'
 *                                  verification relationship in this DID DOC.
 *                                  See https://www.w3.org/TR/did-core/#assertion
 * @property keyAgreements          Key IDs (DID URLs) of all verification methods from the 'keyAgreement'
 *                                  verification relationship in this DID DOC.
 *                                  See https://www.w3.org/TR/did-core/#key-agreement
 * @property capabilityInvocations  Key IDs (DID URLs) of all verification methods from the 'capabilityInvocation'
 *                                  verification relationship in this DID DOC.
 *                                  See https://www.w3.org/TR/did-core/#capability-invocation
 * @property capabilityDelegations  Key IDs (DID URLs) of all verification methods from the 'capabilityDelegation'
 *                                  verification relationship in this DID DOC.
 *                                  See https://www.w3.org/TR/did-core/#capability-delegation
 * @property keyAgreements          Key IDs (DID URLs) of all verification methods from the 'keyAgreement'
 *                                  verification relationship in this DID DOC.
 *                                  See https://www.w3.org/TR/did-core/#key-agreement
 * @property verificationMethods    Returns all local verification methods including embedded
 *                                  to key agreement and authentication sections.
 *                                  See https://www.w3.org/TR/did-core/#verification-methods.
 * @property didCommServices        All services of 'DIDCommMessaging' type in this DID DOC.
 *                                  Empty list is returned if there are no services of 'DIDCommMessaging' type.
 *                                  See https://www.w3.org/TR/did-core/#services and https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint.
 */
data class DIDDoc(
    val did: String,
    val authentications: List<String>,
    val assertionMethods: List<String>,
    val keyAgreements: List<String>,
    val capabilityInvocations: List<String>,
    val capabilityDelegations: List<String>,
    val verificationMethods: List<VerificationMethod>,
    val didCommServices: List<DIDCommService>
) {
    @Deprecated("Deprecated constructor", ReplaceWith("Primary constructor including `assertionMethods`, `capabilityInvocations`, `capabilityDelegations`"))
    constructor(
        did: String,
        keyAgreements: List<String>,
        authentications: List<String>,
        verificationMethods: List<VerificationMethod>,
        didCommServices: List<DIDCommService>) : this(
        did = did,
        authentications = authentications,
        assertionMethods = listOf(),        // empty assertionMethods
        keyAgreements = keyAgreements,
        capabilityInvocations = listOf(),   // empty capabilityInvocations
        capabilityDelegations = listOf(),   // empty capabilityDelegations
        verificationMethods = verificationMethods,
        didCommServices = didCommServices
    )

    companion object {
        fun fromJson(doc: String): DIDDoc = DIDDocDecoder.decodeJson(doc)
    }

    fun findVerificationMethod(id: String): VerificationMethod = verificationMethods.find { it.id == id }
        ?: throw DIDUrlNotFoundException(id, did)

    fun findDIDCommService(id: String): DIDCommService = didCommServices.find { it.id == id }
        ?: throw DIDDocException("DIDComm service '$id' not found in DID Doc '$did'")

    fun encodeJson(pretty: Boolean = false): String = DIDDocEncoder.encodeJson(this, pretty)
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
    val accept: List<String>?
)

object DIDDocEncoder {

    private val gson get() = GsonBuilder().create()
    private val gsonPretty get() = GsonBuilder().setPrettyPrinting().create()

    /**
     * Encode according to
     * https://www.w3.org/TR/did-core/#did-document-properties
     */
    fun encodeJson(doc: DIDDoc, pretty: Boolean = false): String {
        val jsonObj = JsonObject()

        // id
        jsonObj.addProperty("id", doc.did)

        // authentication
        if (doc.authentications.isNotEmpty()) {
            val authentication = doc.authentications.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("authentication", authentication)
        }

        // assertionMethod
        if (doc.assertionMethods.isNotEmpty()) {
            val assertionMethod = doc.assertionMethods.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("assertionMethod", assertionMethod)
        }

        // keyAgreement
        if (doc.keyAgreements.isNotEmpty()) {
            val keyAgreement = doc.keyAgreements.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("keyAgreement", keyAgreement)
        }

        // capabilityInvocation
        if (doc.capabilityInvocations.isNotEmpty()) {
            val capabilityInvocation = doc.capabilityInvocations.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("capabilityInvocation", capabilityInvocation)
        }

        // capabilityDelegation
        if (doc.capabilityDelegations.isNotEmpty()) {
            val capabilityDelegation = doc.capabilityDelegations.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("capabilityDelegation", capabilityDelegation)
        }

        // verificationMethod
        if (doc.verificationMethods.isNotEmpty()) {
            val verificationMethod = doc.verificationMethods.fold(JsonArray()) { arr, el -> arr.add(encodeVerificationMethod(el)); arr }
            jsonObj.add("verificationMethod", verificationMethod)
        }

        // service
        if (doc.didCommServices.isNotEmpty()) {
            val service = doc.didCommServices.fold(JsonArray()) { arr, el -> arr.add(encodeDidCommService(el)); arr }
            jsonObj.add("service", service)
        }

        return if (pretty)
            gsonPretty.toJson(jsonObj)
        else
            gson.toJson(jsonObj)
    }

    private fun encodeVerificationMethod(vm: VerificationMethod): JsonObject {
        val jsonObj = JsonObject()

        // id
        jsonObj.addProperty("id", vm.id)

        // type
        jsonObj.addProperty("type", when(vm.type) {
            VerificationMethodType.ED25519_VERIFICATION_KEY_2018 -> "Ed25519VerificationKey2018"
            VerificationMethodType.ED25519_VERIFICATION_KEY_2020 -> "Ed25519VerificationKey2020"
            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019 -> "X25519KeyAgreementKey2019"
            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020 -> "X25519KeyAgreementKey2020"
            VerificationMethodType.JSON_WEB_KEY_2020 -> "JsonWebKey2020"
            else -> throw IllegalStateException("Unsupported verification type: ${vm.type}")
        })

        // controller
        jsonObj.addProperty("controller", vm.controller)

        // verification material
        val materialFormat = vm.verificationMaterial.format
        val materialValue = vm.verificationMaterial.value
        when(materialFormat) {
            VerificationMaterialFormat.JWK -> {
                jsonObj.add("publicKeyJwk", gson.fromJson(materialValue, JsonObject::class.java))
            }
            VerificationMaterialFormat.BASE58 -> {
                jsonObj.addProperty("publicKeyBase58", materialValue)
            }
            VerificationMaterialFormat.MULTIBASE -> {
                jsonObj.addProperty("publicKeyMultibase", materialValue)
            }
            else -> throw IllegalStateException("Unsupported verification material: $materialFormat")
        }
        return jsonObj
    }

    private fun encodeDidCommService(srv: DIDCommService): JsonObject {
        val jsonObj = JsonObject()

        // id
        jsonObj.addProperty("id", srv.id)

        // type
        jsonObj.addProperty("type", "DIDCommMessaging")

        // accept
        if (srv.accept?.isNotEmpty() == true) {
            val accept = srv.accept.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("accept", accept)
        }

        // routingKeys
        if (srv.routingKeys.isNotEmpty()) {
            val routingKeys = srv.routingKeys.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("routingKeys", routingKeys)
        }

        // serviceEndpoint
        jsonObj.addProperty("serviceEndpoint", srv.serviceEndpoint)

        return jsonObj
    }
}

object DIDDocDecoder {

    private val gson get() = GsonBuilder().create()

    /**
     * Decode according to
     * https://www.w3.org/TR/did-core/#did-document-properties
     */
    fun decodeJson(doc: String): DIDDoc {
        val jsonObj = gson.fromJson(doc, JsonObject::class.java)

        // id
        val id = jsonObj["id"].asString

        // authentication
        val authentications = jsonObj.get("authentication")
            ?.let { it.asJsonArray.map { el -> el.asString }}
            ?: listOf()

        // assertionMethod
        val assertionMethods = jsonObj.get("assertionMethod")
            ?.let { it.asJsonArray.map { el -> el.asString }}
            ?: listOf()

        // keyAgreement
        val keyAgreements = jsonObj.get("keyAgreement")
            ?.let { it.asJsonArray.map { el -> el.asString }}
            ?: listOf()

        // capabilityInvocations
        val capabilityInvocations = jsonObj.get("capabilityInvocation")
            ?.let { it.asJsonArray.map { el -> el.asString }}
            ?: listOf()

        // capabilityDelegation
        val capabilityDelegations = jsonObj.get("capabilityDelegation")
            ?.let { it.asJsonArray.map { el -> el.asString }}
            ?: listOf()

        // verificationMethod
        val verificationMethods = jsonObj.get("verificationMethod")
            ?.let { it.asJsonArray.map { el -> decodeVerificationMethod(el.asJsonObject) }}
            ?: listOf()

        // service
        val didCommServices = jsonObj.get("service")
            ?.let { it.asJsonArray.map { el -> decodeDIDCommService(el.asJsonObject) }}
            ?: listOf()

        return DIDDoc(
            did = id,
            authentications = authentications,
            assertionMethods = assertionMethods,
            keyAgreements = keyAgreements,
            capabilityInvocations = capabilityInvocations,
            capabilityDelegations = capabilityDelegations,
            verificationMethods = verificationMethods,
            didCommServices = didCommServices
        )
    }

    private fun decodeVerificationMethod(obj: JsonObject): VerificationMethod {
        val id = obj["id"].asString
        val methodType = when(val type = obj["type"].asString) {
            "Ed25519VerificationKey2018" -> VerificationMethodType.ED25519_VERIFICATION_KEY_2018
            "Ed25519VerificationKey2020" -> VerificationMethodType.ED25519_VERIFICATION_KEY_2020
            "X25519KeyAgreementKey2019" -> VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019
            "X25519KeyAgreementKey2020" -> VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020
            "JsonWebKey2020" -> VerificationMethodType.JSON_WEB_KEY_2020
            else -> throw IllegalStateException("Unsupported verification type: $type")
        }
        val material = when {
            obj["publicKeyJwk"] != null -> VerificationMaterial(VerificationMaterialFormat.JWK, gson.toJson(obj["publicKeyJwk"]))
            obj["publicKeyBase58"] != null -> VerificationMaterial(VerificationMaterialFormat.BASE58, obj["publicKeyBase58"].asString)
            obj["publicKeyMultibase"] != null -> VerificationMaterial(VerificationMaterialFormat.MULTIBASE, obj["publicKeyMultibase"].asString)
            else -> throw IllegalStateException("Unsupported verification material: $obj")
        }
        val controller = obj["controller"].asString
        return VerificationMethod(id, methodType, material, controller)
    }

    private fun decodeDIDCommService(obj: JsonObject): DIDCommService {
        val id = obj["id"].asString
        val serviceEndpoint = obj["serviceEndpoint"].asString
        val accept = obj["accept"]?.let { it.asJsonArray.map { el -> el.asString }} ?: listOf()
        val routingKeys = obj["routingKeys"]?.let { it.asJsonArray.map { el -> el.asString }} ?: listOf()
        return DIDCommService(id, serviceEndpoint, routingKeys, accept)
    }
}
