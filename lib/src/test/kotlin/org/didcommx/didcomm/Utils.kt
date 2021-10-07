package org.didcommx.didcomm

import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.DID_DOC_ALICE_WITH_NO_SECRETS
import org.didcommx.didcomm.diddoc.DID_DOC_BOB_WITH_NO_SECRETS
import org.didcommx.didcomm.diddoc.DID_DOC_CHARLIE
import org.didcommx.didcomm.diddoc.DID_DOC_MEDIATOR1
import org.didcommx.didcomm.diddoc.DID_DOC_MEDIATOR2
import org.didcommx.didcomm.diddoc.VerificationMethod
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.CharlieSecretResolverMock
import org.didcommx.didcomm.mock.Mediator1SecretResolverMock
import org.didcommx.didcomm.mock.Mediator2SecretResolverMock
import org.didcommx.didcomm.mock.SecretResolverInMemoryMock

enum class Person(num: Int) {
    ALICE(1),
    BOB(2),
    CHARLIE(3),
    MEDIATOR1(4),
    MEDIATOR2(5)
}

enum class KeyAgreementCurveType(num: Int) {
    ALL(0),
    X25519(1),
    P256(2),
    P384(3),
    P521(4);
}

val DIDDocsSpec = mapOf(
    Person.ALICE to Pair(DID_DOC_ALICE_WITH_NO_SECRETS, AliceSecretResolverMock()),
    Person.BOB to Pair(DID_DOC_BOB_WITH_NO_SECRETS, BobSecretResolverMock()),
    Person.CHARLIE to Pair(DID_DOC_CHARLIE, CharlieSecretResolverMock()),
    Person.MEDIATOR1 to Pair(DID_DOC_MEDIATOR1, Mediator1SecretResolverMock()),
    Person.MEDIATOR2 to Pair(DID_DOC_MEDIATOR2, Mediator2SecretResolverMock()),
)

private fun getDIDDoc(person: Person): DIDDoc {
    return DIDDocsSpec.getValue(person).first
}

private fun getSecretsResolver(person: Person): SecretResolverInMemoryMock {
    return DIDDocsSpec.getValue(person).second
}

fun getAuthMethodsInSecrets(person: Person): List<VerificationMethod> {
    val didDoc = getDIDDoc(person)
    val secretsResolver = getSecretsResolver(person)
    return didDoc.verificationMethods.filter { vm ->
        secretsResolver.getSecretKids().contains(vm.id) &&
            didDoc.authentications.contains(vm.id)
    }
}

fun getAuthMethodsNotInSecrets(person: Person): List<VerificationMethod> {
    val didDoc = getDIDDoc(person)
    val secretsResolver = getSecretsResolver(person)
    return didDoc.verificationMethods.filter { vm ->
        !secretsResolver.getSecretKids().contains(vm.id) &&
            didDoc.authentications.contains(vm.id)
    }
}

fun getKeyAgreementMethodsInSecrets(person: Person, type: KeyAgreementCurveType = KeyAgreementCurveType.ALL): List<VerificationMethod> {
    val didDoc = getDIDDoc(person)
    val secretsResolver = getSecretsResolver(person)
    return didDoc.verificationMethods.filter { vm ->
        secretsResolver.getSecretKids().contains(vm.id) &&
            didDoc.keyAgreements.contains(vm.id) &&
            (type == KeyAgreementCurveType.ALL || type == mapCureToType(vm))
    }
}

fun getKeyAgreementMethodsNotInSecrets(person: Person, type: KeyAgreementCurveType = KeyAgreementCurveType.ALL): List<VerificationMethod> {
    val didDoc = getDIDDoc(person)
    val secretsResolver = getSecretsResolver(person)
    return didDoc.verificationMethods.filter { vm ->
        !secretsResolver.getSecretKids().contains(vm.id) &&
            didDoc.keyAgreements.contains(vm.id) &&
            (type == KeyAgreementCurveType.ALL || type == mapCureToType(vm))
    }
}

private fun mapCureToType(vm: VerificationMethod): KeyAgreementCurveType {
    if (
        vm.type == VerificationMethodType.JSON_WEB_KEY_2020 &&
        vm.verificationMaterial.format == VerificationMaterialFormat.JWK
    ) {
        val jwk = JSONObjectUtils.parse(vm.verificationMaterial.value)
        if (jwk["crv"] == "X25519")
            return KeyAgreementCurveType.X25519
        if (jwk["crv"] == "P-256")
            return KeyAgreementCurveType.P256
        if (jwk["crv"] == "P-384")
            return KeyAgreementCurveType.P384
        if (jwk["crv"] == "P-521")
            return KeyAgreementCurveType.P521
    }
    throw IllegalArgumentException("Unknown verification methods curve type: $vm")
}
