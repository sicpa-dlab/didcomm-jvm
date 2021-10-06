package org.didcommx.didcomm.operations

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
import org.didcommx.didcomm.crypto.key.SenderKeySelector
import org.didcommx.didcomm.crypto.signJwt
import org.didcommx.didcomm.crypto.verifyJwt
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.message.FromPrior
import org.didcommx.didcomm.message.Message

fun packFromPrior(message: Message, fromPriorIssuerKid: String?, keySelector: SenderKeySelector):
        Pair<Message, String?> =
    if (message.fromPrior != null) {
        val key = keySelector.findSigningKey(fromPriorIssuerKid ?: message.fromPrior.iss)
        val updatedMessage = message.copy(
            fromPriorJwt = signJwt(JWTClaimsSet.parse(message.fromPrior.toJSONObject()), key)
        )
        Pair(updatedMessage, key.id)
    } else {
        Pair(message, null)
    }

fun unpackFromPrior(message: Message, keySelector: RecipientKeySelector): Pair<Message, String?> =
    if (message.fromPriorJwt != null) {
        val issKid = extractFromPriorKid(message.fromPriorJwt)
        val key = keySelector.findVerificationKey(issKid)
        val updatedMessage = message.copy(
            fromPrior = FromPrior.parse(verifyJwt(message.fromPriorJwt, key).toJSONObject())
        )
        Pair(updatedMessage, key.id)
    } else {
        Pair(message, null)
    }

private fun extractFromPriorKid(fromPriorJwt: String): String {
    val segments = fromPriorJwt.split(".")
    if (segments.size != 3) {
        throw MalformedMessageException("JWT cannot be deserialized")
    }
    val jwsHeader = JWSHeader.parse(segments[0])
    return jwsHeader.keyID
}
