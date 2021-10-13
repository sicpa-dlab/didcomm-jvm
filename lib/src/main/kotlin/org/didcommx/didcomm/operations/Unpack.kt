package org.didcommx.didcomm.operations

import org.didcommx.didcomm.common.AnonCryptAlg
import org.didcommx.didcomm.common.AuthCryptAlg
import org.didcommx.didcomm.crypto.ParseResult
import org.didcommx.didcomm.crypto.anonDecrypt
import org.didcommx.didcomm.crypto.authDecrypt
import org.didcommx.didcomm.crypto.getCryptoAlg
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
import org.didcommx.didcomm.crypto.parse
import org.didcommx.didcomm.crypto.verify
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.Metadata
import org.didcommx.didcomm.model.UnpackForwardResult
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.model.UnpackResult
import org.didcommx.didcomm.utils.calculateAPV

fun unpack(params: UnpackParams, keySelector: RecipientKeySelector): UnpackResult {
    val metadataBuilder = Metadata.Builder()

    val msg = when (val parseResult = parse(params.packedMessage)) {
        is ParseResult.JWS -> parseResult.unpack(keySelector, metadataBuilder)
        is ParseResult.JWE -> parseResult.unpack(
            keySelector, params.expectDecryptByAllKeys, metadataBuilder, params.unwrapReWrappingForward
        )
        is ParseResult.JWM -> parseResult.unpack(keySelector, metadataBuilder)
    }

    return UnpackResult(msg, metadataBuilder.build())
}

fun unpackForward(params: UnpackParams, keySelector: RecipientKeySelector): UnpackForwardResult {
    val metadataBuilder = Metadata.Builder()

    val msg = when (val parseResult = parse(params.packedMessage)) {
        is ParseResult.JWE -> parseResult.unpack(keySelector, params.expectDecryptByAllKeys, metadataBuilder, false)
        else -> throw MalformedMessageException("JWE with anonymous encryption is expected around Forward message")
    }

    val forwardedMsg = msg.forwardedMsg

    if (forwardedMsg != null) {
        return UnpackForwardResult(
            msg,
            forwardedMsg,
            metadataBuilder.build().encryptedTo
        )
    } else {
        throw MalformedMessageException("Not a Forward message")
    }
}

private fun ParseResult.JWM.unpack(keySelector: RecipientKeySelector, metadataBuilder: Metadata.Builder): Message {
    metadataBuilder.fromPriorJwt(message.fromPriorJwt)
    val (updatedMessage, fromPriorIssuerKid) = unpackFromPrior(message, keySelector)
    metadataBuilder.fromPriorIssuerKid(fromPriorIssuerKid)
    return updatedMessage
}

private fun ParseResult.JWS.unpack(keySelector: RecipientKeySelector, metadataBuilder: Metadata.Builder): Message {
    if (message.signatures.isEmpty())
        throw MalformedMessageException("Empty signatures")
    message.signatures.forEach {
        val kid = it.unprotectedHeader?.keyID
            ?: throw MalformedMessageException("JWS Unprotected Per-Signature header must be present")
        val key = keySelector.findVerificationKey(kid)
        val alg = getCryptoAlg(it)
        verify(it, alg, key)

        // TODO: support multiple signatures on Metadata level
        metadataBuilder
            .signAlg(alg)
            .signFrom(kid)
    }

    val unpackedMessage = message.payload.toJSONObject()

    metadataBuilder
        .nonRepudiation(true)
        .authenticated(true)
        .signedMessage(rawMessage)

    return when (val parseResult = parse(unpackedMessage)) {
        is ParseResult.JWM -> parseResult.unpack(keySelector, metadataBuilder)
        else -> throw MalformedMessageException("Malformed Message")
    }
}

private fun ParseResult.JWE.unpack(
    keySelector: RecipientKeySelector,
    decryptByAllKeys: Boolean,
    metadataBuilder: Metadata.Builder,
    unwrapReWrappingForward: Boolean
): Message =
    when (val alg = getCryptoAlg(message)) {
        is AuthCryptAlg -> authUnpack(keySelector, alg, decryptByAllKeys, metadataBuilder)
        is AnonCryptAlg -> anonUnpack(
            keySelector, alg, decryptByAllKeys, metadataBuilder, unwrapReWrappingForward
        )
    }

private fun ParseResult.JWE.authUnpack(
    keySelector: RecipientKeySelector,
    authCryptAlg: AuthCryptAlg,
    decryptByAllKeys: Boolean,
    metadataBuilder: Metadata.Builder
): Message {
    if (message.header.senderKeyID != null &&
        message.header.agreementPartyUInfo.decodeToString() != message.header.senderKeyID
    )
        throw MalformedMessageException("apu is not equal to skid")

    val sender = message.header?.senderKeyID
        ?: message.header.agreementPartyUInfo.decodeToString()
        ?: throw MalformedMessageException("The \"skid\" header must be present")

    val recipients = message.recipients?.mapNotNull { it?.header?.keyID }
        ?: throw MalformedMessageException("JWE Unprotected Per-Recipient header must be present")

    if (message.header.agreementPartyVInfo != null &&
        message.header.agreementPartyVInfo != calculateAPV(recipients)
    )
        throw MalformedMessageException("apv is invalid")

    val (from, to) = keySelector.findAuthCryptKeys(sender, recipients)
    val decrypted = authDecrypt(message, decryptByAllKeys, from, to)

    metadataBuilder
        .encryptedTo(decrypted.toKids)
        .encryptedFrom(decrypted.fromKid)
        .encAlgAuth(authCryptAlg)
        .encrypted(true)
        .authenticated(true)

    return when (val parseResult = parse(decrypted.unpackedMessage)) {
        is ParseResult.JWS -> parseResult.unpack(keySelector, metadataBuilder)
        is ParseResult.JWM -> parseResult.unpack(keySelector, metadataBuilder)
        else -> throw MalformedMessageException("Malformed Message")
    }
}

private fun ParseResult.JWE.anonUnpack(
    keySelector: RecipientKeySelector,
    anonCryptAlg: AnonCryptAlg,
    decryptByAllKeys: Boolean,
    metadataBuilder: Metadata.Builder,
    unwrapReWrappingForward: Boolean
): Message {
    if (message.header.senderKeyID != null &&
        message.header.agreementPartyUInfo.decodeToString() != message.header.senderKeyID
    )
        throw MalformedMessageException("apu is not equal to skid")

    val recipients = message.recipients?.mapNotNull { it?.header?.keyID }
        ?: throw MalformedMessageException("JWE Unprotected Per-Recipient header must be present")

    if (message.header.agreementPartyVInfo != null &&
        message.header.agreementPartyVInfo != calculateAPV(recipients)
    )
        throw MalformedMessageException("apv is invalid")

    val to = keySelector.findAnonCryptKeys(recipients)
    val decrypted = anonDecrypt(message, decryptByAllKeys, to)

    var unpackedMessage = decrypted.unpackedMessage
    val unpackedMsgObj = Message.parse(unpackedMessage)

    var reWrappedInForward = false
    val forwardedMsg = unpackedMsgObj.forwardedMsg
    if (forwardedMsg != null && unwrapReWrappingForward) {
        unpackedMessage = forwardedMsg
        reWrappedInForward = true
    }

    metadataBuilder
        .encryptedTo(decrypted.toKids)
        .anonymousSender(true)
        .encAlgAnon(anonCryptAlg)
        .encrypted(true)
        .reWrappedInForward(reWrappedInForward)

    return when (val parseResult = parse(unpackedMessage)) {
        is ParseResult.JWE -> parseResult.anonAuthUnpack(keySelector, decryptByAllKeys, metadataBuilder)
        is ParseResult.JWS -> parseResult.unpack(keySelector, metadataBuilder)
        is ParseResult.JWM -> parseResult.unpack(keySelector, metadataBuilder)
    }
}

private fun ParseResult.JWE.anonAuthUnpack(
    keySelector: RecipientKeySelector,
    decryptByAllKeys: Boolean,
    metadataBuilder: Metadata.Builder
): Message =
    when (val alg = getCryptoAlg(message)) {
        is AuthCryptAlg -> authUnpack(keySelector, alg, decryptByAllKeys, metadataBuilder)
        else -> throw MalformedMessageException("Malformed Message")
    }
