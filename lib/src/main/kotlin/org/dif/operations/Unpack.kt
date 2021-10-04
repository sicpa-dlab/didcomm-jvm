package org.dif.operations

import org.dif.common.AnonCryptAlg
import org.dif.common.AuthCryptAlg
import org.dif.crypto.ParseResult
import org.dif.crypto.anonDecrypt
import org.dif.crypto.authDecrypt
import org.dif.crypto.getCryptoAlg
import org.dif.crypto.key.RecipientKeySelector
import org.dif.crypto.parse
import org.dif.crypto.verify
import org.dif.exceptions.MalformedMessageException
import org.dif.message.Message
import org.dif.model.Metadata
import org.dif.model.UnpackParams
import org.dif.model.UnpackResult
import org.dif.utils.calculateAPV

fun unpack(params: UnpackParams, keySelector: RecipientKeySelector): UnpackResult {
    val metadataBuilder = Metadata.Builder()

    val msg = when (val parseResult = parse(params.packedMessage)) {
        is ParseResult.JWS -> parseResult.unpack(keySelector, metadataBuilder)
        is ParseResult.JWE -> parseResult.unpack(keySelector, params.expectDecryptByAllKeys, metadataBuilder)
        is ParseResult.JWM -> parseResult.message
    }

    return UnpackResult(msg, metadataBuilder.build())
}

private fun ParseResult.JWS.unpack(keySelector: RecipientKeySelector, metadataBuilder: Metadata.Builder): Message {
    val kid = message.unprotectedHeader?.keyID
        ?: throw MalformedMessageException("JWS Unprotected Per-Signature header must be present")

    val key = keySelector.findVerificationKey(kid)
    val alg = getCryptoAlg(message)
    val message = verify(message, alg, key)

    metadataBuilder
        .signAlg(alg)
        .signFrom(kid)
        .nonRepudiation(true)
        .signedMessage(rawMessage)

    return message
}

private fun ParseResult.JWE.unpack(
    keySelector: RecipientKeySelector,
    decryptByAllKeys: Boolean,
    metadataBuilder: Metadata.Builder
): Message =
    when (val alg = getCryptoAlg(message)) {
        is AuthCryptAlg -> authUnpack(keySelector, alg, decryptByAllKeys, metadataBuilder)
        is AnonCryptAlg -> anonUnpack(keySelector, alg, decryptByAllKeys, metadataBuilder)
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
        is ParseResult.JWM -> parseResult.message
        else -> throw MalformedMessageException("Malformed Message")
    }
}

private fun ParseResult.JWE.anonUnpack(
    keySelector: RecipientKeySelector,
    anonCryptAlg: AnonCryptAlg,
    decryptByAllKeys: Boolean,
    metadataBuilder: Metadata.Builder
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

    metadataBuilder
        .encryptedTo(decrypted.toKids)
        .anonymousSender(true)
        .encAlgAnon(anonCryptAlg)
        .encrypted(true)

    return when (val parseResult = parse(decrypted.unpackedMessage)) {
        is ParseResult.JWE -> parseResult.anonAuthUnpack(keySelector, decryptByAllKeys, metadataBuilder)
        is ParseResult.JWS -> parseResult.unpack(keySelector, metadataBuilder)
        is ParseResult.JWM -> parseResult.message
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
