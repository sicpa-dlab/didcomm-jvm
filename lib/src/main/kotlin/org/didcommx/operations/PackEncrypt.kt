package org.didcommx.didcomm.operations

import org.didcommx.didcomm.crypto.EncryptResult
import org.didcommx.didcomm.crypto.anonEncrypt
import org.didcommx.didcomm.crypto.authEncrypt
import org.didcommx.didcomm.crypto.key.Key
import org.didcommx.didcomm.crypto.key.SenderKeySelector
import org.didcommx.didcomm.crypto.sign
import org.didcommx.didcomm.model.PackEncryptedParams

fun signIfNeeded(params: PackEncryptedParams, keySelector: SenderKeySelector) =
    if (params.signFrom != null) {
        val key = keySelector.findSigningKey(params.signFrom)
        Pair(sign(params.message.toString(), key), key.id)
    } else {
        Pair(params.message.toString(), null)
    }

fun encrypt(params: PackEncryptedParams, payload: String, keySelector: SenderKeySelector) =
    if (params.from != null) {
        val (senderKey, recipientKeys) = keySelector.findAuthCryptKeys(params.from, params.to)
        Pair(authEncrypt(payload, params.encAlgAuth, senderKey, recipientKeys), recipientKeys)
    } else {
        val recipientKeys = keySelector.findAnonCryptKeys(params.to)
        Pair(anonEncrypt(payload, params.encAlgAnon, recipientKeys), recipientKeys)
    }

fun protectSenderIfNeeded(params: PackEncryptedParams, encryptResult: EncryptResult, recipientKeys: List<Key>) =
    if (params.protectSenderId && params.from != null) {
        anonEncrypt(encryptResult.packedMessage, params.encAlgAnon, recipientKeys)
    } else {
        encryptResult
    }
