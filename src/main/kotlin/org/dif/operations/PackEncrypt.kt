package org.dif.operations

import org.dif.crypto.EncryptResult
import org.dif.crypto.anonEncrypt
import org.dif.crypto.authEncrypt
import org.dif.crypto.key.SenderKeySelector
import org.dif.crypto.sign
import org.dif.model.PackEncryptedParams

fun signIfNeeded(params: PackEncryptedParams, keySelector: SenderKeySelector) =
    if (params.signFrom != null) {
        val key = keySelector.signKey(params.signFrom)
        sign(params.message.toString(), key)
    } else {
        params.message.toString()
    }

fun encrypt(params: PackEncryptedParams, payload: String, keySelector: SenderKeySelector) =
    if (params.from != null) {
        val (senderKey, recipientKeys) = keySelector.authCryptKeys(params.from, params.to)
        authEncrypt(payload, params.encAlgAuth, senderKey, recipientKeys)
    } else {
        val keys = keySelector.anonCryptKeys(params.to)
        anonEncrypt(payload, params.encAlgAnon, keys)
    }

fun protectedSenderIdNeeded(params: PackEncryptedParams, encryptResult: EncryptResult, keySelector: SenderKeySelector) =
    if (params.protectSenderId && params.from != null) {
        val keys = keySelector.anonCryptKeys(params.to)
        anonEncrypt(encryptResult.message, params.encAlgAnon, keys)
    } else {
        encryptResult
    }
