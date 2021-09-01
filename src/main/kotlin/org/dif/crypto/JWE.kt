package org.dif.crypto

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObjectJSON
import com.nimbusds.jose.Payload
import com.nimbusds.jose.UnprotectedHeader
import com.nimbusds.jose.crypto.ECDH1PUDecrypterMulti
import com.nimbusds.jose.crypto.ECDH1PUEncrypterMulti
import com.nimbusds.jose.crypto.ECDH1PUX25519DecrypterMulti
import com.nimbusds.jose.crypto.ECDH1PUX25519EncrypterMulti
import com.nimbusds.jose.crypto.ECDHDecrypterMulti
import com.nimbusds.jose.crypto.ECDHEncrypterMulti
import com.nimbusds.jose.crypto.X25519DecrypterMulti
import com.nimbusds.jose.crypto.X25519EncrypterMulti
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.Pair
import org.dif.common.AnonCryptAlg
import org.dif.common.AuthCryptAlg
import org.dif.common.Typ
import org.dif.crypto.key.Key
import org.dif.exceptions.MalformedMessageException
import org.dif.exceptions.UnsupportedAlgorithm
import org.dif.exceptions.UnsupportedJWKException
import org.dif.utils.asKeys
import org.dif.utils.component1
import org.dif.utils.component2
import java.security.MessageDigest

fun authEncrypt(payload: String, auth: AuthCryptAlg, from: Key, to: List<Key>): EncryptResult {
    val digest = MessageDigest.getInstance("SHA-256")

    val skid = from.id
    val kids = to.map { it.id }.sorted()

    val apu = Base64URL.encode(from.id)
    val apv = Base64URL.encode(digest.digest(kids.joinToString(".").encodeToByteArray()))

    val (alg, enc) = when (auth) {
        AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW -> Pair(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256CBC_HS512)
    }

    val jweHeader = JWEHeader.Builder(alg, enc)
        .type(JOSEObjectType(Typ.Encrypted.typ))
        .agreementPartyVInfo(apv)
        .agreementPartyUInfo(apu)
        .senderKeyID(skid)
        .build()

    val sender = from.jwk
    val recipients = to.map { Pair.of(UnprotectedHeader.Builder(it.id).build(), it.jwk) }

    val encryptor = when (sender) {
        is ECKey -> ECDH1PUEncrypterMulti(sender, recipients.asKeys())
        is OctetKeyPair -> ECDH1PUX25519EncrypterMulti(sender, recipients.asKeys())
        else -> throw UnsupportedJWKException(sender.javaClass.name)
    }

    return JWEObjectJSON(jweHeader, Payload(Base64URL.encode(payload)))
        .apply { encrypt(encryptor) }
        .run { EncryptResult(serialize(), kids) }
}

fun anonEncrypt(payload: String, anon: AnonCryptAlg, to: List<Key>): EncryptResult {
    val digest = MessageDigest.getInstance("SHA-256")

    val kids = to.map { it.id }.sorted()
    val apv = Base64URL.encode(digest.digest(kids.joinToString(".").encodeToByteArray()))

    val (alg, enc) = when (anon) {
        AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW -> Pair.of(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512)
        AnonCryptAlg.XC20P_ECDH_ES_A256KW -> Pair.of(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.XC20P)
        AnonCryptAlg.A256GCM_ECDH_ES_A256KW -> Pair.of(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM)
    }

    val jweHeader = JWEHeader.Builder(alg, enc)
        .agreementPartyVInfo(apv)
        .build()

    val recipients = to.map { Pair.of(UnprotectedHeader.Builder(it.id).build(), it.jwk) }

    val encryptor = when (val recipient = recipients.first().right) {
        is ECKey -> ECDHEncrypterMulti(recipients.asKeys())
        is OctetKeyPair -> X25519EncrypterMulti(recipients.asKeys())
        else -> throw UnsupportedJWKException(recipient.javaClass.name)
    }

    return JWEObjectJSON(jweHeader, Payload(Base64URL.encode(payload)))
        .apply { encrypt(encryptor) }
        .run { EncryptResult(serialize(), kids) }
}

fun authDecrypt(jwe: JWEObjectJSON, from: Key, to: List<Key>): Map<String, Any> {
    val sender = from.jwk
    val recipients = to.map { Pair.of(UnprotectedHeader.Builder(it.id).build(), it.jwk) }

    val decrypter = when (sender) {
        is ECKey -> ECDH1PUDecrypterMulti(sender, recipients.asKeys())
        is OctetKeyPair -> ECDH1PUX25519DecrypterMulti(sender, recipients.asKeys())
        else -> throw UnsupportedJWKException(sender.javaClass.name)
    }

    try {
        jwe.decrypt(decrypter)
    } catch (t: Throwable) {
        throw MalformedMessageException("Decrypt is failed", t)
    }

    return jwe.payload.toJSONObject()
}

fun anonDecrypt(jwe: JWEObjectJSON, to: List<Key>): Map<String, Any> {
    val recipients = to.map { Pair.of(UnprotectedHeader.Builder(it.id).build(), it.jwk) }

    val decrypter = when (val recipient = recipients.first().right) {
        is ECKey -> ECDHDecrypterMulti(recipients.asKeys())
        is OctetKeyPair -> X25519DecrypterMulti(recipients.asKeys())
        else -> throw UnsupportedJWKException(recipient.javaClass.name)
    }

    try {
        jwe.decrypt(decrypter)
    } catch (t: Throwable) {
        throw MalformedMessageException("Decrypt is failed", t)
    }

    return jwe.payload.toJSONObject()
}

fun getCryptoAlg(jwe: JWEObjectJSON): Pair<AuthCryptAlg?, AnonCryptAlg?> {
    val alg = jwe.header.algorithm
    val enc = jwe.header.encryptionMethod

    return when {
        alg == JWEAlgorithm.ECDH_1PU_A256KW && enc == EncryptionMethod.A256CBC_HS512 ->
            Pair.of(AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW, null)

        alg == JWEAlgorithm.ECDH_ES_A256KW && enc == EncryptionMethod.A256CBC_HS512 ->
            Pair.of(null, AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW)

        alg == JWEAlgorithm.ECDH_ES_A256KW && enc == EncryptionMethod.XC20P ->
            Pair.of(null, AnonCryptAlg.XC20P_ECDH_ES_A256KW)

        alg == JWEAlgorithm.ECDH_ES_A256KW && enc == EncryptionMethod.A256GCM ->
            Pair.of(null, AnonCryptAlg.A256GCM_ECDH_ES_A256KW)

        else -> throw UnsupportedAlgorithm("${alg.name}+${enc.name}")
    }
}

data class EncryptResult(val message: String, val recipients: List<String>)
