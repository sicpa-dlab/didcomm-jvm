package org.dif.crypto

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEException
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
import org.dif.common.CryptAlg
import org.dif.common.Typ
import org.dif.crypto.key.Key
import org.dif.exceptions.DIDCommException
import org.dif.exceptions.MalformedMessageException
import org.dif.exceptions.UnsupportedAlgorithm
import org.dif.exceptions.UnsupportedCurveException
import org.dif.exceptions.UnsupportedJWKException
import org.dif.utils.asKeys
import java.lang.NullPointerException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

fun authEncrypt(payload: String, auth: AuthCryptAlg, from: Key, to: List<Key>): EncryptResult {
    val algorithm = "SHA-256"
    val digest = try {
        MessageDigest.getInstance(algorithm)
    } catch (e: NullPointerException) {
        throw UnsupportedAlgorithm(algorithm)
    } catch (e: NoSuchAlgorithmException) {
        throw UnsupportedAlgorithm(algorithm)
    }

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

    val encryptor = try {
        when (sender) {
            is ECKey ->
                ECDH1PUEncrypterMulti(sender, recipients.asKeys())
            is OctetKeyPair ->
                ECDH1PUX25519EncrypterMulti(sender, recipients.asKeys())
            else -> throw UnsupportedJWKException(sender.javaClass.name)
        }
    } catch (e: JOSEException) {
        throw DIDCommException("The key subtype is not supported", e)
    }

    return JWEObjectJSON(jweHeader, Payload(Base64URL.encode(payload)))
        .apply {
            try {
                encrypt(encryptor)
            } catch (e: JOSEException) {
                throw DIDCommException("JWE cannot be encrypted", e)
            }
        }
        .run { EncryptResult(serialize(), kids, from.id) }
}

fun anonEncrypt(payload: String, anon: AnonCryptAlg, to: List<Key>): EncryptResult {
    val algorithm = "SHA-256"
    val digest = try {
        MessageDigest.getInstance(algorithm)
    } catch (e: NullPointerException) {
        throw UnsupportedAlgorithm(algorithm)
    } catch (e: NoSuchAlgorithmException) {
        throw UnsupportedAlgorithm(algorithm)
    }

    val kids = to.map { it.id }.sorted()
    val apv = Base64URL.encode(digest.digest(kids.joinToString(".").encodeToByteArray()))

    val (alg, enc) = when (anon) {
        AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW -> Pair(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512)
        AnonCryptAlg.XC20P_ECDH_ES_A256KW -> Pair(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.XC20P)
        AnonCryptAlg.A256GCM_ECDH_ES_A256KW -> Pair(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM)
    }

    val jweHeader = JWEHeader.Builder(alg, enc)
        .agreementPartyVInfo(apv)
        .build()

    val recipients = to.map { Pair.of(UnprotectedHeader.Builder(it.id).build(), it.jwk) }

    val encryptor = try {
        when (val recipient = recipients.first().right) {
            is ECKey -> ECDHEncrypterMulti(recipients.asKeys())
            is OctetKeyPair -> X25519EncrypterMulti(recipients.asKeys())
            else -> throw UnsupportedJWKException(recipient.javaClass.name)
        }
    } catch (e: JOSEException) {
        throw DIDCommException("The key subtype is not supported", e)
    }

    return JWEObjectJSON(jweHeader, Payload(Base64URL.encode(payload)))
        .apply {
            try {
                encrypt(encryptor)
            } catch (e: JOSEException) {
                throw DIDCommException("JWE cannot be encrypted", e)
            }
        }
        .run { EncryptResult(serialize(), kids) }
}

fun authDecrypt(jwe: JWEObjectJSON, decryptByAllKeys: Boolean, from: Key, to: Sequence<Key>) = if (decryptByAllKeys) {
    authDecryptForAllKeys(jwe, from, to.toList())
} else {
    authDecryptForOneKey(jwe, from, to)
        .filterNotNull()
        .firstOrNull() ?: throw MalformedMessageException("Decrypt failed")
}

fun anonDecrypt(jwe: JWEObjectJSON, decryptByAllKeys: Boolean, to: Sequence<Key>) = if (decryptByAllKeys) {
    anonDecryptForAllKeys(jwe, to.toList())
} else {
    anonDecryptForOneKey(jwe, to)
        .filterNotNull()
        .firstOrNull() ?: throw MalformedMessageException("Decrypt failed")
}

private fun authDecryptForOneKey(jwe: JWEObjectJSON, from: Key, to: Sequence<Key>) = to.map {
    try {
        authDecryptForAllKeys(jwe, from, listOf(it))
    } catch (e: MalformedMessageException) {
        null
    }
}

private fun anonDecryptForOneKey(jwe: JWEObjectJSON, to: Sequence<Key>) = to.map {
    try {
        anonDecryptForAllKeys(jwe, listOf(it))
    } catch (e: MalformedMessageException) {
        null
    }
}

private fun authDecryptForAllKeys(jwe: JWEObjectJSON, from: Key, to: List<Key>): DecryptResult {
    val sender = from.jwk
    val recipients = to.map { Pair.of(UnprotectedHeader.Builder(it.id).build(), it.jwk) }

    val decrypter =
        when (sender) {
            is ECKey -> try {
                ECDH1PUDecrypterMulti(sender, recipients.asKeys())
            } catch (e: JOSEException) {
                throw UnsupportedCurveException(sender.curve.name)
            }
            is OctetKeyPair -> try {
                ECDH1PUX25519DecrypterMulti(sender, recipients.asKeys())
            } catch (e: JOSEException) {
                throw UnsupportedCurveException(sender.curve.name)
            }
            else -> throw UnsupportedJWKException(sender.javaClass.name)
        }

    try {
        jwe.decrypt(decrypter)
    } catch (t: Throwable) {
        throw MalformedMessageException("Decrypt is failed", t)
    }

    return DecryptResult(jwe.payload.toJSONObject(), to.map { it.id }, from.id)
}

private fun anonDecryptForAllKeys(jwe: JWEObjectJSON, to: List<Key>): DecryptResult {
    val recipients = to.map { Pair.of(UnprotectedHeader.Builder(it.id).build(), it.jwk) }

    val decrypter =
        when (val recipient = recipients.first().right) {
            is ECKey -> try {
                ECDHDecrypterMulti(recipients.asKeys())
            } catch (e: JOSEException) {
                throw UnsupportedCurveException(recipient.curve.name)
            }
            is OctetKeyPair -> try {
                X25519DecrypterMulti(recipients.asKeys())
            } catch (e: JOSEException) {
                throw UnsupportedCurveException(recipient.curve.name)
            }
            else -> throw UnsupportedJWKException(recipient.javaClass.name)
        }

    try {
        jwe.decrypt(decrypter)
    } catch (t: Throwable) {
        throw MalformedMessageException("Decrypt is failed", t)
    }

    return DecryptResult(jwe.payload.toJSONObject(), to.map { it.id })
}

fun getCryptoAlg(jwe: JWEObjectJSON): CryptAlg {
    val alg = jwe.header.algorithm
    val enc = jwe.header.encryptionMethod

    return when {
        alg == JWEAlgorithm.ECDH_1PU_A256KW && enc == EncryptionMethod.A256CBC_HS512 ->
            AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW

        alg == JWEAlgorithm.ECDH_ES_A256KW && enc == EncryptionMethod.A256CBC_HS512 ->
            AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW

        alg == JWEAlgorithm.ECDH_ES_A256KW && enc == EncryptionMethod.XC20P ->
            AnonCryptAlg.XC20P_ECDH_ES_A256KW

        alg == JWEAlgorithm.ECDH_ES_A256KW && enc == EncryptionMethod.A256GCM ->
            AnonCryptAlg.A256GCM_ECDH_ES_A256KW

        else -> throw UnsupportedAlgorithm("${alg.name}+${enc.name}")
    }
}

data class EncryptResult(
    val packedMessage: String,
    val toKids: List<String>,
    val fromKid: String? = null
)

data class DecryptResult(
    val unpackedMessage: Map<String, Any>,
    val toKids: List<String>,
    val fromKid: String? = null
)
