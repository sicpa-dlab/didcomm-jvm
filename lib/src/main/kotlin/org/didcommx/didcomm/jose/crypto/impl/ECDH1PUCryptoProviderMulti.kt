package org.didcommx.didcomm.jose.crypto.impl

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.UnprotectedHeader
import com.nimbusds.jose.crypto.impl.AESKW
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider
import com.nimbusds.jose.crypto.impl.ECDH
import com.nimbusds.jose.crypto.impl.ECDH1PU
import com.nimbusds.jose.crypto.impl.ECDH1PUCryptoProvider
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.Pair
import org.didcommx.didcomm.jose.JWECryptoPartsMulti
import org.didcommx.didcomm.jose.JWERecipient
import java.util.Collections
import javax.crypto.SecretKey

abstract class ECDH1PUCryptoProviderMulti(curve: Curve) : ECDH1PUCryptoProvider(curve) {

    @Throws(JOSEException::class)
    fun encryptMultiNew(
        header: JWEHeader,
        sharedSecrets: List<Pair<UnprotectedHeader, SecretKey>>,
        clearText: ByteArray
    ): JWECryptoPartsMulti {
        val algMode = ECDH1PU.resolveAlgorithmMode(header.algorithm)
        val cek = ContentCryptoProvider.generateCEK(
            header.encryptionMethod,
            jcaContext.secureRandom
        )
        val recipients = ArrayList<JWERecipient>()
        var encrypted = false
        var parts: JWECryptoPartsMulti? = null
        for (rs in sharedSecrets) {
            var encryptedKey: Base64URL? = null
            if (!encrypted) {
                parts = encryptWithZMulti(header, rs.right, clearText, cek)
                encryptedKey = parts.encryptedKey
                encrypted = true
            } else if (algMode == ECDH.AlgorithmMode.KW) {
                val sharedKey = ECDH1PU.deriveSharedKey(
                    header, rs.right, parts!!.authenticationTag,
                    concatKDF
                )
                encryptedKey = Base64URL.encode(AESKW.wrapCEK(cek, sharedKey, jcaContext.keyEncryptionProvider))
            }
            if (encryptedKey != null) {
                recipients.add(JWERecipient(rs.left, encryptedKey))
            }
        }
        if (parts == null) {
            throw JOSEException("Content MUST be encrypted")
        }
        return JWECryptoPartsMulti(
            parts.header,
            Collections.unmodifiableList(recipients),
            parts.initializationVector,
            parts.cipherText,
            parts.authenticationTag
        )
    }

    @Throws(JOSEException::class)
    fun decryptMultiNew(
        header: JWEHeader,
        sharedSecrets: List<Pair<UnprotectedHeader, SecretKey>>,
        recipients: List<JWERecipient>?,
        iv: Base64URL?,
        cipherText: Base64URL,
        authTag: Base64URL?
    ): ByteArray? {
        var result: ByteArray? = null
        for (rs in sharedSecrets) {
            val kid = rs.left.keyID
            var encryptedKey: Base64URL? = null
            if (recipients != null) {
                for (recipient in recipients) {
                    // if (recipient.header == null) continue
                    if (kid == recipient.header.keyID) {
                        encryptedKey = recipient.encryptedKey
                        break
                    }
                }
            }
            result = decryptWithZ(header, rs.right, encryptedKey, iv, cipherText, authTag)
        }
        return result
    }

    private fun encryptWithZMulti(
        header: JWEHeader?,
        Z: SecretKey?,
        clearText: ByteArray?,
        contentEncryptionKey: SecretKey?
    ): JWECryptoPartsMulti {
        val parts = super.encryptWithZ(header, Z, clearText, contentEncryptionKey)
        return JWECryptoPartsMulti(parts)
    }
}
