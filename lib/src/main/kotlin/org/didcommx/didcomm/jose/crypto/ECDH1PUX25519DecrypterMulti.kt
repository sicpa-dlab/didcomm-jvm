/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.didcommx.didcomm.jose.crypto

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral
import com.nimbusds.jose.crypto.impl.ECDH1PU
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.Pair
import net.jcip.annotations.ThreadSafe
import org.didcommx.didcomm.jose.JWEDecrypterMulti
import org.didcommx.didcomm.jose.crypto.impl.ECDH1PUCryptoProviderMulti
import java.util.*
import javax.crypto.SecretKey

/**
 * Elliptic Curve Diffie-Hellman Multi-recipient decrypter of
 * [JWE objects][com.nimbusds.jose.JWEObjectJSON] for curves using EC JWK
 * Expects a private [OctetKeyPair] key with `"crv"` X25519.
 *
 *
 * See [RFC 8037](https://tools.ietf.org/html/rfc8037)
 * for more information.
 *
 *
 * Public Key Authenticated Encryption for JOSE
 * [ECDH-1PU](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04)
 * for more information.
 *
 *
 * This class is thread-safe.
 *
 *
 * Supports the following key management algorithms:
 *
 *
 *  * [com.nimbusds.jose.JWEAlgorithm.ECDH_1PU]
 *  * [com.nimbusds.jose.JWEAlgorithm.ECDH_1PU_A128KW]
 *  * [com.nimbusds.jose.JWEAlgorithm.ECDH_1PU_A192KW]
 *  * [com.nimbusds.jose.JWEAlgorithm.ECDH_1PU_A256KW]
 *
 *
 *
 * Supports the following elliptic curves:
 *
 *
 *  * [Curve.X25519]
 *
 *
 *
 * Supports the following content encryption algorithms for Direct key agreement mode:
 *
 *
 *  * [com.nimbusds.jose.EncryptionMethod.A128CBC_HS256]
 *  * [com.nimbusds.jose.EncryptionMethod.A192CBC_HS384]
 *  * [com.nimbusds.jose.EncryptionMethod.A256CBC_HS512]
 *  * [com.nimbusds.jose.EncryptionMethod.A128GCM]
 *  * [com.nimbusds.jose.EncryptionMethod.A192GCM]
 *  * [com.nimbusds.jose.EncryptionMethod.A256GCM]
 *  * [com.nimbusds.jose.EncryptionMethod.A128CBC_HS256_DEPRECATED]
 *  * [com.nimbusds.jose.EncryptionMethod.A256CBC_HS512_DEPRECATED]
 *  * [com.nimbusds.jose.EncryptionMethod.XC20P]
 *
 *
 *
 * Supports the following content encryption algorithms for Key wrapping mode:
 *
 *
 *  * [com.nimbusds.jose.EncryptionMethod.A128CBC_HS256]
 *  * [com.nimbusds.jose.EncryptionMethod.A192CBC_HS384]
 *  * [com.nimbusds.jose.EncryptionMethod.A256CBC_HS512]
 *
 *
 * @author Alexander Martynov
 * @version 2021-08-18
 */

/**
 * Creates a curve x25519 Elliptic Curve Diffie-Hellman Multi-recipient decrypter.
 *
 * @param sender         The sender public JWK key.
 * @param recipients     The list of private recipient's keys.
 * @param defCritHeaders The names of the critical header parameters
 * that are deferred to the application for
 * processing, empty set or `null` if none.
 *
 * @throws JOSEException If the key subtype is not supported.
 */
@ThreadSafe
class ECDH1PUX25519DecrypterMulti(private val sender: OctetKeyPair, private val recipients: List<Pair<UnprotectedHeader, OctetKeyPair>>, defCritHeaders: Set<String>? = null) :
    ECDH1PUCryptoProviderMulti(sender.curve), JWEDecrypterMulti, CriticalHeaderParamsAware {

    /**
     * The supported EC JWK curves by the ECDH crypto provider class.
     */
    companion object {
        val SUPPORTED_ELLIPTIC_CURVES= setOf(Curve.X25519)
    }

    /**
     * The critical header policy.
     */
    private val critPolicy = CriticalHeaderParamsDeferral()
    init {
        critPolicy.deferredCriticalHeaderParams = defCritHeaders
    }

    override fun supportedEllipticCurves(): Set<Curve> {
        return SUPPORTED_ELLIPTIC_CURVES
    }

    override fun getProcessedCriticalHeaderParams(): Set<String> {
        return critPolicy.processedCriticalHeaderParams
    }

    override fun getDeferredCriticalHeaderParams(): Set<String> {
        return critPolicy.processedCriticalHeaderParams
    }

    @Throws(JOSEException::class)
    override fun decrypt(
        header: JWEHeader,
        recipients: List<JWERecipient>?,
        iv: Base64URL?,
        cipherText: Base64URL,
        authTag: Base64URL?
    ): ByteArray? {
        critPolicy.ensureHeaderPasses(header)

        // Get ephemeral key from header
        val ephemeralPublicKey = header.ephemeralPublicKey as OctetKeyPair
        val sharedKeys = ArrayList<Pair<UnprotectedHeader, SecretKey>>()
        for (recipient in this.recipients) {
            val Z = ECDH1PU.deriveRecipientZ(
                recipient.right,
                sender.toPublicJWK(),
                ephemeralPublicKey
            )
            sharedKeys.add(Pair.of(recipient.left, Z))
        }
        return decryptMultiNew(header, sharedKeys, recipients, iv, cipherText, authTag)
    }
}