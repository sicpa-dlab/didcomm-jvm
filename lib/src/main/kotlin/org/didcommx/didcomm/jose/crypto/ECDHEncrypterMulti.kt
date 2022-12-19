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
import com.nimbusds.jose.crypto.impl.ECDH
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Pair
import net.jcip.annotations.ThreadSafe
import java.util.*
import javax.crypto.SecretKey

/**
 * Elliptic Curve Diffie-Hellman Multi-recipient encrypter of
 * [JWE objects][JWEObjectJSON] for curves using EC JWK keys.
 * Expects a public EC key (with a P-256, P-384, or P-521 curve).
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
 *  * [com.nimbusds.jose.JWEAlgorithm.ECDH_ES]
 *  * [com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A128KW]
 *  * [com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A192KW]
 *  * [com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A256KW]
 *
 *
 *
 * Supports the following elliptic curves:
 *
 *
 *  * [com.nimbusds.jose.jwk.Curve.P_256]
 *  * [com.nimbusds.jose.jwk.Curve.P_384]
 *  * [com.nimbusds.jose.jwk.Curve.P_521]
 *
 *
 *
 * Supports the following content encryption algorithms:
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
 * @author Alexander Martynov
 * @version 2021-08-18
 */

/**
 * Creates Elliptic Curve Diffie-Hellman Multi-recipient encryptor.
 *
 * @param recipients The list of public recipient's keys.
 *
 * @throws JOSEException If the key subtype is not supported.
 */
@ThreadSafe
class ECDHEncrypterMulti(private val recipients: List<Pair<UnprotectedHeader, ECKey>>) :
    ECDHCryptoProvider(recipients[0].right.curve), JWEEncrypterMulti {

    /**
     * The supported EC JWK curves by the ECDH crypto provider class.
     */
    companion object {
        val SUPPORTED_ELLIPTIC_CURVES= setOf(Curve.P_256, Curve.P_384, Curve.P_521)
    }

    override fun supportedEllipticCurves(): Set<Curve> {
        return SUPPORTED_ELLIPTIC_CURVES
    }

    @Throws(JOSEException::class)
    override fun encrypt(header: JWEHeader, clearText: ByteArray): JWECryptoParts {
        // Generate ephemeral EC key pair on the same curve as the consumer's public key
        val ephemeralKeyPair = ECKeyGenerator(curve).generate()
        val ephemeralPublicKey = ephemeralKeyPair.toECPublicKey()
        val ephemeralPrivateKey = ephemeralKeyPair.toECPrivateKey()

        // Add the ephemeral public EC key to the header
        val updatedHeader = JWEHeader.Builder(header).ephemeralPublicKey(
            ECKey.Builder(
                curve, ephemeralPublicKey
            ).build()
        ).build()
        val sharedKeys: MutableList<Pair<UnprotectedHeader?, SecretKey>> = ArrayList()
        for (recipient in recipients) {
            val Z = ECDH.deriveSharedSecret(
                recipient.right.toECPublicKey(),
                ephemeralPrivateKey,
                jcaContext.keyEncryptionProvider
            )
            sharedKeys.add(Pair.of(recipient.left, Z))
        }
        return encryptMulti(updatedHeader, sharedKeys, clearText)
    }
}