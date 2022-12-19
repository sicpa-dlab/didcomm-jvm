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
import com.nimbusds.jose.crypto.impl.ECDH1PU
import com.nimbusds.jose.crypto.impl.ECDH1PUCryptoProvider
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
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
 * For Curve25519/X25519, see [ECDH1PUX25519Encrypter] instead.
 *
 *
 * This class is thread-safe.
 *
 *
 * Supports the following key management algorithms:
 *
 *
 *  * [JWEAlgorithm.ECDH_1PU]
 *  * [JWEAlgorithm.ECDH_1PU_A128KW]
 *  * [JWEAlgorithm.ECDH_1PU_A192KW]
 *  * [JWEAlgorithm.ECDH_1PU_A256KW]
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
 *  * [EncryptionMethod.A128CBC_HS256]
 *  * [EncryptionMethod.A192CBC_HS384]
 *  * [EncryptionMethod.A256CBC_HS512]
 *  * [EncryptionMethod.A128GCM]
 *  * [EncryptionMethod.A192GCM]
 *  * [EncryptionMethod.A256GCM]
 *  * [EncryptionMethod.A128CBC_HS256_DEPRECATED]
 *  * [EncryptionMethod.A256CBC_HS512_DEPRECATED]
 *  * [EncryptionMethod.XC20P]
 *
 *
 *
 * Supports the following content encryption algorithms for Key wrapping mode:
 *
 *
 *  * [EncryptionMethod.A128CBC_HS256]
 *  * [EncryptionMethod.A192CBC_HS384]
 *  * [EncryptionMethod.A256CBC_HS512]
 *
 *
 * @author Alexander Martynov
 * @version 2021-08-18
 */

/**
 * Creates a curve x25519 Elliptic Curve Diffie-Hellman Multi-recipient encryptor.
 *
 * @param sender     The private sender JWK key.
 * @param recipients The list of public recipient's keys.
 *
 * @throws JOSEException If the key subtype is not supported.
 */
@ThreadSafe
class ECDH1PUX25519EncrypterMulti(private val sender: OctetKeyPair, private val recipients: List<Pair<UnprotectedHeader, OctetKeyPair>>) :
    ECDH1PUCryptoProvider(sender.curve), JWEEncrypterMulti {

    /**
     * The supported EC JWK curves by the ECDH crypto provider class.
     */
    companion object {
        val SUPPORTED_ELLIPTIC_CURVES= setOf(Curve.X25519)
    }

    override fun supportedEllipticCurves(): Set<Curve> {
        return SUPPORTED_ELLIPTIC_CURVES
    }

    @Throws(JOSEException::class)
    override fun encrypt(header: JWEHeader, clearText: ByteArray): JWECryptoParts {

        // Generate ephemeral OctetKey key pair on the same curve as the consumer's public key
        val ephemeralPrivateKey = OctetKeyPairGenerator(curve).generate()
        val ephemeralPublicKey = ephemeralPrivateKey.toPublicJWK()

        // Add the ephemeral public OctetKey key to the header
        val updatedHeader = JWEHeader.Builder(header).ephemeralPublicKey(ephemeralPublicKey).build()
        val sharedKeys: MutableList<Pair<UnprotectedHeader, SecretKey>> = ArrayList()
        for (recipient in recipients) {
            val Z = ECDH1PU.deriveSenderZ(
                sender,
                recipient.right.toPublicJWK(),
                ephemeralPrivateKey
            )
            sharedKeys.add(Pair.of(recipient.left, Z))
        }
        return encryptMulti(updatedHeader, sharedKeys, clearText)
    }
}