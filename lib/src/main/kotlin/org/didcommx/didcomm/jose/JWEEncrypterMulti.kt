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
package org.didcommx.didcomm.jose

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEProvider

/**
 * JSON Web Encryption (JWE) encrypter for multiple recipients.
 * It should be used only for General JSON Serialization [JWEObjectJSON].
 *
 * @author Alexander Martynov
 * @author Thomas Diesler <tdiesler@redhat.com>
 * @version 2021-08-19
 */
interface JWEEncrypterMulti : JWEProvider {
    /**
     * Encrypts the specified clear text of a [JWE object][JWEObjectJSON].
     *
     * @param header    The JSON Web Encryption (JWE) header. Must specify
     * a supported JWE algorithm and method. Must not be
     * `null`.
     * @param clearText The clear text to encrypt. Must not be `null`.
     *
     * @return The resulting JWE crypto parts.
     *
     * @throws JOSEException If the JWE algorithm or method is not
     * supported or if encryption failed for some
     * other internal reason.
     */
    @Throws(JOSEException::class)
    fun encrypt(header: JWEHeader, clearText: ByteArray): JWECryptoPartsMulti
}
