/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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

import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.util.Base64URL
import net.jcip.annotations.Immutable

/**
 * The cryptographic parts of a JSON Web Encryption (JWE) object.
 *
 * @author Vladimir Dzhuvinov
 * @author Thomas Diesler <tdiesler@redhat.com>
 * @version 2021-09-30
 */
@Immutable
class JWECryptoPartsMulti {

    /**
     * The modified JWE header (optional).
     */
    val header: JWEHeader?

    /**
     * The encrypted key (optional).
     */
    val encryptedKey: Base64URL?

    /**
     * The initialisation vector (optional).
     */
    val initializationVector: Base64URL?

    /**
     * The cipher text.
     */
    val cipherText: Base64URL

    /**
     * The authentication tag (optional).
     */
    val authenticationTag: Base64URL?

    /**
     * The recipients (optional)
     */
    val recipients: List<JWERecipient>?

    /**
     * Creates a new cryptographic JWE parts instance.
     *
     * @param header            The modified JWE header, `null` if
     * not.
     * @param recipients        The JWE recipients, `null` if not
     * required by the encryption algorithm.
     * @param iv                The initialisation vector (IV),
     * `null` if not required by the
     * encryption algorithm.
     * @param cipherText        The cipher text. Must not be `null`.
     * @param authenticationTag The authentication tag, `null` if the
     * JWE algorithm provides built-in integrity
     * check.
     */
    constructor(
        header: JWEHeader?,
        recipients: List<JWERecipient>?,
        iv: Base64URL?,
        cipherText: Base64URL,
        authenticationTag: Base64URL?
    ) {
        this.header = header
        this.initializationVector = iv
        this.cipherText = cipherText
        this.authenticationTag = authenticationTag
        this.recipients = recipients
        encryptedKey = null
    }

    /**
     * Creates a new cryptographic JWE parts instance from nimbus JWECryptoParts.
     *
     * @param parts The nimbus JWECryptoParts. Must not be `null`.
     */
    constructor(parts: com.nimbusds.jose.JWECryptoParts) {
        header = parts.header
        encryptedKey = parts.encryptedKey
        initializationVector = parts.initializationVector
        cipherText = parts.cipherText
        authenticationTag = parts.authenticationTag
        recipients = null
    }
}
