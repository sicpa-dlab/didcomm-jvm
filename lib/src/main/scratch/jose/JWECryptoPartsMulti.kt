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
 * @version 2021-09-30
 */
@Immutable
class JWECryptoPartsMulti {
    /**
     * Gets the modified JWE header.
     *
     * @return The modified JWE header, `null` of not.
     */
    /**
     * The modified JWE header (optional).
     */
    val header: JWEHeader?
    /**
     * Gets the encrypted key.
     *
     * @return The encrypted key, `null` if not required by
     * the JWE algorithm or `recipients` are specified.
     */
    /**
     * The encrypted key (optional).
     */
    val encryptedKey: Base64URL?
    /**
     * Gets the initialisation vector (IV).
     *
     * @return The initialisation vector (IV), `null` if not required
     * by the JWE algorithm.
     */
    /**
     * The initialisation vector (optional).
     */
    val initializationVector: Base64URL?
    /**
     * Gets the cipher text.
     *
     * @return The cipher text.
     */
    /**
     * The cipher text.
     */
    val cipherText: Base64URL
    /**
     * Gets the authentication tag.
     *
     * @return The authentication tag, `null` if the encryption
     * algorithm provides built-in integrity checking.
     */
    /**
     * The authentication tag (optional).
     */
    val authenticationTag: Base64URL?

    /**
     * The recipients (optional)
     */
    private val recipients: List<JWERecipient>?

    /**
     * Creates a new cryptographic JWE parts instance.
     *
     * @param encryptedKey      The encrypted key, `null` if not
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
        encryptedKey: Base64URL?,
        iv: Base64URL?,
        cipherText: Base64URL?,
        authenticationTag: Base64URL?
    ) : this(null, encryptedKey, iv, cipherText, authenticationTag)

    /**
     * Creates a new cryptographic JWE parts instance.
     *
     * @param header            The modified JWE header, `null` if
     * not.
     * @param encryptedKey      The encrypted key, `null` if not
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
        encryptedKey: Base64URL?,
        iv: Base64URL?,
        cipherText: Base64URL?,
        authenticationTag: Base64URL?
    ) {
        this.header = header
        this.encryptedKey = encryptedKey
        initializationVector = iv
        requireNotNull(cipherText) { "The cipher text must not be null" }
        this.cipherText = cipherText
        this.authenticationTag = authenticationTag
        recipients = null
    }

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
        cipherText: Base64URL?,
        authenticationTag: Base64URL?
    ) {
        this.header = header
        encryptedKey = null
        initializationVector = iv
        requireNotNull(cipherText) { "The cipher text must not be null" }
        this.cipherText = cipherText
        this.authenticationTag = authenticationTag
        this.recipients = recipients
    }

    /**
     * Gets the JWE recipients.
     *
     * @return The JWE recipients, `null` if not required by the JWE
     * algorithm or an `encryptedKey` is specified.
     */
    fun getRecipients(): List<JWERecipient>? {
        return recipients
    }
}