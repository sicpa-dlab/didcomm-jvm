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

import com.nimbusds.jose.*
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONArrayUtils
import com.nimbusds.jose.util.JSONObjectUtils
import net.jcip.annotations.ThreadSafe
import java.text.ParseException

/**
 * JSON Web Encryption (JWE) secured object.
 *
 * Provides [JWE JSON Serialization](https://datatracker.ietf.org/doc/html/rfc7516#section-7.2)
 *
 * This class is thread-safe.
 *
 * @author Alexander Martynov
 * @version 2021-08-17
 */
@ThreadSafe
class JWEObjectJSON : JOSEObject, JSONSerializable {
    /**
     * Enumeration of the states of a JSON Web Encryption (JWE) object.
     */
    enum class State {
        /**
         * The JWE object is created but not encrypted yet.
         */
        UNENCRYPTED,

        /**
         * The JWE object is encrypted.
         */
        ENCRYPTED,

        /**
         * The JWE object is decrypted.
         */
        DECRYPTED
    }

    /**
     * The header.
     */
    private var header: JWEHeader? = null
    /**
     * Returns the recipients of this JWE object.
     *
     * @return The recipients, `null` if not
     * applicable or the JWE object has not been encrypted yet.
     */
    /**
     * The recipients, `null` if not computed or applicable.
     */
    var recipients: List<JWERecipient>? = null
        private set
    /**
     * Returns the initialisation vector (IV) of this JWE object.
     *
     * @return The initialisation vector (IV), `null` if not
     * applicable or the JWE object has not been encrypted yet.
     */
    /**
     * The initialisation vector, `null` if not generated or
     * applicable.
     */
    var iV: Base64URL? = null
        private set
    /**
     * Returns the cipher text of this JWE object.
     *
     * @return The cipher text, `null` if the JWE object has not been
     * encrypted yet.
     */
    /**
     * The cipher text, `null` if not computed.
     */
    var cipherText: Base64URL?
        private set
    /**
     * Returns the authentication tag of this JWE object.
     *
     * @return The authentication tag, `null` if not applicable or
     * the JWE object has not been encrypted yet.
     */
    /**
     * The authentication tag, `null` if not computed or applicable.
     */
    var authTag: Base64URL? = null
        private set
    /**
     * Returns the state of this JWE object.
     *
     * @return The state.
     */
    /**
     * The JWE object state.
     */
    var state: State
        private set

    /**
     * Creates a new to-be-encrypted JSON Web Encryption (JWE) object with
     * the specified header and payload. The initial state will be
     * [unencrypted][JWEObjectJSON.State.UNENCRYPTED].
     *
     * @param header  The JWE header. Must not be `null`.
     * @param payload The payload. Must not be `null`.
     */
    constructor(header: JWEHeader?, payload: Payload?) {
        this.header = header
        if (payload == null) {
            throw IllegalArgumentException("The payload must not be null")
        }
        setPayload(payload)
        recipients = null
        cipherText = null
        state = State.UNENCRYPTED
    }

    /**
     * Creates a new encrypted JSON Web Encryption (JWE) object with the
     * specified serialised parts. The state will be [ encrypted][JWEObject.State.ENCRYPTED].
     *
     * @param header     The JWE Protected header. Must not be `null`.
     * @param recipients The recipients array. Empty or `null` if none.
     * @param iv         The initialisation vector. Empty or `null` if none.
     * @param ciphertext The cipher text. Must not be `null`.
     * @param tag        The authentication tag. Empty of `null` if none.
     *
     * @throws ParseException If parsing of the serialised parts failed.
     */
    constructor(
        header: Base64URL?,
        recipients: List<JWERecipient>?,
        iv: Base64URL?,
        ciphertext: Base64URL?,
        tag: Base64URL?
    ) {
        if (header == null) {
            throw IllegalArgumentException("The header must not be null")
        }
        try {
            this.header = JWEHeader.parse(header)
        } catch (e: ParseException) {
            throw ParseException("Invalid JWE header: " + e.message, 0)
        }
        if (recipients == null || recipients.isEmpty()) {
            this.recipients = null
        } else {
            this.recipients = recipients
        }
        if (iv == null || iv.toString().isEmpty()) {
            iV = null
        } else {
            iV = iv
        }
        if (ciphertext == null) {
            throw IllegalArgumentException("The ciphertext must not be null")
        }
        cipherText = ciphertext
        if (tag == null || tag.toString().isEmpty()) {
            authTag = null
        } else {
            authTag = tag
        }
        state = State.ENCRYPTED // but not decrypted yet!
    }

    override fun getHeader(): JWEHeader {
        return header!!
    }

    /**
     * Ensures the current state is [unencrypted][JWEObjectJSON.State.UNENCRYPTED].
     *
     * @throws IllegalStateException If the current state is not
     * unencrypted.
     */
    private fun ensureUnencryptedState() {
        if (state != State.UNENCRYPTED) {
            throw IllegalStateException("The JWE object must be in an unencrypted state")
        }
    }

    /**
     * Ensures the current state is [encrypted][JWEObjectJSON.State.ENCRYPTED].
     *
     * @throws IllegalStateException If the current state is not encrypted.
     */
    private fun ensureEncryptedState() {
        if (state != State.ENCRYPTED) {
            throw IllegalStateException("The JWE object must be in an encrypted state")
        }
    }

    /**
     * Ensures the current state is [encrypted][JWEObjectJSON.State.ENCRYPTED] or
     * [decrypted][JWEObjectJSON.State.DECRYPTED].
     *
     * @throws IllegalStateException If the current state is not encrypted
     * or decrypted.
     */
    private fun ensureEncryptedOrDecryptedState() {
        if (state != State.ENCRYPTED && state != State.DECRYPTED) {
            throw IllegalStateException("The JWE object must be in an encrypted or decrypted state")
        }
    }

    /**
     * Ensures the specified JWE encrypter supports the algorithms of this
     * JWE object.
     *
     * @throws JOSEException If the JWE algorithms are not supported.
     */
    @Throws(JOSEException::class)
    private fun ensureJWEEncrypterSupport(encrypter: JWEEncrypterMulti) {
        if (!encrypter.supportedJWEAlgorithms().contains(getHeader().algorithm)) {
            throw JOSEException(
                "The " + getHeader().algorithm +
                        " algorithm is not supported by the JWE encrypter: Supported algorithms: " + encrypter.supportedJWEAlgorithms()
            )
        }
        if (!encrypter.supportedEncryptionMethods().contains(getHeader().encryptionMethod)) {
            throw JOSEException(
                ("The " + getHeader().encryptionMethod +
                        " encryption method or key size is not supported by the JWE encrypter: Supported methods: " + encrypter.supportedEncryptionMethods())
            )
        }
    }

    /**
     * Encrypts this JWE object with the specified encrypter. The JWE
     * object must be in an [unencrypted][JWEObjectJSON.State.UNENCRYPTED] state.
     *
     * @param encrypter The JWE encrypter. Must not be `null`.
     *
     * @throws IllegalStateException If the JWE object is not in an
     * [unencrypted][JWEObjectJSON.State.UNENCRYPTED].
     * @throws JOSEException         If the JWE object couldn't be
     * encrypted.
     */
    @Synchronized
    @Throws(JOSEException::class)
    fun encrypt(encrypter: JWEEncrypterMulti) {
        ensureUnencryptedState()
        ensureJWEEncrypterSupport(encrypter)
        val parts: JWECryptoParts
        try {
            parts = encrypter.encrypt(getHeader(), payload.toBytes())
        } catch (e: JOSEException) {
            throw e
        } catch (e: Exception) {

            // Prevent throwing unchecked exceptions at this point,
            // see issue #20
            throw JOSEException(e.message, e)
        }

        // Check if the header has been modified
        if (parts.header != null) {
            header = parts.header
        }
        recipients = parts.recipients
        iV = parts.initializationVector
        cipherText = parts.cipherText
        authTag = parts.authenticationTag
        state = State.ENCRYPTED
    }

    /**
     * Decrypts this JWE object with the specified decrypter. The JWE
     * object must be in a [encrypted][JWEObjectJSON.State.ENCRYPTED] state.
     *
     * @param decrypter The JWE decrypter. Must not be `null`.
     *
     * @throws IllegalStateException If the JWE object is not in an
     * [encrypted][JWEObjectJSON.State.ENCRYPTED].
     * @throws JOSEException         If the JWE object couldn't be
     * decrypted.
     */
    @Synchronized
    @Throws(JOSEException::class)
    fun decrypt(decrypter: JWEDecrypterMulti) {
        ensureEncryptedState()
        try {
            payload = Payload(
                decrypter.decrypt(
                    getHeader(),
                    recipients,
                    iV,
                    cipherText!!,
                    authTag
                )
            )
        } catch (e: JOSEException) {
            throw e
        } catch (e: Exception) {

            // Prevent throwing unchecked exceptions at this point,
            // see issue #20
            throw JOSEException(e.message, e)
        }
        state = State.DECRYPTED
    }

    /**
     * Serialises this JWE object to General JSON format.
     *
     * @return The serialised JWE object.
     *
     * @throws IllegalStateException If the JWS object is not in a
     * [signed][JWSObject.State.SIGNED] or
     * [verified][JWSObject.State.VERIFIED] state.
     */
    override fun serialize(): String {
        ensureEncryptedOrDecryptedState()
        return JSONObjectUtils.toJSONString(toGeneralJSONObject())
    }

    override fun toGeneralJSONObject(): Map<String, Any> {
        ensureEncryptedOrDecryptedState()
        val recipients = JSONArrayUtils.newJSONArray()
        for (recipient: JWERecipient in this.recipients!!) {
            recipients.add(recipient.toJSONObject())
        }
        val json = JSONObjectUtils.newJSONObject()
        json["iv"] = iV.toString()
        json["recipients"] = recipients
        json["tag"] = authTag.toString()
        json["protected"] = getHeader().toBase64URL().toString()
        json["ciphertext"] = cipherText.toString()
        return json
    }

    override fun toFlattenedJSONObject(): Map<String, Any> {
        throw Exception("Flattened JSON serialization is not implemented")
    }

    companion object {
        private val serialVersionUID = 1L

        /**
         * Parses a JWE object from the specified string in json form. The
         * parsed JWE object will be given an [JWEObjectJSON.State.ENCRYPTED] state.
         *
         * NOTE: Supports only General Serialization Syntax
         *
         * @param s The string to parse. Must not be `null`.
         *
         * @return The JWE object.
         *
         * @throws ParseException If the string couldn't be parsed to a valid
         * JWE object.
         */
        @Throws(ParseException::class)
        fun parse(s: String): JWEObjectJSON {
            val json = JSONObjectUtils.parse(s)
            return parse(json)
        }

        /**
         * Parses a JWE object from the map. The
         * parsed JWE object will be given
         * an [JWEObjectJSON.State.ENCRYPTED] state.
         *
         * NOTE: Supports only General Serialization Syntax
         *
         * @param jsonObject The json map. Must not be `null`.
         *
         * @return The JWE object.
         *
         * @throws ParseException If the string couldn't be parsed to a valid
         * JWE object.
         */
        @Throws(ParseException::class)
        fun parse(jsonObject: Map<String, Any>): JWEObjectJSON {
            return JWEObjectJSON(
                JSONObjectUtils.getBase64URL(jsonObject, "protected"),
                JWERecipient.parse(JSONObjectUtils.getJSONObjectArray(jsonObject, "recipients")),
                JSONObjectUtils.getBase64URL(jsonObject, "iv"),
                JSONObjectUtils.getBase64URL(jsonObject, "ciphertext"),
                JSONObjectUtils.getBase64URL(jsonObject, "tag")
            )
        }
    }
}