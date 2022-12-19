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

import com.nimbusds.jose.UnprotectedHeader
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import net.jcip.annotations.Immutable
import java.text.ParseException

/**
 * JSON Web Encryption (JWE) recipient specific encrypted key and unprotected
 * header.
 *
 *
 * This class is immutable.
 *
 *
 * See https://datatracker.ietf.org/doc/html/rfc7516#section-7.2
 *
 * @author Alexander Martynov
 * @author Vladimir Dzhuvinov
 * @version 2021-09-30
 */

/**
 * Creates a new JWE recipient.
 *
 * @param header       The unprotected header, `null` if not
 * specified.
 * @param encryptedKey The encrypted key, `null` if not
 * specified.
 */
@Immutable
class JWERecipient(val header: UnprotectedHeader, val encryptedKey: Base64URL) {

    /**
     * Returns a JSON object representation.
     *
     * @return The JSON object, empty if no header and encrypted key are
     * specified.
     */
    fun toJSONObject(): Map<String, Any> {
        val json: MutableMap<String, Any> = HashMap()
        json["header"] = header.toJSONObject()
        json["encrypted_key"] = encryptedKey.toString()
        return json
    }

    companion object {
        /**
         * Parses a JWE recipient from the specified JSON object.
         *
         * @param jsonObject The JSON object to parse. Must not be
         * `null`.
         *
         * @return The JWE recipient object.
         *
         * @throws ParseException If parsing failed.
         */
        @Throws(ParseException::class)
        fun parse(jsonObject: Map<String?, Any?>?): JWERecipient {
            val header = UnprotectedHeader.parse(JSONObjectUtils.getJSONObject(jsonObject, "header"))
            val encryptedKey = JSONObjectUtils.getBase64URL(jsonObject, "encrypted_key")
            return JWERecipient(header, encryptedKey)
        }

        /**
         * Parses a JSON array of JWE recipient JSON objects.
         *
         * @param jsonArray The JSON array to parse. Must not be `null`.
         *
         * @return The JWE recipients.
         *
         * @throws ParseException If parsing failed.
         */
        @Throws(ParseException::class)
        fun parse(jsonArray: Array<Map<String?, Any?>?>?): List<JWERecipient> {
            val recipients: MutableList<JWERecipient> = ArrayList()
            if (jsonArray != null) {
                for (json in jsonArray) {
                    recipients.add(parse(json))
                }
            }
            return recipients
        }
    }
}