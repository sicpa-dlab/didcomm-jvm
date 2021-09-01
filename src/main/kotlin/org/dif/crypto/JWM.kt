package org.dif.crypto

import com.nimbusds.jose.JWEObjectJSON
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.message.Message

fun parse(str: String): ParseResult = parse(JSONObjectUtils.parse(str))

fun parse(json: Map<String, Any>): ParseResult = when {
    json.containsKey("signatures") -> ParseResult.JWS(json)
    json.containsKey("recipients") -> ParseResult.JWE(json)
    else -> ParseResult.JWM(Message.parse(json))
}

sealed class ParseResult {
    class JWM(val message: Message) : ParseResult()

    class JWS(val rawMessage: Map<String, Any>) : ParseResult() {
        val message: JWSObjectJSON = JWSObjectJSON.parse(rawMessage)
    }

    class JWE(rawMessage: Map<String, Any>) : ParseResult() {
        val message: JWEObjectJSON = JWEObjectJSON.parse(rawMessage)
    }
}
