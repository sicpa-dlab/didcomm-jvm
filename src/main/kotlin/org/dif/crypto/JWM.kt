package org.dif.crypto

import com.nimbusds.jose.JWEObjectJSON
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.exceptions.ParseException
import org.dif.message.Message

fun parse(str: String): ParseResult = try {
    val json = JSONObjectUtils.parse(str)

    when {
        json.containsKey("signatures") -> ParseResult.JWS(JWSObjectJSON.parse(json))
        json.containsKey("recipients") -> ParseResult.JWE(JWEObjectJSON.parse(json))
        else -> ParseResult.JWM(Message.parse(json))
    }
} catch (t: Throwable) { throw ParseException("An error occurred while parsing the message", t) }

sealed class ParseResult {
    class JWM(val message: Message) : ParseResult()
    class JWS(val message: JWSObjectJSON) : ParseResult()
    class JWE(val message: JWEObjectJSON) : ParseResult()
}
