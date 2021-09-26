package org.dif.crypto

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEObjectJSON
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.exceptions.DIDCommException
import org.dif.exceptions.MalformedMessageException
import org.dif.message.Message
import java.lang.Exception
import java.lang.IllegalArgumentException
import java.text.ParseException

fun parse(str: String): ParseResult = try {
    parse(JSONObjectUtils.parse(str))
} catch (e: ParseException) {
    throw DIDCommException("Message cannot be parsed", e)
}

fun parse(json: Map<String, Any>): ParseResult = when {
    json.containsKey("signatures") -> ParseResult.JWS(json)
    json.containsKey("recipients") -> ParseResult.JWE(json)
    else -> ParseResult.JWM(Message.parse(json))
}

sealed class ParseResult {
    class JWM(val message: Message) : ParseResult()

    class JWS(val rawMessage: Map<String, Any>) : ParseResult() {
        val message: JWSObjectJSON = try {
            JWSObjectJSON.parse(rawMessage)
        } catch (e: JOSEException) {
            throw DIDCommException("Message cannot be parsed", e)
        }
    }

    class JWE(rawMessage: Map<String, Any>) : ParseResult() {
        val message: JWEObjectJSON = try {
            JWEObjectJSON.parse(rawMessage)
        } catch (e: Exception) {
            when (e) {
                is IllegalArgumentException, is ParseException -> {
                    throw MalformedMessageException(e.localizedMessage, e)
                }
                else -> throw e
            }
        }
    }
}
