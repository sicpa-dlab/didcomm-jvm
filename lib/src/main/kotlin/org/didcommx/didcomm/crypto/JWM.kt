package org.didcommx.didcomm.crypto

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSObjectJSON
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.jose.JWEObjectJSON
import org.didcommx.didcomm.message.Message
import java.text.ParseException

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
            throw MalformedMessageException("Message cannot be parsed", e)
        }
    }

    class JWE(rawMessage: Map<String, Any>) : ParseResult() {
        val message: JWEObjectJSON = try {
            JWEObjectJSON.parse(rawMessage)
        } catch (e: IllegalArgumentException) {
            throw MalformedMessageException(e.localizedMessage, e)
        } catch (e: ParseException) {
            throw MalformedMessageException(e.localizedMessage, e)
        }
    }
}
