package org.dif.crypto

import com.nimbusds.jose.JWEObjectJSON
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.common.Typ
import org.dif.exceptions.DIDCommException
import org.dif.exceptions.ParseException
import org.dif.message.Message

fun parse(str: String): ParseResult = try {
    val json = JSONObjectUtils.parse(str)

    when {
        json.containsKey("signatures") -> ParseResult(Typ.Signed, JWSObjectJSON.parse(json))
        json.containsKey("recipients") -> ParseResult(Typ.Encrypted, JWEObjectJSON.parse(json))
        else -> ParseResult(Typ.Plaintext, Message.parse(json))
    }
} catch (t: Throwable) { throw ParseException("An error occurred while parsing the message", t) }

class ParseResult {
    private var _jwm: Message? = null
    private var _jws: JWSObjectJSON? = null
    private var _jwe: JWEObjectJSON? = null

    var typ: Typ
        private set

    val jwm: Message
        get() = _jwm ?: throw DIDCommException("JWM should be specified")

    val jws: JWSObjectJSON
        get() = _jws ?: throw DIDCommException("JWS should be specified")

    val jwe: JWEObjectJSON
        get() = _jwe ?: throw DIDCommException("JWE should be specified")

    constructor(typ: Typ, message: Message) {
        this._jwm = message
        this.typ = typ
    }

    constructor(typ: Typ, _jws: JWSObjectJSON) {
        this._jws = _jws
        this.typ = typ
    }

    constructor(typ: Typ, _jwe: JWEObjectJSON) {
        this._jwe = _jwe
        this.typ = typ
    }
}
