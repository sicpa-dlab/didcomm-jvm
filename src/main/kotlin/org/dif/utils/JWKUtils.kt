package org.dif.utils

import com.nimbusds.jose.jwk.JWK
import java.lang.IllegalArgumentException

inline fun <reified Key> JWK.asKey(): Key {
    if (this !is Key) throw IllegalArgumentException("Can not cast JWK to ${Key::class.java.name}")
    return this
}
