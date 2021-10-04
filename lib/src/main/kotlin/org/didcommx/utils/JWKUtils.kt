package org.didcommx.didcomm.utils

import com.nimbusds.jose.UnprotectedHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Pair
import java.lang.IllegalArgumentException

inline fun <reified Key> JWK.asKey(): Key {
    if (this !is Key) throw IllegalArgumentException("Can not cast JWK to ${Key::class.java.name}")
    return this
}

inline fun <reified Key> List<Pair<UnprotectedHeader, *>>.asKeys(): List<Pair<UnprotectedHeader, Key>> {
    return this.map { it.asKey() }
}

inline fun <reified Key> Pair<UnprotectedHeader, *>.asKey(): Pair<UnprotectedHeader, Key> {
    if (right !is Key) throw IllegalArgumentException("Can not cast JWK to ${Key::class.java.name}")
    return Pair.of(left, right as Key)
}
