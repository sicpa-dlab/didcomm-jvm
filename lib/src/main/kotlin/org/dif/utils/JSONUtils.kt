package org.dif.utils

import com.nimbusds.jose.shaded.json.JSONArray
import com.nimbusds.jose.util.JSONObjectUtils
import org.dif.exceptions.MalformedMessageException

inline fun <reified T> Map<String, Any?>.getTypedArray(key: String): Array<T?>? = this[key]?.let {
    if (it !is JSONArray) throw MalformedMessageException("The expected type of header '$key' is 'JSONArray'. Got '${it::class.simpleName}'")
    else it.getTyped(key)
}

inline fun <reified T> Map<String, Any?>.getTyped(key: String): T? = this[key]?.let {
    if (it !is T) throw MalformedMessageException("The expected type of header '$key' is '${T::class.simpleName}'. Got '${it::class.simpleName}'")
    else it
}

inline fun <reified T> JSONArray.getTyped(key: String): Array<T?> = this.map {
    when (it) {
        null -> null
        !is T -> throw MalformedMessageException("The expected type of header '$key' is '${T::class.simpleName}'. Got '${it::class.simpleName}'")
        else -> it
    }
}.toTypedArray()

fun Map<String, Any?>.toJSONString(): String = JSONObjectUtils.toJSONString(this)
