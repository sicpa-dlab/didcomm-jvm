package org.didcommx.didcomm.utils

import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.exceptions.MalformedMessageException

inline fun <reified T> Map<String, Any?>.getTypedArray(key: String): Array<T?>? = this[key]?.let {
    if (it !is List<*>) throw MalformedMessageException("The expected type of header '$key' is 'List'. Got '${it::class.simpleName}'")
    else it.getTyped(key)
}

inline fun <reified T> Map<String, Any?>.getTyped(key: String): T? = this[key]?.let {
    if (it !is T) throw MalformedMessageException("The expected type of header '$key' is '${T::class.simpleName}'. Got '${it::class.simpleName}'")
    else it
}

inline fun <reified T> List<*>.getTyped(key: String): Array<T?> = this.map {
    when (it) {
        null -> null
        !is T -> throw MalformedMessageException("The expected type of header '$key' is '${T::class.simpleName}'. Got '${it::class.simpleName}'")
        else -> it
    }
}.toTypedArray()

fun Map<String, Any?>.toJSONString(): String = JSONObjectUtils.toJSONString(this)

fun toJson(value: Any?) =
    GsonBuilder().create().toJson(value)

fun fromJsonToList(value: String): List<Map<String, Any>> =
    GsonBuilder().create().fromJson(value, object : TypeToken<List<Map<String, Any>>>() {}.type)

fun fromJsonToMap(value: String): Map<String, Any> =
    GsonBuilder().create().fromJson(value, object : TypeToken<Map<String, Any>>() {}.type)
