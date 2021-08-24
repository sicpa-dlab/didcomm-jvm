package org.dif.common

import com.nimbusds.jose.util.JSONObjectUtils

interface Json {
    fun toJSONObject(): Any
}

class JsonObject(private val data: Map<String, Any>): Json {
    override fun toString(): String
            = JSONObjectUtils.toJSONString(data)

    override fun toJSONObject(): Any
            = data
}

class JsonArray(val data: List<Any>): Json {
    override fun toJSONObject(): Any {
        TODO("Not yet implemented")
    }
}