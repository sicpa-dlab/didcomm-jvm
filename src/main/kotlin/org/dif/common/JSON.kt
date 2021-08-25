package org.dif.common

import com.nimbusds.jose.util.JSONObjectUtils

interface JSON {
    fun toJSONObject(): Any
}

class JSONObject(private val data: Map<String, Any>): JSON {
    override fun toString(): String
            = JSONObjectUtils.toJSONString(data)

    override fun toJSONObject(): Any
            = data
}

class JSONArray(val data: List<Any>): JSON {
    override fun toJSONObject(): Any {
        TODO("Not yet implemented")
    }
}