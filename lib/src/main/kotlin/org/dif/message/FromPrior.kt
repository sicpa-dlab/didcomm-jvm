package org.dif.message

import org.dif.exceptions.MalformedMessageException
import org.dif.utils.getTyped
import org.dif.utils.toJSONString

data class FromPrior(
    val iss: String,
    val sub: String,
    val aud: String?,
    val exp: Long?,
    val nbf: Long?,
    val iat: Long?,
    val jti: String?,
    val issKid: String?
) {
    private constructor(builder: Builder) : this(
        builder.iss,
        builder.sub,
        builder.aud,
        builder.exp,
        builder.nbf,
        builder.iat,
        builder.jti,
        builder.issKid
    )

    companion object {
        class Header {
            companion object {
                const val Iss = "iss"
                const val Sub = "sub"
                const val Aud = "aud"
                const val Exp = "exp"
                const val Nbf = "nbf"
                const val Iat = "iat"
                const val Jti = "jti"
                const val IssKid = "iss_kid"
            }
        }

        fun builder(iss: String, sub: String) = Builder(iss, sub)

        fun parse(json: Map<String, Any>?): FromPrior? = json?.let {
            val iss = json.getTyped<String>(Header.Iss)
                ?: throw MalformedMessageException("The header \"${Header.Iss}\" is missing")

            val sub = json.getTyped<String>(Header.Sub)
                ?: throw MalformedMessageException("The header \"${Header.Sub}\" is missing")

            val builder = builder(iss, sub)

            json.keys.forEach {
                when (it) {
                    Header.Iss, Header.Sub -> {}
                    Header.Aud -> builder.aud(json.getTyped(it))
                    Header.Exp -> builder.exp(json.getTyped(it))
                    Header.Nbf -> builder.nbf(json.getTyped(it))
                    Header.Iat -> builder.iat(json.getTyped(it))
                    Header.Jti -> builder.jti(json.getTyped(it))
                    Header.IssKid -> builder.issKid(json.getTyped(it))
                    else -> throw MalformedMessageException("Unknown from_prior's header: $it")
                }
            }

            builder.build()
        }
    }

    class Builder(val iss: String, val sub: String) {
        var aud: String? = null
            private set

        var exp: Long? = null
            private set

        var nbf: Long? = null
            private set

        var iat: Long? = null
            private set

        var jti: String? = null
            private set

        var issKid: String? = null
            private set

        fun aud(aud: String?) = apply { this.aud = aud }
        fun exp(exp: Long?) = apply { this.exp = exp }
        fun nbf(nbf: Long?) = apply { this.nbf = nbf }
        fun iat(iat: Long?) = apply { this.iat = iat }
        fun jti(jti: String?) = apply { this.jti = jti }
        fun issKid(issKid: String?) = apply { this.issKid = issKid }

        fun build() = FromPrior(this)
    }

    fun toJSONObject(): Map<String, Any?> = mapOf(
        Header.Iss to iss,
        Header.Sub to sub,
        Header.Aud to aud,
        Header.Exp to exp,
        Header.Nbf to nbf,
        Header.Iat to iat,
        Header.Jti to jti,
        Header.IssKid to issKid,
    ).filterValues { it != null }

    override fun toString(): String =
        toJSONObject().toJSONString()
}
