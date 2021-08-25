package org.dif.message

data class FromPrior(
    val iss: String,
    val sub: String,
    val aud: String?,
    val exp: Int?,
    val nbf: Int?,
    val iat: Int?,
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
        fun builder() = Builder()
    }

    class Builder {
        lateinit var iss: String
            private set

        lateinit var sub: String
            private set

        var aud: String? = null
            private set

        var exp: Int? = null
            private set

        var nbf: Int? = null
            private set

        var iat: Int? = null
            private set

        var jti: String? = null
            private set

        var issKid: String? = null
            private set

        fun iss(iss: String) = apply { this.iss = iss }
        fun sub(sub: String) = apply { this.sub = sub }
        fun aud(aud: String) = apply { this.aud = aud }
        fun exp(exp: Int) = apply { this.exp = exp }
        fun nbf(nbf: Int) = apply { this.nbf = nbf }
        fun iat(iat: Int) = apply { this.iat = iat }
        fun jti(jti: String) = apply { this.jti = jti }
        fun issKid(issKid: String) = apply { this.issKid = issKid }

        fun build() = FromPrior(this)
    }

    fun toJSONObject(): Map<String, Any?> = mapOf(
        "iss" to iss,
        "sub" to sub,
        "aud" to aud,
        "exp" to exp,
        "nbf" to nbf,
        "iat" to iat,
        "jti" to jti,
        "iss_kid" to issKid,
    )
}