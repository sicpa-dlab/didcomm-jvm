package org.didcommx.didcomm.utils

import com.nimbusds.jose.util.Base64URL
import java.security.MessageDigest
import java.util.UUID

fun isDIDFragment(str: String) = str.contains("#")

fun divideDIDFragment(str: String) = str.split("#")

fun getDid(str: String) = divideDIDFragment(str)[0]

fun isDID(str: String): Boolean {
    val parts = str.split(":")
    return parts.size >= 3 && parts[0] == "did"
}

fun isDIDUrl(str: String): Boolean {
    val parts = divideDIDFragment(str)
    return (parts.size == 2) && isDID(parts[0]) && (parts[1] != "")
}

fun isDIDOrDidUrl(str: String): Boolean {
    return isDID(str) || isDIDUrl(str)
}

fun calculateAPV(kids: List<String>): Base64URL? {
    val digest = MessageDigest.getInstance("SHA-256")
    return Base64URL.encode(digest.digest(kids.sorted().joinToString(".").encodeToByteArray()))
}

fun idGeneratorDefault(): String = UUID.randomUUID().toString()

fun didcommIdGeneratorDefault(did: String? = null): String {
    var res = idGeneratorDefault()
    if (did != null)
        res = "$did:$res"
    return res
}
