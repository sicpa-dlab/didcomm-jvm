package org.didcommx.didcomm.utils

import com.nimbusds.jose.util.Base64URL
import java.security.MessageDigest

fun isDIDFragment(str: String) = str.contains("#")

fun divideDIDFragment(str: String) = str.split("#")

fun isDID(str: String): Boolean {
    val parts = str.split(":")
    return parts.size >= 3 && parts[0] == "did"
}

fun isDIDUrl(str: String): Boolean {
    val strSplit = str.split("#")
    if (strSplit.size != 2) return false
    val before = strSplit[0]
    val after = strSplit[1]
    return after != "" && isDID(before)
}

fun calculateAPV(kids: List<String>): Base64URL? {
    val digest = MessageDigest.getInstance("SHA-256")
    return Base64URL.encode(digest.digest(kids.sorted().joinToString(".").encodeToByteArray()))
}
