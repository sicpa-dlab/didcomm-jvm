package org.didcommx.didcomm.utils

import com.nimbusds.jose.util.Base64URL
import java.security.MessageDigest

fun isDIDFragment(str: String) = str.contains("#")

fun divideDIDFragment(str: String) = str.split("#")

fun isDID(str: String): Boolean {
    val parts = str.split(":")
    return parts.size >= 3 && parts[0] == "did"
}

fun calculateAPV(kids: List<String>): Base64URL? {
    val digest = MessageDigest.getInstance("SHA-256")
    return Base64URL.encode(digest.digest(kids.sorted().joinToString(".").encodeToByteArray()))
}
