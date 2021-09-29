package org.dif.utils

fun isDIDFragment(str: String) = str.contains("#")

fun divideDIDFragment(str: String) = str.split("#")

fun isDID(str: String): Boolean {
    val parts = str.split(":")
    return parts.size == 3 && parts[0] == "did"
}
