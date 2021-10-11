package org.didcommx.didcomm.utils

fun isJDK15Plus() =
    System.getProperty("java.version")?.let {
        val major = it.split(".")[0].toInt()
        return major >= 15
    } ?: false
