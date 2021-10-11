package org.didcommx.didcomm.utils

fun isJDK15Plus() =
    System.getProperty("java.version")?.let { it.startsWith("15.") } ?: false
