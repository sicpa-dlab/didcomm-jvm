package org.dif.utils

fun isDIDFragment(str: String) = str.contains("#")

fun divideDIDFragment(str: String) = str.split("#")
