package org.dif.utils

import com.nimbusds.jose.util.Pair

operator fun <L, R> Pair<L, R>.component1(): L = left

operator fun <L, R> Pair<L, R>.component2(): R = right
