package org.didcommx.didcomm.utils

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class DIDUtilsTest {

    @Test
    fun calculateApv() {
        assertEquals(
            "_Xzta7iZsfJXb_-2CaL6LCzZJOKmfYzPnGZ5-52RtK0",
            calculateAPV(
                listOf("key1", "key2")
            ).toString()
        )
    }

    @Test
    fun calculateApvOrderIndependent() {
        assertEquals(
            calculateAPV(listOf("key1", "key2")),
            calculateAPV(listOf("key2", "key1"))
        )
    }
}
