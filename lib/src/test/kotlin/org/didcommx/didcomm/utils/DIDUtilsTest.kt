package org.didcommx.didcomm.utils

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

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

    @Test
    fun isDid() {
        assertTrue(isDID("did:example:alice"))
        assertTrue(isDID("did:example:alice:alice2"))
        assertTrue(isDID("did:example:alice#key-1"))
        assertTrue(isDID("did:example:alice:alice2#key-1"))

        assertFalse(isDID("did:example"))
        assertFalse(isDID("did"))
        assertFalse(isDID("did:example#key-1"))
    }
}
