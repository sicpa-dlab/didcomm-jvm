package org.didcommx.didcomm.utils

import com.zman.varint.VarInt
import java.nio.ByteBuffer

enum class Codec(val prefix: Int) {
    X25519_PUB(0xEC),
    ED25519_PUB(0xED),
    ED25519_PRIV(0x1300),
    X25519_PRIV(0x1302),
}

fun fromMulticodec(value: ByteArray): Pair<Codec, ByteArray> {
    val prefix = VarInt.readVarint(ByteBuffer.wrap(value))
    val codec = getCodec(prefix)
    val byteBuffer = ByteBuffer.allocate(2)
    VarInt.writeVarInt(prefix, byteBuffer)
    return Pair(codec, value.drop(byteBuffer.array().size).toByteArray())
}

private fun getCodec(prefix: Int) =
    Codec.values().find { it.prefix == prefix }
        ?: throw IllegalArgumentException("Multicodec prefix $prefix is not supported")
