package org.dif

import org.dif.fixtures.BenchCommon
import org.dif.fixtures.BenchRes
import org.junit.jupiter.api.Disabled
import java.util.logging.Logger
import kotlin.test.Test

@Disabled("Benchmark disabled for CI")
class DIDCommBenchmarkJVMNaive {

    companion object {
        val logger = Logger.getLogger("DIDCommBenchmarkJVMNaive")
    }

    fun measure(aFun: () -> Unit, N: Int = 1000, aFunName: String = "noname") {
        val benchRes: BenchRes = BenchCommon.measureNaive(aFun, N, aFunName)
        // logger.info(benchRes.toStr())
        println(benchRes.toStr())
    }

    @Test
    fun bench_pack_signed() {
        // TODO resolve fun name dynamically
        measure(
            BenchCommon::packSigned,
            aFunName = "packSigned"
        )
    }

    @Test
    fun bench_pack_encrypted_authcrypt_3_keys() {
        measure(
            BenchCommon::packEncryptedAuthcrypt3Keys,
            aFunName = "packEncryptedAuthcrypt3Keys"
        )
    }

    @Test
    fun bench_pack_encrypted_anoncrypt_3_keys() {
        measure(
            BenchCommon::packEncryptedAnoncrypt3Keys,
            aFunName = "packEncryptedAnoncrypt3Keys"
        )
    }

    @Test
    fun bench_pack_encrypted_authcrypt_3_keys_signed() {
        measure(
            BenchCommon::packEncryptedAuthcrypt3KeysSigned,
            aFunName = "packEncryptedAuthcrypt3KeysSigned"
        )
    }

    @Test
    fun bench_pack_encrypted_anoncrypt_3_keys_signed() {
        measure(
            BenchCommon::packEncryptedAnoncrypt3KeysSigned,
            aFunName = "packEncryptedAnoncrypt3KeysSigned"
        )
    }

    @Test
    fun bench_unpack_signed() {
        measure(
            BenchCommon::unpackSigned,
            aFunName = "unpackSigned"
        )
    }

    @Test
    fun bench_unpack_authcrypt_3_keys() {
        measure(
            BenchCommon::unpackAuthcrypt3Keys,
            aFunName = "unpackAuthcrypt3Keys"
        )
    }

    @Test
    fun bench_unpack_anoncrypt_3_keys() {
        measure(
            BenchCommon::unpackAnoncrypt3Keys,
            aFunName = "unpackAnoncrypt3Keys"
        )
    }

    @Test
    fun bench_unpack_authcrypt_3_keys_signed() {
        measure(
            BenchCommon::unpackAuthcrypt3KeysSigned,
            aFunName = "unpackAuthcrypt3KeysSigned"
        )
    }

    @Test
    fun bench_unpack_anoncrypt_3_keys_signed() {
        measure(
            BenchCommon::unpackAnoncrypt3KeysSigned,
            aFunName = "unpackAnoncrypt3KeysSigned"
        )
    }
}
