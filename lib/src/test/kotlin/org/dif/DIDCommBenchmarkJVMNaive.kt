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
        val benchRes: BenchRes = BenchCommon.measure_naive(aFun, N, aFunName)
        // logger.info(benchRes.toStr())
        println(benchRes.toStr())
    }

    @Test
    fun bench_pack_signed() {
        // TODO resolve fun name dynamically
        measure(
            BenchCommon::pack_signed,
            aFunName = "pack_signed"
        )
        /*
        var i = Integer(1000)
        benchmarkRule.measureRepeated {
            if (i < 100) {
                i = Integer(i.toInt() + 1)
            } else {
                i = Integer(0)
            }
        }
        */

        /*
        benchmarkRule.measureRepeated {
            //BenchCommon.pack_signed()
        }
        */
    }

    @Test
    fun bench_pack_encrypted_authcrypt_3_keys() {
        measure(
            BenchCommon::pack_encrypted_authcrypt_3_keys,
            aFunName = "pack_encrypted_authcrypt_3_keys"
        )
    }

    @Test
    fun bench_pack_encrypted_anoncrypt_3_keys() {
        measure(
            BenchCommon::pack_encrypted_anoncrypt_3_keys,
            aFunName = "pack_encrypted_anoncrypt_3_keys"
        )
    }

    @Test
    fun bench_pack_encrypted_authcrypt_3_keys_signed() {
        measure(
            BenchCommon::pack_encrypted_authcrypt_3_keys_signed,
            aFunName = "pack_encrypted_authcrypt_3_keys_signed"
        )
    }

    @Test
    fun bench_pack_encrypted_anoncrypt_3_keys_signed() {
        measure(
            BenchCommon::pack_encrypted_anoncrypt_3_keys_signed,
            aFunName = "pack_encrypted_anoncrypt_3_keys_signed"
        )
    }

    @Test
    fun bench_unpack_signed() {
        measure(
            BenchCommon::unpack_signed,
            aFunName = "unpack_signed"
        )
    }

    @Test
    fun bench_unpack_authcrypt_3_keys() {
        measure(
            BenchCommon::unpack_authcrypt_3_keys,
            aFunName = "unpack_authcrypt_3_keys"
        )
    }

    @Test
    fun bench_unpack_anoncrypt_3_keys() {
        measure(
            BenchCommon::unpack_anoncrypt_3_keys,
            aFunName = "unpack_anoncrypt_3_keys"
        )
    }

    @Test
    fun bench_unpack_authcrypt_3_keys_signed() {
        measure(
            BenchCommon::unpack_authcrypt_3_keys_signed,
            aFunName = "unpack_authcrypt_3_keys_signed"
        )
    }

    @Test
    fun bench_unpack_anoncrypt_3_keys_signed() {
        measure(
            BenchCommon::unpack_anoncrypt_3_keys_signed,
            aFunName = "unpack_anoncrypt_3_keys_signed"
        )
    }
}
