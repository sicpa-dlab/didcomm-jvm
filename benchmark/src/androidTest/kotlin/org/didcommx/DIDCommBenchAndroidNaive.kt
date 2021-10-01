package org.didcommx.didcomm.benchmark

import android.util.Log
import org.junit.jupiter.api.Disabled;
import kotlin.test.Test

import org.didcommx.didcomm.fixtures.BenchCommon
import org.didcommx.didcomm.fixtures.BenchRes


// TODO looks like that doesn't work in android
@Disabled("Benchmark disabled for CI")
class DIDCommBenchmarkAndroidNaive {

    companion object {
       private const val log_tag = "BenchLog"
    }

    //@get:Rule
    //val benchmarkRule = BenchmarkRule()

    fun measure(aFun: () -> Unit, N : Int = 1000, aFunName : String = "noname") {
        val benchRes : BenchRes = BenchCommon.measureNaive(aFun, N, aFunName)
        Log.i(log_tag, benchRes.toStr())
    }

    @Test
    fun bench_pack_signed() {
        // TODO resolve fun name dynamically
        measure(
            BenchCommon::packSigned,
            aFunName = "packSigned"
        )

        /*
        benchmarkRule.measureRepeated {
            //BenchCommon.packSigned()
        }
        */
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
