package org.didcommx.didcomm.jmh

/*
import kotlin.Throws
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
*/

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackEncryptedResult
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.PackSignedResult
import org.didcommx.didcomm.model.UnpackParams
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.infra.Blackhole

@State(Scope.Benchmark)
open class DIDCommBenchUnpack {

    @State(Scope.Benchmark)
    open class Data {
        public lateinit var didComm: DIDComm
        public lateinit var packSignedRes: PackSignedResult
        public lateinit var authPackRes: PackEncryptedResult
        public lateinit var anonPackRes: PackEncryptedResult
        public lateinit var authPackSignedRes: PackEncryptedResult
        public lateinit var anonPackSignedRes: PackEncryptedResult

        @Setup
        fun setup() {
            didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

            packSignedRes = didComm.packSigned(
                PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.ALICE_DID).build()
            )

            authPackRes = didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )

            anonPackRes = didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .build()
            )

            authPackSignedRes = didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(JWM.ALICE_DID)
                    .build()
            )

            anonPackSignedRes = didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .signFrom(JWM.ALICE_DID)
                    .build()
            )
        }
    }

    @Benchmark
    fun unpackSigned(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.unpack(
                UnpackParams.Builder(d.packSignedRes.packedMessage).build()
            )
        )
    }

    @Benchmark
    fun unpackAuthcrypt3Keys(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.unpack(
                UnpackParams.Builder(d.authPackRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        )
    }

    @Benchmark
    fun unpackAnoncrypt3Keys(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.unpack(
                UnpackParams.Builder(d.anonPackRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        )
    }

    @Benchmark
    fun unpackAuthcrypt3KeysSigned(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.unpack(
                UnpackParams.Builder(d.authPackSignedRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        )
    }

    @Benchmark
    fun unpackAnoncrypt3KeysSigned(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.unpack(
                UnpackParams.Builder(d.anonPackSignedRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        )
    }

    /*
    @Throws(RunnerException::class)
    fun main(args: Array<String?>?) {
        val opt: Options = OptionsBuilder()
            .include(
                ".*" + DIDCommBenchmark_unpack::class.java.getSimpleName().toString() + ".*"
            )
            .build()
        Runner(opt).run()
    }
    */
}
