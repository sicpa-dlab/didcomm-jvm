package org.didcommx.didcomm.jmh

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackEncryptedParams
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.infra.Blackhole

@State(Scope.Benchmark)
open class DIDCommBenchPackEncrypted {

    @State(Scope.Benchmark)
    open class Data {
        // @Param(["1", "16", "256"])
        // var count = 0
        public lateinit var didComm: DIDComm

        @Setup
        fun setup() {
            didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())
        }
    }

    @Benchmark
    fun packEncryptedAuthcrypt3Keys(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        )
    }

    @Benchmark
    fun packEncryptedAnoncrypt3Keys(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        )
    }

    @Benchmark
    fun packEncryptedAuthcrypt3KeysSigned(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(JWM.ALICE_DID)
                    .build()
            )
        )
    }

    @Benchmark
    fun packEncryptedAnoncrypt3KeysSigned(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(JWM.ALICE_DID)
                    .build()
            )
        )
    }
}
