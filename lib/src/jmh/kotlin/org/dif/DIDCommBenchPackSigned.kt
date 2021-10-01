package org.didcommx.didcomm.jmh

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.fixtures.BenchCommon
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackSignedParams
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.infra.Blackhole

@State(Scope.Benchmark)
open class DIDCommBenchPackSigned {

    @State(Scope.Benchmark)
    open class Data {
        public lateinit var didComm: DIDComm

        @Setup
        fun setup() {
            didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())
        }
    }

    @Benchmark
    fun packSigned(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.packSigned(
                PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.ALICE_DID).build()
            )
        )
    }

    @Benchmark
    fun packSignedV2(bh: Blackhole/*, d: Data*/) {
        bh.consume(
            BenchCommon.packSigned()
        )
    }
}
