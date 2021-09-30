package org.dif.jmh

import org.dif.DIDComm
import org.dif.fixtures.JWM
import org.dif.mock.AliceSecretResolverMock
import org.dif.mock.DIDDocResolverMock
import org.dif.model.PackEncryptedParams
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.infra.Blackhole

@State(Scope.Benchmark)
open class DIDCommBench_packEncrypted {

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
    fun pack_encrypted_authcrypt_3_keys(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        )
    }

    @Benchmark
    fun pack_encrypted_anoncrypt_3_keys(bh: Blackhole, d: Data) {
        bh.consume(
            d.didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        )
    }

    @Benchmark
    fun pack_encrypted_authcrypt_3_keys_signed(bh: Blackhole, d: Data) {
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
    fun pack_encrypted_anoncrypt_3_keys_signed(bh: Blackhole, d: Data) {
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
