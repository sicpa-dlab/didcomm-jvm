package org.didcommx.didcomm.fixtures

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import kotlin.system.measureTimeMillis

class BenchRes(
    val operations: Int,
    val timeInMs: Long,
    val opName: String = "noname",
) {
    val avrg = timeInMs.toFloat() / operations
    val thrpt = 1 / avrg

    fun toStr(): String {
        return String.format(
            "benchmark of %-45s took %7s ms, %7s ops, %10s ops/ms, %7s mss/op",
            "'${this.opName}'", this.timeInMs, operations, this.thrpt, this.avrg
        )
    }
}

class BenchCommon {
    companion object {
        val didCommDef: DIDComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packSignedRes = didCommDef.packSigned(
            PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.ALICE_DID).build()
        )

        val authPackRes = didCommDef.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        val anonPackRes = didCommDef.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .build()
        )

        val authPackSignedRes = didCommDef.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .from(JWM.ALICE_DID)
                .signFrom(JWM.ALICE_DID)
                .build()
        )

        val anonPackSignedRes = didCommDef.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .signFrom(JWM.ALICE_DID)
                .build()
        )

        fun measureNaive(
            aFun: () -> Unit,
            N: Int = 1000,
            aFunName: String = "noname"
        ): BenchRes {
            val timeInMs = measureTimeMillis {
                for (i in 1..N) {
                    aFun()
                }
            }
            return BenchRes(N, timeInMs, aFunName)
        }

        fun packSigned(didComm: DIDComm = didCommDef) {
            didComm.packSigned(
                PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.ALICE_DID).build()
            )
        }

        fun packEncryptedAuthcrypt3Keys(didComm: DIDComm = didCommDef) {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }

        fun packEncryptedAnoncrypt3Keys(didComm: DIDComm = didCommDef) {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }

        fun packEncryptedAuthcrypt3KeysSigned(didComm: DIDComm = didCommDef) {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(JWM.ALICE_DID)
                    .build()
            )
        }

        fun packEncryptedAnoncrypt3KeysSigned(didComm: DIDComm = didCommDef) {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(JWM.ALICE_DID)
                    .build()
            )
        }

        fun unpackSigned(didComm: DIDComm = didCommDef) {
            didComm.unpack(
                UnpackParams.Builder(packSignedRes.packedMessage).build()
            )
        }

        fun unpackAuthcrypt3Keys(didComm: DIDComm = didCommDef) {
            didComm.unpack(
                UnpackParams.Builder(authPackRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }

        fun unpackAnoncrypt3Keys(didComm: DIDComm = didCommDef) {
            didComm.unpack(
                UnpackParams.Builder(anonPackRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }

        fun unpackAuthcrypt3KeysSigned(didComm: DIDComm = didCommDef) {
            didComm.unpack(
                UnpackParams.Builder(authPackSignedRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }

        fun unpackAnoncrypt3KeysSigned(didComm: DIDComm = didCommDef) {
            didComm.unpack(
                UnpackParams.Builder(anonPackSignedRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }
    }
}
