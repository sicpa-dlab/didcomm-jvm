package org.dif.fixtures

import org.dif.DIDComm
import org.dif.mock.AliceSecretResolverMock
import org.dif.mock.BobSecretResolverMock
import org.dif.mock.DIDDocResolverMock
import org.dif.model.PackEncryptedParams
import org.dif.model.PackSignedParams
import org.dif.model.UnpackParams
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
        val didComm_def: DIDComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        val packSignedRes = didComm_def.packSigned(
            PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.ALICE_DID).build()
        )

        val authPackRes = didComm_def.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .from(JWM.ALICE_DID)
                .build()
        )

        val anonPackRes = didComm_def.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .build()
        )

        val authPackSignedRes = didComm_def.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .from(JWM.ALICE_DID)
                .signFrom(JWM.ALICE_DID)
                .build()
        )

        val anonPackSignedRes = didComm_def.packEncrypted(
            PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                .signFrom(JWM.ALICE_DID)
                .build()
        )

        fun measure_naive(
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

        fun pack_signed(didComm: DIDComm = didComm_def) {
            didComm.packSigned(
                PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, JWM.ALICE_DID).build()
            )
        }

        fun pack_encrypted_authcrypt_3_keys(didComm: DIDComm = didComm_def) {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }

        fun pack_encrypted_anoncrypt_3_keys(didComm: DIDComm = didComm_def) {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .build()
            )
        }

        fun pack_encrypted_authcrypt_3_keys_signed(didComm: DIDComm = didComm_def) {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(JWM.ALICE_DID)
                    .build()
            )
        }

        fun pack_encrypted_anoncrypt_3_keys_signed(didComm: DIDComm = didComm_def) {
            didComm.packEncrypted(
                PackEncryptedParams.Builder(JWM.PLAINTEXT_MESSAGE, JWM.BOB_DID)
                    .from(JWM.ALICE_DID)
                    .signFrom(JWM.ALICE_DID)
                    .build()
            )
        }

        fun unpack_signed(didComm: DIDComm = didComm_def) {
            didComm.unpack(
                UnpackParams.Builder(packSignedRes.packedMessage).build()
            )
        }

        fun unpack_authcrypt_3_keys(didComm: DIDComm = didComm_def) {
            didComm.unpack(
                UnpackParams.Builder(authPackRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }

        fun unpack_anoncrypt_3_keys(didComm: DIDComm = didComm_def) {
            didComm.unpack(
                UnpackParams.Builder(anonPackRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }

        fun unpack_authcrypt_3_keys_signed(didComm: DIDComm = didComm_def) {
            didComm.unpack(
                UnpackParams.Builder(authPackSignedRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }

        fun unpack_anoncrypt_3_keys_signed(didComm: DIDComm = didComm_def) {
            didComm.unpack(
                UnpackParams.Builder(anonPackSignedRes.packedMessage)
                    .secretResolver(BobSecretResolverMock())
                    .expectDecryptByAllKeys(true)
                    .build()
            )
        }
    }
}
