package org.dif

import org.dif.diddoc.DIDDocResolver
import org.dif.model.*
import org.dif.secret.SecretResolver

class DIDComm(val didDocResolver: DIDDocResolver, val secretResolver: SecretResolver) {
    fun packPlaintext(params: PackPlaintextParams): PackPlaintextResult {
        throw NotImplementedError()
    }

    fun packSigned(params: PackSignedParams): PackSignedResult {
        throw NotImplementedError()
    }

    fun packEncrypted(params: PackEncryptedParams): PackEncryptedResult {
        throw NotImplementedError()
    }

    fun unpack(params: UnpackParams): UnpackResult {
        throw NotImplementedError()
    }
}