# DIDComm JVM

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Unit Tests](https://github.com/sicpa-dlab/didcomm-jvm/workflows/verify/badge.svg)](https://github.com/sicpa-dlab/didcomm-jvm/actions/workflows/verify.yml)


Basic [DIDComm v2](https://identity.foundation/didcomm-messaging/spec) support in Java/Kotlin and Android.


## Installation
Available from Maven Central.

Gradle:
```
dependencies {
  implementation 'org.didcommx:didcomm:0.1.0'
}
```


Maven:
```
<dependency>
  <groupId>org.didcommx</groupId>
  <artifactId>didcomm</artifactId>
  <version>0.1.0</version>
</dependency>
```

## DIDComm + peerdid Demo
See https://github.com/sicpa-dlab/didcomm-demo.

## Assumptions and Limitations
- Java 8+
- In order to use the library, `SecretResolver` and `DIDDocResolver` interfaces must be implemented on the application level.
  Implementation of that interfaces is out of DIDComm library scope.
    - Verification materials in DID Docs and secrets are expected in JWK format only.
    - Key IDs (kids) used in `SecretResolver` must match the corresponding key IDs from DID Doc verification methods.
    - Key IDs (kids) in DID Doc verification methods and secrets must be a full [DID Fragment](https://www.w3.org/TR/did-core/#fragment), that is `did#key-id`.
    - Verification methods referencing another DID Document are not supported (see [Referring to Verification Methods](https://www.w3.org/TR/did-core/#referring-to-verification-methods)).
- The following curves and algorithms are supported:
    - Encryption:
        - Curves: X25519, P-384, P-256, P-521
        - Content encryption algorithms:
            - XC20P (to be used with ECDH-ES only, default for anoncrypt),
            - A256GCM (to be used with ECDH-ES only),
            - A256CBC-HS512 (default for authcrypt)
        - Key wrapping algorithms: ECDH-ES+A256KW, ECDH-1PU+A256KW
    - Signing:
        - Curves: Ed25519, Secp256k1 (JDK < 15), P-256
        - Algorithms: EdDSA (with crv=Ed25519), ES256, ES256K
- DID rotation (`fromPrior` field) is supported.
- Limitations and known issues:
  - Forward protocol is not implemented 
  - Secp256k1 is supported on JDK < 15 only
- DIDComm has been implemented under the following [Assumptions](https://hackmd.io/i3gLqgHQR2ihVFV5euyhqg)


## Examples

See [demo scripts](lib/src/test/kotlin/org/didcommx/didcomm/DIDCommDemoTest.kt) for details.

A general usage of the API is the following:
- Sender Side:
    - Build a `Message` (plaintext, payload).
    - Convert a message to a DIDComm Message for further transporting by calling one of the following:
        - `packEncrypted` to build an Encrypted DIDComm message
        - `packSigned` to build a Signed DIDComm message
        - `packPlaintext` to build a Plaintext DIDComm message
- Receiver side:
    - Call `unpack` on receiver side that will decrypt the message, verify signature if needed
      and return a `Message` for further processing on the application level.

### 1. Build an Encrypted DIDComm message for the given recipient

This is the most common DIDComm message to be used in most of the applications.

A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) that
- hides its content from all but authorized recipients
- (optionally) discloses and proves the sender to only those recipients
- provides message integrity guarantees

It is important in privacy-preserving routing. It is what normally moves over network transports in DIDComm
applications, and is the safest format for storing DIDComm data at rest.

See `packEncrypted` documentation for more details.

**Authentication encryption** example (most common case):
```
val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

// ALICE
val message = Message.builder(
    id = "1234567890",
    body = mapOf("messagespecificattribute" to "and its value"),
    type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
)
    .from(ALICE_DID)
    .to(listOf(BOB_DID))
    .createdTime(1516269022)
    .expiresTime(1516385931)
    .build()
val packResult = didComm.packEncrypted(
    PackEncryptedParams.builder(message, BOB_DID)
        .from(JWM.ALICE_DID)
        .build()
)
println("Sending ${packResult.packedMessage} to ${packResult.serviceMetadata?.serviceEndpoint ?: ""}")

// BOB
val unpackResult = didComm.unpack(
    UnpackParams.Builder(packResult.packedMessage).build()
)
println("Got ${unpackResult.message} message")
```

**Anonymous encryption** example:
```
val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())
val message = Message.builder(
    id = "1234567890",
    body = mapOf("messagespecificattribute" to "and its value"),
    type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
)
    .to(listOf(BOB_DID))
    .createdTime(1516269022)
    .expiresTime(1516385931)
    .build()
val packResult = didComm.packEncrypted(
    PackEncryptedParams.builder(message, BOB_DID).build()
)
)
```

**Encryption with non-repudiation** example:
```
val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())
val message = Message.builder(
    id = "1234567890",
    body = mapOf("messagespecificattribute" to "and its value"),
    type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
)
    .from(ALICE_DID)
    .to(listOf(BOB_DID))
    .createdTime(1516269022)
    .expiresTime(1516385931)
    .build()
val packResult = didComm.packEncrypted(
    PackEncryptedParams.builder(message, BOB_DID)
        .signFrom(ALICE_DID)
        .from(ALICE_DID)
        .build()
)
```

### 2. Build an unencrypted but Signed DIDComm message

Signed messages are only necessary when
- the origin of plaintext must be provable to third parties
- or the sender can’t be proven to the recipient by authenticated encryption because the recipient is not known in advance (e.g., in a
  broadcast scenario).

Adding a signature when one is not needed can degrade rather than enhance security because it
relinquishes the sender’s ability to speak off the record.

See `packSigned` documentation for more details.
```
val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

// ALICE
val message = Message.builder(
    id = "1234567890",
    body = mapOf("messagespecificattribute" to "and its value"),
    type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
)
    .from(ALICE_DID)
    .to(listOf(BOB_DID))
    .createdTime(1516269022)
    .expiresTime(1516385931)
    .build()
val packResult = didComm.packSigned(
    PackSignedParams.builder(message, ALICE_DID).build()
)
println("Publishing ${packResult.packedMessage}")

// BOB
val unpackResult = didComm.unpack(
    UnpackParams.Builder(packResult.packedMessage).build()
)
println("Got ${unpackResult.message} message")
```

### 3. Build a Plaintext DIDComm message

A DIDComm message in its plaintext form that
- is not packaged into any protective envelope
- lacks confidentiality and integrity guarantees
- repudiable

They are therefore not normally transported across security boundaries. 
```
val didComm = DIDComm(DIDDocResolverMock(), SecretResolverMock())

// ALICE
val message = Message.builder(
    id = "1234567890",
    body = mapOf("messagespecificattribute" to "and its value"),
    type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
)
    .from(ALICE_DID)
    .to(listOf(BOB_DID))
    .createdTime(1516269022)
    .expiresTime(1516385931)
    .build()
val packResult = didComm.packPlaintext(
    PackPlaintextParams.builder(message)
        .build()
)
println("Publishing ${packResult.packedMessage}")

// BOB
val unpackResult = didComm.unpack(
    UnpackParams.Builder(packResult.packedMessage).build()
)
println("Got ${unpackResult.message} message")
```

## Contribution
PRs are welcome!

The following CI checks are run against every PR:
- all tests must pass
- code style is analyzed using ktlint.
