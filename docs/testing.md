# didcomm-jvm Testing

## Table of Contents

*   [Performance Testing](#performance-testing)

    *   [Local (JVM) Benchmarks](#local-jvm-benchmarks)
    *   [Android Benchmarks](#android-benchmarks)

## Performance Testing

### Local (JVM) Benchmarks

Local benchmark tests can be run in two ways:

*   as usual jUnit tests that implements a naive benchmarking

    ```bash
    $./gradlew cleanTest test --tests DIDCommBenchmarkJVMNaive --info
    ```

    *   **Notes**:
        *   these tests are disabled by default in [DIDCommBenchmarkJVMNaive.kt](../lib/src/test/kotlin/org/dif/DIDCommBenchmarkJVMNaive.kt). So you will need to enable them beforehand.
        *   run from within IDE is an option as well

*   using [Java Microbenchmark Harness (JMH)](https://github.com/openjdk/jmh) and
    related [JMH Gradle plugin](https://github.com/melix/jmh-gradle-plugin)

    ```bash
    $./gradlew jmh
    ```

    *   **Notes**:

        *   you may consider to adjust benchmark settings in `jmh` section of [build.gradle](../lib/build.gradle)
            (please refer to [JMH Gradle plugin](https://github.com/melix/jmh-gradle-plugin#configuration-options)
            for the details)

### Android Benchmarks

Android benchmarks can be run as [Android instrumented tests](https://developer.android.com/training/testing/unit-testing/instrumented-unit-tests) on emulators or real devices.

For the moment only naive benchmarks are available and you may run them as described below.

Requirements:

*   Java 11 and higher

Preparation steps:

*   enable `benchmark` project in using Gradle property `androidBuilds=true`
    (e.g. in [gradle.properties](../gradle.properties) or via CLI option `-PandroidBuilds=true`)
*   enable benchmark tests in [DIDCommBenchAndroidNaive.kt](../benchmark/src/androidTest/kotlin/org/dif/DIDCommBenchAndroidNaive.kt)
*   ensure that either an emulator is [available](https://developer.android.com/studio/run/managing-avds) or real Android device is [attached](https://developer.android.com/studio/run/device)

Run:

*   using Android Studio (recommended)
*   using gradle

    ```bash
    ./gradlew -PandroidBuilds=true :benchmark:cleanConnectedAndroidTest :benchmark:connectedAndroidTest --info
    ```
