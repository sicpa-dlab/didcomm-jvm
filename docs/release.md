## Release

Assumptions:

*   `main` branch can wait until release PR is merged

The steps:

1.  **release**:
    1.  **review and adjust (if needed) the release version in `main`** to match the changes from the latest release following the [SemVer rules](https://semver.org/#summary)
    2.  [create](https://github.com/sicpa-dlab/didcomm-jvm/compare/stable...main) a **PR from `main` to `stable`** (you may likely want to name it as `release-<version>`)
    3.  once merged [release pipeline](https://github.com/sicpa-dlab/didcomm-jvm/actions/workflows/release.yml) will publish the release to [Maven Central](https://s01.oss.sonatype.org/content/repositories/releases/org/didcommx/didcomm/)
2.  **bump next release version in `main`**:
    *   **Note** decision about the next release version should be based on the same [SemVer](https://semver.org/) rules and the expected changes. Usually it would be either a MINOR or MAJOR (if incompatible changes are planned) release.

## Specific cases

### Manual Maven releases

If by some reason you need to publish releases to Sonatype manually you need:

*   define the environment variables:
    *   `ORG_GRADLE_PROJECT_mavenOSSRHUsername` and `ORG_GRADLE_PROJECT_mavenOSSRHPassword`: [Sonatype Nexus](https://s01.oss.sonatype.org) username and token generated pair
    *   `ORG_GRADLE_PROJECT_signingKey`: ascii armored private part of a GPG key used for signing (please refer [Sonatype docs](https://central.sonatype.org/publish/requirements/gpg/) for the details)
    *   `ORG_GRADLE_PROJECT_signingPassword`: passphrase for the key above
*   release commands:
    *   fully automated release:

        ```bash
        $ ./gradlew publishToSonatype closeAndReleaseSonatypeStagingRepository
        ```
    *   two-step release:

        *   publish to Nexus

        ```bash
         $ ./gradlew publishToSonatype
        ```

        *   go to [Nexus staging  repositories](https://oss.sonatype.org/#stagingRepositories) and do `Close` and `Release` as described in [Sonatype docs](https://help.sonatype.com/repomanager2/staging-releases/managing-staging-repositories)
