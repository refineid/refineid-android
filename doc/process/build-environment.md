# Build environment

Status: Active

## The JDK

The JDK runs the build tools only: Gradle, the Kotlin compiler, the Android
Gradle Plugin, lint, detekt and ktlint. The app is compiled to Java 17
bytecode (`jvmTarget` in `app/build.gradle.kts`) and runs on the Android
runtime, so the JDK version does not reach the shipped app.

One file names the version: `toolchainVersion` in
`gradle/gradle-daemon-jvm.properties`. The Gradle daemon requires exactly that
version, `app/build.gradle.kts` reads it for the Kotlin toolchain, and
`Scripts/bootstrap-macos.sh` installs Homebrew's `openjdk@<version>` from it.
GitHub Actions names the same version in `.github/workflows/check.yml`.

The version is the newest JDK that Gradle supports running on, per Gradle's
compatibility matrix (<https://docs.gradle.org/current/userguide/compatibility.html>).
A release Gradle does not yet list stops the build, so the JDK is raised on
purpose, never by following whatever a package manager installs last.

## Selecting it

`Scripts/gradle-environment.sh` sets `JAVA_HOME` to the first JDK of the
required version among: the `JAVA_HOME` the shell already carries, Homebrew's
`openjdk@<version>`, Homebrew's unversioned `openjdk`, and the JDK bundled with
Android Studio, the last three at their standard macOS locations. It reads the
version from each JDK's `release` file. On Linux and Windows only `JAVA_HOME`
is consulted, so point it at a JDK of the required version; GitHub Actions
does through `setup-java`. It also puts Homebrew's keg-only rustup and
`~/.cargo/bin` on `PATH`.

Every script that sources it changes to the repository root first; the script
reads `gradle/gradle-daemon-jvm.properties` relative to it.

Every script that runs Gradle sources it: the hooks, `Scripts/gradle.sh`,
`Scripts/install-device.sh` and the release scripts. Run Gradle through
`Scripts/gradle.sh`; a bare `./gradlew` uses whatever JDK its shell exports, and
a JDK of another version makes Gradle download the required one.

With no JDK of the required version on the machine, the script says so and
Gradle provisions one from the download URLs in
`gradle/gradle-daemon-jvm.properties`. That download depends on the network
and on the hosting of the JDK archives; installing the JDK locally removes the
dependency.

## Raising the version

1. Check Gradle's compatibility matrix for the wrapper's Gradle version.
2. Regenerate the daemon file. This repository configures no toolchain
   download repositories, so supply the foojay resolver for this one run with
   an init script outside the repository:

   ```kotlin
   // foojay-init.gradle.kts
   initscript {
       repositories { gradlePluginPortal() }
       dependencies { classpath("org.gradle.toolchains:foojay-resolver:1.0.0") }
   }
   beforeSettings {
       pluginManager.apply(org.gradle.toolchains.foojay.FoojayToolchainsConventionPlugin::class.java)
   }
   ```

   ```sh
   Scripts/gradle.sh --no-configuration-cache --init-script /path/to/foojay-init.gradle.kts \
       updateDaemonJvm --jvm-version=<version>
   ```

3. Set `java-version` in `.github/workflows/check.yml` to the same version.
4. Install the JDK (`brew install openjdk@<version>`) and run
   `Scripts/gradle.sh check`.
