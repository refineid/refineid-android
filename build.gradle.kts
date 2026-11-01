buildscript {
    configurations.all {
        exclude(group = "org.jdom", module = "jdom2")
        resolutionStrategy {
            force(
                "org.bitbucket.b_c:jose4j:0.9.6",
                "com.google.guava:guava:33.7.2-jre",
                "org.apache.httpcomponents:httpclient:4.5.14",
                "org.apache.commons:commons-lang3:3.20.0",
                "org.bouncycastle:bcprov-jdk18on:1.85.2",
                "org.bouncycastle:bcpkix-jdk18on:1.85",
                "org.bouncycastle:bcutil-jdk18on:1.85",
            )
        }
    }
}

plugins {
    base
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.detekt)
    alias(libs.plugins.play.publisher) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.spotless)
}

allprojects {
    configurations.matching { !it.name.contains("detekt", ignoreCase = true) }.all {
        resolutionStrategy {
            force(
                "com.google.guava:guava:33.7.2-jre",
                "org.apache.httpcomponents:httpclient:4.5.14",
                "org.apache.commons:commons-lang3:3.20.0",
                "org.bouncycastle:bcprov-jdk18on:1.85.2",
                "org.bouncycastle:bcpkix-jdk18on:1.85",
                "org.bouncycastle:bcutil-jdk18on:1.85",
            )
            eachDependency {
                if (requested.group == "io.netty" && !requested.name.startsWith("netty-bom")) {
                    useVersion("4.1.138.Final")
                    because("Fix Dependabot security vulnerabilities")
                }
            }
        }
    }
}

detekt {
    buildUponDefaultConfig = true
    config.setFrom(files("config/detekt/detekt.yml"))
    basePath.set(layout.projectDirectory)
    source.setFrom(
        files(
            "build.gradle.kts",
            "settings.gradle.kts",
            "app/build.gradle.kts",
        ),
    )
}

spotless {
    kotlin {
        target("app/src/**/*.kt")
        ktlint(libs.versions.ktlint.get())
    }
    kotlinGradle {
        target("build.gradle.kts", "settings.gradle.kts", "app/build.gradle.kts")
        ktlint(libs.versions.ktlint.get())
    }
}

val rustCrateDirectory = layout.projectDirectory.dir("native/refineid-android-core")
val rappCrateDirectory = layout.projectDirectory.dir("native/refineid-rapp-android")

// A repository shell script as a command line. Windows cannot start a
// script as a process, so there it runs under the bash of Git for Windows,
// whose launcher puts the tools the scripts use (awk, cmp, sed) on the PATH;
// the hooks run in the same shell. Any bash on the PATH is the last resort.
val hostIsWindows = System.getProperty("os.name").startsWith("Windows")
val gitForWindowsBash: String =
    listOfNotNull(System.getenv("ProgramFiles"), System.getenv("ProgramW6432"), System.getenv("LOCALAPPDATA"))
        .flatMap { listOf(File(it, "Git/bin/bash.exe"), File(it, "Programs/Git/bin/bash.exe")) }
        .firstOrNull { it.isFile }
        ?.absolutePath ?: "bash"

fun shellScript(script: String): List<String> = if (hostIsWindows) listOf(gitForWindowsBash, script) else listOf(script)

// Both native crates build against the latest refineid-core main. Updating one
// core package moves the whole core git source in the crate's Cargo.lock to the
// current main commit; third-party crates keep their locked versions, so every
// later cargo invocation still runs with --locked.
fun registerCoreRefresh(
    taskName: String,
    crateDirectory: Directory,
    corePackage: String,
) = tasks.register<Exec>(taskName) {
    group = "build"
    description = "Move the refineid-core revision in a native Cargo.lock to core main."
    workingDir(crateDirectory)
    outputs.file(crateDirectory.file("Cargo.lock"))
    outputs.upToDateWhen { false }
    commandLine("cargo", "update", "--package", corePackage)
}

val refreshAndroidCoreRevision =
    registerCoreRefresh("refreshAndroidCoreRevision", rustCrateDirectory, "refineid-apdu")
registerCoreRefresh("refreshRappCoreRevision", rappCrateDirectory, "refineid-rapp")
val aospProviderContractVerifier = "Scripts/verify-aosp-provider-contract.sh"
val aospProviderContractPatch =
    "platform/aosp/android-13.0.0_r31/patches/packages-apps-KeyChain/" +
        "0005-Bind-statically-trusted-external-key-provider.patch"
val repositoryShellScripts =
    listOf(
        ".githooks/pre-commit",
        ".githooks/pre-push",
        "Scripts/agent-housekeeping.sh",
        "Scripts/apply-aosp-patches.sh",
        "Scripts/audit-aosp-patches.sh",
        "Scripts/audit-dependencies.sh",
        "Scripts/bootstrap-macos.sh",
        "Scripts/build-aosp-flame.sh",
        "Scripts/build-release-apk.sh",
        "Scripts/configure-aosp-host-compat.sh",
        "Scripts/gradle-environment.sh",
        "Scripts/install-hooks.sh",
        "Scripts/release-play-store.sh",
        "Scripts/stamp-version.sh",
        "Scripts/stage-aosp-prebuilt.sh",
        aospProviderContractVerifier,
        "Scripts/verify-aosp-flame-device.sh",
        "Scripts/verify-commit.sh",
        "Scripts/verify-push.sh",
    )

val rustFormatCheck =
    tasks.register<Exec>("rustFormatCheck") {
        group = "verification"
        description = "Check Rust formatting."
        workingDir(rustCrateDirectory)
        commandLine("cargo", "fmt", "--check")
    }

val rustTest =
    tasks.register<Exec>("rustTest") {
        group = "verification"
        description = "Run locked Rust tests."
        dependsOn(rustFormatCheck, refreshAndroidCoreRevision)
        workingDir(rustCrateDirectory)
        commandLine("cargo", "test", "--locked")
    }

val rustClippy =
    tasks.register<Exec>("rustClippy") {
        group = "verification"
        description = "Run Clippy for every Rust target with warnings denied."
        dependsOn(rustTest, refreshAndroidCoreRevision)
        workingDir(rustCrateDirectory)
        commandLine("cargo", "clippy", "--all-targets", "--locked", "--", "-D", "warnings")
    }

val shellCheck =
    tasks.register<Exec>("shellCheck") {
        group = "verification"
        description = "Run ShellCheck for repository shell scripts."
        inputs.files(repositoryShellScripts)
        commandLine("shellcheck", "--shell=bash", *repositoryShellScripts.toTypedArray())
    }

val verifyAospProviderContract =
    tasks.register<Exec>("verifyAospProviderContract") {
        group = "verification"
        description = "Verify the application and AOSP private provider wire contract."
        inputs.files(
            aospProviderContractVerifier,
            "app/src/main/aidl/com/android/keychain/external/ExternalKeyProviderIdentity.aidl",
            "app/src/main/aidl/com/android/keychain/external/ExternalKeyProviderResult.aidl",
            "app/src/main/aidl/com/android/keychain/external/IExternalKeyProviderService.aidl",
            "app/src/main/java/com/android/keychain/external/ExternalKeyProviderIdentity.java",
            "app/src/main/java/com/android/keychain/external/ExternalKeyProviderResult.java",
            aospProviderContractPatch,
        )
        commandLine(shellScript(aospProviderContractVerifier))
    }

tasks.named("check") {
    dependsOn(":app:check", rustClippy, shellCheck, verifyAospProviderContract)
}
