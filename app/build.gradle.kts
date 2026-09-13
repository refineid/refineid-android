import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.StringReader
import java.nio.charset.StandardCharsets
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.util.Properties
import java.util.zip.ZipFile

val rustDebugJniLibs = layout.buildDirectory.dir("rustJniLibs/debug")
val rustReleaseJniLibs = layout.buildDirectory.dir("rustJniLibs/release")
val rappDebugJniLibs = layout.buildDirectory.dir("rapp/jniLibs/debug")
val rappReleaseJniLibs = layout.buildDirectory.dir("rapp/jniLibs/release")
val rappCrateDirectory =
    rootProject.layout.projectDirectory.dir("native/refineid-rapp-android")
val rappGeneratedKotlin = rappCrateDirectory.dir("generated")
val minimumAndroidApi = 33
val currentAndroidApi = 37
val androidAbis = listOf("arm64-v8a", "x86_64")
val abiTargetArgs = androidAbis.flatMap { abi -> listOf("-t", abi) }
val javaToolchainVersion = 25
val calendarYearBase = 2000
val maximumUtcHour = 23
val buildNumberHourScale = 10
val maximumTenMinuteBucket = 5
val maximumBuildNumber =
    maximumUtcHour * buildNumberHourScale + maximumTenMinuteBucket
val versionCodeYearScale = 10_000_000
val versionCodeMonthScale = 100_000
val versionCodeDayScale = 1_000
val minimumGooglePlayVersionCode = 1
val maximumGooglePlayVersionCode = 2_100_000_000

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.detekt)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.play.publisher)
}

detekt {
    buildUponDefaultConfig = true
    config.setFrom(rootProject.files("config/detekt/detekt.yml"))
    basePath.set(rootProject.layout.projectDirectory)
}

val versionPropertiesFile = rootProject.layout.projectDirectory.file("version.properties")
val versionProperties =
    Properties().apply {
        if (versionPropertiesFile.asFile.exists()) {
            load(
                StringReader(
                    providers.fileContents(versionPropertiesFile).asText.getOrElse(""),
                ),
            )
        }
    }
val liveUtcDate = ZonedDateTime.now(ZoneOffset.UTC)
val defaultLiveVersionName =
    "${liveUtcDate.year % 100}.${liveUtcDate.monthValue}.${liveUtcDate.dayOfMonth}"
val defaultLiveBuildNumber =
    (liveUtcDate.hour * buildNumberHourScale + liveUtcDate.minute / 10).toString()

val refineIdVersionName =
    (
        providers.gradleProperty("versionName").orNull
            ?: providers.environmentVariable("VERSION_NAME").orNull
            ?: defaultLiveVersionName
    ).trim()

val calendarVersionPattern =
    Regex("""([0-9]{2})\.([1-9]|1[0-2])\.([1-9]|[12][0-9]|3[01])""")
val calendarVersionMatch =
    requireNotNull(calendarVersionPattern.matchEntire(refineIdVersionName)) {
        "versionName must use YY.M.D without zero padding (got '$refineIdVersionName')"
    }
val versionYear = calendarVersionMatch.groupValues[1].toInt()
val versionMonth = calendarVersionMatch.groupValues[2].toInt()
val versionDay = calendarVersionMatch.groupValues[3].toInt()
val calendarVersionDate =
    LocalDate.of(calendarYearBase + versionYear, versionMonth, versionDay)

val rawBuildNumber =
    providers.gradleProperty("buildNumber").orNull
        ?: providers.environmentVariable("BUILD_NUMBER").orNull
        ?: defaultLiveBuildNumber

val refineIdBuildNumber =
    rawBuildNumber.trim().toIntOrNull()
        ?: error("buildNumber must be an integer (got '$rawBuildNumber')")

require(
    refineIdBuildNumber in 0..maximumBuildNumber &&
        refineIdBuildNumber % buildNumberHourScale in 0..maximumTenMinuteBucket,
) {
    "buildNumber must be a UTC ten-minute bucket (H * 10 + M / 10) (got $refineIdBuildNumber)"
}

val refineIdVersionCode =
    versionYear * versionCodeYearScale +
        calendarVersionDate.monthValue * versionCodeMonthScale +
        calendarVersionDate.dayOfMonth * versionCodeDayScale +
        refineIdBuildNumber

require(refineIdVersionCode in minimumGooglePlayVersionCode..maximumGooglePlayVersionCode) {
    "derived versionCode is outside the Google Play range"
}

val playPropertiesFile = rootProject.layout.projectDirectory.file("play.properties")
val playProperties =
    if (playPropertiesFile.asFile.exists()) {
        Properties().apply {
            load(
                StringReader(
                    providers.fileContents(playPropertiesFile).asText.get(),
                ),
            )
        }
    } else {
        null
    }

val keystorePropertiesFile = rootProject.layout.projectDirectory.file("keystore.properties")
val keystoreProperties =
    if (keystorePropertiesFile.asFile.exists()) {
        Properties().apply {
            load(
                StringReader(
                    providers.fileContents(keystorePropertiesFile).asText.get(),
                ),
            )
        }
    } else {
        null
    }

android {
    namespace = "fi.refineid.android"
    compileSdk = currentAndroidApi
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "fi.refineid.android"
        minSdk = minimumAndroidApi
        targetSdk = currentAndroidApi
        versionCode = refineIdVersionCode
        versionName = refineIdVersionName
        buildConfigField("int", "BUILD_NUMBER", "$refineIdBuildNumber")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += androidAbis
        }
    }

    signingConfigs {
        if (keystoreProperties != null) {
            register("release") {
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        getByName("debug") {
            signingConfigs.findByName("release")?.let {
                signingConfig = it
            }
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        aidl = true
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            keepDebugSymbols += "**/libjnidispatch.so"
        }
    }

    lint {
        abortOnError = true
        checkAllWarnings = true
        checkReleaseBuilds = true
        warningsAsErrors = true
        disable +=
            setOf(
                "AndroidGradlePluginVersion",
                "GradleDependency",
                "NewerVersionAvailable",
                // JNA references desktop AWT on a code path Android never takes.
                "InvalidPackage",
                // Kotlin emits synthetic accessors by design; modern runtimes
                // make the check moot.
                "SyntheticAccessor",
                // The USB host requirement is deliberate; the product targets
                // physical Pixels, not ChromeOS.
                "UnsupportedChromeOsHardware",
                "ChromeOsAbiSupport",
            )
    }

    sourceSets {
        getByName("debug").jniLibs.directories.add(
            rustDebugJniLibs.get().asFile.absolutePath,
        )
        getByName("release").jniLibs.directories.add(
            rustReleaseJniLibs.get().asFile.absolutePath,
        )
        // The RAPP shared object and its generated binding. The protocol
        // itself lives in the shared Rust repository; nothing here
        // reimplements it.
        getByName("debug").jniLibs.directories.add(
            rappDebugJniLibs.get().asFile.absolutePath,
        )
        getByName("release").jniLibs.directories.add(
            rappReleaseJniLibs.get().asFile.absolutePath,
        )
        getByName("main").kotlin.directories.add(rappGeneratedKotlin.asFile.absolutePath)
    }
}

kotlin {
    jvmToolchain(javaToolchainVersion)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
        extraWarnings.set(true)
        // The generated RAPP binding cannot satisfy the stylistic extra
        // checks; ktlint and detekt cover style for authored sources.
        freeCompilerArgs.addAll(
            "-Xwarning-level=REDUNDANT_RETURN_UNIT_TYPE:disabled",
            "-Xwarning-level=REDUNDANT_VISIBILITY_MODIFIER:disabled",
            "-Xwarning-level=CAN_BE_VAL:disabled",
            "-Xwarning-level=CAN_BE_VAL_LATEINIT:disabled",
        )
    }
}

dependencies {
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)

    testImplementation(libs.junit)
    testImplementation(libs.json)

    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.uiautomator)
    androidTestImplementation(libs.junit)

    debugImplementation(libs.androidx.compose.ui.tooling)
    implementation(variantOf(libs.jna) { artifactType("aar") })
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}

val rustCrateDirectory =
    rootProject.layout.projectDirectory.dir("native/refineid-android-core")
val androidNdkDirectory = androidComponents.sdkComponents.ndkDirectory

// --- RAPP -----------------------------------------------------------------
//
// The Remote Authorization Proxy Protocol is implemented once, in Rust, in the
// shared repository. Android consumes it exactly as Apple does: the crate is
// compiled for the device ABIs and a binding is generated from the built
// library, so a Kotlin peer and a Swift peer cannot drift apart in framing,
// transitions, or failure policy. Nothing in Kotlin decides protocol.

fun registerRappBuild(
    taskName: String,
    output: Provider<Directory>,
    release: Boolean,
) = tasks.register<Exec>(taskName) {
    group = "build"
    description = "Build the shared RAPP core for Android ABIs."
    workingDir(rappCrateDirectory)
    inputs.file(rappCrateDirectory.file("Cargo.toml"))
    inputs.file(rappCrateDirectory.file("Cargo.lock"))
    inputs.dir(rappCrateDirectory.dir("src"))
    outputs.dir(output)
    environment("ANDROID_NDK_HOME", androidNdkDirectory.get().asFile.absolutePath)
    val arguments =
        mutableListOf(
            "cargo",
            "ndk",
            *abiTargetArgs.toTypedArray(),
            "-P",
            minimumAndroidApi,
            "-o",
            output.get().asFile.absolutePath,
            "build",
            "--locked",
        )
    if (release) {
        arguments.add("--release")
    }
    commandLine(arguments)
}

val buildRappDebug = registerRappBuild("buildRappDebug", rappDebugJniLibs, false)
val buildRappRelease = registerRappBuild("buildRappRelease", rappReleaseJniLibs, true)

val buildRustDebug =
    tasks.register<Exec>("buildRustDebug") {
        group = "build"
        description = "Build the pinned RefineID Rust bridge for debug ABIs."
        workingDir(rustCrateDirectory)
        inputs.file(rustCrateDirectory.file("Cargo.toml"))
        inputs.file(rustCrateDirectory.file("Cargo.lock"))
        inputs.dir(rustCrateDirectory.dir("src"))
        outputs.dir(rustDebugJniLibs)
        environment(
            "ANDROID_NDK_HOME",
            androidNdkDirectory.get().asFile.absolutePath,
        )
        commandLine(
            "cargo",
            "ndk",
            *abiTargetArgs.toTypedArray(),
            "-P",
            minimumAndroidApi,
            "-o",
            rustDebugJniLibs.get().asFile.absolutePath,
            "build",
            "--locked",
        )
    }

val buildRustRelease =
    tasks.register<Exec>("buildRustRelease") {
        group = "build"
        description = "Build the pinned RefineID Rust bridge for release ABIs."
        workingDir(rustCrateDirectory)
        inputs.file(rustCrateDirectory.file("Cargo.toml"))
        inputs.file(rustCrateDirectory.file("Cargo.lock"))
        inputs.dir(rustCrateDirectory.dir("src"))
        outputs.dir(rustReleaseJniLibs)
        environment(
            "ANDROID_NDK_HOME",
            androidNdkDirectory.get().asFile.absolutePath,
        )
        commandLine(
            "cargo",
            "ndk",
            *abiTargetArgs.toTypedArray(),
            "-P",
            minimumAndroidApi,
            "-o",
            rustReleaseJniLibs.get().asFile.absolutePath,
            "build",
            "--release",
            "--locked",
        )
    }

tasks.configureEach {
    when (name) {
        "mergeDebugJniLibFolders" -> dependsOn(buildRustDebug, buildRappDebug)
        "mergeReleaseJniLibFolders" -> dependsOn(buildRustRelease, buildRappRelease)
    }
}

val releaseApk =
    layout.buildDirectory.file(
        if (keystoreProperties != null) {
            "outputs/apk/release/app-release.apk"
        } else {
            "outputs/apk/release/app-release-unsigned.apk"
        },
    )
val releaseMergedManifest =
    layout.buildDirectory.file(
        "intermediates/merged_manifest/release/processReleaseMainManifest/AndroidManifest.xml",
    )
val verifyReleaseNoLogging =
    tasks.register("verifyReleaseNoLogging") {
        group = "verification"
        description = "Reject release APKs that retain logging code or trace literals."
        dependsOn("assembleRelease")
        inputs.file(releaseApk)

        doLast {
            val dexHeaderMinimumSize = 0x70
            val dexStringIdsSizeOffset = 0x38
            val dexStringIdsOffsetOffset = 0x3C
            val dexTypeIdsSizeOffset = 0x40
            val dexTypeIdsOffsetOffset = 0x44
            val dexMethodIdsSizeOffset = 0x58
            val dexMethodIdsOffsetOffset = 0x5C
            val dexMethodIdSize = 8
            val dexMethodClassIndexOffset = 0
            val dexMethodNameIndexOffset = 4
            val dexLeb128PayloadBits = 7
            val dexLeb128ContinuationMask = 1 shl dexLeb128PayloadBits
            val dexUnsignedLeb128MaximumBytes =
                (Int.SIZE_BITS + dexLeb128PayloadBits - 1) / dexLeb128PayloadBits
            val dexStringTerminator: Byte = 0

            fun ByteArray.readDexLittleEndian(
                offset: Int,
                byteCount: Int,
            ): Int {
                check(offset >= 0 && offset + byteCount <= size) {
                    "DEX integer read is outside the file"
                }
                return (0 until byteCount).fold(0) { decoded, byteIndex ->
                    decoded or
                        (
                            this[offset + byteIndex].toUByte().toInt() shl
                                (byteIndex * Byte.SIZE_BITS)
                        )
                }
            }

            fun ByteArray.readDexUnsignedShort(offset: Int): Int = readDexLittleEndian(offset, Short.SIZE_BYTES)

            fun ByteArray.readDexInt(offset: Int): Int = readDexLittleEndian(offset, Int.SIZE_BYTES)

            fun ByteArray.skipDexUnsignedLeb128(offset: Int): Int {
                var cursor = offset
                repeat(dexUnsignedLeb128MaximumBytes) {
                    check(cursor in indices) {
                        "DEX ULEB128 is truncated"
                    }
                    val value = this[cursor].toUByte().toInt()
                    cursor += Byte.SIZE_BYTES
                    if (value and dexLeb128ContinuationMask == 0) {
                        return cursor
                    }
                }
                error("DEX ULEB128 exceeds its maximum encoded length")
            }

            fun ByteArray.readDexString(
                stringIdsOffset: Int,
                stringIdsSize: Int,
                index: Int,
            ): String {
                check(index in 0 until stringIdsSize) {
                    "DEX string index is outside the string table"
                }
                val dataOffset = readDexInt(stringIdsOffset + index * Int.SIZE_BYTES)
                val stringStart = skipDexUnsignedLeb128(dataOffset)
                var stringEnd = stringStart
                while (true) {
                    check(stringEnd in indices) {
                        "DEX string is unterminated"
                    }
                    if (this[stringEnd] == dexStringTerminator) {
                        break
                    }
                    stringEnd += 1
                }
                return String(
                    this,
                    stringStart,
                    stringEnd - stringStart,
                    StandardCharsets.UTF_8,
                )
            }

            fun ByteArray.forEachDexMethodReference(action: (String, () -> String) -> Unit) {
                check(
                    size >= dexHeaderMinimumSize &&
                        copyOfRange(0, 4).contentEquals("dex\n".toByteArray()),
                ) {
                    "release APK contains a malformed DEX file"
                }
                val stringIdsSize = readDexInt(dexStringIdsSizeOffset)
                val stringIdsOffset = readDexInt(dexStringIdsOffsetOffset)
                val typeIdsSize = readDexInt(dexTypeIdsSizeOffset)
                val typeIdsOffset = readDexInt(dexTypeIdsOffsetOffset)
                val methodIdsSize = readDexInt(dexMethodIdsSizeOffset)
                val methodIdsOffset = readDexInt(dexMethodIdsOffsetOffset)
                check(stringIdsSize >= 0 && typeIdsSize >= 0 && methodIdsSize >= 0) {
                    "release APK contains negative DEX table sizes"
                }

                val stringCache = arrayOfNulls<String>(stringIdsSize)

                fun getDexString(index: Int): String {
                    val cached = stringCache[index]
                    if (cached != null) {
                        return cached
                    }
                    val decoded = readDexString(stringIdsOffset, stringIdsSize, index)
                    stringCache[index] = decoded
                    return decoded
                }

                repeat(methodIdsSize) { methodIndex ->
                    val methodOffset = methodIdsOffset + methodIndex * dexMethodIdSize
                    val classIndex =
                        readDexUnsignedShort(methodOffset + dexMethodClassIndexOffset)
                    check(classIndex in 0 until typeIdsSize) {
                        "DEX method class index is outside the type table"
                    }
                    val descriptorIndex =
                        readDexInt(typeIdsOffset + classIndex * Int.SIZE_BYTES)
                    val nameIndex = readDexInt(methodOffset + dexMethodNameIndexOffset)
                    action(getDexString(descriptorIndex)) {
                        getDexString(nameIndex)
                    }
                }
            }

            val forbiddenLiterals =
                listOf(
                    "app:activity",
                    "native:",
                    "usb:",
                    "nfc:",
                    "ccid:",
                    "card:public",
                    "card:credential",
                    "authentication:",
                    "qualified-pdf:",
                    "rapp:",
                    "DiagnosticsDumpReceiver",
                    "Lfi/refineid/android/diagnostics/AppTrace;",
                    "Lfi/refineid/android/diagnostics/DiagnosticsDumpReceiver;",
                )
            val forbiddenMethods: Map<String, Set<String>?> =
                mapOf(
                    "Landroid/util/Log;" to null,
                    "Ljava/io/PrintStream;" to
                        setOf(
                            "print",
                            "println",
                            "printf",
                            "format",
                            "append",
                            "write",
                            "flush",
                        ),
                    "Ljava/util/logging/Logger;" to
                        setOf(
                            "log",
                            "logp",
                            "logrb",
                            "severe",
                            "warning",
                            "info",
                            "config",
                            "fine",
                            "finer",
                            "finest",
                            "entering",
                            "exiting",
                            "throwing",
                        ),
                    "Landroid/os/Trace;" to
                        setOf(
                            "beginSection",
                            "endSection",
                            "beginAsyncSection",
                            "endAsyncSection",
                            "setCounter",
                            "traceBegin",
                            "traceEnd",
                            "asyncTraceBegin",
                            "asyncTraceEnd",
                            "traceCounter",
                        ),
                    "Landroidx/tracing/Trace;" to null,
                    "Lkotlin/io/ConsoleKt;" to setOf("print", "println"),
                    "Lorg/slf4j/Logger;" to null,
                    "Ltimber/log/Timber;" to null,
                )
            ZipFile(inputs.files.singleFile).use { apk ->
                val dexEntries =
                    apk
                        .entries()
                        .asSequence()
                        .filter { entry ->
                            entry.name.startsWith("classes") && entry.name.endsWith(".dex")
                        }.toList()
                check(dexEntries.isNotEmpty()) {
                    "release APK contains no DEX files"
                }
                dexEntries.forEach { entry ->
                    val dexBytes =
                        apk.getInputStream(entry).use { input ->
                            input.readBytes()
                        }
                    val dexText =
                        dexBytes.toString(Charsets.ISO_8859_1)
                    forbiddenLiterals.forEach { literal ->
                        check(!dexText.contains(literal)) {
                            "release APK retains forbidden logging material: " + literal
                        }
                    }
                    dexBytes.forEachDexMethodReference { owner, method ->
                        if (owner !in forbiddenMethods) {
                            return@forEachDexMethodReference
                        }
                        val forbiddenNames = forbiddenMethods[owner]
                        val methodName = method()
                        check(forbiddenNames != null && methodName !in forbiddenNames) {
                            "release APK retains an output method: " + owner + methodName
                        }
                    }
                }
            }
        }
    }

val verifyReleaseNetworkIsolation =
    tasks.register("verifyReleaseNetworkIsolation") {
        group = "verification"
        description = "Require the release manifest to reject cleartext traffic."
        dependsOn("processReleaseMainManifest")
        inputs.file(releaseMergedManifest)

        doLast {
            val cleartextDisabledAttribute = "android:usesCleartextTraffic=\"false\""
            val manifest = inputs.files.singleFile.readText()
            check(manifest.contains(cleartextDisabledAttribute)) {
                "release manifest must explicitly disable cleartext traffic"
            }
        }
    }

val verifyReleaseAbis =
    tasks.register("verifyReleaseAbis") {
        group = "verification"
        description = "Require identical native libraries for every supported ABI."
        dependsOn("assembleRelease")
        inputs.file(releaseApk)
        // Local copy: task actions cannot capture script object
        // references under the configuration cache.
        val requiredAbis = androidAbis

        doLast {
            val nativeLibraryPrefix = "lib/"
            val sharedObjectSuffix = ".so"
            val apkEntrySegments = 3
            val abiSegmentIndex = 1
            val librarySegmentIndex = 2
            val librariesByAbi = mutableMapOf<String, MutableSet<String>>()
            ZipFile(inputs.files.singleFile).use { apk ->
                apk.entries().asSequence().forEach { entry ->
                    val isNativeLibrary =
                        entry.name.startsWith(nativeLibraryPrefix) &&
                            entry.name.endsWith(sharedObjectSuffix)
                    if (isNativeLibrary) {
                        val segments = entry.name.split("/")
                        check(segments.size == apkEntrySegments) {
                            "release APK has a malformed native library entry: " + entry.name
                        }
                        librariesByAbi.getOrPut(segments[abiSegmentIndex]) { mutableSetOf() }.add(
                            segments[librarySegmentIndex],
                        )
                    }
                }
            }
            requiredAbis.forEach { abi ->
                check(!librariesByAbi[abi].isNullOrEmpty()) {
                    "release APK is missing native libraries for $abi"
                }
            }
            val referenceLibraries = librariesByAbi.getValue(requiredAbis.first())
            librariesByAbi.forEach { (abi, libraries) ->
                check(libraries == referenceLibraries) {
                    "release APK native libraries differ between ${requiredAbis.first()} and $abi"
                }
            }
        }
    }

tasks.named("check").configure {
    dependsOn(verifyReleaseNoLogging, verifyReleaseNetworkIsolation, verifyReleaseAbis)
}

play {
    enabled.set(playProperties != null)
    if (playProperties != null) {
        serviceAccountCredentials.set(
            rootProject.file(playProperties.getProperty("serviceAccountCredentials")),
        )
    }
}
