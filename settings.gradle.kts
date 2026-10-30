pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

val localProps = rootDir.resolve("local.properties")
if (!localProps.exists()) {
    val candidates =
        listOfNotNull(
            System.getenv("ANDROID_HOME")?.let { File(it) },
            System.getenv("ANDROID_SDK_ROOT")?.let { File(it) },
            File(System.getProperty("user.home"), "Library/Android/sdk"),
            File(System.getProperty("user.home"), "Android/Sdk"),
            System.getenv("LOCALAPPDATA")?.let { File(it, "Android/Sdk") },
        )
    candidates.firstOrNull { it.isDirectory }?.let { sdkDir ->
        // A properties file reads a backslash as an escape and Android Lint
        // wants the drive colon escaped, so a Windows path is written as
        // C\:/..., which the SDK locator reads back as C:/...
        val sdkPath = sdkDir.absolutePath.replace('\\', '/').replace(":", "\\:")
        localProps.writeText("sdk.dir=$sdkPath\n")
    }
}

rootProject.name = "refineid-android"
include(":app")
