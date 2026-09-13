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
        )
    candidates.firstOrNull { it.isDirectory }?.let { sdkDir ->
        localProps.writeText("sdk.dir=${sdkDir.absolutePath}\n")
    }
}

rootProject.name = "refineid-android"
include(":app")
