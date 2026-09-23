pluginManagement {
    repositories {
        val localMirror = System.getenv("VGT_LOCAL_MAVEN")?.trim()
        if (!localMirror.isNullOrEmpty()) {
            maven { url = uri(localMirror) }
        }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        val localMirror = System.getenv("VGT_LOCAL_MAVEN")?.trim()
        if (!localMirror.isNullOrEmpty()) {
            maven { url = uri(localMirror) }
        }
        google()
        mavenCentral()
    }
}
rootProject.name = "VGT-GeDefense-Mobile"
include(":core", ":app")
