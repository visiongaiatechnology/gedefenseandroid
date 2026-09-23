plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}


val releaseStoreFile = System.getenv("GEDEFENSE_RELEASE_STORE_FILE")
val releaseStorePassword = System.getenv("GEDEFENSE_RELEASE_STORE_PASSWORD")
val releaseKeyAlias = System.getenv("GEDEFENSE_RELEASE_KEY_ALIAS")
val releaseKeyPassword = System.getenv("GEDEFENSE_RELEASE_KEY_PASSWORD")

android {
    namespace = "de.visiongaia.gedefense.mobile"
    compileSdk = 36
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "de.visiongaia.gedefense.mobile"
        minSdk = 29
        targetSdk = 36
        versionCode = 55
        versionName = "0.27.8-beta.6"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (releaseStoreFile != null && releaseStorePassword != null && releaseKeyAlias != null && releaseKeyPassword != null) {
            create("release") {
                storeFile = file(releaseStoreFile)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.findByName("release")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf("-Xjsr305=strict")
    }

    buildFeatures {
        buildConfig = true
    }

    packaging {
        resources.excludes += setOf("META-INF/*.kotlin_module")
        jniLibs.keepDebugSymbols += setOf("**/*.so")
        jniLibs.useLegacyPackaging = true
    }
}

dependencies {
    implementation(project(":core"))
}
