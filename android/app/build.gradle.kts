import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

/** The NDK the Rust bridge is built with (cargo-ndk). */
val ndkVersionUsed = "30.0.16248370"

android {
    namespace = "app.goyovault"
    compileSdk = 36
    ndkVersion = ndkVersionUsed

    defaultConfig {
        applicationId = "app.goyovault"
        minSdk = 28
        targetSdk = 36
        versionCode = 3
        versionName = "0.3.0-stage3"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            // The Rust bridge is built for 64-bit ARM phones only.
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        debug {
            // A separate Application ID would put the debug build's vault in
            // another sandbox; stage 1 has the debug build only.
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }

    sourceSets {
        getByName("main") {
            // Filled by cargoNdkBuild below; never committed.
            jniLibs.directories.add(layout.buildDirectory.dir("rustJniLibs").get().asFile.path)
        }
        getByName("androidTest") {
            // The TEST vault of android/rust/examples/make_test_vault.rs.
            assets.directories.add(layout.buildDirectory.dir("testVault").get().asFile.path)
        }
    }

    packaging {
        jniLibs {
            // Native libraries stay compressed in the APK and are extracted at
            // install; nothing changes for the app.
            useLegacyPackaging = false
        }
    }
}

/**
 * The NDK folder: ANDROID_NDK_HOME, else `<sdk.dir>/ndk/<ndkVersionUsed>`
 * from local.properties or ANDROID_HOME.
 */
fun ndkDir(): File {
    System.getenv("ANDROID_NDK_HOME")?.let { return File(it) }
    val props = Properties()
    val local = rootProject.file("local.properties")
    if (local.exists()) local.inputStream().use { props.load(it) }
    val sdk = props.getProperty("sdk.dir") ?: System.getenv("ANDROID_HOME")
        ?: error("Android SDK not found: set sdk.dir in local.properties or ANDROID_HOME")
    return File(sdk, "ndk/$ndkVersionUsed")
}

/**
 * Builds android/rust (the JNI bridge and, through it, the goyo_vault lib)
 * for arm64-v8a with cargo-ndk, release profile (Argon2id is far too slow
 * unoptimized), into build/rustJniLibs/arm64-v8a/libgoyo_android.so.
 */
val cargoNdkBuild = tasks.register<Exec>("cargoNdkBuild") {
    val rustDir = rootProject.file("rust")
    val out = layout.buildDirectory.dir("rustJniLibs").get().asFile
    workingDir = rustDir
    environment("ANDROID_NDK_HOME", ndkDir().absolutePath)
    commandLine(
        "cargo", "ndk", "-t", "arm64-v8a", "--platform", "28",
        "-o", out.absolutePath, "build", "--release", "--locked",
    )
    inputs.dir(rustDir.resolve("src"))
    inputs.file(rustDir.resolve("Cargo.toml"))
    inputs.file(rustDir.resolve("Cargo.lock"))
    inputs.dir(rootProject.file("../src"))
    inputs.file(rootProject.file("../Cargo.toml"))
    outputs.dir(out)
}
tasks.named("preBuild") { dependsOn(cargoNdkBuild) }

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.06.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    // The 15-minute background sync (moves encrypted files only).
    implementation("androidx.work:work-runtime-ktx:2.10.5")
    // YubiKey over USB and NFC, and CTAP2 (FIDO2) for the hmac-secret assertion.
    // 3.1.0: 3.2.0 and later need compileSdk 37.
    implementation("com.yubico.yubikit:android:3.1.0")
    implementation("com.yubico.yubikit:fido:3.1.0")

    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
