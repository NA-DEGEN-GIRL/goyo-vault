// The app module applies these; Kotlin comes with AGP (built-in Kotlin),
// pinned here to the version of the Compose compiler plugin.
plugins {
    id("com.android.application") version "9.5.0" apply false
    id("org.jetbrains.kotlin.android") version "2.4.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
}
