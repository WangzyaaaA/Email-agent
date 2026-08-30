plugins {
    id("com.android.application")
}

fun quotedProperty(name: String): String {
    val value = providers.gradleProperty(name).orElse("").get()
    return "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""
}

android {
    namespace = "com.mailsentinel.push"
    compileSdk {
        version = release(37) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.mailsentinel.push"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        buildConfigField("String", "FIREBASE_API_KEY", quotedProperty("MAIL_SENTINEL_FIREBASE_API_KEY"))
        buildConfigField("String", "FIREBASE_APPLICATION_ID", quotedProperty("MAIL_SENTINEL_FIREBASE_APPLICATION_ID"))
        buildConfigField("String", "FIREBASE_PROJECT_ID", quotedProperty("MAIL_SENTINEL_FIREBASE_PROJECT_ID"))
        buildConfigField("String", "FIREBASE_SENDER_ID", quotedProperty("MAIL_SENTINEL_FIREBASE_SENDER_ID"))
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        buildConfig = true
    }

    val keystoreFile = providers.gradleProperty("MAIL_SENTINEL_KEYSTORE_FILE").orElse(providers.environmentVariable("MAIL_SENTINEL_KEYSTORE_FILE"))
    val keystorePassword = providers.gradleProperty("MAIL_SENTINEL_KEYSTORE_PASSWORD").orElse(providers.environmentVariable("MAIL_SENTINEL_KEYSTORE_PASSWORD"))
    val keyAliasValue = providers.gradleProperty("MAIL_SENTINEL_KEY_ALIAS").orElse(providers.environmentVariable("MAIL_SENTINEL_KEY_ALIAS"))
    val keyPasswordValue = providers.gradleProperty("MAIL_SENTINEL_KEY_PASSWORD").orElse(providers.environmentVariable("MAIL_SENTINEL_KEY_PASSWORD"))
    if (listOf(keystoreFile, keystorePassword, keyAliasValue, keyPasswordValue).all { it.isPresent && it.get().isNotBlank() }) {
        signingConfigs {
            create("release") {
                storeFile = file(keystoreFile.get())
                storePassword = keystorePassword.get()
                keyAlias = keyAliasValue.get()
                keyPassword = keyPasswordValue.get()
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {
    implementation(platform("com.google.firebase:firebase-bom:34.18.0"))
    implementation("com.google.firebase:firebase-messaging")
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.work:work-runtime-ktx:2.11.2")
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:core-ktx:1.7.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
}
