plugins {
    id("com.android.application")
}

android {
    namespace = "com.luay89.pharmacylabels"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.luay89.pharmacylabels"
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }
}

tasks.register<Copy>("syncWebApp") {
    from(rootProject.projectDir.parentFile.resolve("index.html"))
    into(layout.projectDirectory.dir("src/main/assets"))
}

tasks.named("preBuild") {
    dependsOn("syncWebApp")
}
