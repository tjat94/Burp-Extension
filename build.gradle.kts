plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.2")
}

tasks.test {
    useJUnitPlatform()
}

// Define a task to build the Burp extension JAR
tasks.register<Jar>("burpExtensionJar") {
    archiveBaseName.set("BurpExtender")
    archiveVersion.set("1.0")
    from(sourceSets.main.get().output)

    manifest {
        attributes(
            "Manifest-Version" to "1.0",
            "Burp-Extension-Class" to "BurpExtender" // Burp loads this dynamically
        )
    }
}

// Ensure that the JAR task runs after compilation
tasks.named("burpExtensionJar") {
    dependsOn("classes")
}
