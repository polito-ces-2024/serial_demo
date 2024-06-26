plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation("com.fazecast:jSerialComm:[2.0.0,3.0.0)")
    implementation("org.bouncycastle:bcprov-jdk15on:1.50")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.50")
}

tasks.test {
    useJUnitPlatform()
}