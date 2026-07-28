package burp;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PackagingTest {

    @Test
    void gradleUsesCompileOnlyMontoyaAndDoesNotUnpackRuntimeClasspathIntoJar() throws IOException {
        String buildFile = Files.readString(Path.of("build.gradle"));

        assertTrue(buildFile.contains("compileOnly 'net.portswigger.burp.extensions:montoya-api:2023.12.1'"));
        assertFalse(buildFile.contains("implementation 'net.portswigger.burp.extensions:montoya-api"));
        assertFalse(buildFile.contains("zipTree"));
        assertFalse(buildFile.contains("runtimeClasspath.collect"));
    }
}
