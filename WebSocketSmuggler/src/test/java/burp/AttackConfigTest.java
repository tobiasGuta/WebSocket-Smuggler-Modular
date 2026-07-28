package burp;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackConfigTest {

    @Test
    void acceptsTlsAndConnectionOverridesWithoutSchemesOrPorts() {
        AttackConfig config = config("backend.internal", "sni.example");

        assertTrue(config.validate().isEmpty());
        assertTrue(config.isVerifyTlsCertificates());
        assertFalse(config.getConnectionAddressOverride().isEmpty());
    }

    @Test
    void rejectsConnectionOverridesWithSchemesOrPorts() {
        AttackConfig config = config("https://backend.internal:8443", "sni.example");

        assertTrue(config.validate().contains(
                "Connection Address Override must be a valid hostname or IP address without a scheme or port."));
    }

    @Test
    void rejectsSniOverridesWithPorts() {
        AttackConfig config = config("backend.internal", "sni.example:443");

        assertTrue(config.validate().contains(
                "SNI Override must be a valid hostname without a scheme or port."));
    }

    @Test
    void rejectsPayloadOnlySmuggledPathInNormalMode() {
        AttackConfig config = config(false, "/socket", "/check-url?server={SSRF_SERVER}",
                "http://127.0.0.1:8000", "{PAYLOAD}", false, 2048);

        assertTrue(config.validate().contains("Smuggled Path must start with '/'."));
    }

    @Test
    void requiresSsrfServerPlaceholderInSsrfMode() {
        AttackConfig config = config(true, "/socket", "/check-url?server=",
                "http://127.0.0.1:8000", "/robots.txt", false, 2048);

        assertTrue(config.validate().contains("SSRF Injection Path must include {SSRF_SERVER}."));
    }

    @Test
    void encodesSsrfServerPlaceholderInNormalMode() {
        AttackConfig config = config(true, "/socket", "/check-url?server={SSRF_SERVER}",
                "http://127.0.0.1:8000/a b", "/robots.txt", false, 2048);

        assertEquals("/check-url?server=http%3A%2F%2F127.0.0.1%3A8000%2Fa+b", config.getBaitPath());
    }

    @Test
    void doesNotReplaceMissingPayloadWithTest() {
        AttackConfig config = config(false, "/socket", "/check-url?server={SSRF_SERVER}",
                "http://127.0.0.1:8000", "/{PAYLOAD}", false, 2048);

        assertEquals("/{PAYLOAD}", config.resolveSmugglePath(null));
    }

    @Test
    void rejectsWordlistWhenSmuggledPathHasNoPayloadPlaceholder() {
        AttackConfig config = config(false, "/socket", "/check-url?server={SSRF_SERVER}",
                "http://127.0.0.1:8000", "/admin", false, 2048);

        assertTrue(config.validatePayloads(List.of("users")).contains(
                "Smuggled Path must include {PAYLOAD} when a wordlist is loaded."));
    }

    @Test
    void rejectsOversizedPayloadsAndControlCharsInNormalMode() {
        AttackConfig oversized = config(false, "/socket", "/check-url?server={SSRF_SERVER}",
                "http://127.0.0.1:8000", "/{PAYLOAD}", false, 4);
        AttackConfig control = config(false, "/socket", "/check-url?server={SSRF_SERVER}",
                "http://127.0.0.1:8000", "/{PAYLOAD}", false, 2048);

        assertFalse(oversized.validatePayloads(List.of("abcde")).isEmpty());
        assertFalse(control.validatePayloads(List.of("admin\r\nHost: evil")).isEmpty());
    }

    @Test
    void allowsRawRequestTargetsOnlyWhenExplicitlyEnabled() {
        AttackConfig config = config(false, "OPTIONS *", "/check-url?server={SSRF_SERVER}",
                "http://127.0.0.1:8000", "{PAYLOAD}", true, 2048);

        assertTrue(config.validate().isEmpty());
    }

    private static AttackConfig config(String connectHost, String sniHost) {
        return config(false, "/socket", "/check-url?server={SSRF_SERVER}",
                "http://127.0.0.1:8000", "/robots.txt", false, 2048, connectHost, sniHost);
    }

    private static AttackConfig config(boolean ssrfEnabled, String baitPath, String ssrfPath,
                                       String ssrfServer, String smuggledPath,
                                       boolean allowRawTargets, int maxPayloadBytes) {
        return config(ssrfEnabled, baitPath, ssrfPath, ssrfServer, smuggledPath,
                allowRawTargets, maxPayloadBytes, "", "");
    }

    private static AttackConfig config(boolean ssrfEnabled, String baitPath, String ssrfPath,
                                       String ssrfServer, String smuggledPath,
                                       boolean allowRawTargets, int maxPayloadBytes,
                                       String connectHost, String sniHost) {
        return new AttackConfig(
                ssrfEnabled,
                baitPath,
                ssrfPath,
                ssrfServer,
                smuggledPath,
                "13",
                3000,
                5000,
                1000,
                1024 * 1024,
                50,
                1,
                maxPayloadBytes,
                allowRawTargets,
                true,
                RequestTemplateBuilder.DEFAULT_PRESERVED_HEADERS,
                true,
                sniHost,
                connectHost
        );
    }
}
