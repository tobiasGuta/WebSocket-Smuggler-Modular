package burp;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestTemplateBuilderTest {

    @Test
    void preservesDefaultContextHeadersAndOriginalHostInBothRequests() {
        List<RequestTemplateBuilder.HeaderLine> headers = List.of(
                new RequestTemplateBuilder.HeaderLine("Host", "tenant.example"),
                new RequestTemplateBuilder.HeaderLine("Cookie", "sid=abc"),
                new RequestTemplateBuilder.HeaderLine("Authorization", "Bearer token"),
                new RequestTemplateBuilder.HeaderLine("Origin", "https://app.example"),
                new RequestTemplateBuilder.HeaderLine("X-Tenant-ID", "tenant-1")
        );

        String request = RequestTemplateBuilder.buildSmugglingRequest(headers, "10.0.0.10", 8443,
                "/socket", "/admin", "13", true, RequestTemplateBuilder.DEFAULT_PRESERVED_HEADERS);

        assertEquals(2, occurrences(request, "Host: tenant.example\r\n"));
        assertEquals(2, occurrences(request, "Cookie: sid=abc\r\n"));
        assertEquals(2, occurrences(request, "Authorization: Bearer token\r\n"));
        assertEquals(2, occurrences(request, "Origin: https://app.example\r\n"));
        assertFalse(request.contains("Host: 10.0.0.10:8443"));
        assertFalse(request.contains("X-Tenant-ID: tenant-1"));
    }

    @Test
    void preservesExplicitCustomHeaders() {
        List<RequestTemplateBuilder.HeaderLine> headers = List.of(
                new RequestTemplateBuilder.HeaderLine("Host", "tenant.example"),
                new RequestTemplateBuilder.HeaderLine("X-Tenant-ID", "tenant-1"),
                new RequestTemplateBuilder.HeaderLine("X-Forwarded-Host", "customer.example")
        );

        String request = RequestTemplateBuilder.buildSmugglingRequest(headers, "10.0.0.10", 8443,
                "/socket", "/admin", "13", true,
                "Host, X-Tenant-ID, X-Forwarded-Host");

        assertEquals(2, occurrences(request, "X-Tenant-ID: tenant-1\r\n"));
        assertEquals(2, occurrences(request, "X-Forwarded-Host: customer.example\r\n"));
    }

    @Test
    void doesNotCopyHeadersThatWouldCorruptProtocolFraming() {
        List<RequestTemplateBuilder.HeaderLine> headers = List.of(
                new RequestTemplateBuilder.HeaderLine("Host", "tenant.example"),
                new RequestTemplateBuilder.HeaderLine("Connection", "keep-alive"),
                new RequestTemplateBuilder.HeaderLine("Upgrade", "h2c"),
                new RequestTemplateBuilder.HeaderLine("Content-Length", "123"),
                new RequestTemplateBuilder.HeaderLine("Transfer-Encoding", "chunked"),
                new RequestTemplateBuilder.HeaderLine("Sec-WebSocket-Key", "attacker")
        );

        String request = RequestTemplateBuilder.buildSmugglingRequest(headers, "10.0.0.10", 8443,
                "/socket", "/admin", "13", true,
                "Host, Connection, Upgrade, Content-Length, Transfer-Encoding, Sec-WebSocket-Key");

        assertFalse(request.contains("Connection: keep-alive"));
        assertFalse(request.contains("Upgrade: h2c"));
        assertFalse(request.contains("Content-Length: 123"));
        assertFalse(request.contains("Transfer-Encoding: chunked"));
        assertFalse(request.contains("Sec-WebSocket-Key: attacker"));
        assertTrue(request.contains("Connection: Upgrade\r\n"));
        assertTrue(request.contains("Upgrade: websocket\r\n"));
    }

    @Test
    void canDisableHeaderPreservationForSyntheticProbe() {
        List<RequestTemplateBuilder.HeaderLine> headers = List.of(
                new RequestTemplateBuilder.HeaderLine("Host", "tenant.example"),
                new RequestTemplateBuilder.HeaderLine("Cookie", "sid=abc")
        );

        String request = RequestTemplateBuilder.buildSmugglingRequest(headers, "10.0.0.10", 8443,
                "/socket", "/admin", "13", false, RequestTemplateBuilder.DEFAULT_PRESERVED_HEADERS);

        assertEquals(2, occurrences(request, "Host: 10.0.0.10:8443\r\n"));
        assertFalse(request.contains("Host: tenant.example"));
        assertFalse(request.contains("Cookie: sid=abc"));
    }

    private static int occurrences(String value, String needle) {
        int count = 0;
        int offset = 0;
        while ((offset = value.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }
}
