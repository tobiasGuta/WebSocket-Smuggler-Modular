package burp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseAnalyzerTest {

    @Test
    void ignoresHttpStatusAndUpgradeTextInsideContentLengthBody() {
        String body = "body text HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n";
        String raw = "HTTP/1.1 403 Forbidden\r\n" +
                "Content-Length: " + body.length() + "\r\n" +
                "\r\n" +
                body;

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw));

        assertEquals("403", analysis.code1);
        assertEquals("-", analysis.code2);
        assertEquals("Single Response (403) - Manual Validation Required", analysis.status);
        assertFalse(analysis.hasUpgradeHeaders);
    }

    @Test
    void parsesSecondResponseOnlyAfterContentLengthBoundary() {
        String raw = "HTTP/1.1 426 Upgrade Required\r\n" +
                "Content-Length: 0\r\n" +
                "\r\n" +
                "HTTP/1.1 200 OK\r\n" +
                "Content-Length: 2\r\n" +
                "\r\n" +
                "OK";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw));

        assertEquals("426", analysis.code1);
        assertEquals("200", analysis.code2);
        assertEquals("Second HTTP-Like Response Observed (426 -> 200) - Manual Validation Required", analysis.status);
    }

    @Test
    void ignoresHttpStatusTextInsideChunkedBody() {
        String chunk = "HTTP/1.1 500 Internal Server Error\r\n";
        String raw = "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                Integer.toHexString(chunk.length()) + "\r\n" +
                chunk +
                "\r\n" +
                "0\r\n" +
                "\r\n" +
                "HTTP/1.1 404 Not Found\r\n" +
                "Content-Length: 0\r\n" +
                "\r\n";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw));

        assertEquals("200", analysis.code1);
        assertEquals("404", analysis.code2);
        assertEquals("Possible Pipelining (200 -> 404) - Manual Validation Required", analysis.status);
    }

    @Test
    void labelsWebSocketUpgradeAsAcceptedNotConfirmedSmuggling() {
        String raw = "HTTP/1.1 101 Switching Protocols\r\n" +
                "Connection: keep-alive, Upgrade\r\n" +
                "Upgrade: websocket\r\n" +
                "\r\n";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw));

        assertEquals("101", analysis.code1);
        assertEquals("-", analysis.code2);
        assertEquals("WebSocket Upgrade Accepted - Manual Validation Required", analysis.status);
        assertTrue(analysis.hasUpgradeHeaders);
        assertTrue(ResponseAnalyzer.hasAcceptedWebSocketUpgrade(bytes(raw)));
        assertFalse(ResponseAnalyzer.hasSufficientEvidence(bytes(raw)));
    }

    @Test
    void parsesCompleteHttpResponseAfterWebSocketUpgradeBoundary() {
        String raw = "HTTP/1.1 101 Switching Protocols\r\n" +
                "Connection: Upgrade\r\n" +
                "Upgrade: websocket\r\n" +
                "\r\n" +
                "HTTP/1.1 200 OK\r\n" +
                "Content-Length: 2\r\n" +
                "\r\n" +
                "OK";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw));

        assertEquals("101", analysis.code1);
        assertEquals("200", analysis.code2);
        assertEquals("Second HTTP-Like Response Observed (101 -> 200) - Manual Validation Required", analysis.status);
        assertTrue(analysis.hasUpgradeHeaders);
        assertTrue(ResponseAnalyzer.hasSufficientEvidence(bytes(raw)));
    }

    @Test
    void doesNotTreatPartialPostUpgradeHttpResponseAsSufficientEvidence() {
        String raw = "HTTP/1.1 101 Switching Protocols\r\n" +
                "Connection: Upgrade\r\n" +
                "Upgrade: websocket\r\n" +
                "\r\n" +
                "HTTP/1.1 200 OK\r\n" +
                "Content-Length: 5\r\n" +
                "\r\n" +
                "OK";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw),
                ResponseAnalyzer.CaptureTermination.IDLE_TIMEOUT);

        assertEquals("101", analysis.code1);
        assertEquals("-", analysis.code2);
        assertEquals("WebSocket Upgrade Accepted - Manual Validation Required [Idle Timeout]", analysis.status);
        assertFalse(ResponseAnalyzer.hasSufficientEvidence(bytes(raw)));
    }

    @Test
    void recognizesCommaSeparatedConnectionTokensCaseInsensitively() {
        String raw = "HTTP/1.1 101 Switching Protocols\r\n" +
                "Connection: keep-alive, uPgRaDe\r\n" +
                "Upgrade: WebSocket\r\n" +
                "\r\n";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw));

        assertEquals("WebSocket Upgrade Accepted - Manual Validation Required", analysis.status);
        assertTrue(analysis.hasUpgradeHeaders);
    }

    @Test
    void ignoresPartialHeaderBlocksAsNoCompleteResponse() {
        String raw = "HTTP/1.1 200 OK\r\n" +
                "Content-Length: 5\r\n";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw),
                ResponseAnalyzer.CaptureTermination.READ_TIMEOUT);

        assertEquals("-", analysis.code1);
        assertEquals("No Response / Read Timeout", analysis.status);
    }

    @Test
    void reportsOnlyFirstTwoResponsesWhenMoreThanTwoArePresent() {
        String raw = "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n" +
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" +
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw));

        assertEquals("426", analysis.code1);
        assertEquals("200", analysis.code2);
        assertEquals("Second HTTP-Like Response Observed (426 -> 200) - Manual Validation Required", analysis.status);
        assertTrue(ResponseAnalyzer.hasSufficientEvidence(bytes(raw)));
    }

    @Test
    void reportsClosedConnectionWhenNoHttpResponseIsPresent() {
        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes("not an HTTP response"));

        assertEquals("-", analysis.code1);
        assertEquals("-", analysis.code2);
        assertEquals("No Response / Connection Closed", analysis.status);
    }

    @Test
    void reportsTerminationReasonForTimeoutWithoutResponse() {
        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(""),
                ResponseAnalyzer.CaptureTermination.IDLE_TIMEOUT);

        assertEquals("No Response / Idle Timeout", analysis.status);
        assertEquals("Idle Timeout", analysis.captureTermination);
    }

    @Test
    void distinguishesReadTimeoutAndConnectionResetWithoutResponse() {
        ResponseAnalyzer.ResponseAnalysis timeout = ResponseAnalyzer.analyze(bytes(""),
                ResponseAnalyzer.CaptureTermination.READ_TIMEOUT);
        ResponseAnalyzer.ResponseAnalysis reset = ResponseAnalyzer.analyze(bytes(""),
                ResponseAnalyzer.CaptureTermination.CONNECTION_RESET);

        assertEquals("No Response / Read Timeout", timeout.status);
        assertEquals("No Response / Connection Reset", reset.status);
    }

    @Test
    void appendsTerminationReasonToParsedEvidence() {
        String raw = "HTTP/1.1 101 Switching Protocols\r\n" +
                "Connection: Upgrade\r\n" +
                "Upgrade: websocket\r\n" +
                "\r\n";

        ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(bytes(raw),
                ResponseAnalyzer.CaptureTermination.IDLE_TIMEOUT);

        assertEquals("WebSocket Upgrade Accepted - Manual Validation Required [Idle Timeout]", analysis.status);
        assertEquals("Idle Timeout", analysis.captureTermination);
    }

    @Test
    void recognizesSufficientEvidenceWithoutWaitingForSocketClose() {
        String raw = "HTTP/1.1 426 Upgrade Required\r\n" +
                "Content-Length: 0\r\n" +
                "\r\n" +
                "HTTP/1.1 200 OK\r\n" +
                "Content-Length: 0\r\n" +
                "\r\n";

        assertTrue(ResponseAnalyzer.hasSufficientEvidence(bytes(raw)));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.ISO_8859_1);
    }
}
