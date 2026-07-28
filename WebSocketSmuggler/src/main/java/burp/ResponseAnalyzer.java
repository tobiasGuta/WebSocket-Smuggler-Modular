package burp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class ResponseAnalyzer {

    public enum CaptureTermination {
        EOF("EOF"),
        READ_TIMEOUT("Read Timeout"),
        IDLE_TIMEOUT("Idle Timeout"),
        CONNECTION_RESET("Connection Reset"),
        TRUNCATED("Capture Truncated"),
        EVIDENCE_COMPLETE("Evidence Complete"),
        ERROR("Capture Error");

        private final String label;

        CaptureTermination(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public static class ResponseAnalysis {
        public final String status;
        public final String code1;
        public final String code2;
        public final int responseLength;
        public final boolean hasUpgradeHeaders;
        public final String captureTermination;

        public ResponseAnalysis(String status, String code1, String code2,
                                int responseLength, boolean hasUpgradeHeaders) {
            this(status, code1, code2, responseLength, hasUpgradeHeaders, "");
        }

        public ResponseAnalysis(String status, String code1, String code2,
                                int responseLength, boolean hasUpgradeHeaders,
                                String captureTermination) {
            this.status = status;
            this.code1 = code1;
            this.code2 = code2;
            this.responseLength = responseLength;
            this.hasUpgradeHeaders = hasUpgradeHeaders;
            this.captureTermination = captureTermination;
        }
    }

    public static ResponseAnalysis analyze(byte[] rawBytes) {
        return analyze(rawBytes, null);
    }

    public static ResponseAnalysis analyze(byte[] rawBytes, CaptureTermination termination) {
        String terminationLabel = termination != null ? termination.label() : "";
        if (rawBytes == null || rawBytes.length == 0) {
            return new ResponseAnalysis(noResponseStatus(termination), "-", "-", 0, false, terminationLabel);
        }

        String raw = new String(rawBytes, StandardCharsets.ISO_8859_1);
        int length = rawBytes.length;

        List<ParsedResponse> responses = parseResponses(raw);
        if (responses.isEmpty()) {
            return new ResponseAnalysis(noResponseStatus(termination), "-", "-", length, false, terminationLabel);
        }

        ParsedResponse first = responses.get(0);
        String code1 = first.code;
        String code2 = responses.size() > 1 ? responses.get(1).code : "-";
        boolean hasUpgrade = responses.stream().anyMatch(ParsedResponse::hasWebSocketUpgrade);
        String status = withTermination(classify(responses), termination);

        return new ResponseAnalysis(status, code1, code2, length, hasUpgrade, terminationLabel);
    }

    public static boolean hasSufficientEvidence(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length == 0) return false;

        String raw = new String(rawBytes, StandardCharsets.ISO_8859_1);
        List<ParsedResponse> responses = parseResponses(raw);
        return responses.size() >= 2 || responses.stream().anyMatch(response ->
                response.statusCode == 101 && response.hasWebSocketUpgrade());
    }

    private static String classify(List<ParsedResponse> responses) {
        ParsedResponse first = responses.get(0);
        if (responses.size() >= 2) {
            ParsedResponse second = responses.get(1);
            if (second.statusCode >= 200 && second.statusCode < 400) {
                return "Second HTTP-Like Response Observed (" + first.code + " -> " + second.code + ") - Manual Validation Required";
            }
            return "Possible Pipelining (" + first.code + " -> " + second.code + ") - Manual Validation Required";
        }

        if (first.statusCode == 101 && first.hasWebSocketUpgrade()) {
            return "WebSocket Upgrade Accepted - Manual Validation Required";
        }
        if (first.statusCode == 101) {
            return "Manual Validation Required (101 without Upgrade headers)";
        }
        return "Single Response (" + first.code + ") - Manual Validation Required";
    }

    private static String noResponseStatus(CaptureTermination termination) {
        if (termination == null || termination == CaptureTermination.EOF) {
            return "No Response / Connection Closed";
        }
        if (termination == CaptureTermination.IDLE_TIMEOUT) {
            return "No Response / Idle Timeout";
        }
        if (termination == CaptureTermination.READ_TIMEOUT) {
            return "No Response / Read Timeout";
        }
        if (termination == CaptureTermination.CONNECTION_RESET) {
            return "No Response / Connection Reset";
        }
        if (termination == CaptureTermination.TRUNCATED) {
            return "No Response / Capture Truncated";
        }
        return "No Response / " + termination.label();
    }

    private static String withTermination(String status, CaptureTermination termination) {
        if (termination == null) return status;
        return status + " [" + termination.label() + "]";
    }

    private static List<ParsedResponse> parseResponses(String raw) {
        List<ParsedResponse> responses = new ArrayList<>();
        int offset = 0;

        while (offset < raw.length()) {
            offset = skipLineBreaks(raw, offset);
            ParsedResponse parsed = parseResponseAt(raw, offset);
            if (parsed == null) break;
            responses.add(parsed);
            if (parsed.consumesRemainder || parsed.nextOffset <= offset) break;
            offset = parsed.nextOffset;
        }

        return responses;
    }

    private static ParsedResponse parseResponseAt(String raw, int offset) {
        if (!raw.startsWith("HTTP/", offset)) return null;

        int statusLineEnd = findLineEnd(raw, offset);
        if (statusLineEnd < 0) return null;

        String[] parts = raw.substring(offset, statusLineEnd).trim().split("\\s+", 3);
        if (parts.length < 2 || parts[1].length() != 3) return null;

        int statusCode;
        try {
            statusCode = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return null;
        }

        int headersStart = nextLineStart(raw, statusLineEnd);
        HeaderEnd headerEnd = findHeaderEnd(raw, headersStart);
        if (headerEnd == null) return null;

        Map<String, List<String>> headers = parseHeaders(raw.substring(headersStart, headerEnd.headersEnd));
        BodyBoundary boundary = findBodyBoundary(raw, headerEnd.bodyStart, statusCode, headers);
        return new ParsedResponse(statusCode, parts[1], headers, boundary.nextOffset, boundary.consumesRemainder);
    }

    private static Map<String, List<String>> parseHeaders(String headerBlock) {
        Map<String, List<String>> headers = new HashMap<>();
        String[] lines = headerBlock.split("\\r?\\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).trim().toLowerCase(Locale.ROOT);
            headers.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
        }
        return headers;
    }

    private static BodyBoundary findBodyBoundary(String raw, int bodyStart, int statusCode, Map<String, List<String>> headers) {
        if (statusCode == 101) {
            return new BodyBoundary(raw.length(), true);
        }

        if (hasHeaderValue(headers, "transfer-encoding", "chunked")) {
            int chunkedEnd = findChunkedBodyEnd(raw, bodyStart);
            return new BodyBoundary(chunkedEnd, chunkedEnd >= raw.length());
        }

        Integer contentLength = contentLength(headers);
        if (contentLength != null) {
            int nextOffset = Math.min(raw.length(), bodyStart + contentLength);
            return new BodyBoundary(nextOffset, nextOffset >= raw.length());
        }

        if ((statusCode >= 100 && statusCode < 200) || statusCode == 204 || statusCode == 304) {
            return new BodyBoundary(bodyStart, false);
        }

        return new BodyBoundary(raw.length(), true);
    }

    private static int findChunkedBodyEnd(String raw, int offset) {
        int pos = offset;
        while (pos < raw.length()) {
            int sizeLineEnd = findLineEnd(raw, pos);
            if (sizeLineEnd < 0) return raw.length();

            String sizeLine = raw.substring(pos, sizeLineEnd).trim();
            int extensionStart = sizeLine.indexOf(';');
            if (extensionStart >= 0) sizeLine = sizeLine.substring(0, extensionStart).trim();

            int chunkSize;
            try {
                chunkSize = Integer.parseInt(sizeLine, 16);
            } catch (NumberFormatException e) {
                return raw.length();
            }

            pos = nextLineStart(raw, sizeLineEnd);
            if (chunkSize == 0) {
                int emptyTrailerEnd = findLineEnd(raw, pos);
                if (emptyTrailerEnd == pos) return nextLineStart(raw, emptyTrailerEnd);

                HeaderEnd trailersEnd = findHeaderEnd(raw, pos);
                if (trailersEnd != null) return trailersEnd.bodyStart;
                return raw.length();
            }

            pos += chunkSize;
            if (pos >= raw.length()) return raw.length();

            if (raw.charAt(pos) == '\r' && pos + 1 < raw.length() && raw.charAt(pos + 1) == '\n') {
                pos += 2;
            } else if (raw.charAt(pos) == '\n') {
                pos++;
            }
        }
        return raw.length();
    }

    private static Integer contentLength(Map<String, List<String>> headers) {
        List<String> values = headers.get("content-length");
        if (values == null || values.isEmpty()) return null;
        try {
            int value = Integer.parseInt(values.get(0).trim());
            return value >= 0 ? value : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static boolean hasHeaderValue(Map<String, List<String>> headers, String name, String token) {
        List<String> values = headers.get(name);
        if (values == null) return false;
        for (String value : values) {
            for (String part : value.split(",")) {
                if (part.trim().equals(token)) return true;
            }
        }
        return false;
    }

    private static int skipLineBreaks(String raw, int offset) {
        while (offset < raw.length() && (raw.charAt(offset) == '\r' || raw.charAt(offset) == '\n')) {
            offset++;
        }
        return offset;
    }

    private static int findLineEnd(String raw, int offset) {
        int cr = raw.indexOf('\r', offset);
        int lf = raw.indexOf('\n', offset);
        if (cr < 0) return lf;
        if (lf < 0) return cr;
        return Math.min(cr, lf);
    }

    private static int nextLineStart(String raw, int lineEnd) {
        if (lineEnd < 0) return raw.length();
        if (raw.charAt(lineEnd) == '\r' && lineEnd + 1 < raw.length() && raw.charAt(lineEnd + 1) == '\n') {
            return lineEnd + 2;
        }
        return lineEnd + 1;
    }

    private static HeaderEnd findHeaderEnd(String raw, int offset) {
        int crlf = raw.indexOf("\r\n\r\n", offset);
        int lf = raw.indexOf("\n\n", offset);

        if (crlf < 0 && lf < 0) return null;
        if (lf < 0 || (crlf >= 0 && crlf < lf)) return new HeaderEnd(crlf, crlf + 4);
        return new HeaderEnd(lf, lf + 2);
    }

    private static class ParsedResponse {
        private final int statusCode;
        private final String code;
        private final Map<String, List<String>> headers;
        private final int nextOffset;
        private final boolean consumesRemainder;

        private ParsedResponse(int statusCode, String code, Map<String, List<String>> headers,
                               int nextOffset, boolean consumesRemainder) {
            this.statusCode = statusCode;
            this.code = code;
            this.headers = headers;
            this.nextOffset = nextOffset;
            this.consumesRemainder = consumesRemainder;
        }

        private boolean hasWebSocketUpgrade() {
            return hasHeaderValue(headers, "upgrade", "websocket")
                    && hasHeaderValue(headers, "connection", "upgrade");
        }
    }

    private static class HeaderEnd {
        private final int headersEnd;
        private final int bodyStart;

        private HeaderEnd(int headersEnd, int bodyStart) {
            this.headersEnd = headersEnd;
            this.bodyStart = bodyStart;
        }
    }

    private static class BodyBoundary {
        private final int nextOffset;
        private final boolean consumesRemainder;

        private BodyBoundary(int nextOffset, boolean consumesRemainder) {
            this.nextOffset = nextOffset;
            this.consumesRemainder = consumesRemainder;
        }
    }
}
