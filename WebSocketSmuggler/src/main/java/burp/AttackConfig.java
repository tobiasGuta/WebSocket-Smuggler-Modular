package burp;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class AttackConfig {

    public static final String PAYLOAD_PLACEHOLDER = "{PAYLOAD}";
    public static final String SSRF_SERVER_PLACEHOLDER = "{SSRF_SERVER}";

    private final boolean ssrfEnabled;
    private final String simpleBaitPath;
    private final String ssrfInjectionPath;
    private final String ssrfServerUrl;
    private final String smuggledPath;
    private final String wsVersion;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int idleTimeoutMs;
    private final int maxCaptureBytes;
    private final int requestDelayMs;
    private final int threadCount;
    private final int maxPayloadBytes;
    private final boolean allowRawRequestTargets;
    private final boolean differentialValidationEnabled;
    private final boolean preserveSelectedHeaders;
    private final String preservedHeaderNames;
    private final boolean verifyTlsCertificates;
    private final String sniOverride;
    private final String connectionAddressOverride;

    public AttackConfig(boolean ssrfEnabled, String simpleBaitPath, String ssrfInjectionPath,
                        String ssrfServerUrl, String smuggledPath, String wsVersion,
                        int connectTimeoutMs, int readTimeoutMs, int idleTimeoutMs,
                        int maxCaptureBytes, int requestDelayMs, int threadCount,
                        int maxPayloadBytes, boolean allowRawRequestTargets,
                        boolean differentialValidationEnabled,
                        boolean preserveSelectedHeaders, String preservedHeaderNames,
                        boolean verifyTlsCertificates, String sniOverride,
                        String connectionAddressOverride) {
        this.ssrfEnabled = ssrfEnabled;
        this.simpleBaitPath = simpleBaitPath;
        this.ssrfInjectionPath = ssrfInjectionPath;
        this.ssrfServerUrl = ssrfServerUrl;
        this.smuggledPath = smuggledPath;
        this.wsVersion = wsVersion;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.idleTimeoutMs = idleTimeoutMs;
        this.maxCaptureBytes = maxCaptureBytes;
        this.requestDelayMs = requestDelayMs;
        this.threadCount = threadCount;
        this.maxPayloadBytes = maxPayloadBytes;
        this.allowRawRequestTargets = allowRawRequestTargets;
        this.differentialValidationEnabled = differentialValidationEnabled;
        this.preserveSelectedHeaders = preserveSelectedHeaders;
        this.preservedHeaderNames = preservedHeaderNames;
        this.verifyTlsCertificates = verifyTlsCertificates;
        this.sniOverride = sniOverride;
        this.connectionAddressOverride = connectionAddressOverride;
    }

    public List<String> validate() {
        List<String> errors = new ArrayList<>();

        validateRequestTarget("Smuggled Path", smuggledPath, true, errors);

        if (wsVersion == null || wsVersion.trim().isEmpty()) {
            errors.add("WS Version cannot be empty.");
        } else {
            try { Integer.parseInt(wsVersion.trim()); }
            catch (NumberFormatException e) { errors.add("WS Version must be a number."); }
        }

        if (ssrfEnabled) {
            validateRequestTarget("SSRF Injection Path", ssrfInjectionPath, true, errors);
            if (ssrfInjectionPath == null || !ssrfInjectionPath.contains(SSRF_SERVER_PLACEHOLDER))
                errors.add("SSRF Injection Path must include " + SSRF_SERVER_PLACEHOLDER + ".");
            if (ssrfServerUrl == null || ssrfServerUrl.trim().isEmpty()) {
                errors.add("Python Server URL cannot be empty when SSRF is enabled.");
            } else if (!allowRawRequestTargets && containsDisallowedControlChars(ssrfServerUrl)) {
                errors.add("Python Server URL cannot contain carriage returns or control characters.");
            }
        } else {
            validateRequestTarget("Simple Bait Path", simpleBaitPath, false, errors);
        }

        if (connectTimeoutMs < 100 || connectTimeoutMs > 60000)
            errors.add("Connect Timeout must be between 100ms and 60000ms.");
        if (readTimeoutMs < 100 || readTimeoutMs > 60000)
            errors.add("Read Timeout must be between 100ms and 60000ms.");
        if (idleTimeoutMs < 100 || idleTimeoutMs > 60000)
            errors.add("Idle Timeout must be between 100ms and 60000ms.");
        if (maxCaptureBytes < 1024 * 1024 || maxCaptureBytes > 10 * 1024 * 1024)
            errors.add("Max Capture must be between 1024KB and 10240KB.");
        if (requestDelayMs < 0 || requestDelayMs > 10000)
            errors.add("Request Delay must be between 0ms and 10000ms.");
        if (threadCount < 1 || threadCount > 50)
            errors.add("Thread count must be between 1 and 50.");
        if (maxPayloadBytes < 1 || maxPayloadBytes > 65536)
            errors.add("Max Payload must be between 1 and 65536 bytes.");
        if (preserveSelectedHeaders) {
            if (preservedHeaderNames == null || preservedHeaderNames.trim().isEmpty()) {
                errors.add("Preserved Headers cannot be empty when header preservation is enabled.");
            } else {
                for (String headerName : preservedHeaderNames.split(",")) {
                    String trimmed = headerName.trim();
                    if (!trimmed.isEmpty() && !RequestTemplateBuilder.isValidHeaderName(trimmed)) {
                        errors.add("Invalid preserved header name: " + trimmed);
                    }
                }
            }
        }
        if (!isBlank(sniOverride) && !isValidHostOverride(sniOverride))
            errors.add("SNI Override must be a valid hostname without a scheme or port.");
        if (!isBlank(connectionAddressOverride) && !isValidHostOverride(connectionAddressOverride))
            errors.add("Connection Address Override must be a valid hostname or IP address without a scheme or port.");

        return errors;
    }

    public boolean isSsrfEnabled() { return ssrfEnabled; }
    public String getSimpleBaitPath() { return simpleBaitPath; }
    public String getSsrfInjectionPath() { return ssrfInjectionPath; }
    public String getSsrfServerUrl() { return ssrfServerUrl; }
    public String getSmuggledPath() { return smuggledPath; }
    public String getWsVersion() { return wsVersion; }
    public int getSocketTimeoutMs() { return readTimeoutMs; }
    public int getConnectTimeoutMs() { return connectTimeoutMs; }
    public int getReadTimeoutMs() { return readTimeoutMs; }
    public int getIdleTimeoutMs() { return idleTimeoutMs; }
    public int getMaxCaptureBytes() { return maxCaptureBytes; }
    public int getRequestDelayMs() { return requestDelayMs; }
    public int getThreadCount() { return threadCount; }
    public int getMaxPayloadBytes() { return maxPayloadBytes; }
    public boolean isAllowRawRequestTargets() { return allowRawRequestTargets; }
    public boolean isDifferentialValidationEnabled() { return differentialValidationEnabled; }
    public boolean isPreserveSelectedHeaders() { return preserveSelectedHeaders; }
    public String getPreservedHeaderNames() { return preservedHeaderNames; }
    public boolean isVerifyTlsCertificates() { return verifyTlsCertificates; }
    public String getSniOverride() { return sniOverride; }
    public String getConnectionAddressOverride() { return connectionAddressOverride; }

    public String resolveConnectHost(String defaultHost) {
        return isBlank(connectionAddressOverride) ? defaultHost : connectionAddressOverride.trim();
    }

    public String resolveSniHost(String defaultHost) {
        return isBlank(sniOverride) ? defaultHost : sniOverride.trim();
    }

    public String getBaitPath() {
        if (!ssrfEnabled) return simpleBaitPath;

        String replacement = allowRawRequestTargets
                ? ssrfServerUrl
                : URLEncoder.encode(ssrfServerUrl, StandardCharsets.UTF_8);
        return ssrfInjectionPath.replace(SSRF_SERVER_PLACEHOLDER, replacement);
    }

    public String resolveSmugglePath(String payload) {
        if (payload == null) return smuggledPath;
        return smuggledPath.replace(PAYLOAD_PLACEHOLDER, payload);
    }

    public boolean usesPayloadPlaceholder() {
        return smuggledPath != null && smuggledPath.contains(PAYLOAD_PLACEHOLDER);
    }

    public List<String> validatePayloads(List<String> payloads) {
        List<String> errors = new ArrayList<>();
        if (payloads == null || payloads.isEmpty()) return errors;

        if (!usesPayloadPlaceholder()) {
            errors.add("Smuggled Path must include " + PAYLOAD_PLACEHOLDER + " when a wordlist is loaded.");
            return errors;
        }

        for (String payload : payloads) {
            String value = payload != null ? payload : "";
            int byteLength = value.getBytes(StandardCharsets.UTF_8).length;
            if (byteLength > maxPayloadBytes) {
                errors.add("Payload exceeds Max Payload (" + maxPayloadBytes + " bytes): " + summarize(value));
                break;
            }
            if (!allowRawRequestTargets && containsDisallowedControlChars(value)) {
                errors.add("Payload contains carriage returns or control characters: " + summarize(value));
                break;
            }

            String resolved = resolveSmugglePath(value);
            if (!allowRawRequestTargets) {
                if (!resolved.startsWith("/")) {
                    errors.add("Resolved smuggled path must start with '/': " + summarize(resolved));
                    break;
                }
                if (containsDisallowedControlChars(resolved)) {
                    errors.add("Resolved smuggled path contains carriage returns or control characters: " + summarize(resolved));
                    break;
                }
            }
        }
        return errors;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static boolean isValidHostOverride(String value) {
        String trimmed = value.trim();
        return !trimmed.contains("://")
                && !trimmed.contains("/")
                && !trimmed.contains("\\")
                && !trimmed.contains(":")
                && trimmed.matches("[A-Za-z0-9._-]+");
    }

    private void validateRequestTarget(String label, String value, boolean allowPayloadPlaceholder, List<String> errors) {
        if (value == null || value.trim().isEmpty()) {
            errors.add(label + " cannot be empty.");
            return;
        }
        if (value.indexOf('\0') >= 0) {
            errors.add(label + " cannot contain NUL bytes.");
            return;
        }
        if (allowRawRequestTargets) return;
        if (containsDisallowedControlChars(value)) {
            errors.add(label + " cannot contain carriage returns or control characters unless raw request targets are enabled.");
        }
        if (!value.startsWith("/")) {
            errors.add(label + " must start with '/'.");
        }
        if (!allowPayloadPlaceholder && value.contains(PAYLOAD_PLACEHOLDER)) {
            errors.add(label + " cannot contain " + PAYLOAD_PLACEHOLDER + ".");
        }
    }

    private static boolean containsDisallowedControlChars(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) return true;
        }
        return false;
    }

    private static String summarize(String value) {
        String sanitized = value.replace("\r", "\\r").replace("\n", "\\n");
        return sanitized.length() <= 80 ? sanitized : sanitized.substring(0, 80) + "...";
    }
}
