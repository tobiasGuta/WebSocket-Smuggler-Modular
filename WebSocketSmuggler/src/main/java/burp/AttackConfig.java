package burp;

import java.util.ArrayList;
import java.util.List;

public class AttackConfig {

    private final boolean ssrfEnabled;
    private final String simpleBaitPath;
    private final String ssrfInjectionPath;
    private final String ssrfServerUrl;
    private final String smuggledPath;
    private final String wsVersion;
    private final int socketTimeoutMs;
    private final int requestDelayMs;
    private final int threadCount;

    public AttackConfig(boolean ssrfEnabled, String simpleBaitPath, String ssrfInjectionPath,
                        String ssrfServerUrl, String smuggledPath, String wsVersion,
                        int socketTimeoutMs, int requestDelayMs, int threadCount) {
        this.ssrfEnabled = ssrfEnabled;
        this.simpleBaitPath = simpleBaitPath;
        this.ssrfInjectionPath = ssrfInjectionPath;
        this.ssrfServerUrl = ssrfServerUrl;
        this.smuggledPath = smuggledPath;
        this.wsVersion = wsVersion;
        this.socketTimeoutMs = socketTimeoutMs;
        this.requestDelayMs = requestDelayMs;
        this.threadCount = threadCount;
    }

    public List<String> validate() {
        List<String> errors = new ArrayList<>();

        if (smuggledPath == null || smuggledPath.trim().isEmpty()) {
            errors.add("Smuggled Path cannot be empty.");
        } else if (!smuggledPath.startsWith("/") && !smuggledPath.contains("{PAYLOAD}")) {
            errors.add("Smuggled Path must start with '/'.");
        }

        if (wsVersion == null || wsVersion.trim().isEmpty()) {
            errors.add("WS Version cannot be empty.");
        } else {
            try { Integer.parseInt(wsVersion.trim()); }
            catch (NumberFormatException e) { errors.add("WS Version must be a number."); }
        }

        if (ssrfEnabled) {
            if (ssrfInjectionPath == null || ssrfInjectionPath.trim().isEmpty())
                errors.add("SSRF Injection Path cannot be empty when SSRF is enabled.");
            if (ssrfServerUrl == null || ssrfServerUrl.trim().isEmpty())
                errors.add("Python Server URL cannot be empty when SSRF is enabled.");
        } else {
            if (simpleBaitPath == null || simpleBaitPath.trim().isEmpty())
                errors.add("Simple Bait Path cannot be empty.");
            else if (!simpleBaitPath.startsWith("/"))
                errors.add("Simple Bait Path must start with '/'.");
        }

        if (socketTimeoutMs < 100 || socketTimeoutMs > 60000)
            errors.add("Socket Timeout must be between 100ms and 60000ms.");
        if (requestDelayMs < 0 || requestDelayMs > 10000)
            errors.add("Request Delay must be between 0ms and 10000ms.");
        if (threadCount < 1 || threadCount > 50)
            errors.add("Thread count must be between 1 and 50.");

        return errors;
    }

    public boolean isSsrfEnabled() { return ssrfEnabled; }
    public String getSimpleBaitPath() { return simpleBaitPath; }
    public String getSsrfInjectionPath() { return ssrfInjectionPath; }
    public String getSsrfServerUrl() { return ssrfServerUrl; }
    public String getSmuggledPath() { return smuggledPath; }
    public String getWsVersion() { return wsVersion; }
    public int getSocketTimeoutMs() { return socketTimeoutMs; }
    public int getRequestDelayMs() { return requestDelayMs; }
    public int getThreadCount() { return threadCount; }

    public String getBaitPath() {
        return ssrfEnabled ? ssrfInjectionPath + ssrfServerUrl : simpleBaitPath;
    }

    public String resolveSmugglePath(String payload) {
        if (payload != null) return smuggledPath.replace("{PAYLOAD}", payload);
        return smuggledPath.replace("{PAYLOAD}", "TEST");
    }
}
