package burp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ResponseAnalyzer {

    private static final Pattern STATUS_PATTERN = Pattern.compile("HTTP/\\d\\.\\d\\s+(\\d{3})");
    private static final Pattern UPGRADE_HEADER = Pattern.compile("(?i)Upgrade:\\s*websocket");
    private static final Pattern CONNECTION_UPGRADE = Pattern.compile("(?i)Connection:\\s*[Uu]pgrade");

    public static class ResponseAnalysis {
        public final String status;
        public final String code1;
        public final String code2;
        public final int responseLength;
        public final boolean hasUpgradeHeaders;

        public ResponseAnalysis(String status, String code1, String code2,
                                int responseLength, boolean hasUpgradeHeaders) {
            this.status = status;
            this.code1 = code1;
            this.code2 = code2;
            this.responseLength = responseLength;
            this.hasUpgradeHeaders = hasUpgradeHeaders;
        }
    }

    public static ResponseAnalysis analyze(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length == 0) {
            return new ResponseAnalysis("No Response", "-", "-", 0, false);
        }

        String raw = new String(rawBytes, StandardCharsets.UTF_8);
        int length = rawBytes.length;

        Matcher matcher = STATUS_PATTERN.matcher(raw);
        List<String> codes = new ArrayList<>();
        while (matcher.find()) {
            codes.add(matcher.group(1));
        }

        boolean hasUpgrade = UPGRADE_HEADER.matcher(raw).find()
                && CONNECTION_UPGRADE.matcher(raw).find();

        String code1 = !codes.isEmpty() ? codes.get(0) : "-";
        String code2 = codes.size() > 1 ? codes.get(1) : "-";

        String status;
        if (codes.size() >= 2) {
            int secondCode = Integer.parseInt(code2);
            boolean secondIsSuccess = secondCode >= 200 && secondCode < 400;

            if (secondIsSuccess) {
                // The smuggled request got a success response — smuggling worked
                status = "Smuggling Detected (" + code1 + " → " + code2 + ")";
            } else {
                // Both responses are errors — proxy parsed them individually
                status = "Pipelining (Safe)";
            }
        } else if (codes.size() == 1) {
            if ("101".equals(code1) && hasUpgrade) {
                status = "Smuggling Confirmed (101 + Upgrade)";
            } else if ("101".equals(code1)) {
                status = "Potential Smuggling (101)";
            } else {
                status = "Single Response (" + code1 + ")";
            }
        } else {
            status = "No Response";
        }

        return new ResponseAnalysis(status, code1, code2, length, hasUpgrade);
    }
}
