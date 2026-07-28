package burp;

final class DifferentialValidation {

    private DifferentialValidation() {}

    static ResponseAnalyzer.ResponseAnalysis summarize(ResponseAnalyzer.ResponseAnalysis direct,
                                                       ResponseAnalyzer.ResponseAnalysis pipelined,
                                                       ResponseAnalyzer.ResponseAnalysis failedUpgrade,
                                                       ResponseAnalyzer.ResponseAnalysis acceptedUpgrade) {
        String status = classify(direct, pipelined, failedUpgrade, acceptedUpgrade);
        return new ResponseAnalyzer.ResponseAnalysis(
                status,
                acceptedUpgrade.code1,
                acceptedUpgrade.code2,
                acceptedUpgrade.responseLength,
                acceptedUpgrade.hasUpgradeHeaders,
                acceptedUpgrade.captureTermination
        );
    }

    static String classify(ResponseAnalyzer.ResponseAnalysis direct,
                           ResponseAnalyzer.ResponseAnalysis pipelined,
                           ResponseAnalyzer.ResponseAnalysis failedUpgrade,
                           ResponseAnalyzer.ResponseAnalysis acceptedUpgrade) {
        boolean acceptedUpgradeHandshake = "101".equals(acceptedUpgrade.code1) && acceptedUpgrade.hasUpgradeHeaders;
        boolean acceptedProtectedSuccess = acceptedUpgradeHandshake && isSuccessOrRedirect(acceptedUpgrade.code2);

        boolean directEquivalent = isEquivalentProtectedOutcome(acceptedUpgrade.code2, direct.code1);
        boolean pipelinedEquivalent = isEquivalentProtectedOutcome(acceptedUpgrade.code2, pipelined.code2);
        boolean failedUpgradeEquivalent = isEquivalentProtectedOutcome(acceptedUpgrade.code2, failedUpgrade.code2);
        boolean controlEquivalent = directEquivalent || pipelinedEquivalent || failedUpgradeEquivalent;
        boolean controlProtectedSuccess = isSuccessOrRedirect(direct.code1)
                || isSuccessOrRedirect(pipelined.code2)
                || isSuccessOrRedirect(failedUpgrade.code2);

        if (acceptedProtectedSuccess && !controlEquivalent) {
            return "Differential Behavior Observed - Accepted upgrade exposed protected response while controls did not - Manual Validation Required";
        }
        if (acceptedProtectedSuccess) {
            return "Possible Pipelining - Control path returned an equivalent protected response - Manual Validation Required";
        }
        if (controlProtectedSuccess) {
            return "Control Path Exposed Protected Response - Manual Validation Required";
        }
        if (acceptedUpgradeHandshake) {
            return "WebSocket Upgrade Accepted - Differential Controls Did Not Expose Protected Response - Manual Validation Required";
        }
        return "Differential Validation Inconclusive - Manual Validation Required";
    }

    private static boolean isSuccessOrRedirect(String code) {
        if (code == null || code.length() != 3 || "-".equals(code)) return false;
        try {
            int value = Integer.parseInt(code);
            return value >= 200 && value < 400;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isEquivalentProtectedOutcome(String acceptedCode, String controlCode) {
        Integer accepted = parseStatusCode(acceptedCode);
        Integer control = parseStatusCode(controlCode);
        if (accepted == null || control == null) return false;
        if (!isSuccessOrRedirect(accepted) || !isSuccessOrRedirect(control)) return false;

        return statusClass(accepted) == statusClass(control);
    }

    private static boolean isSuccessOrRedirect(int code) {
        return code >= 200 && code < 400;
    }

    private static int statusClass(int code) {
        return code / 100;
    }

    private static Integer parseStatusCode(String code) {
        if (code == null || code.length() != 3 || "-".equals(code)) return null;
        try {
            return Integer.parseInt(code);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
