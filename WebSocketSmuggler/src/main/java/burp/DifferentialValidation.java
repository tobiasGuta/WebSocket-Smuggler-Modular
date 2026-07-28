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

        boolean directProtectedSuccess = isSuccessOrRedirect(direct.code1);
        boolean pipelinedProtectedSuccess = isSuccessOrRedirect(pipelined.code2);
        boolean failedUpgradeProtectedSuccess = isSuccessOrRedirect(failedUpgrade.code2);
        boolean controlProtectedSuccess = directProtectedSuccess || pipelinedProtectedSuccess || failedUpgradeProtectedSuccess;

        if (acceptedProtectedSuccess && !controlProtectedSuccess) {
            return "Differential Behavior Observed - Accepted upgrade exposed protected response while controls did not - Manual Validation Required";
        }
        if (acceptedProtectedSuccess) {
            return "Possible Pipelining - Control path also returned protected response - Manual Validation Required";
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
}
