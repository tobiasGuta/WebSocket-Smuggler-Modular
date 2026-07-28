package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DifferentialValidationTest {

    @Test
    void reportsDifferentialBehaviorOnlyWhenAcceptedUpgradeExposesProtectedSuccess() {
        String status = DifferentialValidation.classify(
                analysis("403", "-", false),
                analysis("200", "403", false),
                analysis("426", "403", false),
                analysis("101", "200", true)
        );

        assertEquals("Differential Behavior Observed - Accepted upgrade exposed protected response while controls did not - Manual Validation Required", status);
    }

    @Test
    void reportsPossiblePipeliningWhenControlAlsoGetsProtectedSuccess() {
        String status = DifferentialValidation.classify(
                analysis("403", "-", false),
                analysis("200", "200", false),
                analysis("426", "403", false),
                analysis("101", "200", true)
        );

        assertEquals("Possible Pipelining - Control path also returned protected response - Manual Validation Required", status);
    }

    @Test
    void doesNotReportDifferentialBehaviorForHandshakeOnlyUpgrade() {
        String status = DifferentialValidation.classify(
                analysis("403", "-", false),
                analysis("200", "403", false),
                analysis("426", "403", false),
                analysis("101", "-", true)
        );

        assertEquals("WebSocket Upgrade Accepted - Differential Controls Did Not Expose Protected Response - Manual Validation Required", status);
    }

    private static ResponseAnalyzer.ResponseAnalysis analysis(String code1, String code2, boolean upgrade) {
        return new ResponseAnalyzer.ResponseAnalysis("", code1, code2, 0, upgrade);
    }
}
