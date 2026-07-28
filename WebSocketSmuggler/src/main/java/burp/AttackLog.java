package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;

public class AttackLog {

    private final ResponseAnalyzer.ResponseAnalysis analysis;
    private final List<Evidence> evidence;

    public AttackLog(HttpRequest request, HttpResponse response,
                     ResponseAnalyzer.ResponseAnalysis analysis) {
        this(analysis, List.of(new Evidence("Accepted Upgrade", request, response)));
    }

    public AttackLog(ResponseAnalyzer.ResponseAnalysis analysis, List<Evidence> evidence) {
        this.analysis = analysis;
        this.evidence = List.copyOf(evidence);
    }

    public HttpRequest getRequest() { return evidence.get(0).request(); }
    public HttpResponse getResponse() { return evidence.get(0).response(); }
    public ResponseAnalyzer.ResponseAnalysis getAnalysis() { return analysis; }
    public List<Evidence> getEvidence() { return evidence; }

    public record Evidence(String label, HttpRequest request, HttpResponse response) {}
}
