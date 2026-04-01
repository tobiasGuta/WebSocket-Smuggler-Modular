package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class AttackLog {

    private final HttpRequest request;
    private final HttpResponse response;
    private final ResponseAnalyzer.ResponseAnalysis analysis;

    public AttackLog(HttpRequest request, HttpResponse response,
                     ResponseAnalyzer.ResponseAnalysis analysis) {
        this.request = request;
        this.response = response;
        this.analysis = analysis;
    }

    public HttpRequest getRequest() { return request; }
    public HttpResponse getResponse() { return response; }
    public ResponseAnalyzer.ResponseAnalysis getAnalysis() { return analysis; }
}
