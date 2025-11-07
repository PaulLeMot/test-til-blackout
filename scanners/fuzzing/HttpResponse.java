package scanners.fuzzing;

import java.util.Map;

public class HttpResponse {
    private int statusCode;
    private String body;
    private Map<String, String> headers;
    private long responseTime;

    public HttpResponse(int statusCode, String body, Map<String, String> headers, long responseTime) {
        this.statusCode = statusCode;
        this.body = body;
        this.headers = headers;
        this.responseTime = responseTime;
    }

    public int getStatusCode() { return statusCode; }
    public String getBody() { return body; }
    public Map<String, String> getHeaders() { return headers; }
    public long getResponseTime() { return responseTime; }
}