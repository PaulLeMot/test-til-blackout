// core/ApiResponse.java
package core;

import java.util.Map;

public class ApiResponse {
    private int status;
    private String body;
    private Map<String, String> headers;
    
    public ApiResponse(int status, String body, Map<String, String> headers) {
        this.status = status;
        this.body = body;
        this.headers = headers;
    }
    
    // Getters
    public int getStatus() { return status; }
    public String getBody() { return body; }
    public Map<String, String> getHeaders() { return headers; }
    
    @Override
    public String toString() {
        return "ApiResponse{status=" + status + ", body='" + body + "'}";
    }
}
