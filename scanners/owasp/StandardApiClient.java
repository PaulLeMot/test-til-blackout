package scanners.owasp;

import java.util.Map;

public class StandardApiClient implements ApiClient {
    @Override
    public Object executeRequest(String method, String url, String body, Map<String, String> headers) {
        System.out.println("🌐 Mock request: " + method + " " + url);
        // Возвращаем простой объект вместо ApiResponse
        return new MockResponse(200, "Mock response body");
    }
    
    private static class MockResponse {
        private int status;
        private String body;
        
        public MockResponse(int status, String body) {
            this.status = status;
            this.body = body;
        }
        
        public int getStatus() { return status; }
        public String getBody() { return body; }
    }
}
