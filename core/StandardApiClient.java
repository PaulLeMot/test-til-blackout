package core;

import java.util.Map;

public class StandardApiClient implements ApiClient {
    
    // Внутренний класс для совместимости
    public static class ApiResponse {
        private final int statusCode;
        private final String body;
        
        public ApiResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }
        
        public int getStatusCode() { return statusCode; }
        public String getBody() { return body; }
        public int getStatus() { return statusCode; }
    }

    @Override
    public Object executeRequest(String method, String url, String body, Map<String, String> headers) {
        System.out.println("🌐 Mock request: " + method + " " + url);
        return new ApiResponse(200, "Mock response body");
    }
}
