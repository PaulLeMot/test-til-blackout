// core/StandardApiClient.java
package core;

import java.util.Map;

public class StandardApiClient implements ApiClient {
    @Override
    public ApiResponse executeRequest(String method, String url, String body, Map<String, String> headers) {
        System.out.println("🌐 Mock request: " + method + " " + url);
        // Возвращаем ApiResponse вместо Object
        return new ApiResponse(200, "Mock response body", Map.of());
    }
    
    // Удаляем внутренний класс MockResponse, так как теперь используем ApiResponse
}
