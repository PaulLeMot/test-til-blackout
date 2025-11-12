package core;

import java.util.List;
import java.util.Map;

public class ApiResponse {
    private final int statusCode;
    private final String body;
    private final Map<String, List<String>> headers;

    public ApiResponse(int statusCode, String body, Map<String, List<String>> headers) {
        this.statusCode = statusCode;
        this.body = body;
        this.headers = headers;
    }

    public int getStatusCode() { 
        return statusCode; 
    }
    
    public String getBody() { 
        return body; 
    }
    
    public Map<String, List<String>> getHeaders() { 
        return headers; 
    }
    
    // Добавляем метод getStatus() для совместимости с API2_BrokenAuthScanner
    public int getStatus() {
        return statusCode;
    }
}
