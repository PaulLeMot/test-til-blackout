// core/RealApiClient.java
package core;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import java.util.*;

public class RealApiClient implements ApiClient {
    private HttpClient client;
    
    public RealApiClient() {
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }
    
    @Override
    public ApiResponse executeRequest(String method, String url, String body, Map<String, String> headers) {
        try {
            System.out.println("🌐 Real request: " + method + " " + url);
            
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30));
            
            // Устанавливаем метод и тело
            switch (method.toUpperCase()) {
                case "GET":
                    requestBuilder.GET();
                    break;
                case "POST":
                    if (body != null) {
                        requestBuilder.POST(HttpRequest.BodyPublishers.ofString(body));
                        if (headers != null && !headers.containsKey("Content-Type")) {
                            requestBuilder.header("Content-Type", "application/json");
                        }
                    } else {
                        requestBuilder.POST(HttpRequest.BodyPublishers.noBody());
                    }
                    break;
                case "PUT":
                    if (body != null) {
                        requestBuilder.PUT(HttpRequest.BodyPublishers.ofString(body));
                        if (headers != null && !headers.containsKey("Content-Type")) {
                            requestBuilder.header("Content-Type", "application/json");
                        }
                    } else {
                        requestBuilder.PUT(HttpRequest.BodyPublishers.noBody());
                    }
                    break;
                case "DELETE":
                    requestBuilder.DELETE();
                    break;
                default:
                    requestBuilder.method(method.toUpperCase(), 
                        body != null ? HttpRequest.BodyPublishers.ofString(body) : HttpRequest.BodyPublishers.noBody());
            }
            
            // Добавляем заголовки
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    if (header.getValue() != null) {
                        requestBuilder.header(header.getKey(), header.getValue());
                    }
                }
            }
            
            // Добавляем User-Agent если не указан
            if (headers == null || !headers.containsKey("User-Agent")) {
                requestBuilder.header("User-Agent", "GOSTGuardian-Scanner/1.0");
            }
            
            HttpRequest request = requestBuilder.build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            System.out.println("📡 Response: " + response.statusCode() + " for " + url);
            
            // Преобразуем заголовки из Map<String, List<String>> в Map<String, String>
            Map<String, String> simpleHeaders = new HashMap<>();
            for (Map.Entry<String, List<String>> header : response.headers().map().entrySet()) {
                if (header.getValue() != null && !header.getValue().isEmpty()) {
                    // Берем первое значение из списка
                    simpleHeaders.put(header.getKey(), header.getValue().get(0));
                }
            }
            
            return new ApiResponse(response.statusCode(), response.body(), simpleHeaders);
            
        } catch (Exception e) {
            System.err.println("💥 Request failed: " + e.getMessage());
            return new ApiResponse(0, "Error: " + e.getMessage(), Map.of());
        }
    }
}
