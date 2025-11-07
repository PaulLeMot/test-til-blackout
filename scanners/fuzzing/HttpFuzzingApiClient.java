// scanners/fuzzing/HttpFuzzingApiClient.java
package scanners.fuzzing;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.HashMap;

public class HttpFuzzingApiClient implements FuzzingApiClient {

    private HttpClient httpClient;

    public HttpFuzzingApiClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    @Override
    public HttpResponse sendRequest(String method, String url, Map<String, String> params,
                                    Map<String, String> headers, Map<String, String> bodyParams) {
        long startTime = System.currentTimeMillis();

        try {
            // Build URL with query parameters
            String fullUrl = buildUrlWithParams(url, params);

            // Build request
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(fullUrl))
                    .timeout(Duration.ofSeconds(10));

            // Set method and body
            switch (method.toUpperCase()) {
                case "GET":
                    requestBuilder.GET();
                    break;
                case "POST":
                    String body = buildRequestBody(bodyParams);
                    requestBuilder.POST(HttpRequest.BodyPublishers.ofString(body));
                    break;
                case "PUT":
                    String putBody = buildRequestBody(bodyParams);
                    requestBuilder.PUT(HttpRequest.BodyPublishers.ofString(putBody));
                    break;
                case "DELETE":
                    requestBuilder.DELETE();
                    break;
                default:
                    requestBuilder.GET();
            }

            // Add headers
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    requestBuilder.header(header.getKey(), header.getValue());
                }
            }

            // Set default Content-Type if not provided
            if ((headers == null || !headers.containsKey("Content-Type")) &&
                    (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT"))) {
                requestBuilder.header("Content-Type", "application/json");
            }

            HttpRequest request = requestBuilder.build();

            // Send request - используем полное имя класса чтобы избежать конфликта
            java.net.http.HttpResponse<String> jdkResponse =
                    httpClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());

            long responseTime = System.currentTimeMillis() - startTime;

            // Convert to our HttpResponse
            Map<String, String> responseHeaders = new HashMap<>();
            jdkResponse.headers().map().forEach((k, v) -> {
                if (!v.isEmpty()) responseHeaders.put(k, v.get(0));
            });

            return new HttpResponse(jdkResponse.statusCode(), jdkResponse.body(), responseHeaders, responseTime);

        } catch (Exception e) {
            long responseTime = System.currentTimeMillis() - startTime;
            return new HttpResponse(500, "Error: " + e.getMessage(), new HashMap<>(), responseTime);
        }
    }

    private String buildUrlWithParams(String url, Map<String, String> params) {
        if (params == null || params.isEmpty()) {
            return url;
        }

        StringBuilder urlBuilder = new StringBuilder(url);
        if (!url.contains("?")) {
            urlBuilder.append("?");
        } else {
            urlBuilder.append("&");
        }

        boolean first = true;
        for (Map.Entry<String, String> param : params.entrySet()) {
            if (!first) {
                urlBuilder.append("&");
            }
            urlBuilder.append(param.getKey())
                    .append("=")
                    .append(java.net.URLEncoder.encode(param.getValue(), java.nio.charset.StandardCharsets.UTF_8));
            first = false;
        }

        return urlBuilder.toString();
    }

    private String buildRequestBody(Map<String, String> bodyParams) {
        if (bodyParams == null || bodyParams.isEmpty()) {
            return "{}";
        }

        // Simple JSON building
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : bodyParams.entrySet()) {
            if (!first) {
                json.append(",");
            }
            json.append("\"").append(entry.getKey()).append("\":")
                    .append("\"").append(escapeJson(entry.getValue())).append("\"");
            first = false;
        }
        json.append("}");
        return json.toString();
    }

    private String escapeJson(String str) {
        return str.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}