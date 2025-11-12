package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;

import java.util.*;

public class API7_SSRFScanner implements SecurityScanner {

    private static final Set<String> COMMON_SSRF_FIELDS = new HashSet<>(Arrays.asList(
            "webhook_url", "callback_url", "notification_url", "redirect_url", "api_url", "endpoint", "url"
    ));

    private static final List<String> SSRF_PAYLOADS = Arrays.asList(
            "http://127.0.0.1:8080/health",
            "http://localhost:8080/metrics",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd"
    );

    @Override
    public String getName() {
        return "OWASP API7: Server Side Request Forgery (SSRF) Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-7) Запуск SSRF сканирования с blind fuzzing...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-7) Ошибка: входной объект не является OpenAPI");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;

        if (openAPI.getPaths() == null) return vulnerabilities;

        for (String path : openAPI.getPaths().keySet()) {
            PathItem pathItem = openAPI.getPaths().get(path);
            if (pathItem.getPost() != null) {
                Operation op = pathItem.getPost();
                if (hasJsonRequestBody(op)) {
                    String endpoint = smartPathReplace(path);
                    if (endpoint == null) continue;

                    System.out.println("(API-7) Тестируем POST-эндпоинт: " + endpoint);

                    // 1. Blind SSRF: добавляем новые URL-поля
                    for (String field : COMMON_SSRF_FIELDS) {
                        for (String payload : SSRF_PAYLOADS) {
                            try {
                                Map<String, Object> body = new HashMap<>();
                                body.put(field, payload);
                                body.put("test", "value"); // чтобы не было пустого тела

                                String jsonBody = toJson(body);
                                Map<String, String> headers = getDefaultHeaders();

                                Object resp = apiClient.executeRequest("POST", config.getTargetBaseUrl() + endpoint, jsonBody, headers);
                                if (isSSRFResponse(resp, payload)) {
                                    vulnerabilities.add(createVuln(endpoint, field, payload, (HttpApiClient.ApiResponse) resp));
                                    System.out.println("(API-7) НАЙДЕНА SSRF в " + endpoint + " через " + field);
                                }
                            } catch (Exception e) {
                                // ignore
                            }
                        }
                    }

                    // 2. Fuzz существующих строковых полей (если схема доступна)
                    fuzzExistingStringFields(op, endpoint, config, apiClient, vulnerabilities);
                }
            }
        }

        System.out.println("(API-7) Сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private boolean hasJsonRequestBody(Operation op) {
        if (op.getRequestBody() == null || op.getRequestBody().getContent() == null) return false;
        Content content = op.getRequestBody().getContent();
        return content.containsKey("application/json") || content.containsKey("application/*+json");
    }

    private void fuzzExistingStringFields(Operation op, String endpoint, ScanConfig config,
                                          ApiClient apiClient, List<Vulnerability> vulns) {
        MediaType mediaType = op.getRequestBody().getContent().get("application/json");
        if (mediaType == null || mediaType.getSchema() == null) return;

        Schema<?> schema = mediaType.getSchema();
        List<String> stringFields = extractStringFields(schema, "");

        for (String fieldPath : stringFields) {
            for (String payload : SSRF_PAYLOADS) {
                try {
                    Map<String, Object> body = new HashMap<>();
                    String[] parts = fieldPath.split("\\.");
                    if (parts.length == 1) {
                        body.put(fieldPath, payload);
                    } else {
                        // простой вложенный объект (уровень 2)
                        Map<String, Object> nested = new HashMap<>();
                        nested.put(parts[1], payload);
                        body.put(parts[0], nested);
                    }

                    String jsonBody = toJson(body);
                    Map<String, String> headers = getDefaultHeaders();

                    Object resp = apiClient.executeRequest("POST", config.getTargetBaseUrl() + endpoint, jsonBody, headers);
                    if (isSSRFResponse(resp, payload)) {
                        vulns.add(createVuln(endpoint, fieldPath, payload, (HttpApiClient.ApiResponse) resp));
                        System.out.println("(API-7) НАЙДЕНА SSRF в " + endpoint + " через существующее поле: " + fieldPath);
                    }
                } catch (Exception e) {
                    // ignore
                }
            }
        }
    }

    private List<String> extractStringFields(Schema<?> schema, String prefix) {
        List<String> fields = new ArrayList<>();
        if (schema.getProperties() == null) return fields;

        for (String propName : schema.getProperties().keySet()) {
            Schema<?> propSchema = (Schema<?>) schema.getProperties().get(propName);
            String fullName = prefix.isEmpty() ? propName : prefix + "." + propName;

            if ("string".equals(propSchema.getType())) {
                fields.add(fullName);
            } else if ("object".equals(propSchema.getType()) && propSchema.getProperties() != null) {
                fields.addAll(extractStringFields(propSchema, fullName));
            }
        }
        return fields;
    }

    private String smartPathReplace(String path) {
        return path.replaceAll("\\{[^}]+\\}", "test-id");
    }

    private Map<String, String> getDefaultHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "SSRF-Scanner/1.0");
        headers.put("Accept", "application/json");
        return headers;
    }

    private String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(e.getKey()).append("\":\"").append(e.getValue()).append("\"");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    private boolean isSSRFResponse(Object response, String payload) {
        if (!(response instanceof HttpApiClient.ApiResponse)) return false;
        HttpApiClient.ApiResponse resp = (HttpApiClient.ApiResponse) response;

        int status = resp.getStatusCode();
        String body = resp.getBody() != null ? resp.getBody().toLowerCase() : "";

        // Быстрый хинт: если ответ содержит "root:" или "ami-", это file:// или cloud metadata
        if (body.contains("root:") || body.contains("passwd") || body.contains("ami-") || body.contains("instance-id")) {
            return true;
        }

        // Внутренние ошибки при SSRF
        if (status >= 500 && (body.contains("connection") || body.contains("timeout") || body.contains("refused"))) {
            return true;
        }

        // Успешный ответ при внутреннем URL — подозрительно
        if (status == 200 && (payload.contains("127.0.0.1") || payload.contains("localhost") || payload.contains("169.254.169.254"))) {
            return true;
        }

        return false;
    }

    private Vulnerability createVuln(String endpoint, String param, String payload, HttpApiClient.ApiResponse resp) {
        Vulnerability v = new Vulnerability();
        v.setTitle("OWASP API7: SSRF через " + param);
        v.setDescription("Эндпоинт " + endpoint + " уязвим к SSRF через параметр/поле '" + param + "'");
        v.setSeverity(Vulnerability.Severity.HIGH);
        v.setCategory(Vulnerability.Category.OWASP_API7_SSRF);
        v.setEndpoint(endpoint);
        v.setMethod("POST");
        v.setParameter(param);
        v.setEvidence("Payload: " + payload + "\nStatus: " + resp.getStatusCode() + "\nBody snippet: " +
                (resp.getBody() != null ? resp.getBody().substring(0, Math.min(200, resp.getBody().length())) : ""));
        v.setStatusCode(resp.getStatusCode());
        v.setRecommendations(Arrays.asList(
                "Валидируйте все внешние URL по белому списку",
                "Блокируйте доступ к внутренним IP и метаданным",
                "Запретите схемы file://, gopher://, dict://",
                "Используйте изолированный outbound proxy"
        ));
        return v;
    }
}