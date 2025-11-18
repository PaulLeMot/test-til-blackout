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
            "webhook_url", "callback_url", "notification_url", "redirect_url", "redirect_uri",
            "api_url", "endpoint", "url", "target", "server", "host", "proxy", "backend", "service",
            "image_url", "avatar_url", "logo_url", "file_url", "resource_url", "callback", "return_url"
    ));

    private static final Set<String> SSRF_PARAM_NAMES = new HashSet<>(Arrays.asList(
            "url", "callback", "redirect", "target", "endpoint", "server", "host", "proxy", "api", "service"
    ));

    private static final List<String> SSRF_PAYLOADS = Arrays.asList(
            "http://127.0.0.1:8080/health",
            "http://localhost:8080/metrics",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://internal.api.local/secret",
            "http://192.168.1.1/admin",
            "http://10.0.0.1/config",
            "http://172.17.0.1:8080/internal", // Docker
            "http://kubernetes.default.svc.cluster.local",
            "file:///etc/passwd",
            "gopher://localhost:8080/",
            "dict://localhost:8080/",
            "http://admin:8080/credentials",
            "http://database.internal:5432",
            "http://redis:6379",
            "http://elasticsearch:9200"
    );

    // Специальные payloads для банковского контекста
    private static final List<String> BANK_SPECIFIC_PAYLOADS = Arrays.asList(
            "http://internal.bank.api/accounts",
            "http://payment-gateway.internal/process",
            "http://card-processing.internal/authorize",
            "http://fraud-detection.internal/check",
            "http://core-banking.internal/transactions",
            "http://vault.internal/secrets",
            "http://kafka.internal:9092",
            "http://redis-cache.internal:6379"
    );

    private ObjectMapper mapper = new ObjectMapper();
    private ScanConfig config;
    private int requestCount = 0;
    private long lastRequestTime = 0;
    private static final long MIN_REQUEST_INTERVAL = 1500; // Увеличили до 1.5 секунд
    private static final int MAX_REQUESTS_PER_ENDPOINT = 15; // Уменьшили лимит
    private static final long RATE_LIMIT_DELAY = 10000; // Увеличили до 10 секунд
    private static final long SSRF_TIMEOUT_THRESHOLD = 3000; // Порог для timeout-based detection

    @Override
    public String getName() {
        return "OWASP API7: Server Side Request Forgery (SSRF) Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        this.config = config;
        System.out.println("(API-7) Запуск улучшенного SSRF сканирования...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-7) Ошибка: входной объект не является OpenAPI");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;

        if (openAPI.getPaths() == null) return vulnerabilities;

        // Получаем токены из конфигурации
        Map<String, String> tokens = config.getUserTokens();
        if (tokens == null || tokens.isEmpty()) {
            System.err.println("(API-7) Ошибка: токены не найдены в конфигурации");
            return vulnerabilities;
        }

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

        // Приоритетные эндпоинты для SSRF тестирования
        List<String> priorityPaths = getPriorityPaths(openAPI);

        // Ограничиваем количество тестируемых эндпоинтов
        if (priorityPaths.size() > 8) {
            System.out.println("(API-7) Слишком много путей (" + priorityPaths.size() + "), ограничиваем до 8 приоритетных");
            priorityPaths = priorityPaths.subList(0, 8);
        }

        for (String path : priorityPaths) {
            if (requestCount >= 80) { // Общее ограничение на все сканирование
                System.out.println("(API-7) Достигнут лимит запросов (80), прекращаем сканирование");
                break;
            }

            PathItem pathItem = openAPI.getPaths().get(path);

            // Проверяем все методы
            for (Operation op : getOperations(pathItem)) {
                System.out.println("(API-7) Тестируем эндпоинт " + getMethodFromOperation(op) + ": " + path);

                // 1. Проверка GET параметров (новое!)
                vulnerabilities.addAll(testGetParameters(path, op, config, apiClient, token));

                // 2. Проверка POST с JSON телом (улучшенное)
                if (hasJsonRequestBody(op)) {
                    String endpoint = smartPathReplace(path);
                    if (endpoint == null) continue;

                    vulnerabilities.addAll(testEndpointWithSSRF(endpoint, config, apiClient, token));
                    vulnerabilities.addAll(fuzzExistingStringFields(op, endpoint, config, apiClient, token));
                }

                // 3. Проверка заголовков (новое!)
                vulnerabilities.addAll(testHeaders(path, op, config, apiClient, token));
            }
        }

        // 4. Проверка общедоступных эндпоинтов (новое!)
        vulnerabilities.addAll(testPublicEndpoints(config, apiClient, token));

        System.out.println("(API-7) Сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        System.out.println("(API-7) Всего выполнено запросов: " + requestCount);
        return vulnerabilities;
    }

    /**
     * Новый метод: тестирование GET параметров
     */
    private List<Vulnerability> testGetParameters(String path, Operation op, ScanConfig config,
                                                  ApiClient apiClient, String token) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (op.getParameters() == null) return vulnerabilities;

        // Собираем все строковые параметры
        List<Parameter> stringParams = new ArrayList<>();
        for (Parameter param : op.getParameters()) {
            if (param.getSchema() != null && "string".equals(param.getSchema().getType())) {
                stringParams.add(param);
            }
        }

        System.out.println("(API-7) Найдено строковых параметров для GET: " + stringParams.size());

        int endpointRequestCount = 0;

        for (Parameter param : stringParams) {
            String paramName = param.getName().toLowerCase();

            // Проверяем только параметры, которые могут содержать URL
            if (!isPotentialSSRFParam(paramName)) {
                continue;
            }

            for (String payload : getAllPayloads()) {
                if (endpointRequestCount >= MAX_REQUESTS_PER_ENDPOINT) {
                    break;
                }

                try {
                    enforceRateLimit();

                    // Формируем URL с SSRF параметром
                    String url = config.getTargetBaseUrl() + smartPathReplace(path) +
                            "?" + param.getName() + "=" + java.net.URLEncoder.encode(payload, "UTF-8");

                    Map<String, String> headers = createAuthHeaders(token);

                    long startTime = System.currentTimeMillis();
                    Object resp = apiClient.executeRequest(getMethodFromOperation(op), url, null, headers);
                    long responseTime = System.currentTimeMillis() - startTime;

                    endpointRequestCount++;
                    requestCount++;

                    if (resp instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResp = (HttpApiClient.ApiResponse) resp;

                        if (apiResp.getStatusCode() == 429) {
                            System.out.println("(API-7) Обнаружен rate limiting, ждем " + RATE_LIMIT_DELAY + "мс");
                            Thread.sleep(RATE_LIMIT_DELAY);
                            continue;
                        }

                        // Улучшенная проверка с учетом времени ответа
                        if (isSSRFResponse(apiResp, payload, responseTime)) {
                            vulnerabilities.add(createVuln(path, param.getName(), payload, apiResp, responseTime));
                            System.out.println("(API-7) НАЙДЕНА SSRF в " + path + " через параметр: " + param.getName());
                        }
                    }
                } catch (Exception ex) {
                    // Игнорируем ошибки при тестировании
                }
            }
        }
        return vulnerabilities;
    }

    /**
     * Новый метод: тестирование заголовков
     */
    private List<Vulnerability> testHeaders(String path, Operation op, ScanConfig config,
                                            ApiClient apiClient, String token) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        String[] ssrfHeaders = {
                "X-Forwarded-Host", "X-Forwarded-For", "X-Real-IP", "X-Original-URL",
                "X-Callback-URL", "X-Target", "X-Requested-With", "X-Forwarded-Proto",
                "X-Original-Host", "X-Rewrite-URL"
        };

        String[] ssrfHeaderValues = {
                "127.0.0.1", "localhost", "169.254.169.254", "internal.api",
                "http://localhost:8080", "http://169.254.169.254/latest/meta-data/"
        };

        int endpointRequestCount = 0;

        for (String header : ssrfHeaders) {
            for (String value : ssrfHeaderValues) {
                if (endpointRequestCount >= 3) { // Ограничиваем тесты заголовков
                    break;
                }

                try {
                    enforceRateLimit();

                    String url = config.getTargetBaseUrl() + smartPathReplace(path);
                    Map<String, String> headers = createAuthHeaders(token);
                    headers.put(header, value);

                    long startTime = System.currentTimeMillis();
                    Object resp = apiClient.executeRequest(getMethodFromOperation(op), url, null, headers);
                    long responseTime = System.currentTimeMillis() - startTime;

                    endpointRequestCount++;
                    requestCount++;

                    if (resp instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResp = (HttpApiClient.ApiResponse) resp;

                        if (apiResp.getStatusCode() == 429) {
                            Thread.sleep(RATE_LIMIT_DELAY);
                            continue;
                        }

                        if (isSSRFResponse(apiResp, value, responseTime)) {
                            vulnerabilities.add(createVuln(path, header, value, apiResp, responseTime));
                            System.out.println("(API-7) НАЙДЕНА SSRF в " + path + " через заголовок: " + header);
                        }
                    }
                } catch (Exception ex) {
                    // Игнорируем ошибки
                }
            }
        }
        return vulnerabilities;
    }

    /**
     * Новый метод: тестирование общедоступных эндпоинтов
     */
    private List<Vulnerability> testPublicEndpoints(ScanConfig config, ApiClient apiClient, String token) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        String[] publicEndpoints = {
                "/health", "/.well-known/jwks.json", "/docs", "/redoc", "/openapi.json",
                "/swagger.json", "/api-docs", "/metrics", "/status"
        };

        for (String endpoint : publicEndpoints) {
            if (requestCount >= 80) break;

            for (String param : SSRF_PARAM_NAMES) {
                for (String payload : getQuickPayloads()) {
                    try {
                        enforceRateLimit();

                        String url = config.getTargetBaseUrl() + endpoint + "?" + param + "=" +
                                java.net.URLEncoder.encode(payload, "UTF-8");

                        Map<String, String> headers = createAuthHeaders(token);

                        long startTime = System.currentTimeMillis();
                        Object resp = apiClient.executeRequest("GET", url, null, headers);
                        long responseTime = System.currentTimeMillis() - startTime;

                        requestCount++;

                        if (resp instanceof HttpApiClient.ApiResponse) {
                            HttpApiClient.ApiResponse apiResp = (HttpApiClient.ApiResponse) resp;

                            if (isSSRFResponse(apiResp, payload, responseTime)) {
                                vulnerabilities.add(createVuln(endpoint, param, payload, apiResp, responseTime));
                                System.out.println("(API-7) НАЙДЕНА SSRF в " + endpoint + " через параметр: " + param);
                            }
                        }
                    } catch (Exception ex) {
                        // Игнорируем ошибки
                    }
                }
            }
        }
        return vulnerabilities;
    }

    /**
     * Улучшенный метод тестирования эндпоинтов с SSRF
     */
    private List<Vulnerability> testEndpointWithSSRF(String endpoint, ScanConfig config,
                                                     ApiClient apiClient, String token) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        int endpointRequestCount = 0;

        for (String field : COMMON_SSRF_FIELDS) {
            if (endpointRequestCount >= MAX_REQUESTS_PER_ENDPOINT) {
                break;
            }

            for (String payload : getAllPayloads()) {
                if (endpointRequestCount >= MAX_REQUESTS_PER_ENDPOINT) {
                    break;
                }

                try {
                    enforceRateLimit();

                    Map<String, Object> body = new HashMap<>();
                    body.put(field, payload);
                    // Добавляем минимальные обязательные поля
                    addRequiredFields(body, endpoint);

                    String jsonBody = toJson(body);
                    Map<String, String> headers = createAuthHeaders(token);

                    long startTime = System.currentTimeMillis();
                    Object resp = apiClient.executeRequest("POST", config.getTargetBaseUrl() + endpoint, jsonBody, headers);
                    long responseTime = System.currentTimeMillis() - startTime;

                    endpointRequestCount++;
                    requestCount++;

                    if (resp instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResp = (HttpApiClient.ApiResponse) resp;

                        if (apiResp.getStatusCode() == 429) {
                            System.out.println("(API-7) Обнаружен rate limiting, ждем " + RATE_LIMIT_DELAY + "мс");
                            Thread.sleep(RATE_LIMIT_DELAY);
                            continue;
                        }

                        if (isSSRFResponse(apiResp, payload, responseTime)) {
                            vulnerabilities.add(createVuln(endpoint, field, payload, apiResp, responseTime));
                            System.out.println("(API-7) НАЙДЕНА SSRF в " + endpoint + " через поле: " + field);
                        }
                    }
                } catch (Exception ex) {
                    System.err.println("(API-7) Ошибка при тестировании " + field + ": " + ex.getMessage());
                }
            }
        }
        return vulnerabilities;
    }

    /**
     * Вспомогательные методы
     */
    private List<String> getPriorityPaths(OpenAPI openAPI) {
        List<String> paths = new ArrayList<>(openAPI.getPaths().keySet());

        // Сортируем по приоритету: сначала health, well-known, потом остальные
        paths.sort((a, b) -> {
            int priorityA = getPathPriority(a);
            int priorityB = getPathPriority(b);
            return Integer.compare(priorityB, priorityA); // Высокий приоритет первый
        });

        return paths;
    }

    private int getPathPriority(String path) {
        if (path.contains("health")) return 100;
        if (path.contains("well-known")) return 90;
        if (path.contains("webhook") || path.contains("callback")) return 80;
        if (path.contains("upload") || path.contains("import")) return 70;
        if (path.contains("export") || path.contains("download")) return 60;
        return 10;
    }

    private boolean isPotentialSSRFParam(String paramName) {
        for (String ssrfParam : SSRF_PARAM_NAMES) {
            if (paramName.contains(ssrfParam)) {
                return true;
            }
        }
        return false;
    }

    private List<String> getAllPayloads() {
        List<String> allPayloads = new ArrayList<>();
        allPayloads.addAll(SSRF_PAYLOADS);
        allPayloads.addAll(BANK_SPECIFIC_PAYLOADS);
        return allPayloads;
    }

    private List<String> getQuickPayloads() {
        // Быстрые payloads для первоначального тестирования
        return Arrays.asList(
                "http://127.0.0.1:8080",
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:8080"
        );
    }

    private void addRequiredFields(Map<String, Object> body, String endpoint) {
        // Добавляем обязательные поля в зависимости от эндпоинта
        body.put("test", "ssrf_scanner");

        if (endpoint.contains("consent")) {
            body.put("client_id", "test-ssrf");
            body.put("permissions", Arrays.asList("ReadAccountsDetail"));
        }
        if (endpoint.contains("payment")) {
            body.put("amount", 100.0);
            body.put("currency", "RUB");
        }
    }

    /**
     * Улучшенная проверка SSRF ответов
     */
    private boolean isSSRFResponse(HttpApiClient.ApiResponse resp, String payload, long responseTime) {
        int status = resp.getStatusCode();
        String body = resp.getBody() != null ? resp.getBody().toLowerCase() : "";
        Map<String, List<String>> headers = resp.getHeaders();

        // 1. Прямые свидетельства в теле ответа
        if (containsSSRFIndicators(body, payload)) {
            return true;
        }

        // 2. Time-based detection (улучшенное)
        if (responseTime > SSRF_TIMEOUT_THRESHOLD && isInternalPayload(payload)) {
            return true;
        }

        // 3. Разница в статусах между внутренними и внешними payloads
        if (isInternalPayload(payload)) {
            if (status >= 500 && status != 429) { // Исключаем rate limiting
                return true;
            }

            // Успешный ответ на внутренний адрес - подозрительно
            if (status == 200 && body.length() < 1000 && !body.contains("error")) {
                return true;
            }
        }

        // 4. Ошибки соединения
        if (status >= 500 && containsConnectionError(body)) {
            return true;
        }

        // 5. Редиректы на внутренние ресурсы
        if ((status == 301 || status == 302 || status == 307) && headers != null) {
            List<String> locationHeaders = headers.get("location");
            if (locationHeaders != null) {
                for (String location : locationHeaders) {
                    if (isInternalTarget(location)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private boolean containsSSRFIndicators(String body, String payload) {
        return body.contains("root:") || body.contains("passwd") || body.contains("ami-") ||
                body.contains("instance-id") || body.contains("metadata") ||
                body.contains("169.254.169.254") || body.contains("localhost") ||
                body.contains("127.0.0.1") || body.contains("internal") ||
                body.contains("connection refused") || body.contains("connection timeout") ||
                body.contains("no route to host") || body.contains("network is unreachable");
    }

    private boolean isInternalPayload(String payload) {
        return payload.contains("127.0.0.1") || payload.contains("localhost") ||
                payload.contains("169.254.169.254") || payload.contains("192.168.") ||
                payload.contains("10.0.") || payload.contains("172.16.") ||
                payload.contains("internal.") || payload.contains(".internal");
    }

    private boolean containsConnectionError(String body) {
        return body.contains("connection") || body.contains("timeout") ||
                body.contains("refused") || body.contains("internal error") ||
                body.contains("service unavailable") || body.contains("gateway timeout");
    }

    private boolean isInternalTarget(String target) {
        return target.contains("127.0.0.1") || target.contains("localhost") ||
                target.contains("169.254.169.254") || target.contains("internal");
    }

    /**
     * Улучшенное создание уязвимости
     */
    private Vulnerability createVuln(String endpoint, String param, String payload,
                                     HttpApiClient.ApiResponse resp, long responseTime) {
        Vulnerability v = new Vulnerability();
        v.setTitle("OWASP API7: Потенциальная SSRF через " + param);
        v.setDescription("Эндпоинт " + endpoint + " может быть уязвим к SSRF через параметр '" + param +
                "'. Время ответа: " + responseTime + "мс. Payload: " + payload);
        v.setSeverity(Vulnerability.Severity.MEDIUM); // MEDIUM вместо HIGH, так как не подтверждено
        v.setCategory(Vulnerability.Category.OWASP_API7_SSRF);
        v.setEndpoint(endpoint);
        v.setMethod("POST");
        v.setParameter(param);
        v.setEvidence("Payload: " + payload +
                "\nStatus: " + resp.getStatusCode() +
                "\nResponse Time: " + responseTime + "ms" +
                "\nResponse: " + (resp.getBody() != null ?
                resp.getBody().substring(0, Math.min(300, resp.getBody().length())) : "empty"));
        v.setStatusCode(resp.getStatusCode());
        v.setRecommendations(Arrays.asList(
                "Валидируйте все внешние URL по белому списку разрешенных доменов",
                "Блокируйте доступ к внутренним IP-адресам и метаданным сервисам",
                "Запретите опасные схемы: file://, gopher://, dict://",
                "Используйте изолированный outbound proxy для всех исходящих запросов",
                "Внедрите проверку DNS resolution",
                "Ограничьте время выполнения внешних запросов",
                "Используйте URL parsing библиотеки для корректного разбора URL"
        ));
        return v;
    }

    // Остальные существующие методы остаются без изменений...
    private void enforceRateLimit() throws InterruptedException {
        long currentTime = System.currentTimeMillis();
        if (lastRequestTime > 0) {
            long timeSinceLastRequest = currentTime - lastRequestTime;
            if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
                long sleepTime = MIN_REQUEST_INTERVAL - timeSinceLastRequest;
                System.out.println("(API-7) Ограничение скорости: ждем " + sleepTime + "мс");
                Thread.sleep(sleepTime);
            }
        }
        lastRequestTime = System.currentTimeMillis();
    }

    private String getMethodFromOperation(Operation op) {
        return "POST";
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

    private List<Vulnerability> fuzzExistingStringFields(Operation op, String endpoint, ScanConfig config,
                                                         ApiClient apiClient, String token) {
        // Существующая реализация без изменений
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        MediaType mediaType = op.getRequestBody().getContent().get("application/json");
        if (mediaType == null || mediaType.getSchema() == null) return vulnerabilities;

        Schema<?> schema = mediaType.getSchema();
        List<String> stringFields = extractStringFields(schema, "");

        System.out.println("(API-7) Найдено строковых полей для фаззинга: " + stringFields.size());

        int endpointRequestCount = 0;

        for (String fieldPath : stringFields) {
            if (endpointRequestCount >= MAX_REQUESTS_PER_ENDPOINT) {
                break;
            }

            for (String payload : getQuickPayloads()) { // Используем быстрые payloads
                if (endpointRequestCount >= MAX_REQUESTS_PER_ENDPOINT) {
                    break;
                }

                try {
                    enforceRateLimit();

                    Map<String, Object> body = buildNestedObject(fieldPath, payload);
                    addRequiredFields(body, endpoint);
                    String jsonBody = toJson(body);
                    Map<String, String> headers = createAuthHeaders(token);

                    long startTime = System.currentTimeMillis();
                    Object resp = apiClient.executeRequest("POST", config.getTargetBaseUrl() + endpoint, jsonBody, headers);
                    long responseTime = System.currentTimeMillis() - startTime;

                    endpointRequestCount++;
                    requestCount++;

                    if (resp instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResp = (HttpApiClient.ApiResponse) resp;

                        if (apiResp.getStatusCode() == 429) {
                            Thread.sleep(RATE_LIMIT_DELAY);
                            continue;
                        }

                        if (isSSRFResponse(apiResp, payload, responseTime)) {
                            vulnerabilities.add(createVuln(endpoint, fieldPath, payload, apiResp, responseTime));
                            System.out.println("(API-7) НАЙДЕНА SSRF в " + endpoint + " через поле: " + fieldPath);
                        }
                    }
                } catch (Exception ex) {
                    // ignore
                }
            }
        }
        return vulnerabilities;
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
                } else {
                    // Добавляем все строковые поля для более широкого покрытия
                    fields.add(fullName);
                }
            } else if ("object".equals(propSchema.getType()) && propSchema.getProperties() != null) {
                fields.addAll(extractStringFields(propSchema, fullName));
            } else if ("array".equals(propSchema.getType()) && propSchema.getItems() != null) {
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
        headers.put("User-Agent", "SSRF-Scanner/2.0");
        headers.put("Accept", "application/json");

        String bankId = config.getBankId();
        if (bankId != null && !bankId.trim().isEmpty()) {
            headers.put("X-Requesting-Bank", bankId);
        }

        return headers;
    }

    private String toJson(Map<String, Object> map) {
        try {
            return mapper.writeValueAsString(map);
        } catch (Exception jsonException) {
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
}