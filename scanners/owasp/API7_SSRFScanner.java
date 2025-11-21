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

@SuppressWarnings("unchecked")
public class API7_SSRFScanner implements SecurityScanner {

    // Расширенный список SSRF параметров
    private static final Set<String> COMMON_SSRF_FIELDS = new HashSet<>(Arrays.asList(
            "webhook_url", "callback_url", "notification_url", "redirect_url", "redirect_uri",
            "api_url", "endpoint", "url", "target", "server", "host", "proxy", "backend", "service",
            "file", "ftp", "dns", "uri", "link", "image", "avatar", "logo", "icon"
    ));

    // Расширенный список параметров запроса
    private static final Set<String> SSRF_PARAM_NAMES = new HashSet<>(Arrays.asList(
            "url", "callback", "redirect", "target", "endpoint", "server", "host", "proxy", "api", "service",
            "file", "ftp", "dns", "backend", "uri", "link", "image", "avatar", "logo", "icon",
            "return", "next", "continue", "goto", "path", "source", "destination"
    ));

    // Целевые payloads для банковских систем
    private static final List<String> HIGH_CONFIDENCE_PAYLOADS = Arrays.asList(
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance",
            "http://internal.banking.api/accounts",
            "http://payment-gateway.internal/process",
            "http://localhost:8080/internal",
            "http://127.0.0.1:8080",
            "http://internal.api:8080",
            "http://admin:8080",
            "file:///etc/passwd",
            "ftp://localhost:21",
            "http://192.168.1.1:8080",
            "http://10.0.0.1:8080",
            "http://[::1]:8080"
    );

    private ObjectMapper mapper = new ObjectMapper();
    private ScanConfig config;
    private int requestCount = 0;
    private long lastRequestTime = 0;
    private static final long MIN_REQUEST_INTERVAL = 1000;
    private static final int MAX_REQUESTS_PER_ENDPOINT = 5;
    private static final long SSRF_TIMEOUT_THRESHOLD = 5000;
    private static final long MIN_SSRF_RESPONSE_TIME = 50;

    // Кэш для избежания дублирования
    private Set<String> detectedVulnerabilities = new HashSet<>();

    @Override
    public String getName() {
        return "OWASP API7: Server Side Request Forgery (SSRF) Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        this.config = config;
        this.detectedVulnerabilities.clear();

        System.out.println("(API-7) Запуск улучшенного SSRF сканирования с расширенным покрытием...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-7) Ошибка: входной объект не является OpenAPI");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        if (openAPI.getPaths() == null) return vulnerabilities;

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

        System.out.println("(API-7) Найдено путей для тестирования: " + priorityPaths.size());

        if (priorityPaths.size() > 10) {
            System.out.println("(API-7) Ограничиваем до 10 приоритетных эндпоинтов");
            priorityPaths = priorityPaths.subList(0, 10);
        }

        for (String path : priorityPaths) {
            if (requestCount >= 100) {
                System.out.println("(API-7) Достигнут лимит запросов (100)");
                break;
            }

            PathItem pathItem = openAPI.getPaths().get(path);

            // Получаем операции с их методами
            Map<String, Operation> operations = getOperationsWithMethods(pathItem);

            for (Map.Entry<String, Operation> entry : operations.entrySet()) {
                String method = entry.getKey();
                Operation op = entry.getValue();

                System.out.println("(API-7) Тестируем " + method + ": " + path);

                // 1. Проверка параметров с улучшенным сравнением
                vulnerabilities.addAll(testParametersWithImprovedDetection(path, method, op, config, apiClient, token));

                // 2. Проверка POST только для эндпоинтов, которые могут обрабатывать внешние URL
                if (method.equals("POST") && hasJsonRequestBody(op) && isPotentialSSRFEndpoint(path, op)) {
                    String endpoint = smartPathReplace(path, config);
                    if (endpoint == null) continue;

                    vulnerabilities.addAll(testEndpointWithSSRFImproved(endpoint, config, apiClient, token));
                }
            }
        }

        System.out.println("(API-7) Сканирование завершено. Найдено подтвержденных уязвимостей: " + vulnerabilities.size());
        System.out.println("(API-7) Всего выполнено запросов: " + requestCount);

        // Если уязвимостей не найдено, создаем информационную уязвимость
        if (vulnerabilities.isEmpty()) {
            vulnerabilities.add(createInfoVulnerability());
        }

        return vulnerabilities;
    }

    /**
     * Улучшенная проверка параметров с более чувствительным обнаружением
     */
    private List<Vulnerability> testParametersWithImprovedDetection(String path, String method, Operation op, ScanConfig config,
                                                                    ApiClient apiClient, String token) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Сначала получаем базовый ответ (без параметров)
        HttpApiClient.ApiResponse baselineResponse = getBaselineResponse(path, method, config, apiClient, token);
        if (baselineResponse == null) {
            System.out.println("(API-7) Пропускаем " + path + " - не удалось получить базовый ответ");
            return vulnerabilities;
        }

        int endpointRequestCount = 0;

        // Используем только 3 самых перспективных параметра на эндпоинт
        List<String> topParams = getTopParametersForEndpoint(path, op);

        for (String param : topParams) {
            if (endpointRequestCount >= 3) {
                break;
            }

            // Используем только 3 самых перспективных payload на параметр
            List<String> topPayloads = getTopPayloadsForParameter(param);

            for (String payload : topPayloads) {
                if (endpointRequestCount >= MAX_REQUESTS_PER_ENDPOINT) {
                    break;
                }

                try {
                    enforceRateLimit();

                    String realPath = smartPathReplace(path, config);
                    String url = config.getTargetBaseUrl() + realPath +
                            "?" + param + "=" + java.net.URLEncoder.encode(payload, "UTF-8");

                    Map<String, String> headers = createAuthHeaders(token);

                    long startTime = System.currentTimeMillis();
                    Object resp = apiClient.executeRequest(method, url, null, headers);
                    long responseTime = System.currentTimeMillis() - startTime;

                    endpointRequestCount++;
                    requestCount++;

                    if (resp instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResp = (HttpApiClient.ApiResponse) resp;

                        if (apiResp.getStatusCode() == 429) {
                            Thread.sleep(5000);
                            continue;
                        }

                        // Улучшенная проверка с более чувствительными критериями
                        if (isPotentialSSRF(apiResp, baselineResponse, payload, responseTime)) {
                            String vulnKey = path + "|" + param + "|" + payload;
                            if (!detectedVulnerabilities.contains(vulnKey)) {
                                detectedVulnerabilities.add(vulnKey);
                                vulnerabilities.add(createPotentialVuln(path, param, payload, apiResp,
                                        baselineResponse, responseTime, method, "parameter"));
                                System.out.println("(API-7) Обнаружена потенциальная SSRF в " + path + " через параметр: " + param);
                            }
                        }
                    }
                } catch (Exception ex) {
                    System.err.println("(API-7) Ошибка при тестировании " + path + ": " + ex.getMessage());
                }
            }
        }
        return vulnerabilities;
    }

    /**
     * Улучшенная проверка POST эндпоинтов
     */
    private List<Vulnerability> testEndpointWithSSRFImproved(String endpoint, ScanConfig config,
                                                             ApiClient apiClient, String token) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        int endpointRequestCount = 0;

        // Сначала получаем базовый ответ
        HttpApiClient.ApiResponse baselineResponse = getBaselinePostResponse(endpoint, config, apiClient, token);
        if (baselineResponse == null || baselineResponse.getStatusCode() >= 500) {
            System.out.println("(API-7) Пропускаем " + endpoint + " - базовый POST ответ ошибочный: " +
                    (baselineResponse != null ? baselineResponse.getStatusCode() : "null"));
            return vulnerabilities;
        }

        // Используем только 2 самых перспективных поля на эндпоинт
        List<String> topFields = getTopFieldsForEndpoint(endpoint);

        for (String field : topFields) {
            if (endpointRequestCount >= 2) {
                break;
            }

            // Используем только 2 самых перспективных payload на поле
            List<String> topPayloads = getTopPayloadsForField(field);

            for (String payload : topPayloads) {
                if (endpointRequestCount >= MAX_REQUESTS_PER_ENDPOINT) {
                    break;
                }

                try {
                    enforceRateLimit();

                    Map<String, Object> body = new HashMap<>();
                    body.put(field, payload);
                    addRealisticFields(body, endpoint);

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
                            Thread.sleep(5000);
                            continue;
                        }

                        // Более чувствительная проверка
                        if (isPotentialSSRF(apiResp, baselineResponse, payload, responseTime)) {
                            String vulnKey = endpoint + "|" + field + "|" + payload;
                            if (!detectedVulnerabilities.contains(vulnKey)) {
                                detectedVulnerabilities.add(vulnKey);
                                vulnerabilities.add(createPotentialVuln(endpoint, field, payload, apiResp,
                                        baselineResponse, responseTime, "POST", "body"));
                                System.out.println("(API-7) Обнаружена потенциальная SSRF в " + endpoint + " через поле: " + field);
                            }
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
     * Более чувствительная проверка SSRF
     */
    private boolean isPotentialSSRF(HttpApiClient.ApiResponse currentResp,
                                    HttpApiClient.ApiResponse baselineResp,
                                    String payload, long responseTime) {
        int currentStatus = currentResp.getStatusCode();

        // Игнорируем ответы с кодом 500 - это не уязвимость
        if (currentStatus == 500) {
            return false;
        }

        int baselineStatus = baselineResp.getStatusCode();
        String currentBody = currentResp.getBody() != null ? currentResp.getBody().toLowerCase() : "";
        String baselineBody = baselineResp.getBody() != null ? baselineResp.getBody().toLowerCase() : "";

        // 1. Прямые доказательства (высокая уверенность) - игнорируем 500 коды
        if (containsCloudMetadata(currentBody) && currentStatus != 500) {
            return true;
        }

        if (containsSpecificConnectionError(currentBody) && currentStatus != 500) {
            return true;
        }

        // 2. Косвенные признаки (средняя уверенность)

        // Значительное увеличение времени ответа (игнорируем для 500 кодов)
        if (responseTime > baselineResponseTime(baselineResp) * 2 && responseTime > 1000 && currentStatus != 500) {
            System.out.println("(API-7) Обнаружено увеличение времени ответа: " + responseTime + "мс");
            return true;
        }

        // Изменение статуса кода (игнорируем если новый статус 500)
        if (currentStatus != baselineStatus && isInternalPayload(payload) && currentStatus != 500) {
            System.out.println("(API-7) Обнаружено изменение статуса: " + baselineStatus + " -> " + currentStatus);
            return true;
        }

        // Изменение тела ответа (игнорируем для 500 кодов)
        if (hasBodyChanged(currentBody, baselineBody) && isInternalPayload(payload) && currentStatus != 500) {
            System.out.println("(API-7) Обнаружено изменение тела ответа");
            return true;
        }

        return false;
    }

    /**
     * Определение базового времени ответа
     */
    private long baselineResponseTime(HttpApiClient.ApiResponse baselineResp) {
        return 200;
    }

    /**
     * Проверка изменения тела ответа
     */
    private boolean hasBodyChanged(String currentBody, String baselineBody) {
        if (currentBody == null || baselineBody == null) return false;

        String normalizedCurrent = normalizeForComparison(currentBody);
        String normalizedBaseline = normalizeForComparison(baselineBody);

        return !normalizedCurrent.equals(normalizedBaseline);
    }

    /**
     * Нормализация для сравнения (удаление временных меток и динамических данных)
     */
    private String normalizeForComparison(String body) {
        if (body == null) return "";

        return body
                .replaceAll("\"timestamp\"[^,]*,", "\"timestamp\":\"REMOVED\",")
                .replaceAll("\"time\"[^,]*,", "\"time\":\"REMOVED\",")
                .replaceAll("\"created_at\"[^,]*,", "\"created_at\":\"REMOVED\",")
                .replaceAll("\"updated_at\"[^,]*,", "\"updated_at\":\"REMOVED\",")
                .replaceAll("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}", "TIMESTAMP_REMOVED")
                .replaceAll("\\s+", " ")
                .trim();
    }

    /**
     * Выбор наиболее перспективных параметров для эндпоинта
     */
    private List<String> getTopParametersForEndpoint(String path, Operation op) {
        List<String> prioritized = new ArrayList<>();

        if (path.contains("webhook") || path.contains("callback")) {
            prioritized.addAll(Arrays.asList("url", "callback", "webhook_url", "target", "endpoint"));
        } else if (path.contains("import") || path.contains("upload")) {
            prioritized.addAll(Arrays.asList("url", "source", "file", "path", "location"));
        } else if (path.contains("export") || path.contains("download")) {
            prioritized.addAll(Arrays.asList("target", "destination", "url", "path"));
        } else {
            prioritized.addAll(Arrays.asList("url", "callback", "redirect", "target", "endpoint"));
        }

        return prioritized.subList(0, Math.min(3, prioritized.size()));
    }

    /**
     * Выбор наиболее перспективных payload для параметра
     */
    private List<String> getTopPayloadsForParameter(String param) {
        if (param.contains("file") || param.contains("path")) {
            return Arrays.asList(
                    "file:///etc/passwd",
                    "http://localhost:8080/internal",
                    "http://169.254.169.254/latest/meta-data/"
            );
        } else {
            return Arrays.asList(
                    "http://169.254.169.254/latest/meta-data/",
                    "http://localhost:8080/internal",
                    "http://internal.api:8080"
            );
        }
    }

    /**
     * Выбор наиболее перспективных полей для эндпоинта
     */
    private List<String> getTopFieldsForEndpoint(String endpoint) {
        if (endpoint.contains("webhook")) {
            return Arrays.asList("webhook_url", "callback_url", "url");
        } else if (endpoint.contains("import")) {
            return Arrays.asList("source_url", "file_url", "import_url");
        } else {
            return Arrays.asList("url", "callback", "redirect_uri");
        }
    }

    /**
     * Выбор наиболее перспективных payload для поля
     */
    private List<String> getTopPayloadsForField(String field) {
        return getTopPayloadsForParameter(field);
    }

    /**
     * Создание потенциальной уязвимости (более низкая уверенность)
     */
    private Vulnerability createPotentialVuln(String endpoint, String param, String payload,
                                              HttpApiClient.ApiResponse ssrfResponse,
                                              HttpApiClient.ApiResponse baselineResponse,
                                              long responseTime, String method, String attackVector) {
        Vulnerability v = new Vulnerability();
        v.setTitle("OWASP API7: Потенциальная SSRF через " + attackVector + " - " + param);
        v.setDescription("Эндпоинт " + endpoint + " может быть уязвим к SSRF через " + attackVector + " '" + param +
                "'. Обнаружены косвенные признаки выполнения внешних запросов.");
        v.setSeverity(Vulnerability.Severity.MEDIUM);
        v.setCategory(Vulnerability.Category.OWASP_API7_SSRF);
        v.setEndpoint(endpoint);
        v.setMethod(method);
        v.setParameter(param);

        StringBuilder evidence = new StringBuilder();
        evidence.append("🔍 ПОТЕНЦИАЛЬНАЯ SSRF УЯЗВИМОСТЬ (требует ручной проверки)\n\n");
        evidence.append("📡 Vector: ").append(attackVector).append("\n");
        evidence.append("🔧 Parameter: ").append(param).append("\n");
        evidence.append("🎯 Payload: ").append(payload).append("\n");
        evidence.append("⏱️ Время ответа: ").append(responseTime).append("мс\n");
        evidence.append("🔒 Метод: ").append(method).append("\n\n");

        evidence.append("📊 ОТВЕТ С PAYLOAD:\n");
        evidence.append("   Статус: ").append(ssrfResponse.getStatusCode()).append("\n");
        if (ssrfResponse.getBody() != null && !ssrfResponse.getBody().isEmpty()) {
            String body = ssrfResponse.getBody();
            evidence.append("   Тело: ").append(body.length() > 200 ? body.substring(0, 200) + "..." : body).append("\n");
        }

        evidence.append("\n📊 БАЗОВЫЙ ОТВЕТ:\n");
        evidence.append("   Статус: ").append(baselineResponse.getStatusCode()).append("\n");
        if (baselineResponse.getBody() != null && !baselineResponse.getBody().isEmpty()) {
            String body = baselineResponse.getBody();
            evidence.append("   Тело: ").append(body.length() > 200 ? body.substring(0, 200) + "..." : body).append("\n");
        }

        evidence.append("\n🔍 ПРИЗНАКИ:\n");
        evidence.append("• Время ответа: ").append(responseTime).append("мс\n");
        evidence.append("• Изменение статуса: ").append(baselineResponse.getStatusCode())
                .append(" → ").append(ssrfResponse.getStatusCode()).append("\n");
        evidence.append("• Payload направлен на внутренний ресурс\n");

        v.setEvidence(evidence.toString());
        v.setStatusCode(ssrfResponse.getStatusCode());
        v.setRecommendations(Arrays.asList(
                "Проверить эндпоинт вручную с различными SSRF payloads",
                "Валидируйте все внешние URL по белому списку разрешенных доменов",
                "Блокируйте доступ к внутренним IP-адресам",
                "Запретите опасные схемы: file://, gopher://, dict://, ftp://",
                "Используйте изолированный outbound proxy для всех исходящих запросов"
        ));
        return v;
    }

    /**
     * Создание информационной уязвимости когда ничего не найдено
     */
    private Vulnerability createInfoVulnerability() {
        Vulnerability v = new Vulnerability();
        v.setTitle("OWASP API7: SSRF сканирование завершено");
        v.setDescription("SSRF сканирование выполнено для " + requestCount + " запросов. Прямые уязвимости не обнаружены, но рекомендуется провести ручное тестирование для критических эндпоинтов.");
        v.setSeverity(Vulnerability.Severity.INFO);
        v.setCategory(Vulnerability.Category.OWASP_API7_SSRF);
        v.setEvidence("Просканировано эндпоинтов: несколько\nВыполнено запросов: " + requestCount + "\nРекомендуется провести ручное тестирование health эндпоинта и эндпоинтов вебхуков.");
        v.setRecommendations(Arrays.asList(
                "Провести ручное тестирование health эндпоинта с различными SSRF payloads",
                "Протестировать эндпоинты вебхуков и обратных вызовов",
                "Проверить обработку файловых схем (file://)",
                "Протестировать заголовки X-Forwarded-For и другие"
        ));
        return v;
    }

    /**
     * Умная замена параметров пути на реальные значения
     */
    private String smartPathReplace(String path, ScanConfig config) {
        if (config == null) {
            return path.replaceAll("\\{[^}]+\\}", "test-value");
        }

        String replacedPath = path;

        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\{([^}]+)\\}");
        java.util.regex.Matcher matcher = pattern.matcher(path);

        while (matcher.find()) {
            String fullParam = matcher.group(0);
            String paramName = matcher.group(1);

            String realValue = getRealValueForParameter(paramName, config);
            replacedPath = replacedPath.replace(fullParam, realValue);
        }

        System.out.println("(API-7) Заменен путь: " + path + " -> " + replacedPath);
        return replacedPath;
    }

    /**
     * Получение реального значения для параметра пути
     */
    private String getRealValueForParameter(String paramName, ScanConfig config) {
        if (config.getRealData() != null && config.getRealData().containsKey(paramName)) {
            return config.getRealData().get(paramName).toString();
        }

        switch (paramName.toLowerCase()) {
            case "account_id":
            case "accountid":
                return config.getClientId() != null ? config.getClientId() : "default";
            case "bank_id":
            case "bankid":
                return config.getBankId() != null ? config.getBankId() : "default";
            case "user_id":
            case "userid":
                if (!config.getCredentials().isEmpty()) {
                    return config.getCredentials().get(0).getUsername();
                }
                return "test-user";
            case "consent_id":
            case "consentid":
                return config.getConsentId() != null ? config.getConsentId() : "test-consent";
            case "payment_id":
            case "paymentid":
                return "payment-12345";
            case "transaction_id":
            case "transactionid":
                return "trans-67890";
            default:
                return "test-" + paramName;
        }
    }

    private void enforceRateLimit() throws InterruptedException {
        long currentTime = System.currentTimeMillis();
        if (lastRequestTime > 0) {
            long timeSinceLastRequest = currentTime - lastRequestTime;
            if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
                Thread.sleep(MIN_REQUEST_INTERVAL - timeSinceLastRequest);
            }
        }
        lastRequestTime = System.currentTimeMillis();
    }

    private HttpApiClient.ApiResponse getBaselineResponse(String path, String method, ScanConfig config,
                                                          ApiClient apiClient, String token) {
        try {
            String realPath = smartPathReplace(path, config);
            String url = config.getTargetBaseUrl() + realPath;
            Map<String, String> headers = createAuthHeaders(token);

            Object resp = apiClient.executeRequest(method, url, null, headers);
            requestCount++;

            if (resp instanceof HttpApiClient.ApiResponse) {
                return (HttpApiClient.ApiResponse) resp;
            }
        } catch (Exception e) {
            System.err.println("(API-7) Ошибка получения базового ответа для " + path);
        }
        return null;
    }

    private HttpApiClient.ApiResponse getBaselinePostResponse(String endpoint, ScanConfig config,
                                                              ApiClient apiClient, String token) {
        try {
            Map<String, Object> body = new HashMap<>();
            addRealisticFields(body, endpoint);

            String jsonBody = toJson(body);
            Map<String, String> headers = createAuthHeaders(token);

            Object resp = apiClient.executeRequest("POST", config.getTargetBaseUrl() + endpoint, jsonBody, headers);
            requestCount++;

            if (resp instanceof HttpApiClient.ApiResponse) {
                return (HttpApiClient.ApiResponse) resp;
            }
        } catch (Exception e) {
            System.err.println("(API-7) Ошибка получения базового POST ответа для " + endpoint);
        }
        return null;
    }

    private Map<String, String> createAuthHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", "Bearer " + token);
        headers.put("User-Agent", "SSRF-Scanner/4.0");
        headers.put("Accept", "application/json");

        String bankId = config.getBankId();
        if (bankId != null) {
            headers.put("X-Requesting-Bank", bankId);
        }

        return headers;
    }

    private boolean isPotentialSSRFEndpoint(String path, Operation op) {
        return path.contains("webhook") || path.contains("callback") || path.contains("import") ||
                path.contains("upload") || path.contains("export") || path.contains("notification");
    }

    private boolean hasJsonRequestBody(Operation op) {
        if (op.getRequestBody() == null || op.getRequestBody().getContent() == null) return false;
        return op.getRequestBody().getContent().containsKey("application/json");
    }

    private void addRealisticFields(Map<String, Object> body, String endpoint) {
        body.put("test", "security_scan");

        if (endpoint.contains("consent")) {
            body.put("client_id", config.getClientId());
            body.put("permissions", Arrays.asList("ReadAccountsDetail"));
            body.put("reason", "Security testing");
        }
        if (endpoint.contains("payment")) {
            body.put("amount", 100.0);
            body.put("currency", "RUB");
            body.put("debtor_account", "test-account");
        }
    }

    private String toJson(Map<String, Object> map) {
        try {
            return mapper.writeValueAsString(map);
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(entry.getKey()).append("\":");
                if (entry.getValue() instanceof String) {
                    sb.append("\"").append(entry.getValue()).append("\"");
                } else if (entry.getValue() instanceof List) {
                    List<?> list = (List<?>) entry.getValue();
                    sb.append("[");
                    for (int i = 0; i < list.size(); i++) {
                        if (i > 0) sb.append(",");
                        sb.append("\"").append(list.get(i).toString()).append("\"");
                    }
                    sb.append("]");
                } else {
                    sb.append(entry.getValue());
                }
                first = false;
            }
            sb.append("}");
            return sb.toString();
        }
    }

    private List<String> getPriorityPaths(OpenAPI openAPI) {
        List<String> paths = new ArrayList<>(openAPI.getPaths().keySet());
        paths.sort((a, b) -> Integer.compare(getPathPriority(b), getPathPriority(a)));
        return paths;
    }

    private int getPathPriority(String path) {
        if (path.contains("webhook") || path.contains("callback")) return 100;
        if (path.contains("import") || path.contains("upload")) return 90;
        if (path.contains("health")) return 80;
        if (path.contains("docs") || path.contains("swagger") || path.contains("redoc")) return 70;
        if (path.contains("well-known")) return 60;
        if (path.contains("consent")) return 50;
        if (path.contains("account")) return 40;
        return 1;
    }

    private Map<String, Operation> getOperationsWithMethods(PathItem pathItem) {
        Map<String, Operation> operations = new HashMap<>();
        if (pathItem.getGet() != null) operations.put("GET", pathItem.getGet());
        if (pathItem.getPost() != null) operations.put("POST", pathItem.getPost());
        if (pathItem.getPut() != null) operations.put("PUT", pathItem.getPut());
        if (pathItem.getPatch() != null) operations.put("PATCH", pathItem.getPatch());
        if (pathItem.getDelete() != null) operations.put("DELETE", pathItem.getDelete());
        return operations;
    }

    private boolean isInternalPayload(String payload) {
        return payload.contains("127.0.0.1") || payload.contains("localhost") ||
                payload.contains("169.254.169.254") || payload.contains("192.168.") ||
                payload.contains("10.0.") || payload.contains("internal.") ||
                payload.contains("file://") || payload.contains("ftp://");
    }

    private boolean containsCloudMetadata(String body) {
        return body.contains("instance-id") || body.contains("ami-") ||
                body.contains("availability-zone") || body.contains("region") ||
                body.contains("public-keys") || body.contains("security-groups") ||
                body.contains("instance-type") || body.contains("local-ipv4") ||
                body.contains("accountid") || body.contains("project-id") ||
                body.contains("metadata.google.internal") ||
                body.contains("169.254.169.254");
    }

    private boolean containsSpecificConnectionError(String body) {
        return body.contains("connection refused") ||
                body.contains("connection timeout") ||
                body.contains("no route to host") ||
                body.contains("network is unreachable") ||
                body.contains("name or service not known") ||
                body.contains("temporary failure in name resolution");
    }

    @Override
    public List<Vulnerability> scanEndpoints(List<core.TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-7) Запуск СТАТИЧЕСКОГО анализа SSRF на " + endpoints.size() + " эндпоинтах");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Определяем режим работы
        boolean isStaticOnly = config.getAnalysisMode() == ScanConfig.AnalysisMode.STATIC_ONLY;
        boolean hasTokens = config.getUserTokens() != null && !config.getUserTokens().isEmpty();

        if (isStaticOnly) {
            // Режим только статического анализа - анализируем структуру эндпоинтов
            vulnerabilities.addAll(analyzeEndpointsStructure(endpoints, config));
        } else if (hasTokens) {
            // Комбинированный режим с токенами - выполняем динамические тесты
            System.out.println("(API-7) В комбинированном режиме с токенами, выполняем динамическое тестирование");
            // Используем существующую логику динамического сканирования
            return scan(null, config, apiClient);
        } else {
            // Комбинированный режим без токенов - только статический анализ
            System.out.println("(API-7) В комбинированном режиме нет токенов, выполняем только статический анализ");
            vulnerabilities.addAll(analyzeEndpointsStructure(endpoints, config));
        }

        System.out.println("(API-7) Статический анализ SSRF завершен. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Анализ структуры эндпоинтов для выявления потенциальных SSRF уязвимостей
     */
    private List<Vulnerability> analyzeEndpointsStructure(List<core.TestedEndpoint> endpoints, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Шаблоны для идентификации эндпоинтов, которые могут быть уязвимы к SSRF
        String[] ssrfPatterns = {
                "webhook", "callback", "import", "upload", "export", "download",
                "proxy", "fetch", "url", "redirect", "image", "file"
        };

        for (core.TestedEndpoint endpoint : endpoints) {
            String path = endpoint.getPath().toLowerCase();
            String method = endpoint.getMethod();

            // Проверяем, содержит ли путь шаблоны SSRF
            boolean hasSSRFPattern = Arrays.stream(ssrfPatterns)
                    .anyMatch(pattern -> path.contains(pattern));

            // Проверяем параметры на наличие SSRF-подобных имен
            boolean hasSSRFParameters = false;
            if (endpoint.getParameters() != null) {
                hasSSRFParameters = endpoint.getParameters().stream()
                        .anyMatch(param -> SSRF_PARAM_NAMES.contains(param.getName().toLowerCase()));
            }

            if (hasSSRFPattern || hasSSRFParameters) {
                Vulnerability vuln = createStaticSSRFVulnerability(endpoint, config);
                vulnerabilities.add(vuln);
                System.out.println("(API-7) Обнаружен потенциально уязвимый к SSRF эндпоинт: " + method + " " + path);
            }
        }

        return vulnerabilities;
    }

    /**
     * Создание уязвимости для статического анализа SSRF
     */
    private Vulnerability createStaticSSRFVulnerability(core.TestedEndpoint endpoint, ScanConfig config) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API7:2023 - Potential Server Side Request Forgery");
        vuln.setDescription(
                "Эндпоинт " + endpoint.getMethod() + " " + endpoint.getPath() +
                        " может быть уязвим к атакам SSRF (Server Side Request Forgery).\n\n" +
                        "Эндпоинт работает с внешними URL или содержит параметры, которые могут использоваться " +
                        "для выполнения запросов к внутренним ресурсам.\n\n" +
                        "Источник: " + endpoint.getSource()
        );
        vuln.setSeverity(Vulnerability.Severity.MEDIUM); // Средний риск, так как требует подтверждения
        vuln.setCategory(Vulnerability.Category.OWASP_API7_SSRF);
        vuln.setEndpoint(endpoint.getPath());
        vuln.setMethod(endpoint.getMethod());

        StringBuilder evidence = new StringBuilder();
        evidence.append("Статический анализ выявил потенциальную SSRF уязвимость:\n");
        evidence.append("- Эндпоинт: ").append(endpoint.getMethod()).append(" ").append(endpoint.getPath()).append("\n");
        evidence.append("- Источник: ").append(endpoint.getSource()).append("\n");
        evidence.append("- Параметры: ").append(endpoint.getParameters() != null ? endpoint.getParameters().size() : 0).append(" параметров\n");

        if (endpoint.getParameters() != null) {
            List<String> ssrfParams = new ArrayList<>();
            for (core.EndpointParameter param : endpoint.getParameters()) {
                if (SSRF_PARAM_NAMES.contains(param.getName().toLowerCase())) {
                    ssrfParams.add(param.getName());
                }
            }
            if (!ssrfParams.isEmpty()) {
                evidence.append("- Подозрительные параметры: ").append(String.join(", ", ssrfParams)).append("\n");
            }
        }

        vuln.setEvidence(evidence.toString());
        vuln.setStatusCode(-1); // Нет реального статуса кода для статического анализа

        vuln.setRecommendations(Arrays.asList(
                "Валидировать все внешние URL по белому списку разрешенных доменов",
                "Блокировать доступ к внутренним IP-адресам (127.0.0.1, 192.168.x.x, 10.x.x.x, 169.254.x.x)",
                "Запретить опасные схемы: file://, gopher://, dict://, ftp://",
                "Использовать изолированный outbound proxy для всех исходящих запросов",
                "Ограничить разрешенные HTTP методы для исходящих запросов",
                "Реализовать лимиты на размер ответов и время выполнения для внешних запросов",
                "Провести динамическое тестирование для подтверждения уязвимости"
        ));

        return vuln;
    }
}