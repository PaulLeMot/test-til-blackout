// scanners/owasp/API3_BOScanner.java
package scanners.owasp;

import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import scanners.SecurityScanner;
import java.util.*;

/**
 * Сканер для OWASP API3: Broken Object Property Level Authorization
 * Адаптирован для работы с доступными эндпоинтами Virtual Bank API
 */
public class API3_BOScanner implements SecurityScanner {

    private static final Set<String> SENSITIVE_PATTERNS = Set.of(
            "password", "token", "secret", "key", "auth", "credential",
            "cvv", "expiry", "pin", "signature", "signature_key"
    );

    private static final Set<String> PII_PATTERNS = Set.of(
            "email", "phone", "address", "birth_date", "birthdate", "snils",
            "first_name", "last_name", "middle_name", "full_name", "inn",
            "passport", "client_id", "user_id", "customer_id"
    );

    private static final Set<String> PRIVILEGED_PATTERNS = Set.of(
            "role", "admin", "permission", "privilege", "superuser",
            "balance", "limit", "status", "type", "level"
    );

    private static final Set<String> INTERNAL_PATTERNS = Set.of(
            "internal_", "db_", "system_", "_id", "servicer", "bank_code",
            "consent_id", "request_id", "agreement_id", "application_id"
    );

    // Конфигурация задержек для избежания rate limiting
    private static final int BASE_DELAY_MS = 1000;

    public API3_BOScanner() {}

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl();

        System.out.println("(API-3) Запуск сканера OWASP API3 BOPLA...");
        System.out.println("(API-3) Целевой API: Virtual Bank API (OpenBanking Russia v2.1)");

        try {
            // Используем уже полученные клиентские токены
            Map<String, String> userTokens = config.getUserTokens();
            if (userTokens == null || userTokens.isEmpty()) {
                System.err.println("(API-3) Нет доступных токенов для сканирования");
                return vulnerabilities;
            }

            // Берем первый доступный токен
            String username = userTokens.keySet().iterator().next();
            String clientToken = userTokens.get(username);

            System.out.println("(API-3) Используем клиентский токен для пользователя: " + username);

            // Основные тесты
            testPublicEndpointsDataLeakage(baseUrl, vulnerabilities, apiClient);
            delay(BASE_DELAY_MS);

            testProductCatalogueMassAssignment(baseUrl, clientToken, vulnerabilities, apiClient);
            delay(BASE_DELAY_MS);

            testJWKSEndpoint(baseUrl, vulnerabilities, apiClient);
            delay(BASE_DELAY_MS);

            testHealthEndpoint(baseUrl, vulnerabilities, apiClient);

        } catch (Exception e) {
            System.err.println("(API-3) Ошибка при сканировании API3: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("(API-3) Сканирование API3 завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Тестирование публичных эндпоинтов на раскрытие данных
     */
    private void testPublicEndpointsDataLeakage(String baseUrl,
                                                List<Vulnerability> vulnerabilities,
                                                ApiClient apiClient) {
        System.out.println("(API-3) Тестирование публичных эндпоинтов на раскрытие данных...");

        // Тестируем публичные эндпоинты без аутентификации
        testPublicEndpoint(baseUrl + "/products", "GET", "Каталог продуктов", vulnerabilities, apiClient);
        testPublicEndpoint(baseUrl + "/.well-known/jwks.json", "GET", "JWKS endpoint", vulnerabilities, apiClient);
        testPublicEndpoint(baseUrl + "/health", "GET", "Health check", vulnerabilities, apiClient);
        testPublicEndpoint(baseUrl + "/", "GET", "Root endpoint", vulnerabilities, apiClient);
    }

    private void testPublicEndpoint(String url, String method, String endpointName,
                                    List<Vulnerability> vulnerabilities, ApiClient apiClient) {
        System.out.println("(API-3) Проверка публичного эндпоинта: " + endpointName);

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("User-Agent", "Security-Scanner/1.0");

            Object response = apiClient.executeRequest(method, url, null, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                System.out.println("(API-3) " + endpointName + " - Статус: " + apiResponse.getStatusCode());

                if (apiResponse.getStatusCode() == 200) {
                    analyzeResponseForSensitiveData(endpointName, url, method, apiResponse, vulnerabilities);

                    // Дополнительно проверяем массовое присвоение для продуктов
                    if (url.contains("/products")) {
                        testProductMassAssignment(url, apiResponse, vulnerabilities, apiClient);
                    }
                } else if (apiResponse.getStatusCode() == 403) {
                    System.out.println("(API-3) Доступ запрещен к публичному эндпоинту: " + endpointName);
                }
            }
        } catch (Exception e) {
            System.err.println("(API-3) Ошибка при тесте публичного эндпоинта " + endpointName + ": " + e.getMessage());
        }
    }

    /**
     * Тестирование массового присвоения в каталоге продуктов
     */
    private void testProductCatalogueMassAssignment(String baseUrl, String token,
                                                    List<Vulnerability> vulnerabilities,
                                                    ApiClient apiClient) {
        System.out.println("(API-3) Тестирование массового присвоения в каталоге продуктов...");

        // Пытаемся создать продукт с привилегированными полями (должно быть запрещено)
        Map<String, String> productPayloads = new LinkedHashMap<>();
        productPayloads.put("Продукт с административными правами",
                "{\"name\":\"Test Product\",\"type\":\"premium\",\"admin_access\":true,\"special_permissions\":\"all\"}");
        productPayloads.put("Продукт с завышенными лимитами",
                "{\"name\":\"Test\",\"type\":\"loan\",\"max_amount\":999999999,\"interest_rate\":0.1}");
        productPayloads.put("Продукт с внутренними полями",
                "{\"name\":\"Test\",\"type\":\"deposit\",\"internal_id\":\"admin-001\",\"system_flag\":true}");

        for (Map.Entry<String, String> test : productPayloads.entrySet()) {
            String testName = test.getKey();
            String payload = test.getValue();

            System.out.println("(API-3) Тест массового присвоения: " + testName);

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("POST", baseUrl + "/products", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    System.out.println("(API-3) Статус: " + apiResponse.getStatusCode());

                    analyzeMassAssignmentResponse(testName, apiResponse, payload, vulnerabilities);
                }
            } catch (Exception e) {
                System.err.println("(API-3) Ошибка при тесте массового присвоения '" + testName + "': " + e.getMessage());
            }

            delay(BASE_DELAY_MS);
        }
    }

    /**
     * Тестирование массового присвоения через GET параметры
     */
    private void testProductMassAssignment(String url, HttpApiClient.ApiResponse apiResponse,
                                           List<Vulnerability> vulnerabilities, ApiClient apiClient) {
        System.out.println("(API-3) Тестирование массового присвоения через параметры запроса...");

        // Пытаемся использовать привилегированные параметры в GET запросах
        String[] maliciousParams = {
                "?admin=true&type=premium",
                "?internal_access=1&system_mode=debug",
                "?max_limit=9999999&override_restrictions=true"
        };

        for (String param : maliciousParams) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("GET", url + param, null, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse paramResponse = (HttpApiClient.ApiResponse) response;

                    if (paramResponse.getStatusCode() == 200) {
                        // Проверяем, не повлияли ли параметры на ответ
                        String originalBody = apiResponse.getBody();
                        String paramBody = paramResponse.getBody();

                        if (!originalBody.equals(paramBody)) {
                            Vulnerability vuln = createVulnerability(
                                    "Массовое присвоение через параметры запроса",
                                    "Параметры запроса влияют на ответ сервера: " + param + ". " +
                                            "Это может указывать на уязвимость массового присвоения.",
                                    Vulnerability.Severity.MEDIUM,
                                    url + param,
                                    "GET",
                                    paramResponse.getStatusCode(),
                                    "N/A",
                                    "Ответ отличается от стандартного",
                                    "Валидируйте и фильтруйте все входные параметры. Запретите использование внутренних параметров."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("(API-3) УЯЗВИМОСТЬ ОБНАРУЖЕНА: Массовое присвоение через параметры");
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("(API-3) Ошибка при тесте параметров '" + param + "': " + e.getMessage());
            }
        }
    }

    /**
     * Тестирование JWKS endpoint на раскрытие чувствительной информации
     */
    private void testJWKSEndpoint(String baseUrl, List<Vulnerability> vulnerabilities, ApiClient apiClient) {
        System.out.println("(API-3) Тестирование JWKS endpoint...");

        try {
            String jwksUrl = baseUrl + "/.well-known/jwks.json";
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("GET", jwksUrl, null, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() == 200) {
                    String responseBody = apiResponse.getBody();

                    // Проверяем наличие чувствительной информации в JWKS
                    if (responseBody.contains("private") || responseBody.contains("PRIVATE") ||
                            responseBody.contains("d ") || responseBody.contains("p ") ||
                            responseBody.contains("q ") || responseBody.contains("dp ") ||
                            responseBody.contains("dq ") || responseBody.contains("qi ")) {

                        Vulnerability vuln = createVulnerability(
                                "Раскрытие приватных ключей в JWKS",
                                "В JWKS endpoint обнаружены приватные ключи или чувствительные параметры RSA. " +
                                        "Это критическая уязвимость, позволяющая подделывать JWT токены.",
                                Vulnerability.Severity.HIGH,
                                jwksUrl,
                                "GET",
                                apiResponse.getStatusCode(),
                                "N/A",
                                responseBody.length() > 500 ? responseBody.substring(0, 500) + "..." : responseBody,
                                "Немедленно удалите приватные ключи из JWKS. JWKS должен содержать только публичные ключи."
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("(API-3) КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Приватные ключи в JWKS");
                    }

                    // Проверяем на избыточное раскрытие информации
                    analyzeResponseForSensitiveData("JWKS endpoint", jwksUrl, "GET", apiResponse, vulnerabilities);
                }
            }
        } catch (Exception e) {
            System.err.println("(API-3) Ошибка при тесте JWKS endpoint: " + e.getMessage());
        }
    }

    /**
     * Тестирование health endpoint
     */
    private void testHealthEndpoint(String baseUrl, List<Vulnerability> vulnerabilities, ApiClient apiClient) {
        System.out.println("(API-3) Тестирование health endpoint...");

        try {
            String healthUrl = baseUrl + "/health";
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("GET", healthUrl, null, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() == 200) {
                    analyzeResponseForSensitiveData("Health endpoint", healthUrl, "GET", apiResponse, vulnerabilities);

                    // Проверяем, не раскрывает ли health endpoint внутреннюю информацию
                    String responseBody = apiResponse.getBody().toLowerCase();
                    if (responseBody.contains("database") || responseBody.contains("internal") ||
                            responseBody.contains("secret") || responseBody.contains("password") ||
                            responseBody.contains("server_info") || responseBody.contains("version")) {

                        Vulnerability vuln = createVulnerability(
                                "Раскрытие внутренней информации в health endpoint",
                                "Health endpoint раскрывает внутреннюю информацию о системе: " +
                                        extractFoundPatterns(responseBody, Set.of("database", "internal", "secret", "password", "server_info", "version")),
                                Vulnerability.Severity.LOW,
                                healthUrl,
                                "GET",
                                apiResponse.getStatusCode(),
                                "N/A",
                                responseBody,
                                "Ограничьте информацию, возвращаемую health endpoint. Не раскрывайте внутренние детали системы."
                        );
                        vulnerabilities.add(vuln);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-3) Ошибка при тесте health endpoint: " + e.getMessage());
        }
    }

    /**
     * Анализ ответа на наличие чувствительных данных
     */
    private void analyzeResponseForSensitiveData(String endpointName, String url, String method,
                                                 HttpApiClient.ApiResponse apiResponse,
                                                 List<Vulnerability> vulnerabilities) {
        String responseBody = apiResponse.getBody();

        if (responseBody == null || responseBody.trim().isEmpty()) {
            return;
        }

        // Поиск чувствительных полей по паттернам
        List<String> sensitiveFields = findFieldsByPatterns(responseBody, SENSITIVE_PATTERNS);
        List<String> piiFields = findFieldsByPatterns(responseBody, PII_PATTERNS);
        List<String> internalFields = findFieldsByPatterns(responseBody, INTERNAL_PATTERNS);
        List<String> privilegedFields = findFieldsByPatterns(responseBody, PRIVILEGED_PATTERNS);

        // Создание уязвимостей для найденных проблем
        if (!sensitiveFields.isEmpty()) {
            vulnerabilities.add(createSensitiveDataVulnerability(
                    "Раскрытие чувствительных данных в " + endpointName,
                    "Обнаружены критические чувствительные поля: " + sensitiveFields,
                    Vulnerability.Severity.HIGH,
                    url, method, apiResponse, sensitiveFields
            ));
            System.out.println("(API-3) ОБНАРУЖЕНО: Чувствительные данные в " + endpointName + ": " + sensitiveFields);
        }

        if (!piiFields.isEmpty()) {
            vulnerabilities.add(createSensitiveDataVulnerability(
                    "Раскрытие PII данных в " + endpointName,
                    "Обнаружены персональные данные (PII): " + piiFields,
                    Vulnerability.Severity.MEDIUM,
                    url, method, apiResponse, piiFields
            ));
            System.out.println("(API-3) ОБНАРУЖЕНО: PII данные в " + endpointName + ": " + piiFields);
        }

        if (!internalFields.isEmpty()) {
            vulnerabilities.add(createSensitiveDataVulnerability(
                    "Раскрытие внутренней информации в " + endpointName,
                    "Обнаружены внутренние технические поля: " + internalFields,
                    Vulnerability.Severity.LOW,
                    url, method, apiResponse, internalFields
            ));
            System.out.println("(API-3) ОБНАРУЖЕНО: Внутренняя информация в " + endpointName + ": " + internalFields);
        }

        if (sensitiveFields.isEmpty() && piiFields.isEmpty() &&
                internalFields.isEmpty() && privilegedFields.isEmpty()) {
            System.out.println("(API-3) Чувствительные данные не обнаружены в " + endpointName);
        }
    }

    /**
     * Анализ ответа на уязвимости массового присвоения
     */
    private void analyzeMassAssignmentResponse(String testName, HttpApiClient.ApiResponse apiResponse,
                                               String payload, List<Vulnerability> vulnerabilities) {
        if (apiResponse.getStatusCode() == 200 || apiResponse.getStatusCode() == 201) {
            String responseBody = apiResponse.getBody().toLowerCase();

            // Проверяем, принял ли сервер подозрительные поля
            boolean acceptedMaliciousFields =
                    responseBody.contains("admin") ||
                            responseBody.contains("internal") ||
                            responseBody.contains("system") ||
                            responseBody.contains("999999999") ||
                            responseBody.contains("special_permissions");

            if (acceptedMaliciousFields) {
                Vulnerability vuln = createVulnerability(
                        "Массовое присвоение - " + testName,
                        "Сервер принял привилегированные поля в запросе. " +
                                "Это указывает на отсутствие proper server-side валидации.",
                        Vulnerability.Severity.HIGH,
                        "/products",
                        "POST",
                        apiResponse.getStatusCode(),
                        payload,
                        apiResponse.getBody(),
                        "Сервер должен отклонять запросы с неразрешенными полями. " +
                                "Реализуйте whitelist валидацию и используйте отдельные DTO для клиентских запросов."
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-3) УЯЗВИМОСТЬ ОБНАРУЖЕНА: " + testName);
            }
        } else if (apiResponse.getStatusCode() == 422 || apiResponse.getStatusCode() == 400) {
            System.out.println("(API-3) Защита работает: сервер вернул ошибку валидации");
        } else if (apiResponse.getStatusCode() == 403) {
            System.out.println("(API-3) Доступ запрещен - это ожидаемое поведение");
        } else if (apiResponse.getStatusCode() == 405) {
            System.out.println("(API-3) Метод не разрешен - это ожидаемое поведение");
        }
    }

    /**
     * Метод для добавления задержки между запросами
     */
    private void delay(int milliseconds) {
        try {
            Thread.sleep(milliseconds);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private Vulnerability createVulnerability(String title, String description,
                                              Vulnerability.Severity severity,
                                              String endpoint, String method, int statusCode,
                                              String requestBody, String responseBody,
                                              String recommendation) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API3:2023 - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API3_BOPLA);
        vuln.setEndpoint(endpoint);
        vuln.setMethod(method);
        vuln.setStatusCode(statusCode);

        String evidence = String.format(
                "Эндпоинт: %s %s\n" +
                        "HTTP Статус: %d\n" +
                        "Тело запроса: %s\n" +
                        "Тело ответа: %s",
                method, endpoint, statusCode,
                requestBody != null ? requestBody : "N/A",
                responseBody.length() > 500 ? responseBody.substring(0, 500) + "..." : responseBody
        );
        vuln.setEvidence(evidence);

        vuln.setRecommendations(Arrays.asList(
                recommendation,
                "Реализуйте строгую схему валидации для всех входных данных",
                "Используйте whitelist подход для разрешенных полей",
                "Разделяйте DTO для клиентов и внутреннего использования"
        ));

        return vuln;
    }

    private Vulnerability createSensitiveDataVulnerability(String title, String description,
                                                           Vulnerability.Severity severity,
                                                           String endpoint, String method,
                                                           HttpApiClient.ApiResponse apiResponse,
                                                           List<String> exposedFields) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API3:2023 - " + title);
        vuln.setDescription(description + " в ответе API");
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API3_BOPLA);
        vuln.setEndpoint(endpoint);
        vuln.setMethod(method);
        vuln.setStatusCode(apiResponse.getStatusCode());

        String evidence = String.format(
                "Эндпоинт: %s %s\n" +
                        "HTTP Статус: %d\n" +
                        "Обнаруженные поля: %s\n" +
                        "Фрагмент ответа: %s",
                method, endpoint, apiResponse.getStatusCode(),
                exposedFields,
                apiResponse.getBody().length() > 300 ? apiResponse.getBody().substring(0, 300) + "..." : apiResponse.getBody()
        );
        vuln.setEvidence(evidence);

        vuln.setRecommendations(Arrays.asList(
                "Маскируйте чувствительные данные в ответах API",
                "Используйте DTO для фильтрации полей",
                "Реализуйте принцип минимальных привилегий",
                "Настройте фильтрацию полей в сериализации"
        ));

        return vuln;
    }

    @Override
    public String getName() {
        return "OWASP API3 - Broken Object Property Level Authorization Scanner";
    }

    private List<String> findFieldsByPatterns(String json, Set<String> patterns) {
        List<String> results = new ArrayList<>();
        if (json == null || json.trim().isEmpty()) {
            return results;
        }

        String lowerJson = json.toLowerCase();

        for (String pattern : patterns) {
            java.util.regex.Pattern regex = java.util.regex.Pattern.compile("\"([^\"]*" + pattern + "[^\"]*)\"\\s*:");
            java.util.regex.Matcher matcher = regex.matcher(lowerJson);

            while (matcher.find()) {
                String fieldName = matcher.group(1);
                if (!results.contains(fieldName)) {
                    results.add(fieldName);
                }
            }
        }

        return results;
    }

    private String extractFoundPatterns(String text, Set<String> patterns) {
        List<String> found = new ArrayList<>();
        String lowerText = text.toLowerCase();

        for (String pattern : patterns) {
            if (lowerText.contains(pattern)) {
                found.add(pattern);
            }
        }

        return found.toString();
    }
}