package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.ApiResponse;
import core.AuthManager;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import java.util.*;
import java.util.stream.Collectors;

public class API6_BusinessFlowScanner implements SecurityScanner {
    private static final Set<String> SENSITIVE_TAGS = Set.of(
            "4 Переводы",
            "3 Согласия на переводы",
            "6 Договоры с продуктами",
            "2 Счета и балансы",
            "1 Согласия на доступ к счетам"
    );

    private static final Set<String> CRITICAL_OPERATIONS = Set.of(
            "POST", "PUT", "DELETE"
    );

    // Правильные тестовые параметры из спецификации API
    private static final Map<String, String> TEST_PARAMETERS = Map.of(
            "account_id", "acc-1010",
            "payment_id", "payment-123",
            "consent_id", "consent-69e75facabba",
            "agreement_id", "agreement-123",
            "product_id", "prod-vb-deposit-001",
            "request_id", "req-123",
            "client_id", "team172-1"
    );

    @Override
    public String getName() {
        return "OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-6) Сканирование уязвимостей Unrestricted Access to Sensitive Business Flows...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-6) Ошибка: передан не OpenAPI объект");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        String baseUrl = config.getTargetBaseUrl();
        String password = config.getPassword();

        if (password == null || password.isEmpty()) {
            System.err.println("(API-6) Пароль не задан в конфигурации. Business Flow сканер пропущен.");
            return vulnerabilities;
        }

        try {
            // ИСПРАВЛЕНО: Используем правильный метод для получения токенов
            System.out.println("(API-6) Получение токенов для команды через AuthManager...");

            // Настраиваем конфиг для получения токенов
            ScanConfig tokenConfig = new ScanConfig();
            tokenConfig.setBankBaseUrl(baseUrl);
            tokenConfig.setClientSecret(password);
            tokenConfig.setClientId(config.getClientId() != null ? config.getClientId() :"***REMOVED***");
            tokenConfig.setBankId("team172");

            Map<String, String> tokens = AuthManager.getTokensForScanning(tokenConfig);

            if (tokens.isEmpty()) {
                System.err.println("(API-6) Не удалось получить токены для Business Flow теста.");
                return vulnerabilities;
            }

            // Ищем банковский токен или берем первый доступный
            String token = null;
            if (tokens.containsKey("bank")) {
                token = tokens.get("bank");
                System.out.println("(API-6) Используется банковский токен для тестирования бизнес-процессов");
            } else {
                token = tokens.values().iterator().next();
                System.out.println("(API-6) Используется клиентский токен для тестирования бизнес-процессов");
            }

            // 5.6.1: Идентификация ключевых бизнес-процессов из OpenAPI
            System.out.println("(API-6) Идентификация бизнес-процессов из OpenAPI спецификации...");
            Map<String, BusinessFlowEndpoint> businessEndpoints = identifyBusinessEndpointsFromSpec(openAPI);

            // 5.6.2: Тестирование возможности автоматизации
            System.out.println("(API-6) Тестирование автоматизации операций...");
            testAutomationCapabilities(baseUrl, token, apiClient, businessEndpoints, vulnerabilities);

            // 5.6.3: Проверка ограничений на частоту
            System.out.println("(API-6) Проверка ограничений частоты...");
            testRateLimiting(baseUrl, token, apiClient, businessEndpoints, vulnerabilities);

            // 5.6.4: Анализ защиты от автоматизации
            System.out.println("(API-6) Анализ защиты от автоматизации...");
            testAutomationProtection(baseUrl, token, apiClient, businessEndpoints, vulnerabilities);

            // 5.6.5: Тестирование обходов бизнес-логики
            System.out.println("(API-6) Тестирование обходов бизнес-логики...");
            testBusinessLogicBypass(baseUrl, token, apiClient, businessEndpoints, vulnerabilities);

            // 5.6.6: Проверка целостности бизнес-процессов
            System.out.println("(API-6) Проверка целостности процессов...");
            testProcessIntegrity(baseUrl, token, apiClient, businessEndpoints, vulnerabilities);

        } catch (Exception e) {
            System.err.println("(API-6) Ошибка в Business Flow сканере: " + e.getMessage());
            if (isDebugMode()) {
                e.printStackTrace();
            }
        }

        System.out.println("(API-6) Business Flow сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    // 5.6.1: Идентификация ключевых бизнес-процессов в API
    private Map<String, BusinessFlowEndpoint> identifyBusinessEndpointsFromSpec(OpenAPI openAPI) {
        Map<String, BusinessFlowEndpoint> businessEndpoints = new HashMap<>();
        Map<String, PathItem> paths = openAPI.getPaths();
        if (paths == null) {
            System.err.println("(API-6) В OpenAPI спецификации не найдены пути");
            return businessEndpoints;
        }

        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            // Пропускаем технические эндпоинты
            if (isTechnicalEndpoint(path)) {
                continue;
            }

            Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();
            for (Map.Entry<PathItem.HttpMethod, Operation> opEntry : operations.entrySet()) {
                PathItem.HttpMethod httpMethod = opEntry.getKey();
                Operation operation = opEntry.getValue();
                if (isSensitiveBusinessFlow(path, httpMethod.name(), operation)) {
                    BusinessFlowEndpoint endpoint = createBusinessFlowEndpoint(path, httpMethod.name(), operation);
                    String endpointKey = path + ":" + httpMethod.name();
                    businessEndpoints.put(endpointKey, endpoint);
                    System.out.println("(API-6) Идентифицирован бизнес-процесс: " +
                            httpMethod.name() + " " + path + " - " + endpoint.getDescription() +
                            " [Критичность: " + endpoint.getCriticality() + "]");
                }
            }
        }
        return businessEndpoints;
    }

    private boolean isTechnicalEndpoint(String path) {
        return path.contains("/.well-known") ||
                path.contains("/health") ||
                path.equals("/") ||
                path.contains("/products") || // Каталог продуктов - публичная информация
                path.contains("/auth/login") || // Аутентификация - отдельная категория
                path.contains("/auth/bank-token");
    }

    private boolean isSensitiveBusinessFlow(String path, String method, Operation operation) {
        // Пропускаем GET запросы к нечувствительным данным (кроме критичных)
        if ("GET".equals(method) && !isCriticalGetOperation(path, operation)) {
            return false;
        }

        // Критические операции всегда считаем чувствительными
        if (CRITICAL_OPERATIONS.contains(method)) {
            return true;
        }

        // Проверяем теги операции
        if (operation.getTags() != null) {
            for (String tag : operation.getTags()) {
                if (SENSITIVE_TAGS.contains(tag)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isCriticalGetOperation(String path, Operation operation) {
        // GET операции к платежам, согласиям и договорам считаем критичными
        return path.contains("/payments") ||
                path.contains("/payment-consents") ||
                path.contains("/product-agreements") ||
                path.contains("/account-consents");
    }

    private BusinessFlowEndpoint createBusinessFlowEndpoint(String path, String method, Operation operation) {
        BusinessFlowEndpoint endpoint = new BusinessFlowEndpoint();
        endpoint.setPath(path);
        endpoint.setMethod(method);
        endpoint.setOperation(operation);
        endpoint.setRequiresParameters(path.contains("{"));

        // Определяем критичность на основе пути, метода и тегов
        if (path.contains("/payments") && "POST".equals(method)) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.HIGH);
            endpoint.setDescription("Создание платежей - критичный финансовый процесс");
        } else if (path.contains("/payment-consents") && "POST".equals(method)) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.HIGH);
            endpoint.setDescription("Создание согласий на платежи - критичный процесс");
        } else if (path.contains("/product-agreements") && "POST".equals(method)) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.HIGH);
            endpoint.setDescription("Открытие продуктовых договоров - доходный процесс");
        } else if (path.contains("/account-consents") && "POST".equals(method)) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.HIGH);
            endpoint.setDescription("Создание согласий на доступ - критичный процесс");
        } else if (CRITICAL_OPERATIONS.contains(method) &&
                (path.contains("/accounts") || path.contains("/agreements"))) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.MEDIUM);
            endpoint.setDescription("Управление ресурсами - бизнес-процесс");
        } else if (path.contains("/payments") || path.contains("/payment-consents")) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.MEDIUM);
            endpoint.setDescription("Операции с платежами - финансовый процесс");
        } else {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.LOW);
            endpoint.setDescription("Бизнес-процесс: " +
                    (operation.getSummary() != null ? operation.getSummary() : path));
        }

        return endpoint;
    }

    // 5.6.2: Тестирование возможности автоматизации бизнес-операций
    private void testAutomationCapabilities(String baseUrl, String token, ApiClient apiClient,
                                            Map<String, BusinessFlowEndpoint> endpoints,
                                            List<Vulnerability> vulnerabilities) {
        // Тестируем все высококритичные и среднекритичные эндпоинты
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH ||
                        e.getCriticality() == BusinessFlowEndpoint.Criticality.MEDIUM)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        System.out.println("(API-6) Тестирование автоматизации для " + testableEndpoints.size() + " эндпоинтов");

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testEndpointAutomation(baseUrl, token, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testEndpointAutomation(String baseUrl, String token, ApiClient apiClient,
                                        BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            String testPayload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            int successfulCalls = 0;
            int totalCalls = 3;

            for (int i = 0; i < totalCalls; i++) {
                System.out.println("(API-6) Автоматизация тест " + (i+1) + "/" + totalCalls + ": " + endpoint.getMethod() + " " + url);
                Object response = apiClient.executeRequest(endpoint.getMethod(), url, testPayload, headers);
                if (isSuccessfulResponse(response)) {
                    successfulCalls++;
                    System.out.println("(API-6) ✓ Успешный запрос: " + endpoint.getMethod() + " " + url);
                } else {
                    if (response instanceof core.HttpApiClient.ApiResponse) {
                        core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                        System.out.println("(API-6) Код ответа: " + apiResponse.getStatusCode());
                        if (apiResponse.getBody() != null) {  // Изменено с getResponseBody() на getBody()
                            System.out.println("(API-6) Тело ответа: " + apiResponse.getBody().substring(0, Math.min(200, apiResponse.getBody().length())) + "...");
                        }
                    }
                }

                try {
                    Thread.sleep(500);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            // Если все запросы успешны - возможна автоматизация
            if (successfulCalls == totalCalls) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Неограниченная автоматизация бизнес-процесса",
                        "Эндпоинт " + endpoint.getPath() + " позволяет выполнять " + successfulCalls +
                                " последовательных операций без ограничений. Возможна полная автоматизация чувствительного бизнес-процесса: " +
                                endpoint.getDescription() + ". Доказательство: успешное выполнение " + totalCalls +
                                " последовательных запросов без блокировок.",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-6) УЯЗВИМОСТЬ: Обнаружена возможность автоматизации " + endpoint.getPath());
            }
        } catch (Exception e) {
            System.err.println("(API-6) Ошибка при тестировании автоматизации " + endpoint.getPath() + ": " + e.getMessage());
        }
    }

    // 5.6.3: Проверка ограничений на частоту бизнес-операций
    private void testRateLimiting(String baseUrl, String token, ApiClient apiClient,
                                  Map<String, BusinessFlowEndpoint> endpoints,
                                  List<Vulnerability> vulnerabilities) {
        // Тестируем только высококритичные эндпоинты
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .limit(3) // Ограничиваем количество тестируемых эндпоинтов
                .collect(Collectors.toList());

        System.out.println("(API-6) Rate limiting тест для " + testableEndpoints.size() + " эндпоинтов");

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testEndpointRateLimiting(baseUrl, token, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testEndpointRateLimiting(String baseUrl, String token, ApiClient apiClient,
                                          BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            String testPayload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            List<Integer> responseCodes = new ArrayList<>();
            int rapidRequests = 5;

            System.out.println("(API-6) Rate limiting тест для: " + endpoint.getMethod() + " " + url);

            for (int i = 0; i < rapidRequests; i++) {
                Object response = apiClient.executeRequest(endpoint.getMethod(), url, testPayload, headers);
                if (response instanceof core.HttpApiClient.ApiResponse) {
                    core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                    responseCodes.add(apiResponse.getStatusCode());
                    System.out.println("(API-6) Rate limiting тест " + (i+1) + "/" + rapidRequests + ": " + apiResponse.getStatusCode());
                }

                try {
                    Thread.sleep(100); // Минимальная пауза для имитации быстрых запросов
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            boolean hasRateLimiting = responseCodes.stream().anyMatch(code -> code == 429);
            int successCount = (int) responseCodes.stream()
                    .filter(code -> code >= 200 && code < 300)
                    .count();

            // Если нет rate limiting и есть успешные запросы - уязвимость
            if (!hasRateLimiting && successCount > 0) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Отсутствие rate limiting для бизнес-операций",
                        "Критичный бизнес-процесс " + endpoint.getPath() + " не имеет ограничений частоты запросов. " +
                                "Успешно выполнено " + successCount + "/" + rapidRequests + " запросов подряд. " +
                                "Возможны DDoS-атаки на бизнес-процессы и автоматическая эксплуатация. " +
                                "Доказательство: выполнено " + rapidRequests + " быстрых запросов без получения кода 429 (Too Many Requests).",
                        successCount >= 3 ? Vulnerability.Severity.HIGH : Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-6) УЯЗВИМОСТЬ: Отсутствие rate limiting для " + endpoint.getPath());
            }
        } catch (Exception e) {
            System.err.println("(API-6) Ошибка при тестировании rate limiting " + endpoint.getPath() + ": " + e.getMessage());
        }
    }

    // 5.6.4: Анализ защиты от автоматизации
    private void testAutomationProtection(String baseUrl, String token, ApiClient apiClient,
                                          Map<String, BusinessFlowEndpoint> endpoints,
                                          List<Vulnerability> vulnerabilities) {
        // Анализируем все высококритичные эндпоинты
        for (BusinessFlowEndpoint endpoint : endpoints.values()) {
            if (endpoint.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH) {
                analyzeEndpointProtection(endpoint, vulnerabilities);
                testIdempotencyProtection(baseUrl, token, apiClient, endpoint, vulnerabilities);
            }
        }
    }

    private void analyzeEndpointProtection(BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        // Анализируем описание и параметры операции на наличие защиты
        Operation operation = endpoint.getOperation();
        String description = operation.getDescription() != null ? operation.getDescription().toLowerCase() : "";
        boolean hasProtectionIndicators =
                description.contains("consent") ||
                        description.contains("authorization") ||
                        description.contains("authentication") ||
                        description.contains("limit") ||
                        description.contains("validation") ||
                        description.contains("approval") ||
                        description.contains("confirm");

        List<Parameter> parameters = operation.getParameters();
        boolean hasSecurityParameters = parameters != null && parameters.stream()
                .anyMatch(p -> p.getName().toLowerCase().contains("consent") ||
                        p.getName().toLowerCase().contains("auth") ||
                        p.getName().toLowerCase().contains("token") ||
                        p.getName().toLowerCase().contains("signature"));

        if (!hasProtectionIndicators && !hasSecurityParameters) {
            Vulnerability vuln = createBusinessFlowVulnerability(
                    endpoint.getPath(),
                    "Недостаточная документация защиты бизнес-процесса",
                    "Критичный бизнес-процесс " + endpoint.getPath() + " не имеет явных указаний на механизмы защиты в документации. " +
                            "Отсутствуют упоминания о согласиях, аутентификации, лимитах или валидации. " +
                            "Рекомендуется явно документировать требования безопасности для критических операций.",
                    Vulnerability.Severity.LOW
            );
            vulnerabilities.add(vuln);
            System.out.println("(API-6) УЯЗВИМОСТЬ: Недостаточная документация защиты для " + endpoint.getPath());
        }
    }

    private void testIdempotencyProtection(String baseUrl, String token, ApiClient apiClient,
                                           BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        // Тестируем защиту от повторных операций (идемпотентность)
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            String testPayload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            // Первый запрос
            Object response1 = apiClient.executeRequest(endpoint.getMethod(), url, testPayload, headers);
            // Немедленный второй идентичный запрос
            Object response2 = apiClient.executeRequest(endpoint.getMethod(), url, testPayload, headers);

            boolean firstSuccess = isSuccessfulResponse(response1);
            boolean secondSuccess = isSuccessfulResponse(response2);

            // Если оба запроса успешны - возможна проблема с идемпотентностью
            if (firstSuccess && secondSuccess) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Отсутствие защиты от повторных операций",
                        "Эндпоинт " + endpoint.getPath() + " не имеет защиты от повторного выполнения одинаковых операций. " +
                                "Возможны дублирующиеся транзакции при повторных запросах. " +
                                "Доказательство: два идентичных последовательных запроса выполнены успешно.",
                        Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-6) УЯЗВИМОСТЬ: Отсутствие защиты от повторных операций для " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Игнорируем ошибки - это нормально для тестовых запросов
        }
    }

    // 5.6.5: Тестирование обходов бизнес-логики
    private void testBusinessLogicBypass(String baseUrl, String token, ApiClient apiClient,
                                         Map<String, BusinessFlowEndpoint> endpoints,
                                         List<Vulnerability> vulnerabilities) {
        // Тестируем высококритичные эндпоинты
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testBusinessLogicValidation(baseUrl, token, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testBusinessLogicValidation(String baseUrl, String token, ApiClient apiClient,
                                             BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        // Тестируем различные сценарии обхода бизнес-логики
        testNegativeValues(baseUrl, token, apiClient, endpoint, vulnerabilities);
        testBoundaryValues(baseUrl, token, apiClient, endpoint, vulnerabilities);
        testInvalidDataTypes(baseUrl, token, apiClient, endpoint, vulnerabilities);
        testMissingRequiredFields(baseUrl, token, apiClient, endpoint, vulnerabilities);
    }

    private void testNegativeValues(String baseUrl, String token, ApiClient apiClient,
                                    BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            String negativePayload = createNegativeValuePayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, negativePayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Обход валидации отрицательных значений",
                        "Эндпоинт " + endpoint.getPath() + " принимает отрицательные значения без должной валидации. " +
                                "Возможны финансовые манипуляции и обход бизнес-логики. " +
                                "Доказательство: успешная обработка запроса с отрицательным значением.",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-6) УЯЗВИМОСТЬ: Обход валидации отрицательных значений в " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение - должна быть ошибка валидации
        }
    }

    private void testBoundaryValues(String baseUrl, String token, ApiClient apiClient,
                                    BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            String boundaryPayload = createBoundaryValuePayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, boundaryPayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Обход проверки граничных значений",
                        "Эндпоинт " + endpoint.getPath() + " принимает экстремально большие значения без валидации. " +
                                "Отсутствует проверка бизнес-логики на разумные лимиты. " +
                                "Доказательство: успешная обработка запроса с экстремальным значением.",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-6) УЯЗВИМОСТЬ: Обход проверки граничных значений в " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение
        }
    }

    private void testInvalidDataTypes(String baseUrl, String token, ApiClient apiClient,
                                      BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            String invalidTypePayload = createInvalidDataTypePayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, invalidTypePayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Обход валидации типов данных",
                        "Эндпоинт " + endpoint.getPath() + " принимает неверные типы данных без должной валидации. " +
                                "Возможны ошибки обработки и обход бизнес-логики. " +
                                "Доказательство: успешная обработка запроса с неверным типом данных.",
                        Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-6) УЯЗВИМОСТЬ: Обход валидации типов данных в " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение
        }
    }

    private void testMissingRequiredFields(String baseUrl, String token, ApiClient apiClient,
                                           BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            String minimalPayload = createMinimalPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, minimalPayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Обход проверки обязательных полей",
                        "Эндпоинт " + endpoint.getPath() + " обрабатывает запросы без обязательных полей. " +
                                "Возможны операции с неполными данными и обход бизнес-логики. " +
                                "Доказательство: успешная обработка запроса с минимальным набором полей.",
                        Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-6) УЯЗВИМОСТЬ: Обход проверки обязательных полей в " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение
        }
    }

    // 5.6.6: Проверка целостности бизнес-процессов
    private void testProcessIntegrity(String baseUrl, String token, ApiClient apiClient,
                                      Map<String, BusinessFlowEndpoint> endpoints,
                                      List<Vulnerability> vulnerabilities) {
        analyzeProcessSequences(endpoints, vulnerabilities);
        testMissingDependencies(baseUrl, token, apiClient, endpoints, vulnerabilities);
        testDirectAccessToOperations(baseUrl, token, apiClient, endpoints, vulnerabilities);
    }

    private void analyzeProcessSequences(Map<String, BusinessFlowEndpoint> endpoints,
                                         List<Vulnerability> vulnerabilities) {
        // Проверяем обязательные последовательности операций
        boolean hasPaymentEndpoint = endpoints.values().stream()
                .anyMatch(e -> e.getPath().contains("/payments") && "POST".equals(e.getMethod()));
        boolean hasPaymentConsentEndpoint = endpoints.values().stream()
                .anyMatch(e -> e.getPath().contains("/payment-consents/request") && "POST".equals(e.getMethod()));

        // Если есть платежи, но нет явного требования согласий - возможна проблема
        if (hasPaymentEndpoint && !hasPaymentConsentEndpoint) {
            Vulnerability vuln = createBusinessFlowVulnerability(
                    "/payments",
                    "Возможное нарушение целостности процесса платежей",
                    "Обнаружены эндпоинты платежей без явного требования согласий в документации. " +
                            "Возможно нарушение обязательной последовательности: согласие → платеж. " +
                            "Рекомендуется явно документировать требования к последовательности операций.",
                    Vulnerability.Severity.MEDIUM
            );
            vulnerabilities.add(vuln);
            System.out.println("(API-6) УЯЗВИМОСТЬ: Возможное нарушение целостности процесса платежей");
        }
    }

    private void testMissingDependencies(String baseUrl, String token, ApiClient apiClient,
                                         Map<String, BusinessFlowEndpoint> endpoints,
                                         List<Vulnerability> vulnerabilities) {
        // Тестируем вызов платежей без согласий
        List<BusinessFlowEndpoint> paymentEndpoints = endpoints.values().stream()
                .filter(e -> e.getPath().contains("/payments") && "POST".equals(e.getMethod()))
                .collect(Collectors.toList());

        for (BusinessFlowEndpoint endpoint : paymentEndpoints) {
            testPaymentWithoutConsent(baseUrl, token, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testPaymentWithoutConsent(String baseUrl, String token, ApiClient apiClient,
                                           BusinessFlowEndpoint endpoint,
                                           List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            // Специально не добавляем consent headers
            String paymentPayload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, paymentPayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Нарушение целостности процесса платежей",
                        "Возможно создание платежа без предварительного согласия. " +
                                "Нарушена обязательная последовательность бизнес-процесса: согласие → платеж. " +
                                "Доказательство: успешное создание платежа без заголовков согласия.",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-6) УЯЗВИМОСТЬ: Нарушение целостности процесса платежей");
            }
        } catch (Exception e) {
            // Ожидаемое поведение - должна быть ошибка из-за отсутствия согласия
        }
    }

    private void testDirectAccessToOperations(String baseUrl, String token, ApiClient apiClient,
                                              Map<String, BusinessFlowEndpoint> endpoints,
                                              List<Vulnerability> vulnerabilities) {
        // Тестируем прямые вызовы операций, которые должны требовать предварительных шагов
        List<BusinessFlowEndpoint> criticalEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        for (BusinessFlowEndpoint endpoint : criticalEndpoints) {
            testDirectEndpointAccess(baseUrl, token, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testDirectEndpointAccess(String baseUrl, String token, ApiClient apiClient,
                                          BusinessFlowEndpoint endpoint,
                                          List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            String payload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, payload, headers);
            if (isSuccessfulResponse(response)) {
                // Если операция выполняется без дополнительных проверок - возможна проблема
                System.out.println("(API-6) Прямой доступ возможен: " + endpoint.getMethod() + " " + url);
                // Для особо критичных операций создаем уязвимость
                if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
                    Vulnerability vuln = createBusinessFlowVulnerability(
                            endpoint.getPath(),
                            "Прямой доступ к критичным операциям",
                            "Критичная операция " + endpoint.getPath() + " доступна для прямого вызова без дополнительных проверок. " +
                                    "Возможно нарушение бизнес-процессов и обход обязательных последовательностей.",
                            Vulnerability.Severity.MEDIUM
                    );
                    vulnerabilities.add(vuln);
                }
            }
        } catch (Exception e) {
            // Ожидаемое поведение для некоторых операций
        }
    }

    // ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========
    private String buildTestUrl(String baseUrl, String path) {
        if (!path.contains("{")) {
            return baseUrl + path;
        }
        // Заменяем параметры тестовыми значениями
        String resolvedPath = path;
        for (Map.Entry<String, String> param : TEST_PARAMETERS.entrySet()) {
            resolvedPath = resolvedPath.replace("{" + param.getKey() + "}", param.getValue());
        }
        return baseUrl + resolvedPath;
    }

    private Map<String, String> createAuthHeaders(String token, String requestingBank) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json");
        // Используем правильный X-Requesting-Bank из конфигурации
        headers.put("X-Requesting-Bank", requestingBank); // Это должен быть team172 (без суффикса)
        return headers;
    }

    private boolean isSuccessfulResponse(Object response) {
        if (response instanceof core.HttpApiClient.ApiResponse) {
            core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
            int statusCode = apiResponse.getStatusCode();
            return statusCode >= 200 && statusCode < 300;
        }
        return false;
    }

    private String createSpecificTestPayload(BusinessFlowEndpoint endpoint) {
        String path = endpoint.getPath();
        String method = endpoint.getMethod();
        // Реальные payload из спецификации API
        if (path.contains("/payment-consents/request") && "POST".equals(method)) {
            return "{\"requesting_bank\":\"team172\",\"client_id\":\"team172-1\",\"debtor_account\":\"acc-1010\",\"amount\":100.00,\"currency\":\"RUB\",\"consent_type\":\"single_use\"}";
        } else if (path.contains("/payments") && "POST".equals(method)) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"},\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1010\"},\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1011\"}}}}";
        } else if (path.contains("/product-agreements") && "POST".equals(method)) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":1000.00}";
        } else if (path.contains("/account-consents/request") && "POST".equals(method)) {
            return "{\"client_id\":\"team172-1\",\"permissions\":[\"ReadAccountsDetail\",\"ReadBalances\"],\"reason\":\"Тестовый запрос\",\"requesting_bank\":\"team172\"}";
        } else if (path.contains("/accounts") && "POST".equals(method)) {
            return "{\"account_type\":\"checking\",\"initial_balance\":100.00}";
        } else {
            return "{}";
        }
    }

    private String createNegativeValuePayload(BusinessFlowEndpoint endpoint) {
        if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"-1000.00\",\"currency\":\"RUB\"},\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1010\"},\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1011\"}}}}";
        } else if (endpoint.getPath().contains("/product-agreements") && "POST".equals(endpoint.getMethod())) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":-1000}";
        }
        return "{\"amount\": -1000}";
    }

    private String createBoundaryValuePayload(BusinessFlowEndpoint endpoint) {
        if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"999999999999.00\",\"currency\":\"RUB\"},\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1010\"},\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1011\"}}}}";
        } else if (endpoint.getPath().contains("/product-agreements") && "POST".equals(endpoint.getMethod())) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":999999999999}";
        }
        return "{\"amount\": 999999999999}";
    }

    private String createInvalidDataTypePayload(BusinessFlowEndpoint endpoint) {
        if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"INVALID\",\"currency\":\"RUB\"},\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1010\"},\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1011\"}}}}";
        } else if (endpoint.getPath().contains("/product-agreements") && "POST".equals(endpoint.getMethod())) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":\"INVALID\"}";
        }
        return "{\"amount\": \"INVALID\"}";
    }

    private String createMinimalPayload(BusinessFlowEndpoint endpoint) {
        // Минимальный payload с только самыми базовыми полями
        if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"}}}}";
        } else if (endpoint.getPath().contains("/product-agreements") && "POST".equals(endpoint.getMethod())) {
            return "{\"product_id\":\"prod-vb-deposit-001\"}";
        }
        return "{}";
    }

    private Vulnerability createBusinessFlowVulnerability(String endpoint, String title,
                                                          String description, Vulnerability.Severity severity) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API6:2023 - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API6_BUSINESS_FLOW);
        vuln.setEndpoint(endpoint);
        vuln.setMethod("POST");
        List<String> recommendations = Arrays.asList(
                "Внедрить rate limiting для чувствительных бизнес-операций",
                "Реализовать проверку последовательности шагов бизнес-процесса",
                "Добавить строгую валидацию бизнес-логики на стороне сервера",
                "Внедрить мониторинг аномальной активности бизнес-процессов",
                "Реализовать лимиты на операции по сумме и частоте",
                "Использовать обязательные подтверждения для критических операций",
                "Документировать требования безопасности для всех бизнес-процессов",
                "Внедрить механизмы идемпотентности для финансовых операций",
                "Реализовать проверку обязательных полей и зависимостей"
        );
        vuln.setRecommendations(recommendations);
        return vuln;
    }

    private static boolean isDebugMode() {
        return System.getProperty("debug") != null ||
                Arrays.asList(System.getenv().getOrDefault("JAVA_OPTS", "").split(" ")).contains("-Ddebug");
    }

    // Внутренний класс для представления бизнес-эндпоинта
    private static class BusinessFlowEndpoint {
        enum Criticality { LOW, MEDIUM, HIGH }

        private String path;
        private String method;
        private Operation operation;
        private Criticality criticality;
        private String description;
        private boolean requiresParameters;

        // Getters and setters
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public Operation getOperation() { return operation; }
        public void setOperation(Operation operation) { this.operation = operation; }
        public Criticality getCriticality() { return criticality; }
        public void setCriticality(Criticality criticality) { this.criticality = criticality; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public boolean isRequiresParameters() { return requiresParameters; }
        public void setRequiresParameters(boolean requiresParameters) { this.requiresParameters = requiresParameters; }
    }
}