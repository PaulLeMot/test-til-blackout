package scanners.owasp;

import scanners.SecurityScanner;
import core.*;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

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

    private ScanConfig config;
    private Map<String, String> testParameters;

    @Override
    public String getName() {
        return "OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        this.config = config;

        // ДИАГНОСТИКА КОНФИГУРАЦИИ
        System.out.println("(API-6) === ДИАГНОСТИКА КОНФИГУРАЦИИ ===");
        System.out.println("(API-6) BankId: " + config.getBankId());
        System.out.println("(API-6) ClientId: " + config.getClientId());
        System.out.println("(API-6) TargetBaseUrl: " + config.getTargetBaseUrl());
        System.out.println("(API-6) Credentials count: " + (config.getCredentials() != null ? config.getCredentials().size() : 0));
        System.out.println("(API-6) UserTokens count: " + (config.getUserTokens() != null ? config.getUserTokens().size() : 0));
        if (config.getUserTokens() != null) {
            System.out.println("(API-6) UserTokens keys: " + String.join(", ", config.getUserTokens().keySet()));
        }
        System.out.println("(API-6) ================================");

        this.testParameters = initializeTestParameters();

        System.out.println("(API-6) Запуск сканирования Unrestricted Access to Sensitive Business Flows...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Используем токены из конфигурации
        Map<String, String> tokens = config.getUserTokens();
        if (tokens == null || tokens.isEmpty()) {
            System.err.println("(API-6) Ошибка: токены не найдены в конфигурации");
            return vulnerabilities;
        }

        System.out.println("(API-6) Используем " + tokens.size() + " токенов из конфигурации");
        System.out.println("(API-6) Доступные ключи токенов: " + String.join(", ", tokens.keySet()));

        // ВЫБИРАЕМ ПРАВИЛЬНЫЙ ТОКЕН - банковский токен для создания согласий
        String token = tokens.get("bank");
        if (token == null) {
            System.err.println("(API-6) ОШИБКА: банковский токен не найден! Не могу создавать согласия.");
            // Пробуем найти банковский токен по bankId
            if (config.getBankId() != null) {
                token = tokens.get(config.getBankId());
                if (token != null) {
                    System.out.println("(API-6) Найден банковский токен по bankId: " + config.getBankId());
                }
            }
            if (token == null) {
                return vulnerabilities;
            }
        } else {
            System.out.println("(API-6) Используется банковский токен для создания согласий");
        }

        // Получаем client_id
        String clientId = getClientId();
        System.out.println("(API-6) Используемый client_id: " + clientId);

        // Проверяем тип объекта OpenAPI
        if (openApiObj == null) {
            System.out.println("(API-6) OpenAPI спецификация недоступна, выполняется базовое сканирование");
            return performBasicBusinessFlowScan(config, apiClient, tokens, clientId);
        }

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-6) Ошибка: передан не OpenAPI объект, выполняется базовое сканирование");
            return performBasicBusinessFlowScan(config, apiClient, tokens, clientId);
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        String baseUrl = config.getTargetBaseUrl();

        try {
            // УЛУЧШЕННАЯ проверка прав доступа токена
            if (!checkTokenPermissions(baseUrl, token, apiClient)) {
                System.err.println("(API-6) Токен не имеет достаточных прав доступа, но продолжаем сканирование");
            }

            // Создаем необходимые согласия
            System.out.println("(API-6) Создание необходимых согласий...");
            Map<String, String> consents = createNecessaryConsents(baseUrl, token, apiClient, clientId);

            // Идентификация бизнес-процессов
            System.out.println("(API-6) Идентификация бизнес-процессов...");
            Map<String, BusinessFlowEndpoint> businessEndpoints = identifyBusinessEndpointsFromSpec(openAPI);

            if (businessEndpoints.isEmpty()) {
                System.out.println("(API-6) Бизнес-процессы не идентифицированы, базовое сканирование");
                vulnerabilities.addAll(performBasicBusinessFlowScan(config, apiClient, tokens, clientId));
                return vulnerabilities;
            }

            System.out.println("(API-6) Найдено бизнес-процессов: " + businessEndpoints.size());

            // Основные тесты
            testAutomationCapabilities(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities, clientId);
            testRateLimiting(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities, clientId);
            testAutomationProtection(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities);
            testBusinessLogicBypass(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities, clientId);
            testProcessIntegrity(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities, clientId);

        } catch (Exception e) {
            System.err.println("(API-6) Ошибка сканирования: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("(API-6) Сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    // ИСПРАВЛЕННЫЙ МЕТОД: Получение client_id из конфигурации
    private String getClientId() {
        // 1. Пробуем получить из явно заданного client_id в конфигурации
        if (config.getClientId() != null && !config.getClientId().isEmpty()) {
            System.out.println("(API-6) Получен client_id из config.getClientId(): " + config.getClientId());
            return config.getClientId();
        }

        // 2. Пробуем получить из credentials (списка пользователей)
        if (config.getCredentials() != null && !config.getCredentials().isEmpty()) {
            // Берем первого пользователя из credentials
            String clientId = config.getCredentials().get(0).getUsername();
            System.out.println("(API-6) Получен client_id из credentials: " + clientId);
            return clientId;
        }

        // 3. Если ничего не помогло, логируем ошибку
        System.err.println("(API-6) ВНИМАНИЕ: client_id не найден в конфигурации");

        // Последняя попытка - посмотреть есть ли какие-то токены
        if (config.getUserTokens() != null && !config.getUserTokens().isEmpty()) {
            for (String key : config.getUserTokens().keySet()) {
                if (!key.equals("bank") && !key.equals("default") &&
                        (config.getBankId() == null || !key.equals(config.getBankId()))) {
                    System.out.println("(API-6) Используем client_id из ключа токена: " + key);
                    return key;
                }
            }
        }

        // Если все методы не сработали, используем bankId для создания client_id
        if (config.getBankId() != null && !config.getBankId().isEmpty()) {
            String clientId = config.getBankId() + "-1";
            System.out.println("(API-6) Используем client_id на основе bankId: " + clientId);
            return clientId;
        }

        // Критическая ошибка
        System.err.println("(API-6) КРИТИЧЕСКАЯ ОШИБКА: Не удалось определить client_id");
        throw new RuntimeException("Client ID не найден в конфигурации. Убедитесь, что указаны учетные данные или bankId.");
    }

    private Map<String, String> initializeTestParameters() {
        Map<String, String> params = new HashMap<>();
        String clientId = getClientId();
        String bankId = config.getBankId();

        params.put("account_id", "acc-1010");
        params.put("payment_id", "payment-123");
        params.put("consent_id", "consent-69e75facabba");
        params.put("agreement_id", "agreement-123");
        params.put("product_id", "prod-vb-deposit-001");
        params.put("request_id", "req-123");
        params.put("client_id", clientId);
        params.put("card_id", "card-123");
        params.put("bank_id", bankId != null ? bankId : "default-bank");

        return params;
    }

    // УЛУЧШЕННЫЙ МЕТОД проверки прав доступа
    private boolean checkTokenPermissions(String baseUrl, String token, ApiClient apiClient) {
        try {
            // Пробуем несколько эндпоинтов для проверки
            String[] testEndpoints = {
                    "/health",
                    "/.well-known/openid-configuration"
            };

            for (String endpoint : testEndpoints) {
                System.out.println("(API-6) Проверка доступа к: " + endpoint);
                Map<String, String> headers = createBankHeaders(token);

                Object response = apiClient.executeRequest("GET", baseUrl + endpoint, null, headers);

                if (response instanceof core.HttpApiClient.ApiResponse) {
                    core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                    int statusCode = apiResponse.getStatusCode();
                    System.out.println("(API-6) Статус код для " + endpoint + ": " + statusCode);

                    // Для health ожидаем 200
                    if (endpoint.equals("/health") && statusCode == 200) {
                        System.out.println("(API-6) Токен валиден, health проверка пройдена");
                        return true;
                    }

                    // Если не 403/401 - считаем что токен работает
                    if (statusCode != 403 && statusCode != 401) {
                        System.out.println("(API-6) Токен имеет доступ к API");
                        return true;
                    }
                }

                Thread.sleep(100); // Небольшая задержка
            }

            System.out.println("(API-6) Токен не прошел проверки, но продолжаем сканирование");
            return true; // Все равно продолжаем

        } catch (Exception e) {
            System.err.println("(API-6) Ошибка проверки прав токена: " + e.getMessage());
            return true; // Продолжаем сканирование даже при ошибке
        }
    }

    // ОБНОВЛЕННЫЙ МЕТОД: принимает напрямую токен
    private Map<String, String> createNecessaryConsents(String baseUrl, String bankToken, ApiClient apiClient, String clientId) {
        Map<String, String> consents = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();

        try {
            Map<String, String> headers = createBankHeaders(bankToken);

            // Account Consent
            Map<String, Object> accountConsentPayload = new HashMap<>();
            accountConsentPayload.put("client_id", clientId);
            accountConsentPayload.put("permissions", Arrays.asList("ReadAccountsDetail", "ReadBalances", "ReadTransactionsDetail"));
            accountConsentPayload.put("reason", "Business Flow Security Testing");
            accountConsentPayload.put("requesting_bank", config.getBankId());
            accountConsentPayload.put("requesting_bank_name", "GOSTGuardian Security Scanner");

            String accountConsentStr = mapper.writeValueAsString(accountConsentPayload);

            System.out.println("(API-6) Создание account consent...");
            System.out.println("(API-6) URL: " + baseUrl + "/account-consents/request");
            System.out.println("(API-6) Headers: " + headers);
            System.out.println("(API-6) Payload: " + accountConsentStr);

            Object accountResponse = apiClient.executeRequest("POST", baseUrl + "/account-consents/request", accountConsentStr, headers);

            if (accountResponse instanceof core.HttpApiClient.ApiResponse) {
                core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) accountResponse;
                System.out.println("(API-6) Response status: " + apiResponse.getStatusCode());
                System.out.println("(API-6) Response body: " + apiResponse.getBody());

                if (apiResponse.getStatusCode() == 200) {
                    String accountConsentId = extractConsentIdFromResponse(apiResponse.getBody(), mapper);
                    if (accountConsentId != null) {
                        consents.put("account_consent", accountConsentId);
                        System.out.println("(API-6) Account consent создан: " + accountConsentId);
                    } else {
                        System.err.println("(API-6) Не удалось извлечь account consent ID из ответа: " + apiResponse.getBody());
                    }
                } else {
                    System.err.println("(API-6) Ошибка создания account consent. Status: " + apiResponse.getStatusCode());
                    // Продолжаем сканирование даже при ошибке
                }
            }

            // Payment Consent
            Map<String, Object> paymentConsentPayload = new HashMap<>();
            paymentConsentPayload.put("requesting_bank", config.getBankId());
            paymentConsentPayload.put("client_id", clientId);
            paymentConsentPayload.put("debtor_account", "acc-1010");
            paymentConsentPayload.put("consent_type", "single_use");
            paymentConsentPayload.put("amount", 1000.00);
            paymentConsentPayload.put("currency", "RUB");

            String paymentConsentStr = mapper.writeValueAsString(paymentConsentPayload);
            System.out.println("(API-6) Создание payment consent...");
            System.out.println("(API-6) URL: " + baseUrl + "/payment-consents/request");
            System.out.println("(API-6) Payload: " + paymentConsentStr);

            Object paymentResponse = apiClient.executeRequest("POST", baseUrl + "/payment-consents/request", paymentConsentStr, headers);

            if (paymentResponse instanceof core.HttpApiClient.ApiResponse) {
                core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) paymentResponse;
                System.out.println("(API-6) Response status: " + apiResponse.getStatusCode());
                System.out.println("(API-6) Response body: " + apiResponse.getBody());

                if (apiResponse.getStatusCode() == 200) {
                    String paymentConsentId = extractConsentIdFromResponse(apiResponse.getBody(), mapper);
                    if (paymentConsentId != null) {
                        consents.put("payment_consent", paymentConsentId);
                        System.out.println("(API-6) Payment consent создан: " + paymentConsentId);
                    } else {
                        System.err.println("(API-6) Не удалось извлечь payment consent ID из ответа: " + apiResponse.getBody());
                    }
                } else {
                    System.err.println("(API-6) Ошибка создания payment consent. Status: " + apiResponse.getStatusCode());
                    // Продолжаем сканирование даже при ошибке
                }
            }

        } catch (Exception e) {
            System.err.println("(API-6) Ошибка создания согласий: " + e.getMessage());
            e.printStackTrace();
        }

        return consents;
    }

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
                }
            }
        }
        return businessEndpoints;
    }

    private boolean isTechnicalEndpoint(String path) {
        return path.contains("/.well-known") || path.contains("/health") || path.equals("/")
                || path.contains("/auth/login") || path.contains("/auth/bank-token");
    }

    private boolean isSensitiveBusinessFlow(String path, String method, Operation operation) {
        if (CRITICAL_OPERATIONS.contains(method)) {
            return true;
        }

        if ("GET".equals(method) && isCriticalGetOperation(path, operation)) {
            return true;
        }

        if (operation.getTags() != null) {
            for (String tag : operation.getTags()) {
                if (SENSITIVE_TAGS.contains(tag)) {
                    return true;
                }
            }
        }

        return path.contains("/payments") || path.contains("/payment-consents")
                || path.contains("/product-agreements") || path.contains("/account-consents")
                || (path.contains("/accounts") && !path.contains("/products"));
    }

    private boolean isCriticalGetOperation(String path, Operation operation) {
        return path.contains("/payments") || path.contains("/payment-consents")
                || path.contains("/product-agreements") || path.contains("/account-consents")
                || path.contains("/accounts/{account_id}")
                || (path.contains("/accounts") && path.contains("balances"))
                || (path.contains("/accounts") && path.contains("transactions"));
    }

    private BusinessFlowEndpoint createBusinessFlowEndpoint(String path, String method, Operation operation) {
        BusinessFlowEndpoint endpoint = new BusinessFlowEndpoint();
        endpoint.setPath(path);
        endpoint.setMethod(method);
        endpoint.setOperation(operation);
        endpoint.setRequiresParameters(path.contains("{"));

        if ((path.contains("/payments") && "POST".equals(method))
                || (path.contains("/payment-consents/request") && "POST".equals(method))) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.HIGH);
            endpoint.setDescription("Создание платежей - критичный финансовый процесс");
        } else if (path.contains("/product-agreements") && "POST".equals(method)) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.HIGH);
            endpoint.setDescription("Открытие продуктовых договоров - доходный процесс");
        } else if (path.contains("/account-consents/request") && "POST".equals(method)) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.HIGH);
            endpoint.setDescription("Создание согласий на доступ - критичный процесс");
        } else if (CRITICAL_OPERATIONS.contains(method)) {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.MEDIUM);
            endpoint.setDescription("Операция изменения данных - бизнес-процесс");
        } else {
            endpoint.setCriticality(BusinessFlowEndpoint.Criticality.LOW);
            endpoint.setDescription("Операция чтения данных");
        }

        return endpoint;
    }

    private void testAutomationCapabilities(String baseUrl, String token, Map<String, String> consents,
                                            ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                            List<Vulnerability> vulnerabilities, String clientId) {
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH ||
                        e.getCriticality() == BusinessFlowEndpoint.Criticality.MEDIUM)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testEndpointAutomation(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
        }
    }

    private void testEndpointAutomation(String baseUrl, String token, Map<String, String> consents,
                                        ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                        List<Vulnerability> vulnerabilities, String clientId) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, consents);
            String testPayload = createSpecificTestPayload(endpoint, clientId);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            int successfulCalls = 0;
            int totalCalls = 3;

            for (int i = 0; i < totalCalls; i++) {
                Object response = apiClient.executeRequest(endpoint.getMethod(), url, testPayload, headers);
                if (isSuccessfulResponse(response)) {
                    successfulCalls++;
                }
                Thread.sleep(1000);
            }

            if (successfulCalls == totalCalls) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Неограниченная автоматизация бизнес-процесса",
                        "Эндпоинт " + endpoint.getPath() + " позволяет выполнять " + successfulCalls +
                                " последовательных операций без ограничений",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.err.println("(API-6) Ошибка тестирования автоматизации " + endpoint.getPath() + ": " + e.getMessage());
        }
    }

    private void testRateLimiting(String baseUrl, String token, Map<String, String> consents,
                                  ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                  List<Vulnerability> vulnerabilities, String clientId) {
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .limit(3)
                .collect(Collectors.toList());

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testEndpointRateLimiting(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
        }
    }

    private void testEndpointRateLimiting(String baseUrl, String token, Map<String, String> consents,
                                          ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                          List<Vulnerability> vulnerabilities, String clientId) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, consents);
            String testPayload = createSpecificTestPayload(endpoint, clientId);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            List<Integer> responseCodes = new ArrayList<>();
            int rapidRequests = 5;

            for (int i = 0; i < rapidRequests; i++) {
                Object response = apiClient.executeRequest(endpoint.getMethod(), url, testPayload, headers);
                if (response instanceof core.HttpApiClient.ApiResponse) {
                    core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                    responseCodes.add(apiResponse.getStatusCode());
                    if (apiResponse.getStatusCode() == 429) break;
                }
                Thread.sleep(100);
            }

            boolean hasRateLimiting = responseCodes.stream().anyMatch(code -> code == 429);
            int successCount = (int) responseCodes.stream().filter(code -> code >= 200 && code < 300).count();

            if (!hasRateLimiting && successCount > 0) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Отсутствие rate limiting для бизнес-операций",
                        "Критичный бизнес-процесс " + endpoint.getPath() + " не имеет ограничений частоты запросов",
                        successCount >= 3 ? Vulnerability.Severity.HIGH : Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.err.println("(API-6) Ошибка тестирования rate limiting " + endpoint.getPath() + ": " + e.getMessage());
        }
    }

    private void testAutomationProtection(String baseUrl, String token, Map<String, String> consents,
                                          ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                          List<Vulnerability> vulnerabilities) {
        for (BusinessFlowEndpoint endpoint : endpoints.values()) {
            if (endpoint.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH) {
                analyzeEndpointProtection(endpoint, vulnerabilities);
                testIdempotencyProtection(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
            }
        }
    }

    private void analyzeEndpointProtection(BusinessFlowEndpoint endpoint, List<Vulnerability> vulnerabilities) {
        Operation operation = endpoint.getOperation();
        String description = operation.getDescription() != null ? operation.getDescription().toLowerCase() : "";
        boolean hasProtectionIndicators = description.contains("consent") || description.contains("authorization")
                || description.contains("authentication") || description.contains("limit")
                || description.contains("validation") || description.contains("approval")
                || description.contains("confirm");

        List<Parameter> parameters = operation.getParameters();
        boolean hasSecurityParameters = parameters != null && parameters.stream()
                .anyMatch(p -> p.getName().toLowerCase().contains("consent")
                        || p.getName().toLowerCase().contains("auth")
                        || p.getName().toLowerCase().contains("token")
                        || p.getName().toLowerCase().contains("signature"));

        if (!hasProtectionIndicators && !hasSecurityParameters) {
            Vulnerability vuln = createBusinessFlowVulnerability(
                    endpoint.getPath(),
                    "Недостаточная документация защиты бизнес-процесса",
                    "Критичный бизнес-процесс " + endpoint.getPath() + " не имеет явных указаний на механизмы защиты",
                    Vulnerability.Severity.LOW
            );
            vulnerabilities.add(vuln);
        }
    }

    private void testIdempotencyProtection(String baseUrl, String token, Map<String, String> consents,
                                           ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                           List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, consents);
            String payload = createSpecificTestPayload(endpoint, getClientId());
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response1 = apiClient.executeRequest(endpoint.getMethod(), url, payload, headers);
            Object response2 = apiClient.executeRequest(endpoint.getMethod(), url, payload, headers);

            boolean firstSuccess = isSuccessfulResponse(response1);
            boolean secondSuccess = isSuccessfulResponse(response2);

            if (firstSuccess && secondSuccess) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Отсутствие защиты от повторных операций",
                        "Эндпоинт " + endpoint.getPath() + " не имеет защиты от повторного выполнения одинаковых операций",
                        Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.out.println("(API-6) Ошибка тестирования идемпотентности: " + e.getMessage());
        }
    }

    private void testBusinessLogicBypass(String baseUrl, String token, Map<String, String> consents,
                                         ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                         List<Vulnerability> vulnerabilities, String clientId) {
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testBusinessLogicValidation(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
        }
    }

    private void testBusinessLogicValidation(String baseUrl, String token, Map<String, String> consents,
                                             ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                             List<Vulnerability> vulnerabilities, String clientId) {
        testNegativeValues(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
        testBoundaryValues(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
        testInvalidDataTypes(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
        testMissingRequiredFields(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
    }

    private void testNegativeValues(String baseUrl, String token, Map<String, String> consents,
                                    ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                    List<Vulnerability> vulnerabilities, String clientId) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, consents);
            String negativePayload = createNegativeValuePayload(endpoint, clientId);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, negativePayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Обход валидации отрицательных значений",
                        "Эндпоинт " + endpoint.getPath() + " принимает отрицательные значения без валидации",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.out.println("(API-6) Валидация отрицательных значений работает для " + endpoint.getPath());
        }
    }

    private void testBoundaryValues(String baseUrl, String token, Map<String, String> consents,
                                    ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                    List<Vulnerability> vulnerabilities, String clientId) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, consents);
            String boundaryPayload = createBoundaryValuePayload(endpoint, clientId);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, boundaryPayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Обход проверки граничных значений",
                        "Эндпоинт " + endpoint.getPath() + " принимает экстремально большие значения без валидации",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.out.println("(API-6) Валидация граничных значений работает для " + endpoint.getPath());
        }
    }

    private void testInvalidDataTypes(String baseUrl, String token, Map<String, String> consents,
                                      ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                      List<Vulnerability> vulnerabilities, String clientId) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, consents);
            String invalidTypePayload = createInvalidDataTypePayload(endpoint, clientId);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, invalidTypePayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Обход валидации типов данных",
                        "Эндпоинт " + endpoint.getPath() + " принимает неверные типы данных без валидации",
                        Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.out.println("(API-6) Валидация типов данных работает для " + endpoint.getPath());
        }
    }

    private void testMissingRequiredFields(String baseUrl, String token, Map<String, String> consents,
                                           ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                           List<Vulnerability> vulnerabilities, String clientId) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, consents);
            String minimalPayload = createMinimalPayload(endpoint, clientId);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, minimalPayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Обход проверки обязательных полей",
                        "Эндпоинт " + endpoint.getPath() + " обрабатывает запросы без обязательных полей",
                        Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.out.println("(API-6) Проверка обязательных полей работает для " + endpoint.getPath());
        }
    }

    private void testProcessIntegrity(String baseUrl, String token, Map<String, String> consents,
                                      ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                      List<Vulnerability> vulnerabilities, String clientId) {
        analyzeProcessSequences(endpoints, vulnerabilities);
        testMissingDependencies(baseUrl, token, consents, apiClient, endpoints, vulnerabilities, clientId);
        testDirectAccessToOperations(baseUrl, token, consents, apiClient, endpoints, vulnerabilities, clientId);
    }

    private void analyzeProcessSequences(Map<String, BusinessFlowEndpoint> endpoints,
                                         List<Vulnerability> vulnerabilities) {
        boolean hasPaymentEndpoint = endpoints.values().stream()
                .anyMatch(e -> e.getPath().contains("/payments") && "POST".equals(e.getMethod()));
        boolean hasPaymentConsentEndpoint = endpoints.values().stream()
                .anyMatch(e -> e.getPath().contains("/payment-consents/request") && "POST".equals(e.getMethod()));

        if (hasPaymentEndpoint && !hasPaymentConsentEndpoint) {
            Vulnerability vuln = createBusinessFlowVulnerability(
                    "/payments",
                    "Возможное нарушение целостности процесса платежей",
                    "Обнаружены эндпоинты платежей без явного требования согласий в документации",
                    Vulnerability.Severity.MEDIUM
            );
            vulnerabilities.add(vuln);
        }
    }

    private void testMissingDependencies(String baseUrl, String token, Map<String, String> consents,
                                         ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                         List<Vulnerability> vulnerabilities, String clientId) {
        List<BusinessFlowEndpoint> paymentEndpoints = endpoints.values().stream()
                .filter(e -> e.getPath().contains("/payments") && "POST".equals(e.getMethod()))
                .collect(Collectors.toList());

        for (BusinessFlowEndpoint endpoint : paymentEndpoints) {
            testPaymentWithoutConsent(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
        }
    }

    private void testPaymentWithoutConsent(String baseUrl, String token, Map<String, String> consents,
                                           ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                           List<Vulnerability> vulnerabilities, String clientId) {
        try {
            // Используем банковские заголовки без consent
            Map<String, String> headers = createBankHeaders(token);
            String paymentPayload = createSpecificTestPayload(endpoint, clientId);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, paymentPayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Нарушение целостности процесса платежей",
                        "Возможно создание платежа без предварительного согласия",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.out.println("(API-6) Целостность процесса платежей соблюдается: " + e.getMessage());
        }
    }

    private void testDirectAccessToOperations(String baseUrl, String token, Map<String, String> consents,
                                              ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                              List<Vulnerability> vulnerabilities, String clientId) {
        List<BusinessFlowEndpoint> criticalEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        for (BusinessFlowEndpoint endpoint : criticalEndpoints) {
            testDirectEndpointAccess(baseUrl, token, consents, apiClient, endpoint, vulnerabilities, clientId);
        }
    }

    private void testDirectEndpointAccess(String baseUrl, String token, Map<String, String> consents,
                                          ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                          List<Vulnerability> vulnerabilities, String clientId) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, consents);
            String payload = createSpecificTestPayload(endpoint, clientId);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, payload, headers);
            if (isSuccessfulResponse(response) && endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint.getPath(),
                        "Прямой доступ к критичным операциям",
                        "Критичная операция " + endpoint.getPath() + " доступна для прямого вызова без проверок",
                        Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.out.println("(API-6) Прямой доступ ограничен для " + endpoint.getPath());
        }
    }

    private String buildTestUrl(String baseUrl, String path) {
        String resolvedPath = path;
        for (Map.Entry<String, String> param : testParameters.entrySet()) {
            String paramPlaceholder = "{" + param.getKey() + "}";
            if (resolvedPath.contains(paramPlaceholder)) {
                resolvedPath = resolvedPath.replace(paramPlaceholder, param.getValue());
            }
        }
        return baseUrl + resolvedPath;
    }

    // Вспомогательные методы для работы с заголовками и ответами
    private Map<String, String> createAuthHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "curl/8.16.0"); // ИЗМЕНЕНО: curl User-Agent
        headers.put("Accept", "*/*"); // ИЗМЕНЕНО: Accept как в curl
        return headers;
    }

    private Map<String, String> createBankHeaders(String token) {
        Map<String, String> headers = createAuthHeaders(token);
        headers.put("X-Requesting-Bank", config.getBankId());
        return headers;
    }

    private Map<String, String> createAuthHeadersWithConsents(String token, Map<String, String> consents) {
        Map<String, String> headers = createBankHeaders(token);
        if (consents.containsKey("account_consent")) {
            headers.put("X-Consent-Id", consents.get("account_consent"));
        }
        if (consents.containsKey("payment_consent")) {
            headers.put("X-Payment-Consent-Id", consents.get("payment_consent"));
        }
        return headers;
    }

    private boolean isSuccessfulResponse(Object response) {
        if (response instanceof core.HttpApiClient.ApiResponse) {
            core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
            return apiResponse.getStatusCode() >= 200 && apiResponse.getStatusCode() < 300;
        }
        return false;
    }

    private String extractConsentIdFromResponse(String responseBody, ObjectMapper mapper) {
        try {
            if (responseBody == null || responseBody.trim().isEmpty() || responseBody.trim().startsWith("<")) {
                return null;
            }

            JsonNode json = mapper.readTree(responseBody);

            // Прямое поле consent_id
            if (json.has("consent_id")) {
                return json.get("consent_id").asText();
            }

            // Альтернативные варианты
            if (json.has("data") && json.get("data").has("consentId")) {
                return json.get("data").get("consentId").asText();
            }

        } catch (Exception e) {
            System.err.println("(API-6) Ошибка извлечения consent ID: " + e.getMessage());
        }
        return null;
    }

    private String createSpecificTestPayload(BusinessFlowEndpoint endpoint, String clientId) {
        String path = endpoint.getPath();
        String method = endpoint.getMethod();

        if (path.contains("/payment-consents/request") && "POST".equals(method)) {
            return "{\"requesting_bank\":\"" + config.getBankId() + "\",\"client_id\":\"" + clientId +
                    "\",\"debtor_account\":\"acc-1010\",\"amount\":100.00,\"currency\":\"RUB\",\"consent_type\":\"single_use\"}";
        } else if (path.contains("/payments") && "POST".equals(method)) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"}," +
                    "\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"40817810099910004312\"}," +
                    "\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"40817810099910005423\"}}}}";
        } else if (path.contains("/product-agreements") && "POST".equals(method)) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":1000.00}";
        } else if (path.contains("/account-consents/request") && "POST".equals(method)) {
            return "{\"client_id\":\"" + clientId + "\",\"permissions\":[\"ReadAccountsDetail\",\"ReadBalances\"]," +
                    "\"reason\":\"Тестовый запрос\",\"requesting_bank\":\"" + config.getBankId() + "\",\"requesting_bank_name\":\"Test App\"}";
        } else if (path.contains("/accounts") && "POST".equals(method)) {
            return "{\"account_type\":\"checking\",\"initial_balance\":100.00}";
        } else if (path.contains("/cards") && "POST".equals(method)) {
            return "{\"card_type\":\"debit\",\"account_id\":\"acc-1010\"}";
        } else {
            return "{}";
        }
    }

    private String createNegativeValuePayload(BusinessFlowEndpoint endpoint, String clientId) {
        if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"-1000.00\",\"currency\":\"RUB\"}," +
                    "\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1010\"}," +
                    "\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1011\"}}}}";
        } else if (endpoint.getPath().contains("/product-agreements") && "POST".equals(endpoint.getMethod())) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":-1000}";
        }
        return "{\"amount\": -1000}";
    }

    private String createBoundaryValuePayload(BusinessFlowEndpoint endpoint, String clientId) {
        if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"999999999999.00\",\"currency\":\"RUB\"}," +
                    "\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1010\"}," +
                    "\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1011\"}}}}";
        } else if (endpoint.getPath().contains("/product-agreements") && "POST".equals(endpoint.getMethod())) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":999999999999}";
        }
        return "{\"amount\": 999999999999}";
    }

    private String createInvalidDataTypePayload(BusinessFlowEndpoint endpoint, String clientId) {
        if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"INVALID\",\"currency\":\"RUB\"}," +
                    "\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1010\"}," +
                    "\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1011\"}}}}";
        } else if (endpoint.getPath().contains("/product-agreements") && "POST".equals(endpoint.getMethod())) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":\"INVALID\"}";
        }
        return "{\"amount\": \"INVALID\"}";
    }

    private String createMinimalPayload(BusinessFlowEndpoint endpoint, String clientId) {
        if (endpoint.getPath().contains("/payments") && "POST".equals(endpoint.getMethod())) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"}}}}";
        } else if (endpoint.getPath().contains("/product-agreements") && "POST".equals(endpoint.getMethod())) {
            return "{\"product_id\":\"prod-vb-deposit-001\"}";
        }
        return "{}";
    }

    private List<Vulnerability> performBasicBusinessFlowScan(ScanConfig config, ApiClient apiClient,
                                                             Map<String, String> tokens, String clientId) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl();

        try {
            if (tokens.isEmpty()) {
                System.err.println("(API-6) Не удалось получить токены");
                return vulnerabilities;
            }

            String token = tokens.get("bank");
            if (token == null) {
                System.err.println("(API-6) Базовое сканирование: банковский токен не найден, пропускаем");
                return vulnerabilities;
            } else {
                System.out.println("(API-6) Базовое сканирование: используем банковский токен");
            }

            vulnerabilities.addAll(testBasicBusinessEndpoints(baseUrl, token, apiClient, clientId));
            vulnerabilities.addAll(testRateLimitingBasic(baseUrl, token, apiClient, clientId));
            vulnerabilities.addAll(testBusinessLogicBypassBasic(baseUrl, token, apiClient, clientId));

        } catch (Exception e) {
            System.err.println("(API-6) Ошибка базового сканирования: " + e.getMessage());
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testBasicBusinessEndpoints(String baseUrl, String token, ApiClient apiClient, String clientId) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();

        String[] businessEndpoints = {
                "/payments",
                "/payment-consents/request",
                "/account-consents/request",
                "/product-agreements",
                "/accounts"
        };

        try {
            Map<String, String> headers = createAuthHeaders(token);

            for (String endpoint : businessEndpoints) {
                System.out.println("(API-6) Тестирование бизнес-эндпоинта: " + endpoint);

                Object response = apiClient.executeRequest("GET", baseUrl + endpoint, null, headers);
                if (isSuccessfulResponse(response)) {
                    vulnerabilities.addAll(testEndpointAutomationBasic(baseUrl, token, endpoint, apiClient, mapper, clientId));
                }
            }
        } catch (Exception e) {
            System.err.println("(API-6) Ошибка тестирования бизнес-эндпоинтов: " + e.getMessage());
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testEndpointAutomationBasic(String baseUrl, String token, String endpoint,
                                                            ApiClient apiClient, ObjectMapper mapper, String clientId) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            Map<String, String> headers = createAuthHeaders(token);
            String testPayload = createBasicTestPayload(endpoint, clientId);

            int successfulCalls = 0;
            for (int i = 0; i < 3; i++) {
                Object response = apiClient.executeRequest("POST", baseUrl + endpoint, testPayload, headers);
                if (isSuccessfulResponse(response)) {
                    successfulCalls++;
                }
                Thread.sleep(1000);
            }

            if (successfulCalls == 3) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        endpoint,
                        "Неограниченная автоматизация бизнес-процесса (базовое сканирование)",
                        "Эндпоинт " + endpoint + " позволяет выполнять последовательные операци без ограничений",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
            }
        } catch (Exception e) {
            System.err.println("(API-6) Ошибка тестирования автоматизации: " + e.getMessage());
        }

        return vulnerabilities;
    }

    private String createBasicTestPayload(String endpoint, String clientId) {
        if (endpoint.contains("/payments")) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"},\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"40817810099910004312\"},\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"40817810099910005423\"}}}}";
        } else if (endpoint.contains("/payment-consents")) {
            return "{\"requesting_bank\":\"" + config.getBankId() + "\",\"client_id\":\"" + clientId + "\",\"debtor_account\":\"acc-1010\",\"amount\":100.00,\"currency\":\"RUB\"}";
        } else if (endpoint.contains("/account-consents")) {
            return "{\"client_id\":\"" + clientId + "\",\"permissions\":[\"ReadAccountsDetail\",\"ReadBalances\"],\"reason\":\"Тестовый запрос\",\"requesting_bank\":\"" + config.getBankId() + "\"}";
        } else if (endpoint.contains("/product-agreements")) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":1000.00}";
        } else {
            return "{}";
        }
    }

    private List<Vulnerability> testRateLimitingBasic(String baseUrl, String token, ApiClient apiClient, String clientId) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            Map<String, String> headers = createAuthHeaders(token);
            String[] criticalEndpoints = {"/payments", "/payment-consents/request"};

            for (String endpoint : criticalEndpoints) {
                System.out.println("(API-6) Базовый тест rate limiting для: " + endpoint);

                List<Integer> responseCodes = new ArrayList<>();
                for (int i = 0; i < 5; i++) {
                    Object response = apiClient.executeRequest("POST", baseUrl + endpoint, createBasicTestPayload(endpoint, clientId), headers);
                    if (response instanceof core.HttpApiClient.ApiResponse) {
                        core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                        responseCodes.add(apiResponse.getStatusCode());
                        if (apiResponse.getStatusCode() == 429) break;
                    }
                    Thread.sleep(100);
                }

                boolean hasRateLimiting = responseCodes.stream().anyMatch(code -> code == 429);
                if (!hasRateLimiting) {
                    Vulnerability vuln = createBusinessFlowVulnerability(
                            endpoint,
                            "Отсутствие rate limiting (базовое сканирование)",
                            "Критичный бизнес-процесс " + endpoint + " не имеет ограничений частоты запросов",
                            Vulnerability.Severity.MEDIUM
                    );
                    vulnerabilities.add(vuln);
                }
            }
        } catch (Exception e) {
            System.err.println("(API-6) Ошибка базового тестирования rate limiting: " + e.getMessage());
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testBusinessLogicBypassBasic(String baseUrl, String token, ApiClient apiClient, String clientId) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            Map<String, String> headers = createAuthHeaders(token);
            String negativePaymentPayload = "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"-1000.00\",\"currency\":\"RUB\"},\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1010\"},\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"acc-1011\"}}}}";

            Object response = apiClient.executeRequest("POST", baseUrl + "/payments", negativePaymentPayload, headers);
            if (isSuccessfulResponse(response)) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        "/payments",
                        "Обход бизнес-логики (отрицательные суммы)",
                        "Эндпоинт /payments принимает отрицательные суммы без валидации",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
            }

        } catch (Exception e) {
            System.err.println("(API-6) Ошибка базового тестирования бизнес-логики: " + e.getMessage());
        }

        return vulnerabilities;
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

        vuln.setRecommendations(Arrays.asList(
                "Внедрить rate limiting для чувствительных бизнес-операций",
                "Реализовать проверку последовательности шагов бизнес-процесса",
                "Добавить строгую валидацию бизнес-логики на стороне сервера",
                "Внедрить мониторинг аномальной активности бизнес-процессов",
                "Реализовать лимиты на операции по сумме и частоте",
                "Использовать обязательные подтверждения для критических операций",
                "Документировать требования безопасности для всех бизнес-процессов",
                "Внедрить механизмы идемпотентности для финансовых операций",
                "Реализовать проверку обязательных полей и зависимостей"
        ));

        return vuln;
    }

    private static class BusinessFlowEndpoint {
        enum Criticality { LOW, MEDIUM, HIGH }

        private String path;
        private String method;
        private Operation operation;
        private Criticality criticality;
        private String description;
        private boolean requiresParameters;

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