package scanners.owasp;

import scanners.SecurityScanner;
import core.HttpApiClient;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.ApiResponse;
import core.AuthManager;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
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
            "client_id", "team172-1",
            "card_id", "card-123"
    );

    @Override
    public String getName() {
        return "OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-6) 🚀 Запуск сканирования Unrestricted Access to Sensitive Business Flows...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-6) ❌ Ошибка: передан не OpenAPI объект");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        String baseUrl = config.getTargetBaseUrl();

        try {
            // ИСПРАВЛЕНИЕ: Используем методы из API3 для получения токенов
            System.out.println("(API-6) 🔑 Получение токенов через методы API3...");
            Map<String, String> tokens = getAllTokens(baseUrl, config);

            if (tokens.isEmpty()) {
                System.err.println("(API-6) ❌ Не удалось получить токены");
                return vulnerabilities;
            }

            System.out.println("(API-6) ✅ Получено токенов: " + tokens.size());

            // Проверяем права доступа токенов
            String token = tokens.get("bank_token");
            if (token == null) {
                // Если нет банковского токена, берем первый доступный
                token = tokens.values().iterator().next();
                System.out.println("(API-6) ⚠️ Используется клиентский токен (банковский не найден)");
            } else {
                System.out.println("(API-6) ✅ Используется банковский токен");
            }

            // Проверяем права доступа токена
            if (!checkTokenPermissions(baseUrl, token, apiClient)) {
                System.err.println("(API-6) ❌ Токен не имеет достаточных прав доступа");
                // Продолжаем сканирование, но логируем проблему
            }

            // Создаем необходимые согласия перед тестированием
            System.out.println("(API-6) 📋 Создание необходимых согласий...");
            Map<String, String> consents = createNecessaryConsents(baseUrl, tokens, apiClient);

            // 1. Идентификация ключевых бизнес-процессов из OpenAPI
            System.out.println("(API-6) 🔍 Идентификация бизнес-процессов из OpenAPI спецификации...");
            Map<String, BusinessFlowEndpoint> businessEndpoints = identifyBusinessEndpointsFromSpec(openAPI);

            if (businessEndpoints.isEmpty()) {
                System.out.println("(API-6) ⚠️ Бизнес-процессы не идентифицированы");
                return vulnerabilities;
            }

            System.out.println("(API-6) ✅ Найдено бизнес-процессов: " + businessEndpoints.size());

            // 2. Тестирование возможности автоматизации (с согласиями)
            System.out.println("(API-6) ⚡ Тестирование автоматизации операций...");
            testAutomationCapabilities(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities);

            // 3. Проверка ограничений на частоту
            System.out.println("(API-6) 📊 Проверка ограничений частоты...");
            testRateLimiting(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities);

            // 4. Анализ защиты от автоматизации
            System.out.println("(API-6) 🛡️ Анализ защиты от автоматизации...");
            testAutomationProtection(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities);

            // 5. Тестирование обходов бизнес-логики
            System.out.println("(API-6) 🔄 Тестирование обходов бизнес-логики...");
            testBusinessLogicBypass(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities);

            // 6. Проверка целостности бизнес-процессов
            System.out.println("(API-6) 🔗 Проверка целостности процессов...");
            testProcessIntegrity(baseUrl, token, consents, apiClient, businessEndpoints, vulnerabilities);

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка в Business Flow сканере: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("(API-6) ✅ Business Flow сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    // ========== МЕТОДЫ ПОЛУЧЕНИЯ ТОКЕНОВ ИЗ API3 ==========

    /**
     * ПОЛУЧАЕМ ВСЕ ВОЗМОЖНЫЕ ТОКЕНЫ РАЗНЫМИ СПОСОБАМИ (из API3)
     */
    private Map<String, String> getAllTokens(String baseUrl, ScanConfig config) {
        Map<String, String> tokens = new HashMap<>();

        try {
            // Получаем учетные данные из конфигурации
            String username = "team172-1";
            String password = "***REMOVED***";

            if (!config.getCredentials().isEmpty()) {
                username = config.getCredentials().get(0).getUsername();
                password = config.getCredentials().get(0).getPassword();
            }

            System.out.println("(API-6) 🔑 Получение токенов для: " + username);

            // 1. Client token через /auth/login (основной)
            String clientToken1 = getTokenViaLogin(baseUrl, username, password);
            if (clientToken1 != null) {
                tokens.put("client_login", clientToken1);
                System.out.println("(API-6) ✅ Client token (login) получен: " +
                        clientToken1.substring(0, Math.min(20, clientToken1.length())) + "...");
            }

            // 2. Bank token через /auth/bank-token (основной)
            String bankToken1 = getTokenViaBankToken(baseUrl, "team172", password);
            if (bankToken1 != null) {
                tokens.put("bank_token", bankToken1);
                System.out.println("(API-6) ✅ Bank token (bank-token) получен: " +
                        bankToken1.substring(0, Math.min(20, bankToken1.length())) + "...");
            }

            // 3. Bank token через /auth/bank-token с client token
            if (clientToken1 != null) {
                String bankToken2 = getTokenViaBankTokenWithAuth(baseUrl, "team172", password, clientToken1);
                if (bankToken2 != null) {
                    tokens.put("bank_token_auth", bankToken2);
                    System.out.println("(API-6) ✅ Bank token (with auth) получен: " +
                            bankToken2.substring(0, Math.min(20, bankToken2.length())) + "...");
                }
            }

            // 4. Пробуем других пользователей
            for (int i = 2; i <= 3; i++) {
                String altUser = "team172-" + i;
                String altToken = getTokenViaLogin(baseUrl, altUser, password);
                if (altToken != null) {
                    tokens.put("client_" + altUser, altToken);
                    System.out.println("(API-6) ✅ Token для " + altUser + " получен: " +
                            altToken.substring(0, Math.min(20, altToken.length())) + "...");
                }
            }

            System.out.println("(API-6) 🎯 Всего получено токенов: " + tokens.size());

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка получения токенов: " + e.getMessage());
        }

        return tokens;
    }

    /**
     * Проверяет, имеет ли токен достаточные права доступа
     */
    private boolean checkTokenPermissions(String baseUrl, String token, ApiClient apiClient) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            Object response = apiClient.executeRequest("GET", baseUrl + "/accounts", null, headers);

            if (response instanceof core.HttpApiClient.ApiResponse) {
                core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                if (apiResponse.getStatusCode() == 200) {
                    System.out.println("(API-6) ✅ Токен имеет достаточные права доступа");
                    return true;
                } else {
                    System.out.println("(API-6) ❌ Токен не имеет прав доступа: " + apiResponse.getStatusCode());
                    // Анализируем тело ответа для лучшей диагностики
                    if (apiResponse.getBody() != null) {
                        String bodyPreview = apiResponse.getBody().length() > 200 ?
                                apiResponse.getBody().substring(0, 200) + "..." : apiResponse.getBody();
                        System.out.println("(API-6) 📄 Тело ответа: " + bodyPreview);

                        if (apiResponse.getBody().contains("CONSENT_REQUIRED")) {
                            System.out.println("(API-6) ⚠️ Требуется согласие для доступа к данным");
                        }
                    }
                    return false;
                }
            }
        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка проверки прав токена: " + e.getMessage());
        }
        return false;
    }

    private String getTokenViaLogin(String baseUrl, String username, String password) {
        try {
            String loginUrl = baseUrl + "/auth/login";

            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("username", username);
            requestBody.put("password", password);

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String jsonBody = new ObjectMapper().writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("(API-6) 🔐 Login response для " + username + ": " + response.statusCode());

            if (response.statusCode() == 200) {
                return extractTokenFromResponse(response.body());
            } else {
                System.out.println("(API-6) ⚠️ Login failed with status: " + response.statusCode());
                if (response.body() != null) {
                    System.out.println("(API-6) 📄 Response body: " + response.body());
                }
            }

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка getTokenViaLogin: " + e.getMessage());
        }
        return null;
    }

    private String getTokenViaBankToken(String baseUrl, String clientId, String clientSecret) {
        try {
            String authUrl = baseUrl + "/auth/bank-token?client_id=" + clientId +
                    "&client_secret=" + clientSecret + "&grant_type=client_credentials";

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("(API-6) 🏦 Bank token response: " + response.statusCode());

            if (response.statusCode() == 200) {
                return extractTokenFromResponse(response.body());
            } else {
                System.out.println("(API-6) ⚠️ Bank token failed with status: " + response.statusCode());
                if (response.body() != null) {
                    System.out.println("(API-6) 📄 Response body: " + response.body());
                }
            }

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка getTokenViaBankToken: " + e.getMessage());
        }
        return null;
    }

    private String getTokenViaBankTokenWithAuth(String baseUrl, String clientId, String clientSecret, String authToken) {
        try {
            String authUrl = baseUrl + "/auth/bank-token?client_id=" + clientId +
                    "&client_secret=" + clientSecret + "&grant_type=client_credentials";

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + authToken)
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("(API-6) 🔐 Bank token with auth response: " + response.statusCode());

            if (response.statusCode() == 200) {
                return extractTokenFromResponse(response.body());
            } else {
                System.out.println("(API-6) ⚠️ Bank token with auth failed with status: " + response.statusCode());
                if (response.body() != null) {
                    System.out.println("(API-6) 📄 Response body: " + response.body());
                }
            }

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка getTokenViaBankTokenWithAuth: " + e.getMessage());
        }
        return null;
    }

    private String extractTokenFromResponse(String responseBody) {
        try {
            if (responseBody == null) return null;

            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(responseBody);

            if (json.has("access_token")) {
                return json.get("access_token").asText();
            }
            if (json.has("token")) {
                return json.get("token").asText();
            }

            // Fallback: поиск в тексте
            if (responseBody.contains("access_token")) {
                String[] parts = responseBody.split("\"access_token\"\\s*:\\s*\"");
                if (parts.length > 1) {
                    return parts[1].split("\"")[0];
                }
            }

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка извлечения токена: " + e.getMessage());
        }
        return null;
    }

    /**
     * СОЗДАЕМ НЕОБХОДИМЫЕ СОГЛАСИЯ ДЛЯ ТЕСТИРОВАНИЯ
     */
    private Map<String, String> createNecessaryConsents(String baseUrl, Map<String, String> tokens, ApiClient apiClient) {
        Map<String, String> consents = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();

        try {
            String token = tokens.get("bank_token");
            if (token == null) {
                System.out.println("(API-6) ⚠️ Bank token не найден, пропускаем создание согласий");
                return consents;
            }

            // 1. Account Consent
            Map<String, Object> accountConsentPayload = new HashMap<>();
            accountConsentPayload.put("client_id", "team172-1");
            accountConsentPayload.put("permissions", Arrays.asList("ReadAccountsDetail", "ReadBalances", "ReadTransactionsDetail"));
            accountConsentPayload.put("reason", "Business Flow Security Testing");
            accountConsentPayload.put("requesting_bank", "team172");
            accountConsentPayload.put("requesting_bank_name", "Security Scanner");

            String accountConsentStr = mapper.writeValueAsString(accountConsentPayload);
            Map<String, String> headers = createAuthHeaders(token, "team172");

            System.out.println("(API-6) 📋 Создание account consent...");
            Object accountResponse = apiClient.executeRequest("POST",
                    baseUrl + "/account-consents/request", accountConsentStr, headers);

            String accountConsentId = extractConsentIdFromResponse(extractResponseBody(accountResponse), mapper);
            if (accountConsentId != null) {
                consents.put("account_consent", accountConsentId);
                System.out.println("(API-6) ✅ Account consent создан: " + accountConsentId);
            } else {
                System.out.println("(API-6) ❌ Не удалось создать account consent");
                logResponseDetails(accountResponse);
            }

            // 2. Payment Consent
            Map<String, Object> paymentConsentPayload = new HashMap<>();
            paymentConsentPayload.put("requesting_bank", "team172");
            paymentConsentPayload.put("client_id", "team172-1");
            paymentConsentPayload.put("debtor_account", "acc-1010");
            paymentConsentPayload.put("consent_type", "single_use");
            paymentConsentPayload.put("amount", 1000.00);
            paymentConsentPayload.put("currency", "RUB");

            String paymentConsentStr = mapper.writeValueAsString(paymentConsentPayload);

            System.out.println("(API-6) 💳 Создание payment consent...");
            Object paymentResponse = apiClient.executeRequest("POST",
                    baseUrl + "/payment-consents/request", paymentConsentStr, headers);

            String paymentConsentId = extractConsentIdFromResponse(extractResponseBody(paymentResponse), mapper);
            if (paymentConsentId != null) {
                consents.put("payment_consent", paymentConsentId);
                System.out.println("(API-6) ✅ Payment consent создан: " + paymentConsentId);
            } else {
                System.out.println("(API-6) ❌ Не удалось создать payment consent");
                logResponseDetails(paymentResponse);
            }

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка создания согласий: " + e.getMessage());
        }

        return consents;
    }

    private void logResponseDetails(Object response) {
        try {
            if (response instanceof core.HttpApiClient.ApiResponse) {
                core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                System.out.println("(API-6) 📊 Статус код: " + apiResponse.getStatusCode());
                if (apiResponse.getBody() != null) {
                    String body = apiResponse.getBody();
                    System.out.println("(API-6) 📄 Тело ответа: " +
                            (body.length() > 500 ? body.substring(0, 500) + "..." : body));
                }
            }
        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка логирования ответа: " + e.getMessage());
        }
    }

    private String extractConsentIdFromResponse(String responseBody, ObjectMapper mapper) {
        try {
            if (responseBody == null) return null;

            // Проверяем, не является ли ответ HTML страницей с ошибкой
            if (responseBody.trim().startsWith("<")) {
                System.out.println("(API-6) ⚠️ Получен HTML ответ вместо JSON");
                return null;
            }

            JsonNode json = mapper.readTree(responseBody);

            if (json.has("consent_id")) {
                return json.get("consent_id").asText();
            }
            if (json.has("data") && json.get("data").has("consentId")) {
                return json.get("data").get("consentId").asText();
            }
            if (json.has("status")) {
                System.out.println("(API-6) 📊 Статус согласия: " + json.get("status").asText());
            }

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка извлечения consent ID: " + e.getMessage());
        }
        return null;
    }

    // ========== ОСНОВНЫЕ МЕТОДЫ СКАНЕРА (с интегрированными согласиями) ==========

    // Идентификация ключевых бизнес-процессов из OpenAPI
    private Map<String, BusinessFlowEndpoint> identifyBusinessEndpointsFromSpec(OpenAPI openAPI) {
        Map<String, BusinessFlowEndpoint> businessEndpoints = new HashMap<>();
        Map<String, PathItem> paths = openAPI.getPaths();

        if (paths == null) {
            System.err.println("(API-6) ❌ В OpenAPI спецификации не найдены пути");
            return businessEndpoints;
        }

        System.out.println("(API-6) 📁 Анализ путей API: " + paths.size());

        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();

            // Пропускаем технические эндпоинты
            if (isTechnicalEndpoint(path)) {
                System.out.println("(API-6) ⏭️ Пропущен технический эндпоинт: " + path);
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
                    System.out.println("(API-6) ✅ Бизнес-процесс: " + httpMethod.name() + " " + path +
                            " - " + endpoint.getDescription() + " [Критичность: " + endpoint.getCriticality() + "]");
                } else {
                    System.out.println("(API-6) ❌ Не чувствительный: " + httpMethod.name() + " " + path);
                }
            }
        }
        return businessEndpoints;
    }

    private boolean isTechnicalEndpoint(String path) {
        return path.contains("/.well-known") ||
                path.contains("/health") ||
                path.equals("/") ||
                path.contains("/auth/login") ||
                path.contains("/auth/bank-token");
    }

    private boolean isSensitiveBusinessFlow(String path, String method, Operation operation) {
        // Все POST, PUT, DELETE операции считаем чувствительными
        if (CRITICAL_OPERATIONS.contains(method)) {
            return true;
        }

        // GET операции только к чувствительным данным
        if ("GET".equals(method) && isCriticalGetOperation(path, operation)) {
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

        // Дополнительные критерии по пути
        return path.contains("/payments") ||
                path.contains("/payment-consents") ||
                path.contains("/product-agreements") ||
                path.contains("/account-consents") ||
                path.contains("/accounts") && !path.contains("/products");
    }

    private boolean isCriticalGetOperation(String path, Operation operation) {
        return path.contains("/payments") ||
                path.contains("/payment-consents") ||
                path.contains("/product-agreements") ||
                path.contains("/account-consents") ||
                path.contains("/accounts/{account_id}") ||
                path.contains("/accounts") && path.contains("balances") ||
                path.contains("/accounts") && path.contains("transactions");
    }

    private BusinessFlowEndpoint createBusinessFlowEndpoint(String path, String method, Operation operation) {
        BusinessFlowEndpoint endpoint = new BusinessFlowEndpoint();
        endpoint.setPath(path);
        endpoint.setMethod(method);
        endpoint.setOperation(operation);
        endpoint.setRequiresParameters(path.contains("{"));

        // Определяем критичность
        if ((path.contains("/payments") && "POST".equals(method)) ||
                (path.contains("/payment-consents/request") && "POST".equals(method))) {
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

    // Тестирование возможности автоматизации бизнес-операций (с согласиями)
    private void testAutomationCapabilities(String baseUrl, String token, Map<String, String> consents,
                                            ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                            List<Vulnerability> vulnerabilities) {
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH ||
                        e.getCriticality() == BusinessFlowEndpoint.Criticality.MEDIUM)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        System.out.println("(API-6) 🔄 Тестирование автоматизации для " + testableEndpoints.size() + " эндпоинтов");

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testEndpointAutomation(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testEndpointAutomation(String baseUrl, String token, Map<String, String> consents,
                                        ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                        List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, "team172", consents);
            String testPayload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            System.out.println("(API-6) 🧪 Тестирование автоматизации: " + endpoint.getMethod() + " " + url);

            int successfulCalls = 0;
            int totalCalls = 3;

            for (int i = 0; i < totalCalls; i++) {
                System.out.println("(API-6) 🔁 Попытка " + (i+1) + "/" + totalCalls);

                try {
                    Object response = apiClient.executeRequest(endpoint.getMethod(), url, testPayload, headers);

                    if (response instanceof core.HttpApiClient.ApiResponse) {
                        core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                        int statusCode = apiResponse.getStatusCode();

                        if (statusCode == 403) {
                            // Анализируем 403 ошибки
                            String responseBody = apiResponse.getBody();
                            if (responseBody != null) {
                                if (responseBody.contains("CONSENT_REQUIRED") || responseBody.contains("consent")) {
                                    System.out.println("(API-6) ⚠️ Требуется согласие для доступа к эндпоинту");
                                    // Это может быть нормальным поведением безопасности
                                } else if (responseBody.contains("Forbidden")) {
                                    System.out.println("(API-6) ❌ Доступ запрещен - недостаточно прав");
                                } else if (responseBody.contains("rate limit") || responseBody.contains("limit")) {
                                    System.out.println("(API-6) ⚠️ Сработало ограничение частоты запросов");
                                }
                            }
                            System.out.println("(API-6) ❌ Неуспешный запрос: код " + statusCode + " (Forbidden)");
                        } else if (statusCode >= 200 && statusCode < 300) {
                            successfulCalls++;
                            System.out.println("(API-6) ✅ Успешный запрос: код " + statusCode);
                        } else if (statusCode == 429) {
                            System.out.println("(API-6) ⚠️ Rate limiting сработал: код 429");
                        } else {
                            System.out.println("(API-6) ❌ Неуспешный запрос: код " + statusCode);
                            if (apiResponse.getBody() != null) {
                                String bodyPreview = apiResponse.getBody().length() > 100 ?
                                        apiResponse.getBody().substring(0, 100) + "..." : apiResponse.getBody();
                                System.out.println("(API-6) 📄 Тело ответа: " + bodyPreview);
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("(API-6) 💥 Ошибка выполнения запроса: " + e.getMessage());
                }

                try {
                    Thread.sleep(1000); // Увеличиваем паузу между запросами
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
                System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Обнаружена возможность автоматизации " + endpoint.getPath());
            } else if (successfulCalls > 0) {
                System.out.println("(API-6) ⚠️ Частичная автоматизация: " + successfulCalls + "/" + totalCalls);
            } else {
                System.out.println("(API-6) ℹ️ Автоматизация невозможна: все запросы завершились ошибкой");
            }

        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка при тестировании автоматизации " + endpoint.getPath() + ": " + e.getMessage());
        }
    }

    // Проверка ограничений на частоту бизнес-операций (с согласиями)
    private void testRateLimiting(String baseUrl, String token, Map<String, String> consents,
                                  ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                  List<Vulnerability> vulnerabilities) {
        // Тестируем только высококритичные эндпоинты
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .limit(3) // Ограничиваем количество тестируемых эндпоинтов
                .collect(Collectors.toList());

        System.out.println("(API-6) 📊 Rate limiting тест для " + testableEndpoints.size() + " эндпоинтов");

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testEndpointRateLimiting(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testEndpointRateLimiting(String baseUrl, String token, Map<String, String> consents,
                                          ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                          List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, "team172", consents);
            String testPayload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            List<Integer> responseCodes = new ArrayList<>();
            int rapidRequests = 5;

            System.out.println("(API-6) 📈 Rate limiting тест для: " + endpoint.getMethod() + " " + url);

            for (int i = 0; i < rapidRequests; i++) {
                try {
                    Object response = apiClient.executeRequest(endpoint.getMethod(), url, testPayload, headers);
                    if (response instanceof core.HttpApiClient.ApiResponse) {
                        core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                        responseCodes.add(apiResponse.getStatusCode());
                        System.out.println("(API-6) 📊 Rate limiting тест " + (i+1) + "/" + rapidRequests + ": " + apiResponse.getStatusCode());

                        // Если получили 429, прерываем тест
                        if (apiResponse.getStatusCode() == 429) {
                            System.out.println("(API-6) ✅ Rate limiting обнаружен на запросе " + (i+1));
                            break;
                        }
                    }
                } catch (Exception e) {
                    System.err.println("(API-6) 💥 Ошибка в rate limiting тесте: " + e.getMessage());
                    responseCodes.add(500); // Добавляем код ошибки
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
                System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Отсутствие rate limiting для " + endpoint.getPath());
            } else if (hasRateLimiting) {
                System.out.println("(API-6) ✅ Rate limiting присутствует для " + endpoint.getPath());
            } else {
                System.out.println("(API-6) ℹ️ Rate limiting тест не показал результатов (все запросы завершились ошибкой)");
            }
        } catch (Exception e) {
            System.err.println("(API-6) ❌ Ошибка при тестировании rate limiting " + endpoint.getPath() + ": " + e.getMessage());
        }
    }

    // Анализ защиты от автоматизации
    private void testAutomationProtection(String baseUrl, String token, Map<String, String> consents,
                                          ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                          List<Vulnerability> vulnerabilities) {
        // Анализируем все высококритичные эндпоинты
        for (BusinessFlowEndpoint endpoint : endpoints.values()) {
            if (endpoint.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH) {
                analyzeEndpointProtection(endpoint, vulnerabilities);
                testIdempotencyProtection(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
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
            System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Недостаточная документация защиты для " + endpoint.getPath());
        } else {
            System.out.println("(API-6) ✅ Документация защиты присутствует для " + endpoint.getPath());
        }
    }

    private void testIdempotencyProtection(String baseUrl, String token, Map<String, String> consents,
                                           ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                           List<Vulnerability> vulnerabilities) {
        // Тестируем защиту от повторных операций (идемпотентность)
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, "team172", consents);
            String testPayload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            System.out.println("(API-6) 🔄 Тестирование идемпотентности для: " + endpoint.getMethod() + " " + url);

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
                System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Отсутствие защиты от повторных операций для " + endpoint.getPath());
            } else if (firstSuccess && !secondSuccess) {
                System.out.println("(API-6) ✅ Идемпотентность присутствует для " + endpoint.getPath());
            } else {
                System.out.println("(API-6) ℹ️ Тест идемпотентности не выполнен (первый запрос неуспешен)");
            }
        } catch (Exception e) {
            // Игнорируем ошибки - это нормально для тестовых запросов
            System.out.println("(API-6) ⚠️ Ошибка при тестировании идемпотентности: " + e.getMessage());
        }
    }

    // Тестирование обходов бизнес-логики
    private void testBusinessLogicBypass(String baseUrl, String token, Map<String, String> consents,
                                         ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                         List<Vulnerability> vulnerabilities) {
        // Тестируем высококритичные эндпоинты
        List<BusinessFlowEndpoint> testableEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        System.out.println("(API-6) 🔄 Тестирование обходов бизнес-логики для " + testableEndpoints.size() + " эндпоинтов");

        for (BusinessFlowEndpoint endpoint : testableEndpoints) {
            testBusinessLogicValidation(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testBusinessLogicValidation(String baseUrl, String token, Map<String, String> consents,
                                             ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                             List<Vulnerability> vulnerabilities) {
        // Тестируем различные сценарии обхода бизнес-логики
        testNegativeValues(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
        testBoundaryValues(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
        testInvalidDataTypes(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
        testMissingRequiredFields(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
    }

    private void testNegativeValues(String baseUrl, String token, Map<String, String> consents,
                                    ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                    List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, "team172", consents);
            String negativePayload = createNegativeValuePayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            System.out.println("(API-6) ➖ Тестирование отрицательных значений: " + endpoint.getMethod() + " " + url);

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
                System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Обход валидации отрицательных значений в " + endpoint.getPath());
            } else {
                System.out.println("(API-6) ✅ Валидация отрицательных значений присутствует для " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение - должна быть ошибка валидации
            System.out.println("(API-6) ✅ Валидация отрицательных значений работает для " + endpoint.getPath());
        }
    }

    private void testBoundaryValues(String baseUrl, String token, Map<String, String> consents,
                                    ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                    List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, "team172", consents);
            String boundaryPayload = createBoundaryValuePayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            System.out.println("(API-6) 📏 Тестирование граничных значений: " + endpoint.getMethod() + " " + url);

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
                System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Обход проверки граничных значений в " + endpoint.getPath());
            } else {
                System.out.println("(API-6) ✅ Валидация граничных значений присутствует для " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение
            System.out.println("(API-6) ✅ Валидация граничных значений работает для " + endpoint.getPath());
        }
    }

    private void testInvalidDataTypes(String baseUrl, String token, Map<String, String> consents,
                                      ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                      List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, "team172", consents);
            String invalidTypePayload = createInvalidDataTypePayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            System.out.println("(API-6) 🔤 Тестирование неверных типов данных: " + endpoint.getMethod() + " " + url);

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
                System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Обход валидации типов данных в " + endpoint.getPath());
            } else {
                System.out.println("(API-6) ✅ Валидация типов данных присутствует для " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение
            System.out.println("(API-6) ✅ Валидация типов данных работает для " + endpoint.getPath());
        }
    }

    private void testMissingRequiredFields(String baseUrl, String token, Map<String, String> consents,
                                           ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                           List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, "team172", consents);
            String minimalPayload = createMinimalPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            System.out.println("(API-6) ❓ Тестирование отсутствующих полей: " + endpoint.getMethod() + " " + url);

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
                System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Обход проверки обязательных полей в " + endpoint.getPath());
            } else {
                System.out.println("(API-6) ✅ Проверка обязательных полей присутствует для " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение
            System.out.println("(API-6) ✅ Проверка обязательных полей работает для " + endpoint.getPath());
        }
    }

    // Проверка целостности бизнес-процессов
    private void testProcessIntegrity(String baseUrl, String token, Map<String, String> consents,
                                      ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                      List<Vulnerability> vulnerabilities) {
        analyzeProcessSequences(endpoints, vulnerabilities);
        testMissingDependencies(baseUrl, token, consents, apiClient, endpoints, vulnerabilities);
        testDirectAccessToOperations(baseUrl, token, consents, apiClient, endpoints, vulnerabilities);
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
            System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Возможное нарушение целостности процесса платежей");
        } else if (hasPaymentEndpoint && hasPaymentConsentEndpoint) {
            System.out.println("(API-6) ✅ Последовательность платежей документирована");
        }
    }

    private void testMissingDependencies(String baseUrl, String token, Map<String, String> consents,
                                         ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                         List<Vulnerability> vulnerabilities) {
        // Тестируем вызов платежей без согласий
        List<BusinessFlowEndpoint> paymentEndpoints = endpoints.values().stream()
                .filter(e -> e.getPath().contains("/payments") && "POST".equals(e.getMethod()))
                .collect(Collectors.toList());

        System.out.println("(API-6) 🔗 Тестирование зависимостей для " + paymentEndpoints.size() + " платежных эндпоинтов");

        for (BusinessFlowEndpoint endpoint : paymentEndpoints) {
            testPaymentWithoutConsent(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testPaymentWithoutConsent(String baseUrl, String token, Map<String, String> consents,
                                           ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                           List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeaders(token, "team172");
            // Специально не добавляем consent headers
            String paymentPayload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            System.out.println("(API-6) 💸 Тестирование платежа без согласия: " + endpoint.getMethod() + " " + url);

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
                System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Нарушение целостности процесса платежей");
            } else {
                System.out.println("(API-6) ✅ Целостность процесса платежей соблюдается");
            }
        } catch (Exception e) {
            // Ожидаемое поведение - должна быть ошибка из-за отсутствия согласия
            System.out.println("(API-6) ✅ Целостность процесса платежей соблюдается (ошибка ожидаема)");
        }
    }

    private void testDirectAccessToOperations(String baseUrl, String token, Map<String, String> consents,
                                              ApiClient apiClient, Map<String, BusinessFlowEndpoint> endpoints,
                                              List<Vulnerability> vulnerabilities) {
        // Тестируем прямые вызовы операций, которые должны требовать предварительных шагов
        List<BusinessFlowEndpoint> criticalEndpoints = endpoints.values().stream()
                .filter(e -> e.getCriticality() == BusinessFlowEndpoint.Criticality.HIGH)
                .filter(e -> CRITICAL_OPERATIONS.contains(e.getMethod()))
                .collect(Collectors.toList());

        System.out.println("(API-6) 🔓 Тестирование прямого доступа для " + criticalEndpoints.size() + " эндпоинтов");

        for (BusinessFlowEndpoint endpoint : criticalEndpoints) {
            testDirectEndpointAccess(baseUrl, token, consents, apiClient, endpoint, vulnerabilities);
        }
    }

    private void testDirectEndpointAccess(String baseUrl, String token, Map<String, String> consents,
                                          ApiClient apiClient, BusinessFlowEndpoint endpoint,
                                          List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = createAuthHeadersWithConsents(token, "team172", consents);
            String payload = createSpecificTestPayload(endpoint);
            String url = buildTestUrl(baseUrl, endpoint.getPath());

            System.out.println("(API-6) 🎯 Тестирование прямого доступа: " + endpoint.getMethod() + " " + url);

            Object response = apiClient.executeRequest(endpoint.getMethod(), url, payload, headers);
            if (isSuccessfulResponse(response)) {
                // Если операция выполняется без дополнительных проверок - возможна проблема
                System.out.println("(API-6) ⚠️ Прямой доступ возможен: " + endpoint.getMethod() + " " + url);
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
                    System.out.println("(API-6) 🚨 УЯЗВИМОСТЬ: Прямой доступ к критичным операциям");
                }
            } else {
                System.out.println("(API-6) ✅ Прямой доступ ограничен для " + endpoint.getPath());
            }
        } catch (Exception e) {
            // Ожидаемое поведение для некоторых операций
            System.out.println("(API-6) ✅ Прямой доступ ограничен (ошибка ожидаема) для " + endpoint.getPath());
        }
    }

    // ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========

    private String buildTestUrl(String baseUrl, String path) {
        String resolvedPath = path;

        // Заменяем параметры в пути
        for (Map.Entry<String, String> param : TEST_PARAMETERS.entrySet()) {
            String paramPlaceholder = "{" + param.getKey() + "}";
            if (resolvedPath.contains(paramPlaceholder)) {
                resolvedPath = resolvedPath.replace(paramPlaceholder, param.getValue());
                System.out.println("(API-6) 🔄 Замена параметра " + paramPlaceholder + " -> " + param.getValue());
            }
        }

        String fullUrl = baseUrl + resolvedPath;
        System.out.println("(API-6) 🌐 Построен URL: " + fullUrl);
        return fullUrl;
    }

    private Map<String, String> createAuthHeaders(String token, String requestingBank) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json");
        headers.put("X-Requesting-Bank", requestingBank);

        System.out.println("(API-6) 🔑 Заголовки: Authorization=Bearer ***, X-Requesting-Bank=" + requestingBank);
        return headers;
    }

    private Map<String, String> createAuthHeadersWithConsents(String token, String requestingBank, Map<String, String> consents) {
        Map<String, String> headers = createAuthHeaders(token, requestingBank);

        // Добавляем согласия если они есть
        if (consents.containsKey("account_consent")) {
            headers.put("X-Consent-Id", consents.get("account_consent"));
        }
        if (consents.containsKey("payment_consent")) {
            headers.put("X-Payment-Consent-Id", consents.get("payment_consent"));
        }

        System.out.println("(API-6) 📋 Заголовки с согласиями: " + headers.keySet());
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

    private String extractResponseBody(Object response) {
        try {
            if (response instanceof core.ApiResponse) {
                return ((core.ApiResponse) response).getBody();
            } else if (response instanceof HttpApiClient.ApiResponse) {
                return ((HttpApiClient.ApiResponse) response).getBody();
            } else {
                return (String) response.getClass().getMethod("getBody").invoke(response);
            }
        } catch (Exception e) {
            return null;
        }
    }

    private String createSpecificTestPayload(BusinessFlowEndpoint endpoint) {
        String path = endpoint.getPath();
        String method = endpoint.getMethod();

        System.out.println("(API-6) 🎯 Создание payload для: " + method + " " + path);

        // Реальные payload из спецификации API
        if (path.contains("/payment-consents/request") && "POST".equals(method)) {
            return "{\"requesting_bank\":\"team172\",\"client_id\":\"team172-1\",\"debtor_account\":\"acc-1010\",\"amount\":100.00,\"currency\":\"RUB\",\"consent_type\":\"single_use\"}";
        } else if (path.contains("/payments") && "POST".equals(method)) {
            return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"},\"debtorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"40817810099910004312\"},\"creditorAccount\":{\"schemeName\":\"RU.CBR.PAN\",\"identification\":\"40817810099910005423\"}}}}";
        } else if (path.contains("/product-agreements") && "POST".equals(method)) {
            return "{\"product_id\":\"prod-vb-deposit-001\",\"amount\":1000.00}";
        } else if (path.contains("/account-consents/request") && "POST".equals(method)) {
            return "{\"client_id\":\"team172-1\",\"permissions\":[\"ReadAccountsDetail\",\"ReadBalances\"],\"reason\":\"Тестовый запрос\",\"requesting_bank\":\"team172\",\"requesting_bank_name\":\"Test App\"}";
        } else if (path.contains("/accounts") && "POST".equals(method)) {
            return "{\"account_type\":\"checking\",\"initial_balance\":100.00}";
        } else if (path.contains("/cards") && "POST".equals(method)) {
            return "{\"card_type\":\"debit\",\"account_id\":\"acc-1010\"}";
        } else {
            System.out.println("(API-6) ⚠️ Используется пустой payload для неподдерживаемого эндпоинта");
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

        System.out.println("(API-6) 📝 Создана уязвимость: " + title);
        return vuln;
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