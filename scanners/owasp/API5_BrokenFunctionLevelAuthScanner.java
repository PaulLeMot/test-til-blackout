package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API5_BrokenFunctionLevelAuthScanner implements SecurityScanner {

    // Административные/привилегированные эндпоинты в банковском API
    private static final List<String> ADMIN_ENDPOINTS = Arrays.asList(
            "/admin/capital",
            "/admin/key-rate",
            "/admin/key-rate/history",
            "/admin/stats",
            "/admin/teams",
            "/banker/clients",
            "/banker/consents/pending",
            "/banker/consents/{request_id}/approve",
            "/banker/consents/{request_id}/reject",
            "/payment-consents/pending/list",
            "/payment-consents/{request_id}/approve",
            "/payment-consents/{request_id}/reject"
    );

    // Критические операции, требующие повышенных привилегий
    private static final List<String> CRITICAL_OPERATIONS = Arrays.asList(
            "approve", "reject", "upload", "capital", "key-rate", "stats", "teams"
    );

    // Публичные технические эндпоинты, которые не являются уязвимостями
    private static final List<String> PUBLIC_ENDPOINTS = Arrays.asList(
            "/.well-known/jwks.json",
            "/health",
            "/openapi.json",
            "/swagger.json",
            "/swagger.yaml",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/docs"
    );

    // Параметры для управления частотой запросов
    private static final int BASE_DELAY_MS = 600;
    private static final int MAX_RETRIES = 3;
    private static final int BASE_RETRY_DELAY_MS = 1000;
    private static final double RETRY_BACKOFF_FACTOR = 2.0;

    // Для отслеживания уникальных уязвимостей
    private Set<String> reportedVulnerabilities = new HashSet<>();

    @Override
    public String getName() {
        return "OWASP API5: Broken Function Level Authorization Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-5) Сканирование уязвимостей Broken Function Level Authorization (OWASP API5)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        reportedVulnerabilities.clear();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-5) OpenAPI спецификация недоступна. Сканирование невозможно.");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        String baseUrl = config.getTargetBaseUrl().trim();

        // Получаем пользовательские токены из конфигурации
        Map<String, String> tokens = config.getUserTokens();
        if (tokens == null || tokens.size() < 2) {
            System.err.println("(API-5) Недостаточно токенов для API5-теста (нужно минимум 2).");
            return vulnerabilities;
        }

        // Получаем первых двух пользователей
        List<String> users = new ArrayList<>(tokens.keySet());
        String regularUser = users.get(0);
        String anotherUser = users.get(1);
        String regularToken = tokens.get(regularUser);
        String anotherToken = tokens.get(anotherUser);

        System.out.println("(API-5) Используются токены для пользователей: " + regularUser + ", " + anotherUser);

        // 1. Анализ OpenAPI для поиска административных эндпоинтов
        List<String> adminEndpoints = analyzeOpenAPIForAdminEndpoints(openAPI);
        System.out.println("(API-5) Найдено административных эндпоинтов в OpenAPI: " + adminEndpoints.size());

        // Добавляем известные административные эндпоинты банковского API
        for (String endpoint : ADMIN_ENDPOINTS) {
            if (!adminEndpoints.contains(endpoint)) {
                adminEndpoints.add(endpoint);
            }
        }
        System.out.println("(API-5) Общее количество эндпоинтов для проверки: " + adminEndpoints.size());

        // 2. Проверка доступа к административным эндпоинтам с правами обычного пользователя
        testAdminEndpointAccess(config, apiClient, adminEndpoints, regularUser, regularToken, vulnerabilities);

        // 3. Проверка доступа к критическим операциям (approve/reject)
        testCriticalOperations(config, apiClient, openAPI, regularUser, regularToken, vulnerabilities);

        // 4. Проверка межбанковских административных функций
        testInterbankAdminFunctions(config, apiClient, regularUser, regularToken, vulnerabilities);

        // 5. Интеллектуальное тестирование с реальными согласиями
        testCriticalOperationsWithRealConsents(config, apiClient, regularUser, regularToken, vulnerabilities);

        System.out.println("(API-5) API5 сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Анализ OpenAPI спецификации для поиска административных эндпоинтов
     */
    private List<String> analyzeOpenAPIForAdminEndpoints(OpenAPI openAPI) {
        List<String> adminEndpoints = new ArrayList<>();

        if (openAPI.getPaths() == null) {
            return adminEndpoints;
        }

        // Ищем эндпоинты с тегами, содержащими ключевые слова
        Set<String> adminTags = new HashSet<>(Arrays.asList("Internal", "Admin", "Banker", "Technical"));

        for (String path : openAPI.getPaths().keySet()) {
            PathItem pathItem = openAPI.getPaths().get(path);

            // Проверяем теги операций
            for (Operation operation : getAllOperations(pathItem)) {
                if (operation.getTags() != null) {
                    for (String tag : operation.getTags()) {
                        if (adminTags.stream().anyMatch(tag::contains)) {
                            // Проверяем, не является ли эндпоинт публичным
                            if (!isPublicEndpoint(path)) {
                                if (!adminEndpoints.contains(path)) {
                                    adminEndpoints.add(path);
                                    System.out.println("(API-5) Найден административный эндпоинт по тегу '" + tag + "': " + path);
                                }
                            }
                            break;
                        }
                    }
                }
            }

            // Проверяем путь на наличие ключевых слов
            if (path.toLowerCase().matches(".*(/admin|/banker|/internal|/system|capital|key-rate|stats|teams|approve|reject).*")) {
                if (!adminEndpoints.contains(path) && !isPublicEndpoint(path)) {
                    adminEndpoints.add(path);
                    System.out.println("(API-5) Найден административный эндпоинт по пути: " + path);
                }
            }
        }

        return adminEndpoints;
    }

    /**
     * Проверка, является ли эндпоинт публичным техническим
     */
    private boolean isPublicEndpoint(String endpoint) {
        for (String publicEndpoint : PUBLIC_ENDPOINTS) {
            if (endpoint.equals(publicEndpoint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Получение всех операций для PathItem
     */
    private List<Operation> getAllOperations(PathItem pathItem) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        return operations;
    }

    /**
     * Тестирование доступа к административным эндпоинтам
     */
    private void testAdminEndpointAccess(ScanConfig config, ApiClient apiClient,
                                         List<String> adminEndpoints, String username,
                                         String token, List<Vulnerability> vulnerabilities) {

        System.out.println("(API-5) === Тестирование доступа к административным эндпоинтам ===");

        for (int i = 0; i < adminEndpoints.size(); i++) {
            String endpoint = adminEndpoints.get(i);
            String testableEndpoint = replacePathParameters(endpoint);
            String url = config.getTargetBaseUrl() + testableEndpoint;

            System.out.println("(API-5) [" + (i+1) + "/" + adminEndpoints.size() + "] Проверка доступа к: " + url);

            // Определяем метод запроса
            String method = getRequestMethodForAdminEndpoint(endpoint);

            // Добавляем задержку для предотвращения 429 ошибки
            applyRateLimitDelay(i);

            // Выполняем запрос с повторными попытками
            HttpApiClient.ApiResponse response = executeRequestWithRetry(
                    apiClient, method, url, null, createHeaders(token, config.getBankId()),
                    username, endpoint
            );

            if (response != null) {
                checkAdminAccessVulnerability(endpoint, username, response, url, vulnerabilities);
            }
        }
    }

    /**
     * Тестирование критических операций (approve/reject)
     */
    private void testCriticalOperations(ScanConfig config, ApiClient apiClient, OpenAPI openAPI,
                                        String username, String token,
                                        List<Vulnerability> vulnerabilities) {

        System.out.println("(API-5) === Тестирование критических операций ===");

        // Ищем эндпоинты, содержащие approve/reject
        List<String> criticalEndpoints = new ArrayList<>();
        for (String path : openAPI.getPaths().keySet()) {
            if (path.contains("approve") || path.contains("reject")) {
                criticalEndpoints.add(path);
            }
        }

        System.out.println("(API-5) Найдено критических эндпоинтов для проверки: " + criticalEndpoints.size());

        for (int i = 0; i < criticalEndpoints.size(); i++) {
            String endpoint = criticalEndpoints.get(i);
            String testableEndpoint = replacePathParameters(endpoint);
            String url = config.getTargetBaseUrl() + testableEndpoint;

            System.out.println("(API-5) [" + (i+1) + "/" + criticalEndpoints.size() + "] Проверка критической операции: " + endpoint);

            // Для approve/reject обычно используется POST
            String method = "POST";

            // Тестовые payload для разных типов операций
            String payload = "{}";
            if (endpoint.contains("approve")) {
                payload = "{\"reason\": \"Security scanner test - should be rejected\"}";
            } else if (endpoint.contains("reject")) {
                payload = "{\"reason\": \"Security scanner test - should be rejected\"}";
            }

            // Добавляем задержку для предотвращения 429 ошибки
            applyRateLimitDelay(i);

            // Выполняем запрос с повторными попытками
            HttpApiClient.ApiResponse response = executeRequestWithRetry(
                    apiClient, method, url, payload, createHeaders(token, config.getBankId()),
                    username, endpoint
            );

            if (response != null) {
                checkCriticalOperationVulnerability(endpoint, username, response, url, payload, vulnerabilities);
            }
        }
    }

    /**
     * Тестирование межбанковских административных функций
     */
    private void testInterbankAdminFunctions(ScanConfig config, ApiClient apiClient,
                                             String username, String token,
                                             List<Vulnerability> vulnerabilities) {

        System.out.println("(API-5) === Тестирование межбанковских административных функций ===");

        // Эндпоинты, которые должны быть доступны только банкирам
        List<String> bankerEndpoints = Arrays.asList(
                "/banker/clients",
                "/banker/consents/pending",
                "/payment-consents/pending/list"
        );

        for (int i = 0; i < bankerEndpoints.size(); i++) {
            String endpoint = bankerEndpoints.get(i);
            String url = config.getTargetBaseUrl() + endpoint;

            System.out.println("(API-5) [" + (i+1) + "/" + bankerEndpoints.size() + "] Проверка банкирского эндпоинта: " + endpoint);

            // Добавляем задержку для предотвращения 429 ошибки
            applyRateLimitDelay(i);

            // Выполняем запрос без заголовков межбанка (как обычный клиент)
            HttpApiClient.ApiResponse response = executeRequestWithRetry(
                    apiClient, "GET", url, null, createHeaders(token, null),
                    username, endpoint
            );

            if (response != null) {
                if (isSuccessfulResponse(response)) {
                    // Уязвимость: доступ к банкирским функциям без соответствующих прав
                    createAndAddVulnerability(
                            "Доступ к банкирским функциям без прав",
                            "Пользователь " + username + " получил доступ к банкирскому эндпоинту " + endpoint +
                                    " без необходимых привилегий. Это позволяет несанкционированно просматривать клиентов и согласия.",
                            endpoint,
                            response.getStatusCode(),
                            username,
                            "banker",
                            url,
                            vulnerabilities
                    );
                } else if (response.getStatusCode() == 401 || response.getStatusCode() == 403) {
                    System.out.println("(API-5) Доступ к банкирскому эндпоинту " + endpoint + " корректно заблокирован для " + username);
                } else {
                    System.out.println("(API-5) Неожиданный статус " + response.getStatusCode() +
                            " при доступе к банкирскому эндпоинту " + endpoint + " для пользователя " + username);
                }
            }
        }
    }

    /**
     * Интеллектуальное тестирование с реальными согласиями
     */
    private void testCriticalOperationsWithRealConsents(ScanConfig config, ApiClient apiClient,
                                                        String username, String token,
                                                        List<Vulnerability> vulnerabilities) {

        System.out.println("(API-5) === Тестирование критических операций с реальными согласиями ===");

        try {
            // 1. Создаем тестовое согласие на платеж
            String consentId = createTestPaymentConsent(config, apiClient, token, username);
            if (consentId == null) {
                System.out.println("(API-5) Не удалось создать тестовое согласие для проверки критических операций");
                return;
            }
            System.out.println("(API-5) Создано тестовое согласие: " + consentId);

            // 2. Тестируем операции approve/reject с реальным ID
            String[] criticalEndpoints = {
                    "/payment-consents/" + consentId + "/approve",
                    "/payment-consents/" + consentId + "/reject"
            };

            for (String endpoint : criticalEndpoints) {
                String url = config.getTargetBaseUrl() + endpoint;
                System.out.println("(API-5) Проверка критической операции с реальным согласием: " + endpoint);

                String payload = "{\"reason\": \"Security scanner test\"}";
                HttpApiClient.ApiResponse response = executeRequestWithRetry(
                        apiClient, "POST", url, payload, createHeaders(token, config.getBankId()),
                        username, endpoint
                );

                if (response != null) {
                    if (isSuccessfulResponse(response)) {
                        createAndAddVulnerability(
                                "Несанкционированное выполнение критической операции",
                                "Пользователь " + username + " успешно выполнил критическую операцию через " + endpoint +
                                        " с правами обычного пользователя. Это позволяет одобрять или отклонять чужие платежи.",
                                endpoint,
                                response.getStatusCode(),
                                username,
                                "admin",
                                url,
                                vulnerabilities
                        );
                    } else if (response.getStatusCode() == 401 || response.getStatusCode() == 403) {
                        System.out.println("(API-5) Критическая операция " + endpoint + " корректно заблокирована для " + username);
                    } else {
                        System.out.println("(API-5) Неожиданный статус " + response.getStatusCode() +
                                " при выполнении " + endpoint + " для пользователя " + username);
                    }
                }

                // Задержка между запросами
                Thread.sleep(1000);
            }

        } catch (Exception e) {
            System.err.println("(API-5) Ошибка при тестировании критических операций с реальными согласиями: " + e.getMessage());
        }
    }

    /**
     * Создание тестового согласия на платеж
     */
    private String createTestPaymentConsent(ScanConfig config, ApiClient apiClient,
                                            String token, String username) {
        try {
            String url = config.getTargetBaseUrl() + "/payment-consents/request";

            // Получаем тестовый счет для создания согласия
            String debtorAccount = getTestAccount(config, apiClient, token, username);
            if (debtorAccount == null) {
                System.out.println("(API-5) Не удалось получить тестовый счет для создания согласия");
                return null;
            }

            // Создаем тело запроса для согласия
            String body = "{"
                    + "\"requesting_bank\": \"" + config.getBankId() + "\","
                    + "\"client_id\": \"" + username + "\","
                    + "\"consent_type\": \"single_use\","
                    + "\"amount\": 1.00,"
                    + "\"debtor_account\": \"" + debtorAccount + "\","
                    + "\"creditor_account\": \"" + debtorAccount + "\","
                    + "\"creditor_name\": \"Security Scanner Test\","
                    + "\"reference\": \"Security scanner test consent\""
                    + "}";

            HttpApiClient.ApiResponse response = executeRequestWithRetry(
                    apiClient, "POST", url, body, createHeaders(token, config.getBankId()),
                    username, "создание тестового согласия"
            );

            if (response != null && response.getStatusCode() == 200 && response.getBody() != null) {
                // Извлекаем consent_id из ответа
                Pattern pattern = Pattern.compile("\"consent_id\"\\s*:\\s*\"([^\"]+)\"");
                Matcher matcher = pattern.matcher(response.getBody());
                if (matcher.find()) {
                    return matcher.group(1);
                }

                // Попробуем другой формат
                pattern = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
                matcher = pattern.matcher(response.getBody());
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }

        } catch (Exception e) {
            System.err.println("(API-5) Ошибка при создании тестового согласия: " + e.getMessage());
        }
        return null;
    }

    /**
     * Получение тестового счета для создания согласия
     */
    private String getTestAccount(ScanConfig config, ApiClient apiClient, String token, String username) {
        try {
            String url = config.getTargetBaseUrl() + "/accounts";
            HttpApiClient.ApiResponse response = executeRequestWithRetry(
                    apiClient, "GET", url, null, createHeaders(token, null),
                    username, "получение списка счетов"
            );

            if (response != null && response.getStatusCode() == 200 && response.getBody() != null) {
                // Ищем accountId в ответе
                Pattern pattern = Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\"");
                Matcher matcher = pattern.matcher(response.getBody());
                if (matcher.find()) {
                    return matcher.group(1);
                }

                // Попробуем другой формат
                pattern = Pattern.compile("\"account_id\"\\s*:\\s*\"([^\"]+)\"");
                matcher = pattern.matcher(response.getBody());
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }

        } catch (Exception e) {
            System.err.println("(API-5) Ошибка при получении тестового счета: " + e.getMessage());
        }
        return null;
    }

    /**
     * Проверка уязвимости при доступе к административным эндпоинтам
     */
    private void checkAdminAccessVulnerability(String endpoint, String username,
                                               HttpApiClient.ApiResponse response,
                                               String url, List<Vulnerability> vulnerabilities) {

        if (isSuccessfulResponse(response)) {
            // Проверяем, не является ли эндпоинт публичным
            if (!isPublicEndpoint(endpoint)) {
                // Уязвимость: успешный доступ к административному эндпоинту
                createAndAddVulnerability(
                        "Несанкционированный доступ к административной функции",
                        "Пользователь " + username + " получил доступ к административному эндпоинту " + endpoint +
                                " с правами обычного пользователя. Статус: " + response.getStatusCode(),
                        endpoint,
                        response.getStatusCode(),
                        username,
                        "admin",
                        url,
                        vulnerabilities
                );
            } else {
                System.out.println("(API-5) Эндпоинт " + endpoint + " является публичным техническим эндпоинтом - не уязвимость");
            }
        } else if (response.getStatusCode() == 401 || response.getStatusCode() == 403) {
            System.out.println("(API-5) Доступ к " + endpoint + " корректно заблокирован для " + username);
        } else if (response.getStatusCode() == 404) {
            System.out.println("(API-5) Эндпоинт " + endpoint + " не существует в данном API");
        } else {
            System.out.println("(API-5) Неожиданный статус " + response.getStatusCode() +
                    " при доступе к " + endpoint + " для пользователя " + username);
        }
    }

    /**
     * Проверка уязвимости при выполнении критических операций
     */
    private void checkCriticalOperationVulnerability(String endpoint, String username,
                                                     HttpApiClient.ApiResponse response,
                                                     String url, String payload,
                                                     List<Vulnerability> vulnerabilities) {

        if (isSuccessfulResponse(response)) {
            // Уязвимость: успешное выполнение критической операции
            createAndAddVulnerability(
                    "Несанкционированное выполнение критической операции",
                    "Пользователь " + username + " успешно выполнил критическую операцию через " + endpoint +
                            " с правами обычного пользователя. Payload: " + payload +
                            ". Статус: " + response.getStatusCode(),
                    endpoint,
                    response.getStatusCode(),
                    username,
                    "admin",
                    url,
                    vulnerabilities
            );
        } else if (response.getStatusCode() == 401 || response.getStatusCode() == 403) {
            System.out.println("(API-5) Критическая операция " + endpoint + " корректно заблокирована для " + username);
        } else if (response.getStatusCode() == 404) {
            System.out.println("(API-5) Эндпоинт " + endpoint + " не существует в данном API");
        } else {
            System.out.println("(API-5) Неожиданный статус " + response.getStatusCode() +
                    " при выполнении " + endpoint + " для пользователя " + username);
        }
    }

    /**
     * Определение метода запроса для административного эндпоинта
     */
    private String getRequestMethodForAdminEndpoint(String endpoint) {
        if (endpoint.contains("approve") || endpoint.contains("reject") || endpoint.contains("upload")) {
            return "POST";
        }
        return "GET";
    }

    /**
     * Замена параметров пути на тестовые значения
     */
    private String replacePathParameters(String endpoint) {
        return endpoint
                .replace("{bank_code}", "vbank")
                .replace("{client_id}", "test-client-001")
                .replace("{request_id}", "req-test-001")
                .replace("{consent_id}", "consent-test-001")
                .replace("{account_id}", "acc-test-001")
                .replace("{payment_id}", "pay-test-001")
                .replace("{product_id}", "prod-test-001")
                .replace("{team_id}", "team172")
                .replace("{agreement_id}", "agr-test-001");
    }

    /**
     * Создание заголовков для запросов
     */
    private Map<String, String> createHeaders(String token, String bankId) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

        // Для межбанковских запросов
        if (bankId != null) {
            headers.put("X-Requesting-Bank", bankId);
        }

        return headers;
    }

    /**
     * Проверка успешного ответа
     */
    private boolean isSuccessfulResponse(HttpApiClient.ApiResponse response) {
        return response.getStatusCode() == 200 || response.getStatusCode() == 201 || response.getStatusCode() == 204;
    }

    /**
     * Добавление задержки для предотвращения 429 ошибки
     */
    private void applyRateLimitDelay(int requestIndex) {
        try {
            int delay = BASE_DELAY_MS;

            // Увеличиваем задержку для последних запросов
            if (requestIndex > 5) {
                delay *= 2;
            }

            // Дополнительная задержка после каждых 10 запросов
            if ((requestIndex + 1) % 10 == 0 && requestIndex > 0) {
                delay *= 3;
                System.out.println("(API-5) Дополнительная пауза перед продолжением тестирования...");
            }

            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Выполнение запроса с повторными попытками при ошибке 429
     */
    private HttpApiClient.ApiResponse executeRequestWithRetry(ApiClient apiClient, String method,
                                                              String url, String body,
                                                              Map<String, String> headers,
                                                              String username, String context) {
        int attempt = 0;
        int currentDelay = BASE_RETRY_DELAY_MS;

        while (attempt < MAX_RETRIES) {
            try {
                Object response = apiClient.executeRequest(method, url, body, headers);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    // Если запрос успешен или это не ошибка 429 - возвращаем результат
                    if (apiResponse.getStatusCode() != 429) {
                        return apiResponse;
                    }

                    System.out.println("(API-5) [" + username + "] Получена ошибка 429 при " + context +
                            ". Попытка " + (attempt + 1) + " из " + MAX_RETRIES);
                }
            } catch (Exception e) {
                System.err.println("(API-5) Ошибка при выполнении запроса: " + e.getMessage());
            }

            // Увеличиваем задержку экспоненциально
            attempt++;
            if (attempt < MAX_RETRIES) {
                try {
                    System.out.println("(API-5) Ожидание " + currentDelay + " мс перед повторной попыткой...");
                    Thread.sleep(currentDelay);
                    currentDelay = (int) (currentDelay * RETRY_BACKOFF_FACTOR);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        System.err.println("(API-5) [" + username + "] Достигнуто максимальное количество попыток для " + context);
        return null;
    }

    /**
     * Создание и добавление уязвимости в список
     */
    private void createAndAddVulnerability(String title, String description, String endpoint,
                                           int statusCode, String attacker, String victim,
                                           String url, List<Vulnerability> vulnerabilities) {

        // Создаем уникальный ключ для уязвимости
        String vulnerabilityKey = endpoint + "|" + attacker + "|" + statusCode;

        if (reportedVulnerabilities.contains(vulnerabilityKey)) {
            System.out.println("(API-5) Уязвимость уже зарегистрирована: " + endpoint);
            return; // Уязвимость уже зарегистрирована
        }

        reportedVulnerabilities.add(vulnerabilityKey);

        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API5:2023 - " + title);
        vuln.setDescription(description);

        // Определяем серьезность на основе типа уязвимости
        if (endpoint.contains("approve") || endpoint.contains("reject") ||
                endpoint.contains("banker") || endpoint.contains("/admin/")) {
            vuln.setSeverity(Vulnerability.Severity.CRITICAL);
        } else {
            vuln.setSeverity(Vulnerability.Severity.HIGH);
        }

        vuln.setCategory(Vulnerability.Category.OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH);
        vuln.setEndpoint(endpoint);
        vuln.setStatusCode(statusCode);
        vuln.setEvidence(String.format(
                "{\"attacker\":\"%s\",\"victim\":\"%s\",\"endpoint\":\"%s\",\"url\":\"%s\",\"statusCode\":%d}",
                attacker, victim, endpoint, url, statusCode
        ));

        // Добавляем рекомендации
        List<String> recommendations = new ArrayList<>();
        recommendations.add("Реализуйте строгую проверку авторизации на уровне функций");
        recommendations.add("Используйте ролевую модель доступа (RBAC) с разделением прав");
        recommendations.add("Запрещайте доступ к административным функциям для обычных пользователей");
        recommendations.add("Проверяйте права доступа перед выполнением критических операций");
        recommendations.add("Используйте централизованную систему управления доступом");
        recommendations.add("Регулярно проводите аудит прав доступа");
        recommendations.add("Внедрите принцип минимальных привилегий");
        vuln.setRecommendations(recommendations);

        vulnerabilities.add(vuln);
        System.out.println("(API-5) НАЙДЕНА УЯЗВИМОСТЬ BFLA");
        System.out.println("(API-5) " + title);
        System.out.println("(API-5) " + description);
    }
}