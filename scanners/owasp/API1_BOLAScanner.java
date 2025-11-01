// scanners/owasp/API1_BOLAScanner.java
package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.AuthManager;
import core.HttpApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.Operation;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class API1_BOLAScanner implements SecurityScanner {

    public API1_BOLAScanner() {}

    @Override
    public String getName() {
        return "API1_BOLA";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-1) Запуск сканирования на уязвимости BOLA (OWASP API Security Top 10:2023 - API1)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-1) Ошибка: передан неверный объект OpenAPI");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        String baseUrl = config.getTargetBaseUrl().trim();
        String password = config.getPassword();

        if (password == null || password.isEmpty()) {
            System.err.println("(API-1) Пароль не задан в конфигурации. BOLA-сканер пропущен.");
            return vulnerabilities;
        }

        // Получаем токены для двух пользователей
        Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(baseUrl, password);
        if (tokens.size() < 2) {
            System.err.println("(API-1) Недостаточно токенов для BOLA-теста (нужно минимум 2).");
            return vulnerabilities;
        }

        // Используем первых двух пользователей из полученных токенов
        Iterator<Map.Entry<String, String>> tokenIterator = tokens.entrySet().iterator();
        Map.Entry<String, String> user1Entry = tokenIterator.next();
        Map.Entry<String, String> user2Entry = tokenIterator.next();

        String user1 = user1Entry.getKey();
        String user2 = user2Entry.getKey();
        String token1 = user1Entry.getValue();
        String token2 = user2Entry.getValue();

        System.out.println("(API-1) Получены токены для пользователей: " + user1 + ", " + user2);

        // 5.1.1: Анализ путей эндпоинтов на наличие ID-параметров
        List<BOLATestCase> testCases = analyzeEndpointsForIDParameters(openAPI);
        System.out.println("(API-1) Найдено эндпоинтов с ID параметрами: " + testCases.size());

        // 5.1.2: Генерация тестовых ID для подмены
        Map<String, Object> testData = generateTestData(baseUrl, token1, token2, user1, user2, apiClient);

        // Выполнение тестов BOLA
        vulnerabilities.addAll(executeBOLATests(baseUrl, testCases, testData, user1, user2, token1, token2, apiClient));

        // 5.1.9: Генерация отчета с найденными уязвимостями BOLA
        generateBOLAReport(vulnerabilities);

        System.out.println("(API-1) Сканирование BOLA завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * 5.1.1: Анализ путей эндпоинтов на наличие ID-параметров (/{id}, /users/{userId})
     */
    private List<BOLATestCase> analyzeEndpointsForIDParameters(OpenAPI openAPI) {
        List<BOLATestCase> testCases = new ArrayList<>();

        if (openAPI.getPaths() == null) {
            System.out.println("(API-1) OpenAPI paths is null");
            return testCases;
        }

        Paths paths = openAPI.getPaths();
        System.out.println("(API-1) Всего путей в OpenAPI: " + paths.size());

        // Список целевых эндпоинтов для тестирования BOLA
        String[] targetEndpoints = {
                "/accounts/{account_id}",
                "/accounts/{account_id}/balances",
                "/accounts/{account_id}/transactions",
                "/accounts/{account_id}/status",
                "/accounts/{account_id}/close",
                "/account-consents/{consent_id}",
                "/payment-consents/{consent_id}",
                "/payments/{payment_id}",
                "/products/{product_id}",
                "/product-agreements/{agreement_id}"
        };

        // Создаем тестовые случаи для целевых эндпоинтов
        for (String endpoint : targetEndpoints) {
            if (paths.containsKey(endpoint)) {
                PathItem pathItem = paths.get(endpoint);

                // Анализируем все HTTP методы для этого пути
                Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();
                for (Map.Entry<PathItem.HttpMethod, Operation> entry : operations.entrySet()) {
                    PathItem.HttpMethod method = entry.getKey();
                    Operation operation = entry.getValue();

                    String methodStr = method.toString();

                    // Создаем тестовый случай для PATH параметров
                    BOLATestCase testCase = new BOLATestCase();
                    testCase.path = endpoint;
                    testCase.method = methodStr;
                    testCase.parameterLocation = "path";
                    testCase.idType = determineIDTypeFromPath(endpoint);
                    testCases.add(testCase);
                    System.out.println("(API-1) Добавлен тест PATH: " + methodStr + " " + endpoint);

                    // Для GET запросов также тестируем query параметры
                    if (methodStr.equals("GET") && operation.getParameters() != null) {
                        for (Parameter param : operation.getParameters()) {
                            if (param.getIn() != null && param.getIn().equals("query") && isIDParameter(param.getName())) {
                                BOLATestCase queryTestCase = new BOLATestCase();
                                queryTestCase.path = endpoint;
                                queryTestCase.method = methodStr;
                                queryTestCase.parameterLocation = "query";
                                queryTestCase.parameterName = param.getName();
                                queryTestCase.idType = determineIDType(param.getName());
                                testCases.add(queryTestCase);
                                System.out.println("(API-1) Добавлен тест QUERY: " + methodStr + " " + endpoint + "?" + param.getName());
                            }
                        }
                    }

                    // Для POST/PUT/PATCH добавляем тесты body параметров
                    if (methodStr.equals("POST") || methodStr.equals("PUT") || methodStr.equals("PATCH")) {
                        BOLATestCase bodyTestCase = new BOLATestCase();
                        bodyTestCase.path = endpoint;
                        bodyTestCase.method = methodStr;
                        bodyTestCase.parameterLocation = "body";
                        bodyTestCase.idType = determineIDTypeFromPath(endpoint);
                        testCases.add(bodyTestCase);
                        System.out.println("(API-1) Добавлен тест BODY: " + methodStr + " " + endpoint);
                    }
                }
            }
        }

        // Также анализируем эндпоинты с query параметрами client_id
        String[] queryEndpoints = {"/accounts", "/product-agreements"};
        for (String endpoint : queryEndpoints) {
            if (paths.containsKey(endpoint)) {
                PathItem pathItem = paths.get(endpoint);
                Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();

                for (Map.Entry<PathItem.HttpMethod, Operation> entry : operations.entrySet()) {
                    PathItem.HttpMethod method = entry.getKey();
                    Operation operation = entry.getValue();

                    if (operation.getParameters() != null) {
                        for (Parameter param : operation.getParameters()) {
                            if (param.getIn() != null && param.getIn().equals("query") &&
                                    (param.getName().contains("client_id") || param.getName().contains("clientId"))) {

                                BOLATestCase testCase = new BOLATestCase();
                                testCase.path = endpoint;
                                testCase.method = method.toString();
                                testCase.parameterLocation = "query";
                                testCase.parameterName = param.getName();
                                testCase.idType = "client_id";
                                testCases.add(testCase);
                                System.out.println("(API-1) Добавлен тест QUERY: " + method.toString() + " " + endpoint + "?" + param.getName());
                            }
                        }
                    }
                }
            }
        }

        return testCases;
    }

    /**
     * Определение типа ID параметра из пути
     */
    private String determineIDTypeFromPath(String path) {
        if (path.contains("{account_id}") || path.contains("{accountId}") || path.contains("{account}")) {
            return "account_id";
        } else if (path.contains("{consent_id}") || path.contains("{consentId}") || path.contains("{consent}")) {
            return "consent_id";
        } else if (path.contains("{payment_id}") || path.contains("{paymentId}") || path.contains("{payment}")) {
            return "payment_id";
        } else if (path.contains("{agreement_id}") || path.contains("{agreementId}") || path.contains("{agreement}")) {
            return "agreement_id";
        } else if (path.contains("{client_id}") || path.contains("{clientId}") || path.contains("{client}")) {
            return "client_id";
        } else if (path.contains("{product_id}") || path.contains("{productId}") || path.contains("{product}")) {
            return "product_id";
        }

        return "generic_id";
    }

    /**
     * Проверка является ли параметр ID параметром
     */
    private boolean isIDParameter(String paramName) {
        if (paramName == null) return false;

        String[] idKeywords = {"id", "account", "client", "consent", "payment", "agreement", "user", "customer", "product"};
        String lowerParam = paramName.toLowerCase();

        for (String keyword : idKeywords) {
            if (lowerParam.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Определение типа ID параметра
     */
    private String determineIDType(String paramName) {
        if (paramName == null) return "generic_id";

        String lowerParam = paramName.toLowerCase();

        if (lowerParam.contains("account")) return "account_id";
        if (lowerParam.contains("client")) return "client_id";
        if (lowerParam.contains("consent")) return "consent_id";
        if (lowerParam.contains("payment")) return "payment_id";
        if (lowerParam.contains("agreement")) return "agreement_id";
        if (lowerParam.contains("product")) return "product_id";
        if (lowerParam.contains("user")) return "user_id";

        return "generic_id";
    }

    /**
     * 5.1.2: Генерация тестовых ID для подмены (числа, UUID, строки)
     */
    private Map<String, Object> generateTestData(String baseUrl, String token1, String token2,
                                                 String user1, String user2, ApiClient apiClient) {
        Map<String, Object> testData = new HashMap<>();

        System.out.println("(API-1) Генерация тестовых данных...");

        // Получаем реальные ID от пользователей
        List<String> user1Accounts = getAccountIds(baseUrl, token1, apiClient);
        List<String> user2Accounts = getAccountIds(baseUrl, token2, apiClient);

        testData.put("user1_accounts", user1Accounts);
        testData.put("user2_accounts", user2Accounts);

        // Если нет реальных account_id, создаем тестовые данные на основе имен пользователей
        if (user1Accounts.isEmpty()) {
            user1Accounts = Arrays.asList(user1 + "-account-1", user1 + "-account-2");
            testData.put("user1_accounts", user1Accounts);
        }
        if (user2Accounts.isEmpty()) {
            user2Accounts = Arrays.asList(user2 + "-account-1", user2 + "-account-2");
            testData.put("user2_accounts", user2Accounts);
        }

        // Генерируем случайные ID для тестирования
        testData.put("random_uuid", UUID.randomUUID().toString());
        testData.put("random_numeric", "999999");
        testData.put("random_string", "test_id_123");
        testData.put("sequential_ids", Arrays.asList("123", "456", "789", "1000", "1001"));

        System.out.println("(API-1) Сгенерировано тестовых ID:");
        System.out.println("(API-1) - user1_accounts: " + testData.get("user1_accounts"));
        System.out.println("(API-1) - user2_accounts: " + testData.get("user2_accounts"));
        System.out.println("(API-1) - Случайные ID: " + testData.get("random_uuid") + ", " + testData.get("random_numeric"));

        return testData;
    }

    /**
     * Получение ID счетов пользователя
     */
    private List<String> getAccountIds(String baseUrl, String token, ApiClient apiClient) {
        List<String> accountIds = new ArrayList<>();
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("GET", baseUrl + "/accounts", null, headers);
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                System.out.println("(API-1) Ответ от /accounts: статус " + apiResponse.getStatusCode());

                if (apiResponse.getStatusCode() == 200) {
                    String responseBody = apiResponse.getBody();

                    // Пробуем разные паттерны для извлечения ID
                    Pattern[] patterns = {
                            Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\""),
                            Pattern.compile("\"account_id\"\\s*:\\s*\"([^\"]+)\""),
                            Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"")
                    };

                    for (Pattern pattern : patterns) {
                        Matcher matcher = pattern.matcher(responseBody);
                        while (matcher.find()) {
                            String accountId = matcher.group(1);
                            if (!accountIds.contains(accountId)) {
                                accountIds.add(accountId);
                            }
                        }
                    }
                } else {
                    System.out.println("(API-1) Не удалось получить счета, статус: " + apiResponse.getStatusCode());
                }
            }
        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при получении счетов: " + e.getMessage());
        }

        System.out.println("(API-1) Извлеченные account_ids: " + accountIds);
        return accountIds;
    }

    /**
     * Выполнение тестов BOLA
     */
    private List<Vulnerability> executeBOLATests(String baseUrl, List<BOLATestCase> testCases,
                                                 Map<String, Object> testData, String user1, String user2,
                                                 String token1, String token2, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        System.out.println("(API-1) Выполнение тестов BOLA...");

        if (testCases.isEmpty()) {
            System.out.println("(API-1) Нет тестовых случаев для выполнения");
            // Даже если нет тестовых случаев из OpenAPI, выполняем базовые тесты
            vulnerabilities.addAll(executeBasicBOLATests(baseUrl, testData, user1, user2, token1, token2, apiClient));
            return vulnerabilities;
        }

        // 5.1.3: Подмена ID в path-параметрах
        vulnerabilities.addAll(testPathParameterBOLA(baseUrl, testCases, testData, user1, user2, token2, apiClient));

        // 5.1.4: Подмена ID в query-параметрах
        vulnerabilities.addAll(testQueryParameterBOLA(baseUrl, testCases, testData, user1, user2, token2, apiClient));

        // 5.1.5: Подмена ID в body-запросах
        vulnerabilities.addAll(testBodyParameterBOLA(baseUrl, testCases, testData, user1, user2, token2, apiClient));

        // 5.1.7: Обход коллекций
        vulnerabilities.addAll(testCollectionBypass(baseUrl, user1, user2, token1, token2, apiClient));

        // 5.1.8: Сравнение прав доступа между разными пользователями
        vulnerabilities.addAll(testPermissionComparison(baseUrl, testData, user1, user2, token1, token2, apiClient));

        return vulnerabilities;
    }

    /**
     * Базовые тесты BOLA, если не удалось извлечь тесты из OpenAPI
     */
    private List<Vulnerability> executeBasicBOLATests(String baseUrl, Map<String, Object> testData,
                                                      String user1, String user2, String token1, String token2,
                                                      ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        System.out.println("(API-1) Выполнение базовых тестов BOLA...");

        // Базовые тесты для common endpoints
        String[][] basicTests = {
                {"/accounts/{account_id}", "GET", "path", "account_id"},
                {"/accounts/{account_id}/balances", "GET", "path", "account_id"},
                {"/accounts/{account_id}/transactions", "GET", "path", "account_id"},
                {"/accounts", "GET", "query", "client_id"},
                {"/product-agreements", "GET", "query", "client_id"}
        };

        for (String[] test : basicTests) {
            String path = test[0];
            String method = test[1];
            String location = test[2];
            String idType = test[3];

            BOLATestCase testCase = new BOLATestCase();
            testCase.path = path;
            testCase.method = method;
            testCase.parameterLocation = location;
            testCase.idType = idType;
            if (location.equals("query")) {
                testCase.parameterName = idType;
            }

            List<BOLATestCase> singleTestCase = Arrays.asList(testCase);

            if (location.equals("path")) {
                vulnerabilities.addAll(testPathParameterBOLA(baseUrl, singleTestCase, testData, user1, user2, token2, apiClient));
            } else if (location.equals("query")) {
                vulnerabilities.addAll(testQueryParameterBOLA(baseUrl, singleTestCase, testData, user1, user2, token2, apiClient));
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.3: Подмена ID в path-параметрах (/users/123 → /users/456)
     */
    private List<Vulnerability> testPathParameterBOLA(String baseUrl, List<BOLATestCase> testCases,
                                                      Map<String, Object> testData, String user1, String user2,
                                                      String attackerToken, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (BOLATestCase testCase : testCases) {
            if (!testCase.parameterLocation.equals("path")) continue;

            System.out.println("(API-1) Тестирование PATH BOLA: " + testCase.method + " " + testCase.path);

            // Получаем ID пользователя 1 для подмены
            List<String> testIds = getTestIdsForType(testCase.idType, testData, "user1");

            for (String testId : testIds.subList(0, Math.min(3, testIds.size()))) { // Ограничиваем количество тестов
                // Заменяем ID в пути
                String testPath = replacePathParameters(testCase.path, testId);
                String fullUrl = baseUrl + testPath;

                System.out.println("(API-1) Тестирование URL: " + fullUrl);

                // Выполняем запрос с токеном атакующего
                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, testCase.method, fullUrl, attackerToken);

                // 5.1.6: Проверка ответов на коды 403/404/200 при подмене ID
                if (response != null) {
                    int statusCode = response.getStatusCode();
                    boolean isVulnerable = isVulnerableStatusCode(statusCode, testCase.method);

                    if (isVulnerable) {
                        Vulnerability vuln = createBOLAVulnerability(
                                "BOLA через PATH параметр",
                                "Пользователь " + user2 + " получил доступ к ресурсу " + testCase.path +
                                        " с ID " + testId + ", принадлежащим " + user1 + ". HTTP статус: " + statusCode +
                                        ". Эндпоинт не проверяет права доступа на уровне объектов.",
                                testCase.path,
                                statusCode,
                                user2, user1, fullUrl,
                                testCase.idType, testId, "path"
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: доступ через PATH параметр к " + testPath);
                    } else {
                        System.out.println("(API-1) Защита работает: статус " + statusCode + " для " + testPath);
                    }
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.4: Подмена ID в query-параметрах (?user_id=123 → ?user_id=456)
     */
    private List<Vulnerability> testQueryParameterBOLA(String baseUrl, List<BOLATestCase> testCases,
                                                       Map<String, Object> testData, String user1, String user2,
                                                       String attackerToken, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (BOLATestCase testCase : testCases) {
            if (!testCase.parameterLocation.equals("query")) continue;

            System.out.println("(API-1) Тестирование QUERY BOLA: " + testCase.method + " " + testCase.path + "?" + testCase.parameterName);

            List<String> testIds = getTestIdsForType(testCase.idType, testData, "user1");

            for (String testId : testIds.subList(0, Math.min(2, testIds.size()))) {
                // Добавляем query параметр
                String queryParam = testCase.parameterName + "=" + testId;
                String testUrl = baseUrl + testCase.path + (testCase.path.contains("?") ? "&" : "?") + queryParam;

                System.out.println("(API-1) Тестирование URL: " + testUrl);

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, testCase.method, testUrl, attackerToken);

                if (response != null) {
                    int statusCode = response.getStatusCode();
                    boolean isVulnerable = isVulnerableStatusCode(statusCode, testCase.method);

                    if (isVulnerable) {
                        Vulnerability vuln = createBOLAVulnerability(
                                "BOLA через QUERY параметр",
                                "Пользователь " + user2 + " получил доступ через query параметр " + testCase.parameterName +
                                        " с ID " + testId + ", принадлежащим " + user1 + ". HTTP статус: " + statusCode +
                                        ". Эндпоинт не проверяет права доступа для query параметров.",
                                testCase.path + "?" + queryParam,
                                statusCode,
                                user2, user1, testUrl,
                                testCase.idType, testId, "query"
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: доступ через QUERY параметр " + testCase.parameterName);
                    } else {
                        System.out.println("(API-1) Защита работает: статус " + statusCode + " для " + testUrl);
                    }
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.5: Подмена ID в body-запросах (для POST/PUT/PATCH)
     */
    private List<Vulnerability> testBodyParameterBOLA(String baseUrl, List<BOLATestCase> testCases,
                                                      Map<String, Object> testData, String user1, String user2,
                                                      String attackerToken, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (BOLATestCase testCase : testCases) {
            if (!testCase.parameterLocation.equals("body")) continue;

            System.out.println("(API-1) Тестирование BODY BOLA: " + testCase.method + " " + testCase.path);

            List<String> testIds = getTestIdsForType(testCase.idType, testData, "user1");

            for (String testId : testIds.subList(0, Math.min(2, testIds.size()))) {
                String testPath = replacePathParameters(testCase.path, testId);
                String fullUrl = baseUrl + testPath;

                // Создаем корректное тело запроса в зависимости от эндпоинта
                String requestBody = createAppropriateRequestBody(testCase.path, testCase.method, testCase.idType, testId);

                if (requestBody == null) {
                    continue; // Пропускаем если не можем создать корректное тело
                }

                System.out.println("(API-1) Тестирование URL: " + fullUrl + " с телом: " + requestBody);

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, testCase.method,
                        fullUrl, attackerToken, requestBody);

                if (response != null) {
                    int statusCode = response.getStatusCode();
                    boolean isVulnerable = isVulnerableStatusCode(statusCode, testCase.method);

                    if (isVulnerable) {
                        Vulnerability vuln = createBOLAVulnerability(
                                "BOLA через BODY параметр",
                                "Пользователь " + user2 + " выполнил операцию " + testCase.method +
                                        " через body с ID " + testId + ", принадлежащим " + user1 + ". HTTP статус: " + statusCode +
                                        ". Эндпоинт не проверяет права доступа в теле запроса.",
                                testCase.path,
                                statusCode,
                                user2, user1, fullUrl,
                                testCase.idType, testId, "body"
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: доступ через BODY параметр для " + testCase.path);
                    } else {
                        System.out.println("(API-1) Защита работает: статус " + statusCode + " для " + fullUrl);
                    }
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.7: Обход коллекций (/users/me/accounts → /users/123/accounts)
     */
    private List<Vulnerability> testCollectionBypass(String baseUrl, String user1, String user2,
                                                     String token1, String token2, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        System.out.println("(API-1) Тестирование обхода коллекций...");

        // Получаем реальные account_id пользователя 1
        List<String> user1Accounts = getAccountIds(baseUrl, token1, apiClient);
        if (user1Accounts.isEmpty()) return vulnerabilities;

        String user1Account = user1Accounts.get(0);

        // Тестируем прямой доступ к ресурсам другого пользователя
        String[][] directAccessTests = {
                {"/accounts/" + user1Account, "GET"},
                {"/accounts/" + user1Account + "/balances", "GET"},
                {"/accounts/" + user1Account + "/transactions", "GET"}
        };

        for (String[] test : directAccessTests) {
            String endpoint = test[0];
            String method = test[1];
            String fullUrl = baseUrl + endpoint;

            System.out.println("(API-1) Тестирование прямого доступа: " + fullUrl);

            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, method, fullUrl, token2);

            if (response != null && isVulnerableStatusCode(response.getStatusCode(), method)) {
                Vulnerability vuln = createBOLAVulnerability(
                        "BOLA через прямой доступ к ресурсам",
                        "Пользователь " + user2 + " получил прямой доступ к ресурсу " + endpoint +
                                ", принадлежащему " + user1 + ". HTTP статус: " + response.getStatusCode() +
                                ". Обнаружен обход защиты через прямой доступ к объектам по ID.",
                        endpoint,
                        response.getStatusCode(),
                        user2, user1, fullUrl,
                        "account_id", user1Account, "direct_access"
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: прямой доступ к " + endpoint);
            } else if (response != null) {
                System.out.println("(API-1) Защита работает: статус " + response.getStatusCode() + " для " + endpoint);
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.8: Сравнение прав доступа между разными пользователями
     */
    private List<Vulnerability> testPermissionComparison(String baseUrl, Map<String, Object> testData,
                                                         String user1, String user2, String token1, String token2,
                                                         ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        System.out.println("(API-1) Сравнение прав доступа между пользователями...");

        // user1 имеет счета, user2 - нет (согласно логам)
        List<String> user1Accounts = (List<String>) testData.get("user1_accounts");

        if (!user1Accounts.isEmpty()) {
            // Проверяем, может ли user2 получить доступ к счетам user1 через разные эндпоинты
            String user1Account = user1Accounts.get(0);
            String[] testEndpoints = {
                    "/accounts/" + user1Account,
                    "/accounts/" + user1Account + "/balances",
                    "/accounts/" + user1Account + "/transactions"
            };

            for (String endpoint : testEndpoints) {
                String fullUrl = baseUrl + endpoint;

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET", fullUrl, token2);

                if (response != null && isVulnerableStatusCode(response.getStatusCode(), "GET")) {
                    Vulnerability vuln = createBOLAVulnerability(
                            "BOLA через несанкционированный доступ к объектам",
                            "Пользователь " + user2 + " имеет доступ к объекту " + user1Account +
                                    ", принадлежащему " + user1 + " через эндпоинт " + endpoint +
                                    ". Обнаружено нарушение разграничения прав доступа между пользователями.",
                            endpoint,
                            response.getStatusCode(),
                            user2, user1, fullUrl,
                            "account_id", user1Account, "permission_comparison"
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: несанкционированный доступ к " + user1Account);
                } else if (response != null) {
                    System.out.println("(API-1) Защита работает: статус " + response.getStatusCode() + " для " + endpoint);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.9: Генерация отчета с найденными уязвимостями BOLA
     */
    private void generateBOLAReport(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities.isEmpty()) {
            System.out.println("(API-1) ОТЧЕТ BOLA: Уязвимостей не обнаружено");
            return;
        }

        System.out.println("\n(API-1) ===== ОТЧЕТ ПО УЯЗВИМОСТЯМ BOLA =====");
        System.out.println("(API-1) Всего обнаружено уязвимостей: " + vulnerabilities.size());

        Map<String, Integer> vulnerabilityTypes = new HashMap<>();
        for (Vulnerability vuln : vulnerabilities) {
            String evidence = vuln.getEvidence();
            String type = evidence.contains("path") ? "PATH" :
                    evidence.contains("query") ? "QUERY" :
                            evidence.contains("body") ? "BODY" :
                                    evidence.contains("direct") ? "DIRECT_ACCESS" :
                                            evidence.contains("permission") ? "PERMISSION" : "OTHER";

            vulnerabilityTypes.put(type, vulnerabilityTypes.getOrDefault(type, 0) + 1);
        }

        System.out.println("(API-1) Распределение по типам:");
        for (Map.Entry<String, Integer> entry : vulnerabilityTypes.entrySet()) {
            System.out.println("(API-1) - " + entry.getKey() + ": " + entry.getValue());
        }
        System.out.println("(API-1) ======================================\n");
    }

    // ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================

    private List<String> getTestIdsForType(String idType, Map<String, Object> testData, String user) {
        String key = user + "_" + idType.replace("_id", "s");
        @SuppressWarnings("unchecked")
        List<String> ids = (List<String>) testData.get(key);

        if (ids != null && !ids.isEmpty()) {
            return ids;
        }

        // Если нет реальных ID, используем сгенерированные
        return Arrays.asList(
                (String) testData.get("random_numeric"),
                (String) testData.get("random_uuid"),
                (String) testData.get("random_string")
        );
    }

    /**
     * Замена параметров пути на реальные значения
     */
    private String replacePathParameters(String path, String newId) {
        if (path == null || newId == null) return path;

        String result = path;

        // Список всех возможных паттернов параметров
        String[] parameterPatterns = {
                "\\{account_id\\}", "\\{accountId\\}", "\\{account\\}",
                "\\{consent_id\\}", "\\{consentId\\}", "\\{consent\\}",
                "\\{payment_id\\}", "\\{paymentId\\}", "\\{payment\\}",
                "\\{agreement_id\\}", "\\{agreementId\\}", "\\{agreement\\}",
                "\\{client_id\\}", "\\{clientId\\}", "\\{client\\}",
                "\\{product_id\\}", "\\{productId\\}", "\\{product\\}",
                "\\{id\\}"
        };

        // Заменяем все возможные параметры
        for (String pattern : parameterPatterns) {
            result = result.replaceAll(pattern, newId);
        }

        return result;
    }

    /**
     * Создание корректного тела запроса в зависимости от эндпоинта
     */
    private String createAppropriateRequestBody(String path, String method, String idType, String id) {
        if (path.contains("/status")) {
            return "{\"status\":\"active\"}";
        } else if (path.contains("/close")) {
            return "{\"action\":\"donate\"}";
        } else if (path.contains("/product-agreements")) {
            return "{\"product_id\":\"prod-test\",\"amount\":1000}";
        } else {
            // Универсальное тело для других эндпоинтов
            Map<String, Object> body = new HashMap<>();
            body.put(idType, id);

            StringBuilder json = new StringBuilder("{");
            for (Map.Entry<String, Object> entry : body.entrySet()) {
                if (json.length() > 1) json.append(",");
                json.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
            }
            json.append("}");
            return json.toString();
        }
    }

    private boolean isVulnerableStatusCode(int statusCode, String method) {
        // 5.1.6: Проверка ответов на коды 403/404/200 при подмене ID
        // Успешный доступ (200/201) считается уязвимостью

        if (method.equals("GET")) {
            return statusCode == 200;
        } else {
            return statusCode == 200 || statusCode == 201;
        }
    }

    private HttpApiClient.ApiResponse makeAuthenticatedRequest(ApiClient apiClient, String method, String url, String token) {
        return makeAuthenticatedRequest(apiClient, method, url, token, null);
    }

    private HttpApiClient.ApiResponse makeAuthenticatedRequest(ApiClient apiClient, String method, String url, String token, String body) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Accept", "application/json");
            if (body != null) {
                headers.put("Content-Type", "application/json");
            }

            Object response = apiClient.executeRequest(method, url, body, headers);
            return (HttpApiClient.ApiResponse) response;
        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при запросе " + url + ": " + e.getMessage());
            return null;
        }
    }

    private Vulnerability createBOLAVulnerability(String title, String description, String endpoint,
                                                  int statusCode, String attacker, String victim, String url,
                                                  String idType, String exploitedId, String attackVector) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API1:2023 - Broken Object Level Authorization - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(Vulnerability.Severity.HIGH);
        vuln.setCategory(Vulnerability.Category.OWASP_API1_BOLA);
        vuln.setEndpoint(endpoint);
        vuln.setStatusCode(statusCode);
        vuln.setEvidence(String.format(
                "{\"attacker\":\"%s\",\"victim\":\"%s\",\"endpoint\":\"%s\",\"url\":\"%s\"," +
                        "\"statusCode\":%d,\"idType\":\"%s\",\"exploitedId\":\"%s\",\"attackVector\":\"%s\"}",
                attacker, victim, endpoint, url, statusCode, idType, exploitedId, attackVector
        ));

        List<String> recommendations = new ArrayList<>();
        recommendations.add("Реализуйте проверку прав доступа на уровне объектов для каждого запроса");
        recommendations.add("Используйте механизмы авторизации, которые проверяют принадлежность объекта пользователю");
        recommendations.add("Не полагайтесь только на ID параметры в запросе - проверяйте контекст пользователя");
        recommendations.add("Используйте случайные UUID вместо последовательных ID");
        recommendations.add("Регулярно проводите тестирование на уязвимости BOLA");
        recommendations.add("Внедрите централизованную систему контроля доступа");
        recommendations.add("Обеспечьте, чтобы пользователи могли access только свои объекты");
        recommendations.add("Для чувствительных операций используйте двухфакторную проверку прав доступа");
        vuln.setRecommendations(recommendations);

        return vuln;
    }

    /**
     * Вспомогательный класс для тестовых случаев BOLA
     */
    private static class BOLATestCase {
        String path;
        String method;
        String parameterLocation; // "path", "query", "body"
        String parameterName; // для query параметров
        String idType; // "account_id", "client_id", etc.
    }
}
