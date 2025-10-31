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

        Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(baseUrl, password);
        if (tokens.size() < 2) {
            System.err.println("(API-1) Недостаточно токенов для BOLA-теста (нужно минимум 2).");
            return vulnerabilities;
        }

        String user1 = "team172-1";
        String user2 = "team172-2";
        String token1 = tokens.get(user1);
        String token2 = tokens.get(user2);

        if (token1 == null || token2 == null) {
            System.err.println("(API-1) Не удалось получить токены для обоих пользователей.");
            return vulnerabilities;
        }

        System.out.println("(API-1) Получены токены для пользователей: " + user1 + ", " + user2);

        // 5.1.1: Анализ путей эндпоинтов на наличие ID-параметров
        List<BOLATestCase> testCases = analyzeEndpointsForIDParameters(openAPI);
        System.out.println("(API-1) Найдено эндпоинтов с ID параметрами: " + testCases.size());

        // 5.1.2: Генерация тестовых ID для подмены
        Map<String, Object> testData = generateTestData(baseUrl, token1, token2, apiClient);

        // Выполнение тестов BOLA
        vulnerabilities.addAll(executeBOLATests(baseUrl, testCases, testData, user1, user2, token1, token2, apiClient));

        System.out.println("(API-1) Сканирование BOLA завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * 5.1.1: Анализ путей эндпоинтов на наличие ID-параметров
     */
    private List<BOLATestCase> analyzeEndpointsForIDParameters(OpenAPI openAPI) {
        List<BOLATestCase> testCases = new ArrayList<>();

        if (openAPI.getPaths() == null) {
            return testCases;
        }

        Paths paths = openAPI.getPaths();
        for (String path : paths.keySet()) {
            PathItem pathItem = paths.get(path);

            // Проверяем наличие ID параметров в пути
            if (containsIDParameters(path)) {
                // Анализируем все методы для этого пути
                for (PathItem.HttpMethod method : pathItem.readOperationsMap().keySet()) {
                    BOLATestCase testCase = new BOLATestCase();
                    testCase.path = path;
                    testCase.method = method.toString();
                    testCase.parameterLocation = "path";

                    // Определяем тип ID параметра
                    if (path.contains("{account_id}") || path.contains("{accountId}")) {
                        testCase.idType = "account_id";
                    } else if (path.contains("{consent_id}") || path.contains("{consentId}")) {
                        testCase.idType = "consent_id";
                    } else if (path.contains("{payment_id}") || path.contains("{paymentId}")) {
                        testCase.idType = "payment_id";
                    } else if (path.contains("{agreement_id}") || path.contains("{agreementId}")) {
                        testCase.idType = "agreement_id";
                    } else if (path.contains("{client_id}") || path.contains("{clientId}")) {
                        testCase.idType = "client_id";
                    } else {
                        testCase.idType = "generic_id";
                    }

                    testCases.add(testCase);
                }
            }

            // Также проверяем query параметры
            for (PathItem.HttpMethod method : pathItem.readOperationsMap().keySet()) {
                var operation = pathItem.readOperationsMap().get(method);
                if (operation.getParameters() != null) {
                    for (Parameter param : operation.getParameters()) {
                        if (param.getIn().equals("query") && isIDParameter(param.getName())) {
                            BOLATestCase testCase = new BOLATestCase();
                            testCase.path = path;
                            testCase.method = method.toString();
                            testCase.parameterLocation = "query";
                            testCase.parameterName = param.getName();
                            testCase.idType = determineIDType(param.getName());
                            testCases.add(testCase);
                        }
                    }
                }
            }
        }

        return testCases;
    }

    /**
     * Проверка содержит ли путь ID параметры
     */
    private boolean containsIDParameters(String path) {
        String[] idPatterns = {
                "\\{.*[iI][dD].*\\}", "\\{.*account.*\\}", "\\{.*client.*\\}",
                "\\{.*consent.*\\}", "\\{.*payment.*\\}", "\\{.*agreement.*\\}"
        };

        for (String pattern : idPatterns) {
            if (Pattern.compile(pattern).matcher(path).find()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Проверка является ли параметр ID параметром
     */
    private boolean isIDParameter(String paramName) {
        String[] idKeywords = {"id", "account", "client", "consent", "payment", "agreement", "user"};
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
        String lowerParam = paramName.toLowerCase();

        if (lowerParam.contains("account")) return "account_id";
        if (lowerParam.contains("client")) return "client_id";
        if (lowerParam.contains("consent")) return "consent_id";
        if (lowerParam.contains("payment")) return "payment_id";
        if (lowerParam.contains("agreement")) return "agreement_id";
        if (lowerParam.contains("user")) return "user_id";

        return "generic_id";
    }

    /**
     * 5.1.2: Генерация тестовых ID для подмены
     */
    private Map<String, Object> generateTestData(String baseUrl, String token1, String token2, ApiClient apiClient) {
        Map<String, Object> testData = new HashMap<>();

        // Получаем реальные ID от пользователя 1
        testData.put("user1_accounts", getAccountIds(baseUrl, token1, apiClient));
        testData.put("user1_consents", getConsentIds(baseUrl, token1, apiClient));
        testData.put("user1_payments", getPaymentIds(baseUrl, token1, apiClient));
        testData.put("user1_agreements", getAgreementIds(baseUrl, token1, apiClient));

        // Получаем реальные ID от пользователя 2
        testData.put("user2_accounts", getAccountIds(baseUrl, token2, apiClient));
        testData.put("user2_consents", getConsentIds(baseUrl, token2, apiClient));
        testData.put("user2_payments", getPaymentIds(baseUrl, token2, apiClient));
        testData.put("user2_agreements", getAgreementIds(baseUrl, token2, apiClient));

        // Генерируем случайные ID для тестирования
        testData.put("random_uuid", UUID.randomUUID().toString());
        testData.put("random_numeric", "");
        testData.put("random_string", "test_id_123");

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
                if (apiResponse.getStatusCode() == 200) {
                    // Ищем account_id в ответе
                    Pattern pattern = Pattern.compile("\"account_id\"\\s*:\\s*\"([^\"]+)\"");
                    Matcher matcher = pattern.matcher(apiResponse.getBody());
                    while (matcher.find()) {
                        accountIds.add(matcher.group(1));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при получении счетов: " + e.getMessage());
        }
        return accountIds;
    }

    /**
     * Получение ID согласий
     */
    private List<String> getConsentIds(String baseUrl, String token, ApiClient apiClient) {
        List<String> consentIds = new ArrayList<>();
        // Эндпоинт для получения согласий может отличаться
        // В данном случае пробуем получить через известные эндпоинты
        return consentIds;
    }

    /**
     * Получение ID платежей
     */
    private List<String> getPaymentIds(String baseUrl, String token, ApiClient apiClient) {
        List<String> paymentIds = new ArrayList<>();
        // Эндпоинт для получения списка платежей может быть недоступен
        return paymentIds;
    }

    /**
     * Получение ID договоров
     */
    private List<String> getAgreementIds(String baseUrl, String token, ApiClient apiClient) {
        List<String> agreementIds = new ArrayList<>();
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("GET", baseUrl + "/product-agreements", null, headers);
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                if (apiResponse.getStatusCode() == 200) {
                    // Ищем agreement_id в ответе
                    Pattern pattern = Pattern.compile("\"agreement_id\"\\s*:\\s*\"([^\"]+)\"");
                    Matcher matcher = pattern.matcher(apiResponse.getBody());
                    while (matcher.find()) {
                        agreementIds.add(matcher.group(1));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при получении договоров: " + e.getMessage());
        }
        return agreementIds;
    }

    /**
     * Выполнение тестов BOLA
     */
    private List<Vulnerability> executeBOLATests(String baseUrl, List<BOLATestCase> testCases,
                                                 Map<String, Object> testData, String user1, String user2,
                                                 String token1, String token2, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (BOLATestCase testCase : testCases) {
            System.out.println("(API-1) Тестирование BOLA для: " + testCase.method + " " + testCase.path);

            // 5.1.3: Подмена ID в path-параметрах
            if (testCase.parameterLocation.equals("path")) {
                vulnerabilities.addAll(testPathParameterBOLA(baseUrl, testCase, testData, user1, user2, token2, apiClient));
            }

            // 5.1.4: Подмена ID в query-параметрах
            if (testCase.parameterLocation.equals("query")) {
                vulnerabilities.addAll(testQueryParameterBOLA(baseUrl, testCase, testData, user1, user2, token2, apiClient));
            }

            // 5.1.5: Подмена ID в body-запросах (для POST/PUT/PATCH)
            if (testCase.method.equals("POST") || testCase.method.equals("PUT") || testCase.method.equals("PATCH")) {
                vulnerabilities.addAll(testBodyParameterBOLA(baseUrl, testCase, testData, user1, user2, token2, apiClient));
            }
        }

        // 5.1.7: Обход коллекций (/users/me/accounts → /users/123/accounts)
        vulnerabilities.addAll(testCollectionBypass(baseUrl, user1, user2, token1, token2, apiClient));

        // 5.1.8: Сравнение прав доступа между разными пользователями
        vulnerabilities.addAll(testPermissionComparison(baseUrl, testData, user1, user2, token1, token2, apiClient));

        return vulnerabilities;
    }

    /**
     * 5.1.3: Подмена ID в path-параметрах
     */
    private List<Vulnerability> testPathParameterBOLA(String baseUrl, BOLATestCase testCase,
                                                      Map<String, Object> testData, String user1, String user2,
                                                      String attackerToken, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Получаем ID пользователя 1 для подмены
        List<String> user1Ids = getRelevantIds(testCase.idType, testData, "user1");
        if (user1Ids.isEmpty()) {
            // Если нет реальных ID, используем сгенерированные
            user1Ids.add((String) testData.get("random_numeric"));
        }

        for (String user1Id : user1Ids) {
            // Заменяем ID в пути
            String testPath = replacePathParameters(testCase.path, testCase.idType, user1Id);
            String fullUrl = baseUrl + testPath;

            // Выполняем запрос с токеном атакующего
            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, testCase.method, fullUrl, attackerToken);

            // 5.1.6: Проверка ответов на коды 403/404/200 при подмене ID
            if (response != null) {
                int statusCode = response.getStatusCode();
                boolean isVulnerable = (statusCode == 200 || statusCode == 201);

                if (isVulnerable) {
                    Vulnerability vuln = createBOLAVulnerability(
                            "BOLA через path параметр",
                            "Пользователь " + user2 + " получил доступ к ресурсу " + testCase.path +
                                    " с ID " + user1Id + ", принадлежащим " + user1 + ". HTTP статус: " + statusCode,
                            testCase.path,
                            statusCode,
                            user2, user1, fullUrl,
                            testCase.idType, user1Id
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: доступ через path параметр к " + testPath);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.4: Подмена ID в query-параметрах
     */
    private List<Vulnerability> testQueryParameterBOLA(String baseUrl, BOLATestCase testCase,
                                                       Map<String, Object> testData, String user1, String user2,
                                                       String attackerToken, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        List<String> user1Ids = getRelevantIds(testCase.idType, testData, "user1");
        if (user1Ids.isEmpty()) {
            user1Ids.add((String) testData.get("random_numeric"));
        }

        for (String user1Id : user1Ids) {
            // Добавляем query параметр
            String queryParam = testCase.parameterName + "=" + user1Id;
            String testUrl = baseUrl + testCase.path + (testCase.path.contains("?") ? "&" : "?") + queryParam;

            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, testCase.method, testUrl, attackerToken);

            if (response != null) {
                int statusCode = response.getStatusCode();
                boolean isVulnerable = (statusCode == 200 || statusCode == 201);

                if (isVulnerable) {
                    Vulnerability vuln = createBOLAVulnerability(
                            "BOLA через query параметр",
                            "Пользователь " + user2 + " получил доступ через query параметр " + testCase.parameterName +
                                    " с ID " + user1Id + ", принадлежащим " + user1 + ". HTTP статус: " + statusCode,
                            testCase.path + "?" + queryParam,
                            statusCode,
                            user2, user1, testUrl,
                            testCase.idType, user1Id
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: доступ через query параметр " + testCase.parameterName);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.5: Подмена ID в body-запросах
     */
    private List<Vulnerability> testBodyParameterBOLA(String baseUrl, BOLATestCase testCase,
                                                      Map<String, Object> testData, String user1, String user2,
                                                      String attackerToken, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Создаем тестовое тело запроса с подмененным ID
        List<String> user1Ids = getRelevantIds(testCase.idType, testData, "user1");
        if (user1Ids.isEmpty()) return vulnerabilities;

        for (String user1Id : user1Ids) {
            String requestBody = createRequestBodyWithID(testCase.idType, user1Id);

            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, testCase.method,
                    baseUrl + testCase.path, attackerToken, requestBody);

            if (response != null) {
                int statusCode = response.getStatusCode();
                boolean isVulnerable = (statusCode == 200 || statusCode == 201);

                if (isVulnerable) {
                    Vulnerability vuln = createBOLAVulnerability(
                            "BOLA через body параметр",
                            "Пользователь " + user2 + " выполнил операцию через body с ID " + user1Id +
                                    ", принадлежащим " + user1 + ". HTTP статус: " + statusCode,
                            testCase.path,
                            statusCode,
                            user2, user1, baseUrl + testCase.path,
                            testCase.idType, user1Id
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: доступ через body параметр");
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.7: Обход коллекций
     */
    private List<Vulnerability> testCollectionBypass(String baseUrl, String user1, String user2,
                                                     String token1, String token2, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Примеры обхода коллекций
        String[] collectionTests = {
                "/users/me/accounts", "/users/" + user1 + "/accounts",
                "/clients/me/consents", "/clients/" + user1 + "/consents"
        };

        for (int i = 0; i < collectionTests.length; i += 2) {
            String meEndpoint = collectionTests[i];
            String idEndpoint = collectionTests[i + 1];

            // Проверяем доступ к эндпоинту с конкретным ID
            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET",
                    baseUrl + idEndpoint, token2);

            if (response != null && (response.getStatusCode() == 200 || response.getStatusCode() == 201)) {
                Vulnerability vuln = createBOLAVulnerability(
                        "BOLA через обход коллекции",
                        "Пользователь " + user2 + " получил доступ к коллекции " + idEndpoint +
                                ", которая должна быть доступна только " + user1 + ". HTTP статус: " + response.getStatusCode(),
                        idEndpoint,
                        response.getStatusCode(),
                        user2, user1, baseUrl + idEndpoint,
                        "user_id", user1
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: обход коллекции " + idEndpoint);
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.1.8: Сравнение прав доступа
     */
    private List<Vulnerability> testPermissionComparison(String baseUrl, Map<String, Object> testData,
                                                         String user1, String user2, String token1, String token2,
                                                         ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Сравниваем доступ к одним и тем же ресурсам
        String[] testEndpoints = {"/accounts", "/product-agreements"};

        for (String endpoint : testEndpoints) {
            HttpApiClient.ApiResponse user1Response = makeAuthenticatedRequest(apiClient, "GET", baseUrl + endpoint, token1);
            HttpApiClient.ApiResponse user2Response = makeAuthenticatedRequest(apiClient, "GET", baseUrl + endpoint, token2);

            if (user1Response != null && user2Response != null &&
                    user1Response.getStatusCode() == 200 && user2Response.getStatusCode() == 200) {

                // Анализируем различия в ответах
                List<String> user1Ids = extractIDsFromResponse(user1Response.getBody());
                List<String> user2Ids = extractIDsFromResponse(user2Response.getBody());

                // Проверяем, есть ли у user2 доступ к ID user1
                for (String user1Id : user1Ids) {
                    if (user2Ids.contains(user1Id)) {
                        Vulnerability vuln = createBOLAVulnerability(
                                "BOLA через несанкционированный доступ к объектам",
                                "Пользователь " + user2 + " имеет доступ к объекту " + user1Id +
                                        ", принадлежащему " + user1 + " через эндпоинт " + endpoint,
                                endpoint,
                                200,
                                user2, user1, baseUrl + endpoint,
                                "object_id", user1Id
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("(API-1) УЯЗВИМОСТЬ BOLA: несанкционированный доступ к " + user1Id);
                    }
                }
            }
        }

        return vulnerabilities;
    }

    // Вспомогательные методы
    private List<String> getRelevantIds(String idType, Map<String, Object> testData, String user) {
        String key = user + "_" + idType.replace("_id", "s");
        @SuppressWarnings("unchecked")
        List<String> ids = (List<String>) testData.get(key);
        return ids != null ? ids : new ArrayList<>();
    }

    private String replacePathParameters(String path, String idType, String newId) {
        return path.replaceAll("\\{[^}]*" + idType.replace("_", "").toLowerCase() + "[^}]*\\}", newId)
                .replaceAll("\\{[^}]*id[^}]*\\}", newId);
    }

    private String createRequestBodyWithID(String idType, String id) {
        Map<String, Object> body = new HashMap<>();

        switch (idType) {
            case "account_id":
                body.put("account_id", id);
                break;
            case "client_id":
                body.put("client_id", id);
                break;
            case "consent_id":
                body.put("consent_id", id);
                break;
            case "payment_id":
                body.put("payment_id", id);
                break;
            case "agreement_id":
                body.put("agreement_id", id);
                break;
            default:
                body.put("id", id);
        }

        // Простое преобразование в JSON
        StringBuilder json = new StringBuilder("{");
        for (Map.Entry<String, Object> entry : body.entrySet()) {
            if (json.length() > 1) json.append(",");
            json.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
        }
        json.append("}");

        return json.toString();
    }

    private List<String> extractIDsFromResponse(String responseBody) {
        List<String> ids = new ArrayList<>();
        Pattern pattern = Pattern.compile("\"(account_id|id|agreement_id)\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(responseBody);
        while (matcher.find()) {
            ids.add(matcher.group(2));
        }
        return ids;
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
                                                  String idType, String exploitedId) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API1:2023 - Broken Object Level Authorization - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(Vulnerability.Severity.HIGH);
        vuln.setCategory(Vulnerability.Category.OWASP_API1_BOLA);
        vuln.setEndpoint(endpoint);
        vuln.setStatusCode(statusCode);
        vuln.setEvidence(String.format(
                "{\"attacker\":\"%s\",\"victim\":\"%s\",\"endpoint\":\"%s\",\"url\":\"%s\"," +
                        "\"statusCode\":%d,\"idType\":\"%s\",\"exploitedId\":\"%s\"}",
                attacker, victim, endpoint, url, statusCode, idType, exploitedId
        ));

        List<String> recommendations = new ArrayList<>();
        recommendations.add("Реализуйте проверку прав доступа на уровне объектов для каждого запроса");
        recommendations.add("Используйте механизмы авторизации, которые проверяют принадлежность объекта пользователю");
        recommendations.add("Не полагайтесь только на ID параметры в запросе");
        recommendations.add("Используйте случайные UUID вместо последовательных ID");
        recommendations.add("Регулярно проводите тестирование на уязвимости BOLA");
        recommendations.add("Внедрите централизованную систему контроля доступа");
        recommendations.add("Обеспечьте, чтобы пользователи могли access только свои объекты");
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