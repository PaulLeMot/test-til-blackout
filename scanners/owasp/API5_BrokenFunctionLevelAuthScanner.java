// scanners/owasp/API5_BrokenFunctionLevelAuthScanner.java
package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.AuthManager;
import core.HttpApiClient;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API5_BrokenFunctionLevelAuthScanner implements SecurityScanner {

    private static final String[] ADMIN_KEYWORDS = {"/admin", "/manage", "/internal", "/system", "/config", "/banker", "/capital", "/key-rate", "/teams", "/stats"};
    private static final String[] PRIVILEGED_ROLES = {"admin", "administrator", "superuser", "manager", "root", "banker"};

    // Административные эндпоинты из документации API
    private static final String[] ADMIN_ENDPOINTS = {
            // Internal: Admin endpoints
            "/admin/banks/{bank_code}/settings",
            "/admin/capital",
            "/admin/key-rate",
            "/admin/key-rate/history",
            "/admin/payments",
            "/admin/stats",
            "/admin/teams",
            "/admin/teams/upload",
            "/admin/transfers",

            // Internal: Banker endpoints
            "/banker/clients",
            "/banker/clients/{client_id}",
            "/banker/consents/{request_id}/approve",
            "/banker/consents/{request_id}/reject",
            "/banker/consents/all",
            "/banker/consents/pending",
            "/banker/products",
            "/banker/products/{product_id}",

            // Payment approval endpoints
            "/payment-consents/{request_id}/approve",
            "/payment-consents/{request_id}/reject",
            "/payment-consents/pending/list"
    };

    public API5_BrokenFunctionLevelAuthScanner() {}

    @Override
    public String getName() {
        return "API5_Broken_Function_Level_Auth";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("🔍 Scanning for Broken Function Level Authorization vulnerabilities (OWASP API5)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl().trim();
        String password = config.getPassword();

        if (password == null || password.isEmpty()) {
            System.err.println("⚠️ Пароль не задан в конфигурации. API5-сканер пропущен.");
            return vulnerabilities;
        }

        Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(baseUrl, password);
        if (tokens.size() < 2) {
            System.err.println("⚠️ Недостаточно токенов для API5-теста (нужно минимум 2).");
            return vulnerabilities;
        }

        String user1 = "team172-1";
        String user2 = "team172-2";
        String token1 = tokens.get(user1);
        String token2 = tokens.get(user2);

        if (token1 == null || token2 == null) {
            System.err.println("⚠️ Не удалось получить токены для обоих пользователей.");
            return vulnerabilities;
        }

        System.out.println("✅ Получены токены для пользователей: " + user1 + ", " + user2);

        // 5.5.1: Поиск административных эндпоинтов через анализ API документации
        List<String> adminEndpoints = discoverAdminEndpoints(baseUrl, token1, apiClient);
        System.out.println("🔍 Найдено потенциальных административных эндпоинтов: " + adminEndpoints.size());

        // 5.5.2: Попытка вызова админ-функций с правами обычного пользователя
        vulnerabilities.addAll(testAdminAccessWithUserTokens(baseUrl, adminEndpoints, token1, token2, user1, user2, apiClient));

        // 5.5.3: Тестирование эскалации привилегий через модификацию ролей
        vulnerabilities.addAll(testRoleEscalation(baseUrl, token1, user1, apiClient));

        // 5.5.4: Проверка доступа к функциям других пользователей
        vulnerabilities.addAll(testCrossUserAccess(baseUrl, token1, token2, user1, user2, apiClient));

        // 5.5.7: Проверка отсутствия авторизации для критических операций
        vulnerabilities.addAll(testUnauthorizedCriticalOperations(baseUrl, adminEndpoints, apiClient));

        System.out.println("✅ API5 scan completed. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * 5.5.1: Поиск административных эндпоинтов через анализ API документации
     */
    private List<String> discoverAdminEndpoints(String baseUrl, String token, ApiClient apiClient) {
        List<String> adminEndpoints = new ArrayList<>();

        // Добавляем известные административные эндпоинты из документации
        for (String endpoint : ADMIN_ENDPOINTS) {
            adminEndpoints.add(endpoint);
        }

        // Попробуем получить OpenAPI спецификацию
        String[] discoveryPaths = {
                "/openapi.json", "/swagger.json", "/swagger.yaml",
                "/api-docs", "/v2/api-docs", "/v3/api-docs", "/docs"
        };

        for (String path : discoveryPaths) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("GET", baseUrl + path, null, headers);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    if (apiResponse.getStatusCode() == 200) {
                        adminEndpoints.addAll(extractAdminEndpointsFromOpenAPI(apiResponse.getBody()));
                    }
                }
            } catch (Exception e) {
                // Игнорируем ошибки - эндпоинт может не существовать
            }
        }

        // Также проверяем стандартные административные пути
        for (String keyword : ADMIN_KEYWORDS) {
            adminEndpoints.add(keyword);
            adminEndpoints.add("/api" + keyword);
            adminEndpoints.add("/v1" + keyword);
            adminEndpoints.add("/v2" + keyword);
        }

        return adminEndpoints;
    }

    /**
     * Извлечение административных эндпоинтов из OpenAPI спецификации
     */
    private List<String> extractAdminEndpointsFromOpenAPI(String openApiJson) {
        List<String> endpoints = new ArrayList<>();

        // Ищем пути, содержащие административные ключевые слова
        for (String keyword : ADMIN_KEYWORDS) {
            Pattern pathPattern = Pattern.compile("\"/([^\"]*" + keyword.replace("/", "") + "[^\"]*)\"", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pathPattern.matcher(openApiJson);

            while (matcher.find()) {
                String path = "/" + matcher.group(1);
                if (!endpoints.contains(path)) {
                    endpoints.add(path);
                }
            }
        }

        return endpoints;
    }

    /**
     * 5.5.2: Попытка вызова админ-функций с правами обычного пользователя
     */
    private List<Vulnerability> testAdminAccessWithUserTokens(String baseUrl, List<String> adminEndpoints,
                                                              String userToken, String otherUserToken,
                                                              String user1, String user2, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (String endpoint : adminEndpoints) {
            // Заменяем параметры на тестовые значения
            String testEndpoint = replacePathParameters(endpoint);
            String fullUrl = baseUrl + testEndpoint;

            // Тестируем с токеном обычного пользователя (GET запросы)
            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET", fullUrl, userToken);

            if (response != null && (response.getStatusCode() == 200 || response.getStatusCode() == 201)) {
                Vulnerability vuln = createVulnerability(
                        "Несанкционированный доступ к административной функции",
                        "Пользователь " + user1 + " получил доступ к административному эндпоинту " + endpoint +
                                " с правами обычного пользователя. HTTP статус: " + response.getStatusCode(),
                        endpoint,
                        response.getStatusCode(),
                        user1, "system", fullUrl
                );
                vulnerabilities.add(vuln);
                System.out.println("🚨 Обнаружен несанкционированный доступ к: " + endpoint);
            }

            // Тестируем POST запросы для критических операций
            if (endpoint.contains("approve") || endpoint.contains("reject") || endpoint.contains("upload")) {
                String testPayload = "{}";
                HttpApiClient.ApiResponse postResponse = makeAuthenticatedRequest(apiClient, "POST", fullUrl, userToken, testPayload);

                if (postResponse != null && (postResponse.getStatusCode() == 200 || postResponse.getStatusCode() == 201)) {
                    Vulnerability vuln = createVulnerability(
                            "Несанкционированное выполнение административной операции",
                            "Пользователь " + user1 + " выполнил административную операцию через эндпоинт " + endpoint +
                                    " с правами обычного пользователя. HTTP статус: " + postResponse.getStatusCode(),
                            endpoint,
                            postResponse.getStatusCode(),
                            user1, "system", fullUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("🚨 Обнаружено несанкционированное выполнение операции: " + endpoint);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.5.3: Тестирование эскалации привилегий через модификацию ролей
     */
    private List<Vulnerability> testRoleEscalation(String baseUrl, String token, String username, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Тестируем возможные эндпоинты изменения ролей и привилегий
        String[] roleModificationEndpoints = {
                "/users/me/role", "/profile/role", "/account/role",
                "/admin/assign-role", "/api/roles", "/auth/me"
        };

        for (String endpoint : roleModificationEndpoints) {
            String fullUrl = baseUrl + endpoint;

            // Пробуем различные payloads для эскалации привилегий
            for (String role : PRIVILEGED_ROLES) {
                String payload = String.format("{\"role\":\"%s\"}", role);

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "POST", fullUrl, token, payload);

                if (response != null && response.getStatusCode() == 200) {
                    // Проверяем, изменилась ли роль
                    HttpApiClient.ApiResponse verifyResponse = makeAuthenticatedRequest(apiClient, "GET", baseUrl + "/auth/me", token);
                    if (verifyResponse != null && verifyResponse.getStatusCode() == 200 &&
                            verifyResponse.getBody().toLowerCase().contains(role)) {

                        Vulnerability vuln = createVulnerability(
                                "Успешная эскалация привилегий",
                                "Пользователь " + username + " успешно повысил свои привилегии до роли '" + role +
                                        "' через эндпоинт " + endpoint,
                                endpoint,
                                response.getStatusCode(),
                                username, "system", fullUrl
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("🚨 Обнаружена эскалация привилегий через: " + endpoint);
                    }
                }
            }

            // Тестируем PUT запросы
            for (String role : PRIVILEGED_ROLES) {
                String payload = String.format("{\"role\":\"%s\"}", role);
                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "PUT", fullUrl, token, payload);

                if (response != null && response.getStatusCode() == 200) {
                    Vulnerability vuln = createVulnerability(
                            "Возможная эскалация привилегий через PUT",
                            "Пользователь " + username + " успешно отправил запрос на изменение роли на '" + role +
                                    "' через эндпоинт " + endpoint + ". HTTP статус: " + response.getStatusCode(),
                            endpoint,
                            response.getStatusCode(),
                            username, "system", fullUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("🚨 Обнаружена возможная эскалация привилегий через PUT: " + endpoint);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.5.4: Проверка доступа к функциям других пользователей
     */
    private List<Vulnerability> testCrossUserAccess(String baseUrl, String token1, String token2,
                                                    String user1, String user2, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Получаем ID пользователей и их счета
        String user1Id = getUserId(baseUrl, token1, apiClient);
        String user2Id = getUserId(baseUrl, token2, apiClient);

        List<String> user1Accounts = getUserAccounts(baseUrl, token1, apiClient);
        List<String> user2Accounts = getUserAccounts(baseUrl, token2, apiClient);

        if (user1Id != null && user2Id != null) {
            // Тестируем доступ к функциям другого пользователя
            String[] userEndpoints = {
                    "/users/%s/profile", "/users/%s/settings", "/users/%s/permissions",
                    "/accounts/%s", "/profile/%s", "/banker/clients/%s"
            };

            for (String endpointTemplate : userEndpoints) {
                String endpoint = String.format(endpointTemplate, user2Id);
                String fullUrl = baseUrl + endpoint;

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET", fullUrl, token1);

                if (response != null && response.getStatusCode() == 200) {
                    Vulnerability vuln = createVulnerability(
                            "Доступ к функциям другого пользователя",
                            "Пользователь " + user1 + " получил доступ к функциям пользователя " + user2 +
                                    " через эндпоинт " + endpoint,
                            endpoint,
                            response.getStatusCode(),
                            user1, user2, fullUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("🚨 Обнаружен доступ к функциям другого пользователя: " + endpoint);
                }
            }
        }

        // Тестируем доступ к счетам другого пользователя
        if (!user2Accounts.isEmpty()) {
            String user2Account = user2Accounts.get(0);
            String[] accountEndpoints = {
                    "/accounts/%s",
                    "/accounts/%s/balances",
                    "/accounts/%s/transactions"
            };

            for (String endpointTemplate : accountEndpoints) {
                String endpoint = String.format(endpointTemplate, user2Account);
                String fullUrl = baseUrl + endpoint;

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET", fullUrl, token1);

                if (response != null && response.getStatusCode() == 200) {
                    Vulnerability vuln = createVulnerability(
                            "Доступ к счетам другого пользователя",
                            "Пользователь " + user1 + " получил доступ к счету " + user2Account +
                                    " пользователя " + user2 + " через эндпоинт " + endpoint,
                            endpoint,
                            response.getStatusCode(),
                            user1, user2, fullUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("🚨 Обнаружен доступ к счетам другого пользователя: " + endpoint);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.5.7: Проверка отсутствия авторизации для критических операций
     */
    private List<Vulnerability> testUnauthorizedCriticalOperations(String baseUrl, List<String> adminEndpoints, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (String endpoint : adminEndpoints) {
            // Пропускаем эндпоинты, которые по документации доступны без аутентификации
            if (endpoint.contains("/account-consents/") &&
                    (endpoint.contains("GET") || endpoint.contains("DELETE"))) {
                continue;
            }

            String testEndpoint = replacePathParameters(endpoint);
            String fullUrl = baseUrl + testEndpoint;

            // Пробуем доступ без авторизации (GET)
            HttpApiClient.ApiResponse response = makeUnauthenticatedRequest(apiClient, "GET", fullUrl);

            if (response != null && (response.getStatusCode() == 200 || response.getStatusCode() == 201)) {
                Vulnerability vuln = createVulnerability(
                        "Отсутствие авторизации для критической операции",
                        "Обнаружен доступ к административному эндпоинту " + endpoint +
                                " без аутентификации. HTTP статус: " + response.getStatusCode(),
                        endpoint,
                        response.getStatusCode(),
                        "anonymous", "system", fullUrl
                );
                vulnerabilities.add(vuln);
                System.out.println("🚨 Обнаружен доступ без авторизации к: " + endpoint);
            }

            // Для критических операций тестируем также POST без авторизации
            if (endpoint.contains("approve") || endpoint.contains("reject") || endpoint.contains("upload")) {
                String testPayload = "{}";
                HttpApiClient.ApiResponse postResponse = makeUnauthenticatedRequest(apiClient, "POST", fullUrl, testPayload);

                if (postResponse != null && (postResponse.getStatusCode() == 200 || postResponse.getStatusCode() == 201)) {
                    Vulnerability vuln = createVulnerability(
                            "Отсутствие авторизации для критической POST операции",
                            "Обнаружено выполнение административной операции через эндпоинт " + endpoint +
                                    " без аутентификации. HTTP статус: " + postResponse.getStatusCode(),
                            endpoint,
                            postResponse.getStatusCode(),
                            "anonymous", "system", fullUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("🚨 Обнаружено выполнение операции без авторизации: " + endpoint);
                }
            }
        }

        return vulnerabilities;
    }

    // Вспомогательные методы
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
            System.err.println("⚠️ Ошибка при запросе " + url + ": " + e.getMessage());
            return null;
        }
    }

    private HttpApiClient.ApiResponse makeUnauthenticatedRequest(ApiClient apiClient, String method, String url) {
        return makeUnauthenticatedRequest(apiClient, method, url, null);
    }

    private HttpApiClient.ApiResponse makeUnauthenticatedRequest(ApiClient apiClient, String method, String url, String body) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            if (body != null) {
                headers.put("Content-Type", "application/json");
            }

            Object response = apiClient.executeRequest(method, url, body, headers);
            return (HttpApiClient.ApiResponse) response;
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при запросе " + url + ": " + e.getMessage());
            return null;
        }
    }

    private String getUserId(String baseUrl, String token, ApiClient apiClient) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("GET", baseUrl + "/auth/me", null, headers);
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                if (apiResponse.getStatusCode() == 200) {
                    // Ищем ID пользователя в ответе
                    Pattern pattern = Pattern.compile("\"(id|client_id)\"\\s*:\\s*\"([^\"]+)\"");
                    Matcher matcher = pattern.matcher(apiResponse.getBody());
                    if (matcher.find()) {
                        return matcher.group(2);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при получении ID пользователя: " + e.getMessage());
        }
        return null;
    }

    private List<String> getUserAccounts(String baseUrl, String token, ApiClient apiClient) {
        List<String> accounts = new ArrayList<>();
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
                        accounts.add(matcher.group(1));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при получении счетов пользователя: " + e.getMessage());
        }
        return accounts;
    }

    private String replacePathParameters(String endpoint) {
        // Заменяем параметры пути на тестовые значения
        return endpoint
                .replace("{bank_code}", "vbank")
                .replace("{client_id}", "test-client")
                .replace("{request_id}", "test-request")
                .replace("{consent_id}", "test-consent")
                .replace("{account_id}", "test-account")
                .replace("{payment_id}", "test-payment")
                .replace("{product_id}", "test-product")
                .replace("{offer_id}", "test-offer")
                .replace("{application_id}", "test-application")
                .replace("{agreement_id}", "test-agreement")
                .replace("{customer_lead_id}", "test-lead");
    }

    private Vulnerability createVulnerability(String title, String description, String endpoint,
                                              int statusCode, String attacker, String victim, String url) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API5:2023 - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(Vulnerability.Severity.HIGH);
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
        recommendations.add("Используйте ролевую модель доступа (RBAC)");
        recommendations.add("Запрещайте доступ к административным функциям для обычных пользователей");
        recommendations.add("Регулярно проводите аудит прав доступа");
        recommendations.add("Внедрите принцип минимальных привилегий");
        recommendations.add("Проверяйте авторизацию для всех критических операций");
        recommendations.add("Используйте централизованную систему управления доступом");
        vuln.setRecommendations(recommendations);

        return vuln;
    }
}
