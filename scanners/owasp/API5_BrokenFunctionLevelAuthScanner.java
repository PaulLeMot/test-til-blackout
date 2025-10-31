// scanners/owasp/API5_BrokenFunctionLevelAuthScanner.java
package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.AuthManager;
import core.HttpApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.Paths;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API5_BrokenFunctionLevelAuthScanner implements SecurityScanner {

    private static final String[] ADMIN_KEYWORDS = {"/admin", "/manage", "/internal", "/system", "/config", "/banker", "/capital", "/key-rate", "/teams", "/stats"};
    private static final String[] PRIVILEGED_ROLES = {"admin", "administrator", "superuser", "manager", "root", "banker"};

    public API5_BrokenFunctionLevelAuthScanner() {}

    @Override
    public String getName() {
        return "API5_Broken_Function_Level_Auth";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-5) Сканирование уязвимостей Broken Function Level Authorization (OWASP API5)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-5) Ошибка: передан неверный объект OpenAPI");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        String baseUrl = config.getTargetBaseUrl().trim();
        String password = config.getPassword();

        if (password == null || password.isEmpty()) {
            System.err.println("(API-5) Пароль не задан в конфигурации. API5-сканер пропущен.");
            return vulnerabilities;
        }

        Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(baseUrl, password);
        if (tokens.size() < 2) {
            System.err.println("(API-5) Недостаточно токенов для API5-теста (нужно минимум 2).");
            return vulnerabilities;
        }

        String user1 = "team172-1";
        String user2 = "team172-2";
        String token1 = tokens.get(user1);
        String token2 = tokens.get(user2);

        if (token1 == null || token2 == null) {
            System.err.println("(API-5) Не удалось получить токены для обоих пользователей.");
            return vulnerabilities;
        }

        System.out.println("(API-5) Получены токены для пользователей: " + user1 + ", " + user2);

        // 5.5.1: Поиск административных эндпоинтов через анализ OpenAPI спецификации
        List<String> adminEndpoints = discoverAdminEndpointsFromOpenAPI(openAPI);
        System.out.println("(API-5) Найдено административных эндпоинтов из OpenAPI: " + adminEndpoints.size());

        // 5.5.2: Попытка вызова админ-функций с правами обычного пользователя
        vulnerabilities.addAll(testAdminAccessWithUserTokens(baseUrl, adminEndpoints, token1, user1, apiClient));

        // 5.5.3: Тестирование эскалации привилегий через модификацию ролей
        vulnerabilities.addAll(testRoleEscalation(baseUrl, token1, user1, apiClient));

        // 5.5.4: Проверка доступа к функциям других пользователей
        vulnerabilities.addAll(testCrossUserAccess(baseUrl, token1, token2, user1, user2, apiClient, openAPI));

        // 5.5.7: Проверка отсутствия авторизации для критических операций
        vulnerabilities.addAll(testUnauthorizedCriticalOperations(baseUrl, adminEndpoints, apiClient));

        System.out.println("(API-5) API5 сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * 5.5.1: Поиск административных эндпоинтов через анализ OpenAPI спецификации
     */
    private List<String> discoverAdminEndpointsFromOpenAPI(OpenAPI openAPI) {
        List<String> adminEndpoints = new ArrayList<>();

        if (openAPI.getPaths() == null) {
            return adminEndpoints;
        }

        Paths paths = openAPI.getPaths();
        for (String path : paths.keySet()) {
            PathItem pathItem = paths.get(path);

            // Проверяем все операции на пути
            for (PathItem.HttpMethod method : pathItem.readOperationsMap().keySet()) {
                Operation operation = pathItem.readOperationsMap().get(method);

                // Ищем административные эндпоинты по ключевым словам
                if (isAdminEndpoint(path, operation)) {
                    adminEndpoints.add(path);
                    break; // Добавляем путь только один раз
                }
            }
        }

        return adminEndpoints;
    }

    /**
     * Проверка, является ли эндпоинт административным
     */
    private boolean isAdminEndpoint(String path, Operation operation) {
        // Проверка пути
        for (String keyword : ADMIN_KEYWORDS) {
            if (path.toLowerCase().contains(keyword)) {
                return true;
            }
        }

        // Проверка тегов операции
        if (operation.getTags() != null) {
            for (String tag : operation.getTags()) {
                if (tag.toLowerCase().contains("admin") ||
                        tag.toLowerCase().contains("internal") ||
                        tag.toLowerCase().contains("banker")) {
                    return true;
                }
            }
        }

        // Проверка описания и summary
        String description = operation.getDescription() != null ? operation.getDescription().toLowerCase() : "";
        String summary = operation.getSummary() != null ? operation.getSummary().toLowerCase() : "";

        return description.contains("admin") || description.contains("internal") ||
                description.contains("banker") || summary.contains("admin") ||
                summary.contains("internal") || summary.contains("banker");
    }

    /**
     * 5.5.2: Попытка вызова админ-функций с правами обычного пользователя
     */
    private List<Vulnerability> testAdminAccessWithUserTokens(String baseUrl, List<String> adminEndpoints,
                                                              String userToken, String username,
                                                              ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        Set<String> testedEndpoints = new HashSet<>(); // Для избежания дублирования

        for (String endpoint : adminEndpoints) {
            if (testedEndpoints.contains(endpoint)) {
                continue;
            }
            testedEndpoints.add(endpoint);

            String testEndpoint = replacePathParameters(endpoint);
            String fullUrl = baseUrl + testEndpoint;

            // Тестируем с токеном обычного пользователя (GET запросы)
            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET", fullUrl, userToken);

            if (response != null && (response.getStatusCode() == 200 || response.getStatusCode() == 201)) {
                Vulnerability vuln = createVulnerability(
                        "Несанкционированный доступ к административной функции",
                        "Пользователь " + username + " получил доступ к административному эндпоинту " + endpoint +
                                " с правами обычного пользователя. HTTP статус: " + response.getStatusCode() +
                                ". Доказательство: успешный ответ 200/201 на административный эндпоинт с токеном обычного пользователя.",
                        endpoint,
                        response.getStatusCode(),
                        username, "system", fullUrl
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-5) УЯЗВИМОСТЬ: Обнаружен несанкционированный доступ к административному эндпоинту: " + endpoint +
                        " с правами пользователя " + username + ". Статус: " + response.getStatusCode());
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
                    Vulnerability vuln = createVulnerability(
                            "Возможная эскалация привилегий",
                            "Пользователь " + username + " успешно отправил запрос на изменение роли на '" + role +
                                    "' через эндпоинт " + endpoint + ". HTTP статус: " + response.getStatusCode() +
                                    ". Доказательство: запрос на изменение роли выполнен успешно (статус 200).",
                            endpoint,
                            response.getStatusCode(),
                            username, "system", fullUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-5) УЯЗВИМОСТЬ: Обнаружена возможная эскалация привилегий: " + endpoint +
                            ". Пользователь: " + username + ", запрошенная роль: " + role);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.5.4: Проверка доступа к функциям других пользователей
     */
    private List<Vulnerability> testCrossUserAccess(String baseUrl, String token1, String token2,
                                                    String user1, String user2, ApiClient apiClient,
                                                    OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Получаем ID пользователей
        String user1Id = getUserId(baseUrl, token1, apiClient);
        String user2Id = getUserId(baseUrl, token2, apiClient);

        // Получаем счета пользователей
        List<String> user1Accounts = getUserAccounts(baseUrl, token1, apiClient);
        List<String> user2Accounts = getUserAccounts(baseUrl, token2, apiClient);

        // Тестируем доступ к счетам другого пользователя
        if (!user2Accounts.isEmpty()) {
            String user2Account = user2Accounts.get(0);

            // Получаем эндпоинты для работы со счетами из OpenAPI
            List<String> accountEndpoints = getAccountEndpointsFromOpenAPI(openAPI);

            for (String endpointTemplate : accountEndpoints) {
                String endpoint = endpointTemplate.replace("{account_id}", user2Account);
                String fullUrl = baseUrl + endpoint;

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET", fullUrl, token1);

                if (response != null && response.getStatusCode() == 200) {
                    Vulnerability vuln = createVulnerability(
                            "Доступ к счетам другого пользователя",
                            "Пользователь " + user1 + " получил доступ к счету " + user2Account +
                                    " пользователя " + user2 + " через эндпоинт " + endpoint +
                                    ". Доказательство: успешный доступ к финансовым данным чужого счета.",
                            endpoint,
                            response.getStatusCode(),
                            user1, user2, fullUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-5) УЯЗВИМОСТЬ: Обнаружен доступ к счетам другого пользователя: " + endpoint +
                            ". Пользователь " + user1 + " получил доступ к счету " + user2Account + " пользователя " + user2);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Получение эндпоинтов для работы со счетами из OpenAPI
     */
    private List<String> getAccountEndpointsFromOpenAPI(OpenAPI openAPI) {
        List<String> accountEndpoints = new ArrayList<>();

        if (openAPI.getPaths() == null) {
            return accountEndpoints;
        }

        for (String path : openAPI.getPaths().keySet()) {
            if (path.contains("/accounts/") && path.contains("{account_id}")) {
                accountEndpoints.add(path);
            }
        }

        return accountEndpoints;
    }

    /**
     * 5.5.7: Проверка отсутствия авторизации для критических операций
     */
    private List<Vulnerability> testUnauthorizedCriticalOperations(String baseUrl, List<String> adminEndpoints, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        Set<String> testedEndpoints = new HashSet<>(); // Для избежания дублирования

        for (String endpoint : adminEndpoints) {
            if (testedEndpoints.contains(endpoint)) {
                continue;
            }
            testedEndpoints.add(endpoint);

            // Пропускаем эндпоинты, которые по документации доступны без аутентификации
            if (endpoint.contains("/account-consents/") || endpoint.contains("/.well-known/")) {
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
                                " без аутентификации. HTTP статус: " + response.getStatusCode() +
                                ". Доказательство: успешный доступ к административному функционалу без предоставления токена авторизации.",
                        endpoint,
                        response.getStatusCode(),
                        "anonymous", "system", fullUrl
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-5) УЯЗВИМОСТЬ: Обнаружен доступ без авторизации к административному эндпоинту: " + endpoint +
                        ". Статус: " + response.getStatusCode());
            }
        }

        return vulnerabilities;
    }

    // Вспомогательные методы (остаются без изменений)
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
            System.err.println("(API-5) Ошибка при запросе " + url + ": " + e.getMessage());
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
            System.err.println("(API-5) Ошибка при запросе " + url + ": " + e.getMessage());
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
                    Pattern pattern = Pattern.compile("\"(id|client_id)\"\\s*:\\s*\"([^\"]+)\"");
                    Matcher matcher = pattern.matcher(apiResponse.getBody());
                    if (matcher.find()) {
                        return matcher.group(2);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-5) Ошибка при получении ID пользователя: " + e.getMessage());
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
                    Pattern pattern = Pattern.compile("\"account_id\"\\s*:\\s*\"([^\"]+)\"");
                    Matcher matcher = pattern.matcher(apiResponse.getBody());
                    while (matcher.find()) {
                        accounts.add(matcher.group(1));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-5) Ошибка при получении счетов пользователя: " + e.getMessage());
        }
        return accounts;
    }

    private String replacePathParameters(String endpoint) {
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