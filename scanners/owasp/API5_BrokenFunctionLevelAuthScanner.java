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
import io.swagger.v3.oas.models.security.SecurityRequirement;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API5_BrokenFunctionLevelAuthScanner implements SecurityScanner {

    // Обновленные ключевые слова для банковских/административных функций
    private static final String[] ADMIN_KEYWORDS = {
            "/banker", "/capital", "/key-rate", "/teams", "/stats",
            "/pending/list", "/approve", "/reject", "/internal", "/system",
            "/admin", "/manage"
    };

    private static final String[] PRIVILEGED_ROLES = {"admin", "administrator", "superuser", "manager", "root", "banker"};

    // Эндпоинты, которые точно являются административными (из спецификации)
    private static final String[] DEFINITE_ADMIN_ENDPOINTS = {
            "/payment-consents/pending/list",
            "/payment-consents/{request_id}/approve",
            "/payment-consents/{request_id}/reject",
            "/banker/capital",
            "/banker/key-rate",
            "/teams/stats"
    };

    // Эндпоинты, которые НЕ являются административными (исключения)
    private static final String[] NON_ADMIN_ENDPOINTS = {
            "/.well-known/jwks.json",
            "/account-consents/request",
            "/payments",
            "/accounts/{account_id}/close",
            "/accounts/{account_id}/status",
            "/products",
            "/products/{product_id}",
            "/auth/bank-token",
            "/health",
            "/"
    };

    public API5_BrokenFunctionLevelAuthScanner() {}

    @Override
    public String getName() {
        return "API5_Broken_Function_Level_Auth";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-5) Запуск сканирования на уязвимости Broken Function Level Authorization (OWASP API Security Top 10:2023 - API5)...");

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

        System.out.println("(API-5) Получение токенов для команды...");
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
        System.out.println("(API-5) Поиск административных эндпоинтов в OpenAPI спецификации...");
        List<String> adminEndpoints = discoverAdminEndpointsFromOpenAPI(openAPI);
        System.out.println("(API-5) Найдено административных эндпоинтов: " + adminEndpoints.size());
        for (String endpoint : adminEndpoints) {
            System.out.println("(API-5) - " + endpoint);
        }

        // 5.5.2: Попытка вызова админ-функций с правами обычного пользователя
        System.out.println("(API-5) Тестирование доступа к административным функциям с правами обычного пользователя...");
        vulnerabilities.addAll(testAdminAccessWithUserTokens(baseUrl, adminEndpoints, token1, user1, apiClient, openAPI));

        // 5.5.3: Тестирование эскалации привилегий через модификацию ролей
        System.out.println("(API-5) Тестирование эскалации привилегий через модификацию ролей...");
        vulnerabilities.addAll(testRoleEscalation(baseUrl, token1, user1, apiClient));

        // 5.5.4: Проверка доступа к функциям других пользователей
        System.out.println("(API-5) Проверка доступа к функциям других пользователей...");
        vulnerabilities.addAll(testCrossUserAccess(baseUrl, token1, token2, user1, user2, apiClient, openAPI));

        // 5.5.5: Анализ разграничения прав между разными группами пользователей
        System.out.println("(API-5) Анализ разграничения прав между разными группами пользователей...");
        vulnerabilities.addAll(testGroupPermissionSeparation(baseUrl, tokens, apiClient, openAPI));

        // 5.5.6: Тестирование обходов контроля доступа через альтернативные пути
        System.out.println("(API-5) Тестирование обходов контроля доступа через альтернативные пути...");
        vulnerabilities.addAll(testAccessControlBypass(baseUrl, token1, user1, apiClient, openAPI));

        // 5.5.7: Проверка отсутствия авторизации для критических операций
        System.out.println("(API-5) Проверка отсутствия авторизации для критических операций...");
        vulnerabilities.addAll(testUnauthorizedCriticalOperations(baseUrl, adminEndpoints, apiClient, openAPI));

        // Генерация отчета
        System.out.println("(API-5) ===== ОТЧЕТ ПО УЯЗВИМОСТЯМ BROKEN FUNCTION LEVEL AUTHORIZATION =====");
        System.out.println("(API-5) Всего обнаружено уязвимостей: " + vulnerabilities.size());
        if (!vulnerabilities.isEmpty()) {
            System.out.println("(API-5) Распределение по типам:");
            Map<String, Integer> vulnTypes = new HashMap<>();
            for (Vulnerability vuln : vulnerabilities) {
                String title = vuln.getTitle();
                String type = "OTHER";
                if (title.contains("административной")) type = "ADMIN_ACCESS";
                else if (title.contains("эскалация")) type = "PRIVILEGE_ESCALATION";
                else if (title.contains("счетам другого")) type = "CROSS_USER_ACCESS";
                else if (title.contains("разграничения прав")) type = "PERMISSION_SEPARATION";
                else if (title.contains("обход контроля")) type = "ACCESS_BYPASS";
                else if (title.contains("отсутствие авторизации")) type = "UNAUTHORIZED_ACCESS";

                vulnTypes.put(type, vulnTypes.getOrDefault(type, 0) + 1);
            }

            for (Map.Entry<String, Integer> entry : vulnTypes.entrySet()) {
                System.out.println("(API-5) - " + entry.getKey() + ": " + entry.getValue());
            }
        }
        System.out.println("(API-5) ================================================================");

        System.out.println("(API-5) Сканирование Broken Function Level Authorization завершено. Найдено уязвимостей: " + vulnerabilities.size());
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
        System.out.println("(API-5) Анализ путей OpenAPI: " + paths.size() + " путей найдено");

        // Сначала добавляем определенные административные эндпоинты
        for (String definiteEndpoint : DEFINITE_ADMIN_ENDPOINTS) {
            if (paths.containsKey(definiteEndpoint)) {
                // Для определенных эндпоинтов добавляем с правильным HTTP методом
                String method = getDefaultMethodForEndpoint(definiteEndpoint);
                String fullEndpoint = method + " " + definiteEndpoint;
                if (!adminEndpoints.contains(fullEndpoint)) {
                    adminEndpoints.add(fullEndpoint);
                    System.out.println("(API-5) Обнаружен определенный административный эндпоинт: " + fullEndpoint);
                }
            }
        }

        // Затем анализируем все пути по ключевым словам
        for (String path : paths.keySet()) {
            // Пропускаем не-административные эндпоинты
            if (isNonAdminEndpoint(path)) {
                continue;
            }

            PathItem pathItem = paths.get(path);

            // Проверяем все операции на пути
            for (PathItem.HttpMethod method : pathItem.readOperationsMap().keySet()) {
                Operation operation = pathItem.readOperationsMap().get(method);

                // Ищем административные эндпоинты по ключевым словам
                if (isAdminEndpoint(path, operation)) {
                    String fullEndpoint = method.name() + " " + path;
                    if (!adminEndpoints.contains(fullEndpoint)) {
                        adminEndpoints.add(fullEndpoint);
                        System.out.println("(API-5) Обнаружен административный эндпоинт по ключевым словам: " + fullEndpoint);
                    }
                }
            }
        }

        return adminEndpoints;
    }

    /**
     * Проверка, является ли эндпоинт НЕ административным
     */
    private boolean isNonAdminEndpoint(String path) {
        for (String nonAdminPath : NON_ADMIN_ENDPOINTS) {
            if (path.equals(nonAdminPath)) {
                return true;
            }
            // Также проверяем частичное совпадение для параметризованных путей
            if (nonAdminPath.contains("{") && path.startsWith(nonAdminPath.substring(0, nonAdminPath.indexOf("{")))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Проверка, является ли эндпоинт административным
     */
    private boolean isAdminEndpoint(String path, Operation operation) {
        String lowerPath = path.toLowerCase();
        String lowerSummary = operation.getSummary() != null ? operation.getSummary().toLowerCase() : "";
        String lowerDescription = operation.getDescription() != null ? operation.getDescription().toLowerCase() : "";

        // Проверка пути на административные ключевые слова
        for (String keyword : ADMIN_KEYWORDS) {
            if (lowerPath.contains(keyword)) {
                return true;
            }
        }

        // Проверка описания на административные функции
        if (lowerDescription.contains("банкир") || lowerDescription.contains("банкиром") ||
                lowerDescription.contains("админ") || lowerDescription.contains("администратор") ||
                lowerDescription.contains("одобрение") || lowerDescription.contains("отклонение") ||
                lowerDescription.contains("ожидающих") || lowerDescription.contains("внутренний")) {
            return true;
        }

        // Проверка summary на административные функции
        if (lowerSummary.contains("банкир") || lowerSummary.contains("одобрить") ||
                lowerSummary.contains("отклонить") || lowerSummary.contains("ожидающих") ||
                lowerSummary.contains("внутренний") || lowerSummary.contains("админ")) {
            return true;
        }

        // Проверка тегов операции
        if (operation.getTags() != null) {
            for (String tag : operation.getTags()) {
                String lowerTag = tag.toLowerCase();
                if (lowerTag.contains("admin") || lowerTag.contains("internal") ||
                        lowerTag.contains("banker") || lowerTag.contains("technical") ||
                        lowerTag.contains("внутренний")) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 5.5.2: Попытка вызова админ-функций с правами обычного пользователя
     */
    private List<Vulnerability> testAdminAccessWithUserTokens(String baseUrl, List<String> adminEndpoints,
                                                              String userToken, String username,
                                                              ApiClient apiClient, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        Set<String> testedEndpoints = new HashSet<>();

        System.out.println("(API-5) Тестирование " + adminEndpoints.size() + " административных эндпоинтов с правами пользователя " + username);

        for (String endpoint : adminEndpoints) {
            if (testedEndpoints.contains(endpoint)) {
                continue;
            }
            testedEndpoints.add(endpoint);

            // Парсим метод и путь
            String[] parts = endpoint.split(" ", 2);
            if (parts.length != 2) continue;

            String method = parts[0];
            String path = parts[1];

            String testEndpoint = replacePathParameters(path);
            String fullUrl = baseUrl + testEndpoint;

            System.out.println("(API-5) Тестирование эндпоинта: " + method + " " + path);
            System.out.println("(API-5) URL: " + fullUrl);

            // Тестируем с токеном обычного пользователя
            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, method, fullUrl, userToken, getDefaultPayload(method, path));

            if (response != null) {
                if (response.getStatusCode() == 200 || response.getStatusCode() == 201) {
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
                } else if (response.getStatusCode() >= 400 && response.getStatusCode() < 500) {
                    System.out.println("(API-5) Защита работает: статус " + response.getStatusCode() + " для " + endpoint);
                } else {
                    System.out.println("(API-5) Неопределенный результат: статус " + response.getStatusCode() + " для " + endpoint);
                }
            } else {
                System.out.println("(API-5) Ошибка при тестировании: " + endpoint);
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
                "/auth/me/role", "/profile/role", "/account/role",
                "/admin/assign-role", "/api/roles", "/auth/me"
        };

        System.out.println("(API-5) Тестирование " + roleModificationEndpoints.length + " эндпоинтов для эскалации привилегий");

        for (String endpoint : roleModificationEndpoints) {
            String fullUrl = baseUrl + endpoint;
            System.out.println("(API-5) Тестирование эндпоинта изменения ролей: " + endpoint);

            // Пробуем различные payloads для эскалации привилегий
            for (String role : PRIVILEGED_ROLES) {
                String payload = String.format("{\"role\":\"%s\"}", role);
                System.out.println("(API-5) Попытка установки роли: " + role);

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "POST", fullUrl, token, payload);

                if (response != null) {
                    if (response.getStatusCode() == 200) {
                        // Проверяем, действительно ли произошла эскалация привилегий
                        if (response.getBody() != null &&
                                (response.getBody().toLowerCase().contains(role) ||
                                        response.getBody().toLowerCase().contains("admin") ||
                                        response.getBody().toLowerCase().contains("success"))) {

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
                        } else {
                            System.out.println("(API-5) Запрос выполнен, но эскалация не подтверждена: " + endpoint);
                        }
                    } else if (response.getStatusCode() >= 400 && response.getStatusCode() < 500) {
                        System.out.println("(API-5) Защита работает: статус " + response.getStatusCode() + " для изменения роли на " + role);
                    } else {
                        System.out.println("(API-5) Неопределенный результат: статус " + response.getStatusCode() + " для изменения роли на " + role);
                    }
                } else {
                    System.out.println("(API-5) Ошибка при запросе изменения роли: " + endpoint);
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

        System.out.println("(API-5) Проверка доступа между пользователями " + user1 + " и " + user2);

        // Получаем ID пользователей
        String user1Id = getUserId(baseUrl, token1, apiClient);
        String user2Id = getUserId(baseUrl, token2, apiClient);
        System.out.println("(API-5) User1 ID: " + user1Id + ", User2 ID: " + user2Id);

        // Получаем счета пользователей
        List<String> user1Accounts = getUserAccounts(baseUrl, token1, apiClient);
        List<String> user2Accounts = getUserAccounts(baseUrl, token2, apiClient);
        System.out.println("(API-5) User1 счетов: " + user1Accounts.size() + ", User2 счетов: " + user2Accounts.size());

        // Тестируем доступ к счетам другого пользователя
        if (!user2Accounts.isEmpty() && !user1Accounts.isEmpty()) {
            String user2Account = user2Accounts.get(0);
            String user1Account = user1Accounts.size() > 1 ? user1Accounts.get(1) : user1Accounts.get(0);

            // Тест 1: Попытка доступа к счету другого пользователя
            String accountDetailsUrl = baseUrl + "/accounts/" + user2Account;
            System.out.println("(API-5) Тестирование доступа к чужому счету: " + accountDetailsUrl);

            HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET", accountDetailsUrl, token1);

            if (response != null) {
                if (response.getStatusCode() == 200) {
                    Vulnerability vuln = createVulnerability(
                            "Доступ к счетам другого пользователя",
                            "Пользователь " + user1 + " получил доступ к счету " + user2Account +
                                    " пользователя " + user2 + ". Доказательство: успешный доступ к финансовым данным чужого счета.",
                            "/accounts/{account_id}",
                            response.getStatusCode(),
                            user1, user2, accountDetailsUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-5) УЯЗВИМОСТЬ: Обнаружен доступ к счетам другого пользователя: " + user1 + " → " + user2Account);
                } else if (response.getStatusCode() >= 400 && response.getStatusCode() < 500) {
                    System.out.println("(API-5) Защита работает: статус " + response.getStatusCode() + " для доступа к чужому счету");
                } else {
                    System.out.println("(API-5) Неопределенный результат: статус " + response.getStatusCode() + " для доступа к чужому счету");
                }
            }

            // Тест 2: Попытка выполнения операций с чужим счетом
            String closeAccountUrl = baseUrl + "/accounts/" + user2Account + "/close";
            String closePayload = "{\"action\":\"transfer\", \"destination_account_id\":\"" + user1Account + "\"}";
            System.out.println("(API-5) Тестирование операции закрытия чужого счета: " + closeAccountUrl);

            HttpApiClient.ApiResponse closeResponse = makeAuthenticatedRequest(apiClient, "PUT", closeAccountUrl, token1, closePayload);
            if (closeResponse != null) {
                if (closeResponse.getStatusCode() == 200 || closeResponse.getStatusCode() == 201) {
                    Vulnerability vuln = createVulnerability(
                            "Несанкционированные операции с чужим счетом",
                            "Пользователь " + user1 + " успешно выполнил операцию закрытия счета " + user2Account +
                                    " принадлежащего пользователю " + user2,
                            "/accounts/{account_id}/close",
                            closeResponse.getStatusCode(),
                            user1, user2, closeAccountUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-5) УЯЗВИМОСТЬ: Обнаружены несанкционированные операции с чужим счетом: " + user1 + " → " + user2Account);
                } else if (closeResponse.getStatusCode() >= 400 && closeResponse.getStatusCode() < 500) {
                    System.out.println("(API-5) Защита работает: статус " + closeResponse.getStatusCode() + " для операции с чужим счетом");
                } else {
                    System.out.println("(API-5) Неопределенный результат: статус " + closeResponse.getStatusCode() + " для операции с чужим счетом");
                }
            }
        } else {
            System.out.println("(API-5) Недостаточно данных для тестирования доступа между пользователями");
        }

        return vulnerabilities;
    }

    /**
     * 5.5.5: Анализ разграничения прав между разными группами пользователей
     */
    private List<Vulnerability> testGroupPermissionSeparation(String baseUrl, Map<String, String> tokens,
                                                              ApiClient apiClient, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Тестируем разные уровни доступа для разных пользователей
        String[] sensitiveEndpoints = {
                "/payment-consents/pending/list",
                "/payment-consents/{request_id}/approve",
                "/payment-consents/{request_id}/reject",
                "/banker/capital",
                "/banker/key-rate",
                "/teams/stats"
        };

        System.out.println("(API-5) Тестирование разграничения прав для " + tokens.size() + " пользователей");

        for (Map.Entry<String, String> entry : tokens.entrySet()) {
            String user = entry.getKey();
            String token = entry.getValue();

            System.out.println("(API-5) Тестирование пользователя: " + user);

            for (String endpoint : sensitiveEndpoints) {
                String testEndpoint = replacePathParameters(endpoint);
                String fullUrl = baseUrl + testEndpoint;

                System.out.println("(API-5) Тестирование чувствительного эндпоинта: " + endpoint);

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, "GET", fullUrl, token);

                if (response != null) {
                    if (response.getStatusCode() == 200 || response.getStatusCode() == 201) {
                        // Проверяем, имеет ли обычный пользователь доступ к банковским функциям
                        if (!user.contains("banker") && !user.contains("admin")) {
                            Vulnerability vuln = createVulnerability(
                                    "Нарушение разграничения прав между группами",
                                    "Обычный пользователь " + user + " получил доступ к чувствительному эндпоинту " + endpoint +
                                            ", который должен быть доступен только банкирам/администраторам.",
                                    endpoint,
                                    response.getStatusCode(),
                                    user, "banker", fullUrl
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("(API-5) УЯЗВИМОСТЬ: Нарушение разграничения прав: " + user + " → " + endpoint);
                        } else {
                            System.out.println("(API-5) Легитимный доступ: " + user + " → " + endpoint);
                        }
                    } else if (response.getStatusCode() >= 400 && response.getStatusCode() < 500) {
                        System.out.println("(API-5) Защита работает: статус " + response.getStatusCode() + " для " + user + " → " + endpoint);
                    } else {
                        System.out.println("(API-5) Неопределенный результат: статус " + response.getStatusCode() + " для " + user + " → " + endpoint);
                    }
                } else {
                    System.out.println("(API-5) Ошибка при тестировании: " + user + " → " + endpoint);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.5.6: Тестирование обходов контроля доступа через альтернативные пути
     */
    private List<Vulnerability> testAccessControlBypass(String baseUrl, String token, String username,
                                                        ApiClient apiClient, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Тестируем обходы через различные методы HTTP
        String[] bypassEndpoints = {
                "/accounts/{account_id}/close",
                "/accounts/{account_id}/status",
                "/product-agreements/{agreement_id}"
        };

        System.out.println("(API-5) Тестирование обходов контроля доступа для " + bypassEndpoints.length + " эндпоинтов");

        for (String endpoint : bypassEndpoints) {
            String testEndpoint = replacePathParameters(endpoint);
            String fullUrl = baseUrl + testEndpoint;

            System.out.println("(API-5) Тестирование обходов для эндпоинта: " + endpoint);

            // Пробуем разные HTTP методы
            String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH"};
            for (String method : methods) {
                System.out.println("(API-5) Тестирование метода " + method + " для " + endpoint);

                HttpApiClient.ApiResponse response = makeAuthenticatedRequest(apiClient, method, fullUrl, token,
                        getDefaultPayload(method, endpoint));

                if (response != null) {
                    if (response.getStatusCode() == 200 || response.getStatusCode() == 201) {
                        // Проверяем, не должен ли этот метод быть запрещенным
                        if (isDangerousMethodForEndpoint(method, endpoint)) {
                            Vulnerability vuln = createVulnerability(
                                    "Обход контроля доступа через альтернативный HTTP метод",
                                    "Пользователь " + username + " получил доступ к эндпоинту " + endpoint +
                                            " через метод " + method + ", который должен быть запрещен. HTTP статус: " + response.getStatusCode(),
                                    endpoint,
                                    response.getStatusCode(),
                                    username, "system", fullUrl
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("(API-5) УЯЗВИМОСТЬ: Обнаружен обход контроля доступа: " + method + " " + endpoint);
                        } else {
                            System.out.println("(API-5) Легитимный доступ: " + method + " " + endpoint);
                        }
                    } else if (response.getStatusCode() >= 400 && response.getStatusCode() < 500) {
                        System.out.println("(API-5) Защита работает: статус " + response.getStatusCode() + " для " + method + " " + endpoint);
                    } else {
                        System.out.println("(API-5) Неопределенный результат: статус " + response.getStatusCode() + " для " + method + " " + endpoint);
                    }
                } else {
                    System.out.println("(API-5) Ошибка при тестировании: " + method + " " + endpoint);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * 5.5.7: Проверка отсутствия авторизации для критических операций
     */
    private List<Vulnerability> testUnauthorizedCriticalOperations(String baseUrl, List<String> adminEndpoints,
                                                                   ApiClient apiClient, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        Set<String> testedEndpoints = new HashSet<>();

        // Критические операции, которые никогда не должны быть доступны без авторизации
        String[] criticalEndpoints = {
                "/payment-consents/pending/list",
                "/payment-consents/{request_id}/approve",
                "/payment-consents/{request_id}/reject",
                "/banker/capital",
                "/banker/key-rate",
                "/teams/stats"
        };

        System.out.println("(API-5) Тестирование отсутствия авторизации для " + criticalEndpoints.length + " критических операций");

        for (String endpoint : criticalEndpoints) {
            if (testedEndpoints.contains(endpoint)) {
                continue;
            }
            testedEndpoints.add(endpoint);

            String testEndpoint = replacePathParameters(endpoint);
            String fullUrl = baseUrl + testEndpoint;

            // Определяем метод на основе эндпоинта
            String method = getDefaultMethodForEndpoint(endpoint);

            System.out.println("(API-5) Тестирование критической операции: " + method + " " + endpoint);
            System.out.println("(API-5) URL: " + fullUrl);

            // Пробуем доступ без авторизации
            HttpApiClient.ApiResponse response = makeUnauthenticatedRequest(apiClient, method, fullUrl,
                    getDefaultPayload(method, endpoint));

            if (response != null) {
                if (response.getStatusCode() == 200 || response.getStatusCode() == 201) {
                    Vulnerability vuln = createVulnerability(
                            "Отсутствие авторизации для критической операции",
                            "Обнаружен доступ к критическому эндпоинту " + endpoint +
                                    " без аутентификации. HTTP статус: " + response.getStatusCode() +
                                    ". Доказательство: успешный доступ к банковским/административным функциям без предоставления токена авторизации.",
                            endpoint,
                            response.getStatusCode(),
                            "anonymous", "system", fullUrl
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-5) УЯЗВИМОСТЬ: Обнаружен доступ без авторизации к критическому эндпоинту: " + endpoint +
                            ". Статус: " + response.getStatusCode());
                } else if (response.getStatusCode() >= 400 && response.getStatusCode() < 500) {
                    System.out.println("(API-5) Защита работает: статус " + response.getStatusCode() + " для " + endpoint);
                } else {
                    System.out.println("(API-5) Неопределенный результат: статус " + response.getStatusCode() + " для " + endpoint);
                }
            } else {
                System.out.println("(API-5) Ошибка при тестировании: " + endpoint);
            }
        }

        return vulnerabilities;
    }

    // Вспомогательные методы

    private boolean isDangerousMethodForEndpoint(String method, String endpoint) {
        if (endpoint.contains("/close") || endpoint.contains("/status") || endpoint.contains("/agreements")) {
            return "DELETE".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
        }
        return false;
    }

    private String getDefaultMethodForEndpoint(String endpoint) {
        if (endpoint.contains("/approve") || endpoint.contains("/reject")) {
            return "POST";
        } else if (endpoint.contains("/pending/list") || endpoint.contains("/capital") ||
                endpoint.contains("/key-rate") || endpoint.contains("/stats")) {
            return "GET";
        } else if (endpoint.contains("/close") || endpoint.contains("/status")) {
            return "PUT";
        }
        return "GET";
    }

    private String getDefaultPayload(String method, String endpoint) {
        if ("POST".equals(method) || "PUT".equals(method)) {
            if (endpoint.contains("/close")) {
                return "{\"action\":\"transfer\", \"destination_account_id\":\"test-account\"}";
            } else if (endpoint.contains("/status")) {
                return "{\"status\":\"active\"}";
            } else if (endpoint.contains("/approve") || endpoint.contains("/reject")) {
                return "{}";
            }
        }
        return null;
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
                    Pattern pattern = Pattern.compile("\"(client_id|id)\"\\s*:\\s*\"([^\"]+)\"");
                    Matcher matcher = pattern.matcher(apiResponse.getBody());
                    if (matcher.find()) {
                        return matcher.group(2);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-5) Ошибка при получении ID пользователя: " + e.getMessage());
        }
        return "unknown";
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

                    if (accounts.isEmpty()) {
                        pattern = Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\"");
                        matcher = pattern.matcher(apiResponse.getBody());
                        while (matcher.find()) {
                            accounts.add(matcher.group(1));
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-5) Ошибка при получении счетов пользователя: " + e.getMessage());
        }

        if (accounts.isEmpty()) {
            accounts.add("acc-" + System.currentTimeMillis());
            accounts.add("acc-" + (System.currentTimeMillis() + 1));
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
        recommendations.add("Обеспечьте правильное разграничение прав между банкирами и обычными пользователями");
        vuln.setRecommendations(recommendations);

        return vuln;
    }
}