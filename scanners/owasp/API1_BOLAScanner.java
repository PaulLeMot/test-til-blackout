package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import java.util.stream.Collectors;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class API1_BOLAScanner implements SecurityScanner {

    private static final String ACCOUNTS_ENDPOINT = "/accounts";
    private static final String ACCOUNT_DETAIL_ENDPOINT = "/accounts/%s";
    private static final String ACCOUNT_BALANCES_ENDPOINT = "/accounts/%s/balances";
    private static final String ACCOUNT_TRANSACTIONS_ENDPOINT = "/accounts/%s/transactions";

    // Параметры управления частотой запросов
    private static final int BASE_DELAY_MS = 1000; // увеличена базовая задержка
    private static final int MAX_RETRIES = 2; // уменьшено количество повторных попыток
    private static final int MAX_ACCOUNTS_TO_TEST = 3; // ОГРАНИЧЕНИЕ: тестируем только 3 счета

    @Override
    public String getName() {
        return "OWASP API1: Broken Object Level Authorization (BOLA) Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-1) Запуск сканирования BOLA с ограничением количества тестов...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Получаем токены пользователей
        Map<String, String> tokens = config.getUserTokens();
        if (tokens == null || tokens.size() < 2) {
            System.err.println("(API-1) Недостаточно токенов для BOLA-теста (нужно минимум 2).");
            return vulnerabilities;
        }

        // Получаем список пользователей из токенов (исключаем служебные токены)
        List<String> users = tokens.keySet().stream()
                .filter(user -> !user.equals("default") && !user.equals("bank"))
                .collect(Collectors.toList());

        if (users.size() < 2) {
            System.err.println("(API-1) Недостаточно пользователей в токенах для BOLA-теста (нужно минимум 2).");
            return vulnerabilities;
        }

        String user1 = users.get(0);
        String user2 = users.get(1);

        String token1 = tokens.get(user1);
        String token2 = tokens.get(user2);

        System.out.println("(API-1) Тестируем пользователей из токенов: " + user1 + " и " + user2);

        if (token1 == null || token2 == null) {
            System.err.println("(API-1) Не удалось получить токены для указанных пользователей");
            return vulnerabilities;
        }

        try {
            // 1. Получаем счета пользователя user1 (ограниченное количество)
            List<String> user1Accounts = getAccountIds(config, apiClient, token1, user1);
            if (user1Accounts == null || user1Accounts.isEmpty()) {
                System.out.println("(API-1) У пользователя " + user1 + " нет счетов для тестирования");
                return vulnerabilities;
            }

            // Ограничиваем количество тестируемых счетов
            List<String> limitedUser1Accounts = user1Accounts.subList(0, Math.min(MAX_ACCOUNTS_TO_TEST, user1Accounts.size()));
            System.out.println("(API-1) Тестируем первые " + limitedUser1Accounts.size() + " счета из " + user1Accounts.size() + " для пользователя " + user1);

            // 2. Проверяем, может ли user2 получить доступ к счетам user1
            boolean foundVulnerability = testAccountAccess(config, apiClient, token2, user2, limitedUser1Accounts, user1, vulnerabilities);

            // 3. Если уязвимость уже найдена, пропускаем обратную проверку для оптимизации
            if (!foundVulnerability) {
                List<String> user2Accounts = getAccountIds(config, apiClient, token2, user2);
                if (user2Accounts != null && !user2Accounts.isEmpty()) {
                    List<String> limitedUser2Accounts = user2Accounts.subList(0, Math.min(MAX_ACCOUNTS_TO_TEST, user2Accounts.size()));
                    System.out.println("(API-1) Тестируем первые " + limitedUser2Accounts.size() + " счета из " + user2Accounts.size() + " для пользователя " + user2);
                    testAccountAccess(config, apiClient, token1, user1, limitedUser2Accounts, user2, vulnerabilities);
                }
            }

        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при сканировании BOLA: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("(API-1) Сканирование BOLA завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Получение списка счетов пользователя
     */
    private List<String> getAccountIds(ScanConfig config, ApiClient apiClient, String token, String username) {
        try {
            Map<String, String> headers = createDefaultHeaders(token);
            String url = config.getTargetBaseUrl() + ACCOUNTS_ENDPOINT;

            HttpApiClient.ApiResponse apiResponse = executeRequestWithRetry(
                    apiClient, "GET", url, null, headers, username, "получение списка счетов"
            );

            if (apiResponse != null && apiResponse.getStatusCode() == 200 && apiResponse.getBody() != null) {
                return extractAccountIds(apiResponse.getBody());
            } else {
                System.err.println("(API-1) Не удалось получить счета для " + username + ". Статус: " +
                        (apiResponse != null ? apiResponse.getStatusCode() : "null"));
            }
        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при получении счетов для " + username + ": " + e.getMessage());
        }
        return new ArrayList<>();
    }

    /**
     * Проверка доступа к счетам другого пользователя
     * Возвращает true, если найдена хотя бы одна уязвимость
     */
    private boolean testAccountAccess(ScanConfig config, ApiClient apiClient, String token,
                                      String attackerUser, List<String> targetAccounts,
                                      String ownerUser, List<Vulnerability> vulnerabilities) {

        System.out.println("(API-1) Проверка доступа пользователя " + attackerUser + " к счетам пользователя " + ownerUser);

        boolean foundVulnerability = false;

        for (int i = 0; i < targetAccounts.size(); i++) {
            String accountId = targetAccounts.get(i);
            System.out.println("(API-1) Тестирование доступа к счету " + accountId + " (" + (i+1) + "/" + targetAccounts.size() + ")");

            // Проверяем все три эндпоинта для данного счета
            boolean accountVulnerable = testSingleAccount(config, apiClient, token, attackerUser, accountId, ownerUser, vulnerabilities);

            if (accountVulnerable) {
                foundVulnerability = true;
                // Если нашли уязвимость для одного счета, останавливаем тестирование для этого пользователя
                System.out.println("(API-1) Уязвимость BOLA подтверждена для счета " + accountId + ". Прекращаем тестирование остальных счетов.");
                break;
            }

            // Задержка между запросами
            applyDelay();
        }

        return foundVulnerability;
    }

    /**
     * Тестирование одного счета на всех эндпоинтах
     */
    private boolean testSingleAccount(ScanConfig config, ApiClient apiClient, String token,
                                      String attackerUser, String accountId, String ownerUser,
                                      List<Vulnerability> vulnerabilities) {

        boolean isVulnerable = false;

        // Тестируем три основных эндпоинта
        String[] endpoints = {
                String.format(ACCOUNT_DETAIL_ENDPOINT, accountId),
                String.format(ACCOUNT_BALANCES_ENDPOINT, accountId),
                String.format(ACCOUNT_TRANSACTIONS_ENDPOINT, accountId)
        };

        String vulnerableEndpoint = null;
        HttpApiClient.ApiResponse vulnerableResponse = null;

        for (String endpoint : endpoints) {
            HttpApiClient.ApiResponse response = tryAccessEndpoint(config, apiClient, token, attackerUser, endpoint);
            if (isBolaVulnerability(response)) {
                isVulnerable = true;
                vulnerableEndpoint = endpoint;
                vulnerableResponse = response;
                break; // Достаточно одной уязвимости на счет
            }
        }

        if (isVulnerable) {
            Vulnerability vuln = createVulnerability(
                    vulnerableEndpoint, ownerUser, attackerUser, accountId, vulnerableResponse
            );
            vulnerabilities.add(vuln);
            System.out.println("(API-1) !!! НАЙДЕНА УЯЗВИМОСТЬ BOLA !!!");
            System.out.println("(API-1) Пользователь " + attackerUser + " получил доступ к счету " + accountId + " пользователя " + ownerUser);
        }

        return isVulnerable;
    }

    /**
     * Задержка между запросами
     */
    private void applyDelay() {
        try {
            Thread.sleep(BASE_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private Map<String, String> createDefaultHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        return headers;
    }

    private List<String> extractAccountIds(String responseBody) {
        List<String> accountIds = new ArrayList<>();
        Pattern pattern = Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(responseBody);

        while (matcher.find()) {
            accountIds.add(matcher.group(1));
        }

        System.out.println("(API-1) Извлеченные accountIds: " + accountIds.size() + " счетов");
        return accountIds;
    }

    private HttpApiClient.ApiResponse tryAccessEndpoint(ScanConfig config, ApiClient apiClient,
                                                        String token, String username, String endpoint) {
        Map<String, String> headers = createDefaultHeaders(token);
        String url = config.getTargetBaseUrl() + endpoint;
        return executeRequestWithRetry(apiClient, "GET", url, null, headers, username, endpoint);
    }

    private HttpApiClient.ApiResponse executeRequestWithRetry(ApiClient apiClient, String method,
                                                              String url, String body,
                                                              Map<String, String> headers,
                                                              String username, String context) {
        int attempt = 0;
        int currentDelay = 1000;

        while (attempt <= MAX_RETRIES) {
            try {
                Object response = apiClient.executeRequest(method, url, body, headers);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    if (apiResponse.getStatusCode() != 429) {
                        return apiResponse;
                    }
                    System.out.println("(API-1) [" + username + "] Получена ошибка 429 при " + context);
                }
            } catch (Exception e) {
                System.err.println("(API-1) Ошибка при выполнении запроса: " + e.getMessage());
            }

            attempt++;
            if (attempt <= MAX_RETRIES) {
                try {
                    Thread.sleep(currentDelay);
                    currentDelay *= 2;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        System.err.println("(API-1) [" + username + "] Достигнуто максимальное количество попыток для " + context);
        return null;
    }

    private boolean isBolaVulnerability(HttpApiClient.ApiResponse response) {
        if (response == null) return false;

        int statusCode = response.getStatusCode();
        String responseBody = response.getBody();

        // Успешный доступ к чужим данным
        if (statusCode == 200) {
            return responseBody != null &&
                    (responseBody.contains("\"accountId\"") ||
                            responseBody.contains("\"balance\"") ||
                            responseBody.contains("\"transaction\""));
        }

        return false;
    }

    private Vulnerability createVulnerability(String endpoint, String ownerUser,
                                              String attackerUser, String accountId,
                                              HttpApiClient.ApiResponse response) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API1:2023 - Broken Object Level Authorization");
        vuln.setDescription(
                "Пользователь " + attackerUser + " получил несанкционированный доступ " +
                        "к счету (ID: " + accountId + "), принадлежащему пользователю " + ownerUser + ".\n\n" +
                        "Эндпоинт: " + endpoint + "\n" +
                        "Это критическая уязвимость, позволяющая злоумышленнику получить доступ к финансовым данным других пользователей."
        );
        vuln.setSeverity(Vulnerability.Severity.CRITICAL);
        vuln.setCategory(Vulnerability.Category.OWASP_API1_BOLA);
        vuln.setEndpoint(endpoint);
        vuln.setMethod("GET");
        vuln.setEvidence("Статус ответа: " + response.getStatusCode() + "\nТело ответа (первые 200 символов): " +
                (response.getBody() != null ? response.getBody().substring(0, Math.min(200, response.getBody().length())) : "пусто"));
        vuln.setStatusCode(response.getStatusCode());

        vuln.setRecommendations(Arrays.asList(
                "Реализовать строгую проверку принадлежности счета авторизованному пользователю перед возвратом данных",
                "Использовать модель \"Deny by default\" - явно разрешать доступ только к своим ресурсам",
                "Добавить middleware для проверки прав доступа на каждом уровне (endpoint, сервис, база данных)",
                "Залогировать все попытки доступа к чужим ресурсам для последующего анализа",
                "Провести аудит всех эндпоинтов, работающих с идентификаторами объектов"
        ));

        return vuln;
    }
}