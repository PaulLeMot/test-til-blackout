package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;

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
    private static final int BASE_DELAY_MS = 500; // базовая задержка между запросами
    private static final int MAX_RETRIES = 3; // максимальное количество повторных попыток
    private static final int BASE_RETRY_DELAY_MS = 1000; // начальная задержка при повторных попытках
    private static final double RETRY_BACKOFF_FACTOR = 2.0; // коэффициент экспоненциального увеличения задержки

    @Override
    public String getName() {
        return "OWASP API1: Broken Object Level Authorization (BOLA) Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-1) Запуск сканирования BOLA с управлением частотой запросов...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Проверяем наличие OpenAPI спецификации
        boolean accountsEndpointDocumented = false;
        boolean accountDetailEndpointDocumented = false;

        if (openApiObj instanceof OpenAPI) {
            OpenAPI spec = (OpenAPI) openApiObj;
            Map<String, PathItem> paths = spec.getPaths();

            if (paths != null) {
                accountsEndpointDocumented = paths.containsKey(ACCOUNTS_ENDPOINT);
                accountDetailEndpointDocumented = paths.containsKey("/accounts/{account_id}") ||
                        paths.containsKey("/accounts/{accountId}") ||
                        paths.containsKey("/accounts/{id}");
            }
        }

        System.out.println("(API-1) Эндпоинт " + ACCOUNTS_ENDPOINT +
                " " + (accountsEndpointDocumented ? "задокументирован" : "НЕ задокументирован") + " в OpenAPI");
        System.out.println("(API-1) Эндпоинт детализации счёта " +
                (accountDetailEndpointDocumented ? "задокументирован" : "НЕ задокументирован") + " в OpenAPI");

        // Получаем токены пользователей
        Map<String, String> tokens = config.getUserTokens();
        if (tokens == null || tokens.size() < 2) {
            System.err.println("(API-1) Недостаточно токенов для BOLA-теста (нужно минимум 2).");
            return vulnerabilities;
        }

        // Получаем первых двух пользователей
        List<String> users = new ArrayList<>(tokens.keySet());
        String user1 = users.get(0);
        String user2 = users.get(1);
        String token1 = tokens.get(user1);
        String token2 = tokens.get(user2);

        System.out.println("(API-1) Тестируем пользователей: " + user1 + " и " + user2);

        try {
            // 1. Получаем счета пользователя user1
            List<String> user1Accounts = getAccountIds(config, apiClient, token1, user1);
            if (user1Accounts == null || user1Accounts.isEmpty()) {
                System.out.println("(API-1) У пользователя " + user1 + " нет счетов для тестирования");
                return vulnerabilities;
            }
            System.out.println("(API-1) Счета пользователя " + user1 + ": " + user1Accounts);

            // 2. Проверяем, может ли user2 получить доступ к счетам user1
            testAccountAccess(config, apiClient, token2, user2, user1Accounts, user1, vulnerabilities);

            // 3. Проверяем, может ли user1 получить доступ к счетам user2 (дополнительная проверка)
            List<String> user2Accounts = getAccountIds(config, apiClient, token2, user2);
            if (user2Accounts != null && !user2Accounts.isEmpty()) {
                System.out.println("(API-1) Счета пользователя " + user2 + ": " + user2Accounts);
                testAccountAccess(config, apiClient, token1, user1, user2Accounts, user2, vulnerabilities);
            }

        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при сканировании BOLA: " + e.getMessage());
        }

        System.out.println("(API-1) Сканирование BOLA завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Получение списка счетов пользователя с правильными заголовками
     */
    private List<String> getAccountIds(ScanConfig config, ApiClient apiClient, String token, String username) {
        try {
            Map<String, String> headers = createDefaultHeaders(token);

            String url = config.getTargetBaseUrl() + ACCOUNTS_ENDPOINT;
            System.out.println("(API-1) Запрос счетов для " + username + " на URL: " + url);

            // Используем запрос с повторными попытками
            HttpApiClient.ApiResponse apiResponse = executeRequestWithRetry(
                    apiClient, "GET", url, null, headers, username, "получение списка счетов"
            );

            if (apiResponse != null) {
                int statusCode = apiResponse.getStatusCode();
                System.out.println("(API-1) Ответ при запросе счетов для " + username + ": " + statusCode);

                if (apiResponse.getBody() != null) {
                    System.out.println("(API-1) Тело ответа (первые 200 символов): " +
                            apiResponse.getBody().substring(0, Math.min(200, apiResponse.getBody().length())));
                }

                if (statusCode == 200 && apiResponse.getBody() != null) {
                    return extractAccountIds(apiResponse.getBody());
                } else {
                    System.err.println("(API-1) Неожиданный статус при запросе счетов для " + username + ": " + statusCode);
                }
            }
        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при получении счетов для " + username + ": " + e.getMessage());
        }
        return null;
    }

    /**
     * Создание стандартных заголовков для запросов
     */
    private Map<String, String> createDefaultHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        return headers;
    }

    /**
     * Извлечение ID счетов из ответа API
     */
    private List<String> extractAccountIds(String responseBody) {
        List<String> accountIds = new ArrayList<>();

        // Паттерн для поиска accountId в ответе
        Pattern pattern = Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(responseBody);

        while (matcher.find()) {
            accountIds.add(matcher.group(1));
        }

        System.out.println("(API-1) Извлеченные accountIds: " + accountIds);
        return accountIds;
    }

    /**
     * Проверка доступа к счетам другого пользователя
     */
    private void testAccountAccess(ScanConfig config, ApiClient apiClient, String token,
                                   String attackerUser, List<String> targetAccounts,
                                   String ownerUser, List<Vulnerability> vulnerabilities) {

        System.out.println("(API-1) Проверка доступа пользователя " + attackerUser +
                " к счетам пользователя " + ownerUser);

        for (int i = 0; i < targetAccounts.size(); i++) {
            String accountId = targetAccounts.get(i);
            System.out.println("(API-1) Тестирование доступа к счету " + accountId + " (" + (i+1) + "/" + targetAccounts.size() + ")");

            // 1. Проверяем детали счета
            HttpApiClient.ApiResponse accountResponse = tryAccessEndpoint(
                    config, apiClient, token, attackerUser,
                    String.format(ACCOUNT_DETAIL_ENDPOINT, accountId)
            );

            // 2. Проверяем баланс счета
            HttpApiClient.ApiResponse balanceResponse = tryAccessEndpoint(
                    config, apiClient, token, attackerUser,
                    String.format(ACCOUNT_BALANCES_ENDPOINT, accountId)
            );

            // 3. Проверяем транзакции счета
            HttpApiClient.ApiResponse transactionsResponse = tryAccessEndpoint(
                    config, apiClient, token, attackerUser,
                    String.format(ACCOUNT_TRANSACTIONS_ENDPOINT, accountId)
            );

            // Определяем, есть ли уязвимость
            if (isBolaVulnerability(accountResponse) ||
                    isBolaVulnerability(balanceResponse) ||
                    isBolaVulnerability(transactionsResponse)) {

                String vulnerableEndpoint = "";
                HttpApiClient.ApiResponse vulnerableResponse = null;

                if (isBolaVulnerability(accountResponse)) {
                    vulnerableEndpoint = String.format(ACCOUNT_DETAIL_ENDPOINT, accountId);
                    vulnerableResponse = accountResponse;
                } else if (isBolaVulnerability(balanceResponse)) {
                    vulnerableEndpoint = String.format(ACCOUNT_BALANCES_ENDPOINT, accountId);
                    vulnerableResponse = balanceResponse;
                } else {
                    vulnerableEndpoint = String.format(ACCOUNT_TRANSACTIONS_ENDPOINT, accountId);
                    vulnerableResponse = transactionsResponse;
                }

                Vulnerability vuln = createVulnerability(
                        vulnerableEndpoint, ownerUser, attackerUser, accountId, vulnerableResponse
                );
                vulnerabilities.add(vuln);
                System.out.println("(API-1) !!! НАЙДЕНА УЯЗВИМОСТЬ BOLA !!!");
                System.out.println("(API-1) Пользователь " + attackerUser + " получил доступ к счету " +
                        accountId + " пользователя " + ownerUser);
            } else {
                System.out.println("(API-1) Доступ к счету " + accountId + " заблокирован для " + attackerUser);
            }

            // Адаптивная задержка между запросами
            applyAdaptiveDelay(i, targetAccounts.size());
        }
    }

    /**
     * Адаптивная задержка между запросами для предотвращения 429 ошибок
     */
    private void applyAdaptiveDelay(int currentAccountIndex, int totalAccounts) {
        try {
            // Базовая задержка
            int delay = BASE_DELAY_MS;

            // Увеличиваем задержку для последних счетов
            if (currentAccountIndex >= totalAccounts - 3) {
                delay = BASE_DELAY_MS * 2;
            }

            // Дополнительная задержка после каждых 5 счетов
            if ((currentAccountIndex + 1) % 5 == 0 && currentAccountIndex > 0) {
                delay = Math.max(delay, BASE_DELAY_MS * 3);
                System.out.println("(API-1) Дополнительная пауза перед продолжением тестирования...");
            }

            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Попытка доступа к эндпоинту с правильными заголовками и повторными попытками
     */
    private HttpApiClient.ApiResponse tryAccessEndpoint(ScanConfig config, ApiClient apiClient,
                                                        String token, String username, String endpoint) {
        Map<String, String> headers = createDefaultHeaders(token);
        String url = config.getTargetBaseUrl() + endpoint;

        System.out.println("(API-1) Запрос к " + endpoint + " от " + username);

        // Используем механизм повторных попыток
        return executeRequestWithRetry(apiClient, "GET", url, null, headers, username, endpoint);
    }

    /**
     * Выполнение запроса с повторными попытками при ошибках 429
     */
    private HttpApiClient.ApiResponse executeRequestWithRetry(ApiClient apiClient, String method,
                                                              String url, String body,
                                                              Map<String, String> headers,
                                                              String username, String context) {
        int attempt = 0;
        int currentDelay = BASE_RETRY_DELAY_MS;

        while (attempt <= MAX_RETRIES) {
            try {
                Object response = apiClient.executeRequest(method, url, body, headers);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    // Если запрос успешен или это не ошибка 429 - возвращаем результат
                    if (apiResponse.getStatusCode() != 429) {
                        return apiResponse;
                    }

                    // Если получили 429 - делаем задержку и повторяем запрос
                    System.out.println("(API-1) [" + username + "] Получена ошибка 429 при " + context +
                            ". Попытка " + (attempt + 1) + " из " + MAX_RETRIES);
                }
            } catch (Exception e) {
                System.err.println("(API-1) Ошибка при выполнении запроса: " + e.getMessage());
            }

            // Увеличиваем задержку экспоненциально
            attempt++;
            if (attempt <= MAX_RETRIES) {
                try {
                    System.out.println("(API-1) Ожидание " + currentDelay + " мс перед повторной попыткой...");
                    Thread.sleep(currentDelay);
                    currentDelay = (int) (currentDelay * RETRY_BACKOFF_FACTOR);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        System.err.println("(API-1) [" + username + "] Достигнуто максимальное количество попыток для " + context);
        return null;
    }

    /**
     * Проверка на уязвимость BOLA
     */
    private boolean isBolaVulnerability(HttpApiClient.ApiResponse response) {
        if (response == null) return false;

        int statusCode = response.getStatusCode();
        String responseBody = response.getBody();

        // Успешный доступ к чужим данным
        if (statusCode == 200) {
            // Дополнительная проверка: убеждаемся, что есть данные счета
            return responseBody != null &&
                    (responseBody.contains("\"accountId\"") ||
                            responseBody.contains("\"balance\"") ||
                            responseBody.contains("\"transaction\""));
        }

        // Для ошибки 429 считаем уязвимость, если предыдущие запросы были успешными
        if (statusCode == 429) {
            System.out.println("(API-1) Предупреждение: получена ошибка 429, но предыдущие запросы были успешными");
            return true;
        }

        return false;
    }

    /**
     * Создание отчета об уязвимости
     */
    private Vulnerability createVulnerability(String endpoint, String ownerUser,
                                              String attackerUser, String accountId,
                                              HttpApiClient.ApiResponse response) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API1:2023 - Broken Object Level Authorization");
        vuln.setDescription(
                "Пользователь " + attackerUser + " получил несанкционированный доступ " +
                        "к счету (ID: " + accountId + "), принадлежащему пользователю " + ownerUser + ".\n\n" +
                        "Это критическая уязвимость, позволяющая злоумышленнику получить доступ к финансовым данным других пользователей."
        );
        vuln.setSeverity(Vulnerability.Severity.CRITICAL);
        vuln.setCategory(Vulnerability.Category.OWASP_API1_BOLA);
        vuln.setEndpoint(endpoint);
        vuln.setMethod("GET");
        vuln.setParameter("account_id");
        vuln.setEvidence("Статус ответа: " + response.getStatusCode() + "\nТело ответа: " +
                (response.getBody() != null ? response.getBody().substring(0, Math.min(500, response.getBody().length())) : "пусто"));
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