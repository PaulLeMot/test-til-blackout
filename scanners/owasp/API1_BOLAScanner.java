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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class API1_BOLAScanner implements SecurityScanner {

    private static final String ACCOUNTS_ENDPOINT = "/accounts";
    private static final String ACCOUNT_DETAIL_ENDPOINT_TEMPLATE = "/accounts/%s";

    public API1_BOLAScanner() {}

    @Override
    public String getName() {
        return "API1_BOLA";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-1) Запуск сканирования на уязвимости BOLA (OWASP API Security Top 10:2023 - API1)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl().trim();
        String password = config.getPassword();

        // === Проверка документирования эндпоинтов в OpenAPI ===
        boolean accountsEndpointDocumented = false;
        boolean accountDetailEndpointDocumented = false;

        if (openAPI instanceof OpenAPI) {
            OpenAPI spec = (OpenAPI) openAPI;
            Map<String, PathItem> paths = spec.getPaths();

            if (paths != null) {
                accountsEndpointDocumented = paths.containsKey(ACCOUNTS_ENDPOINT);
                accountDetailEndpointDocumented = paths.containsKey("/accounts/{accountId}") ||
                        paths.containsKey("/accounts/{id}") ||
                        paths.containsKey("/accounts/{account_id}") ||
                        paths.containsKey("/accounts/{account}");

                System.out.println("(API-1) Эндпоинт " + ACCOUNTS_ENDPOINT +
                        " " + (accountsEndpointDocumented ? "задокументирован" : "НЕ задокументирован") + " в OpenAPI");
                System.out.println("(API-1) Эндпоинт детализации счёта " +
                        (accountDetailEndpointDocumented ? "задокументирован" : "НЕ задокументирован") + " в OpenAPI");

                // Опционально: можно создать уязвимость API9 здесь, но лучше в API9_InventoryScanner
            }
        } else {
            System.out.println("(API-1) OpenAPI-спецификация недоступна — пропуск проверки контракта");
        }

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

        String accountId = getFirstAccountId(baseUrl, token1, apiClient);
        if (accountId == null) {
            System.out.println("(API-1) У пользователя " + user1 + " нет счетов — BOLA-тест невозможен.");
            return vulnerabilities;
        }

        System.out.println("(API-1) Найден счёт пользователя " + user1 + ": " + accountId);

        HttpApiClient.ApiResponse response = tryAccessAccountAsOtherUser(baseUrl, accountId, token2, apiClient);

        if (response == null) {
            System.out.println("(API-1) Не удалось выполнить запрос к счёту " + accountId + " от имени " + user2);
        } else {
            int statusCode = response.getStatusCode();
            System.out.println("(API-1) Ответ при доступе к " + accountId + " от " + user2 + ": HTTP " + statusCode);

            boolean isVulnerable = (statusCode == 200);

            if (isVulnerable) {
                String endpoint = String.format(ACCOUNT_DETAIL_ENDPOINT_TEMPLATE, accountId);
                String fullUrl = baseUrl + endpoint;

                Vulnerability vuln = new Vulnerability();
                vuln.setTitle("API1:2023 - Broken Object Level Authorization (BOLA)");
                vuln.setDescription(
                        "Пользователь " + user2 + " получил HTTP " + statusCode +
                                " при запросе к счёту " + accountId + ", принадлежащему " + user1 + ".\n" +
                                "Сервер не проверил право доступа — это нарушение уровня авторизации объекта (BOLA)."
                );
                vuln.setSeverity(Vulnerability.Severity.HIGH);
                vuln.setCategory(Vulnerability.Category.OWASP_API1_BOLA);
                vuln.setEndpoint(endpoint);
                vuln.setStatusCode(statusCode);
                vuln.setEvidence(String.format(
                        "{\"victimUser\":\"%s\",\"attackerUser\":\"%s\",\"accountId\":\"%s\",\"url\":\"%s\",\"statusCode\":%d}",
                        user1, user2, accountId, fullUrl, statusCode
                ));

                vulnerabilities.add(vuln);
                System.out.println("(API-1) УЯЗВИМОСТЬ BOLA ПОДТВЕРЖДЕНА!");
                System.out.println("(API-1) ДОКАЗАТЕЛЬСТВА УЯЗВИМОСТИ:");
                System.out.println("(API-1) - Атакующий пользователь: " + user2);
                System.out.println("(API-1) - Владелец счета: " + user1);
                System.out.println("(API-1) - Идентификатор счета: " + accountId);
                System.out.println("(API-1) - URL запроса: " + fullUrl);
                System.out.println("(API-1) - Код ответа сервера: HTTP 200 (успешный доступ к чужому ресурсу)");
                System.out.println("(API-1) - Вывод: сервер не проверяет права доступа к объектам, что позволяет получить несанкционированный доступ к данным других пользователей");
            } else {
                System.out.println("(API-1) Защита работает корректно: сервер вернул код " + statusCode + " при попытке доступа к чужому ресурсу");
            }
        }

        System.out.println("(API-1) Сканирование BOLA завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private String getFirstAccountId(String baseUrl, String token, ApiClient apiClient) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("GET", baseUrl + ACCOUNTS_ENDPOINT, null, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                if (apiResponse.getStatusCode() == 200) {
                    Pattern pattern = Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\"");
                    Matcher matcher = pattern.matcher(apiResponse.getBody());
                    if (matcher.find()) {
                        return matcher.group(1);
                    }
                } else {
                    System.err.println("(API-1) Получен неожиданный статус при запросе счетов: " + apiResponse.getStatusCode());
                }
            }
        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при получении списка счетов: " + e.getMessage());
        }
        return null;
    }

    private HttpApiClient.ApiResponse tryAccessAccountAsOtherUser(String baseUrl, String accountId, String token, ApiClient apiClient) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Accept", "application/json");

            String url = baseUrl + String.format(ACCOUNT_DETAIL_ENDPOINT_TEMPLATE, accountId);
            Object response = apiClient.executeRequest("GET", url, null, headers);
            return (HttpApiClient.ApiResponse) response;
        } catch (Exception e) {
            System.err.println("(API-1) Ошибка при попытке доступа к чужому счёту: " + e.getMessage());
            return null;
        }
    }
}