package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.AuthManager;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class API1_BOLAScanner implements SecurityScanner {

    private static final String ACCOUNTS_ENDPOINT = "/accounts";
    private static final String ACCOUNT_DETAIL_ENDPOINT = "/accounts/%s";

    public API1_BOLAScanner() {}

    @Override
    public String getName() {
        return "API1_BOLA";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("🔍 Scanning for BOLA vulnerabilities (OWASP API Security Top 10:2023 - API1)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl().trim();
        String password = config.getPassword();

        if (password == null || password.isEmpty()) {
            System.err.println("⚠️ Пароль не задан в конфигурации. BOLA-сканер пропущен.");
            return vulnerabilities;
        }

        Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(baseUrl, password);
        if (tokens.size() < 2) {
            System.err.println("⚠️ Недостаточно токенов для BOLA-теста (нужно минимум 2).");
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

        String accountId = getFirstAccountId(baseUrl, token1);
        if (accountId == null) {
            System.out.println("ℹ️ У пользователя " + user1 + " нет счетов — BOLA-тест невозможен.");
            return vulnerabilities;
        }

        System.out.println("✅ Найден счёт пользователя " + user1 + ": " + accountId);

        HttpResponse<String> response = tryAccessAccountAsOtherUserWithResponse(baseUrl, accountId, token2);

        if (response == null) {
            System.out.println("⚠️ Не удалось выполнить запрос к счёту " + accountId + " от имени " + user2);
        } else {
            int statusCode = response.statusCode();
            System.out.println("📡 Ответ при доступе к " + accountId + " от " + user2 + ": HTTP " + statusCode);

            boolean isVulnerable = (statusCode == 200);

            if (isVulnerable) {
                String endpoint = String.format("/accounts/%s", accountId);
                String fullUrl = baseUrl + endpoint;

                Vulnerability vuln = new Vulnerability();
                vuln.setTitle("API1:2023 - Broken Object Level Authorization (BOLA)");
                vuln.setDescription(
                        "Пользователь " + user2 + " получил HTTP " + statusCode +
                                " при запросе к счёту " + accountId + ", принадлежащему " + user1 + ".\n" +
                                "Сервер не проверил право доступа — это нарушение уровня авторизации объекта (BOLA)."
                );
                vuln.setSeverity(Vulnerability.Severity.HIGH);
                vuln.setEndpoint(endpoint);
                vuln.setStatusCode(statusCode);
                vuln.setEvidence(String.format(
                        "{\"victimUser\":\"%s\",\"attackerUser\":\"%s\",\"accountId\":\"%s\",\"url\":\"%s\",\"statusCode\":%d}",
                        user1, user2, accountId, fullUrl, statusCode
                ));

                vulnerabilities.add(vuln);
                System.out.println("🚨 BOLA УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА! Сервер вернул 200 для чужого ресурса.");
            } else {
                System.out.println("✅ Защита работает: сервер вернул " + statusCode + " (ожидаемо).");
            }
        }

        System.out.println("✅ BOLA scan completed. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private String getFirstAccountId(String baseUrl, String token) {
        try {
            String url = baseUrl + ACCOUNTS_ENDPOINT;
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                Pattern pattern = Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\"");
                Matcher matcher = pattern.matcher(response.body());
                if (matcher.find()) {
                    return matcher.group(1);
                }
            } else {
                System.err.println("⚠️ Получен неожиданный статус при запросе счетов: " + response.statusCode());
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при получении списка счетов: " + e.getMessage());
        }
        return null;
    }

    private HttpResponse<String> tryAccessAccountAsOtherUserWithResponse(String baseUrl, String accountId, String token) {
        try {
            String url = baseUrl + String.format(ACCOUNT_DETAIL_ENDPOINT, accountId);
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            return client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при попытке доступа к чужому счёту: " + e.getMessage());
            return null;
        }
    }
}