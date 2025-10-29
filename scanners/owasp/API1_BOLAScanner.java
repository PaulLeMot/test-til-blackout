// scanners/owasp/API1_BOLAScanner.java
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
        System.out.println("🔍 Scanning for BOLA vulnerabilities...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl().trim(); // убираем пробелы
        String password = config.getPassword();

        if (password == null || password.isEmpty()) {
            System.err.println("⚠️ Пароль не задан в конфигурации. BOLA-сканер пропущен.");
            return vulnerabilities;
        }

        // 1. Получаем токены для двух пользователей
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

        // 2. Получаем список счетов от user1
        String accountId = getFirstAccountId(baseUrl, token1);
        if (accountId == null) {
            System.out.println("ℹ️ У пользователя team172-1 нет счетов — BOLA-тест невозможен.");
            return vulnerabilities;
        }

        System.out.println("✅ Найден счёт для team172-1: " + accountId);

        // 3. Пытаемся получить этот счёт от имени user2
        boolean isVulnerable = tryAccessAccountAsOtherUser(baseUrl, accountId, token2);

        if (isVulnerable) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("API1:2023 - Broken Object Level Authorization (BOLA)");
            vuln.setDescription(String.format(
                "Пользователь %s может получить данные счёта %s, принадлежащего %s.",
                user2, accountId, user1
            ));
            vuln.setSeverity(Vulnerability.Severity.HIGH);
            vuln.setEndpoint(String.format("/accounts/%s", accountId));
            String evidence = String.format(
                "{\"victimUser\":\"%s\",\"attackerUser\":\"%s\",\"accountId\":\"%s\",\"endpoint\":\"%s\"}",
                user1, user2, accountId, String.format("%s/accounts/%s", baseUrl, accountId)
            );
            vuln.setEvidence(evidence);

            vulnerabilities.add(vuln);
            System.out.println("🚨 BOLA УЯЗВИМОСТЬ ОБНАРУЖЕНА!");
        } else {
            System.out.println("✅ BOLA не обнаружена: доступ к чужому счёту запрещён.");
        }

        System.out.println("✅ BOLA scan completed. Found: " + vulnerabilities.size() + " vulnerabilities");
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
                // Ищем первый accountId в ответе
                Pattern pattern = Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\"");
                Matcher matcher = pattern.matcher(response.body());
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при получении списка счетов: " + e.getMessage());
        }
        return null;
    }

    private boolean tryAccessAccountAsOtherUser(String baseUrl, String accountId, String token) {
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

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Если сервер отдаёт данные чужого счёта — это BOLA
            return response.statusCode() == 200;

        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при попытке доступа к чужому счёту: " + e.getMessage());
            return false;
        }
    }
}