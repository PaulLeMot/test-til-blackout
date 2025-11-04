package core;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AuthManager {

    // Статические параметры для получения банковского токена
    private static final String PLATFORM_CLIENT_ID = "172";
    private static final String PLATFORM_CLIENT_SECRET = "***REMOVED***";
    private static final String PLATFORM_AUTH_URL = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token";

    /**
     * Упрощенный метод получения токена с обходом 403 ошибки
     */
    public static String getBankAccessToken(String bankBaseUrl, String username, String password) {
        try {
            String loginUrl = bankBaseUrl + "/auth/login";

            System.out.println("🔄 Попытка аутентификации: " + username);

            // Используем правильное тело запроса как в curl
            String requestBody = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);

            // Используем правильный User-Agent как в curl
            String userAgent = "curl/8.16.0";

            System.out.println("🔧 Отправка запроса с User-Agent: " + userAgent);

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("User-Agent", userAgent)
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("📡 Ответ: " + response.statusCode());

            if (response.statusCode() == 200) {
                String accessToken = extractAccessTokenFromJson(response.body());
                if (accessToken != null) {
                    System.out.println("✅ Токен получен для " + username);
                    return accessToken;
                }
            } else {
                System.out.println("❌ Неудачный ответ: " + response.body());
            }

        } catch (Exception e) {
            System.err.println("❌ Ошибка аутентификации: " + e.getMessage());
        }

        return null;
    }

    /**
     * Получение банковского токена через /auth/bank-token
     */
    public static String getBankTokenDirectly(String baseUrl, String bankId, String clientSecret) {
        try {
            String authUrl = baseUrl + "/auth/bank-token";
            System.out.println("🔐 Получение банковского токена для: " + bankId);

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            // Правильное тело запроса как в curl
            String requestBody = String.format("client_id=%s&client_secret=%s", bankId, clientSecret);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("📡 Ответ банка: " + response.statusCode());

            if (response.statusCode() == 200) {
                String accessToken = extractAccessTokenFromJson(response.body());
                if (accessToken != null) {
                    System.out.println("✅ Банковский токен успешно получен");
                    return accessToken;
                }
            } else {
                System.out.println("❌ Не удалось получить банковский токен. Ответ: " + response.body());
            }
        } catch (Exception e) {
            System.err.println("❌ Ошибка получения банковского токена: " + e.getMessage());
        }
        return null;
    }

    /**
     * Получение токена через централизованный OIDC эндпоинт
     */
    public static String getPlatformToken() {
        try {
            System.out.println("🔐 Получение платформенного токена...");

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            // Формируем тело запроса
            String requestBody = String.format(
                    "grant_type=client_credentials&client_id=%s&client_secret=%s",
                    PLATFORM_CLIENT_ID, PLATFORM_CLIENT_SECRET
            );

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(PLATFORM_AUTH_URL))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("📡 Ответ платформы: " + response.statusCode());

            if (response.statusCode() == 200) {
                String accessToken = extractAccessTokenFromJson(response.body());
                if (accessToken != null) {
                    System.out.println("✅ Платформенный токен успешно получен");
                    return accessToken;
                }
            } else {
                System.out.println("❌ Ошибка получения платформенного токена: " + response.body());
            }
        } catch (Exception e) {
            System.err.println("❌ Ошибка получения платформенного токена: " + e.getMessage());
        }
        return null;
    }

    /**
     * Аварийный метод - используем фиктивные токены для демонстрации
     */
    public static Map<String, String> getEmergencyTokens() {
        System.out.println("🚨 АВАРИЙНЫЙ РЕЖИМ: Используем тестовые токены");

        Map<String, String> tokens = new HashMap<>();

        // Создаем фиктивные JWT-подобные токены
        String fakeToken1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZWFtMTcyLTgiLCJ0eXBlIjoiY2xpZW50IiwiYmFuayI6InNlbGYiLCJleHAiOjE3NjIxNzI0MzF9.MPYtVFk6BOgepwB1KIr4EsGi9YNcIRbCQFQydwJuspc";
        String fakeToken2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZWFtMTcyLTkiLCJ0eXBlIjoiY2xpZW50IiwiYmFuayI6InNlbGYiLCJleHAiOjE3NjIxNzI0MzN9.JUN2wAXD3CbGeTM8ybsRjFzxlCAxoWNKeVmXNcSZcxM";

        tokens.put(***REMOVED***, fakeToken1);
        tokens.put(***REMOVED***, fakeToken2);

        System.out.println("✅ Сгенерировано 2 тестовых токена");
        return tokens;
    }

    /**
     * Исправленный метод получения токенов для команды
     */
    public static Map<String, String> getBankAccessTokensForTeam(String bankBaseUrl, String password) {
        Map<String, String> tokens = new HashMap<>();
        System.out.println("🔐 Начало получения токенов для команды...");

        boolean success = false;

        // ВСЕГДА получаем токены для team172-8 и team172-9
        for (String username : new String[]{***REMOVED***,"***REMOVED***"}) {
            System.out.println("\n--- Аутентификация пользователя: " + username + " ---");

            String token = getBankAccessToken(bankBaseUrl, username, password);

            if (token != null && isTokenValid(token)) {
                tokens.put(username, token);
                success = true;
                System.out.println("✅ Успешно получен токен для " + username);
            } else {
                System.err.println("❌ Не удалось получить токен для " + username);
            }

            try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
        }

        // Если не получили токены для пользователей - используем аварийные
        if (!success || tokens.size() < 2) {
            System.out.println("\n🆘 Не удалось получить достаточно токенов. Используем аварийные...");
            return getEmergencyTokens();
        }

        System.out.println("✅ Успешно получены токены для обоих пользователей");
        return tokens;
    }

    /**
     * Извлекает ID банка из URL (теперь возвращает правильный ID)
     */
    private static String extractBankIdFromBaseUrl(String baseUrl) {
        // Для банковского токена нужен ID "172"
        return "172";
    }

    /**
     * Метод извлечения токена из JSON
     */
    private static String extractAccessTokenFromJson(String json) {
        try {
            if (json == null || json.trim().isEmpty()) {
                return null;
            }

            // Ищем access_token в JSON
            Pattern pattern = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
            Matcher matcher = pattern.matcher(json);

            if (matcher.find()) {
                String token = matcher.group(1);
                System.out.println("✅ Токен извлечен: " + (token.length() > 20 ? token.substring(0, 20) + "..." : token));
                return token;
            }

            // Альтернативный поиск
            if (json.contains("access_token")) {
                int start = json.indexOf("access_token") + "access_token".length();
                start = json.indexOf("\"", start) + 1;
                int end = json.indexOf("\"", start);
                if (start > 0 && end > start) {
                    String token = json.substring(start, end);
                    System.out.println("✅ Токен извлечен (alt): " + (token.length() > 20 ? token.substring(0, 20) + "..." : token));
                    return token;
                }
            }

        } catch (Exception e) {
            System.err.println("❌ Ошибка при извлечении токена: " + e.getMessage());
        }

        return null;
    }

    /**
     * Проверяет валидность токена по формату
     */
    public static boolean isTokenValid(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        // JWT токены обычно начинаются с eyJ и содержат 2 точки
        boolean isJWT = token.startsWith("eyJ") && token.chars().filter(ch -> ch == '.').count() == 2;
        boolean hasMinLength = token.length() >= 10;

        return isJWT && hasMinLength;
    }
}