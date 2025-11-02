package core;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class AuthManager {

    /**
     * Получает банковский токен через login endpoint
     */
    public static String getBankAccessToken(String bankBaseUrl, String username, String password) {
        try {
            String loginUrl = bankBaseUrl + "/auth/login";

            System.out.println("Аутентификация: " + username + " на " + loginUrl);

            // Формируем JSON как в curl
            String requestBody = String.format(
                    "{\"username\":\"%s\",\"password\":\"%s\"}",
                    username, password
            );

            System.out.println("Тело запроса: " + requestBody);

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_2)  // HTTP/2
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("User-Agent", "curl/7.68.0")  // Используем тот же User-Agent что и curl
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("Ответ: " + response.statusCode() + " - " + response.body());

            if (response.statusCode() == 200) {
                String accessToken = extractAccessTokenFromJson(response.body());
                if (accessToken != null) {
                    System.out.println("✅ Токен получен для " + username);
                    return accessToken;
                } else {
                    System.err.println("❌ Не удалось извлечь токен из ответа");
                }
            } else {
                System.err.println("❌ Ошибка аутентификации: " + response.statusCode() + " - " + response.body());
                // Дополнительная диагностика для 403 ошибки
                if (response.statusCode() == 403) {
                    System.err.println("⚠️  Возможные причины 403:");
                    System.err.println("   - Неправильный User-Agent");
                    System.err.println("   - Блокировка по IP");
                    System.err.println("   - Требуется дополнительная аутентификация");
                }
            }

        } catch (Exception e) {
            System.err.println("❌ Ошибка при аутентификации " + username + ": " + e.getMessage());
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Альтернативный метод с более простым подходом
     */
    public static String getBankAccessTokenSimple(String bankBaseUrl, String username, String password) {
        try {
            String loginUrl = bankBaseUrl + "/auth/login";
            String requestBody = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);

            // Минималистичный подход - только необходимые заголовки
            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_2)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    // Специально НЕ устанавливаем User-Agent
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("Простой метод - Ответ: " + response.statusCode());

            if (response.statusCode() == 200) {
                return extractAccessTokenFromJson(response.body());
            }

        } catch (Exception e) {
            System.err.println("Ошибка в простом методе: " + e.getMessage());
        }

        return null;
    }

    /**
     * Улучшенный метод извлечения токена из JSON
     */
    private static String extractAccessTokenFromJson(String json) {
        try {
            if (json == null || json.trim().isEmpty()) {
                return null;
            }

            // Пробуем несколько способов извлечения
            String[] patterns = {
                    "\"access_token\"\\s*:\\s*\"([^\"]+)\"",
                    "'access_token'\\s*:\\s*'([^']+)'",
                    "access_token\"\\s*:\\s*\"([^\"]+)\""
            };

            for (String pattern : patterns) {
                java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
                java.util.regex.Matcher m = p.matcher(json);
                if (m.find()) {
                    String token = m.group(1);
                    System.out.println("✅ Токен извлечен: " + (token.length() > 20 ? token.substring(0, 20) + "..." : token));
                    return token;
                }
            }

            // Если регулярки не сработали, попробуем простой поиск
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

        System.err.println("❌ Не удалось извлечь токен из: " + json);
        return null;
    }

    /**
     * Получает токены для пользователей с fallback методами
     */
    public static Map<String, String> getBankAccessTokensForTeam(String bankBaseUrl, String password) {
        Map<String, String> tokens = new HashMap<>();
        System.out.println("Получение токенов для команды...");

        for (String username : new String[]{***REMOVED***,"***REMOVED***"}) {
            System.out.println("\n--- Аутентификация пользователя: " + username + " ---");

            // Пробуем основной метод
            String token = getBankAccessToken(bankBaseUrl, username, password);

            // Если не получилось, пробуем простой метод
            if (token == null) {
                System.out.println("Пробуем альтернативный метод...");
                token = getBankAccessTokenSimple(bankBaseUrl, username, password);
            }

            if (token != null && isTokenValid(token)) {
                tokens.put(username, token);
                System.out.println("✅ Токен получен для " + username);
            } else {
                System.err.println("❌ Не удалось получить токен для " + username);
            }

            // Увеличиваем паузу между запросами
            try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
        }

        return tokens;
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

        if (!isJWT) {
            System.err.println("⚠️ Токен не в JWT формате: " + (token.length() > 20 ? token.substring(0, 20) + "..." : token));
        }

        return isJWT && hasMinLength;
    }
}