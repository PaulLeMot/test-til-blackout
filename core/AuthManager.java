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
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("User-Agent", "GOSTGuardian/1.0")
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("Ответ: " + response.statusCode() + " - " + response.body());

            if (response.statusCode() == 200) {
                String accessToken = extractAccessTokenFromJson(response.body());
                if (accessToken != null) {
                    System.out.println("Токен получен для " + username);
                    return accessToken;
                } else {
                    System.err.println("Не удалось извлечь токен из ответа");
                }
            } else {
                System.err.println("Ошибка аутентификации: " + response.statusCode() + " - " + response.body());
            }

        } catch (Exception e) {
            System.err.println("Ошибка при аутентификации " + username + ": " + e.getMessage());
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Улучшенный метод извлечения токена из JSON
     */
    private static String extractAccessTokenFromJson(String json) {
        try {
            // Убираем пробелы и переносы для надежности
            String cleanJson = json.replaceAll("\\s+", "");

            System.out.println("Извлечение токена из: " + cleanJson);

            // Ищем "access_token":"значение"
            if (cleanJson.contains("\"access_token\":")) {
                int start = cleanJson.indexOf("\"access_token\":\"") + 16;
                int end = cleanJson.indexOf("\"", start);
                if (start > 15 && end > start) {
                    String token = cleanJson.substring(start, end);
                    System.out.println("Токен извлечен: " + token.substring(0, Math.min(20, token.length())) + "...");
                    return token;
                }
            }

            // Альтернативный формат
            if (cleanJson.contains("access_token")) {
                String[] parts = cleanJson.split("access_token");
                if (parts.length > 1) {
                    String tokenPart = parts[1];
                    if (tokenPart.startsWith("\":\"")) {
                        int start = 3;
                        int end = tokenPart.indexOf("\"", start);
                        if (end > start) {
                            String token = tokenPart.substring(start, end);
                            System.out.println("✅ Токен извлечен (alt): " + token.substring(0, Math.min(20, token.length())) + "...");
                            return token;
                        }
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("Ошибка при извлечении токена: " + e.getMessage());
        }
        return null;
    }

    /**
     * Получает токены для пользователей
     */
    public static Map<String, String> getBankAccessTokensForTeam(String bankBaseUrl, String password) {
        Map<String, String> tokens = new HashMap<>();
        System.out.println("Получение токенов для команды...");

        for (String username : new String[]{"team172-8", "team172-9"}) {
            System.out.println("\n--- Аутентификация пользователя: " + username + " ---");
            String token = getBankAccessToken(bankBaseUrl, username, password);
            if (token != null && isTokenValid(token)) {
                tokens.put(username, token);
                System.out.println("Токен получен для " + username);
            } else {
                System.err.println("Не удалось получить токен для " + username);
            }

            // Пауза между запросами
            try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
        }

        return tokens;
    }

    /**
     * Получает токены для конкретных пользователей
     */
    public static Map<String, String> getSpecificUserTokens(String bankBaseUrl, String password, String[] usernames) {
        Map<String, String> tokens = new HashMap<>();
        System.out.println("Получение токенов для указанных пользователей...");

        for (String username : usernames) {
            System.out.println("\n--- Аутентификация пользователя: " + username + " ---");
            String token = getBankAccessToken(bankBaseUrl, username, password);
            if (token != null && isTokenValid(token)) {
                tokens.put(username, token);
                System.out.println("Токен получен для " + username);
            } else {
                System.err.println("Не удалось получить токен для " + username);
            }

            // Пауза между запросами
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
            System.err.println("Токен не в JWT формате: " + token.substring(0, Math.min(20, token.length())) + "...");
        }

        return isJWT && hasMinLength;
    }

    /**
     * Тестовый метод для проверки аутентификации
     */
    public static void testAuthentication() {
        String bankUrl = "https://vbank.open.bankingapi.ru";
        String password = "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";

        System.out.println("Тестирование аутентификации...");
        Map<String, String> tokens = getBankAccessTokensForTeam(bankUrl, password);

        if (!tokens.isEmpty()) {
            System.out.println("\nТокены успешно получены:");
            tokens.forEach((user, token) -> {
                String tokenPreview = token.length() > 20 ? token.substring(0, 20) + "..." : token;
                System.out.println(user + ": " + tokenPreview);
            });
        } else {
            System.out.println("\nНе удалось получить ни одного токена.");
        }
    }
}