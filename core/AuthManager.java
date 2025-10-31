package core;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Менеджер аутентификации для получения токенов у банковского API
 */
public class AuthManager {

    /**
     * Получает банковский токен для хакатона
     */
    public static String getBankHackathonToken(String bankBaseUrl, String clientId, String clientSecret) {
        try {
            String tokenUrl = bankBaseUrl + "/auth/bank-token";

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            // Формируем form-data запрос
            String formData = "client_id=" + clientId + "&client_secret=" + clientSecret;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(formData))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String accessToken = extractAccessToken(response.body());
                if (accessToken != null) {
                    return accessToken;
                }
            } else {
                System.err.println("Ошибка получения банковского токена: " + response.statusCode() + " - " + response.body());
            }

        } catch (Exception e) {
            System.err.println("Ошибка при получении банковского токена: " + e.getMessage());
        }

        return null;
    }

    /**
     * access token через login endpoint
     */
    public static String getBankAccessToken(String bankBaseUrl, String username, String password) {
        try {
            String loginUrl = bankBaseUrl + "/auth/login";

            String requestBody = String.format(
                    "{\"username\":\"%s\",\"password\":\"%s\"}",
                    username, password
            );

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String accessToken = extractAccessToken(response.body());
                if (accessToken != null) {
                    return accessToken;
                }
            } else {
                System.err.println("Ошибка аутентификации: " + response.statusCode() + " - " + response.body());
            }

        } catch (Exception e) {
            System.err.println("Ошибка при аутентификации: " + e.getMessage());
        }

        return null;
    }

    /**
     * Извлекает access_token из JSON ответа
     * Ожидаемый формат: {"access_token":"eyJ...", ...}
     */
    private static String extractAccessToken(String json) {
        try {
            // Пробуем парсить как JSON для надежности
            if (json.contains("\"access_token\"")) {
                String[] parts = json.split("\"access_token\"\\s*:\\s*\"");
                if (parts.length > 1) {
                    return parts[1].split("\"")[0];
                }
            }

            if (json.contains("\"token\"")) {
                String[] parts = json.split("\"token\"\\s*:\\s*\"");
                if (parts.length > 1) {
                    return parts[1].split("\"")[0];
                }
            }

            // Дополнительные форматы ответа
            if (json.contains("access_token")) {
                String[] parts = json.split("access_token\"?\\s*:\\s*\"?");
                if (parts.length > 1) {
                    String token = parts[1].split("[\",}]")[0];
                    if (token.length() > 10) {
                        return token;
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("Ошибка при извлечении токена: " + e.getMessage());
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
        // Или просто проверяем минимальную длину
        boolean hasMinLength = token.length() >= 10;

        return isJWT || hasMinLength;
    }

    /**
     * Получает токены для обоих пользователей команды: team172-1 и team172-2
     * @param bankBaseUrl базовый URL банковского API
     * @param password общий пароль для обоих аккаунтов
     * @return карта вида {username -> accessToken}
     */
    public static Map<String, String> getBankAccessTokensForTeam(String bankBaseUrl, String password) {
        Map<String, String> tokens = new HashMap<>();
        System.out.println("Получение токенов для команды...");

        for (String username : new String[]{"team172-1", "team172-2"}) {
            System.out.println("   Аутентификация пользователя: " + username);
            String token = getBankAccessToken(bankBaseUrl, username, password);
            if (token != null && isTokenValid(token)) {
                tokens.put(username, token);
                System.out.println("   Токен получен для " + username);
            } else {
                System.err.println("   Не удалось получить токен для " + username);
            }
        }

        return tokens;
    }

    /**
     * Тестовый метод для проверки аутентификации
     */
    public static void testAuthentication() {
        String bankUrl = "https://vbank.open.bankingapi.ru";
        String password = "***REMOVED***";

        System.out.println("Тестирование аутентификации...");
        Map<String, String> tokens = getBankAccessTokensForTeam(bankUrl, password);

        if (!tokens.isEmpty()) {
            System.out.println("Токены успешно получены:");
            tokens.forEach((user, token) -> {
                String tokenPreview = token.length() > 20 ? token.substring(0, 20) + "..." : token;
                System.out.println("   " + user + ": " + tokenPreview);
            });
        } else {
            System.out.println("Не удалось получить ни одного токена.");
            System.out.println("Проверьте:");
            System.out.println("   • Доступность банковского API");
            System.out.println("   • Правильность логина и пароля");
            System.out.println("   • Сетевые настройки");
        }
    }

    /**
     * Получает токен для конкретного пользователя с валидацией
     */
    public static String getValidatedToken(String bankBaseUrl, String username, String password) {
        String token = getBankAccessToken(bankBaseUrl, username, password);
        if (token != null && isTokenValid(token)) {
            return token;
        }
        return null;
    }
}
