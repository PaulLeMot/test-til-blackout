// core/AuthManager.java
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
     * Получает access token через login endpoint
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
            }
            
        } catch (Exception e) {
            System.err.println("💥 Ошибка при аутентификации: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Извлекает access_token из JSON ответа
     * Ожидаемый формат: {"access_token":"eyJ...", ...}
     */
    private static String extractAccessToken(String json) {
        try {
            String cleanJson = json.replaceAll("\\s+", "");
            
            if (cleanJson.contains("\"access_token\":")) {
                String[] parts = cleanJson.split("\"access_token\":\"");
                if (parts.length > 1) {
                    return parts[1].split("\"")[0];
                }
            }
            
            if (cleanJson.contains("\"token\":")) {
                String[] parts = cleanJson.split("\"token\":\"");
                if (parts.length > 1) {
                    return parts[1].split("\"")[0];
                }
            }
            
        } catch (Exception ignored) {
        }
        return null;
    }
    
    /**
     * Проверяет валидность JWT токена (базовая проверка)
     */
    public static boolean isTokenValid(String token) {
        if (token == null || token.length() < 10) {
            return false;
        }
        return token.startsWith("eyJ") || (token.length() > 20 && token.contains("."));
    }
    
    /**
     * Получает токены для обоих пользователей команды: team172-1 и team172-2
     * @param bankBaseUrl базовый URL банковского API
     * @param password общий пароль для обоих аккаунтов
     * @return карта вида {username -> accessToken}
     */
    public static Map<String, String> getBankAccessTokensForTeam(String bankBaseUrl, String password) {
        Map<String, String> tokens = new HashMap<>();
        for (String username : new String[]{"team172-1", "team172-2"}) {
            String token = getBankAccessToken(bankBaseUrl, username, password);
            if (token != null) {
                tokens.put(username, token);
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
        
        Map<String, String> tokens = getBankAccessTokensForTeam(bankUrl, password);
        
        if (!tokens.isEmpty()) {
            System.out.println("🎉 Токены получены:");
            tokens.forEach((user, token) -> 
                System.out.println("  👤 " + user + ": " + token.substring(0, Math.min(20, token.length())) + "..."));
        } else {
            System.out.println("💥 Не удалось получить ни одного токена.");
        }
    }
}