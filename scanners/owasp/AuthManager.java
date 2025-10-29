package scanners.owasp;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;

/**
 * Менеджер аутентификации для получения токенов у банковского API
 */
public class AuthManager {
    
    /**
     * Получает access token через login endpoint
     */
    public static String getBankAccessToken(String bankBaseUrl, String username, String password) {
        System.out.println("🔐 Получение токена через login: " + bankBaseUrl);
        
        try {
            String loginUrl = bankBaseUrl + "/auth/login";
            
            // JSON тело запроса
            String requestBody = String.format(
                "{\"username\":\"%s\",\"password\":\"%s\"}",
                username, password
            );
            
            System.out.println("🌐 Запрос к: " + loginUrl);
            System.out.println("👤 Username: " + username);
                
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
            
            System.out.println("📡 Ответ от сервера: " + response.statusCode());
            
            if (response.statusCode() == 200) {
                String jsonResponse = response.body();
                System.out.println("✅ Успешная аутентификация!");
                
                // Парсим токен из ответа
                String accessToken = extractAccessToken(jsonResponse);
                if (accessToken != null) {
                    System.out.println("🎫 Токен получен, длина: " + accessToken.length() + " символов");
                    System.out.println("🔍 Первые 20 символов токена: " + accessToken.substring(0, Math.min(20, accessToken.length())) + "...");
                    return accessToken;
                } else {
                    System.out.println("❌ Не удалось извлечь токен из ответа");
                    System.out.println("📄 Полный ответ: " + jsonResponse);
                }
            } else {
                System.out.println("❌ Ошибка аутентификации: " + response.statusCode());
                System.out.println("📄 Тело ответа: " + response.body());
            }
            
        } catch (Exception e) {
            System.err.println("💥 Ошибка при аутентификации: " + e.getMessage());
            e.printStackTrace();
        }
        
        return null;
    }
    
    /**
     * Извлекает access_token из JSON ответа
     * Ожидаемый формат: {"access_token":"eyJ...", ...}
     */
    private static String extractAccessToken(String json) {
        try {
            // Убираем пробелы для упрощения парсинга
            String cleanJson = json.replaceAll("\\s+", "");
            
            // Ищем "access_token":"значение"
            if (cleanJson.contains("\"access_token\":")) {
                String[] parts = cleanJson.split("\"access_token\":\"");
                if (parts.length > 1) {
                    String tokenPart = parts[1];
                    String token = tokenPart.split("\"")[0];
                    return token;
                }
            }
            
            // Альтернативный вариант: может быть в другом поле
            if (cleanJson.contains("\"token\":")) {
                String[] parts = cleanJson.split("\"token\":\"");
                if (parts.length > 1) {
                    String tokenPart = parts[1];
                    String token = tokenPart.split("\"")[0];
                    return token;
                }
            }
            
        } catch (Exception e) {
            System.err.println("Ошибка при парсинге токена: " + e.getMessage());
        }
        
        System.out.println("🔍 Не найден access_token в ответе. Структура JSON: " + json);
        return null;
    }
    
    /**
     * Проверяет валидность JWT токена (базовая проверка)
     */
    public static boolean isTokenValid(String token) {
        if (token == null || token.length() < 10) {
            return false;
        }
        
        // JWT токены обычно начинаются с eyJ (закодированный JSON)
        boolean isJwt = token.startsWith("eyJ");
        
        // Или может быть в другом формате
        boolean looksValid = token.length() > 20 && token.contains(".");
        
        return isJwt || looksValid;
    }
    
    /**
     * Тестовый метод для проверки аутентификации
     */
    public static void testAuthentication() {
        System.out.println("🧪 Тестирование аутентификации...");
        
        String bankUrl = "https://vbank.open.bankingapi.ru";
        String username = "team172-1";
        String password = "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";
        
        String token = getBankAccessToken(bankUrl, username, password);
        
        if (token != null) {
            System.out.println("🎉 Тест пройден! Токен получен успешно.");
        } else {
            System.out.println("💥 Тест не пройден! Не удалось получить токен.");
        }
    }
}
