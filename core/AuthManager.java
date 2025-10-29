package core;

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
     * Получает access token через login endpoint (старый метод)
     */

    /**
     * Получает access token для хакатона через банковское API
     */
    public static String getBankHackathonToken(String bankBaseUrl, String clientId, String clientSecret) {
        System.out.println("🔐 Получение токена для хакатона: " + bankBaseUrl);
        
        try {
            // ПАРАМЕТРЫ В URL, а не в теле!
            String tokenUrl = bankBaseUrl + "/auth/bank-token?client_id=" + clientId + "&client_secret=" + clientSecret;
            
            System.out.println("🌐 Запрос к: " + tokenUrl);
            System.out.println("👤 Client ID: " + clientId);
                
            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
                
            // POST запрос БЕЗ тела (параметры в URL)
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUrl))
                .POST(HttpRequest.BodyPublishers.noBody())  // ← POST без тела
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(15))
                .build();
                
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            System.out.println("📡 Ответ от сервера: " + response.statusCode());
            
            if (response.statusCode() == 200) {
                String jsonResponse = response.body();
                System.out.println("✅ Успешная аутентификация!");
                
                // Парсим токен из ответа банковского API
                String accessToken = extractAccessToken(jsonResponse);
                if (accessToken != null) {
                    System.out.println("🎫 Токен получен, длина: " + accessToken.length() + " символов");
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
     * Получает access token для хакатона через банковское API
     */

    
    /**
     * Получает токен через OAuth2 endpoint (альтернативный метод)
     */
    public static String getOAuth2Token(String authUrl, String clientId, String clientSecret) {
        System.out.println("🔐 Получение OAuth2 токена: " + authUrl);
        
        try {
            String requestBody = String.format(
                "grant_type=client_credentials&client_id=%s&client_secret=%s",
                clientId, clientSecret
            );
            
            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
                
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(authUrl))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(15))
                .build();
                
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            System.out.println("📡 Ответ от сервера: " + response.statusCode());
            
            if (response.statusCode() == 200) {
                String jsonResponse = response.body();
                System.out.println("✅ Успешная аутентификация OAuth2!");
                
                String accessToken = extractAccessToken(jsonResponse);
                if (accessToken != null) {
                    System.out.println("🎫 OAuth2 токен получен");
                    return accessToken;
                }
            } else {
                System.out.println("❌ Ошибка OAuth2 аутентификации: " + response.statusCode());
                System.out.println("📄 Тело ответа: " + response.body());
            }
            
        } catch (Exception e) {
            System.err.println("💥 Ошибка при OAuth2 аутентификации: " + e.getMessage());
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
            
            // Для формата: {"access_token": "value"}
            if (cleanJson.contains("\"access_token\":")) {
                String[] parts = cleanJson.split("\"access_token\":");
                if (parts.length > 1) {
                    String valuePart = parts[1].split("[,\\}]")[0];
                    String token = valuePart.replaceAll("\"", "").trim();
                    if (!token.isEmpty()) {
                        return token;
                    }
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
     * Декодирует JWT токен (базовая информация)
     */
    public static void analyzeToken(String token) {
        if (token == null || !token.contains(".")) {
            System.out.println("❌ Невалидный JWT токен");
            return;
        }
        
        try {
            String[] parts = token.split("\\.");
            if (parts.length == 3) {
                // Декодируем header
                String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
                System.out.println("📋 JWT Header: " + header);
                
                // Декодируем payload
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                System.out.println("📄 JWT Payload: " + payload);
                
                // Анализируем expiration
                if (payload.contains("\"exp\"")) {
                    System.out.println("✅ Токен имеет expiration time");
                } else {
                    System.out.println("⚠ Токен БЕЗ expiration time!");
                }
            }
        } catch (Exception e) {
            System.out.println("❌ Ошибка при анализе токена: " + e.getMessage());
        }
    }
    
    /**
     * Тестовый метод для проверки аутентификации хакатона
     */
    public static void testHackathonAuthentication() {
        System.out.println("🧪 Тестирование аутентификации хакатона...");
        
        String bankUrl = "https://vbank.open.bankingapi.ru";
        String clientId = "team172-1";
        String clientSecret = "***REMOVED***";
        
        String token = getBankHackathonToken(bankUrl, clientId, clientSecret);
        
        if (token != null) {
            System.out.println("🎉 Тест пройден! Токен получен успешно.");
            analyzeToken(token);
        } else {
            System.out.println("💥 Тест не пройден! Не удалось получить токен.");
        }
    }
    
    /**
     * Тестовый метод для OAuth2 аутентификации
     */
    public static void testOAuth2Authentication() {
        System.out.println("🧪 Тестирование OAuth2 аутентификации...");
        
        String authUrl = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token";
        String clientId = "team172-1";
        String clientSecret = "***REMOVED***";
        
        String token = getOAuth2Token(authUrl, clientId, clientSecret);
        
        if (token != null) {
            System.out.println("🎉 OAuth2 тест пройден! Токен получен успешно.");
            analyzeToken(token);
        } else {
            System.out.println("💥 OAuth2 тест не пройден! Не удалось получить токен.");
        }
    }
}
