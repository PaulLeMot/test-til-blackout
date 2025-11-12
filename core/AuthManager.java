package core;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;
import org.json.JSONArray;

public class AuthManager {
    private static final Logger logger = Logger.getLogger(AuthManager.class.getName());

    /**
     * Получение токена для команды через /auth/login
     */
    public static String getTeamToken(String baseUrl, String username, String password) {
        try {
            String loginUrl = baseUrl + "/auth/login";
            logger.info("🔄 Аутентификация в sandbox: " + username);

            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("username", username);
            requestBody.put("password", password);

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String jsonBody = new org.json.JSONObject(requestBody).toString();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("📡 Ответ аутентификации: " + response.statusCode());

            if (response.statusCode() == 200) {
                String accessToken = extractAccessTokenFromJson(response.body());
                if (accessToken != null && isTokenValid(accessToken)) {
                    logger.info("✅ Токен успешно получен для " + username);
                    return accessToken;
                }
            } else {
                logger.warning("❌ Ошибка аутентификации: " + response.body());
            }
        } catch (Exception e) {
            logger.severe("❌ Критическая ошибка при аутентификации: " + e.getMessage());
        }
        return null;
    }

    /**
     * Получение bank token для межбанковских запросов (обновленная версия)
     */
    public static String getBankToken(String baseUrl, String teamToken, String bankId, String clientSecret) {
        try {
            // Формируем URL с query параметрами как в curl
            String authUrl = baseUrl + "/auth/bank-token?client_id=" + bankId +
                    "&client_secret=" + clientSecret +
                    "&grant_type=client_credentials";

            logger.info("🔐 Получение bank token для: " + bankId);
            logger.info("📤 URL: " + authUrl);

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            // Используем BodyPublishers.noBody() как в curl
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl))
                    .POST(HttpRequest.BodyPublishers.noBody()) // Важно: без тела как в curl
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + teamToken)
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("📡 Ответ bank token: " + response.statusCode());

            if (response.statusCode() == 200) {
                String bankToken = extractAccessTokenFromJson(response.body());
                if (bankToken != null && isTokenValid(bankToken)) {
                    logger.info("✅ Bank token успешно получен");
                    return bankToken;
                } else {
                    logger.warning("⚠️ Bank token получен, но невалиден");
                }
            } else {
                logger.warning("❌ Ошибка получения bank token. Status: " + response.statusCode());
                logger.warning("❌ Response body: " + response.body());
            }
        } catch (Exception e) {
            logger.severe("❌ Ошибка получения bank token: " + e.getMessage());
        }
        return null;
    }

    /**
     * Альтернативный метод получения bank token без team token (как в curl)
     */
    public static String getBankTokenDirect(String baseUrl, String bankId, String clientSecret) {
        try {
            // Формируем URL с query параметрами как в curl
            String authUrl = baseUrl + "/auth/bank-token?client_id=" + bankId +
                    "&client_secret=" + clientSecret +
                    "&grant_type=client_credentials";

            logger.info("🔐 Прямое получение bank token для: " + bankId);
            logger.info("📤 URL: " + authUrl);

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            // Используем BodyPublishers.noBody() как в curl
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("📡 Ответ bank token: " + response.statusCode());

            if (response.statusCode() == 200) {
                String bankToken = extractAccessTokenFromJson(response.body());
                if (bankToken != null && isTokenValid(bankToken)) {
                    logger.info("✅ Bank token успешно получен напрямую");
                    return bankToken;
                } else {
                    logger.warning("⚠️ Bank token получен, но невалиден");
                }
            } else {
                logger.warning("❌ Ошибка получения bank token. Status: " + response.statusCode());
                logger.warning("❌ Response body: " + response.body());
            }
        } catch (Exception e) {
            logger.severe("❌ Ошибка получения bank token напрямую: " + e.getMessage());
        }
        return null;
    }

    /**
     * Создание согласия (consent) для межбанковских запросов
     */
    public static String createConsent(String baseUrl, String bankToken, String bankId, String clientId) {
        try {
            String consentUrl = baseUrl + "/account-consents/request?client_id=" + bankId;
            logger.info("📋 Создание согласия для bankId: " + bankId);

            // Тело запроса для согласия
            Map<String, Object> consentBody = new HashMap<>();
            consentBody.put("client_id", clientId);
            consentBody.put("permissions", new String[]{"ReadAccountsDetail", "ReadBalances"});
            consentBody.put("reason", "Security testing for hackathon");
            consentBody.put("requesting_bank", bankId);
            consentBody.put("requesting_bank_name", "Hackathon Scanner");

            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String jsonBody = new org.json.JSONObject(consentBody).toString();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(consentUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + bankToken)
                    .header("X-Requesting-Bank", bankId)
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("📡 Ответ согласия: " + response.statusCode());

            if (response.statusCode() == 200 || response.statusCode() == 201) {
                JSONObject jsonResponse = new JSONObject(response.body());
                if (jsonResponse.has("consent_id")) {
                    String consentId = jsonResponse.getString("consent_id");
                    logger.info("✅ Consent ID успешно получен: " + consentId);
                    return consentId;
                }

                if (jsonResponse.has("data")) {
                    JSONObject data = jsonResponse.getJSONObject("data");
                    if (data.has("consentId")) {
                        String consentId = data.getString("consentId");
                        logger.info("✅ Consent ID из data.consentId: " + consentId);
                        return consentId;
                    }
                    if (data.has("consent_id")) {
                        String consentId = data.getString("consent_id");
                        logger.info("✅ Consent ID из data.consent_id: " + consentId);
                        return consentId;
                    }
                }
            } else {
                logger.warning("❌ Ошибка создания согласия: " + response.body());
            }
        } catch (Exception e) {
            logger.severe("❌ Ошибка создания согласия: " + e.getMessage());
        }
        return null;
    }

    /**
     * Основной метод получения всех необходимых токенов для сканирования
     */
    public static Map<String, String> getTokensForScanning(ScanConfig config) {
        Map<String, String> tokens = new HashMap<>();
        String baseUrl = config.getBankBaseUrl();
        String password = config.getClientSecret();
        String clientId = config.getClientId();
        String bankId = config.getBankId();

        logger.info("🎯 Начало получения токенов для сканирования");
        logger.info("🏦 Bank Base URL: " + baseUrl);
        logger.info("🆔 Bank ID: " + bankId);
        logger.info("👤 Client ID: " + clientId);

        // 1. Получаем токен команды через /auth/login
        logger.info("\n--- Шаг 1: Получение токена команды ---");
        String teamToken = getTeamToken(baseUrl, clientId, password);
        if (teamToken != null) {
            tokens.put("default", teamToken);
            tokens.put(clientId, teamToken);
            logger.info("✅ Токен команды сохранен");
        } else {
            logger.severe("❌ Не удалось получить токен команды. Проверьте учетные данные.");
            return tokens;
        }

        // 2. Получаем bank token для межбанковских запросов (обновленный метод)
        logger.info("\n--- Шаг 2: Получение bank token ---");
        String bankToken = getBankToken(baseUrl, teamToken, bankId, password);

        // Если не удалось получить bank token с team token, пробуем напрямую
        if (bankToken == null) {
            logger.info("🔄 Попытка прямого получения bank token...");
            bankToken = getBankTokenDirect(baseUrl, bankId, password);
        }

        if (bankToken != null) {
            tokens.put("bank", bankToken);
            tokens.put(bankId, bankToken);
            logger.info("✅ Bank token сохранен");
        } else {
            logger.warning("❌ Не удалось получить bank token. Продолжаем без него.");
        }

        // 3. Создаем согласие для межбанковских запросов
        if (bankToken != null) {
            logger.info("\n--- Шаг 3: Создание согласия ---");
            String consentId = createConsent(baseUrl, bankToken, bankId, clientId);
            if (consentId != null) {
                config.setConsentId(consentId);
                logger.info("✅ Consent ID сохранен в конфигурацию");
            } else {
                logger.warning("❌ Не удалось создать согласие. Некоторые сканы могут не работать.");
            }
        }

        // 4. Дополнительные токены для BOLA тестирования
        logger.info("\n--- Шаг 4: Получение дополнительных токенов ---");
        for (int i = 8; i <= 9; i++) {
            String altUsername = "team172-" + i;
            if (!altUsername.equals(clientId)) {
                try {
                    logger.info("🔄 Попытка получить токен для: " + altUsername);
                    String altToken = getTeamToken(baseUrl, altUsername, password);
                    if (altToken != null) {
                        tokens.put(altUsername, altToken);
                        logger.info("✅ Токен получен для: " + altUsername);
                    }
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        logger.info("\n✅ Всего получено токенов: " + tokens.size());
        for (String key : tokens.keySet()) {
            String token = tokens.get(key);
            logger.info("🔑 " + key + ": " + (token != null ? token.substring(0, 20) + "..." : "null"));
        }

        return tokens;
    }

    /**
     * Извлечение access_token из JSON ответа
     */
    private static String extractAccessTokenFromJson(String json) {
        try {
            if (json == null || json.trim().isEmpty()) {
                return null;
            }

            JSONObject jsonObject = new JSONObject(json);
            if (jsonObject.has("access_token")) {
                return jsonObject.getString("access_token");
            }

            if (jsonObject.has("token")) {
                return jsonObject.getString("token");
            }
            if (jsonObject.has("data") && new JSONObject(jsonObject.getString("data")).has("access_token")) {
                return new JSONObject(jsonObject.getString("data")).getString("access_token");
            }

            Pattern pattern = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
            Matcher matcher = pattern.matcher(json);
            if (matcher.find()) {
                return matcher.group(1);
            }

        } catch (Exception e) {
            logger.warning("⚠️ Ошибка при извлечении токена из JSON: " + e.getMessage());
            logger.fine("⚠️ Оригинальный ответ: " + json);
        }
        return null;
    }

    /**
     * Проверка валидности токена
     */
    public static boolean isTokenValid(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        // Проверяем JWT формат (начинается с eyJ и содержит 2 точки)
        boolean isJWT = token.startsWith("eyJ") && token.chars().filter(ch -> ch == '.').count() >= 2;
        boolean hasMinLength = token.length() >= 30;

        return isJWT && hasMinLength;
    }
}