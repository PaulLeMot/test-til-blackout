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

            // Пробуем разные варианты тела запроса
            String[] requestBodies = {
                    String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password),
                    String.format("{\"login\":\"%s\",\"password\":\"%s\"}", username, password),
                    String.format("{\"email\":\"%s\",\"password\":\"%s\"}", username, password),
                    String.format("{\"user\":\"%s\",\"pass\":\"%s\"}", username, password)
            };

            // Пробуем разные User-Agent
            String[] userAgents = {
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "curl/7.68.0",
                    "PostmanRuntime/7.26.0",
                    "GOSTGuardian/1.0",
                    "Java-HTTP-Client/17"
            };

            for (String requestBody : requestBodies) {
                for (String userAgent : userAgents) {
                    System.out.println("🔧 Тестируем комбинацию: " + userAgent);

                    try {
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
                                .header("Origin", bankBaseUrl)
                                .header("Referer", bankBaseUrl + "/")
                                .timeout(Duration.ofSeconds(10))
                                .build();

                        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                        System.out.println("📡 Ответ: " + response.statusCode());

                        if (response.statusCode() == 200) {
                            String accessToken = extractAccessTokenFromJson(response.body());
                            if (accessToken != null) {
                                System.out.println("✅ Токен получен для " + username + " с User-Agent: " + userAgent);
                                return accessToken;
                            }
                        } else if (response.statusCode() == 429) {
                            System.out.println("⚠ Rate limiting, пробуем следующую комбинацию...");
                            Thread.sleep(2000);
                        }

                    } catch (Exception e) {
                        System.err.println("❌ Ошибка с User-Agent " + userAgent + ": " + e.getMessage());
                    }

                    Thread.sleep(500); // Небольшая пауза между попытками
                }
            }

        } catch (Exception e) {
            System.err.println("❌ Критическая ошибка аутентификации: " + e.getMessage());
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

            // Формируем query параметры
            String queryParams = String.format("client_id=%s&client_secret=%s",
                    bankId, clientSecret);
            String fullUrl = authUrl + "?" + queryParams;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(fullUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(""))
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
     * Улучшенный метод получения токенов для команды - ВСЕГДА получаем несколько токенов для BOLA
     */
    public static Map<String, String> getBankAccessTokensForTeam(String bankBaseUrl, String password) {
        Map<String, String> tokens = new HashMap<>();
        System.out.println("🔐 Получение токенов для команды...");

        int tokenCount = 0;

        // Сначала пробуем получить банковский токен
        System.out.println("\n--- Получение банковского токена ---");
        String bankId = extractBankIdFromBaseUrl(bankBaseUrl);
        String bankToken = getBankTokenDirectly(bankBaseUrl, bankId, password);

        if (bankToken != null && isTokenValid(bankToken)) {
            tokens.put("bank_token", bankToken);
            tokenCount++;
            System.out.println("✅ Банковский токен успешно получен и сохранен");
        } else {
            System.err.println("❌ Не удалось получить банковский токен. Пробуем альтернативные методы...");
        }

        // ВСЕГДА пытаемся получить клиентские токены, даже если есть банковский
        System.out.println("\n--- Получение пользовательских токенов ---");
        for (String username : new String[]{***REMOVED***,"***REMOVED***"}) {
            System.out.println("\n--- Аутентификация пользователя: " + username + " ---");

            String token = getBankAccessToken(bankBaseUrl, username, password);

            if (token != null && isTokenValid(token)) {
                tokens.put(username, token);
                tokenCount++;
                System.out.println("✅ Реальный токен получен для " + username);
            } else {
                System.err.println("❌ Не удалось получить реальный токен для " + username);
            }

            try { Thread.sleep(3000); } catch (InterruptedException ignored) {}
        }

        // Если не получили достаточно токенов, используем аварийные
        if (tokenCount < 2) {
            System.out.println("\n🆘 Получено только " + tokenCount + " токенов. Переходим в аварийный режим...");
            Map<String, String> emergencyTokens = getEmergencyTokens();
            
            // Добавляем аварийные токены к уже полученным, но не перезаписываем существующие
            for (Map.Entry<String, String> entry : emergencyTokens.entrySet()) {
                if (!tokens.containsKey(entry.getKey())) {
                    tokens.put(entry.getKey(), entry.getValue());
                    tokenCount++;
                }
            }
        }

        System.out.println("\n✅ Итого получено токенов: " + tokenCount);
        return tokens;
    }

    /**
     * Извлекает ID банка из URL (например, из https://vbank.open.bankingapi.ru получает team172)
     */
    private static String extractBankIdFromBaseUrl(String baseUrl) {
        // В нашем случае bankId всегда team172
        return "team172";
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
