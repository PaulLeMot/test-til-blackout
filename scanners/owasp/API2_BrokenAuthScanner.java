package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import core.AuthManager;
import java.util.*;

public class API2_BrokenAuthScanner implements SecurityScanner {

    // Кэш для токенов в рамках одного сканирования
    private Map<String, String> tokenCache = new HashMap<>();
    private String cachedValidToken = null;
    private long lastRequestTime = 0;
    private final long MIN_REQUEST_INTERVAL = 1000; // 1 секунда между запросами

    public API2_BrokenAuthScanner() {}

    @Override
    public String getName() {
        return "API2_BrokenAuth";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-2) Запуск сканирования на уязвимости Broken Authentication (OWASP API Security Top 10:2023 - API2)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Предварительно получаем токены один раз
        preloadTokens(config);

        testUnauthorizedAccess(config, apiClient, vulnerabilities);
        testInvalidTokens(config, apiClient, vulnerabilities);
        testAuthHeaders(config, apiClient, vulnerabilities);
        testSensitiveEndpoints(config, apiClient, vulnerabilities);
        testWithValidToken(config, apiClient, vulnerabilities);
        testBruteforceProtection(config, apiClient, vulnerabilities);
        testRateLimiting(config, apiClient, vulnerabilities);
        testTokenSecurity(config, apiClient, vulnerabilities);
        testJWTWeaknesses(config, vulnerabilities);

        System.out.println("(API-2) Сканирование Broken Authentication завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private void preloadTokens(ScanConfig config) {
        System.out.println("(API-2) Предварительная загрузка токенов...");
        Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(
                config.getTargetBaseUrl(),
                config.getPassword()
        );

        tokenCache.putAll(tokens);

        // Сохраняем первый валидный токен
        for (String token : tokens.values()) {
            if (token != null && AuthManager.isTokenValid(token)) {
                cachedValidToken = token;
                break;
            }
        }

        if (cachedValidToken != null) {
            System.out.println("(API-2) Токены успешно загружены, найдено: " + tokens.size());
        } else {
            System.out.println("(API-2) Предупреждение: не удалось загрузить валидные токены");
        }
    }

    /**
     * Умная задержка между запросами для избежания 429 ошибок
     */
    private void smartDelay() {
        long currentTime = System.currentTimeMillis();
        long timeSinceLastRequest = currentTime - lastRequestTime;

        if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
            long delayNeeded = MIN_REQUEST_INTERVAL - timeSinceLastRequest;
            try {
                Thread.sleep(delayNeeded);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        lastRequestTime = System.currentTimeMillis();
    }

    /**
     * Выполняет запрос с интеллектуальной задержкой
     */
    private Object executeRequestWithDelay(ApiClient apiClient, String method, String url, String body, Map<String, String> headers) {
        smartDelay();
        return apiClient.executeRequest(method, url, body, headers);
    }

    private void testUnauthorizedAccess(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование несанкционированного доступа к защищенным endpoint...");

        String[] protectedEndpoints = {
                "/",
                "/health",
                "/api/version",
                "/admin",
                "/config",
                "/docs",
                "/swagger"
        };

        for (String endpoint : protectedEndpoints) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;

            try {
                Map<String, String> noAuthHeaders = new HashMap<>();
                noAuthHeaders.put("Content-Type", "application/json");
                noAuthHeaders.put("Accept", "application/json");

                Object responseObj = executeRequestWithDelay(apiClient, "GET", fullUrl, null, noAuthHeaders);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (isSuccessResponse(response) && !endpoint.equals("/") && !endpoint.equals("/health")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Unauthorized Access to Protected Endpoint");
                    vuln.setDescription("Endpoint " + endpoint + " is accessible without authentication");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint(endpoint);
                    vuln.setMethod("GET");
                    vuln.setEvidence("Status " + response.getStatus() + " without Authorization header");
                    vuln.setRecommendations(Arrays.asList(
                            "Implement proper authentication checks",
                            "Require valid JWT tokens for all protected endpoints",
                            "Return 401 Unauthorized for unauthenticated requests"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Endpoint " + endpoint + " доступен без аутентификации");
                } else {
                    System.out.println("(API-2) Endpoint " + endpoint + " корректно защищен (статус: " + response.getStatus() + ")");
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private void testInvalidTokens(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование с невалидными/просроченными токенами...");

        String[] invalidTokens = {
                "invalid_token_123",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "Bearer invalid",
                "null",
                ""
        };

        String testEndpoint = config.getTargetBaseUrl() + "/health";

        for (String token : invalidTokens) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                if (token != null && !token.isEmpty() && !token.equals("null")) {
                    headers.put("Authorization", "Bearer " + token);
                }

                Object responseObj = executeRequestWithDelay(apiClient, "GET", testEndpoint, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (isSuccessResponse(response)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Accepts Invalid JWT Token");
                    vuln.setDescription("API accepts invalid/expired JWT tokens");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/health");
                    vuln.setMethod("GET");
                    vuln.setEvidence("Accepted invalid token and returned status " + response.getStatus());
                    vuln.setRecommendations(Arrays.asList(
                            "Validate JWT signature and expiration",
                            "Reject tokens with invalid format",
                            "Implement proper token validation middleware"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: API принимает невалидный JWT токен");
                    break;
                } else {
                    System.out.println("(API-2) Невалидный токен корректно отклонен: " + response.getStatus());
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования невалидного токена: " + e.getMessage());
            }
        }
    }

    private void testAuthHeaders(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование различных заголовков аутентификации...");

        String testEndpoint = config.getTargetBaseUrl() + "/health";

        if (cachedValidToken == null) {
            System.out.println("(API-2) Нет валидного токена для тестирования заголовков аутентификации");
            return;
        }

        Map<String, String> authHeaderTests = new HashMap<>();
        authHeaderTests.put("Authorization", "Bearer " + cachedValidToken);
        authHeaderTests.put("authorization", "Bearer " + cachedValidToken);
        authHeaderTests.put("AUTHORIZATION", "Bearer " + cachedValidToken);
        authHeaderTests.put("X-API-Key", cachedValidToken);
        authHeaderTests.put("Token", cachedValidToken);
        authHeaderTests.put("X-Auth-Token", cachedValidToken);

        for (Map.Entry<String, String> test : authHeaderTests.entrySet()) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                headers.put(test.getKey(), test.getValue());

                Object responseObj = executeRequestWithDelay(apiClient, "GET", testEndpoint, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (isSuccessResponse(response) && !test.getKey().equals("Authorization")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Multiple Authentication Header Support");
                    vuln.setDescription("API accepts authentication via non-standard headers: " + test.getKey());
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/health");
                    vuln.setMethod("GET");
                    vuln.setEvidence("Accepted non-standard header: " + test.getKey() + " with status " + response.getStatus());
                    vuln.setRecommendations(Arrays.asList(
                            "Use only standard Authorization header with Bearer scheme",
                            "Reject authentication via non-standard headers",
                            "Document proper authentication method"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: API принимает нестандартные заголовки аутентификации");
                } else if (isSuccessResponse(response) && test.getKey().equals("Authorization")) {
                    System.out.println("(API-2) Стандартный заголовок Authorization работает корректно");
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования заголовка " + test.getKey() + ": " + e.getMessage());
            }
        }
    }

    private void testSensitiveEndpoints(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование чувствительных endpoint без аутентификации...");

        String[] sensitiveEndpoints = {
                "/admin",
                "/config",
                "/logs",
                "/debug",
                "/env",
                "/metrics",
                "/actuator",
                "/phpmyadmin",
                "/.git",
                "/backup"
        };

        for (String endpoint : sensitiveEndpoints) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object responseObj = executeRequestWithDelay(apiClient, "GET", fullUrl, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (isSuccessResponse(response)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Sensitive Endpoint Accessible Without Authentication");
                    vuln.setDescription("Highly sensitive endpoint " + endpoint + " is accessible without any authentication");
                    vuln.setSeverity(Vulnerability.Severity.CRITICAL);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint(endpoint);
                    vuln.setMethod("GET");
                    vuln.setEvidence("Status " + response.getStatus() + " for sensitive endpoint without auth");
                    vuln.setRecommendations(Arrays.asList(
                            "Implement strict authentication for all sensitive endpoints",
                            "Use role-based access control",
                            "Regularly audit endpoint access controls"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) КРИТИЧЕСКАЯ УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Чувствительный endpoint доступен без аутентификации");
                } else if (response.getStatus() != 404) {
                    System.out.println("(API-2) Чувствительный endpoint " + endpoint + " вернул: " + response.getStatus());
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования чувствительного endpoint " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private void testWithValidToken(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование с валидным токеном...");

        if (cachedValidToken == null) {
            System.out.println("(API-2) Нет валидного токена для тестирования");
            return;
        }

        String[] endpointsWithToken = {
                "/",
                "/health"
        };

        for (String endpoint : endpointsWithToken) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                headers.put("Authorization", "Bearer " + cachedValidToken);

                Object responseObj = executeRequestWithDelay(apiClient, "GET", fullUrl, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (response.getStatus() == 403) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Valid Token Rejected - Authorization Issue");
                    vuln.setDescription("Valid JWT token is rejected with 403 Forbidden");
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint(endpoint);
                    vuln.setMethod("GET");
                    vuln.setEvidence("Status 403 with valid token");
                    vuln.setRecommendations(Arrays.asList(
                            "Check token validation logic",
                            "Ensure proper scope/permission validation",
                            "Verify token signature verification"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Валидный токен отклонен с ошибкой 403");
                } else if (isSuccessResponse(response)) {
                    System.out.println("(API-2) " + endpoint + " корректно работает с валидным токеном (статус: " + response.getStatus() + ")");
                } else {
                    System.out.println("(API-2) " + endpoint + " вернул статус: " + response.getStatus() + " с валидным токеном");
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования " + endpoint + " с валидным токеном: " + e.getMessage());
            }
        }
    }

    private void testBruteforceProtection(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование защиты от брутфорс-атак...");

        String loginUrl = config.getBankBaseUrl() + "/auth/bank-token";
        int maxAttempts = 10;
        boolean protectionDetected = false;

        for (int i = 1; i <= maxAttempts; i++) {
            try {
                String fakeClientId = "team" + (1000 + i);
                String fakeSecret = "fake_secret_" + i;

                String requestBody = "client_id=" + fakeClientId + "&client_secret=" + fakeSecret;

                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/x-www-form-urlencoded");

                Object responseObj = executeRequestWithDelay(apiClient, "POST", loginUrl, requestBody, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                System.out.println("(API-2) Попытка брутфорс-атаки " + i + ": " + response.getStatus());

                if (response.getStatus() == 429) {
                    protectionDetected = true;
                    System.out.println("(API-2) Защита от брутфорс-атак обнаружена на попытке " + i);
                    break;
                }

                if (i >= 5 && (response.getStatus() == 401 || response.getStatus() == 422)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Missing Bruteforce Protection");
                    vuln.setDescription("No rate limiting or account lockout after " + i + " failed authentication attempts");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/auth/bank-token");
                    vuln.setMethod("POST");
                    vuln.setEvidence("Still returns " + response.getStatus() + " after " + i + " failed attempts");
                    vuln.setRecommendations(Arrays.asList(
                            "Implement account lockout after 5-10 failed attempts",
                            "Add rate limiting for authentication endpoints",
                            "Use CAPTCHA or delay mechanisms"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Отсутствует защита от брутфорс-атак");
                    break;
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования брутфорс-защиты: " + e.getMessage());
            }
        }

        if (protectionDetected) {
            System.out.println("(API-2) Защита от брутфорс-атак реализована корректно");
        }
    }

    private void testRateLimiting(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование ограничения частоты запросов (rate limiting)...");

        String testEndpoint = config.getTargetBaseUrl() + "/health";
        int rapidRequests = 10; // Уменьшил количество запросов
        int rateLimitTriggered = 0;

        // Для этого теста временно отключаем нашу задержку
        long originalInterval = MIN_REQUEST_INTERVAL;

        for (int i = 1; i <= rapidRequests; i++) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");

                // Для теста rate limiting используем обычный запрос без задержки
                Object responseObj = apiClient.executeRequest("GET", testEndpoint, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                System.out.println("(API-2) Тест rate limiting " + i + ": " + response.getStatus());

                if (response.getStatus() == 429) {
                    rateLimitTriggered++;
                }

                // Минимальная задержка только для этого теста
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования rate limiting: " + e.getMessage());
            }
        }

        if (rateLimitTriggered == 0) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("Missing Rate Limiting");
            vuln.setDescription("No rate limiting detected after " + rapidRequests + " rapid requests");
            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
            vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
            vuln.setEndpoint("/health");
            vuln.setMethod("GET");
            vuln.setEvidence("No 429 responses after " + rapidRequests + " requests");
            vuln.setRecommendations(Arrays.asList(
                    "Implement rate limiting for all API endpoints",
                    "Use sliding window or token bucket algorithm",
                    "Set reasonable limits per IP/user"
            ));
            vulnerabilities.add(vuln);
            System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Отсутствует ограничение частоты запросов");
        } else {
            System.out.println("(API-2) Ограничение частоты запросов обнаружено: " + rateLimitTriggered + "/" + rapidRequests + " запросов заблокировано");
        }
    }

    private void testTokenSecurity(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование безопасности токенов...");

        if (cachedValidToken == null) return;

        if (cachedValidToken.length() < 100) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("Short JWT Token");
            vuln.setDescription("JWT token is too short, may be weak");
            vuln.setSeverity(Vulnerability.Severity.LOW);
            vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
            vuln.setEvidence("Token length: " + cachedValidToken.length() + " characters");
            vuln.setRecommendations(Arrays.asList(
                    "Use longer JWT tokens (minimum 128 characters)",
                    "Ensure proper entropy in token generation"
            ));
            vulnerabilities.add(vuln);
            System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Слишком короткий JWT токен");
        }

        try {
            String[] parts = cachedValidToken.split("\\.");
            if (parts.length == 3) {
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                if (!payload.contains("\"iss\"") || !payload.contains("\"aud\"")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Missing Standard JWT Claims");
                    vuln.setDescription("JWT token missing standard claims (iss, aud, etc.)");
                    vuln.setSeverity(Vulnerability.Severity.LOW);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEvidence("JWT payload missing standard claims");
                    vuln.setRecommendations(Arrays.asList(
                            "Include standard JWT claims: iss, aud, exp, iat",
                            "Follow JWT best practices for claim structure"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Отсутствуют стандартные JWT claims");
                }
            }
        } catch (Exception e) {
            System.out.println("(API-2) Ошибка анализа безопасности токена: " + e.getMessage());
        }
    }

    private void testJWTWeaknesses(ScanConfig config, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Анализ слабостей JWT токенов...");

        if (cachedValidToken == null) {
            System.out.println("(API-2) Нет токена для анализа JWT слабостей");
            return;
        }

        if (cachedValidToken.startsWith("eyJ")) {
            String[] parts = cachedValidToken.split("\\.");
            if (parts.length == 3) {
                try {
                    String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
                    if (header.contains("none") || header.contains("HS256")) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("Weak JWT Signature Algorithm");
                        vuln.setDescription("JWT uses weak signature algorithm that may be vulnerable to attacks");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                        vuln.setEvidence("JWT header: " + header);
                        vuln.setRecommendations(Arrays.asList(
                                "Use strong signature algorithms like RS256",
                                "Avoid 'none' algorithm in production",
                                "Regularly rotate signing keys"
                        ));
                        vulnerabilities.add(vuln);
                        System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Слабый алгоритм подписи JWT");
                    }

                    String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                    if (!payload.contains("\"exp\"")) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("JWT Token Without Expiration");
                        vuln.setDescription("JWT tokens do not have expiration time");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                        vuln.setEvidence("JWT payload missing 'exp' claim");
                        vuln.setRecommendations(Arrays.asList(
                                "Always set expiration time for JWT tokens",
                                "Use reasonable token lifetime (e.g., 15-60 minutes)",
                                "Implement token refresh mechanism"
                        ));
                        vulnerabilities.add(vuln);
                        System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: JWT токен без срока действия");
                    }

                    if (payload.contains("\"password\"") || payload.contains("\"secret\"") || payload.contains("\"private_key\"")) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("Sensitive Data in JWT Payload");
                        vuln.setDescription("JWT token contains sensitive information in payload");
                        vuln.setSeverity(Vulnerability.Severity.HIGH);
                        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                        vuln.setEvidence("JWT payload contains sensitive fields");
                        vuln.setRecommendations(Arrays.asList(
                                "Never store sensitive data in JWT payload",
                                "Use reference tokens for sensitive information",
                                "Encrypt JWT payload if sensitive data is required"
                        ));
                        vulnerabilities.add(vuln);
                        System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Чувствительные данные в JWT payload");
                    }
                } catch (Exception e) {
                    System.out.println("(API-2) Ошибка анализа JWT: " + e.getMessage());
                }
            }
        }
    }

    private String getValidToken(ScanConfig config) {
        // Используем кэшированный токен
        return cachedValidToken;
    }

    private boolean isSuccessResponse(HttpApiClient.ApiResponse response) {
        int status = response.getStatus();
        return status >= 200 && status < 300;
    }
}