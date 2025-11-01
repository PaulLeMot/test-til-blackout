package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import core.AuthManager;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import java.util.*;

public class API2_BrokenAuthScanner implements SecurityScanner {

    private OpenAPI openAPI;
    private String validToken; // Кэшируем валидный токен

    public API2_BrokenAuthScanner() {}

    @Override
    public String getName() {
        return "API2_BrokenAuth";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-2) Запуск сканирования на уязвимости Broken Authentication (OWASP API Security Top 10:2023 - API2)...");

        this.openAPI = (OpenAPI) openApiObj;
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (openAPI == null) {
            System.out.println("(API-2) ОШИБКА: OpenAPI спецификация не загружена");
            return vulnerabilities;
        }

        // Получаем токены один раз в начале сканирования
        Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(
                config.getTargetBaseUrl(),
                config.getPassword()
        );

        // Сохраняем первый валидный токен
        for (String token : tokens.values()) {
            if (token != null && AuthManager.isTokenValid(token)) {
                this.validToken = token;
                break;
            }
        }

        if (validToken == null) {
            System.out.println("(API-2) Не удалось получить валидный токен для тестирования");
        } else {
            System.out.println("(API-2) Получен валидный токен для тестирования");
        }

        testAuthEndpointSecurity(config, apiClient, vulnerabilities);
        testProtectedEndpointsWithoutAuth(config, apiClient, vulnerabilities);
        testInvalidTokens(config, apiClient, vulnerabilities);

        if (validToken != null) {
            testTokenSecurity(config, vulnerabilities);
            testJWTWeaknesses(config, vulnerabilities);
        }

        testBruteforceProtection(config, apiClient, vulnerabilities);
        testRateLimiting(config, apiClient, vulnerabilities);

        System.out.println("(API-2) Сканирование Broken Authentication завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private void testAuthEndpointSecurity(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование endpoint'ов аутентификации...");

        // Тестируем основной endpoint аутентификации из спецификации
        String authEndpoint = "/auth/bank-token";

        try {
            // Тест 1: Запрос без client_id и client_secret
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");

            Object responseObj = apiClient.executeRequest("POST", config.getTargetBaseUrl() + authEndpoint, null, headers);
            HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

            if (isSuccessResponse(response)) {
                Vulnerability vuln = new Vulnerability();
                vuln.setTitle("Authentication Endpoint Missing Required Parameters Validation");
                vuln.setDescription("Auth endpoint " + authEndpoint + " accepts requests without required client_id and client_secret parameters");
                vuln.setSeverity(Vulnerability.Severity.HIGH);
                vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                vuln.setEndpoint(authEndpoint);
                vuln.setMethod("POST");
                vuln.setEvidence("Status " + response.getStatus() + " without required authentication parameters");
                vuln.setRecommendations(Arrays.asList(
                        "Require client_id and client_secret for all authentication requests",
                        "Validate all required parameters before processing",
                        "Return 400 Bad Request for missing required parameters"
                ));
                vulnerabilities.add(vuln);
            }

            // Тест 2: Запрос с неверными credentials
            String invalidBody = "client_id=invalid_team&client_secret=invalid_secret";
            Map<String, String> formHeaders = new HashMap<>();
            formHeaders.put("Content-Type", "application/x-www-form-urlencoded");

            responseObj = apiClient.executeRequest("POST", config.getTargetBaseUrl() + authEndpoint, invalidBody, formHeaders);
            response = (HttpApiClient.ApiResponse) responseObj;

            if (isSuccessResponse(response)) {
                Vulnerability vuln = new Vulnerability();
                vuln.setTitle("Authentication Endpoint Accepts Invalid Credentials");
                vuln.setDescription("Auth endpoint " + authEndpoint + " accepts invalid client_id and client_secret");
                vuln.setSeverity(Vulnerability.Severity.HIGH);
                vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                vuln.setEndpoint(authEndpoint);
                vuln.setMethod("POST");
                vuln.setEvidence("Status " + response.getStatus() + " with invalid credentials");
                vuln.setRecommendations(Arrays.asList(
                        "Validate credentials against secure storage",
                        "Return 401 Unauthorized for invalid credentials",
                        "Implement proper credential validation"
                ));
                vulnerabilities.add(vuln);
            }

        } catch (Exception e) {
            System.out.println("(API-2) Ошибка тестирования auth endpoint: " + e.getMessage());
        }
    }

    private void testProtectedEndpointsWithoutAuth(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование защищенных endpoint'ов без аутентификации...");

        // Получаем все endpoint'ы из спецификации которые требуют аутентификации
        Map<String, PathItem> paths = openAPI.getPaths();

        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();

            // Пропускаем публичные endpoint'ы
            if (path.equals("/auth/bank-token") || path.equals("/.well-known/jwks.json") ||
                    path.equals("/") || path.equals("/health") || path.equals("/products")) {
                continue;
            }

            // Проверяем все методы для этого пути
            testOperationWithoutAuth(config, apiClient, vulnerabilities, path, "GET", pathItem.getGet());
            testOperationWithoutAuth(config, apiClient, vulnerabilities, path, "POST", pathItem.getPost());
            testOperationWithoutAuth(config, apiClient, vulnerabilities, path, "PUT", pathItem.getPut());
            testOperationWithoutAuth(config, apiClient, vulnerabilities, path, "DELETE", pathItem.getDelete());
        }
    }

    private void testOperationWithoutAuth(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities,
                                          String path, String method, Operation operation) {
        if (operation == null) return;

        // Проверяем требует ли операция аутентификации
        boolean requiresAuth = operation.getSecurity() != null && !operation.getSecurity().isEmpty();

        if (requiresAuth) {
            try {
                String fullUrl = config.getTargetBaseUrl() + path;

                // Заменяем path parameters на тестовые значения
                fullUrl = replacePathParameters(fullUrl);

                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object responseObj = apiClient.executeRequest(method, fullUrl, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (isSuccessResponse(response)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Protected Endpoint Accessible Without Authentication");
                    vuln.setDescription("Endpoint " + path + " (" + method + ") is accessible without proper authentication");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint(path);
                    vuln.setMethod(method);
                    vuln.setEvidence("Status " + response.getStatus() + " without Authorization header");
                    vuln.setRecommendations(Arrays.asList(
                            "Require valid Bearer token for all protected endpoints",
                            "Implement proper JWT validation middleware",
                            "Return 401 Unauthorized for unauthenticated requests"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ: " + method + " " + path + " доступен без аутентификации");
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования " + method + " " + path + ": " + e.getMessage());
            }
        }
    }

    private void testInvalidTokens(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование с невалидными токенами...");

        String[] invalidTokens = {
                "invalid_token_123",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "Bearer invalid",
                "null",
                ""
        };

        // Тестируем на защищенном endpoint'е из спецификации
        String testEndpoint = "/accounts";
        String fullUrl = config.getTargetBaseUrl() + testEndpoint;

        for (String token : invalidTokens) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                if (token != null && !token.isEmpty() && !token.equals("null")) {
                    headers.put("Authorization", "Bearer " + token);
                }

                Object responseObj = apiClient.executeRequest("GET", fullUrl, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (isSuccessResponse(response)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("API Accepts Invalid JWT Tokens");
                    vuln.setDescription("Protected endpoint accepts invalid/expired JWT tokens");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint(testEndpoint);
                    vuln.setMethod("GET");
                    vuln.setEvidence("Accepted invalid token and returned status " + response.getStatus());
                    vuln.setRecommendations(Arrays.asList(
                            "Validate JWT signature and expiration properly",
                            "Reject tokens with invalid format or signature",
                            "Implement proper token validation middleware"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ: API принимает невалидный токен");
                    break;
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования невалидного токена: " + e.getMessage());
            }
        }
    }

    private void testTokenSecurity(ScanConfig config, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование безопасности токенов...");

        if (validToken == null) {
            System.out.println("(API-2) Не удалось получить валидный токен для тестирования");
            return;
        }

        // Проверяем длину токена
        if (validToken.length() < 100) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("JWT Token Too Short");
            vuln.setDescription("JWT token length is insufficient for security");
            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
            vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
            vuln.setEvidence("Token length: " + validToken.length() + " characters");
            vuln.setRecommendations(Arrays.asList(
                    "Use longer JWT tokens with proper entropy",
                    "Ensure minimum token length of 128 characters"
            ));
            vulnerabilities.add(vuln);
        }

        // Проверяем структуру JWT
        try {
            String[] parts = validToken.split("\\.");
            if (parts.length == 3) {
                String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));

                // Проверяем наличие стандартных claims
                if (!payload.contains("\"exp\"")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("JWT Missing Expiration Claim");
                    vuln.setDescription("JWT tokens should include expiration time");
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEvidence("JWT payload missing 'exp' claim");
                    vuln.setRecommendations(Arrays.asList(
                            "Always include 'exp' claim in JWT tokens",
                            "Set reasonable token expiration time"
                    ));
                    vulnerabilities.add(vuln);
                }

                if (!payload.contains("\"iss\"")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("JWT Missing Issuer Claim");
                    vuln.setDescription("JWT tokens should include issuer information");
                    vuln.setSeverity(Vulnerability.Severity.LOW);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEvidence("JWT payload missing 'iss' claim");
                    vuln.setRecommendations(Arrays.asList(
                            "Include 'iss' claim to identify token issuer",
                            "Validate issuer during token verification"
                    ));
                    vulnerabilities.add(vuln);
                }
            }
        } catch (Exception e) {
            System.out.println("(API-2) Ошибка анализа JWT токена: " + e.getMessage());
        }
    }

    private void testBruteforceProtection(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование защиты от брутфорс-атак...");

        String authUrl = config.getTargetBaseUrl() + "/auth/bank-token";
        int maxAttempts = 10;
        boolean protectionDetected = false;

        for (int i = 1; i <= maxAttempts; i++) {
            try {
                String fakeClientId = "team" + (1000 + i);
                String fakeSecret = "fake_secret_" + i;

                String requestBody = "client_id=" + fakeClientId + "&client_secret=" + fakeSecret;

                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/x-www-form-urlencoded");

                Object responseObj = apiClient.executeRequest("POST", authUrl, requestBody, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (response.getStatus() == 429) {
                    protectionDetected = true;
                    System.out.println("(API-2) Защита от брутфорс-атак обнаружена на попытке " + i);
                    break;
                }

                // Если после 5 попыток нет блокировки - уязвимость
                if (i >= 5 && (response.getStatus() == 401 || response.getStatus() == 422)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Missing Bruteforce Protection on Auth Endpoint");
                    vuln.setDescription("No rate limiting detected after " + i + " failed authentication attempts");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/auth/bank-token");
                    vuln.setMethod("POST");
                    vuln.setEvidence("Still returns " + response.getStatus() + " after " + i + " failed attempts");
                    vuln.setRecommendations(Arrays.asList(
                            "Implement rate limiting for authentication endpoints",
                            "Lock accounts after 5-10 failed attempts",
                            "Use CAPTCHA or increasing delays for repeated failures"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ: Отсутствует защита от брутфорс-атак");
                    break;
                }

                Thread.sleep(100); // Небольшая задержка между запросами

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования брутфорс-защиты: " + e.getMessage());
            }
        }

        if (protectionDetected) {
            System.out.println("(API-2) Защита от брутфорс-атак реализована корректно");
        }
    }

    private void testRateLimiting(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование ограничения частоты запросов...");

        // Тестируем на публичном endpoint'е
        String testEndpoint = config.getTargetBaseUrl() + "/products";
        int rapidRequests = 15;
        int rateLimitTriggered = 0;

        for (int i = 1; i <= rapidRequests; i++) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");

                Object responseObj = apiClient.executeRequest("GET", testEndpoint, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;

                if (response.getStatus() == 429) {
                    rateLimitTriggered++;
                }

                Thread.sleep(50);

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
            vuln.setEndpoint("/products");
            vuln.setMethod("GET");
            vuln.setEvidence("No 429 responses after " + rapidRequests + " requests");
            vuln.setRecommendations(Arrays.asList(
                    "Implement rate limiting for all API endpoints",
                    "Set reasonable limits per IP/user",
                    "Use sliding window algorithm for better protection"
            ));
            vulnerabilities.add(vuln);
            System.out.println("(API-2) УЯЗВИМОСТЬ: Отсутствует ограничение частоты запросов");
        } else {
            System.out.println("(API-2) Rate limiting обнаружен: " + rateLimitTriggered + "/" + rapidRequests + " запросов заблокировано");
        }
    }

    private void testJWTWeaknesses(ScanConfig config, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Анализ слабостей JWT...");

        if (validToken == null) {
            System.out.println("(API-2) Не удалось получить валидный токен для анализа");
            return;
        }

        try {
            String[] parts = validToken.split("\\.");
            if (parts.length == 3) {
                String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));

                // Проверяем слабые алгоритмы
                if (header.contains("\"alg\":\"none\"") || header.contains("\"alg\":\"HS256\"")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Weak JWT Signature Algorithm");
                    vuln.setDescription("JWT uses weak signature algorithm that may be vulnerable to attacks");
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEvidence("JWT header indicates weak algorithm: " + header);
                    vuln.setRecommendations(Arrays.asList(
                            "Use strong signature algorithms like RS256 or ES256",
                            "Avoid 'none' algorithm in production environments",
                            "Regularly rotate JWT signing keys"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ: Обнаружен слабый алгоритм подписи JWT");
                }
            }
        } catch (Exception e) {
            System.out.println("(API-2) Ошибка анализа JWT: " + e.getMessage());
        }
    }

    private String replacePathParameters(String url) {
        // Заменяем path parameters на тестовые значения
        return url.replaceAll("\\{.*?\\}", "test123");
    }

    private boolean isSuccessResponse(HttpApiClient.ApiResponse response) {
        int status = response.getStatus();
        return status >= 200 && status < 300;
    }
}