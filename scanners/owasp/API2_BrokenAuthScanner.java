package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.ApiResponse;
import core.AuthManager;
import java.util.*;

public class API2_BrokenAuthScanner implements SecurityScanner {
    
    public API2_BrokenAuthScanner() {}
    
    @Override
    public String getName() {
        return "API2_BrokenAuth";
    }
    
    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("🔐 Scanning for Broken Authentication vulnerabilities...");
        
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // 5.3.1: Вызов защищенных эндпоинтов без токена авторизации
        testUnauthorizedAccess(config, apiClient, vulnerabilities);
        
        // 5.3.2: Проверка с истекшим/невалидным JWT токеном
        testInvalidTokens(config, apiClient, vulnerabilities);
        
        // 5.3.3: Анализ заголовков аутентификации
        testAuthHeaders(config, apiClient, vulnerabilities);
        
        // 5.3.4: Проверка чувствительных эндпоинтов без аутентификации
        testSensitiveEndpoints(config, apiClient, vulnerabilities);
        
        // 5.3.5: Тестирование с валидным токеном
        testWithValidToken(config, apiClient, vulnerabilities);
        
        // 5.3.6: Анализ JWT на слабую подпись/шифрование
        testJWTWeaknesses(config, vulnerabilities);
        
        System.out.println("✅ Broken Auth scan completed. Found: " + vulnerabilities.size() + " vulnerabilities");
        return vulnerabilities;
    }
    
    private void testUnauthorizedAccess(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("🔓 Testing unauthorized access to protected endpoints...");
        
        // Реальные эндпоинты банковского API
        String[] protectedEndpoints = {
            "/accounts",
            "/customers",
            "/transactions", 
            "/cards",
            "/loans",
            "/payments",
            "/consents",
            "/balances"
        };
        
        for (String endpoint : protectedEndpoints) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;
            
            try {
                // Запрос без авторизации
                Map<String, String> noAuthHeaders = new HashMap<>();
                noAuthHeaders.put("Content-Type", "application/json");
                noAuthHeaders.put("Accept", "application/json");
                
                ApiResponse response = apiClient.executeRequest("GET", fullUrl, null, noAuthHeaders);
                
                // Если получили 200 без авторизации - это уязвимость
                if (isSuccessResponse(response)) {
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
                } else {
                    System.out.println("✅ " + endpoint + " properly protected (status: " + response.getStatus() + ")");
                }
                
            } catch (Exception e) {
                System.out.println("⚠ Error testing " + endpoint + ": " + e.getMessage());
            }
        }
    }
    
    private void testInvalidTokens(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("🎫 Testing with invalid/expired tokens...");
        
        String[] invalidTokens = {
            "invalid_token_123",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // слабая подпись
            "Bearer invalid",
            null,
            ""
        };
        
        String testEndpoint = config.getTargetBaseUrl() + "/accounts";
        
        for (String token : invalidTokens) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                if (token != null && !token.isEmpty()) {
                    headers.put("Authorization", "Bearer " + token);
                }
                
                ApiResponse response = apiClient.executeRequest("GET", testEndpoint, null, headers);
                
                // Если принимает невалидный токен - уязвимость
                if (isSuccessResponse(response)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Accepts Invalid JWT Token");
                    vuln.setDescription("API accepts invalid/expired JWT tokens");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/accounts");
                    vuln.setMethod("GET");
                    vuln.setEvidence("Accepted token: " + (token != null ? token.substring(0, Math.min(20, token.length())) + "..." : "null"));
                    vuln.setRecommendations(Arrays.asList(
                        "Validate JWT signature and expiration",
                        "Reject tokens with invalid format",
                        "Implement proper token validation middleware"
                    ));
                    vulnerabilities.add(vuln);
                    break; // достаточно одной найденной уязвимости
                }
                
            } catch (Exception e) {
                // Ожидаемое поведение - токен должен отвергаться
            }
        }
    }
    
    private void testAuthHeaders(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("📋 Testing different authentication headers...");
        
        String testEndpoint = config.getTargetBaseUrl() + "/accounts";
        String validToken = getValidToken(config);
        
        if (validToken == null) {
            System.out.println("⚠ No valid token available for auth header testing");
            return;
        }
        
        // Тестируем разные форматы заголовков
        Map<String, String> authHeaderTests = new HashMap<>();
        authHeaderTests.put("Authorization", "Bearer " + validToken); // правильный
        authHeaderTests.put("authorization", "Bearer " + validToken); // lowercase
        authHeaderTests.put("AUTHORIZATION", "Bearer " + validToken); // uppercase
        authHeaderTests.put("X-API-Key", validToken); // API Key вместо Bearer
        authHeaderTests.put("Token", validToken); // кастомный заголовок
        
        for (Map.Entry<String, String> test : authHeaderTests.entrySet()) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                headers.put(test.getKey(), test.getValue());
                
                ApiResponse response = apiClient.executeRequest("GET", testEndpoint, null, headers);
                
                // Если принимает нестандартные заголовки - возможная уязвимость
                if (isSuccessResponse(response) && !test.getKey().equals("Authorization")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Multiple Authentication Header Support");
                    vuln.setDescription("API accepts authentication via non-standard headers: " + test.getKey());
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/accounts");
                    vuln.setMethod("GET");
                    vuln.setEvidence("Accepted header: " + test.getKey());
                    vuln.setRecommendations(Arrays.asList(
                        "Use only standard Authorization header with Bearer scheme",
                        "Reject authentication via non-standard headers",
                        "Document proper authentication method"
                    ));
                    vulnerabilities.add(vuln);
                }
                
            } catch (Exception e) {
                // Ожидаемое поведение для нестандартных заголовков
            }
        }
    }
    
    private void testSensitiveEndpoints(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("🔒 Testing sensitive endpoints without authentication...");
        
        // Список особо чувствительных эндпоинтов
        String[] sensitiveEndpoints = {
            "/admin/users",
            "/config",
            "/logs",
            "/backup",
            "/api/keys",
            "/secrets",
            "/credentials"
        };
        
        for (String endpoint : sensitiveEndpoints) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;
            
            try {
                // Запрос без авторизации
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                
                ApiResponse response = apiClient.executeRequest("GET", fullUrl, null, headers);
                
                // Если доступен без авторизации - критическая уязвимость
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
                }
                
            } catch (Exception e) {
                System.out.println("⚠ Error testing sensitive endpoint " + endpoint + ": " + e.getMessage());
            }
        }
    }
    
    private void testWithValidToken(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("🔑 Testing with valid token...");
        
        String validToken = getValidToken(config);
        
        if (validToken == null) {
            System.out.println("⚠ No valid token available for testing");
            return;
        }
        
        // Эндпоинты которые должны работать с валидным токеном
        String[] endpointsWithToken = {
            "/accounts",
            "/balances",
            "/transactions",
            "/consents"
        };
        
        for (String endpoint : endpointsWithToken) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;
            
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                headers.put("Authorization", "Bearer " + validToken);
                
                ApiResponse response = apiClient.executeRequest("GET", fullUrl, null, headers);
                
                // Анализируем ответ с валидным токеном
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
                } else if (isSuccessResponse(response)) {
                    System.out.println("✅ " + endpoint + " works correctly with valid token (status: " + response.getStatus() + ")");
                } else {
                    System.out.println("⚠ " + endpoint + " returned status: " + response.getStatus() + " with valid token");
                }
                
            } catch (Exception e) {
                System.out.println("⚠ Error testing " + endpoint + " with valid token: " + e.getMessage());
            }
        }
    }
    
    private void testJWTWeaknesses(ScanConfig config, List<Vulnerability> vulnerabilities) {
        System.out.println("🔍 Analyzing JWT token weaknesses...");
        
        String token = getValidToken(config);
        
        if (token != null) {
            // Базовая проверка JWT
            if (token.startsWith("eyJ")) {
                String[] parts = token.split("\\.");
                if (parts.length == 3) {
                    // Проверяем алгоритм подписи
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
                    }
                    
                    // Проверяем expiration
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
                    }
                }
            }
        }
    }
    
    private String getValidToken(ScanConfig config) {
        // Пытаемся получить токен из конфига
        if (config.getAccessToken() != null && AuthManager.isTokenValid(config.getAccessToken())) {
            return config.getAccessToken();
        }
        
        // Если токена нет, пытаемся аутентифицироваться через банковское API
        if (config.getBankBaseUrl() != null && config.getClientId() != null && config.getClientSecret() != null) {
            String token = AuthManager.getBankHackathonToken(
                config.getBankBaseUrl(),
                config.getClientId(), 
                config.getClientSecret()
            );
            if (token != null) {
                config.setAccessToken(token);
                return token;
            }
        }
        
        return null;
    }
    
    private boolean isSuccessResponse(ApiResponse response) {
        int status = response.getStatus();
        return status >= 200 && status < 300;
    }
}
