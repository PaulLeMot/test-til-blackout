package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
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
        
        testUnauthorizedAccess(config, apiClient, vulnerabilities);
        testInvalidTokens(config, apiClient, vulnerabilities);
        testAuthHeaders(config, apiClient, vulnerabilities);
        testSensitiveEndpoints(config, apiClient, vulnerabilities);
        testWithValidToken(config, apiClient, vulnerabilities);
        testBruteforceProtection(config, apiClient, vulnerabilities);
        testRateLimiting(config, apiClient, vulnerabilities);
        testTokenSecurity(config, apiClient, vulnerabilities);
        testJWTWeaknesses(config, vulnerabilities);
        
        System.out.println("✅ Broken Auth scan completed. Found: " + vulnerabilities.size() + " vulnerabilities");
        return vulnerabilities;
    }
    
    private void testUnauthorizedAccess(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("🔓 Testing unauthorized access to protected endpoints...");
        
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
                
                Object responseObj = apiClient.executeRequest("GET", fullUrl, null, noAuthHeaders);
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
                
                Object responseObj = apiClient.executeRequest("GET", testEndpoint, null, headers);
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
                    break;
                } else {
                    System.out.println("✅ Invalid token correctly rejected: " + response.getStatus());
                }
                
            } catch (Exception e) {
                System.out.println("⚠ Error testing invalid token: " + e.getMessage());
            }
        }
    }
    
    private void testAuthHeaders(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("📋 Testing different authentication headers...");
        
        String testEndpoint = config.getTargetBaseUrl() + "/health";
        String validToken = getValidToken(config);
        
        if (validToken == null) {
            System.out.println("⚠ No valid token available for auth header testing");
            return;
        }
        
        Map<String, String> authHeaderTests = new HashMap<>();
        authHeaderTests.put("Authorization", "Bearer " + validToken);
        authHeaderTests.put("authorization", "Bearer " + validToken);
        authHeaderTests.put("AUTHORIZATION", "Bearer " + validToken);
        authHeaderTests.put("X-API-Key", validToken);
        authHeaderTests.put("Token", validToken);
        authHeaderTests.put("X-Auth-Token", validToken);
        
        for (Map.Entry<String, String> test : authHeaderTests.entrySet()) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                headers.put(test.getKey(), test.getValue());
                
                Object responseObj = apiClient.executeRequest("GET", testEndpoint, null, headers);
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
                } else if (isSuccessResponse(response) && test.getKey().equals("Authorization")) {
                    System.out.println("✅ Standard Authorization header works correctly");
                }
                
            } catch (Exception e) {
                System.out.println("⚠ Error testing header " + test.getKey() + ": " + e.getMessage());
            }
        }
    }
    
    private void testSensitiveEndpoints(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("🔒 Testing sensitive endpoints without authentication...");
        
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
                
                Object responseObj = apiClient.executeRequest("GET", fullUrl, null, headers);
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
                } else if (response.getStatus() != 404) {
                    System.out.println("⚠ Sensitive endpoint " + endpoint + " returned: " + response.getStatus());
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
                headers.put("Authorization", "Bearer " + validToken);
                
                Object responseObj = apiClient.executeRequest("GET", fullUrl, null, headers);
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
    
    private void testBruteforceProtection(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("💥 Testing bruteforce protection...");
        
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
                
                Object responseObj = apiClient.executeRequest("POST", loginUrl, requestBody, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;
                
                System.out.println("🔐 Bruteforce attempt " + i + ": " + response.getStatus());
                
                if (response.getStatus() == 429) {
                    protectionDetected = true;
                    System.out.println("✅ Bruteforce protection detected at attempt " + i);
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
                    break;
                }
                
                Thread.sleep(100);
                
            } catch (Exception e) {
                System.out.println("⚠ Bruteforce test error: " + e.getMessage());
            }
        }
        
        if (protectionDetected) {
            System.out.println("✅ Bruteforce protection is implemented");
        }
    }
    
    private void testRateLimiting(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("🚀 Testing rate limiting...");
        
        String testEndpoint = config.getTargetBaseUrl() + "/health";
        int rapidRequests = 20;
        int rateLimitTriggered = 0;
        
        for (int i = 1; i <= rapidRequests; i++) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                
                Object responseObj = apiClient.executeRequest("GET", testEndpoint, null, headers);
                HttpApiClient.ApiResponse response = (HttpApiClient.ApiResponse) responseObj;
                
                System.out.println("📡 Rate limit test " + i + ": " + response.getStatus());
                
                if (response.getStatus() == 429) {
                    rateLimitTriggered++;
                }
                
                Thread.sleep(50);
                
            } catch (Exception e) {
                System.out.println("⚠ Rate limit test error: " + e.getMessage());
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
        } else {
            System.out.println("✅ Rate limiting detected: " + rateLimitTriggered + "/" + rapidRequests + " requests blocked");
        }
    }
    
    private void testTokenSecurity(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("🔒 Testing token security...");
        
        String validToken = getValidToken(config);
        if (validToken == null) return;
        
        if (validToken.length() < 100) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("Short JWT Token");
            vuln.setDescription("JWT token is too short, may be weak");
            vuln.setSeverity(Vulnerability.Severity.LOW);
            vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
            vuln.setEvidence("Token length: " + validToken.length() + " characters");
            vuln.setRecommendations(Arrays.asList(
                "Use longer JWT tokens (minimum 128 characters)",
                "Ensure proper entropy in token generation"
            ));
            vulnerabilities.add(vuln);
        }
        
        try {
            String[] parts = validToken.split("\\.");
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
                }
            }
        } catch (Exception e) {
            System.out.println("⚠ Token security analysis error: " + e.getMessage());
        }
    }
    
    private void testJWTWeaknesses(ScanConfig config, List<Vulnerability> vulnerabilities) {
        System.out.println("🔍 Analyzing JWT token weaknesses...");
        
        String token = getValidToken(config);
        
        if (token != null) {
            if (token.startsWith("eyJ")) {
                String[] parts = token.split("\\.");
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
                        }
                    } catch (Exception e) {
                        System.out.println("⚠ JWT analysis error: " + e.getMessage());
                    }
                }
            }
        }
    }
    
    private String getValidToken(ScanConfig config) {
        // Используем тот же механизм, что и другие сканеры
        Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(
            config.getTargetBaseUrl(), 
            config.getPassword()
        );
        
        // Возвращаем первый найденный токен
        for (String token : tokens.values()) {
            if (token != null && AuthManager.isTokenValid(token)) {
                return token;
            }
        }
        
        return null;
    }
    
    private boolean isSuccessResponse(HttpApiClient.ApiResponse response) {
        int status = response.getStatus();
        return status >= 200 && status < 300;
    }
}
