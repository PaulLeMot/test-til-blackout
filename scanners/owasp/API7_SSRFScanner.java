package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;

import java.util.*;

public class API7_SSRFScanner implements SecurityScanner {
    
    private static final Set<String> URL_PARAMETERS = new HashSet<>(Arrays.asList(
        "url", "webhook", "callback", "image", "target", "redirect", 
        "return", "next", "uri", "path", "file", "load", "fetch",
        "download", "source", "destination", "endpoint", "service",
        "client_id", "bank_code", "account_number", "destination_account",
        "avatar_url", "logo_url", "icon_url", "confirmation_url",
        "notification_url", "webhook_url", "callback_url", "return_url"
    ));
    
    // Расширенный список целей для тестирования
    private static final List<String> SSRF_TARGETS = Arrays.asList(
        // Локальные цели
        "http://localhost:8080/api/accounts",
        "http://127.0.0.1:80/admin",
        "http://[::1]:80/",
        "http://localhost:22/",
        "http://127.0.0.1:22/",
        
        // Внутренние сети
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        
        // Облачные метаданные
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        
        // Альтернативные схемы
        "file:///etc/passwd",
        "gopher://localhost:25/_TEST",
        "dict://localhost:11211/stat",
        
        // Обходы валидации
        "http://localtest.me",
        "http://127.0.0.1.nip.io",
        "http://0x7f000001",
        "http://2130706433"
    );

    @Override
    public String getName() {
        return "OWASP API7: Server Side Request Forgery (SSRF) Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("🌐 Starting enhanced SSRF vulnerability scan...");
        
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl();
        
        // 1. Находим существующие эндпоинты
        List<String> existingEndpoints = findExistingEndpoints(config, apiClient);
        System.out.println("✅ Found " + existingEndpoints.size() + " existing endpoints: " + existingEndpoints);
        
        if (existingEndpoints.isEmpty()) {
            System.out.println("❌ No existing endpoints found to test");
            return vulnerabilities;
        }
        
        // 2. Тестируем каждый существующий эндпоинт с расширенными payload'ами
        for (String endpoint : existingEndpoints) {
            System.out.println("🎯 Testing endpoint: " + endpoint);
            testEndpointWithMultiplePayloads(config, apiClient, vulnerabilities, endpoint);
        }
        
        System.out.println("✅ SSRF scan completed. Found: " + vulnerabilities.size() + " vulnerabilities");
        return vulnerabilities;
    }
    
    private List<String> findExistingEndpoints(ScanConfig config, ApiClient apiClient) {
        List<String> existing = new ArrayList<>();
        List<String> potentialEndpoints = Arrays.asList(
            "/interbank/receive", "/payment-consents/request", "/payments",
            "/account-consents/request", "/auth/bank-token", "/domestic-vrp-payments",
            "/customer-leads", "/product-application", "/webhook", "/api/callback"
        );
        
        for (String endpoint : potentialEndpoints) {
            try {
                String url = config.getTargetBaseUrl() + endpoint;
                Map<String, String> headers = createBasicHeaders();
                
                Object response = apiClient.executeRequest("OPTIONS", url, null, headers);
                
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse httpResponse = (HttpApiClient.ApiResponse) response;
                    int status = httpResponse.getStatus();
                    
                    // Более либеральная проверка существования
                    if (status != 404) {
                        existing.add(endpoint);
                        System.out.println("   ✅ Endpoint exists: " + endpoint + " (status: " + status + ")");
                    }
                }
                
            } catch (Exception e) {
                // Пропускаем ошибки
            }
        }
        
        return existing;
    }
    
    private void testEndpointWithMultiplePayloads(ScanConfig config, ApiClient apiClient, 
                                                List<Vulnerability> vulnerabilities, String endpoint) {
        
        // Генерируем различные типы payload'ов для этого эндпоинта
        List<Map<String, Object>> testCases = generateTestCases(endpoint);
        
        for (Map<String, Object> testCase : testCases) {
            String parameter = (String) testCase.get("parameter");
            String payload = (String) testCase.get("payload");
            String method = (String) testCase.get("method");
            String body = (String) testCase.get("body");
            
            try {
                System.out.println("   🧪 Testing: " + parameter + "=" + payload);
                
                String url = config.getTargetBaseUrl() + endpoint;
                Map<String, String> headers = createBankingHeaders(endpoint);
                
                Object response = apiClient.executeRequest(method, url, body, headers);
                
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse httpResponse = (HttpApiClient.ApiResponse) response;
                    
                    System.out.println("   📡 Response: " + httpResponse.getStatus() + 
                                     ", length: " + httpResponse.getBody().length());
                    
                    // УЛУЧШЕННАЯ ЛОГИКА ОБНАРУЖЕНИЯ
                    if (isPotentialSSRF(httpResponse, payload)) {
                        Vulnerability vuln = createSSRFVulnerability(
                            "Potential SSRF in " + endpoint,
                            "SSRF vulnerability detected via parameter: " + parameter,
                            Vulnerability.Severity.HIGH,
                            endpoint,
                            parameter,
                            payload,
                            httpResponse
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("   🔴 POTENTIAL SSRF DETECTED!");
                    }
                }
                
            } catch (Exception e) {
                System.out.println("   ⚠ Request failed: " + e.getMessage());
            }
        }
    }
    
    private List<Map<String, Object>> generateTestCases(String endpoint) {
        List<Map<String, Object>> testCases = new ArrayList<>();
        
        // Генерируем тестовые случаи для разных параметров
        for (String parameter : URL_PARAMETERS) {
            for (String target : SSRF_TARGETS) {
                Map<String, Object> testCase = new HashMap<>();
                testCase.put("parameter", parameter);
                testCase.put("payload", target);
                testCase.put("method", "POST");
                
                // Генерируем тело запроса в зависимости от эндпоинта
                String body = generateRequestBody(endpoint, parameter, target);
                testCase.put("body", body);
                
                testCases.add(testCase);
                
                // Ограничиваем количество тестов на параметр
                if (testCases.size() > 50) break;
            }
            if (testCases.size() > 50) break;
        }
        
        return testCases;
    }
    
    private String generateRequestBody(String endpoint, String parameter, String target) {
        // Базовый JSON шаблон
        String baseTemplate = "{\"data\":{\"test\":\"value\"},\"risk\":{\"webhook\":\"%s\"}}";
        
        // Специализированные шаблоны для разных эндпоинтов
        if (endpoint.contains("/payment")) {
            return String.format(
                "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"}}},\"risk\":{\"%s\":\"%s\"}}",
                parameter, target
            );
        } else if (endpoint.contains("/auth")) {
            return String.format(
                "{\"client_id\":\"test\",\"redirect_uri\":\"%s\"}",
                target
            );
        } else if (endpoint.contains("/customer") || endpoint.contains("/product")) {
            return String.format(
                "{\"user_data\":{\"avatar_url\":\"%s\"}}",
                target
            );
        } else {
            return String.format(
                "{\"%s\":\"%s\",\"test_field\":\"test_value\"}",
                parameter, target
            );
        }
    }
    
    // УЛУЧШЕННАЯ ЛОГИКА ОБНАРУЖЕНИЯ SSRF
    private boolean isPotentialSSRF(HttpApiClient.ApiResponse response, String payload) {
        int status = response.getStatus();
        String body = response.getBody().toLowerCase();
        
        // 1. Успешные ответы на подозрительные URL
        if ((status == 200 || status == 201 || status == 202) && 
            !containsErrorKeywords(body)) {
            return true;
        }
        
        // 2. Ответы с данными от облачных метаданных
        if (payload.contains("169.254.169.254") && 
            (body.contains("instance-id") || body.contains("ami-id") || body.contains("hostname"))) {
            return true;
        }
        
        // 3. Ошибки, указывающие на попытку подключения
        if ((status >= 500 && status <= 599) && 
            (body.contains("connection") || body.contains("timeout") || body.contains("refused") || 
             body.contains("socket") || body.contains("network"))) {
            return true;
        }
        
        // 4. Нестандартные ответы на локальные адреса
        if (payload.contains("localhost") || payload.contains("127.0.0.1")) {
            if (status != 400 && status != 422 && status != 403 && !containsValidationErrors(body)) {
                return true;
            }
        }
        
        // 5. Ответы с содержимым файловой системы
        if (payload.contains("file://") && body.contains("root:") || body.contains("/etc/")) {
            return true;
        }
        
        return false;
    }
    
    private boolean containsErrorKeywords(String body) {
        return body.contains("error") || body.contains("invalid") || 
               body.contains("validation") || body.contains("not allowed") ||
               body.contains("forbidden") || body.contains("unauthorized");
    }
    
    private boolean containsValidationErrors(String body) {
        return body.contains("validation") || body.contains("invalid") || 
               body.contains("malformed") || body.contains("not acceptable");
    }
    
    private Map<String, String> createBasicHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Security-Scanner/1.0");
        headers.put("Accept", "application/json");
        return headers;
    }
    
    private Map<String, String> createBankingHeaders(String endpoint) {
        Map<String, String> headers = createBasicHeaders();
        headers.put("Content-Type", "application/json");
        headers.put("X-Requesting-Bank", "security-test");
        headers.put("X-Test-ID", UUID.randomUUID().toString());
        return headers;
    }
    
    private Vulnerability createSSRFVulnerability(String title, String description, 
                                                Vulnerability.Severity severity,
                                                String endpoint, String parameter, 
                                                String payload, HttpApiClient.ApiResponse response) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API7_SSRF);
        vuln.setEndpoint(endpoint);
        vuln.setMethod("POST");
        vuln.setParameter(parameter);
        
        String evidence = String.format(
            "SSRF Payload: %s\nParameter: %s\nResponse Status: %d\nResponse Body: %s",
            payload, parameter, response.getStatus(),
            response.getBody().length() > 200 ? response.getBody().substring(0, 200) + "..." : response.getBody()
        );
        vuln.setEvidence(evidence);
        
        vuln.setRecommendations(Arrays.asList(
            "Validate and sanitize all user-supplied URLs",
            "Implement strict URL whitelisting",
            "Block access to internal IP ranges (127.0.0.1, 192.168.*.*, 10.*.*.*, 172.16.*.*)",
            "Disable dangerous URL schemes (file://, gopher://, dict://)",
            "Use network segmentation and outbound firewalls",
            "Implement proper error handling to avoid information disclosure"
        ));
        
        vuln.setStatusCode(response.getStatus());
        
        return vuln;
    }
}
