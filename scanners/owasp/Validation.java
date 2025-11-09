package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import core.HttpApiClient;

import java.util.*;

public class Validation implements SecurityScanner {
    
    private static final boolean DEBUG = true;
    
    @Override
    public String getName() {
        return "API Contract Validation Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (!(openApiObj instanceof OpenAPI)) {
            vulnerabilities.add(createVulnerability(
                "OpenAPI Specification Not Available",
                "Cannot perform contract validation without OpenAPI specification",
                Vulnerability.Severity.MEDIUM,
                "N/A", "N/A",
                "No OpenAPI specification was loaded during scan"
            ));
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        String baseUrl = config.getTargetBaseUrl();
        
        try {
            logDebug("Starting contract validation for: " + baseUrl);
            
            // Test basic connectivity first
            if (!testBasicConnectivity(baseUrl, apiClient)) {
                vulnerabilities.add(createVulnerability(
                    "API Server Connectivity Issue",
                    "Cannot establish connection to API server",
                    Vulnerability.Severity.HIGH,
                    "N/A", "N/A",
                    "Cannot connect to public endpoints"
                ));
                return vulnerabilities;
            }
            
            vulnerabilities.addAll(validateSpecificationCompleteness(openAPI));
            
            // Сначала собираем реальные данные через API
            Map<String, Object> testData = collectRealTestData(openAPI, baseUrl, config, apiClient);
            vulnerabilities.addAll(validateDocumentedEndpoints(openAPI, baseUrl, config, apiClient, testData));
            vulnerabilities.addAll(validateStandardEndpoints(openAPI, baseUrl, config, apiClient));
            
            logDebug("Contract validation completed. Found: " + vulnerabilities.size() + " vulnerabilities");
        } catch (Exception e) {
            vulnerabilities.add(createVulnerability(
                "Contract Validation Error",
                "Error during contract validation: " + e.getMessage(),
                Vulnerability.Severity.MEDIUM,
                "N/A", "N/A",
                "Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage()
            ));
        }
        
        return vulnerabilities;
    }

    private Map<String, Object> collectRealTestData(OpenAPI openAPI, String baseUrl, ScanConfig config, ApiClient apiClient) {
        Map<String, Object> testData = new HashMap<>();
        
        try {
            // Получаем реальный bank token через /auth/bank-token
            String realBankToken = getRealBankToken(baseUrl, config, apiClient);
            if (realBankToken != null) {
                testData.put("real_bank_token", realBankToken);
                logDebug("Obtained real bank token");
            }
            
            // Получаем реальные consent_id через создание согласия с bank token
            String consentId = createRealConsent(baseUrl, config, apiClient);
            if (consentId != null) {
                testData.put("consent_id", consentId);
                logDebug("Created real consent with ID: " + consentId);
            }

            // СОЗДАЕМ РЕАЛЬНЫЙ СЧЕТ ДЛЯ ТЕСТИРОВАНИЯ
            String accountId = createRealAccount(baseUrl, config, apiClient);
            if (accountId != null) {
                testData.put("account_ids", Collections.singletonList(accountId));
                testData.put("account_id", accountId);
                logDebug("Created real account with ID: " + accountId);
            } else {
                // Если не удалось создать счет, пробуем получить существующие
                List<String> accountIds = getRealAccountIds(baseUrl, config, apiClient);
                if (!accountIds.isEmpty()) {
                    testData.put("account_ids", accountIds);
                    testData.put("account_id", accountIds.get(0));
                    logDebug("Collected " + accountIds.size() + " real account IDs: " + accountIds);
                } else {
                    logDebug("No real account IDs found");
                }
            }
            
            // СОЗДАЕМ ТЕСТОВЫЕ ПРОДУКТЫ И ПОЛУЧАЕМ ИХ ID
            List<String> productIds = createTestProducts(baseUrl, config, apiClient);
            if (!productIds.isEmpty()) {
                testData.put("product_ids", productIds);
                testData.put("product_id", productIds.get(0));
                logDebug("Collected " + productIds.size() + " product IDs: " + productIds);
            } else {
                logDebug("No product IDs found - trying to get existing products");
                List<String> existingProductIds = getExistingProductIds(baseUrl, config, apiClient);
                if (!existingProductIds.isEmpty()) {
                    testData.put("product_ids", existingProductIds);
                    testData.put("product_id", existingProductIds.get(0));
                    logDebug("Using existing product IDs: " + existingProductIds);
                }
            }
            
        } catch (Exception e) {
            // Не логируем ошибки сбора тестовых данных
        }
        
        return testData;
    }

    private String createRealAccount(String baseUrl, ScanConfig config, ApiClient apiClient) {
        try {
            String accountsUrl = baseUrl + "/accounts";
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "curl/7.68.0");
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            
            // Используем client token для создания счета (свои счета)
            String clientToken = config.getUserToken("team172-8");
            if (clientToken != null) {
                headers.put("Authorization", "Bearer " + clientToken);
                
                String requestBody = "{\n" +
                    "  \"account_type\": \"checking\",\n" +
                    "  \"initial_balance\": 1000\n" +
                    "}";
                
                logDebug("Creating real account at: " + accountsUrl);
                Object response = apiClient.executeRequest("POST", accountsUrl, requestBody, headers);
                
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    int statusCode = apiResponse.getStatusCode();
                    
                    if (statusCode == 200 || statusCode == 201) {
                        String responseBody = apiResponse.getBody();
                        
                        // Парсим account_id из ответа
                        String accountId = extractAccountId(responseBody);
                        if (accountId != null) {
                            logSuccess("✅ Successfully created account with ID: " + accountId);
                            return accountId;
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            // Не логируем ошибки создания счета
        }
        return null;
    }

    // НОВЫЙ МЕТОД: Извлечение account_id из ответа
    private String extractAccountId(String responseBody) {
        if (responseBody == null) return null;
        
        // Пробуем разные варианты извлечения account_id
        String[] possibleFields = {"accountId", "account_id", "id"};
        for (String field : possibleFields) {
            if (responseBody.contains(field)) {
                int start = responseBody.indexOf("\"" + field + "\"") + ("\"" + field + "\"").length();
                start = responseBody.indexOf("\"", start) + 1;
                int end = responseBody.indexOf("\"", start);
                if (start > 0 && end > start) {
                    String accountId = responseBody.substring(start, end);
                    if (accountId.startsWith("acc-")) {
                        return accountId;
                    }
                }
            }
        }
        return null;
    }

    // НОВЫЙ МЕТОД: Создание тестовых продуктов
    private List<String> createTestProducts(String baseUrl, ScanConfig config, ApiClient apiClient) {
        List<String> productIds = new ArrayList<>();
        
        try {
            String productsUrl = baseUrl + "/products";
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "curl/7.68.0");
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            
            // Используем bank token для создания продуктов (требует повышенных привилегий)
            String bankToken = config.getUserToken("bank_token");
            if (bankToken != null) {
                headers.put("Authorization", "Bearer " + bankToken);
                
                // Создаем тестовый депозитный продукт
                String depositProductBody = "{" +
                    "\"productType\": \"deposit\"," +
                    "\"productName\": \"Тестовый вклад для сканирования\"," +
                    "\"description\": \"Вклад создан для тестирования API безопасности\"," +
                    "\"interestRate\": 5.5," +
                    "\"minAmount\": 1000," +
                    "\"maxAmount\": 100000," +
                    "\"termMonths\": 12," +
                    "\"currency\": \"RUB\"," +
                    "\"features\": [\"пополнение\", \"капитализация\"]," +
                    "\"isTestProduct\": true" +
                    "}";
                
                logDebug("Creating test deposit product at: " + productsUrl);
                Object response = apiClient.executeRequest("POST", productsUrl, depositProductBody, headers);
                
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    int statusCode = apiResponse.getStatusCode();
                    
                    if (statusCode == 200 || statusCode == 201) {
                        String responseBody = apiResponse.getBody();
                        
                        // Парсим productId из ответа
                        String productId = extractProductId(responseBody);
                        if (productId != null) {
                            productIds.add(productId);
                            logSuccess("✅ Successfully created deposit product with ID: " + productId);
                        }
                    }
                }
                
                // Создаем тестовый кредитный продукт
                String loanProductBody = "{" +
                    "\"productType\": \"loan\"," +
                    "\"productName\": \"Тестовый кредит для сканирования\"," +
                    "\"description\": \"Кредит создан для тестирования API безопасности\"," +
                    "\"interestRate\": 15.9," +
                    "\"minAmount\": 5000," +
                    "\"maxAmount\": 500000," +
                    "\"termMonths\": 36," +
                    "\"currency\": \"RUB\"," +
                    "\"loanPurpose\": \"потребительский\"," +
                    "\"isTestProduct\": true" +
                    "}";
                
                logDebug("Creating test loan product at: " + productsUrl);
                response = apiClient.executeRequest("POST", productsUrl, loanProductBody, headers);
                
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    int statusCode = apiResponse.getStatusCode();
                    
                    if (statusCode == 200 || statusCode == 201) {
                        String responseBody = apiResponse.getBody();
                        
                        // Парсим productId из ответа
                        String productId = extractProductId(responseBody);
                        if (productId != null) {
                            productIds.add(productId);
                            logSuccess("✅ Successfully created loan product with ID: " + productId);
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            // Не логируем ошибки создания продуктов
        }
        
        return productIds;
    }

    // НОВЫЙ МЕТОД: Получение существующих продуктов
    private List<String> getExistingProductIds(String baseUrl, ScanConfig config, ApiClient apiClient) {
        List<String> productIds = new ArrayList<>();
        
        try {
            String productsUrl = baseUrl + "/products";
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "curl/7.68.0");
            headers.put("Accept", "application/json");
            
            // Используем client token для получения продуктов
            String clientToken = config.getUserToken("team172-8");
            if (clientToken != null) {
                headers.put("Authorization", "Bearer " + clientToken);
                
                logDebug("Fetching existing products from: " + productsUrl);
                Object response = apiClient.executeRequest("GET", productsUrl, null, headers);
                
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    int statusCode = apiResponse.getStatusCode();
                    
                    if (statusCode == 200) {
                        String responseBody = apiResponse.getBody();
                        
                        // Парсим productId из ответа
                        if (responseBody != null && responseBody.contains("productId")) {
                            String[] parts = responseBody.split("\"productId\"");
                            for (int i = 1; i < parts.length; i++) {
                                String part = parts[i];
                                int start = part.indexOf("\"") + 1;
                                int end = part.indexOf("\"", start);
                                if (start > 0 && end > start) {
                                    String productId = part.substring(start, end);
                                    if (productId.startsWith("prod-") || productId.startsWith("product-")) {
                                        productIds.add(productId);
                                    }
                                }
                            }
                        }
                        
                        // Если не нашли в стандартном формате, пробуем альтернативный
                        if (productIds.isEmpty() && responseBody != null) {
                            // Пробуем найти в массиве
                            String[] productEntries = responseBody.split("\\{");
                            for (String entry : productEntries) {
                                if (entry.contains("\"id\"")) {
                                    int start = entry.indexOf("\"id\"") + "\"id\"".length();
                                    start = entry.indexOf("\"", start) + 1;
                                    int end = entry.indexOf("\"", start);
                                    if (start > 0 && end > start) {
                                        String productId = entry.substring(start, end);
                                        productIds.add(productId);
                                    }
                                }
                            }
                        }
                        
                        if (!productIds.isEmpty()) {
                            logSuccess("✅ Successfully fetched " + productIds.size() + " existing product IDs");
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            // Не логируем ошибки получения продуктов
        }
        
        return productIds;
    }

    // НОВЫЙ МЕТОД: Извлечение productId из ответа
    private String extractProductId(String responseBody) {
        if (responseBody == null) return null;
        
        // Пробуем разные варианты извлечения product_id
        String[] possibleFields = {"productId", "product_id", "id"};
        for (String field : possibleFields) {
            if (responseBody.contains(field)) {
                int start = responseBody.indexOf("\"" + field + "\"") + ("\"" + field + "\"").length();
                start = responseBody.indexOf("\"", start) + 1;
                int end = responseBody.indexOf("\"", start);
                if (start > 0 && end > start) {
                    String productId = responseBody.substring(start, end);
                    if (!productId.isEmpty()) {
                        return productId;
                    }
                }
            }
        }
        return null;
    }

    private String getRealBankToken(String baseUrl, ScanConfig config, ApiClient apiClient) {
        try {
            String authUrl = baseUrl + "/auth/bank-token";
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "curl/7.68.0");
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            
            // Используем реальные credentials из конфигурации
            String clientId = "team172"; // Базовый ID команды без суффикса
            String clientSecret = config.getPassword();
            
            String fullUrl = authUrl + "?client_id=" + clientId + "&client_secret=" + clientSecret;
            
            logDebug("Getting real bank token from: " + authUrl);
            Object response = apiClient.executeRequest("POST", fullUrl, "", headers);
            
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                int statusCode = apiResponse.getStatusCode();
                
                if (statusCode == 200) {
                    String responseBody = apiResponse.getBody();
                    
                    // Парсим access_token из ответа
                    if (responseBody != null && responseBody.contains("access_token")) {
                        int start = responseBody.indexOf("\"access_token\"") + "\"access_token\"".length();
                        start = responseBody.indexOf("\"", start) + 1;
                        int end = responseBody.indexOf("\"", start);
                        if (start > 0 && end > start) {
                            String token = responseBody.substring(start, end);
                            logSuccess("✅ Successfully obtained real bank token");
                            return token;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Не логируем ошибки получения токена
        }
        return null;
    }

    private List<String> getRealAccountIds(String baseUrl, ScanConfig config, ApiClient apiClient) {
        List<String> accountIds = new ArrayList<>();
        
        try {
            String accountsUrl = baseUrl + "/accounts";
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "curl/7.68.0");
            headers.put("Accept", "application/json");
            
            // Сначала пробуем с client token для получения собственных счетов
            String clientToken = config.getUserToken("team172-8");
            if (clientToken != null) {
                headers.put("Authorization", "Bearer " + clientToken);
                
                logDebug("Fetching account IDs with client token from: " + accountsUrl);
                Object response = apiClient.executeRequest("GET", accountsUrl, null, headers);
                
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    int statusCode = apiResponse.getStatusCode();
                    
                    if (statusCode == 200) {
                        String responseBody = apiResponse.getBody();
                        
                        // Парсим JSON для извлечения account_id
                        if (responseBody != null && responseBody.contains("accountId")) {
                            String[] parts = responseBody.split("\"accountId\"");
                            for (int i = 1; i < parts.length; i++) {
                                String part = parts[i];
                                int start = part.indexOf("\"") + 1;
                                int end = part.indexOf("\"", start);
                                if (start > 0 && end > start) {
                                    String accountId = part.substring(start, end);
                                    if (accountId.startsWith("acc-")) {
                                        accountIds.add(accountId);
                                    }
                                }
                            }
                        }
                        
                        if (!accountIds.isEmpty()) {
                            logSuccess("✅ Successfully fetched " + accountIds.size() + " account IDs with client token");
                        }
                    }
                }
            }
            
            // Если не нашли своих счетов, пробуем межбанковый запрос с bank token
            if (accountIds.isEmpty()) {
                String bankToken = config.getUserToken("bank_token");
                if (bankToken != null) {
                    headers.put("Authorization", "Bearer " + bankToken);
                    headers.put("X-Requesting-Bank", "team172");
                    
                    // Добавляем client_id в query параметры для межбанкового запроса
                    String interbankAccountsUrl = accountsUrl + "?client_id=team172-1";
                    
                    logDebug("Fetching account IDs with bank token from: " + interbankAccountsUrl);
                    Object response = apiClient.executeRequest("GET", interbankAccountsUrl, null, headers);
                    
                    if (response instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                        int statusCode = apiResponse.getStatusCode();
                        
                        if (statusCode == 200) {
                            String responseBody = apiResponse.getBody();
                            
                            // Парсим JSON для извлечения account_id
                            if (responseBody != null && responseBody.contains("accountId")) {
                                String[] parts = responseBody.split("\"accountId\"");
                                for (int i = 1; i < parts.length; i++) {
                                    String part = parts[i];
                                    int start = part.indexOf("\"") + 1;
                                    int end = part.indexOf("\"", start);
                                    if (start > 0 && end > start) {
                                        String accountId = part.substring(start, end);
                                        if (accountId.startsWith("acc-")) {
                                            accountIds.add(accountId);
                                        }
                                    }
                                }
                            }
                            
                            if (!accountIds.isEmpty()) {
                                logSuccess("✅ Successfully fetched " + accountIds.size() + " account IDs with bank token");
                            }
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            // Не логируем ошибки получения счетов
        }
        
        return accountIds;
    }

    private String createRealConsent(String baseUrl, ScanConfig config, ApiClient apiClient) {
        try {
            String consentUrl = baseUrl + "/account-consents/request";
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "curl/7.68.0");
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            
            // Используем bank token для создания согласия
            String bankToken = config.getUserToken("bank_token");
            if (bankToken != null) {
                headers.put("Authorization", "Bearer " + bankToken);
                headers.put("X-Requesting-Bank", "team172");
                
                String requestBody = "{" +
                    "\"client_id\": \"team172-1\"," +
                    "\"permissions\": [\"ReadAccountsDetail\", \"ReadBalances\", \"ReadTransactionsDetail\"]," +
                    "\"reason\": \"Security testing for contract validation\"," +
                    "\"requesting_bank\": \"team172\"," +
                    "\"requesting_bank_name\": \"Security Scanner\"" +
                    "}";
                
                logDebug("Creating real consent at: " + consentUrl);
                Object response = apiClient.executeRequest("POST", consentUrl, requestBody, headers);
                
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    int statusCode = apiResponse.getStatusCode();
                    
                    if (statusCode == 200) {
                        String responseBody = apiResponse.getBody();
                        
                        // Парсим JSON для извлечения consent_id
                        if (responseBody != null) {
                            // Пробуем разные варианты извлечения consent_id
                            String[] possibleFields = {"consent_id", "consentId"};
                            for (String field : possibleFields) {
                                if (responseBody.contains(field)) {
                                    int start = responseBody.indexOf("\"" + field + "\"") + ("\"" + field + "\"").length();
                                    start = responseBody.indexOf("\"", start) + 1;
                                    int end = responseBody.indexOf("\"", start);
                                    if (start > 0 && end > start) {
                                        String consentId = responseBody.substring(start, end);
                                        if (consentId.startsWith("consent-")) {
                                            logSuccess("✅ Successfully created real consent with ID: " + consentId);
                                            return consentId;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            // Не логируем ошибки создания согласия
        }
        
        return null;
    }

    private boolean testBasicConnectivity(String baseUrl, ApiClient apiClient) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "curl/7.68.0");
            headers.put("Accept", "*/*");
            
            String testUrl = baseUrl + "/health";
            logDebug("Testing basic connectivity to: " + testUrl);
            
            Object response = apiClient.executeRequest("GET", testUrl, null, headers);
            
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                int statusCode = apiResponse.getStatusCode();
                
                if (statusCode == 200) {
                    logSuccess("✅ Basic connectivity test passed - API server is accessible");
                    return true;
                }
            }
        } catch (Exception e) {
            // Не логируем ошибки проверки connectivity
        }
        return false;
    }

    private List<Vulnerability> validateSpecificationCompleteness(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        Map<String, PathItem> paths = openAPI.getPaths();
        
        if (paths == null || paths.isEmpty()) {
            vulnerabilities.add(createVulnerability(
                "No Paths Defined in OpenAPI Specification",
                "OpenAPI specification does not contain any API endpoints",
                Vulnerability.Severity.HIGH,
                "N/A", "N/A",
                "Paths object is null or empty in OpenAPI spec"
            ));
            return vulnerabilities;
        }

        logDebug("Checking specification completeness for " + paths.size() + " paths");
        
        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            
            for (Map.Entry<PathItem.HttpMethod, Operation> operationEntry : getOperations(pathItem).entrySet()) {
                PathItem.HttpMethod method = operationEntry.getKey();
                Operation operation = operationEntry.getValue();
                
                // Check for operationId
                if (operation.getOperationId() == null || operation.getOperationId().trim().isEmpty()) {
                    vulnerabilities.add(createVulnerability(
                        "Missing Operation ID in OpenAPI Specification",
                        "API operation is missing operationId in OpenAPI specification",
                        Vulnerability.Severity.LOW,
                        path, method.name(),
                        "No operationId defined for " + method.name() + " " + path
                    ));
                }
                
                // Check for response definitions
                if (operation.getResponses() == null || operation.getResponses().isEmpty()) {
                    vulnerabilities.add(createVulnerability(
                        "Missing Response Definitions",
                        "API operation has no response definitions in OpenAPI specification",
                        Vulnerability.Severity.MEDIUM,
                        path, method.name(),
                        "No responses defined for " + method.name() + " " + path
                    ));
                }
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> validateDocumentedEndpoints(OpenAPI openAPI, String baseUrl, ScanConfig config, 
                                                          ApiClient apiClient, Map<String, Object> testData) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        Map<String, PathItem> paths = openAPI.getPaths();
        
        if (paths == null) return vulnerabilities;
        
        logDebug("Testing " + paths.size() + " documented endpoints with real test data");
        
        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            
            for (Map.Entry<PathItem.HttpMethod, Operation> operationEntry : getOperations(pathItem).entrySet()) {
                PathItem.HttpMethod method = operationEntry.getKey();
                Operation operation = operationEntry.getValue();
                
                testDocumentedEndpoint(path, method.name(), operation, openAPI, baseUrl, config, apiClient, vulnerabilities, testData);
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> validateStandardEndpoints(OpenAPI openAPI, String baseUrl, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        String[] standardEndpoints = {
            "/health",
            "/.well-known/jwks.json",
            "/",
            "/openapi.json"
        };
        
        logDebug("Testing " + standardEndpoints.length + " standard endpoints");
        
        for (String endpoint : standardEndpoints) {
            testStandardEndpoint(endpoint, openAPI, baseUrl, apiClient, vulnerabilities);
        }
        
        return vulnerabilities;
    }

    private void testDocumentedEndpoint(String path, String method, Operation operation, 
                                      OpenAPI openAPI, String baseUrl, ScanConfig config,
                                      ApiClient apiClient, List<Vulnerability> vulnerabilities, 
                                      Map<String, Object> testData) {
        
        // Пропускаем endpoints, для которых нет реальных данных
        if (shouldSkipEndpoint(path, method, testData)) {
            logDebug("Skipping endpoint " + method + " " + path + " - no real data available");
            return;
        }
        
        // Заменяем path parameters на реальные значения
        String resolvedPath = resolvePathParameters(path, testData);
        if (resolvedPath == null) {
            logDebug("Skipping endpoint " + method + " " + path + " - cannot resolve path parameters");
            return;
        }
        
        String fullUrl = buildUrlWithParameters(baseUrl + resolvedPath, operation, testData);
        
        // Получаем правильный токен для endpoint
        String authToken = getAppropriateAuthToken(config, operation, path, testData);
        Map<String, String> headers = buildCorrectHeaders(operation, path, testData, authToken);
        
        try {
            logDebug("Testing documented endpoint: " + method + " " + resolvedPath + 
                    (authToken != null ? " (with auth)" : " (without auth)"));
            
            String requestBody = buildCorrectRequestBody(operation, path, testData);
            Object response = apiClient.executeRequest(method, fullUrl, requestBody, headers);
            
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                int statusCode = apiResponse.getStatusCode();
                
                // ВЫВОДИМ ТОЛЬКО УСПЕШНЫЕ ЗАПРОСЫ (200)
                if (statusCode == 200) {
                    logSuccess("✅ Endpoint " + method + " " + resolvedPath + " is accessible (status: " + statusCode + ")");
                }
                
                // Анализируем ответ (даже для ошибок, но не выводим в консоль)
                analyzeResponse(path, method, statusCode, requiresAuthentication(operation, openAPI), 
                              requiresInterbankHeaders(operation, path), vulnerabilities);
            }
        } catch (Exception e) {
            // Не логируем ошибки тестирования endpoints
        }
    }

    private boolean shouldSkipEndpoint(String path, String method, Map<String, Object> testData) {
        // Пропускаем endpoints, для которых нужны специальные данные, которых у нас нет
        if (path.contains("{card_id}") || path.contains("{payment_id}") || path.contains("{agreement_id}")) {
            return true;
        }
        
        // НЕ пропускаем product_id endpoints - у нас теперь есть тестовые данные
        if (path.contains("{product_id}")) {
            return testData.get("product_id") == null;
        }
        
        // Пропускаем POST /auth/bank-token - он требует специальных параметров
        if (path.equals("/auth/bank-token") && "POST".equals(method)) {
            return true;
        }
        
        // Пропускаем endpoints, требующие согласия, если его нет
        if (requiresConsent(path) && testData.get("consent_id") == null) {
            return true;
        }
        
        // Пропускаем endpoints, требующие account_id, если его нет
        if (requiresAccountId(path) && testData.get("account_id") == null) {
            return true;
        }
        
        return false;
    }

    private boolean requiresConsent(String path) {
        return path.contains("/accounts") && !path.equals("/accounts") ||
               path.contains("/cards") || path.contains("/payments");
    }

    private boolean requiresAccountId(String path) {
        return path.contains("{account_id}") || 
               path.contains("/accounts/") && !path.equals("/accounts");
    }

    private String resolvePathParameters(String path, Map<String, Object> testData) {
        // Заменяем параметры пути на реальные значения
        String resolvedPath = path;
        
        if (path.contains("{account_id}")) {
            String accountId = (String) testData.get("account_id");
            if (accountId != null) {
                resolvedPath = resolvedPath.replace("{account_id}", accountId);
            } else {
                return null;
            }
        }
        
        if (path.contains("{consent_id}")) {
            String consentId = (String) testData.get("consent_id");
            if (consentId != null) {
                resolvedPath = resolvedPath.replace("{consent_id}", consentId);
            } else {
                return null;
            }
        }
        
        // ДОБАВЛЯЕМ ОБРАБОТКУ product_id
        if (path.contains("{product_id}")) {
            String productId = (String) testData.get("product_id");
            if (productId != null) {
                resolvedPath = resolvedPath.replace("{product_id}", productId);
            } else {
                return null;
            }
        }
        
        return resolvedPath;
    }

    private String buildUrlWithParameters(String baseUrl, Operation operation, Map<String, Object> testData) {
        // For GET requests, add appropriate query parameters
        if (operation.getParameters() != null) {
            StringBuilder urlBuilder = new StringBuilder(baseUrl);
            boolean firstParam = true;
            
            for (Parameter param : operation.getParameters()) {
                if ("query".equals(param.getIn())) {
                    if (firstParam) {
                        urlBuilder.append("?");
                        firstParam = false;
                    } else {
                        urlBuilder.append("&");
                    }
                    
                    String paramName = param.getName();
                    String realValue = getRealParameterValue(param, testData);
                    if (realValue != null) {
                        urlBuilder.append(paramName).append("=").append(realValue);
                    }
                }
            }
            return urlBuilder.toString();
        }
        return baseUrl;
    }

    private String buildCorrectRequestBody(Operation operation, String path, Map<String, Object> testData) {
        // Create appropriate request body using real data
        if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            
            if (path.equals("/account-consents/request")) {
                return "{\n" +
                       "  \"client_id\": \"team172-1\",\n" +
                       "  \"permissions\": [\"ReadAccountsDetail\", \"ReadBalances\", \"ReadTransactionsDetail\"],\n" +
                       "  \"reason\": \"Security testing\",\n" +
                       "  \"requesting_bank\": \"team172\",\n" +
                       "  \"requesting_bank_name\": \"Security Scanner\"\n" +
                       "}";
            }
            
            if (path.equals("/accounts") && "POST".equals(operation.getOperationId())) {
                return "{\n" +
                       "  \"account_type\": \"checking\",\n" +
                       "  \"initial_balance\": 0\n" +
                       "}";
            }
            
            if (path.contains("/status")) {
                return "{\n" +
                       "  \"status\": \"active\"\n" +
                       "}";
            }
            
            if (path.contains("/close")) {
                return "{\n" +
                       "  \"action\": \"donate\"\n" +
                       "}";
            }
            
            if (path.equals("/payment-consents/request")) {
                String accountId = (String) testData.get("account_id");
                return "{\n" +
                       "  \"requesting_bank\": \"team172\",\n" +
                       "  \"client_id\": \"team172-1\",\n" +
                       "  \"consent_type\": \"single_use\",\n" +
                       "  \"amount\": 100.00,\n" +
                       "  \"currency\": \"RUB\",\n" +
                       "  \"debtor_account\": \"" + (accountId != null ? accountId : "acc-test") + "\",\n" +
                       "  \"reference\": \"Test payment\"\n" +
                       "}";
            }
            
            if (path.equals("/payments") && "POST".equals(operation.getOperationId())) {
                String accountId = (String) testData.get("account_id");
                return "{\n" +
                       "  \"data\": {\n" +
                       "    \"initiation\": {\n" +
                       "      \"instructedAmount\": {\n" +
                       "        \"amount\": \"100.00\",\n" +
                       "        \"currency\": \"RUB\"\n" +
                       "      },\n" +
                       "      \"debtorAccount\": {\n" +
                       "        \"schemeName\": \"RU.CBR.PAN\",\n" +
                       "        \"identification\": \"" + (accountId != null ? accountId : "acc-test") + "\"\n" +
                       "      },\n" +
                       "      \"creditorAccount\": {\n" +
                       "        \"schemeName\": \"RU.CBR.PAN\", \n" +
                       "        \"identification\": \"40817810099910005423\"\n" +
                       "      },\n" +
                       "      \"comment\": \"Test payment\"\n" +
                       "    }\n" +
                       "  }\n" +
                       "}";
            }
            
            // ДОБАВЛЯЕМ ТЕЛО ДЛЯ СОЗДАНИЯ ПРОДУКТОВЫХ СОГЛАШЕНИЙ
            if (path.equals("/product-agreements") && "POST".equals(operation.getOperationId())) {
                String productId = (String) testData.get("product_id");
                String accountId = (String) testData.get("account_id");
                return "{\n" +
                       "  \"product_id\": \"" + (productId != null ? productId : "prod-test-001") + "\",\n" +
                       "  \"account_id\": \"" + (accountId != null ? accountId : "acc-test") + "\",\n" +
                       "  \"amount\": 5000,\n" +
                       "  \"term_months\": 12,\n" +
                       "  \"auto_renewal\": false\n" +
                       "}";
            }
            
            if (path.equals("/product-agreement-consents/request")) {
                String productId = (String) testData.get("product_id");
                return "{\n" +
                       "  \"product_id\": \"" + (productId != null ? productId : "prod-test-001") + "\",\n" +
                       "  \"client_id\": \"team172-1\",\n" +
                       "  \"permissions\": [\"ReadProductDetails\", \"ManageProduct\"],\n" +
                       "  \"reason\": \"Security testing\",\n" +
                       "  \"requesting_bank\": \"team172\"\n" +
                       "}";
            }
            
            // Return minimal JSON object as fallback
            return "{}";
        }
        return null;
    }

    private Map<String, String> buildCorrectHeaders(Operation operation, String path, Map<String, Object> testData, String authToken) {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "curl/7.68.0");
        headers.put("Accept", "application/json");
        
        if (authToken != null) {
            headers.put("Authorization", "Bearer " + authToken);
        }
        
        // Межбанковые заголовки ТОЛЬКО для создания согласий
        if (path.contains("/consents/request")) {
            headers.put("X-Requesting-Bank", "team172");
        }
        
        // Для POST/PUT/PATCH добавляем Content-Type
        String method = operation.getOperationId();
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            headers.put("Content-Type", "application/json");
        }
        
        return headers;
    }

    private String getRealParameterValue(Parameter param, Map<String, Object> testData) {
        // Provide real values based on parameter type and available test data
        String paramName = param.getName().toLowerCase();
        
        if (paramName.contains("client_id")) {
            return "team172-1"; // Используем реальный client_id
        } else if (paramName.contains("client_secret")) {
            return null; // Не передаем client_secret в query параметрах
        } else if (paramName.contains("account_id") && testData.containsKey("account_id")) {
            return (String) testData.get("account_id");
        } else if (paramName.contains("consent_id") && testData.containsKey("consent_id")) {
            return (String) testData.get("consent_id");
        } else if (paramName.contains("product_id") && testData.containsKey("product_id")) {
            return (String) testData.get("product_id");
        } else if (paramName.contains("product_type")) {
            return "deposit"; // Используем deposit как тестовый тип продукта
        } else if (paramName.contains("page")) {
            return "1";
        } else if (paramName.contains("limit")) {
            return "10";
        } else if (paramName.contains("show_full_number")) {
            return "false";
        }
        
        return null;
    }

    private boolean requiresAuthentication(Operation operation, OpenAPI openAPI) {
        // Check operation-level security
        if (operation.getSecurity() != null && !operation.getSecurity().isEmpty()) {
            return true;
        }
        
        // Check global security
        if (openAPI.getSecurity() != null && !openAPI.getSecurity().isEmpty()) {
            return true;
        }
        
        return false;
    }

    private boolean requiresInterbankHeaders(Operation operation, String path) {
        // Межбанковые заголовки нужны ТОЛЬКО для создания согласий
        return path.contains("/consents/request");
    }

    private String getAppropriateAuthToken(ScanConfig config, Operation operation, String path, Map<String, Object> testData) {
        // Bank token ТОЛЬКО для:
        // - получения банковского токена
        // - создания согласий
        if (path.equals("/auth/bank-token") || 
            path.contains("/consents/request")) {
            return config.getUserToken("bank_token");
        }
        
        // Client token для ВСЕГО остального:
        return config.getUserToken("team172-8");
    }

    private void analyzeResponse(String path, String method, int statusCode, boolean requiresAuth, 
                               boolean requiresInterbank, List<Vulnerability> vulnerabilities) {
        // Check if endpoint is accessible
        if (statusCode >= 400 && statusCode < 500) {
            if (statusCode == 401 || statusCode == 403) {
                if (!requiresAuth) {
                    vulnerabilities.add(createVulnerability(
                        "Unexpected Authentication Requirement",
                        "Endpoint requires authentication but is not marked as secured in OpenAPI",
                        Vulnerability.Severity.MEDIUM,
                        path, method,
                        "Endpoint " + method + " " + path + " returns " + statusCode + " but has no security requirement in spec"
                    ));
                } else if (requiresInterbank && statusCode == 403) {
                    vulnerabilities.add(createVulnerability(
                        "Missing Interbank Headers",
                        "Endpoint requires interbank headers but they are missing or incorrect",
                        Vulnerability.Severity.MEDIUM,
                        path, method,
                        "Interbank endpoint " + method + " " + path + " returns 403 - check X-Requesting-Bank and X-Consent-Id headers"
                    ));
                }
            } else if (statusCode == 422) {
                // 422 Validation Error - обычно проблема с request body
                vulnerabilities.add(createVulnerability(
                    "Request Validation Error",
                    "Endpoint returns validation error - check request body format",
                    Vulnerability.Severity.LOW,
                    path, method,
                    "Endpoint " + method + " " + path + " returns 422 Validation Error"
                ));
            } else if (statusCode != 404) { // 404 может быть нормальным для тестовых данных
                vulnerabilities.add(createVulnerability(
                    "Documented Endpoint Not Accessible",
                    "Endpoint documented in OpenAPI specification returns client error",
                    Vulnerability.Severity.MEDIUM,
                    path, method,
                    "Endpoint " + method + " " + path + " documented but returns " + statusCode
                ));
            }
        } else if (statusCode >= 500) {
            vulnerabilities.add(createVulnerability(
                "Documented Endpoint Server Error",
                "Endpoint documented in OpenAPI specification returns server error",
                Vulnerability.Severity.HIGH,
                path, method,
                "Endpoint " + method + " " + path + " documented but returns " + statusCode
            ));
        }
    }

    private void testStandardEndpoint(String endpoint, OpenAPI openAPI, String baseUrl, 
                                   ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        String fullUrl = baseUrl + endpoint;
        
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "curl/7.68.0");
        headers.put("Accept", "*/*");
        
        try {
            logDebug("Testing standard endpoint: GET " + endpoint);
            Object response = apiClient.executeRequest("GET", fullUrl, null, headers);
            
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                int statusCode = apiResponse.getStatusCode();
                
                boolean documented = isEndpointDocumented(endpoint, "GET", openAPI);
                boolean accessible = statusCode == 200 || statusCode == 201;
                
                // ВЫВОДИМ ТОЛЬКО УСПЕШНЫЕ ЗАПРОСЫ
                if (accessible) {
                    logSuccess("✅ Standard endpoint " + endpoint + " is accessible (status: " + statusCode + ")");
                }
                
                if (accessible && !documented) {
                    vulnerabilities.add(createVulnerability(
                        "Undocumented Public API Endpoint",
                        "Public API endpoint exists but is not documented in OpenAPI specification",
                        Vulnerability.Severity.MEDIUM,
                        endpoint, "GET",
                        "Public endpoint " + endpoint + " exists (status: " + statusCode + ") but not in OpenAPI spec"
                    ));
                } else if (!accessible && documented) {
                    vulnerabilities.add(createVulnerability(
                        "Documented Public Endpoint Not Accessible",
                        "Public API endpoint documented in OpenAPI specification is not accessible",
                        Vulnerability.Severity.HIGH,
                        endpoint, "GET",
                        "Public endpoint " + endpoint + " documented but returns " + statusCode
                    ));
                }
            }
        } catch (Exception e) {
            // Не логируем ошибки тестирования стандартных endpoints
        }
    }

    private Map<PathItem.HttpMethod, Operation> getOperations(PathItem pathItem) {
        Map<PathItem.HttpMethod, Operation> operations = new HashMap<>();
        
        if (pathItem.getGet() != null) operations.put(PathItem.HttpMethod.GET, pathItem.getGet());
        if (pathItem.getPost() != null) operations.put(PathItem.HttpMethod.POST, pathItem.getPost());
        if (pathItem.getPut() != null) operations.put(PathItem.HttpMethod.PUT, pathItem.getPut());
        if (pathItem.getDelete() != null) operations.put(PathItem.HttpMethod.DELETE, pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.put(PathItem.HttpMethod.PATCH, pathItem.getPatch());
        
        return operations;
    }

    private boolean isEndpointDocumented(String endpoint, String method, OpenAPI openAPI) {
        Map<String, PathItem> paths = openAPI.getPaths();
        if (paths == null) return false;
        
        PathItem pathItem = paths.get(endpoint);
        if (pathItem == null) return false;
        
        switch (method) {
            case "GET": return pathItem.getGet() != null;
            case "POST": return pathItem.getPost() != null;
            case "PUT": return pathItem.getPut() != null;
            case "DELETE": return pathItem.getDelete() != null;
            case "PATCH": return pathItem.getPatch() != null;
            default: return false;
        }
    }

    private Vulnerability createVulnerability(String title, String description, 
                                            Vulnerability.Severity severity, 
                                            String endpoint, String method, String evidence) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.CONTRACT_VALIDATION);
        vuln.setEndpoint(endpoint);
        vuln.setMethod(method);
        vuln.setEvidence(evidence);
        
        List<String> recommendations = new ArrayList<>();
        if (title.contains("Undocumented")) {
            recommendations.add("Document all existing API endpoints in OpenAPI specification");
            recommendations.add("Ensure specification reflects actual API capabilities");
        } else if (title.contains("Not Accessible")) {
            recommendations.add("Verify the endpoint is properly implemented on the server");
            recommendations.add("Check server configuration and routing");
            recommendations.add("Ensure authentication requirements are correctly configured");
        } else if (title.contains("Missing Operation ID")) {
            recommendations.add("Add unique operationId for each API operation");
            recommendations.add("Use meaningful operationId names (e.g., getAccounts, createPayment)");
        } else if (title.contains("Missing Response")) {
            recommendations.add("Define at least one response for each API operation");
            recommendations.add("Include both success (2xx) and error (4xx, 5xx) responses");
        } else if (title.contains("Unexpected Authentication")) {
            recommendations.add("Update OpenAPI specification to reflect actual security requirements");
            recommendations.add("Ensure security schemes are properly defined");
        } else if (title.contains("Missing Interbank Headers")) {
            recommendations.add("Add X-Requesting-Bank and X-Consent-Id headers for interbank requests");
            recommendations.add("Ensure consent is properly created and active");
        } else if (title.contains("Request Validation")) {
            recommendations.add("Check request body format and required fields");
            recommendations.add("Verify parameter types and constraints");
        } else if (title.contains("Server Error")) {
            recommendations.add("Check server implementation for the endpoint");
            recommendations.add("Verify backend services are running correctly");
        }
        
        vuln.setRecommendations(recommendations);
        return vuln;
    }

    private void logDebug(String message) {
        if (DEBUG) {
            System.out.println("[DEBUG Validation] " + message);
        }
    }

    // НОВЫЙ МЕТОД: вывод только успешных операций
    private void logSuccess(String message) {
        System.out.println("[SUCCESS Validation] " + message);
    }
}
