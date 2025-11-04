package scanners.owasp;

import core.*;
import scanners.SecurityScanner;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.MediaType;

import java.util.*;
import java.util.regex.Pattern;

@SuppressWarnings({"rawtypes", "unchecked"})
public class ContractValidationScanner implements SecurityScanner {

    @Override
    public String getName() {
        return "API Contract Validation Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Проверяем и приводим тип openApiObj к OpenAPI
        if (!(openApiObj instanceof OpenAPI)) {
            if (openApiObj == null) {
                vulnerabilities.add(createVulnerability(
                    "OpenAPI спецификация недоступна",
                    "Не удалось загрузить OpenAPI спецификацию для валидации контракта",
                    Vulnerability.Severity.HIGH,
                    "N/A"
                ));
            } else {
                vulnerabilities.add(createVulnerability(
                    "Неверный тип OpenAPI объекта",
                    "Ожидался OpenAPI, но получен: " + openApiObj.getClass().getName(),
                    Vulnerability.Severity.MEDIUM,
                    "N/A"
                ));
            }
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;

        try {
            log("🔍 Запуск валидации контракта API...");
            
            // Получаем базовый URL из конфигурации
            String baseUrl = config.getTargetBaseUrl();
            if (baseUrl == null || baseUrl.trim().isEmpty()) {
                vulnerabilities.add(createVulnerability(
                    "Базовый URL не задан",
                    "Не удалось выполнить валидацию контракта: отсутствует базовый URL",
                    Vulnerability.Severity.MEDIUM,
                    "N/A"
                ));
                return vulnerabilities;
            }

            // Получаем токен для аутентифицированных запросов
            String accessToken = getAccessToken(config);
            
            // Валидация путей API
            validateApiPaths(openAPI, baseUrl, accessToken, apiClient, vulnerabilities, config);
            
            // Валидация схем данных
            validateDataSchemas(openAPI, vulnerabilities);
            
            // Проверка обязательных эндпоинтов
            validateRequiredEndpoints(openAPI, vulnerabilities);
            
            log("✅ Валидация контракта завершена. Найдено проблем: " + vulnerabilities.size());
            
        } catch (Exception e) {
            vulnerabilities.add(createVulnerability(
                "Ошибка при валидации контракта",
                "Произошла ошибка во время проверки соответствия API спецификации: " + e.getMessage(),
                Vulnerability.Severity.MEDIUM,
                "N/A"
            ));
        }
        
        return vulnerabilities;
    }

    private void validateApiPaths(OpenAPI openAPI, String baseUrl, String accessToken, 
                                ApiClient apiClient, List<Vulnerability> vulnerabilities, ScanConfig config) {
        
        Map<String, PathItem> paths = openAPI.getPaths();
        Set<String> testedPaths = new HashSet<>();
        
        log("📊 Проверка путей API...");
        
        // Сначала получим реальные данные для параметров
        Map<String, String> testValues = getTestValues(baseUrl, accessToken, apiClient, config);
        
        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            
            // Пропускаем технические эндпоинты
            if (path.equals("/.well-known/jwks.json") || path.equals("/") || path.equals("/health")) {
                continue;
            }
            
            // Тестируем GET методы (наиболее безопасные)
            if (pathItem.getGet() != null) {
                testEndpoint("GET", path, pathItem.getGet(), baseUrl, accessToken, apiClient, vulnerabilities, testValues);
                testedPaths.add(path);
            }
            
            // Для POST методов делаем тестовые запросы с минимальными данными
            if (pathItem.getPost() != null && isSafeToTest(path)) {
                testPostEndpoint(path, pathItem.getPost(), baseUrl, accessToken, apiClient, vulnerabilities, testValues);
                testedPaths.add(path);
            }
        }
        
        // Проверяем отсутствующие, но важные эндпоинты
        checkMissingImportantEndpoints(testedPaths, vulnerabilities);
    }

    private Map<String, String> getTestValues(String baseUrl, String accessToken, ApiClient apiClient, ScanConfig config) {
        Map<String, String> testValues = new HashMap<>();
        
        // Базовые тестовые значения
        testValues.put("account_id", "acc-1010");
        testValues.put("consent_id", "consent-test-123");
        testValues.put("payment_id", "pay-test-123");
        testValues.put("product_id", "prod-vb-deposit-001");
        testValues.put("agreement_id", "agr-test-123");
        testValues.put("client_id", "team172-8");
        
        // Попробуем получить реальные account_id через API
        try {
            String accountsUrl = baseUrl + "/accounts";
            Map<String, String> headers = new HashMap<>();
            if (accessToken != null) {
                headers.put("Authorization", "Bearer " + accessToken);
            }
            
            Object response = apiClient.executeRequest("GET", accountsUrl, null, headers);
            if (response instanceof core.ApiResponse) {
                core.ApiResponse apiResponse = (core.ApiResponse) response;
                if (apiResponse.getStatusCode() == 200) {
                    String body = apiResponse.getBody();
                    // Парсим JSON чтобы найти account_id
                    if (body.contains("account_id")) {
                        Pattern pattern = Pattern.compile("\"account_id\"\\s*:\\s*\"([^\"]+)\"");
                        java.util.regex.Matcher matcher = pattern.matcher(body);
                        if (matcher.find()) {
                            String realAccountId = matcher.group(1);
                            testValues.put("account_id", realAccountId);
                            log("✅ Найден реальный account_id: " + realAccountId);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log("⚠ Не удалось получить реальные account_id, используем тестовые");
        }
        
        return testValues;
    }

    private void testEndpoint(String method, String path, Operation operation, 
                            String baseUrl, String accessToken, ApiClient apiClient,
                            List<Vulnerability> vulnerabilities, Map<String, String> testValues) {
        
        try {
            // Заменяем параметры в пути на тестовые значения
            String resolvedPath = resolvePathParameters(path, testValues);
            String fullUrl = baseUrl + resolvedPath;
            
            Map<String, String> headers = new HashMap<>();
            
            // Добавляем авторизацию если требуется
            if (operation.getSecurity() != null && !operation.getSecurity().isEmpty()) {
                if (accessToken != null) {
                    headers.put("Authorization", "Bearer " + accessToken);
                }
            }
            
            // Добавляем обязательные заголовки из спецификации
            addRequiredHeaders(operation, headers);
            
            // Добавляем query параметры
            String urlWithParams = addQueryParameters(fullUrl, operation, testValues);
            
            // Выполняем запрос
            Object response = apiClient.executeRequest(method, urlWithParams, null, headers);
            
            if (response instanceof core.ApiResponse) {
                core.ApiResponse apiResponse = (core.ApiResponse) response;
                validateResponse(operation, apiResponse, method, path, vulnerabilities);
            }
            
            // Небольшая задержка между запросами
            Thread.sleep(500);
            
        } catch (Exception e) {
            vulnerabilities.add(createVulnerability(
                "Ошибка при тестировании эндпоинта",
                "Метод: " + method + ", Путь: " + path + ", Ошибка: " + e.getMessage(),
                Vulnerability.Severity.LOW,
                path
            ));
        }
    }

    private void testPostEndpoint(String path, Operation operation, String baseUrl, 
                                String accessToken, ApiClient apiClient,
                                List<Vulnerability> vulnerabilities, Map<String, String> testValues) {
        
        try {
            // Заменяем параметры в пути на тестовые значения
            String resolvedPath = resolvePathParameters(path, testValues);
            String fullUrl = baseUrl + resolvedPath;
            
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            
            // Добавляем авторизацию если требуется
            if (operation.getSecurity() != null && !operation.getSecurity().isEmpty()) {
                if (accessToken != null) {
                    headers.put("Authorization", "Bearer " + accessToken);
                }
            }
            
            // Создаем минимальное тело запроса на основе схемы
            String requestBody = createMinimalRequestBody(operation, testValues);
            
            // Добавляем query параметры
            String urlWithParams = addQueryParameters(fullUrl, operation, testValues);
            
            // Выполняем запрос
            Object response = apiClient.executeRequest("POST", urlWithParams, requestBody, headers);
            
            if (response instanceof core.ApiResponse) {
                core.ApiResponse apiResponse = (core.ApiResponse) response;
                validateResponse(operation, apiResponse, "POST", path, vulnerabilities);
            }
            
            // Небольшая задержка между запросами
            Thread.sleep(500);
            
        } catch (Exception e) {
            vulnerabilities.add(createVulnerability(
                "Ошибка при тестировании POST эндпоинта",
                "Путь: " + path + ", Ошибка: " + e.getMessage(),
                Vulnerability.Severity.LOW,
                path
            ));
        }
    }

    private String resolvePathParameters(String path, Map<String, String> testValues) {
        String resolvedPath = path;
        // Заменяем {param} на значения из testValues
        for (Map.Entry<String, String> entry : testValues.entrySet()) {
            String paramPlaceholder = "{" + entry.getKey() + "}";
            if (resolvedPath.contains(paramPlaceholder)) {
                resolvedPath = resolvedPath.replace(paramPlaceholder, entry.getValue());
            }
        }
        return resolvedPath;
    }

    private String addQueryParameters(String url, Operation operation, Map<String, String> testValues) {
        if (operation.getParameters() == null) {
            return url;
        }
        
        StringBuilder urlBuilder = new StringBuilder(url);
        boolean firstParam = true;
        
        for (Parameter param : operation.getParameters()) {
            if ("query".equals(param.getIn()) && param.getRequired() != null && param.getRequired()) {
                String paramName = param.getName();
                String paramValue = testValues.getOrDefault(paramName, "test-value");
                
                if (firstParam) {
                    urlBuilder.append("?");
                    firstParam = false;
                } else {
                    urlBuilder.append("&");
                }
                
                urlBuilder.append(paramName).append("=").append(paramValue);
            }
        }
        
        return urlBuilder.toString();
    }

    private void validateResponse(Operation operation, core.ApiResponse apiResponse,
                                String method, String path, List<Vulnerability> vulnerabilities) {
        
        int statusCode = apiResponse.getStatusCode();
        
        // Проверяем, что статус код соответствует ожидаемым в спецификации
        Map<String, ApiResponse> expectedResponses = operation.getResponses();
        boolean isValidStatus = false;
        
        for (String expectedStatus : expectedResponses.keySet()) {
            if (matchesStatusCode(expectedStatus, statusCode)) {
                isValidStatus = true;
                break;
            }
        }
        
        if (!isValidStatus && statusCode >= 400) {
            vulnerabilities.add(createVulnerability(
                "Неожиданный статус код",
                method + " " + path + " вернул " + statusCode + ", но в спецификации не описаны такие коды ошибок. Тело ответа: " + 
                (apiResponse.getBody() != null ? apiResponse.getBody().substring(0, Math.min(100, apiResponse.getBody().length())) : "пусто"),
                statusCode == 500 ? Vulnerability.Severity.HIGH : Vulnerability.Severity.MEDIUM,
                path
            ));
        } else if (statusCode >= 200 && statusCode < 300) {
            // Для успешных ответов проверяем Content-Type
            validateContentType(apiResponse, operation, path, vulnerabilities);
        }
    }

    private boolean matchesStatusCode(String expectedStatus, int actualStatus) {
        if (expectedStatus.equals("default")) return true;
        if (expectedStatus.equals(String.valueOf(actualStatus))) return true;
        
        // Проверяем диапазоны (2xx, 4xx и т.д.)
        if (expectedStatus.endsWith("xx")) {
            int rangeStart = Integer.parseInt(expectedStatus.substring(0, 1)) * 100;
            int rangeEnd = rangeStart + 99;
            return actualStatus >= rangeStart && actualStatus <= rangeEnd;
        }
        
        return false;
    }

    private void validateContentType(core.ApiResponse apiResponse, Operation operation, 
                                   String path, List<Vulnerability> vulnerabilities) {
        
        Map<String, List<String>> headers = apiResponse.getHeaders();
        List<String> contentTypes = headers.get("Content-Type");
        
        if (contentTypes == null || contentTypes.isEmpty()) {
            vulnerabilities.add(createVulnerability(
                "Отсутствует Content-Type",
                "Эндпоинт " + path + " не возвращает заголовок Content-Type",
                Vulnerability.Severity.LOW,
                path
            ));
            return;
        }
        
        String contentType = contentTypes.get(0);
        Map<String, ApiResponse> expectedResponses = operation.getResponses();
        
        // Проверяем, что Content-Type соответствует спецификации
        boolean isValidContentType = false;
        for (ApiResponse expectedResponse : expectedResponses.values()) {
            if (expectedResponse.getContent() != null) {
                for (String mediaType : expectedResponse.getContent().keySet()) {
                    if (contentType.contains(mediaType) || mediaType.equals("*/*")) {
                        isValidContentType = true;
                        break;
                    }
                }
            }
            if (isValidContentType) break;
        }
        
        if (!isValidContentType) {
            vulnerabilities.add(createVulnerability(
                "Несоответствующий Content-Type",
                "Эндпоинт " + path + " вернул Content-Type: " + contentType + ", но в спецификации не указан этот тип",
                Vulnerability.Severity.MEDIUM,
                path
            ));
        }
    }

    private void validateDataSchemas(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        log("📋 Проверка схем данных...");
        
        if (openAPI.getComponents() == null || openAPI.getComponents().getSchemas() == null) {
            vulnerabilities.add(createVulnerability(
                "Отсутствуют схемы данных",
                "В OpenAPI спецификации не определены схемы данных (components.schemas)",
                Vulnerability.Severity.MEDIUM,
                "components/schemas"
            ));
            return;
        }
        
        Map<String, Schema> schemas = openAPI.getComponents().getSchemas();
        
        // Проверяем наличие ключевых схем
        checkRequiredSchemas(schemas, vulnerabilities);
        
        // Проверяем целостность схем
        for (Map.Entry<String, Schema> schemaEntry : schemas.entrySet()) {
            validateSchemaStructure(schemaEntry.getKey(), schemaEntry.getValue(), vulnerabilities);
        }
    }

    private void checkRequiredSchemas(Map<String, Schema> schemas, List<Vulnerability> vulnerabilities) {
        String[] requiredSchemas = {
            "ConsentRequestBody", "PaymentRequest", "ProductAgreementRequest",
            "AccountCloseRequest", "CreateAccountRequest"
        };
        
        for (String schemaName : requiredSchemas) {
            if (!schemas.containsKey(schemaName)) {
                vulnerabilities.add(createVulnerability(
                    "Отсутствует обязательная схема",
                    "В спецификации отсутствует схема: " + schemaName,
                    Vulnerability.Severity.MEDIUM,
                    "components/schemas/" + schemaName
                ));
            }
        }
    }

    private void validateSchemaStructure(String schemaName, Schema schema, List<Vulnerability> vulnerabilities) {
        // Проверяем наличие обязательных свойств для известных схем
        switch (schemaName) {
            case "ConsentRequestBody":
                validateConsentSchema(schema, vulnerabilities);
                break;
            case "PaymentRequest":
                validatePaymentSchema(schema, vulnerabilities);
                break;
            // Можно добавить проверки для других схем
        }
    }

    private void validateConsentSchema(Schema schema, List<Vulnerability> vulnerabilities) {
        Map<String, Schema> properties = schema.getProperties();
        if (properties == null) return;
        
        if (!properties.containsKey("client_id")) {
            vulnerabilities.add(createVulnerability(
                "Неполная схема ConsentRequestBody",
                "Отсутствует обязательное свойство: client_id",
                Vulnerability.Severity.MEDIUM,
                "components/schemas/ConsentRequestBody"
            ));
        }
        
        if (!properties.containsKey("permissions")) {
            vulnerabilities.add(createVulnerability(
                "Неполная схема ConsentRequestBody",
                "Отсутствует обязательное свойство: permissions",
                Vulnerability.Severity.MEDIUM,
                "components/schemas/ConsentRequestBody"
            ));
        }
    }

    private void validatePaymentSchema(Schema schema, List<Vulnerability> vulnerabilities) {
        Map<String, Schema> properties = schema.getProperties();
        if (properties == null) return;
        
        if (!properties.containsKey("data")) {
            vulnerabilities.add(createVulnerability(
                "Неполная схема PaymentRequest",
                "Отсутствует обязательное свойство: data",
                Vulnerability.Severity.MEDIUM,
                "components/schemas/PaymentRequest"
            ));
        }
    }

    private void validateRequiredEndpoints(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        log("🎯 Проверка обязательных эндпоинтов...");
        
        Map<String, PathItem> paths = openAPI.getPaths();
        
        // Список критически важных эндпоинтов
        String[] requiredEndpoints = {
            "/auth/bank-token", "/accounts", "/account-consents/request",
            "/payments", "/products"
        };
        
        for (String endpoint : requiredEndpoints) {
            if (!paths.containsKey(endpoint)) {
                vulnerabilities.add(createVulnerability(
                    "Отсутствует обязательный эндпоинт",
                    "В спецификации отсутствует эндпоинт: " + endpoint,
                    Vulnerability.Severity.HIGH,
                    endpoint
                ));
            }
        }
        
        // Проверяем методы для ключевых эндпоинтов
        checkEndpointMethods(paths, "/auth/bank-token", "POST", vulnerabilities);
        checkEndpointMethods(paths, "/accounts", "GET", vulnerabilities);
        checkEndpointMethods(paths, "/account-consents/request", "POST", vulnerabilities);
    }

    private void checkEndpointMethods(Map<String, PathItem> paths, String endpoint, 
                                    String requiredMethod, List<Vulnerability> vulnerabilities) {
        
        PathItem pathItem = paths.get(endpoint);
        if (pathItem == null) return;
        
        boolean hasMethod = false;
        switch (requiredMethod) {
            case "GET": hasMethod = pathItem.getGet() != null; break;
            case "POST": hasMethod = pathItem.getPost() != null; break;
            case "PUT": hasMethod = pathItem.getPut() != null; break;
            case "DELETE": hasMethod = pathItem.getDelete() != null; break;
        }
        
        if (!hasMethod) {
            vulnerabilities.add(createVulnerability(
                "Отсутствует обязательный метод",
                "Эндпоинт " + endpoint + " не поддерживает метод " + requiredMethod,
                Vulnerability.Severity.HIGH,
                endpoint
            ));
        }
    }

    private void checkMissingImportantEndpoints(Set<String> testedPaths, List<Vulnerability> vulnerabilities) {
        // Проверяем, что протестированы все важные эндпоинты
        String[] importantEndpoints = {
            "/accounts", "/products", "/payments"
        };
        
        for (String endpoint : importantEndpoints) {
            if (!testedPaths.contains(endpoint)) {
                vulnerabilities.add(createVulnerability(
                    "Важный эндпоинт не протестирован",
                    "Эндпоинт " + endpoint + " присутствует в спецификации, но не был протестирован",
                    Vulnerability.Severity.LOW,
                    endpoint
                ));
            }
        }
    }

    private String getAccessToken(ScanConfig config) {
        if (config.hasUserTokens()) {
            // Возвращаем первый доступный токен
            return config.getUserTokens().values().iterator().next();
        }
        return config.getAccessToken();
    }

    private void addRequiredHeaders(Operation operation, Map<String, String> headers) {
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                if (param.getIn().equals("header") && param.getRequired() != null && param.getRequired()) {
                    // Добавляем заголовки с тестовыми значениями
                    switch (param.getName()) {
                        case "x-requesting-bank":
                            headers.put("x-requesting-bank", "team172");
                            break;
                        case "x-consent-id":
                            headers.put("x-consent-id", "consent-test-123");
                            break;
                        case "x-fapi-interaction-id":
                            headers.put("x-fapi-interaction-id", "test-interaction-123");
                            break;
                        case "x-product-agreement-consent-id":
                            headers.put("x-product-agreement-consent-id", "prod-consent-test-123");
                            break;
                    }
                }
            }
        }
    }

    private String createMinimalRequestBody(Operation operation, Map<String, String> testValues) {
        // Создаем минимальное тело запроса на основе ожидаемой схемы
        if (operation.getRequestBody() == null) return "{}";
        
        MediaType mediaType = operation.getRequestBody().getContent().get("application/json");
        if (mediaType == null) return "{}";
        
        Schema schema = mediaType.getSchema();
        if (schema == null) return "{}";
        
        // Простая логика создания минимального тела на основе типа схемы
        String schemaName = getSchemaName(schema);
        
        switch (schemaName) {
            case "ConsentRequestBody":
                return "{\"client_id\":\"" + testValues.get("client_id") + "\",\"permissions\":[\"ReadAccountsDetail\"],\"requesting_bank\":\"team172\"}";
            case "CreateAccountRequest":
                return "{\"account_type\":\"checking\"}";
            case "PaymentRequest":
                return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"1.00\",\"currency\":\"RUB\"}}}}";
            case "ProductAgreementRequest":
                return "{\"product_id\":\"" + testValues.get("product_id") + "\",\"amount\":1000}";
            default:
                return "{}";
        }
    }

    private String getSchemaName(Schema schema) {
        if (schema.get$ref() != null) {
            // Извлекаем имя схемы из reference
            String ref = schema.get$ref();
            return ref.substring(ref.lastIndexOf("/") + 1);
        }
        return "Unknown";
    }

    private boolean isSafeToTest(String path) {
        // Определяем, безопасно ли тестировать POST эндпоинт
        return !path.contains("close") && 
               !path.contains("delete") && 
               !path.contains("transfer");
    }

    private Vulnerability createVulnerability(String title, String description, 
                                            Vulnerability.Severity severity, String endpoint) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.CONTRACT_VALIDATION);
        vuln.setEndpoint(endpoint);
        return vuln;
    }

    private void log(String message) {
        System.out.println("[ContractValidation] " + message);
    }
}
