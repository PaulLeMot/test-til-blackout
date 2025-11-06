package scanners.owasp;

import core.*;
import scanners.SecurityScanner;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.servers.Server;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class ContractValidationScanner implements SecurityScanner {

    @Override
    public String getName() {
        return "API Contract Validation Scanner";
    }

    public String getDescription() {
        return "Проверяет соответствие реального API OpenAPI-спецификации";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        OpenAPI openAPI = null;
        if (openApiObj instanceof OpenAPI) {
            openAPI = (OpenAPI) openApiObj;
        }
        
        if (openAPI == null) {
            vulnerabilities.add(createVulnerability(
                "Отсутствует OpenAPI спецификация",
                "Не удалось загрузить OpenAPI спецификацию для валидации контракта",
                Vulnerability.Severity.MEDIUM,
                "CONTRACT_VALIDATION"
            ));
            return vulnerabilities;
        }

        try {
            log("🔍 Начало валидации контракта API");
            log("Целевой URL: " + config.getTargetBaseUrl());
            
            // Получаем токен для аутентифицированных запросов
            String accessToken = getAccessToken(config);
            
            // Валидация базовой структуры
            validateBasicStructure(openAPI, vulnerabilities);
            
            // Валидация эндпоинтов
            validateEndpoints(openAPI, config, apiClient, accessToken, vulnerabilities);
            
            // Проверка серверов
            validateServers(openAPI, config, vulnerabilities);
            
            // Проверка схем данных
            validateSchemas(openAPI, vulnerabilities);
            
        } catch (Exception e) {
            vulnerabilities.add(createVulnerability(
                "Ошибка при валидации контракта",
                "Произошла ошибка во время проверки соответствия API спецификации: " + e.getMessage(),
                Vulnerability.Severity.HIGH,
                "CONTRACT_VALIDATION"
            ));
        }
        
        log("✅ Валидация контракта завершена. Найдено проблем: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private String getAccessToken(ScanConfig config) {
        // Пытаемся получить любой валидный токен
        if (config.hasUserTokens()) {
            for (Map.Entry<String, String> entry : config.getUserTokens().entrySet()) {
                if (entry.getValue() != null && !entry.getValue().isEmpty()) {
                    return entry.getValue();
                }
            }
        }
        return config.getAccessToken();
    }

    private void validateBasicStructure(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        log("Проверка базовой структуры спецификации...");
        
        if (openAPI.getInfo() == null) {
            vulnerabilities.add(createVulnerability(
                "Отсутствует информация о API",
                "В спецификации отсутствует блок 'info' с основной информацией",
                Vulnerability.Severity.LOW,
                "CONTRACT_VALIDATION"
            ));
        } else {
            if (openAPI.getInfo().getTitle() == null) {
                vulnerabilities.add(createVulnerability(
                    "Отсутствует название API",
                    "В спецификации отсутствует название API (info.title)",
                    Vulnerability.Severity.LOW,
                    "CONTRACT_VALIDATION"
                ));
            }
            if (openAPI.getInfo().getVersion() == null) {
                vulnerabilities.add(createVulnerability(
                    "Отсутствует версия API",
                    "В спецификации отсутствует версия API (info.version)",
                    Vulnerability.Severity.LOW,
                    "CONTRACT_VALIDATION"
                ));
            }
        }
        
        if (openAPI.getPaths() == null || openAPI.getPaths().isEmpty()) {
            vulnerabilities.add(createVulnerability(
                "Отсутствуют пути API",
                "В спецификации не определены пути (paths)",
                Vulnerability.Severity.HIGH,
                "CONTRACT_VALIDATION"
            ));
        } else {
            log("Найдено путей в спецификации: " + openAPI.getPaths().size());
        }
    }

    private void validateEndpoints(OpenAPI openAPI, ScanConfig config, ApiClient apiClient, 
                                 String accessToken, List<Vulnerability> vulnerabilities) {
        log("Проверка эндпоинтов...");
        
        Map<String, PathItem> paths = openAPI.getPaths();
        int testedEndpoints = 0;
        int problematicEndpoints = 0;
        
        // Тестируем основные эндпоинты из спецификации
        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            
            // Пропускаем технические эндпоинты для избежания side effects
            if (shouldSkipEndpoint(path)) {
                log("⏭️  Пропускаем эндпоинт (изменяет состояние): " + path);
                continue;
            }
            
            // Проверяем каждый HTTP метод
            for (Map.Entry<PathItem.HttpMethod, Operation> operationEntry : getOperations(pathItem).entrySet()) {
                PathItem.HttpMethod method = operationEntry.getKey();
                Operation operation = operationEntry.getValue();
                
                if (operation == null) continue;
                
                testedEndpoints++;
                boolean hasProblems = testEndpoint(method, path, operation, config, apiClient, 
                                                 accessToken, vulnerabilities);
                if (hasProblems) {
                    problematicEndpoints++;
                }
                
                // Задержка между запросами чтобы не перегружать API
                try { Thread.sleep(500); } catch (InterruptedException e) {}
            }
        }
        
        log("📊 Итоги проверки эндпоинтов:");
        log("   Протестировано: " + testedEndpoints);
        log("   Проблемных: " + problematicEndpoints);
        log("   Без проблем: " + (testedEndpoints - problematicEndpoints));
    }

    private boolean shouldSkipEndpoint(String path) {
        // Пропускаем эндпоинты которые могут изменить состояние
        List<String> skipPatterns = Arrays.asList(
            "delete", "put", "patch", "close", "status", "transfer", "payment"
        );
        
        String lowerPath = path.toLowerCase();
        for (String pattern : skipPatterns) {
            if (lowerPath.contains(pattern)) {
                return true;
            }
        }
        
        return false;
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

    private boolean testEndpoint(PathItem.HttpMethod method, String path, Operation operation,
                               ScanConfig config, ApiClient apiClient, String accessToken,
                               List<Vulnerability> vulnerabilities) {
        String fullUrl = buildUrl(config.getTargetBaseUrl(), path, operation);
        String requestBody = null;
        
        log("\n🎯 Тестирование: " + method + " " + fullUrl);
        log("   Операция: " + (operation.getSummary() != null ? operation.getSummary() : "N/A"));
        
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "GOSTGuardian-Contract-Validator/1.0");
            headers.put("Accept", "application/json");
            headers.put("Content-Type", "application/json");
            
            // Добавляем специфичные заголовки для API
            if (path.contains("/account-consents") || path.contains("/payment-consents") || 
                path.contains("/product-agreement-consents")) {
                headers.put("X-Requesting-Bank", "team172");
                log("   Заголовок: X-Requesting-Bank=team172");
            }
            
            // Добавляем авторизацию если требуется
            boolean requiresAuth = operation.getSecurity() != null && !operation.getSecurity().isEmpty();
            if (requiresAuth && accessToken != null) {
                headers.put("Authorization", "Bearer " + accessToken);
                
                // Определяем тип токена
                boolean isBankToken = accessToken.equals(config.getUserTokens().get("bank_token"));
                if (isBankToken) {
                    log("   Аутентификация: Bank token (для межбанковых операций)");
                    // Для bank token добавляем client_id в query параметры если требуется
                    if (requiresClientIdInQuery(path, method)) {
                        fullUrl = addQueryParam(fullUrl, "client_id", "team172-8");
                        log("   Query параметр: client_id=team172-8");
                    }
                } else {
                    log("   Аутентификация: Client token (для операций со своими счетами)");
                }
            } else if (requiresAuth) {
                log("   Аутентификация: Требуется (токен отсутствует)");
            } else {
                log("   Аутентификация: Не требуется");
            }
            
            // Подготавливаем тело запроса для POST endpoints
            if (method == PathItem.HttpMethod.POST) {
                requestBody = prepareRequestBody(path, operation);
                if (requestBody != null) {
                    log("   Тело запроса: " + requestBody);
                }
            }
            
            // Специальная обработка для /auth/bank-token
            if (path.equals("/auth/bank-token") && method == PathItem.HttpMethod.POST) {
                fullUrl = config.getTargetBaseUrl() + "/auth/bank-token?client_id=team172&client_secret=" + config.getPassword();
                requestBody = ""; // Пустое тело для этого endpoint
                log("   Специальная обработка: /auth/bank-token с query параметрами");
            }
            
            // Добавляем заголовок X-Consent-Id для эндпоинтов требующих согласия
            if (requiresConsent(path)) {
                headers.put("X-Consent-Id", "test-consent-id");
                log("   Заголовок: X-Consent-Id=test-consent-id");
            }
            
            log("   Отправка запроса...");
            Object response = apiClient.executeRequest(method.name(), fullUrl, requestBody, headers);
            
            // Исправленная проверка типа ответа
            if (response != null && response.getClass().getName().contains("ApiResponse")) {
                return validateResponse(method, path, operation, response, vulnerabilities);
            } else {
                log("   ❌ Неожиданный тип ответа: " + (response != null ? response.getClass().getName() : "null"));
                return true;
            }
            
        } catch (Exception e) {
            log("   ❌ Исключение при запросе: " + e.getMessage());
            vulnerabilities.add(createVulnerability(
                "Ошибка при тестировании эндпоинта: " + method + " " + path,
                "Исключение при проверке эндпоинта: " + e.getMessage(),
                Vulnerability.Severity.MEDIUM,
                "CONTRACT_VALIDATION"
            ));
            return true;
        }
    }

    private boolean requiresClientIdInQuery(String path, PathItem.HttpMethod method) {
        // Эндпоинты которые требуют client_id в query при использовании bank token
        List<String> endpointsRequiringClientId = Arrays.asList(
            "/accounts", "/accounts/{account_id}", "/accounts/{account_id}/balances",
            "/accounts/{account_id}/transactions", "/product-agreements",
            "/product-agreements/{agreement_id}", "/product-agreement-consents/request"
        );
        
        return endpointsRequiringClientId.contains(path) && method == PathItem.HttpMethod.GET;
    }

    private boolean requiresConsent(String path) {
        // Эндпоинты которые требуют согласия для межбанковых запросов
        List<String> endpointsRequiringConsent = Arrays.asList(
            "/accounts", "/accounts/{account_id}", "/accounts/{account_id}/balances",
            "/accounts/{account_id}/transactions"
        );
        
        return endpointsRequiringConsent.contains(path);
    }

    private String buildUrl(String baseUrl, String path, Operation operation) {
        // Заменяем path parameters на примерные значения
        String resolvedPath = resolvePathParameters(path, operation);
        return baseUrl + resolvedPath;
    }

    private String resolvePathParameters(String path, Operation operation) {
        Pattern pattern = Pattern.compile("\\{([^}]+)\\}");
        Matcher matcher = pattern.matcher(path);
        StringBuffer result = new StringBuffer();
        
        while (matcher.find()) {
            String paramName = matcher.group(1);
            String replacement = findParameterExample(paramName, operation);
            String finalReplacement = replacement != null ? replacement : getDefaultParameterValue(paramName);
            log("   Замена параметра {" + paramName + "} на: " + finalReplacement);
            matcher.appendReplacement(result, finalReplacement);
        }
        matcher.appendTail(result);
        
        return result.toString();
    }

    private String getDefaultParameterValue(String paramName) {
        // Значения по умолчанию для различных параметров
        Map<String, String> defaultValues = new HashMap<>();
        defaultValues.put("account_id", "acc-1010");
        defaultValues.put("consent_id", "consent-d8f0724a4775");
        defaultValues.put("agreement_id", "agreement-test-001");
        defaultValues.put("product_id", "prod-vbank-deposit-001");
        defaultValues.put("payment_id", "payment-test-001");
        
        return defaultValues.getOrDefault(paramName, "test-value");
    }

    private String findParameterExample(String paramName, Operation operation) {
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                if (paramName.equals(param.getName()) && "path".equals(param.getIn())) {
                    if (param.getExample() != null) {
                        return param.getExample().toString();
                    }
                    if (param.getSchema() != null && param.getSchema().getExample() != null) {
                        return param.getSchema().getExample().toString();
                    }
                }
            }
        }
        return null;
    }

    private String prepareRequestBody(String path, Operation operation) {
        // Базовые тела запросов для разных endpoints
        switch (path) {
            case "/account-consents/request":
                return "{\"client_id\":\"team172-8\",\"permissions\":[\"ReadAccountsDetail\",\"ReadBalances\"],\"reason\":\"Security testing\",\"requesting_bank\":\"team172\",\"requesting_bank_name\":\"Security Scanner\"}";
            
            case "/payment-consents/request":
                return "{\"requesting_bank\":\"team172\",\"client_id\":\"team172-8\",\"consent_type\":\"single_use\",\"amount\":1000,\"currency\":\"RUB\",\"debtor_account\":\"test-account\",\"reference\":\"Test payment\"}";
            
            case "/product-agreement-consents/request":
                return "{\"requesting_bank\":\"team172\",\"client_id\":\"team172-8\",\"read_product_agreements\":true,\"open_product_agreements\":false,\"close_product_agreements\":false,\"reason\":\"Security testing\"}";
                
            case "/accounts":
                return "{\"account_type\":\"checking\",\"initial_balance\":0}";
                
            case "/product-agreements":
                return "{\"product_id\":\"prod-vbank-deposit-001\",\"amount\":50000,\"term_months\":12,\"source_account_id\":\"acc-1010\"}";
                
            default:
                return "{}"; // Пустое тело по умолчанию
        }
    }

    private String addQueryParam(String url, String param, String value) {
        if (url.contains("?")) {
            return url + "&" + param + "=" + value;
        } else {
            return url + "?" + param + "=" + value;
        }
    }

    private boolean validateResponse(PathItem.HttpMethod method, String path, Operation operation,
                                   Object responseObj, List<Vulnerability> vulnerabilities) {
        try {
            // Используем рефлексию для доступа к полям ответа
            Class<?> responseClass = responseObj.getClass();
            
            // Получаем статус код
            int statusCode = (int) responseClass.getMethod("getStatusCode").invoke(responseObj);
            
            // Получаем тело ответа
            String responseBody = (String) responseClass.getMethod("getBody").invoke(responseObj);
            
            // Получаем заголовки
            Map<String, List<String>> headers = (Map<String, List<String>>) responseClass.getMethod("getHeaders").invoke(responseObj);
            
            // Выводим подробную информацию о ответе
            log("   📡 Ответ сервера:");
            log("      Код статуса: " + statusCode + " " + getStatusText(statusCode));
            log("      Content-Type: " + getHeaderValue(headers, "content-type"));
            log("      Content-Length: " + getHeaderValue(headers, "content-length"));
            
            // Выводим тело ответа (обрезанное)
            if (responseBody != null && !responseBody.isEmpty()) {
                String truncatedBody = responseBody.length() > 300 ? 
                    responseBody.substring(0, 300) + "..." : responseBody;
                log("      Тело ответа: " + truncatedBody.replace("\n", " "));
            } else {
                log("      Тело ответа: [пусто]");
            }
            
            boolean hasProblems = false;
            
            // Проверяем код ответа
            String expectedCodes = getExpectedResponseCodes(operation);
            boolean isExpectedCode = isExpectedStatusCode(statusCode, operation);
            
            if (!isExpectedCode) {
                log("   ⚠️  Неожиданный код ответа!");
                log("      Ожидались: " + expectedCodes);
                vulnerabilities.add(createVulnerability(
                    "Неожиданный код ответа для " + method + " " + path,
                    "Получен код: " + statusCode + " (" + getStatusText(statusCode) + "), ожидались: " + expectedCodes + 
                    ". Тело ответа: " + (responseBody != null ? responseBody.substring(0, Math.min(200, responseBody.length())) : "пусто"),
                    statusCode == 500 ? Vulnerability.Severity.HIGH : Vulnerability.Severity.MEDIUM,
                    "CONTRACT_VALIDATION"
                ));
                hasProblems = true;
            } else {
                log("   ✅ Код ответа соответствует ожиданиям");
            }
            
            // Проверяем content-type
            List<String> contentTypeHeaders = headers != null ? headers.get("content-type") : null;
            if (contentTypeHeaders != null && !contentTypeHeaders.isEmpty()) {
                String contentType = contentTypeHeaders.get(0);
                if (statusCode >= 200 && statusCode < 300) {
                    if (!contentType.contains("application/json") && !contentType.contains("json")) {
                        log("   ⚠️  Неожиданный Content-Type!");
                        vulnerabilities.add(createVulnerability(
                            "Неожиданный Content-Type для " + method + " " + path,
                            "Получен: " + contentType + ", ожидался application/json",
                            Vulnerability.Severity.LOW,
                            "CONTRACT_VALIDATION"
                        ));
                        hasProblems = true;
                    } else {
                        log("   ✅ Content-Type соответствует ожиданиям");
                    }
                }
            }
            
            // Проверяем структуру JSON ответа (базовая проверка)
            if (statusCode >= 200 && statusCode < 300 && responseBody != null && !responseBody.isEmpty()) {
                if (!isValidJson(responseBody)) {
                    log("   ⚠️  Невалидный JSON в ответе!");
                    vulnerabilities.add(createVulnerability(
                        "Невалидный JSON в ответе для " + method + " " + path,
                        "Тело ответа не является валидным JSON",
                        Vulnerability.Severity.MEDIUM,
                        "CONTRACT_VALIDATION"
                    ));
                    hasProblems = true;
                } else {
                    log("   ✅ JSON валиден");
                }
            }
            
            if (!hasProblems) {
                log("   ✅ Эндпоинт прошел проверку без ошибок");
            }
            
            return hasProblems;
            
        } catch (Exception e) {
            log("   ❌ Ошибка при обработке ответа: " + e.getMessage());
            vulnerabilities.add(createVulnerability(
                "Ошибка при обработке ответа для " + method + " " + path,
                "Не удалось обработать ответ сервера: " + e.getMessage(),
                Vulnerability.Severity.MEDIUM,
                "CONTRACT_VALIDATION"
            ));
            return true;
        }
    }

    private String getStatusText(int statusCode) {
        switch (statusCode) {
            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default: return "Unknown";
        }
    }

    private String getHeaderValue(Map<String, List<String>> headers, String headerName) {
        if (headers != null && headers.containsKey(headerName)) {
            List<String> values = headers.get(headerName);
            return values != null && !values.isEmpty() ? values.get(0) : "N/A";
        }
        return "N/A";
    }

    private boolean isExpectedStatusCode(int statusCode, Operation operation) {
        if (operation.getResponses() == null) {
            return statusCode >= 200 && statusCode < 300;
        }
        
        // Проверяем точное соответствие
        if (operation.getResponses().containsKey(String.valueOf(statusCode))) {
            return true;
        }
        
        // Проверяем диапазоны
        if (statusCode >= 200 && statusCode < 300 && operation.getResponses().containsKey("2xx")) {
            return true;
        }
        if (statusCode >= 400 && statusCode < 500 && operation.getResponses().containsKey("4xx")) {
            return true;
        }
        if (statusCode >= 500 && statusCode < 600 && operation.getResponses().containsKey("5xx")) {
            return true;
        }
        
        // Если есть default response, считаем любой код валидным
        if (operation.getResponses().containsKey("default")) {
            return true;
        }
        
        return false;
    }

    private String getExpectedResponseCodes(Operation operation) {
        if (operation.getResponses() == null) return "2xx";
        
        List<String> codes = new ArrayList<>();
        for (String code : operation.getResponses().keySet()) {
            if ("default".equals(code)) continue;
            codes.add(code);
        }
        
        return codes.isEmpty() ? "2xx" : String.join(", ", codes);
    }

    private boolean isValidJson(String json) {
        if (json == null || json.trim().isEmpty()) return false;
        String trimmed = json.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}")) || 
               (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    private void validateServers(OpenAPI openAPI, ScanConfig config, List<Vulnerability> vulnerabilities) {
        log("Проверка серверов...");
        
        List<Server> servers = openAPI.getServers();
        if (servers == null || servers.isEmpty()) {
            vulnerabilities.add(createVulnerability(
                "Отсутствует информация о серверах",
                "В спецификации не указаны серверы (servers)",
                Vulnerability.Severity.LOW,
                "CONTRACT_VALIDATION"
            ));
            return;
        }
        
        boolean targetServerFound = false;
        String targetBaseUrl = config.getTargetBaseUrl().toLowerCase();
        
        for (Server server : servers) {
            String serverUrl = server.getUrl().toLowerCase();
            if (serverUrl.contains(targetBaseUrl) || targetBaseUrl.contains(serverUrl)) {
                targetServerFound = true;
                break;
            }
        }
        
        if (!targetServerFound) {
            vulnerabilities.add(createVulnerability(
                "Несоответствие серверов спецификации",
                "Целевой URL " + config.getTargetBaseUrl() + " не соответствует серверам в спецификации: " + 
                servers.stream().map(Server::getUrl).reduce((a, b) -> a + ", " + b).orElse(""),
                Vulnerability.Severity.MEDIUM,
                "CONTRACT_VALIDATION"
            ));
        }
    }

    private void validateSchemas(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        log("Проверка схем данных...");
        
        if (openAPI.getComponents() == null || openAPI.getComponents().getSchemas() == null) {
            vulnerabilities.add(createVulnerability(
                "Отсутствуют схемы данных",
                "В спецификации не определены схемы данных (components.schemas)",
                Vulnerability.Severity.LOW,
                "CONTRACT_VALIDATION"
            ));
            return;
        }
        
        Map<String, io.swagger.v3.oas.models.media.Schema> schemas = openAPI.getComponents().getSchemas();
        log("Найдено схем в спецификации: " + schemas.size());
        
        // Проверяем наличие ключевых схем
        String[] requiredSchemas = {"HTTPValidationError", "ValidationError"};
        for (String requiredSchema : requiredSchemas) {
            if (!schemas.containsKey(requiredSchema)) {
                vulnerabilities.add(createVulnerability(
                    "Отсутствует обязательная схема: " + requiredSchema,
                    "В спецификации отсутствует схема для обработки ошибок валидации",
                    Vulnerability.Severity.LOW,
                    "CONTRACT_VALIDATION"
                ));
            }
        }
    }

    private Vulnerability createVulnerability(String title, String description, 
                                            Vulnerability.Severity severity, String category) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.CONTRACT_VALIDATION);
        vuln.setEndpoint("OpenAPI Specification");
        vuln.setMethod("VALIDATION");
        
        // Используем setRecommendations вместо addRecommendation
        List<String> recommendations = new ArrayList<>();
        recommendations.add("Убедитесь, что API соответствует OpenAPI спецификации");
        recommendations.add("Обновите спецификацию при изменении API");
        recommendations.add("Используйте инструменты валидации OpenAPI");
        vuln.setRecommendations(recommendations);
        
        return vuln;
    }

    private void log(String message) {
        System.out.println("[ContractValidation] " + message);
    }
}
