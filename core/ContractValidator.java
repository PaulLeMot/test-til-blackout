package core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Упрощенная версия ContractValidator.java
 * 
 * Основные упрощения:
 * - Убрана сложная логика пропуска эндпоинтов
 * - Упрощена замена плейсхолдеров на реальные ID
 * - Более прямолинейный подход к созданию ресурсов
 */
public class ContractValidator {

    private static final String TOKEN_URL = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token";
    private static final ObjectMapper mapper = new ObjectMapper();

    private String accessToken = null;
    private int responseCode = 0;
    private String baseUrl;
    private String clientId;
    private String clientSecret;

    // Простое хранилище созданных ID ресурсов
    private final Map<String, String> resourceIds = new HashMap<>();

    public ContractValidator(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public ContractValidator(String clientId, String clientSecret, String baseUrl) {
        this(clientId, clientSecret);
        this.baseUrl = baseUrl;
    }

    public void setCredentials(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public static void main(String[] args) {
        try {
            System.out.println("🚀 ЗАПУСК ВАЛИДАЦИИ КОНТРАКТОВ API");
            System.out.println("=".repeat(80));

            String clientId = args.length > 0 ? args[0] : "team172";
            String clientSecret = args.length > 1 ? args[1] : "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";

            ContractValidator validator = new ContractValidator(clientId, clientSecret);
            List<ValidationResult> results = validator.validateAllContracts();

            System.out.println("\n🎉 Валидация завершена! Результатов: " + results.size());
            printValidationSummary(results);

        } catch (Exception e) {
            System.err.println("❌ Ошибка при валидации: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Основной сценарий валидации
     */
    public List<ValidationResult> validateAllContracts() {
        List<ValidationResult> validationResults = new ArrayList<>();
        resourceIds.clear();

        try {
            System.out.println("🔍 Начало валидации контрактов...");

            if (clientId == null || clientSecret == null) {
                System.err.println("❌ Не указаны clientId и clientSecret");
                return validationResults;
            }

            accessToken = getAccessToken();
            if (accessToken == null) {
                System.err.println("❌ Не удалось получить токен авторизации");
                return validationResults;
            }
            System.out.println("✅ Токен получен успешно");

            // Загружаем спецификации через парсер
            List<OpenApiSpecParser.ApiSpec> specs = OpenApiSpecParser.parseAllSpecs();
            if (specs == null || specs.isEmpty()) {
                System.err.println("❌ Не найдено спецификаций для валидации");
                return validationResults;
            }
            System.out.println("✅ Загружено спецификаций: " + specs.size());

            System.out.println("\n🔄 Создание ресурсов для получения ID...");
            createResources(specs, accessToken);

            // Выводим все созданные ID для отладки
            System.out.println("\n📋 СОЗДАННЫЕ РЕСУРСНЫЕ ID:");
            for (Map.Entry<String, String> entry : resourceIds.entrySet()) {
                System.out.println("   " + entry.getKey() + " = " + entry.getValue());
            }

            for (OpenApiSpecParser.ApiSpec spec : specs) {
                System.out.println("\n📋 ВАЛИДАЦИЯ: " + spec.title);
                System.out.println("=".repeat(60));
                List<ValidationResult> specResults = validateApiSpec(spec, accessToken);
                validationResults.addAll(specResults);
            }

        } catch (Exception e) {
            System.err.println("❌ Ошибка при validateAllContracts: " + e.getMessage());
            e.printStackTrace();
        }
        return validationResults;
    }

    /**
     * Создание всех ресурсов для получения ID
     */
    private void createResources(List<OpenApiSpecParser.ApiSpec> specs, String accessToken) {
        // Сначала создаем ресурсы без path-параметров
        for (OpenApiSpecParser.ApiSpec spec : specs) {
            String baseUrlToUse = chooseBaseUrl(spec);
            if (baseUrlToUse == null) continue;

            for (OpenApiSpecParser.ApiEndpoint endpoint : spec.endpoints) {
                try {
                    if ("POST".equals(endpoint.method) && endpoint.hasRequestBody && !hasPathParameters(endpoint)) {
                        System.out.println("🔧 Создание ресурса: " + endpoint.path);
                        
                        String fullUrl = concatPaths(baseUrlToUse, endpoint.path);
                        String requestBody = generateRequestBodyFromSchema(endpoint);
                        
                        String response = executeRequest("POST", fullUrl, requestBody, accessToken);
                        
                        if (responseCode >= 200 && responseCode < 300) {
                            extractResourceIdFromResponse(endpoint, response, baseUrlToUse);
                        }
                        
                        Thread.sleep(200);
                    }
                } catch (Exception e) {
                    System.err.println("❌ Ошибка при создании ресурса " + endpoint.path + ": " + e.getMessage());
                }
            }
        }

        // Затем создаем ресурсы с path-параметрами
        for (OpenApiSpecParser.ApiSpec spec : specs) {
            String baseUrlToUse = chooseBaseUrl(spec);
            if (baseUrlToUse == null) continue;

            for (OpenApiSpecParser.ApiEndpoint endpoint : spec.endpoints) {
                try {
                    if ("POST".equals(endpoint.method) && endpoint.hasRequestBody && hasPathParameters(endpoint)) {
                        System.out.println("🔧 Создание ресурса с параметрами: " + endpoint.path);
                        
                        // Подготавливаем URL с реальными значениями
                        String fullUrl = prepareUrlWithRealIds(baseUrlToUse, endpoint);
                        
                        String requestBody = generateRequestBodyFromSchema(endpoint);
                        String response = executeRequest("POST", fullUrl, requestBody, accessToken);
                        
                        if (responseCode >= 200 && responseCode < 300) {
                            extractResourceIdFromResponse(endpoint, response, baseUrlToUse);
                        }
                        
                        Thread.sleep(200);
                    }
                } catch (Exception e) {
                    System.err.println("❌ Ошибка при создании ресурса " + endpoint.path + ": " + e.getMessage());
                }
            }
        }
    }

    private boolean hasPathParameters(OpenApiSpecParser.ApiEndpoint endpoint) {
        return endpoint.path.contains("{") && endpoint.path.contains("}");
    }

    /**
     * Извлечение ID ресурса из ответа
     */
    private void extractResourceIdFromResponse(OpenApiSpecParser.ApiEndpoint endpoint, String response, String baseUrl) {
        try {
            if (response == null || response.trim().isEmpty()) {
                return;
            }

            JsonNode root = mapper.readTree(response);

            // Простой поиск ID в разных полях
            String[] idFields = {"id", "consentId", "accountId", "applicationId", "paymentId",
                    "VRPId", "offerId", "customerLeadId", "productApplicationId", "consentid"};

            for (String field : idFields) {
                JsonNode node = root.path(field);
                if (!node.isMissingNode() && (node.isTextual() || node.isNumber())) {
                    String value = node.asText();
                    storeResourceId(field, value);
                    System.out.println("✅ Извлечен ID: " + field + " = " + value);
                    return;
                }
            }

            // Поиск в Data.*
            JsonNode dataNode = root.path("Data");
            if (dataNode.isObject()) {
                for (String field : idFields) {
                    JsonNode node = dataNode.path(field);
                    if (!node.isMissingNode() && (node.isTextual() || node.isNumber())) {
                        String value = node.asText();
                        storeResourceId(field, value);
                        System.out.println("✅ Извлечен ID из Data: " + field + " = " + value);
                        return;
                    }
                }
            }

        } catch (Exception e) {
            // Игнорируем ошибки извлечения ID
        }
    }

    private void storeResourceId(String fieldName, String idValue) {
        if (fieldName == null || idValue == null) return;
        resourceIds.put(fieldName.toLowerCase(), idValue);
    }

    /**
     * Подготовка URL: замена всех плейсхолдеров {param} на реальные значения
     */
    private String prepareUrlWithRealIds(String baseUrl, OpenApiSpecParser.ApiEndpoint endpoint) {
        String path = endpoint.path;

        // Заменяем все {param} с помощью regex
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\\{([^/}]+)\\}");
        java.util.regex.Matcher m = p.matcher(path);
        StringBuffer sb = new StringBuffer();

        while (m.find()) {
            String paramName = m.group(1);
            String replacement = findParameterValue(paramName);
            m.appendReplacement(sb, replacement);
        }
        m.appendTail(sb);
        String resolvedPath = sb.toString();

        // Добавляем query-параметры
        StringBuilder urlBuilder = new StringBuilder(concatPaths(baseUrl, resolvedPath));
        boolean firstQueryParam = true;

        if (endpoint.parameters != null) {
            for (OpenApiSpecParser.ApiParameter param : endpoint.parameters) {
                if ("query".equalsIgnoreCase(param.in) && param.required) {
                    String val = findParameterValue(param.name);
                    if (firstQueryParam) {
                        urlBuilder.append("?");
                        firstQueryParam = false;
                    } else {
                        urlBuilder.append("&");
                    }
                    urlBuilder.append(urlEncode(param.name)).append("=").append(urlEncode(val));
                }
            }
        }

        return urlBuilder.toString();
    }

    /**
     * Поиск значения параметра в созданных ресурсах
     */
    private String findParameterValue(String paramName) {
        if (paramName == null) return generateParameterValue(paramName);
        
        // Ищем точное совпадение
        String key = paramName.toLowerCase();
        if (resourceIds.containsKey(key)) {
            return resourceIds.get(key);
        }

        // Ищем по синонимам
        String[] synonyms = getParameterSynonyms(paramName);
        for (String syn : synonyms) {
            if (resourceIds.containsKey(syn.toLowerCase())) {
                return resourceIds.get(syn.toLowerCase());
            }
        }

        return generateParameterValue(paramName);
    }

    private String[] getParameterSynonyms(String paramName) {
        if (paramName == null) return new String[0];
        
        switch (paramName.toLowerCase()) {
            case "consentid":
            case "consent-id":
            case "consent_id":
                return new String[]{"consentid"};
            case "accountid":
            case "externalaccountid":
                return new String[]{"accountid"};
            case "vrpid":
                return new String[]{"vrpid", "paymentid"};
            case "applicationid":
                return new String[]{"applicationid"};
            case "paymentid":
                return new String[]{"paymentid"};
            case "offerid":
                return new String[]{"offerid"};
            case "customerleadid":
                return new String[]{"customerleadid"};
            case "productapplicationid":
                return new String[]{"productapplicationid"};
            case "publicid":
                return new String[]{"id"};
            case "uin":
                return new String[]{"id"};
            default:
                return new String[]{"id"};
        }
    }

    /**
     * Генерация значения параметра по имени
     */
    private String generateParameterValue(String paramName) {
        if (paramName == null) return UUID.randomUUID().toString();
        
        switch (paramName.toLowerCase()) {
            case "externalaccountid":
            case "accountid":
                return "test-account-" + UUID.randomUUID().toString().substring(0, 8);
            case "publicid":
                return "test-public-id-123";
            case "uin":
                return "18810150200605213474";
            case "id":
                return UUID.randomUUID().toString();
            default:
                return "test-" + paramName + "-" + UUID.randomUUID().toString().substring(0, 8);
        }
    }

    private String concatPaths(String base, String path) {
        if (base == null) return path;
        if (path == null || path.isEmpty()) return base;
        if (base.endsWith("/") && path.startsWith("/")) return base.substring(0, base.length() - 1) + path;
        if (!base.endsWith("/") && !path.startsWith("/")) return base + "/" + path;
        return base + path;
    }

    /**
     * Генерация тела запроса
     */
    private String generateRequestBodyFromSchema(OpenApiSpecParser.ApiEndpoint endpoint) {
        try {
            if (endpoint.requestBodySchema != null) {
                return generateJsonFromSchema(endpoint.requestBodySchema);
            }
            return generateDefaultRequestBody();
        } catch (Exception e) {
            return generateDefaultRequestBody();
        }
    }

    private String generateJsonFromSchema(JsonNode schema) {
        try {
            JsonNode properties = schema.path("properties");
            if (properties.isObject()) {
                Map<String, Object> requestBody = new LinkedHashMap<>();
                Iterator<Map.Entry<String, JsonNode>> fields = properties.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> f = fields.next();
                    requestBody.put(f.getKey(), generateValueFromFieldSchema(f.getKey(), f.getValue()));
                }
                return mapper.writeValueAsString(requestBody);
            }
        } catch (Exception e) {
            // ignore
        }
        return generateDefaultRequestBody();
    }

    private Object generateValueFromFieldSchema(String fieldName, JsonNode schema) {
        String type = schema.path("type").asText("string");
        switch (type) {
            case "string":
                return "test-" + fieldName;
            case "integer":
            case "number":
                return 100;
            case "boolean":
                return true;
            case "array":
                return Collections.singletonList("test-value");
            default:
                return "test-value";
        }
    }

    private String generateDefaultRequestBody() {
        return "{\"test\": \"data\", \"reference\": \"" + UUID.randomUUID().toString() + "\"}";
    }

    /**
     * Выполнение HTTP запроса
     */
    private String executeRequest(String method, String url, String requestBody, String accessToken) throws Exception {
        URL requestUrl = new URI(url).toURL();
        HttpURLConnection conn = (HttpURLConnection) requestUrl.openConnection();

        conn.setConnectTimeout(15000);
        conn.setReadTimeout(15000);

        if ("PATCH".equalsIgnoreCase(method)) {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("X-HTTP-Method-Override", "PATCH");
        } else {
            conn.setRequestMethod(method);
        }

        conn.setRequestProperty("Content-Type", "application/json");
        if (accessToken != null && !accessToken.isEmpty()) {
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        }
        conn.setRequestProperty("X-Caller-Id", "team172");

        if (requestBody != null && !requestBody.isEmpty()) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = requestBody.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
        }

        responseCode = conn.getResponseCode();

        InputStream stream = responseCode >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (stream == null) {
            return "";
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line);
            }
        }
        return response.toString();
    }

    /**
     * Получение access token
     */
    private String getAccessToken() throws Exception {
        if (clientId == null || clientSecret == null) {
            throw new IllegalStateException("Client ID and Client Secret must be set before getting access token");
        }

        URL url = new URI(TOKEN_URL).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(15000);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);

        String formData = "grant_type=client_credentials"
                + "&client_id=" + urlEncode(clientId)
                + "&client_secret=" + urlEncode(clientSecret);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = formData.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        responseCode = conn.getResponseCode();

        InputStream stream = responseCode >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (stream == null) {
            return null;
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line);
            }
        }

        if (responseCode == 200) {
            JsonNode root = mapper.readTree(response.toString());
            return root.path("access_token").asText(null);
        } else {
            System.err.println("Ошибка при получении токена: " + response.toString());
            return null;
        }
    }

    /**
     * Анализ ответа и назначение статуса валидации
     */
    private void analyzeResponse(ValidationResult result, OpenApiSpecParser.ApiEndpoint endpoint) {
        if (result.statusCode >= 200 && result.statusCode < 300) {
            result.status = ValidationStatus.SUCCESS;
            result.message = (result.statusCode == 201) ? "✅ Ресурс создан" : "✅ Успешный ответ";
        } else if (result.statusCode >= 400 && result.statusCode < 500) {
            result.status = ValidationStatus.WARNING;
            switch (result.statusCode) {
                case 400:
                    result.message = "⚠️  Неверный запрос (Bad Request)";
                    break;
                case 401:
                    result.message = "⚠️  Неавторизован (Unauthorized)";
                    break;
                case 403:
                    result.message = "⚠️  Запрещено (Forbidden)";
                    break;
                case 404:
                    result.message = "⚠️  Не найдено (Not Found)";
                    break;
                default:
                    result.message = "⚠️  Клиентская ошибка: " + result.statusCode;
            }
        } else if (result.statusCode >= 500) {
            result.status = ValidationStatus.ERROR;
            result.message = "❌ Ошибка сервера: " + result.statusCode;
        } else {
            result.status = ValidationStatus.UNKNOWN;
            result.message = "❓ Неизвестный статус: " + result.statusCode;
        }
        result.message += " (" + result.responseTime + "ms)";
    }

    /**
     * Валидация всей спецификации
     */
    private List<ValidationResult> validateApiSpec(OpenApiSpecParser.ApiSpec spec, String accessToken) {
        List<ValidationResult> results = new ArrayList<>();

        String baseUrlToUse = chooseBaseUrl(spec);
        if (baseUrlToUse == null) {
            System.out.println("❌ Нет базового URL для валидации");
            ValidationResult errorResult = new ValidationResult();
            errorResult.specName = spec.title;
            errorResult.endpoint = "N/A";
            errorResult.method = "N/A";
            errorResult.status = ValidationStatus.ERROR;
            errorResult.message = "Отсутствует базовый URL";
            results.add(errorResult);
            return results;
        }

        System.out.println("🌐 Базовый URL: " + baseUrlToUse);
        System.out.println("📊 Эндпоинтов для проверки: " + spec.endpoints.size());

        for (OpenApiSpecParser.ApiEndpoint endpoint : spec.endpoints) {
            try {
                ValidationResult result = validateEndpoint(endpoint, baseUrlToUse, accessToken, spec.title);
                results.add(result);
                printEndpointResult(result);
                Thread.sleep(200);
            } catch (Exception e) {
                System.err.println("❌ Ошибка при валидации эндпоинта: " + e.getMessage());
                ValidationResult errorResult = new ValidationResult();
                errorResult.specName = spec.title;
                errorResult.endpoint = endpoint.path;
                errorResult.method = endpoint.method;
                errorResult.status = ValidationStatus.ERROR;
                errorResult.message = "Ошибка: " + e.getMessage();
                results.add(errorResult);
            }
        }

        return results;
    }

    private ValidationResult validateEndpoint(OpenApiSpecParser.ApiEndpoint endpoint, String baseUrl, String accessToken, String specName) {
        ValidationResult result = new ValidationResult();
        result.specName = specName;
        result.endpoint = endpoint.path;
        result.method = endpoint.method;
        result.operationId = endpoint.operationId;

        try {
            String fullUrl = prepareUrlWithRealIds(baseUrl, endpoint);
            String requestBody = endpoint.hasRequestBody ? generateRequestBodyFromSchema(endpoint) : null;

            long startTime = System.currentTimeMillis();
            String response = executeRequest(endpoint.method, fullUrl, requestBody, accessToken);
            long responseTime = System.currentTimeMillis() - startTime;

            result.statusCode = responseCode;
            result.responseTime = responseTime;
            result.responseBody = response;

            analyzeResponse(result, endpoint);

        } catch (Exception e) {
            result.status = ValidationStatus.ERROR;
            result.message = "Ошибка выполнения: " + e.getMessage();
        }

        return result;
    }

    private void printEndpointResult(ValidationResult result) {
        String statusIcon = switch (result.status) {
            case SUCCESS -> "✅";
            case WARNING -> "⚠️ ";
            case ERROR -> "❌";
            default -> "❓";
        };

        System.out.println(statusIcon + " " + result.method + " " + result.endpoint + " - " + result.message);
    }

    private static void printValidationSummary(List<ValidationResult> results) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("📊 СВОДКА ВАЛИДАЦИИ КОНТРАКТОВ");
        System.out.println("=".repeat(80));

        long successCount = results.stream().filter(r -> r.status == ValidationStatus.SUCCESS).count();
        long warningCount = results.stream().filter(r -> r.status == ValidationStatus.WARNING).count();
        long errorCount = results.stream().filter(r -> r.status == ValidationStatus.ERROR).count();

        System.out.println("✅ Успешных: " + successCount);
        System.out.println("⚠️  Предупреждений: " + warningCount);
        System.out.println("❌ Ошибок: " + errorCount);
        System.out.println("📈 Всего проверок: " + results.size());

        Map<String, List<ValidationResult>> bySpec = new HashMap<>();
        for (ValidationResult res : results) {
            bySpec.computeIfAbsent(res.specName == null ? "UNNAMED" : res.specName, k -> new ArrayList<>()).add(res);
        }

        System.out.println("\n📁 РЕЗУЛЬТАТЫ ПО СПЕЦИФИКАЦИЯМ:");
        for (Map.Entry<String, List<ValidationResult>> entry : bySpec.entrySet()) {
            String specName = entry.getKey();
            List<ValidationResult> specResults = entry.getValue();
            long specSuccess = specResults.stream().filter(r -> r.status == ValidationStatus.SUCCESS).count();
            System.out.println("📋 " + specName + ": " + specSuccess + "/" + specResults.size() + " успешно");
        }
    }

    // Утилиты
    private static String urlEncode(String s) {
        try {
            return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            return s;
        }
    }

    private String chooseBaseUrl(OpenApiSpecParser.ApiSpec spec) {
        if (this.baseUrl != null && !this.baseUrl.isEmpty()) return this.baseUrl;
        if (spec.baseUrls != null && !spec.baseUrls.isEmpty()) return spec.baseUrls.get(0);
        return null;
    }

    // Классы вспомогательные
    public static class ValidationResult {
        public String specName;
        public String endpoint;
        public String method;
        public String operationId;
        public int statusCode;
        public ValidationStatus status;
        public String message;
        public String responseBody;
        public long responseTime;

        public ValidationResult() {
            this.status = ValidationStatus.UNKNOWN;
        }
    }

    public enum ValidationStatus {
        SUCCESS, WARNING, ERROR, UNKNOWN
    }
}
