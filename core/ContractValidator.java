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
 * Исправленный ContractValidator с правильной подстановкой ID
 */
public class ContractValidator {

    private static final String TOKEN_URL = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token";
    private static final ObjectMapper mapper = new ObjectMapper();

    private String accessToken = null;
    private int responseCode = 0;
    private String baseUrl;
    private String clientId;
    private String clientSecret;

    // Хранилище созданных ID ресурсов
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

            // Загружаем спецификации через улучшенный парсер
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
        System.out.println("\n🔄 Этап 1: Создание базовых ресурсов...");
        
        // Сначала создаем простые ресурсы без параметров
        for (OpenApiSpecParser.ApiSpec spec : specs) {
            String baseUrlToUse = chooseBaseUrl(spec);
            if (baseUrlToUse == null) continue;

            for (OpenApiSpecParser.ApiEndpoint endpoint : spec.endpoints) {
                try {
                    if ("POST".equals(endpoint.method) && endpoint.hasRequestBody && !hasPathParameters(endpoint)) {
                        String fullUrl = concatPaths(baseUrlToUse, endpoint.path);
                        System.out.println("🔧 Создание ресурса: " + fullUrl);
                        
                        // Генерируем улучшенное тело запроса
                        String requestBody = generateImprovedRequestBody(endpoint, baseUrlToUse);
                        
                        System.out.println("   📤 Отправка запроса...");
                        String response = executeRequest("POST", fullUrl, requestBody, accessToken);
                        
                        if (responseCode >= 200 && responseCode < 300) {
                            System.out.println("   ✅ Запрос успешен, извлекаем ID...");
                            extractResourceIdFromResponse(endpoint, response, baseUrlToUse);
                        } else {
                            System.err.println("   ❌ Ошибка создания: " + responseCode + " - " + 
                                (response.length() > 100 ? response.substring(0, 100) + "..." : response));
                        }
                        
                        Thread.sleep(300);
                    }
                } catch (Exception e) {
                    System.err.println("❌ Ошибка при создании ресурса " + endpoint.path + ": " + e.getMessage());
                }
            }
        }

        System.out.println("\n🔄 Этап 2: Создание ресурсов с параметрами...");
        
        // Затем создаем ресурсы с path-параметрами, используя уже созданные ID
        for (OpenApiSpecParser.ApiSpec spec : specs) {
            String baseUrlToUse = chooseBaseUrl(spec);
            if (baseUrlToUse == null) continue;

            for (OpenApiSpecParser.ApiEndpoint endpoint : spec.endpoints) {
                try {
                    if ("POST".equals(endpoint.method) && endpoint.hasRequestBody && hasPathParameters(endpoint)) {
                        System.out.println("🔧 Создание ресурса с параметрами: " + endpoint.path);
                        
                        // Подготавливаем URL с реальными значениями
                        String fullUrl = prepareUrlWithRealIds(baseUrlToUse, endpoint);
                        
                        // Проверяем, что все плейсхолдеры заменены
                        if (fullUrl.contains("{") || fullUrl.contains("}")) {
                            System.err.println("   ❌ Остались неразрешенные плейсхолдеры: " + fullUrl);
                            continue;
                        }
                        
                        String requestBody = generateImprovedRequestBody(endpoint, baseUrlToUse);
                        System.out.println("   📤 Отправка запроса...");
                        String response = executeRequest("POST", fullUrl, requestBody, accessToken);
                        
                        if (responseCode >= 200 && responseCode < 300) {
                            System.out.println("   ✅ Запрос успешен, извлекаем ID...");
                            extractResourceIdFromResponse(endpoint, response, baseUrlToUse);
                        } else {
                            System.err.println("   ❌ Ошибка создания: " + responseCode + " - " + 
                                (response.length() > 100 ? response.substring(0, 100) + "..." : response));
                        }
                        
                        Thread.sleep(300);
                    }
                } catch (Exception e) {
                    System.err.println("❌ Ошибка при создании ресурса " + endpoint.path + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     * Улучшенная генерация тела запроса для разных типов эндпоинтов
     */
    private String generateImprovedRequestBody(OpenApiSpecParser.ApiEndpoint endpoint, String baseUrl) {
        String path = endpoint.path.toLowerCase();
        
        // Специфичные тела для разных API
        if (path.contains("/pin/") || path.contains("/token/")) {
            return "{\n" +
                   "  \"pin\": \"1234\",\n" +
                   "  \"publicKeyId\": \"test-key-123\",\n" +
                   "  \"callId\": \"call-" + UUID.randomUUID() + "\",\n" +
                   "  \"sessionId\": \"session-" + UUID.randomUUID() + "\",\n" +
                   "  \"mobilePayService\": \"test-service\",\n" +
                   "  \"inputParameters\": {\n" +
                   "    \"param1\": \"value1\"\n" +
                   "  }\n" +
                   "}";
        }
        else if (path.contains("redemption")) {
            return "{\n" +
                   "  \"redemptionReferenceNumber\": \"" + UUID.randomUUID() + "\",\n" +
                   "  \"redemptionAmount\": 50,\n" +
                   "  \"valuePerPoint\": 0.01,\n" +
                   "  \"programId\": \"A7DV56B\",\n" +
                   "  \"catalogId\": \"C9AP78DS9K\"\n" +
                   "}";
        }
        else if (path.contains("application") || path.contains("lead")) {
            return "{\n" +
                   "  \"name\": \"Test Application\",\n" +
                   "  \"description\": \"Test application for validation\",\n" +
                   "  \"amount\": 1000,\n" +
                   "  \"currency\": \"RUB\",\n" +
                   "  \"customerId\": \"test-customer-123\"\n" +
                   "}";
        }
        else if (path.contains("consent")) {
            return "{\n" +
                   "  \"permissions\": [\"ReadAccounts\", \"ReadBalances\"],\n" +
                   "  \"expirationDateTime\": \"2025-12-31T23:59:59Z\",\n" +
                   "  \"transactionFromDateTime\": \"2024-01-01T00:00:00Z\",\n" +
                   "  \"transactionToDateTime\": \"2024-12-31T23:59:59Z\"\n" +
                   "}";
        }
        else if (path.contains("prepaid")) {
            return "{\n" +
                   "  \"partnerId\": \"test-partner-123\",\n" +
                   "  \"cardType\": \"virtual\",\n" +
                   "  \"currency\": \"RUB\"\n" +
                   "}";
        }
        else if (path.contains("leads")) {
            return "{\n" +
                   "  \"leads\": [\n" +
                   "    {\n" +
                   "      \"firstName\": \"Test\",\n" +
                   "      \"lastName\": \"User\",\n" +
                   "      \"phone\": \"+79123456789\",\n" +
                   "      \"email\": \"test@example.com\"\n" +
                   "    }\n" +
                   "  ]\n" +
                   "}";
        }
        
        // Стандартное тело по схеме
        if (endpoint.requestBodySchema != null) {
            return generateJsonFromSchema(endpoint.requestBodySchema);
        }
        
        return generateDefaultRequestBody();
    }

    private boolean hasPathParameters(OpenApiSpecParser.ApiEndpoint endpoint) {
        return endpoint.path.contains("{") && endpoint.path.contains("}");
    }

    /**
     * Улучшенное извлечение ID с учетом baseUrl
     */
    private void extractResourceIdFromResponse(OpenApiSpecParser.ApiEndpoint endpoint, String response, String baseUrl) {
        try {
            if (response == null || response.trim().isEmpty()) {
                System.err.println("   ❌ Пустой ответ, невозможно извлечь ID");
                return;
            }

            JsonNode root = mapper.readTree(response);
            System.out.println("   🔍 Анализ ответа для извлечения ID...");

            // Список полей для поиска ID
            String[] idFields = {"id", "consentId", "accountId", "applicationId", "paymentId",
                    "VRPId", "offerId", "customerLeadId", "productApplicationId", "consentid"};

            // Поиск в корне
            for (String field : idFields) {
                JsonNode node = root.path(field);
                if (!node.isMissingNode() && (node.isTextual() || node.isNumber())) {
                    String value = node.asText();
                    storeResourceIdWithContext(field, value, baseUrl);
                    System.out.println("   ✅ Извлечен ID из поля '" + field + "': " + value);
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
                        storeResourceIdWithContext(field, value, baseUrl);
                        System.out.println("   ✅ Извлечен ID из поля 'Data." + field + "': " + value);
                        return;
                    }
                }
            }

            // Рекурсивный поиск
            for (String field : idFields) {
                String foundValue = findIdRecursively(root, field);
                if (foundValue != null) {
                    storeResourceIdWithContext(field, foundValue, baseUrl);
                    System.out.println("   ✅ Извлечен ID рекурсивным поиском '" + field + "': " + foundValue);
                    return;
                }
            }

            System.err.println("   ❌ Не удалось найти ID в ответе");

        } catch (Exception e) {
            System.err.println("   ❌ Ошибка извлечения ID: " + e.getMessage());
        }
    }

    /**
     * Рекурсивный поиск ID в JSON дереве
     */
    private String findIdRecursively(JsonNode node, String targetField) {
        if (node == null || node.isMissingNode()) return null;
        
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String fieldName = entry.getKey();
                JsonNode fieldValue = entry.getValue();
                
                if (fieldName.equalsIgnoreCase(targetField) && (fieldValue.isTextual() || fieldValue.isNumber())) {
                    return fieldValue.asText();
                }
                
                String nestedResult = findIdRecursively(fieldValue, targetField);
                if (nestedResult != null) {
                    return nestedResult;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode item : node) {
                String nestedResult = findIdRecursively(item, targetField);
                if (nestedResult != null) {
                    return nestedResult;
                }
            }
        }
        
        return null;
    }

    /**
     * Сохранение ID с учетом контекста (baseUrl)
     */
    private void storeResourceIdWithContext(String fieldName, String idValue, String baseUrl) {
        if (fieldName == null || idValue == null || baseUrl == null) return;
        
        // Сохраняем под оригинальным именем
        String key = fieldName.toLowerCase();
        resourceIds.put(key, idValue);
        
        // Сохраняем с контекстом baseUrl для специфичных сервисов
        String contextKey = normalizeBaseUrl(baseUrl) + ":" + key;
        resourceIds.put(contextKey, idValue);
        
        System.out.println("   💾 Сохранен ID: " + key + " = " + idValue);
        System.out.println("   💾 Сохранен ID с контекстом: " + contextKey + " = " + idValue);
    }

    /**
     * Нормализация baseUrl для использования как ключа
     */
    private String normalizeBaseUrl(String baseUrl) {
        if (baseUrl == null) return "default";
        // Извлекаем домен и путь, убираем протокол
        return baseUrl.replace("https://", "")
                      .replace("http://", "")
                      .replace("/", "_")
                      .toLowerCase();
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
            String replacement = findParameterValue(paramName, endpoint, baseUrl);
            System.out.println("   🔍 Замена параметра {" + paramName + "} на: " + replacement);
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
                    String val = findParameterValue(param.name, endpoint, baseUrl);
                    if (firstQueryParam) {
                        urlBuilder.append("?");
                        firstQueryParam = false;
                    } else {
                        urlBuilder.append("&");
                    }
                    urlBuilder.append(urlEncode(param.name)).append("=").append(urlEncode(val));
                    System.out.println("   🔍 Query параметр " + param.name + " = " + val);
                }
            }
        }

        return urlBuilder.toString();
    }

    /**
     * Улучшенный поиск параметров с учетом контекста
     */
    private String findParameterValue(String paramName, OpenApiSpecParser.ApiEndpoint endpoint, String baseUrl) {
        if (paramName == null) return generateParameterValue(paramName, endpoint);
        
        String key = paramName.toLowerCase();
        String contextKey = normalizeBaseUrl(baseUrl) + ":" + key;
        
        // Сначала ищем с контекстом (специфичный для сервиса)
        if (resourceIds.containsKey(contextKey)) {
            String value = resourceIds.get(contextKey);
            System.out.println("   ✅ Найден параметр " + paramName + " с контекстом = " + value);
            return value;
        }
        
        // Затем ищем без контекста (глобальный)
        if (resourceIds.containsKey(key)) {
            String value = resourceIds.get(key);
            System.out.println("   ✅ Найден параметр " + paramName + " = " + value);
            return value;
        }

        // Поиск по синонимам с контекстом
        String[] synonyms = getParameterSynonyms(paramName);
        for (String syn : synonyms) {
            String synContextKey = normalizeBaseUrl(baseUrl) + ":" + syn.toLowerCase();
            if (resourceIds.containsKey(synContextKey)) {
                String value = resourceIds.get(synContextKey);
                System.out.println("   ✅ Найден параметр " + paramName + " через синоним с контекстом " + syn + " = " + value);
                return value;
            }
        }
        
        // Поиск по синонимам без контекста
        for (String syn : synonyms) {
            String synKey = syn.toLowerCase();
            if (resourceIds.containsKey(synKey)) {
                String value = resourceIds.get(synKey);
                System.out.println("   ✅ Найден параметр " + paramName + " через синоним " + syn + " = " + value);
                return value;
            }
        }

        // Если не нашли - генерируем
        String generatedValue = generateParameterValue(paramName, endpoint);
        System.out.println("   ⚠️  Параметр " + paramName + " не найден, сгенерировано: " + generatedValue);
        return generatedValue;
    }

    /**
     * Улучшенная система синонимов - только логически связанные типы
     */
    private String[] getParameterSynonyms(String paramName) {
        if (paramName == null) return new String[0];
        
        String lowerParam = paramName.toLowerCase();
        
        switch (lowerParam) {
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
                return new String[]{"publicid"};
            case "uin":
                return new String[]{"uin"};
            case "statementid":
                return new String[]{"statementid"};
            default:
                return new String[0]; // Не возвращаем "id" как синоним для всех
        }
    }

    /**
     * Генерация значения параметра по имени с учетом контекста
     */
    private String generateParameterValue(String paramName, OpenApiSpecParser.ApiEndpoint endpoint) {
        if (paramName == null) return UUID.randomUUID().toString();
        
        String lowerParam = paramName.toLowerCase();
        
        // Генерируем значения в зависимости от типа параметра и контекста эндпоинта
        switch (lowerParam) {
            case "externalaccountid":
            case "accountid":
                // Для accountId генерируем UUID формата
                return UUID.randomUUID().toString();
            case "publicid":
                return "public-id-" + UUID.randomUUID().toString().substring(0, 8);
            case "uin":
                return "18810150200605213474";
            case "statementid":
                return "statement-" + UUID.randomUUID().toString().substring(0, 8);
            case "consentid":
                return UUID.randomUUID().toString();
            case "id":
                // Для общего id также используем UUID
                return UUID.randomUUID().toString();
            default:
                // Для неизвестных параметров генерируем значение на основе имени
                return lowerParam + "-" + UUID.randomUUID().toString().substring(0, 8);
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
     * Генерация тела запроса на основе схемы из спецификации
     */
    private String generateRequestBodyFromSchema(OpenApiSpecParser.ApiEndpoint endpoint) {
        try {
            if (endpoint.requestBodySchema != null) {
                return generateJsonFromSchema(endpoint.requestBodySchema);
            }
            return generateRequestBodyByPath(endpoint.path);
        } catch (Exception e) {
            System.err.println("❌ Ошибка генерации тела: " + e.getMessage());
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
                    String fieldName = f.getKey();
                    JsonNode fieldSchema = f.getValue();
                    requestBody.put(fieldName, generateValueFromFieldSchema(fieldName, fieldSchema));
                }
                return mapper.writeValueAsString(requestBody);
            }
            
            return generateDefaultRequestBody();
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка generateJsonFromSchema: " + e.getMessage());
        }
        return generateDefaultRequestBody();
    }

    private Object generateValueFromFieldSchema(String fieldName, JsonNode schema) {
        String type = schema.path("type").asText("string");
        String format = schema.path("format").asText("");
        
        switch (type) {
            case "string":
                if ("uuid".equals(format)) return UUID.randomUUID().toString();
                if ("date-time".equals(format)) return new Date().toInstant().toString();
                return generateStringValue(fieldName);
            case "integer":
            case "number":
                return schema.path("minimum").asInt(100);
            case "boolean":
                return true;
            case "array":
                JsonNode items = schema.path("items");
                return Collections.singletonList(generateValueFromFieldSchema(fieldName, items));
            case "object":
                Map<String, Object> obj = new HashMap<>();
                JsonNode objProperties = schema.path("properties");
                if (objProperties.isObject()) {
                    Iterator<Map.Entry<String, JsonNode>> objFields = objProperties.fields();
                    while (objFields.hasNext()) {
                        Map.Entry<String, JsonNode> f = objFields.next();
                        obj.put(f.getKey(), generateValueFromFieldSchema(f.getKey(), f.getValue()));
                    }
                }
                return obj;
            default:
                return generateStringValue(fieldName);
        }
    }

    private String generateStringValue(String fieldName) {
        if (fieldName == null) return "test-value";
        switch (fieldName.toLowerCase()) {
            case "name":
            case "username":
                return "testuser";
            case "email":
                return "test@example.com";
            case "phone":
            case "phonenumber":
                return "+79123456789";
            case "description":
                return "Test description";
            case "programid":
                return "A7DV56B";
            case "catalogid":
                return "C9AP78DS9K";
            case "redemptionreferencenumber":
                return UUID.randomUUID().toString();
            case "redemptionamount":
                return "50";
            case "valueperpoint":
                return "0.01";
            default:
                return "test-value";
        }
    }

    private String generateRequestBodyByPath(String path) {
        if (path == null) return generateDefaultRequestBody();
        if (path.contains("redemption")) {
            return "{"
                    + "\"redemptionReferenceNumber\": \"" + UUID.randomUUID().toString() + "\","
                    + "\"redemptionAmount\": 50,"
                    + "\"valuePerPoint\": 0.01,"
                    + "\"programId\": \"A7DV56B\","
                    + "\"catalogId\": \"C9AP78DS9K\""
                    + "}";
        } else if (path.contains("application") || path.contains("lead")) {
            return "{"
                    + "\"name\": \"Test Application\","
                    + "\"description\": \"Test application for validation\","
                    + "\"amount\": 1000,"
                    + "\"currency\": \"RUB\""
                    + "}";
        } else if (path.contains("payment")) {
            return "{"
                    + "\"amount\": 100,"
                    + "\"currency\": \"RUB\","
                    + "\"description\": \"Test payment\","
                    + "\"recipient\": \"test-recipient\""
                    + "}";
        } else {
            return generateDefaultRequestBody();
        }
    }

    private String generateDefaultRequestBody() {
        return "{"
                + "\"test\": \"data\","
                + "\"timestamp\": \"" + System.currentTimeMillis() + "\","
                + "\"reference\": \"" + UUID.randomUUID().toString() + "\""
                + "}";
    }

    /**
     * Выполнение HTTP запроса
     */
    private String executeRequest(String method, String url, String requestBody, String accessToken) throws Exception {
        System.out.println("   📤 Выполнение запроса: " + method + " " + url);
        
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

        System.out.println("🔑 Получение токена: " + TOKEN_URL);
        
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
        System.out.println("Response Code при получении токена: " + responseCode);

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
        System.out.println("-".repeat(60));

        for (OpenApiSpecParser.ApiEndpoint endpoint : spec.endpoints) {
            try {
                System.out.println("\n🔹 Проверка: " + endpoint.method + " " + endpoint.path);
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

        System.out.println(statusIcon + " " + result.method + " " + result.endpoint);
        System.out.println("   Статус: " + result.statusCode + " - " + result.message);

        if (result.operationId != null && !"N/A".equals(result.operationId)) {
            System.out.println("   OperationId: " + result.operationId);
        }
    }

    private static void printValidationSummary(List<ValidationResult> results) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("📊 СВОДКА ВАЛИДАЦИИ КОНТРАКТОВ");
        System.out.println("=".repeat(80));

        long successCount = results.stream().filter(r -> r.status == ValidationStatus.SUCCESS).count();
        long warningCount = results.stream().filter(r -> r.status == ValidationStatus.WARNING).count();
        long errorCount = results.stream().filter(r -> r.status == ValidationStatus.ERROR).count();
        long unknownCount = results.stream().filter(r -> r.status == ValidationStatus.UNKNOWN).count();

        System.out.println("✅ Успешных: " + successCount);
        System.out.println("⚠️  Предупреждений: " + warningCount);
        System.out.println("❌ Ошибок: " + errorCount);
        System.out.println("❓ Неизвестных: " + unknownCount);
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
