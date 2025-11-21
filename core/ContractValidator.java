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
 * Исправленная версия ContractValidator.java
 *
 * Основные исправления и улучшения:
 * - Нормализация имён параметров и ключей resourceIds (все ключи в lower-case)
 * - Универсальная замена path-параметров {param} регулярным выражением (независимо от регистра)
 * - Расширенный поиск ID в ответах (разные поля, Data.*, nested)
 * - Безопасная отправка form-data при получении токена (URLEncoder)
 * - Поддержка PATCH через X-HTTP-Method-Override
 * - Устранение ошибки "Illegal character in path" — плейсхолдеры заменяются на реальные значения ДО создания URI
 * - Более устойчивое чтение ответов (обработка null stream)
 * - Таймауты у HttpURLConnection для избегания зависаний
 *
 * Примечание: этот класс не зависит от сторонних библиотек кроме Jackson (com.fasterxml.jackson.databind).
 */
public class ContractValidator {

    private static final String TOKEN_URL = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token";
    private static final ObjectMapper mapper = new ObjectMapper();

    private String accessToken = null;
    private int responseCode = 0;
    private String baseUrl;
    private String clientId;
    private String clientSecret;

    // Хранение созданных ID ресурсов. Ключи нормализованы: baseUrl.toLowerCase() + ":" + fieldName.toLowerCase()
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
     * Основной сценарий валидации: получение токена, парсинг спецификаций, создание ресурсов и проверка эндпоинтов.
     * Здесь предполагается, что парсер спецификаций (OpenApiSpecParser) доступен и возвращает структуры,
     * совместимые с используемыми в этом классе.
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

            // Загружаем спецификации через парсер (который должен быть в проекте)
            List<OpenApiSpecParser.ApiSpec> specs = OpenApiSpecParser.parseAllSpecs();
            if (specs == null || specs.isEmpty()) {
                System.err.println("❌ Не найдено спецификаций для валидации");
                return validationResults;
            }
            System.out.println("✅ Загружено спецификаций: " + specs.size());

            System.out.println("\n🔄 Создание базовых ресурсов для получения ID...");
            createBasicResources(specs, accessToken);

            System.out.println("\n🔄 Создание сложных ресурсов...");
            createComplexResources(specs, accessToken);

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
     * Создание базовых ресурсов: POST без path-параметров.
     */
    private void createBasicResources(List<OpenApiSpecParser.ApiSpec> specs, String accessToken) {
        for (OpenApiSpecParser.ApiSpec spec : specs) {
            String baseUrlToUse = chooseBaseUrl(spec);
            if (baseUrlToUse == null) continue;

            for (OpenApiSpecParser.ApiEndpoint endpoint : spec.endpoints) {
                try {
                    if ("POST".equals(endpoint.method) && endpoint.hasRequestBody && !hasPathParameters(endpoint)) {
                        System.out.println("🔧 Создание базового ресурса: " + endpoint.path);
                        String fullUrl = concatPaths(baseUrlToUse, endpoint.path);
                        String requestBody = generateRequestBodyFromSchema(endpoint);
                        String response = executeRequest("POST", fullUrl, requestBody, accessToken);
                        extractResourceIdFromResponse(endpoint, response, baseUrlToUse);
                        Thread.sleep(300);
                    }
                } catch (Exception e) {
                    System.err.println("❌ Ошибка при создании базового ресурса " + endpoint.path + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     * Создание сложных ресурсов: POST с path-параметрами.
     */
    private void createComplexResources(List<OpenApiSpecParser.ApiSpec> specs, String accessToken) {
        for (OpenApiSpecParser.ApiSpec spec : specs) {
            String baseUrlToUse = chooseBaseUrl(spec);
            if (baseUrlToUse == null) continue;

            for (OpenApiSpecParser.ApiEndpoint endpoint : spec.endpoints) {
                try {
                    if ("POST".equals(endpoint.method) && endpoint.hasRequestBody && hasPathParameters(endpoint)) {
                        System.out.println("🔧 Создание сложного ресурса: " + endpoint.path);
                        String fullUrl = prepareUrlWithRealIds(baseUrlToUse, endpoint);
                        String requestBody = generateRequestBodyFromSchema(endpoint);
                        String response = executeRequest("POST", fullUrl, requestBody, accessToken);
                        extractResourceIdFromResponse(endpoint, response, baseUrlToUse);
                        Thread.sleep(300);
                    }
                } catch (Exception e) {
                    System.err.println("❌ Ошибка при создании сложного ресурса " + endpoint.path + ": " + e.getMessage());
                }
            }
        }
    }

    private boolean hasPathParameters(OpenApiSpecParser.ApiEndpoint endpoint) {
        return endpoint.parameters != null && endpoint.parameters.stream().anyMatch(p -> "path".equalsIgnoreCase(p.in));
    }

    /**
     * Попытка извлечь ID ресурса из ответа JSON и сохранить его в resourceIds (ключи нормализованы).
     */
    private void extractResourceIdFromResponse(OpenApiSpecParser.ApiEndpoint endpoint, String response, String baseUrl) {
        try {
            if (response == null || response.trim().isEmpty()) return;

            JsonNode root = mapper.readTree(response);

            // Список кандидатных полей для ID
            String[] idFields = {"id", "consentId", "accountId", "applicationId", "paymentId",
                    "VRPId", "offerId", "customerLeadId", "productApplicationId", "paymentId", "consentid"};

            // Непосредственные поля в корне
            for (String field : idFields) {
                JsonNode node = root.path(field);
                if (!node.isMissingNode() && (node.isTextual() || node.isNumber())) {
                    String value = node.asText();
                    storeResourceId(baseUrl, field, value);
                    return;
                }
            }

            // Data.*
            JsonNode dataNode = root.path("Data");
            if (dataNode.isObject()) {
                for (String field : idFields) {
                    JsonNode node = dataNode.path(field);
                    if (!node.isMissingNode() && (node.isTextual() || node.isNumber())) {
                        String value = node.asText();
                        storeResourceId(baseUrl, field, value);
                        return;
                    }
                }
            }

            // Ищем рекурсивно по дереву первые попавшиеся поля с именем id / *Id
            String found = findIdRecursively(root);
            if (found != null) {
                storeResourceId(baseUrl, "id", found);
            }

        } catch (Exception e) {
            System.err.println("❌ Не удалось извлечь ID из ответа: " + e.getMessage());
        }
    }

    private String findIdRecursively(JsonNode node) {
        if (node == null || node.isMissingNode()) return null;
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> it = node.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                String key = e.getKey();
                JsonNode val = e.getValue();
                if (key != null && (key.equalsIgnoreCase("id") || key.toLowerCase().endsWith("id"))) {
                    if (val.isTextual() || val.isNumber()) return val.asText();
                }
                String nested = findIdRecursively(val);
                if (nested != null) return nested;
            }
        } else if (node.isArray()) {
            for (JsonNode item : node) {
                String nested = findIdRecursively(item);
                if (nested != null) return nested;
            }
        }
        return null;
    }

    private void storeResourceId(String baseUrl, String fieldName, String idValue) {
        if (baseUrl == null || fieldName == null || idValue == null) return;
        String key = normalizeKey(baseUrl) + ":" + normalizeKey(fieldName);
        resourceIds.put(key, idValue);
        System.out.println("✅ Создан ресурс: " + fieldName + " = " + idValue);
    }

    private String normalizeKey(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    /**
     * Подготовка URL: замена всех плейсхолдеров {param} на реальные значения, добавление query параметров.
     * Проблема Illegal character in path решается здесь — до создания URI мы заменяем фигурные скобки.
     */
    private String prepareUrlWithRealIds(String baseUrl, OpenApiSpecParser.ApiEndpoint endpoint) {
        String path = endpoint.path;

        // Заменяем все {param} с помощью regex — независимо от регистра
        // Находим все вхождения {paramName}
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\\{([^/}]+)\\}");
        java.util.regex.Matcher m = p.matcher(path);
        StringBuffer sb = new StringBuffer();

        while (m.find()) {
            String rawParamName = m.group(1); // original param from braces
            String replacement = getRealParameterValueByName(rawParamName, baseUrl, endpoint);
            if (replacement == null) {
                // если не нашли — генерируем тестовое значение и используем его
                replacement = generateParameterValue(rawParamName);
            }
            // escape replacement for usage in URL path (encode path segment)
            String encoded = urlEncodePathSegment(replacement);
            m.appendReplacement(sb, encoded);
        }
        m.appendTail(sb);
        String resolvedPath = sb.toString();

        // Добавляем query-параметры, если есть обязательные query параметры (required=true)
        StringBuilder urlBuilder = new StringBuilder(concatPaths(baseUrl, resolvedPath));
        boolean firstQueryParam = !urlBuilder.toString().contains("?");

        if (endpoint.parameters != null) {
            for (OpenApiSpecParser.ApiParameter param : endpoint.parameters) {
                if ("query".equalsIgnoreCase(param.in) && param.required) {
                    String val = getRealParameterValue(param, baseUrl);
                    if (val == null) val = generateParameterValue(param.name);
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

    private String concatPaths(String base, String path) {
        if (base == null) return path;
        if (path == null || path.isEmpty()) return base;
        if (base.endsWith("/") && path.startsWith("/")) return base.substring(0, base.length() - 1) + path;
        if (!base.endsWith("/") && !path.startsWith("/")) return base + "/" + path;
        return base + path;
    }

    /**
     * По имени параметра (как в плейсхолдере) пытаемся найти значение среди ресурсо-идов, синомимов и примеров.
     */
    private String getRealParameterValueByName(String rawParamName, String baseUrl, OpenApiSpecParser.ApiEndpoint endpoint) {
        // пытаемся найти параметр в списке endpoint.parameters по разным вариантам имени
        if (endpoint.parameters != null) {
            for (OpenApiSpecParser.ApiParameter p : endpoint.parameters) {
                if (p.name != null && p.name.equalsIgnoreCase(rawParamName)) {
                    return getRealParameterValue(p, baseUrl);
                }
            }
        }
        // если не нашли — попробуем напрямую в resourceIds по синонимам
        String[] synonyms = getParameterSynonyms(rawParamName);
        for (String syn : synonyms) {
            String key = normalizeKey(baseUrl) + ":" + normalizeKey(syn);
            if (resourceIds.containsKey(key)) return resourceIds.get(key);
        }
        // fallback: use example or generated
        return null;
    }

    /**
     * Возвращает реальное значение параметра (если найдено в resourceIds или из примера).
     */
    private String getRealParameterValue(OpenApiSpecParser.ApiParameter param, String baseUrl) {
        if (param == null) return null;
        // 1) check exact resource key (normalized)
        String key = normalizeKey(baseUrl) + ":" + normalizeKey(param.name);
        if (resourceIds.containsKey(key)) return resourceIds.get(key);

        // 2) check synonyms
        String[] synonyms = getParameterSynonyms(param.name);
        for (String syn : synonyms) {
            String k = normalizeKey(baseUrl) + ":" + normalizeKey(syn);
            if (resourceIds.containsKey(k)) return resourceIds.get(k);
        }

        // 3) example from spec
        if (param.example != null && !param.example.isEmpty()) return param.example;

        // 4) fallback generate value
        return generateParameterValue(param.name);
    }

    private String[] getParameterSynonyms(String paramName) {
        if (paramName == null) return new String[]{"id"};
        switch (paramName.toLowerCase(Locale.ROOT)) {
            case "consentid":
            case "consent-id":
            case "consent_id":
                return new String[]{"consentId", "consentid", "id"};
            case "accountid":
            case "externalaccountid":
                return new String[]{"externalAccountID", "externalAccountId", "accountId", "id"};
            case "vrpid":
            case "vrpId":
                return new String[]{"VRPId", "vrpId", "paymentId", "id"};
            case "applicationid":
                return new String[]{"applicationId", "id"};
            case "paymentid":
                return new String[]{"paymentId", "id"};
            case "offerid":
                return new String[]{"offerId", "id"};
            case "customerleadid":
                return new String[]{"customerLeadId", "id"};
            case "productapplicationid":
                return new String[]{"productApplicationId", "id"};
            case "publicid":
                return new String[]{"publicId", "id"};
            case "uin":
                return new String[]{"uin", "id"};
            default:
                return new String[]{"id", paramName};
        }
    }

    /**
     * Генерация значения параметра по имени (тестовое значение).
     */
    private String generateParameterValue(String paramName) {
        if (paramName == null) return UUID.randomUUID().toString();
        switch (paramName.toLowerCase(Locale.ROOT)) {
            case "externalaccountid":
            case "accountid":
                return "0dbcb7ee-6c59-483b-966a-44d11557665b";
            case "correlation-id":
            case "correlationid":
                return UUID.randomUUID().toString();
            case "authorization":
                return "Bearer " + (accessToken != null ? accessToken : "");
            case "publicid":
                return "test-public-id-123";
            case "uin":
                return "18810150200605213474";
            case "id":
                return UUID.randomUUID().toString();
            default:
                return "test-value-" + UUID.randomUUID().toString().substring(0, 8);
        }
    }

    /**
     * Генерация тела запроса по схеме или по пути, адаптирована из предыдущей версии.
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
                    requestBody.put(f.getKey(), generateValueFromFieldSchema(f.getKey(), f.getValue()));
                }
                return mapper.writeValueAsString(requestBody);
            }
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
            default:
                return generateStringValue(fieldName);
        }
    }

    private String generateStringValue(String fieldName) {
        if (fieldName == null) return "test-value";
        switch (fieldName.toLowerCase(Locale.ROOT)) {
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
     * Выполнение HTTP запроса (GET/POST/PUT/DELETE/PATCH), поддерживает X-HTTP-Method-Override для PATCH.
     */
    private String executeRequest(String method, String url, String requestBody, String accessToken) throws Exception {
        // Перед созданием URI убеждаемся, что url не содержит незаменённых фигурных скобок
        if (url.contains("{") || url.contains("}")) {
            throw new IllegalArgumentException("URL содержит неразрешённые плейсхолдеры: " + url);
        }

        URL requestUrl = new URI(url).toURL();
        HttpURLConnection conn = (HttpURLConnection) requestUrl.openConnection();

        // таймауты
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
     * Получение access token через OAuth2 client_credentials с URLEncoding.
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
     * Анализ ответа и назначение статуса валидации.
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
     * Валидация всей спецификации: последовательная проверка эндпоинтов.
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
                Thread.sleep(300);
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

    private static String urlEncodePathSegment(String s) {
        // Простая кодировка для сегмента пути (замена пробелов и некоторых спецсимволов)
        if (s == null) return "";
        return s.replace(" ", "%20").replace("{", "%7B").replace("}", "%7D");
    }

    // безопасное кодирование для form data
    private static String urlEncodeForm(String s) {
        return urlEncode(s);
    }

    // helper for path concatenation
    private String chooseBaseUrl(OpenApiSpecParser.ApiSpec spec) {
        if (this.baseUrl != null && !this.baseUrl.isEmpty()) return this.baseUrl;
        if (spec.baseUrls != null && !spec.baseUrls.isEmpty()) return spec.baseUrls.get(0);
        return null;
    }

    // Преобразования и поиск в resourceIds доступны через normalizeKey и resourceIds map

    // Классы вспомогательные (ValidationResult и статусы)
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

/*
 * Зависимость: предполагается, что OpenApiSpecParser находится в проекте и предоставляет типы:
 * OpenApiSpecParser.ApiSpec { String title; List<String> baseUrls; List<ApiEndpoint> endpoints; }
 * OpenApiSpecParser.ApiEndpoint { String method; String path; String operationId; boolean hasRequestBody;
 *      List<ApiParameter> parameters; JsonNode requestBodySchema; }
 * OpenApiSpecParser.ApiParameter { String name; String in; boolean required; String example; }
 *
 * Если парсер назван иначе — нужно адаптировать вызовы.
 */
