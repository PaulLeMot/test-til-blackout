package scanners.fuzzing;

import core.ScanConfig;
import core.Vulnerability;
import core.Vulnerability.Category;
import core.Vulnerability.Severity;
import core.ApiClient;
import scanners.SecurityScanner;
import java.util.*;
import java.util.logging.Logger;
import org.json.JSONObject;
import org.json.JSONArray;

// Импорты для OpenAPI
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;

public class AdvancedFuzzingScanner implements SecurityScanner {
    private static final Logger logger = Logger.getLogger(AdvancedFuzzingScanner.class.getName());
    private EnhancedVulnerabilityDetector vulnerabilityDetector;
    private HttpClientWrapper httpClient;
    private BaselineRequestGenerator baselineGenerator;
    private Set<String> testedEndpoints = new HashSet<>();

    public AdvancedFuzzingScanner() {
        this.vulnerabilityDetector = new EnhancedVulnerabilityDetector();
        this.httpClient = new HttpClientWrapper();
        this.baselineGenerator = new BaselineRequestGenerator();
    }

    @Override
    public String getName() {
        return "Advanced Fuzzing Scanner v3.0";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        try {
            logger.info("🚀 Starting REAL vulnerability scanning...");

            // Преобразуем OpenAPI объект в Map для совместимости
            Map<String, Object> openApi = convertOpenApiToMap(openApiObj);

            if (openApi == null) {
                logger.severe("❌ Не удалось преобразовать OpenAPI объект в Map");
                return vulnerabilities;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> paths = (Map<String, Object>) openApi.get("paths");

            if (paths == null || paths.isEmpty()) {
                logger.warning("❌ No paths found in OpenAPI specification");
                return vulnerabilities;
            }

            logger.info("📊 Found " + paths.size() + " endpoints in API specification");

            // Получаем банковский токен
            String bankToken = config.getBankToken();
            if (bankToken == null || bankToken.isEmpty()) {
                logger.warning("⚠️  No bank token available. Skipping authenticated scans.");
                return vulnerabilities;
            }

            // Создаем согласие
            String consentId = baselineGenerator.generateConsentId(config, bankToken);
            if (consentId == null) {
                logger.warning("⚠️  Failed to create consent. Skipping authenticated scans.");
                return vulnerabilities;
            }

            // Получаем реальные accountId
            List<String> realAccountIds = getRealAccountIds(config, bankToken, consentId);
            logger.info("📋 Found " + realAccountIds.size() + " real accounts");

            // Сохраняем реальные ID для использования в фаззинге
            baselineGenerator.setRealAccountIds(realAccountIds);
            baselineGenerator.setConsentId(consentId);

            // Тестируем каждый эндпоинт
            int totalEndpoints = 0;
            for (Map.Entry<String, Object> pathEntry : paths.entrySet()) {
                String path = pathEntry.getKey();
                @SuppressWarnings("unchecked")
                Map<String, Object> pathMethods = (Map<String, Object>) pathEntry.getValue();

                for (Map.Entry<String, Object> methodEntry : pathMethods.entrySet()) {
                    String method = methodEntry.getKey().toUpperCase();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> operation = (Map<String, Object>) methodEntry.getValue();

                    // Пропускаем сервисные эндпоинты
                    if (path.contains("/auth") || path.contains("jwks.json") || path.equals("/")) {
                        continue;
                    }

                    ApiEndpoint endpoint = createEndpointFromSpec(path, method, operation);
                    if (endpoint == null) continue;

                    totalEndpoints++;

                    // Проверяем, не тестировали ли мы уже этот эндпоинт
                    String endpointKey = method + ":" + path;
                    if (testedEndpoints.contains(endpointKey)) {
                        continue;
                    }
                    testedEndpoints.add(endpointKey);

                    logger.info("🎯 Testing endpoint: " + method + " " + path);

                    try {
                        // Генерируем базовый валидный запрос
                        ValidRequestTemplate template = baselineGenerator.generateValidRequestTemplate(
                                endpoint, config, bankToken, paths
                        );

                        if (template == null || !template.isValid()) {
                            logger.warning("⚠️  Could not generate valid request template for " + endpointKey +
                                    ". Skipping fuzzing for this endpoint.");
                            continue;
                        }

                        // Проводим фаззинг с валидными запросами
                        List<Vulnerability> endpointVulns = fuzzEndpointWithValidRequests(
                                endpoint, template, config
                        );
                        vulnerabilities.addAll(endpointVulns);

                        logger.info("✅ Endpoint " + endpointKey + " completed: " +
                                endpointVulns.size() + " vulnerabilities found");

                        // Не спамим сервер
                        Thread.sleep(300);
                    } catch (Exception e) {
                        logger.severe("❌ Error scanning endpoint " + endpointKey + ": " + e.getMessage());
                    }
                }
            }

            logger.info("✅ Fuzzing completed. Tested " + totalEndpoints + " endpoints. Found " +
                    vulnerabilities.size() + " REAL vulnerabilities");

            // Фильтрация дубликатов
            return filterDuplicateVulnerabilities(vulnerabilities);

        } catch (Exception e) {
            logger.severe("❌ Critical error during fuzzing scan: " + e.getMessage());
            e.printStackTrace();
            return vulnerabilities;
        }
    }

    /**
     * Конвертирует объект OpenAPI в Map для обратной совместимости
     */
    private Map<String, Object> convertOpenApiToMap(Object openApiObj) {
        try {
            if (openApiObj instanceof Map) {
                return (Map<String, Object>) openApiObj;
            }

            // Если это объект OpenAPI из swagger, конвертируем в Map
            if (openApiObj instanceof OpenAPI) {
                OpenAPI openAPI = (OpenAPI) openApiObj;
                Map<String, Object> result = new HashMap<>();

                if (openAPI.getPaths() != null) {
                    Map<String, Object> pathsMap = new HashMap<>();
                    for (String pathKey : openAPI.getPaths().keySet()) {
                        PathItem pathItem = openAPI.getPaths().get(pathKey);
                        pathsMap.put(pathKey, convertPathItemToMap(pathItem));
                    }
                    result.put("paths", pathsMap);
                }

                logger.info("✅ OpenAPI объект успешно преобразован в Map");
                return result;
            }

        } catch (Exception e) {
            logger.severe("❌ Error converting OpenAPI to Map: " + e.getMessage());
        }
        return null;
    }

    private Map<String, Object> convertPathItemToMap(PathItem pathItem) {
        Map<String, Object> result = new HashMap<>();
        // Конвертируем методы (GET, POST, etc.)
        if (pathItem.getGet() != null) {
            result.put("get", convertOperationToMap(pathItem.getGet()));
        }
        if (pathItem.getPost() != null) {
            result.put("post", convertOperationToMap(pathItem.getPost()));
        }
        if (pathItem.getPut() != null) {
            result.put("put", convertOperationToMap(pathItem.getPut()));
        }
        if (pathItem.getDelete() != null) {
            result.put("delete", convertOperationToMap(pathItem.getDelete()));
        }
        if (pathItem.getPatch() != null) {
            result.put("patch", convertOperationToMap(pathItem.getPatch()));
        }
        return result;
    }

    private Map<String, Object> convertOperationToMap(Operation operation) {
        Map<String, Object> result = new HashMap<>();

        // Параметры
        if (operation.getParameters() != null) {
            List<Map<String, Object>> parameters = new ArrayList<>();
            for (Parameter parameter : operation.getParameters()) {
                parameters.add(convertParameterToMap(parameter));
            }
            result.put("parameters", parameters);
        }

        // Тело запроса
        if (operation.getRequestBody() != null) {
            result.put("requestBody", convertRequestBodyToMap(operation.getRequestBody()));
        }

        return result;
    }

    private Map<String, Object> convertParameterToMap(Parameter parameter) {
        Map<String, Object> result = new HashMap<>();
        result.put("name", parameter.getName());
        result.put("in", parameter.getIn());
        result.put("required", parameter.getRequired());
        if (parameter.getSchema() != null) {
            result.put("schema", convertSchemaToMap(parameter.getSchema()));
        }
        return result;
    }

    private Map<String, Object> convertRequestBodyToMap(RequestBody requestBody) {
        Map<String, Object> result = new HashMap<>();
        if (requestBody.getContent() != null) {
            Map<String, Object> content = new HashMap<>();
            for (String mediaType : requestBody.getContent().keySet()) {
                MediaType mt = requestBody.getContent().get(mediaType);
                if (mt != null) {
                    content.put(mediaType, convertMediaTypeToMap(mt));
                }
            }
            result.put("content", content);
        }
        return result;
    }

    private Map<String, Object> convertMediaTypeToMap(MediaType mediaType) {
        Map<String, Object> result = new HashMap<>();
        if (mediaType.getSchema() != null) {
            result.put("schema", convertSchemaToMap(mediaType.getSchema()));
        }
        return result;
    }

    private Map<String, Object> convertSchemaToMap(Schema<?> schema) {
        Map<String, Object> result = new HashMap<>();
        if (schema.getType() != null) {
            result.put("type", schema.getType());
        }
        if (schema.getProperties() != null) {
            Map<String, Object> properties = new HashMap<>();
            for (String propName : schema.getProperties().keySet()) {
                Schema<?> propSchema = (Schema<?>) schema.getProperties().get(propName);
                properties.put(propName, convertSchemaToMap(propSchema));
            }
            result.put("properties", properties);
        }
        if (schema.getRequired() != null) {
            result.put("required", new ArrayList<>(schema.getRequired()));
        }
        return result;
    }

    /**
     * Получение реальных accountId из API
     */
    private List<String> getRealAccountIds(ScanConfig config, String bankToken, String consentId) {
        List<String> accountIds = new ArrayList<>();
        try {
            String url = config.getBankBaseUrl() + "/accounts?client_id=team172-1";

            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + bankToken);
            headers.put("X-Requesting-Bank", "team172");
            headers.put("X-Consent-Id", consentId);
            headers.put("Accept", "application/json");

            HttpResponse response = httpClient.sendRequest("GET", url, new HashMap<>(), headers, null);

            if (response.getStatusCode() == 200) {
                JSONObject json = new JSONObject(response.getBody());
                // Парсим реальные accountId из ответа
                if (json.has("data") && json.getJSONObject("data").has("account")) {
                    JSONArray accounts = json.getJSONObject("data").getJSONArray("account");
                    for (int i = 0; i < accounts.length(); i++) {
                        JSONObject account = accounts.getJSONObject(i);
                        if (account.has("accountId")) {
                            accountIds.add(account.getString("accountId"));
                        }
                    }
                }
            } else {
                logger.warning("❌ Failed to get real account IDs. Status: " + response.getStatusCode());
            }
        } catch (Exception e) {
            logger.severe("❌ Error getting real account IDs: " + e.getMessage());
        }

        // Если не удалось получить реальные ID, используем известные рабочие
        if (accountIds.isEmpty()) {
            accountIds.add("acc-4686");
            accountIds.add("acc-4698");
            logger.info("📋 Using fallback account IDs: " + accountIds);
        }

        return accountIds;
    }

    private ApiEndpoint createEndpointFromSpec(String path, String method, Map<String, Object> operation) {
        try {
            List<ApiParameter> parameters = new ArrayList<>();
            // Обрабатываем параметры пути
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> pathParams = (List<Map<String, Object>>) operation.get("parameters");
            if (pathParams != null) {
                for (Map<String, Object> param : pathParams) {
                    String name = (String) param.get("name");
                    String in = (String) param.get("in");
                    Boolean requiredObj = (Boolean) param.get("required");
                    boolean required = requiredObj != null ? requiredObj : false;
                    String type = "string";

                    @SuppressWarnings("unchecked")
                    Map<String, Object> schema = (Map<String, Object>) param.get("schema");
                    if (schema != null && schema.get("type") != null) {
                        type = schema.get("type").toString();
                    }
                    ParameterLocation location = ParameterLocation.valueOf(in.toUpperCase());
                    parameters.add(new ApiParameter(name, type, location, required));
                }
            }

            // Обрабатываем тело запроса
            @SuppressWarnings("unchecked")
            Map<String, Object> requestBody = (Map<String, Object>) operation.get("requestBody");
            if (requestBody != null) {
                @SuppressWarnings("unchecked")
                Map<String, Object> content = (Map<String, Object>) requestBody.get("content");
                if (content != null && !content.isEmpty()) {
                    // Берем первый доступный контент-тип
                    String contentType = content.keySet().iterator().next();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> mediaType = (Map<String, Object>) content.get(contentType);
                    @SuppressWarnings("unchecked")
                    Map<String, Object> schemaObj = (Map<String, Object>) mediaType.get("schema");
                    if (schemaObj != null) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> properties = (Map<String, Object>) schemaObj.get("properties");
                        if (properties != null) {
                            for (String propName : properties.keySet()) {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> propSchema = (Map<String, Object>) properties.get(propName);
                                String type = propSchema.containsKey("type") ?
                                        propSchema.get("type").toString() : "string";

                                boolean paramRequired = false;
                                if (schemaObj.containsKey("required")) {
                                    @SuppressWarnings("unchecked")
                                    List<String> requiredList = (List<String>) schemaObj.get("required");
                                    paramRequired = requiredList != null && requiredList.contains(propName);
                                }

                                parameters.add(new ApiParameter(propName, type, ParameterLocation.BODY, paramRequired));
                            }
                        }
                    }
                }
            }

            return new ApiEndpoint(path, HttpMethod.valueOf(method), parameters);
        } catch (Exception e) {
            logger.warning("⚠️  Error creating endpoint from spec for " + path + ": " + e.getMessage());
            return null;
        }
    }

    private List<Vulnerability> fuzzEndpointWithValidRequests(ApiEndpoint endpoint,
                                                              ValidRequestTemplate template,
                                                              ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        // Получаем параметры для тестирования
        List<ApiParameter> testableParams = getTestableParameters(endpoint, template);
        for (ApiParameter parameter : testableParams) {
            logger.info("🔍 Testing parameter: " + parameter.getName() +
                    " (" + parameter.getType() + ") at " + parameter.getLocation());
            // Тестируем разные категории уязвимостей
            testInjectionVulnerabilities(endpoint, template, parameter, vulnerabilities, config);
            testBusinessLogicVulnerabilities(endpoint, template, parameter, vulnerabilities, config);
            // Не спамим сервер
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return vulnerabilities;
    }

    private void testInjectionVulnerabilities(ApiEndpoint endpoint, ValidRequestTemplate template,
                                              ApiParameter parameter, List<Vulnerability> vulnerabilities,
                                              ScanConfig config) {
        List<InjectionTest> tests = createInjectionTests(parameter);
        for (InjectionTest test : tests) {
            try {
                // Создаем копию шаблона запроса
                ValidRequestTemplate testTemplate = template.copy();
                // Подставляем payload в нужное место
                if (!applyPayloadToTemplate(testTemplate, parameter, test.payload)) {
                    continue;
                }
                // Отправляем запрос
                HttpResponse response = httpClient.sendRequest(
                        endpoint.getMethod().name(),
                        config.getBankBaseUrl() + testTemplate.getPath(),
                        testTemplate.getQueryParams(),
                        testTemplate.getHeaders(),
                        testTemplate.getJsonBody()
                );
                // Обнаруживаем уязвимость
                Vulnerability vulnerability = vulnerabilityDetector.detectInjection(
                        endpoint, parameter, test.payload, response, test.vulnerabilityType
                );
                if (vulnerability != null) {
                    vulnerabilities.add(vulnerability);
                    logger.info("🎉 REAL vulnerability found: " + vulnerability.getTitle() +
                            " [" + vulnerability.getCategory() + "]");
                    // Не тестируем другие пейлоады для этого параметра, если уже нашли уязвимость
                    break;
                }
            } catch (Exception e) {
                logger.warning("⚠️  Error testing injection for " + parameter.getName() +
                        ": " + e.getMessage());
            }
        }
    }

    private void testBusinessLogicVulnerabilities(ApiEndpoint endpoint, ValidRequestTemplate template,
                                                  ApiParameter parameter, List<Vulnerability> vulnerabilities,
                                                  ScanConfig config) {
        // Проверяем только параметры, связанные с бизнес-логикой
        if (!isBusinessParameter(parameter)) {
            return;
        }
        List<BusinessLogicTest> tests = createBusinessLogicTests(parameter);
        for (BusinessLogicTest test : tests) {
            try {
                ValidRequestTemplate testTemplate = template.copy();
                if (!applyPayloadToTemplate(testTemplate, parameter, test.payload)) {
                    continue;
                }
                HttpResponse response = httpClient.sendRequest(
                        endpoint.getMethod().name(),
                        config.getBankBaseUrl() + testTemplate.getPath(),
                        testTemplate.getQueryParams(),
                        testTemplate.getHeaders(),
                        testTemplate.getJsonBody()
                );
                Vulnerability vulnerability = vulnerabilityDetector.detectBusinessLogicBypass(
                        endpoint, parameter, test.payload, response, test.expectedBehavior
                );
                if (vulnerability != null) {
                    vulnerabilities.add(vulnerability);
                    logger.info("💰 Business logic bypass found: " + vulnerability.getTitle());
                    break;
                }
            } catch (Exception e) {
                logger.warning("⚠️  Error testing business logic for " + parameter.getName() +
                        ": " + e.getMessage());
            }
        }
    }

    private boolean applyPayloadToTemplate(ValidRequestTemplate template, ApiParameter parameter, String payload) {
        try {
            switch (parameter.getLocation()) {
                case QUERY:
                    template.getQueryParams().put(parameter.getName(), payload);
                    break;
                case HEADER:
                    template.getHeaders().put(parameter.getName(), payload);
                    break;
                case PATH:
                    String path = template.getPath();
                    path = path.replace("{" + parameter.getName() + "}",
                            java.net.URLEncoder.encode(payload, "UTF-8"));
                    template.setPath(path);
                    break;
                case BODY:
                    JSONObject body = template.getJsonBody();
                    if (body != null) {
                        body.put(parameter.getName(), payload);
                    }
                    break;
                default:
                    return false;
            }
            return true;
        } catch (Exception e) {
            logger.warning("⚠️  Error applying payload to template: " + e.getMessage());
            return false;
        }
    }

    private List<ApiParameter> getTestableParameters(ApiEndpoint endpoint, ValidRequestTemplate template) {
        List<ApiParameter> result = new ArrayList<>();
        for (ApiParameter param : endpoint.getParameters()) {
            // Пропускаем обязательные параметры, которые уже заполнены в шаблоне
            if (param.isRequired() && template.isParameterPopulated(param.getName(), param.getLocation())) {
                continue;
            }
            // Пропускаем служебные параметры
            if (param.getName().toLowerCase().contains("token") ||
                    param.getName().toLowerCase().contains("signature") ||
                    param.getName().toLowerCase().contains("timestamp")) {
                continue;
            }
            result.add(param);
        }
        return result;
    }

    private boolean isBusinessParameter(ApiParameter parameter) {
        String name = parameter.getName().toLowerCase();
        return name.contains("amount") ||
                name.contains("balance") ||
                name.contains("limit") ||
                name.contains("total") ||
                name.contains("max") ||
                name.contains("min");
    }

    private List<Vulnerability> filterDuplicateVulnerabilities(List<Vulnerability> vulnerabilities) {
        Map<String, Vulnerability> uniqueVulns = new HashMap<>();
        for (Vulnerability vuln : vulnerabilities) {
            // Ключ для дедупликации: эндпоинт + параметр + категория
            String key = vuln.getEndpoint() + ":" + vuln.getParameter() + ":" + vuln.getCategory();
            // Если уязвимость с такой же ключевой информацией уже есть
            if (uniqueVulns.containsKey(key)) {
                // Выбираем уязвимость с более высоким уровнем критичности
                if (vuln.getSeverity().ordinal() > uniqueVulns.get(key).getSeverity().ordinal()) {
                    uniqueVulns.put(key, vuln);
                }
            } else {
                uniqueVulns.put(key, vuln);
            }
        }
        return new ArrayList<>(uniqueVulns.values());
    }

    // Внутренние классы для тестирования
    private static class InjectionTest {
        String payload;
        Category vulnerabilityType;
        InjectionTest(String payload, Category vulnerabilityType) {
            this.payload = payload;
            this.vulnerabilityType = vulnerabilityType;
        }
    }

    private static class BusinessLogicTest {
        String payload;
        String expectedBehavior;
        BusinessLogicTest(String payload, String expectedBehavior) {
            this.payload = payload;
            this.expectedBehavior = expectedBehavior;
        }
    }

    private List<InjectionTest> createInjectionTests(ApiParameter parameter) {
        List<InjectionTest> tests = new ArrayList<>();
        String paramName = parameter.getName().toLowerCase();
        // SSTI тесты для текстовых полей
        if (parameter.getType().equals("string") &&
                (paramName.contains("reason") || paramName.contains("reference") ||
                        paramName.contains("name") || paramName.contains("description"))) {
            tests.add(new InjectionTest("{{7*7}}", Category.SSTI));
            tests.add(new InjectionTest("${7*7}", Category.SSTI));
        }
        // NoSQL инъекции для JSON параметров
        if (paramName.contains("filter") || parameter.getType().equals("object")) {
            tests.add(new InjectionTest("{\"$ne\": \"\"}", Category.NOSQL_INJECTION));
            tests.add(new InjectionTest("{\"$where\": \"sleep(100)\"}", Category.NOSQL_INJECTION));
        }
        // Path Traversal для параметров, связанных с путями
        if (paramName.contains("path") || paramName.contains("file") || paramName.contains("url")) {
            tests.add(new InjectionTest("../../../../etc/passwd", Category.PATH_TRAVERSAL));
        }
        return tests;
    }

    private List<BusinessLogicTest> createBusinessLogicTests(ApiParameter parameter) {
        List<BusinessLogicTest> tests = new ArrayList<>();
        String paramName = parameter.getName().toLowerCase();
        if (paramName.contains("amount") || paramName.contains("balance")) {
            tests.add(new BusinessLogicTest("-10000.00", "should be rejected as negative amount"));
            tests.add(new BusinessLogicTest("999999999999.99", "should be rejected as excessive amount"));
        }
        return tests;
    }

    class HttpClientWrapper {
        private java.net.http.HttpClient client;

        public HttpClientWrapper() {
            this.client = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(10))
                    .build();
        }

        public HttpResponse sendRequest(String method, String url,
                                        Map<String, String> params,
                                        Map<String, String> headers,
                                        JSONObject jsonBody) throws Exception {
            long startTime = System.currentTimeMillis();
            // Строим полный URL с параметрами
            String fullUrl = buildUrlWithParams(url, params);
            java.net.http.HttpRequest.Builder requestBuilder = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(fullUrl))
                    .timeout(java.time.Duration.ofSeconds(10));

            // Устанавливаем заголовки
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    requestBuilder.header(header.getKey(), header.getValue());
                }
            }

            // Устанавливаем тело для POST/PUT
            if (("POST".equals(method) || "PUT".equals(method)) && jsonBody != null) {
                requestBuilder.header("Content-Type", "application/json");
                requestBuilder.method(method, java.net.http.HttpRequest.BodyPublishers.ofString(jsonBody.toString()));
            } else {
                requestBuilder.method(method, java.net.http.HttpRequest.BodyPublishers.noBody());
            }

            java.net.http.HttpRequest request = requestBuilder.build();
            java.net.http.HttpResponse<String> response = client.send(
                    request,
                    java.net.http.HttpResponse.BodyHandlers.ofString()
            );

            long responseTime = System.currentTimeMillis() - startTime;

            // Преобразуем в наш Response объект
            Map<String, String> responseHeaders = new HashMap<>();
            response.headers().map().forEach((k, v) -> {
                if (!v.isEmpty()) responseHeaders.put(k.toLowerCase(), v.get(0));
            });

            return new HttpResponse(
                    response.statusCode(),
                    response.body(),
                    responseHeaders,
                    responseTime
            );
        }

        private String buildUrlWithParams(String baseUrl, Map<String, String> params) {
            if (params == null || params.isEmpty()) {
                return baseUrl;
            }
            StringBuilder urlBuilder = new StringBuilder(baseUrl);
            if (!baseUrl.contains("?")) {
                urlBuilder.append("?");
            } else {
                urlBuilder.append("&");
            }
            boolean first = true;
            for (Map.Entry<String, String> entry : params.entrySet()) {
                if (!first) {
                    urlBuilder.append("&");
                }
                urlBuilder.append(entry.getKey())
                        .append("=")
                        .append(java.net.URLEncoder.encode(entry.getValue(), java.nio.charset.StandardCharsets.UTF_8));
                first = false;
            }
            return urlBuilder.toString();
        }
    }

    class BaselineRequestGenerator {
        private static final Map<String, String> SAMPLE_DATA = new HashMap<>();
        private Random random = new Random();
        private List<String> realAccountIds = new ArrayList<>();
        private String consentId;

        static {
            SAMPLE_DATA.put("client_id", "team172-1");
            SAMPLE_DATA.put("permissions", "[\"ReadAccountsDetail\",\"ReadBalances\"]");
            SAMPLE_DATA.put("reason", "Security testing");
            SAMPLE_DATA.put("requesting_bank", "team172");
            SAMPLE_DATA.put("requesting_bank_name", "Hackathon Scanner");
            SAMPLE_DATA.put("debtor_account", "40817810099910004312");
            SAMPLE_DATA.put("creditor_account", "40817810099910005423");
            SAMPLE_DATA.put("creditor_name", "Test Recipient");
            SAMPLE_DATA.put("reference", "Security Test");
            SAMPLE_DATA.put("nickname", "Test Account");
            SAMPLE_DATA.put("amount", "100.00");
        }

        public void setRealAccountIds(List<String> realAccountIds) {
            this.realAccountIds = realAccountIds;
        }

        public void setConsentId(String consentId) {
            this.consentId = consentId;
        }

        public ValidRequestTemplate generateValidRequestTemplate(ApiEndpoint endpoint,
                                                                 ScanConfig config,
                                                                 String bankToken,
                                                                 Map<String, Object> allPaths) {
            ValidRequestTemplate template = new ValidRequestTemplate();
            template.setPath(endpoint.getPath());

            // Заголовки по умолчанию
            Map<String, String> headers = new HashMap<>();
            if (bankToken != null && !bankToken.isEmpty()) {
                headers.put("Authorization", "Bearer " + bankToken);
            }
            headers.put("Content-Type", "application/json");
            headers.put("User-Agent", "SecurityScanner/3.0");

            // Если эндпоинт требует согласия, добавляем необходимые заголовки
            if (isEndpointRequiringConsent(endpoint)) {
                headers.put("X-Requesting-Bank", "team172");
                if (consentId != null) {
                    headers.put("X-Consent-Id", consentId);
                }
            }

            template.setHeaders(headers);

            // Параметры запроса
            Map<String, String> queryParams = new HashMap<>();
            // Для эндпоинтов, требующих client_id, добавляем его в query параметры
            if (isEndpointRequiringClientId(endpoint)) {
                queryParams.put("client_id", "team172-1");
            }

            // Тело запроса
            JSONObject jsonBody = new JSONObject();
            boolean hasBody = false;

            // Заполняем обязательные параметры
            for (ApiParameter param : endpoint.getParameters()) {
                if (!param.isRequired()) continue;
                String value = getSampleValueForParameter(param);
                if (value == null) continue;
                switch (param.getLocation()) {
                    case QUERY:
                        queryParams.put(param.getName(), value);
                        break;
                    case HEADER:
                        headers.put(param.getName(), value);
                        break;
                    case PATH:
                        // Для параметров пути, связанных с accountId, используем реальные accountId
                        if (param.getName().toLowerCase().contains("account") && !realAccountIds.isEmpty()) {
                            String encodedValue = java.net.URLEncoder.encode(realAccountIds.get(0), java.nio.charset.StandardCharsets.UTF_8);
                            template.setPath(template.getPath().replace("{" + param.getName() + "}", encodedValue));
                        } else {
                            String encodedValue = java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
                            template.setPath(template.getPath().replace("{" + param.getName() + "}", encodedValue));
                        }
                        break;
                    case BODY:
                        try {
                            if (value.startsWith("[") && value.endsWith("]")) {
                                jsonBody.put(param.getName(), new JSONArray(value));
                            } else if (value.startsWith("{") && value.endsWith("}")) {
                                jsonBody.put(param.getName(), new JSONObject(value));
                            } else if ("number".equals(param.getType()) || "integer".equals(param.getType())) {
                                jsonBody.put(param.getName(), Double.parseDouble(value));
                            } else if ("boolean".equals(param.getType())) {
                                jsonBody.put(param.getName(), Boolean.parseBoolean(value));
                            } else {
                                jsonBody.put(param.getName(), value);
                            }
                            hasBody = true;
                        } catch (Exception e) {
                            jsonBody.put(param.getName(), value);
                            hasBody = true;
                        }
                        break;
                }
            }

            template.setQueryParams(queryParams);
            template.setJsonBody(hasBody ? jsonBody : null);
            template.setValid(true);
            return template;
        }

        private boolean isEndpointRequiringConsent(ApiEndpoint endpoint) {
            String path = endpoint.getPath().toLowerCase();
            return path.contains("/accounts") ||
                    path.contains("/balances") ||
                    path.contains("/transactions") ||
                    path.contains("/account-consents") ||
                    path.contains("/payment-consents");
        }

        private boolean isEndpointRequiringClientId(ApiEndpoint endpoint) {
            String path = endpoint.getPath().toLowerCase();
            return path.contains("/accounts") ||
                    path.contains("/balances") ||
                    path.contains("/transactions") ||
                    path.contains("/payments") ||
                    path.contains("/consents");
        }

        public String generateConsentId(ScanConfig config, String bankToken) {
            try {
                HttpClientWrapper client = new HttpClientWrapper();
                // Формируем правильный запрос для создания согласия
                JSONObject consentBody = new JSONObject();
                consentBody.put("client_id", "team172-1");
                consentBody.put("permissions", new JSONArray(Arrays.asList("ReadAccountsDetail", "ReadBalances")));
                consentBody.put("reason", "Automated security testing");
                consentBody.put("requesting_bank", "team172");
                consentBody.put("requesting_bank_name", "Security Scanner");

                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + bankToken);
                headers.put("Content-Type", "application/json");
                headers.put("X-Requesting-Bank", "team172");

                HttpResponse response = client.sendRequest(
                        "POST",
                        config.getBankBaseUrl() + "/account-consents/request",
                        new HashMap<>(),
                        headers,
                        consentBody
                );

                if (response.getStatusCode() == 200 || response.getStatusCode() == 201) {
                    JSONObject responseBody = new JSONObject(response.getBody());
                    // Пробуем разные варианты извлечения consent_id
                    if (responseBody.has("consent_id")) {
                        return responseBody.getString("consent_id");
                    }
                    if (responseBody.has("consentId")) {
                        return responseBody.getString("consentId");
                    }
                    if (responseBody.has("data")) {
                        JSONObject data = responseBody.getJSONObject("data");
                        if (data.has("consent_id")) {
                            return data.getString("consent_id");
                        }
                        if (data.has("consentId")) {
                            return data.getString("consentId");
                        }
                    }
                }
                logger.warning("❌ Failed to generate consent ID. Status: " + response.getStatusCode());
            } catch (Exception e) {
                logger.severe("❌ Error generating consent ID: " + e.getMessage());
            }
            return null;
        }

        private String getSampleValueForParameter(ApiParameter param) {
            String paramName = param.getName().toLowerCase();
            String paramType = param.getType().toLowerCase();

            // Если параметр связан с accountId и у нас есть реальные accountId, используем их
            if (paramName.contains("account") && paramName.contains("id") && !realAccountIds.isEmpty()) {
                return realAccountIds.get(0);
            }

            // Пытаемся найти значение в предопределенных данных
            for (Map.Entry<String, String> entry : SAMPLE_DATA.entrySet()) {
                if (paramName.contains(entry.getKey())) {
                    return entry.getValue();
                }
            }

            // Генерируем значения на основе типа
            if ("string".equals(paramType)) {
                if (paramName.contains("id") || paramName.contains("uuid")) {
                    return "test-" + random.nextInt(1000);
                }
                return "Test " + param.getName();
            } else if ("number".equals(paramType) || "integer".equals(paramType)) {
                if (paramName.contains("amount") || paramName.contains("balance")) {
                    return "100.00";
                }
                return String.valueOf(random.nextInt(1000));
            } else if ("boolean".equals(paramType)) {
                return "true";
            }
            return null;
        }
    }

    class ValidRequestTemplate {
        private String path;
        private Map<String, String> queryParams = new HashMap<>();
        private Map<String, String> headers = new HashMap<>();
        private JSONObject jsonBody;
        private boolean isValid = false;

        public ValidRequestTemplate copy() {
            ValidRequestTemplate copy = new ValidRequestTemplate();
            copy.path = this.path;
            copy.queryParams = new HashMap<>(this.queryParams);
            copy.headers = new HashMap<>(this.headers);
            if (this.jsonBody != null) {
                copy.jsonBody = new JSONObject(this.jsonBody.toString());
            }
            copy.isValid = this.isValid;
            return copy;
        }

        public boolean isParameterPopulated(String paramName, ParameterLocation location) {
            switch (location) {
                case QUERY:
                    return queryParams.containsKey(paramName);
                case HEADER:
                    return headers.containsKey(paramName);
                case PATH:
                    return path != null && !path.contains("{" + paramName + "}");
                case BODY:
                    return jsonBody != null && jsonBody.has(paramName);
            }
            return false;
        }

        // Геттеры и сеттеры
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public Map<String, String> getQueryParams() { return queryParams; }
        public void setQueryParams(Map<String, String> queryParams) { this.queryParams = queryParams; }
        public Map<String, String> getHeaders() { return headers; }
        public void setHeaders(Map<String, String> headers) { this.headers = headers; }
        public JSONObject getJsonBody() { return jsonBody; }
        public void setJsonBody(JSONObject jsonBody) { this.jsonBody = jsonBody; }
        public boolean isValid() { return isValid; }
        public void setValid(boolean valid) { isValid = valid; }
    }
}