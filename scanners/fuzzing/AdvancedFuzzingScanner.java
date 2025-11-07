// scanners/fuzzing/AdvancedFuzzingScanner.java
package scanners.fuzzing;

import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import scanners.SecurityScanner;

import java.util.*;
import java.util.logging.Logger;

public class AdvancedFuzzingScanner implements SecurityScanner {

    private static final Logger logger = Logger.getLogger(AdvancedFuzzingScanner.class.getName());
    private FuzzingEngine fuzzingEngine;
    private EnhancedFuzzingEngine enhancedFuzzingEngine;
    private VulnerabilityDetector vulnerabilityDetector;
    private EnhancedVulnerabilityDetector enhancedDetector;
    private FuzzingApiClient fuzzingApiClient;

    public AdvancedFuzzingScanner() {
        this.fuzzingEngine = new FuzzingEngine();
        this.enhancedFuzzingEngine = new EnhancedFuzzingEngine();
        this.vulnerabilityDetector = new VulnerabilityDetector();
        this.enhancedDetector = new EnhancedVulnerabilityDetector();
        this.fuzzingApiClient = new HttpFuzzingApiClient();
    }

    @Override
    public String getName() {
        return "Advanced Fuzzing Scanner v2.0";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            logger.info("🚀 Starting enhanced fuzzing scan...");

            // Используем готовые эндпоинты из конфигурации или создаем тестовые
            List<ApiEndpoint> endpoints = createTestEndpoints();

            logger.info("📊 Using " + endpoints.size() + " endpoints for fuzzing");

            // Приоритизация эндпоинтов
            endpoints.sort((e1, e2) -> Integer.compare(getEndpointPriority(e2), getEndpointPriority(e1)));

            int totalRequests = 0;
            int maxRequests = 300; // Увеличили лимит для расширенного фаззинга

            // Фаззинг каждого эндпоинта
            for (ApiEndpoint endpoint : endpoints) {
                if (totalRequests >= maxRequests) {
                    logger.info("⚠️  Reached maximum request limit (" + maxRequests + "), stopping fuzzing");
                    break;
                }

                logger.info("🎯 Fuzzing endpoint: " + endpoint.getMethod() + " " + endpoint.getPath());

                List<Vulnerability> endpointVulns = fuzzEndpoint(endpoint, config);
                vulnerabilities.addAll(endpointVulns);

                totalRequests += estimateRequests(endpoint);

                logger.info("✅ Endpoint completed: " + endpointVulns.size() + " vulnerabilities found");

                // Rate limiting между эндпоинтами
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            logger.info("✅ Enhanced fuzzing completed. Found " + vulnerabilities.size() + " potential vulnerabilities");

        } catch (Exception e) {
            logger.severe("❌ Error during enhanced fuzzing scan: " + e.getMessage());
            e.printStackTrace();
        }

        return vulnerabilities;
    }

    private List<Vulnerability> fuzzEndpoint(ApiEndpoint endpoint, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Получаем токены аутентификации из конфигурации
        Map<String, String> userTokens = config.getUserTokens();
        if (userTokens == null || userTokens.isEmpty()) {
            logger.warning("⚠️  No user tokens available for endpoint: " + endpoint.getPath());
            return vulnerabilities;
        }

        // Используем первый доступный токен
        String token = userTokens.values().iterator().next();

        // Фаззинг каждого параметра эндпоинта
        for (ApiParameter parameter : endpoint.getParameters()) {
            logger.info("🔍 Testing parameter: " + parameter.getName() + " (" + parameter.getLocation() + ")");

            // 🔥 Используем улучшенные пейлоады для банковского API
            List<String> payloads = enhancedFuzzingEngine.generateAdvancedPayloads(parameter);

            logger.info("📦 Generated " + payloads.size() + " payloads for parameter " + parameter.getName());

            for (String payload : payloads) {
                try {
                    // Пробуем стандартный детектор
                    Vulnerability vulnerability = testParameter(
                            endpoint, parameter, payload, token, config
                    );

                    // 🔥 Пробуем улучшенный детектор
                    if (vulnerability == null) {
                        vulnerability = testParameterWithEnhancedDetector(
                                endpoint, parameter, payload, token, config
                        );
                    }

                    if (vulnerability != null) {
                        vulnerabilities.add(vulnerability);
                        logger.info("🎉 Vulnerability found: " + vulnerability.getTitle() +
                                " [" + vulnerability.getCategory() + "]");
                    }

                    // Rate limiting между запросами
                    Thread.sleep(200);

                } catch (Exception e) {
                    logger.warning("⚠️  Error testing parameter " + parameter.getName() + ": " + e.getMessage());
                }
            }
        }

        return vulnerabilities;
    }

    private Vulnerability testParameter(ApiEndpoint endpoint, ApiParameter parameter,
                                        String payload, String token, ScanConfig config) {
        try {
            // Подготовка запроса
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", getContentType(endpoint));
            headers.put("User-Agent", "SecurityScanner/2.0");

            Map<String, String> params = new HashMap<>();
            Map<String, String> bodyParams = new HashMap<>();

            String targetUrl = config.getBankBaseUrl() + endpoint.getPath();

            // В зависимости от типа параметра, помещаем payload в нужное место
            switch (parameter.getLocation()) {
                case QUERY:
                    params.put(parameter.getName(), payload);
                    break;
                case HEADER:
                    headers.put(parameter.getName(), payload);
                    break;
                case PATH:
                    String encodedValue = encodePathParameter(payload);
                    targetUrl = targetUrl.replace("{" + parameter.getName() + "}", encodedValue);
                    break;
                case BODY:
                    bodyParams.put(parameter.getName(), payload);
                    break;
            }

            // Отправка запроса через FuzzingApiClient
            HttpResponse response;

            if (endpoint.getMethod() == HttpMethod.GET) {
                response = fuzzingApiClient.sendRequest("GET", targetUrl, params, headers, null);
            } else if (endpoint.getMethod() == HttpMethod.POST) {
                response = fuzzingApiClient.sendRequest("POST", targetUrl, params, headers, bodyParams);
            } else if (endpoint.getMethod() == HttpMethod.PUT) {
                response = fuzzingApiClient.sendRequest("PUT", targetUrl, params, headers, bodyParams);
            } else if (endpoint.getMethod() == HttpMethod.DELETE) {
                response = fuzzingApiClient.sendRequest("DELETE", targetUrl, params, headers, null);
            } else {
                logger.warning("⚠️  Unsupported HTTP method: " + endpoint.getMethod());
                return null;
            }

            // Анализ ответа
            return vulnerabilityDetector.analyzeResponse(
                    endpoint, parameter, payload, response, response.getResponseTime()
            );

        } catch (Exception e) {
            logger.warning("❌ Request failed for " + parameter.getName() + ": " + e.getMessage());
            return null;
        }
    }

    private Vulnerability testParameterWithEnhancedDetector(ApiEndpoint endpoint, ApiParameter parameter,
                                                            String payload, String token, ScanConfig config) {
        try {
            // Подготовка запроса (аналогично testParameter)
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", getContentType(endpoint));
            headers.put("User-Agent", "SecurityScanner/2.0-Enhanced");

            Map<String, String> params = new HashMap<>();
            Map<String, String> bodyParams = new HashMap<>();

            String targetUrl = config.getBankBaseUrl() + endpoint.getPath();

            // В зависимости от типа параметра
            switch (parameter.getLocation()) {
                case QUERY:
                    params.put(parameter.getName(), payload);
                    break;
                case HEADER:
                    headers.put(parameter.getName(), payload);
                    break;
                case PATH:
                    String encodedValue = encodePathParameter(payload);
                    targetUrl = targetUrl.replace("{" + parameter.getName() + "}", encodedValue);
                    break;
                case BODY:
                    bodyParams.put(parameter.getName(), payload);
                    break;
            }

            // Отправка запроса
            HttpResponse response;
            if (endpoint.getMethod() == HttpMethod.GET) {
                response = fuzzingApiClient.sendRequest("GET", targetUrl, params, headers, null);
            } else if (endpoint.getMethod() == HttpMethod.POST) {
                response = fuzzingApiClient.sendRequest("POST", targetUrl, params, headers, bodyParams);
            } else {
                return null;
            }

            // 🔥 Используем улучшенный детектор
            return enhancedDetector.analyzeEnhancedResponse(
                    endpoint, parameter, payload, response
            );

        } catch (Exception e) {
            logger.warning("❌ Enhanced detection failed for " + parameter.getName() + ": " + e.getMessage());
            return null;
        }
    }

    // НОВЫЙ МЕТОД: Кодирование параметров пути для избежания ошибок URL
    private String encodePathParameter(String value) {
        try {
            // Кодируем специальные символы для пути URL, но сохраняем /
            return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8)
                    .replace("+", "%20")
                    .replace("%2F", "/");
        } catch (Exception e) {
            return value;
        }
    }

    private List<ApiEndpoint> createTestEndpoints() {
        List<ApiEndpoint> endpoints = new ArrayList<>();

        // 🔥 Критичные банковские эндпоинты для тестирования с улучшенными параметрами
        endpoints.add(new ApiEndpoint("/account-consents/request", HttpMethod.POST, Arrays.asList(
                new ApiParameter("client_id", "string", ParameterLocation.QUERY, false),
                new ApiParameter("reason", "string", ParameterLocation.BODY, true),
                new ApiParameter("x-consent-id", "string", ParameterLocation.HEADER, false)
        )));

        endpoints.add(new ApiEndpoint("/payment-consents/request", HttpMethod.POST, Arrays.asList(
                new ApiParameter("client_id", "string", ParameterLocation.QUERY, false),
                new ApiParameter("reference", "string", ParameterLocation.BODY, true),
                new ApiParameter("creditor_name", "string", ParameterLocation.BODY, false),
                new ApiParameter("amount", "number", ParameterLocation.BODY, true)
        )));

        endpoints.add(new ApiEndpoint("/accounts", HttpMethod.POST, Arrays.asList(
                new ApiParameter("nickname", "string", ParameterLocation.BODY, false),
                new ApiParameter("client_id", "string", ParameterLocation.QUERY, false)
        )));

        endpoints.add(new ApiEndpoint("/accounts/{account_id}", HttpMethod.GET, Arrays.asList(
                new ApiParameter("account_id", "string", ParameterLocation.PATH, true),
                new ApiParameter("x-consent-id", "string", ParameterLocation.HEADER, false)
        )));

        endpoints.add(new ApiEndpoint("/accounts/{account_id}/balances", HttpMethod.GET, Arrays.asList(
                new ApiParameter("account_id", "string", ParameterLocation.PATH, true)
        )));

        endpoints.add(new ApiEndpoint("/accounts/{account_id}/transactions", HttpMethod.GET, Arrays.asList(
                new ApiParameter("account_id", "string", ParameterLocation.PATH, true),
                new ApiParameter("page", "integer", ParameterLocation.QUERY, false),
                new ApiParameter("limit", "integer", ParameterLocation.QUERY, false)
        )));

        endpoints.add(new ApiEndpoint("/payments", HttpMethod.POST, Arrays.asList(
                new ApiParameter("client_id", "string", ParameterLocation.QUERY, false),
                new ApiParameter("data", "object", ParameterLocation.BODY, true)
        )));

        return endpoints;
    }

    private String getContentType(ApiEndpoint endpoint) {
        // Определяем Content-Type на основе эндпоинта
        if (endpoint.getMethod() == HttpMethod.POST || endpoint.getMethod() == HttpMethod.PUT) {
            return "application/json";
        }
        return "application/x-www-form-urlencoded";
    }

    private int getEndpointPriority(ApiEndpoint endpoint) {
        int priority = 0;

        String path = endpoint.getPath().toLowerCase();

        // Критичные пути получают высший приоритет
        if (path.contains("/admin") || path.contains("/user") || path.contains("/account")) {
            priority += 10;
        }
        if (path.contains("/delete") || path.contains("/update") || path.contains("/transfer")) {
            priority += 8;
        }
        if (path.contains("/payment") || path.contains("/transfer") || path.contains("/consent")) {
            priority += 7;
        }
        if (path.contains("/auth") || path.contains("/token")) {
            priority += 6;
        }
        if (path.contains("/consent")) {
            priority += 5;
        }

        // POST/PUT методы обычно более критичны
        if (endpoint.getMethod() == HttpMethod.POST || endpoint.getMethod() == HttpMethod.PUT) {
            priority += 3;
        }

        // DELETE методы очень критичны
        if (endpoint.getMethod() == HttpMethod.DELETE) {
            priority += 5;
        }

        return priority;
    }

    private int estimateRequests(ApiEndpoint endpoint) {
        // Оценка количества запросов для этого эндпоинта
        return endpoint.getParameters().size() * 8; // Увеличили для расширенного фаззинга
    }
}