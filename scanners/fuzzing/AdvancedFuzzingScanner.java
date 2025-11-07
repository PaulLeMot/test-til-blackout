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
    private VulnerabilityDetector vulnerabilityDetector;
    private FuzzingApiClient fuzzingApiClient;

    public AdvancedFuzzingScanner() {
        this.fuzzingEngine = new FuzzingEngine();
        this.vulnerabilityDetector = new VulnerabilityDetector();
        this.fuzzingApiClient = new HttpFuzzingApiClient();
    }

    @Override
    public String getName() {
        return "Advanced Fuzzing Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            logger.info("🚀 Starting advanced fuzzing scan...");

            // Используем готовые эндпоинты из конфигурации или создаем тестовые
            List<ApiEndpoint> endpoints = createTestEndpoints();

            logger.info("📊 Using " + endpoints.size() + " endpoints for fuzzing");

            // Приоритизация эндпоинтов
            endpoints.sort((e1, e2) -> Integer.compare(getEndpointPriority(e2), getEndpointPriority(e1)));

            int totalRequests = 0;
            int maxRequests = 200; // Лимит запросов для демо

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

            logger.info("✅ Fuzzing completed. Found " + vulnerabilities.size() + " potential vulnerabilities");

        } catch (Exception e) {
            logger.severe("❌ Error during fuzzing scan: " + e.getMessage());
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

            // Генерируем приоритетные payloads для быстрого тестирования
            List<String> payloads = fuzzingEngine.generatePriorityPayloads(parameter);

            for (String payload : payloads) {
                try {
                    Vulnerability vulnerability = testParameter(
                            endpoint, parameter, payload, token, config
                    );

                    if (vulnerability != null) {
                        vulnerabilities.add(vulnerability);
                        logger.info("🎉 Vulnerability found: " + vulnerability.getTitle());
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
            headers.put("User-Agent", "SecurityScanner/1.0");

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
                    // Заменяем в пути {param} на payload
                    targetUrl = targetUrl.replace("{" + parameter.getName() + "}", payload);
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

    private List<ApiEndpoint> createTestEndpoints() {
        List<ApiEndpoint> endpoints = new ArrayList<>();

        // Критичные банковские эндпоинты для тестирования
        endpoints.add(new ApiEndpoint("/accounts", HttpMethod.GET, Arrays.asList(
                new ApiParameter("client_id", "string", ParameterLocation.QUERY, false),
                new ApiParameter("x-consent-id", "string", ParameterLocation.HEADER, false)
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
        if (path.contains("/payment") || path.contains("/transfer")) {
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
        return endpoint.getParameters().size() * 5; // 5 payloads на параметр для демо
    }
}