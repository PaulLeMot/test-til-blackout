package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API9_InventoryScanner implements SecurityScanner {

    // Легитимные endpoints из спецификации API
    private static final Set<String> LEGITIMATE_ENDPOINTS = Set.of(
        "/auth/bank-token", "/accounts", "/account-consents/request", 
        "/account-consents", "/payment-consents/request", "/payment-consents",
        "/payments", "/products", "/product-agreements", "/product-agreement-consents/request",
        "/product-agreement-consents", "/.well-known/jwks.json", "/", "/health"
    );

    // Легитимные версии API
    private static final Set<String> LEGITIMATE_VERSIONS = Set.of("v1", "v2", "v3");

    // Подозрительные endpoints, которые действительно могут быть уязвимыми
    private static final List<String> SUSPICIOUS_ENDPOINTS = Arrays.asList(
        "admin", "debug", "test", "api/admin", "api/debug", "api/test",
        "management", "console", "api/console", "_admin", "_debug", "_test", 
        "private", "secret", "backup", "database", "config", "api/config",
        "logs", "system", "vendor", "tmp", "temp", "cache", "upload", "download",
        "export", "import", "backdoor", "shell", "cmd", "exec", "phpmyadmin", 
        "mysql", "phpinfo", "env", "/.git", "/.env", "DS_Store", "wp-admin", 
        "administrator"
    );

    private static final List<String> MONITORING_PATHS = Arrays.asList(
        "actuator", "actuator/health", "actuator/metrics", "actuator/info",
        "prometheus", "grafana", "monitoring", "heapdump", "threaddump",
        "configprops", "mappings", "flyway", "liquibase", "beans", "conditions",
        "loggers", "scheduledtasks", "sessions", "shutdown", "trace"
    );

    private int totalRequests = 0;
    private int foundEndpoints = 0;
    private Set<String> testedUrls = new HashSet<>();

    public API9_InventoryScanner() {}

    @Override
    public String getName() {
        return "OWASP API9:2023 - Improper Inventory Management";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-9) Запуск улучшенного сканирования управления инвентаризацией...");
        System.out.println("(API-9) Целевой URL: " + config.getTargetBaseUrl());

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = normalizeBaseUrl(config.getTargetBaseUrl().trim());
        OpenAPI openAPI = (OpenAPI) openApiObj;

        // Сброс счетчиков
        totalRequests = 0;
        foundEndpoints = 0;
        testedUrls.clear();

        try {
            // Получаем документированные endpoints из OpenAPI спецификации
            Set<String> documentedEndpoints = extractDocumentedEndpoints(openAPI);
            System.out.println("(API-9) Документировано endpoints: " + documentedEndpoints.size());

            // 1. Проверка подозрительных endpoints
            System.out.println("(API-9) 5.9.1: Сканирование подозрительных конечных точек...");
            vulnerabilities.addAll(scanSuspiciousEndpoints(baseUrl, apiClient, documentedEndpoints));

            // 2. Проверка мониторинговых endpoints
            System.out.println("(API-9) 5.9.4: Сканирование мониторинговых конечных точек...");
            vulnerabilities.addAll(scanMonitoringEndpoints(baseUrl, apiClient, documentedEndpoints));

            // 3. Поиск устаревших версий
            System.out.println("(API-9) 5.9.6: Поиск устаревших версий API...");
            vulnerabilities.addAll(scanDeprecatedEndpoints(baseUrl, apiClient, documentedEndpoints));

            // 4. Проверка debug endpoints
            System.out.println("(API-9) 5.9.7: Проверка debug конечных точек...");
            vulnerabilities.addAll(scanDebugEndpoints(baseUrl, apiClient, documentedEndpoints));

        } catch (Exception e) {
            System.err.println("(API-9) Ошибка при сканировании инвентаризации: " + e.getMessage());
            if (isDebugMode()) {
                e.printStackTrace();
            }
        }

        System.out.println("(API-9) СКАНИРОВАНИЕ ИНВЕНТАРИЗАЦИИ ЗАВЕРШЕНО:");
        System.out.println("(API-9) Всего выполнено запросов: " + totalRequests);
        System.out.println("(API-9) Обнаружено подозрительных конечных точек: " + foundEndpoints);
        System.out.println("(API-9) Найдено уязвимостей: " + vulnerabilities.size());

        return vulnerabilities;
    }

    private Set<String> extractDocumentedEndpoints(OpenAPI openAPI) {
        Set<String> endpoints = new HashSet<>();
        if (openAPI == null) {
            return endpoints;
        }

        try {
            Paths paths = openAPI.getPaths();
            if (paths != null) {
                for (String path : paths.keySet()) {
                    endpoints.add(path);
                    // Также добавляем базовые пути без параметров
                    if (path.contains("/")) {
                        String basePath = path.split("/")[0];
                        if (!basePath.isEmpty()) {
                            endpoints.add("/" + basePath);
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-9) Ошибка при извлечении documented endpoints: " + e.getMessage());
        }

        // Добавляем легитимные endpoints из спецификации
        endpoints.addAll(LEGITIMATE_ENDPOINTS);
        return endpoints;
    }

    private List<Vulnerability> scanSuspiciousEndpoints(String baseUrl, ApiClient apiClient, Set<String> documentedEndpoints) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        for (String endpoint : SUSPICIOUS_ENDPOINTS) {
            // Пропускаем если endpoint документирован
            if (isEndpointDocumented("/" + endpoint, documentedEndpoints)) {
                continue;
            }

            String fullUrl = baseUrl + endpoint;
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "SUSPICIOUS_ENDPOINT");
            testedUrls.add(fullUrl);

            if (response != null && isTrulySuspiciousResponse(response, endpoint)) {
                discovered++;
                String evidence = buildEvidence("Подозрительная конечная точка", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                    "Обнаружена подозрительная конечная точка: " + endpoint,
                    "УРОВЕНЬ РИСКА: " + assessSuspiciousEndpointRisk(endpoint, response) +
                    "\nОбнаружена потенциально опасная конечная точка: " + endpoint +
                    "\nСтатус: HTTP " + response.getStatusCode() +
                    "\nТип: " + classifySuspiciousEndpoint(endpoint) +
                    "\n\nКонечная точка соответствует известным шаблонам административных, debug или системных путей. " +
                    "Рекомендуется проверить необходимость существования данной конечной точки в production среде.",
                    "/" + endpoint,
                    response.getStatusCode(),
                    evidence,
                    assessSuspiciousEndpointSeverity(endpoint, response)
                );

                vulns.add(vuln);
                System.out.println("(API-9) Подозрительная конечная точка: " + endpoint + " (" + response.getStatusCode() + ")");
            }
        }

        System.out.println("(API-9) Подозрительных конечных точек обнаружено: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private List<Vulnerability> scanMonitoringEndpoints(String baseUrl, ApiClient apiClient, Set<String> documentedEndpoints) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        for (String monitoringPath : MONITORING_PATHS) {
            // Пропускаем если endpoint документирован
            if (isEndpointDocumented("/" + monitoringPath, documentedEndpoints)) {
                continue;
            }

            String fullUrl = baseUrl + monitoringPath;
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "MONITORING");
            testedUrls.add(fullUrl);

            if (response != null && response.getStatusCode() == 200 && containsSensitiveMonitoringData(response)) {
                discovered++;
                String evidence = buildEvidence("Мониторинговая конечная точка с чувствительными данными", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                    "Публичная мониторинговая конечная точка с чувствительными данными: " + monitoringPath,
                    "КРИТИЧЕСКИЙ УРОВЕНЬ: Обнаружена публичная мониторинговая конечная точка с чувствительными данными!" +
                    "\nКонечная точка: " + monitoringPath +
                    "\nРиск: Раскрытие системной информации, конфигурации или метрик" +
                    "\nОбнаруженные чувствительные данные: " + identifySensitiveData(response),
                    "/" + monitoringPath,
                    response.getStatusCode(),
                    evidence,
                    Vulnerability.Severity.HIGH
                );

                vulns.add(vuln);
                System.out.println("(API-9) КРИТИЧЕСКИЙ: Мониторинговая конечная точка с чувствительными данными: " + monitoringPath);
            }
        }

        System.out.println("(API-9) Опасных мониторинговых конечных точек: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private List<Vulnerability> scanDeprecatedEndpoints(String baseUrl, ApiClient apiClient, Set<String> documentedEndpoints) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        // Проверяем наличие устаревших версий API
        for (String version : Arrays.asList("v0", "v1", "beta", "alpha", "legacy", "old")) {
            if (LEGITIMATE_VERSIONS.contains(version)) {
                continue; // Пропускаем легитимные версии
            }

            String versionUrl = baseUrl + version;
            if (testedUrls.contains(versionUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, versionUrl, "DEPRECATED_VERSION");
            testedUrls.add(versionUrl);

            if (response != null && response.getStatusCode() == 200) {
                // Проверяем действительно ли это устаревшая версия API
                if (isTrulyDeprecatedAPI(response, version)) {
                    discovered++;
                    String evidence = buildEvidence("Устаревшая версия API", versionUrl, response);

                    Vulnerability vuln = createInventoryVulnerability(
                        "Обнаружена устаревшая версия API: " + version,
                        "СРЕДНИЙ УРОВЕНЬ: Обнаружена устаревшая версия API!" +
                        "\nВерсия: " + version +
                        "\nРиск: Устаревшие версии могут содержать известные уязвимости и не получать security updates" +
                        "\nРекомендация: Отключить устаревшие версии API или обеспечить их безопасность",
                        "/" + version,
                        response.getStatusCode(),
                        evidence,
                        Vulnerability.Severity.MEDIUM
                    );

                    vulns.add(vuln);
                    System.out.println("(API-9) Устаревшая версия API: " + version);
                }
            }
        }

        System.out.println("(API-9) Устаревших версий API: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private List<Vulnerability> scanDebugEndpoints(String baseUrl, ApiClient apiClient, Set<String> documentedEndpoints) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        List<String> debugEndpoints = Arrays.asList("debug", "api/debug", "_debug", "develop", "development");

        for (String debugPath : debugEndpoints) {
            // Пропускаем если endpoint документирован
            if (isEndpointDocumented("/" + debugPath, documentedEndpoints)) {
                continue;
            }

            String fullUrl = baseUrl + debugPath;
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "DEBUG_ENDPOINT");
            testedUrls.add(fullUrl);

            if (response != null && response.getStatusCode() == 200 && isTrulyDebugEndpoint(response)) {
                discovered++;
                String evidence = buildEvidence("Debug конечная точка в production", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                    "Debug конечная точка в production: " + debugPath,
                    "ВЫСОКИЙ УРОВЕНЬ: Debug конечная точка доступна в production среде!" +
                    "\nКонечная точка: " + debugPath +
                    "\nРиск: Раскрытие отладочной информации, stack traces, системной конфигурации" +
                    "\nУгроза: Получение чувствительной информации о приложении",
                    "/" + debugPath,
                    response.getStatusCode(),
                    evidence,
                    Vulnerability.Severity.HIGH
                );

                vulns.add(vuln);
                System.out.println("(API-9) ВЫСОКИЙ УРОВЕНЬ: Debug конечная точка: " + debugPath);
            }
        }

        System.out.println("(API-9) Debug конечных точек обнаружено: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    // Вспомогательные методы
    private boolean isEndpointDocumented(String endpoint, Set<String> documentedEndpoints) {
        return documentedEndpoints.contains(endpoint) || 
               documentedEndpoints.stream().anyMatch(doc -> doc.startsWith(endpoint) || endpoint.startsWith(doc));
    }

    private boolean isTrulySuspiciousResponse(HttpApiClient.ApiResponse response, String endpoint) {
        if (response.getStatusCode() != 200) {
            return false;
        }

        String body = response.getBody().toLowerCase();
        
        // Игнорируем стандартные ответы
        if (body.contains("page not found") || body.contains("404") || 
            body.contains("not found") || body.isEmpty()) {
            return false;
        }

        // Для подозрительных endpoints требуем дополнительные индикаторы
        return containsSensitiveKeywords(body) || 
               isAdminInterface(response, endpoint) ||
               isDebugInterface(response, endpoint);
    }

    private boolean containsSensitiveKeywords(String body) {
        String[] sensitiveKeywords = {"password", "secret", "key", "token", "admin", "debug", "config", "environment"};
        return Arrays.stream(sensitiveKeywords).anyMatch(body::contains);
    }

    private boolean isAdminInterface(HttpApiClient.ApiResponse response, String endpoint) {
        String body = response.getBody().toLowerCase();
        return endpoint.contains("admin") && 
               (body.contains("dashboard") || body.contains("management") || body.contains("control"));
    }

    private boolean isDebugInterface(HttpApiClient.ApiResponse response, String endpoint) {
        String body = response.getBody().toLowerCase();
        return endpoint.contains("debug") && 
               (body.contains("stack trace") || body.contains("exception") || body.contains("debug"));
    }

    private boolean containsSensitiveMonitoringData(HttpApiClient.ApiResponse response) {
        String body = response.getBody().toLowerCase();
        String[] sensitiveMonitoringIndicators = {
            "environment", "configuration", "password", "secret", "database", 
            "heap", "thread", "memory", "credentials"
        };
        return Arrays.stream(sensitiveMonitoringIndicators).anyMatch(body::contains);
    }

    private boolean isTrulyDeprecatedAPI(HttpApiClient.ApiResponse response, String version) {
        String body = response.getBody().toLowerCase();
        return body.contains("deprecated") || body.contains("legacy") || 
               body.contains("outdated") || body.contains("no longer supported") ||
               body.contains("version") && body.contains(version);
    }

    private boolean isTrulyDebugEndpoint(HttpApiClient.ApiResponse response) {
        String body = response.getBody().toLowerCase();
        return body.contains("stack trace") || body.contains("exception") || 
               body.contains("debug information") || body.contains("environment variables") ||
               body.contains("configuration") && body.contains("password");
    }

    private String identifySensitiveData(HttpApiClient.ApiResponse response) {
        String body = response.getBody().toLowerCase();
        List<String> foundData = new ArrayList<>();
        
        if (body.contains("password")) foundData.add("пароли");
        if (body.contains("secret")) foundData.add("секреты");
        if (body.contains("key")) foundData.add("ключи");
        if (body.contains("database")) foundData.add("информация о БД");
        if (body.contains("environment")) foundData.add("переменные окружения");
        if (body.contains("configuration")) foundData.add("конфигурация");
        
        return foundData.isEmpty() ? "не определено" : String.join(", ", foundData);
    }

    private String assessSuspiciousEndpointRisk(String endpoint, HttpApiClient.ApiResponse response) {
        if (endpoint.contains("admin") || endpoint.contains("debug") || endpoint.contains("secret")) {
            return "ВЫСОКИЙ - Административный/Debug доступ";
        }
        if (endpoint.contains("config") || endpoint.contains("log") || endpoint.contains("system")) {
            return "СРЕДНИЙ - Доступ к системной информации";
        }
        if (endpoint.contains("backup") || endpoint.contains("database")) {
            return "ВЫСОКИЙ - Доступ к данным";
        }
        return "НИЗКИЙ - Общая конечная точка";
    }

    private Vulnerability.Severity assessSuspiciousEndpointSeverity(String endpoint, HttpApiClient.ApiResponse response) {
        if (endpoint.contains("admin") || endpoint.contains("debug") || endpoint.contains("secret") ||
            endpoint.contains("backdoor") || endpoint.contains("env")) {
            return Vulnerability.Severity.HIGH;
        } else if (endpoint.contains("config") || endpoint.contains("log") || endpoint.contains("system")) {
            return Vulnerability.Severity.MEDIUM;
        } else {
            return Vulnerability.Severity.LOW;
        }
    }

    private String classifySuspiciousEndpoint(String endpoint) {
        if (endpoint.contains("admin")) return "Административный интерфейс";
        if (endpoint.contains("debug")) return "Интерфейс отладки";
        if (endpoint.contains("log")) return "Доступ к логам";
        if (endpoint.contains("config")) return "Доступ к конфигурации";
        if (endpoint.contains("backup")) return "Доступ к резервным копиям";
        if (endpoint.contains("database")) return "Интерфейс базы данных";
        return "Подозрительная конечная точка";
    }

    private String normalizeBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            return baseUrl;
        }
        return baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
    }

    private HttpApiClient.ApiResponse makeRequest(ApiClient apiClient, String url, String type) {
        totalRequests++;
        try {
            // Добавляем задержку чтобы не перегружать сервер
            Thread.sleep(100);
            
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("User-Agent", "GOSTGuardian-Scanner/1.0");

            Object response = apiClient.executeRequest("GET", url, null, headers);
            return (HttpApiClient.ApiResponse) response;

        } catch (Exception e) {
            return null;
        }
    }

    private String buildEvidence(String title, String url, HttpApiClient.ApiResponse response) {
        StringBuilder evidence = new StringBuilder();
        evidence.append(title).append("\n");
        evidence.append("URL: ").append(url).append("\n");
        evidence.append("HTTP Статус: ").append(response.getStatusCode()).append("\n");

        if (response.getBody() != null && !response.getBody().isEmpty()) {
            evidence.append("\nТЕЛО ОТВЕТА (первые 200 символов):\n");
            String bodyPreview = response.getBody().length() > 200 ?
                    response.getBody().substring(0, 200) + "..." : response.getBody();
            evidence.append(bodyPreview);
        }

        return evidence.toString();
    }

    private Vulnerability createInventoryVulnerability(String title, String description,
                                                       String endpoint, int statusCode, String evidence,
                                                       Vulnerability.Severity severity) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API9:2023 - Improper Inventory Management - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API9_INVENTORY);
        vuln.setEndpoint(endpoint);
        vuln.setStatusCode(statusCode);
        vuln.setEvidence(evidence);
        vuln.setMethod("GET");

        List<String> recommendations = new ArrayList<>();
        recommendations.add("Проведите инвентаризацию всех API конечных точек");
        recommendations.add("Удалите неиспользуемые и устаревшие конечные точки");
        recommendations.add("Ограничьте доступ к debug и monitoring конечным точкам в production среде");
        recommendations.add("Внедрите процесс управления версиями API");
        recommendations.add("Регулярно обновляйте документацию API");
        vuln.setRecommendations(recommendations);

        return vuln;
    }

    private static boolean isDebugMode() {
        return System.getProperty("debug") != null ||
                Arrays.asList(System.getenv().getOrDefault("JAVA_OPTS", "").split(" ")).contains("-Ddebug");
    }
}
