// scanners/owasp/API9_InventoryScanner.java
package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API9_InventoryScanner implements SecurityScanner {

    private static final List<String> COMMON_ENDPOINTS = Arrays.asList(
            "admin", "debug", "test", "api/admin", "api/debug", "api/test",
            "management", "monitoring", "console", "api/console",
            "_admin", "_debug", "_test", "private", "secret",
            "backup", "database", "config", "api/config",
            "logs", "api/logs", "system", "api/system",
            "vendor", "api/vendor", "tmp", "temp", "cache",
            "api/cache", "upload", "api/upload", "download",
            "api/download", "export", "api/export", "import",
            "api/import"
    );

    private static final List<String> VERSION_PATHS = Arrays.asList(
            "v1", "v2", "v3", "v4", "v5",
            "api/v1", "api/v2", "api/v3", "api/v4", "api/v5",
            "internal", "internal/api", "dev", "development",
            "staging", "test", "uat", "beta", "alpha",
            "legacy", "old", "new", "current"
    );

    private static final List<String> MONITORING_PATHS = Arrays.asList(
            "health", "metrics", "status", "info", "actuator",
            "actuator/health", "actuator/metrics", "actuator/info",
            "prometheus", "grafana", "monitoring", "api/health",
            "api/metrics", "api/status", "management/health",
            "ping", "ready", "live", "heapdump", "threaddump",
            "env", "configprops", "mappings", "flyway", "liquibase"
    );

    private static final List<String> DEPRECATED_KEYWORDS = Arrays.asList(
            "deprecated", "legacy", "old", "v1", "v0", "beta", "alpha",
            "obsolete", "outdated", "removed", "sunset", "discontinued"
    );

    private static final List<String> JS_PATH_PATTERNS = Arrays.asList(
            "[\"'](/[a-zA-Z0-9_\\-\\./]+)[\"']",
            "[\"'](api/[a-zA-Z0-9_\\-\\./]+)[\"']",
            "[\"'](v[0-9]/[a-zA-Z0-9_\\-\\./]+)[\"']",
            "url:\\s*[\"']([^\"']+)[\"']",
            "endpoint:\\s*[\"']([^\"']+)[\"']",
            "path:\\s*[\"']([^\"']+)[\"']"
    );

    public API9_InventoryScanner() {}

    @Override
    public String getName() {
        return "OWASP API9:2023 - Improper Inventory Management";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("🔍 Scanning for Improper Inventory Management vulnerabilities (OWASP API Security Top 10:2023 - API9)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = normalizeBaseUrl(config.getTargetBaseUrl().trim());

        try {
            // 5.9.1: Проверка common endpoints
            System.out.println("📋 5.9.1: Scanning common endpoints...");
            vulnerabilities.addAll(scanCommonEndpoints(baseUrl, apiClient));

            // 5.9.2: Брутфорс путей на основе структуры документации API
            System.out.println("📋 5.9.2: Brute-forcing endpoints based on API structure...");
            vulnerabilities.addAll(bruteForceFromDocumentation(baseUrl, apiClient, openAPI));

            // 5.9.3: Поиск версионированных эндпоинтов
            System.out.println("📋 5.9.3: Scanning versioned endpoints...");
            vulnerabilities.addAll(scanVersionedEndpoints(baseUrl, apiClient));

            // 5.9.4: Проверка стандартных мониторинг-путей
            System.out.println("📋 5.9.4: Scanning monitoring endpoints...");
            vulnerabilities.addAll(scanMonitoringEndpoints(baseUrl, apiClient));

            // 5.9.5: Анализ JavaScript файлов на наличие скрытых API-путей
            System.out.println("📋 5.9.5: Analyzing JavaScript files for hidden API paths...");
            vulnerabilities.addAll(scanJavaScriptFiles(baseUrl, apiClient));

            // 5.9.6: Поиск устаревших и deprecated версий API
            System.out.println("📋 5.9.6: Scanning for deprecated API versions...");
            vulnerabilities.addAll(scanDeprecatedEndpoints(baseUrl, apiClient));

            // 5.9.7: Проверка debug и development эндпоинтов в production
            System.out.println("📋 5.9.7: Scanning debug endpoints in production...");
            vulnerabilities.addAll(scanDebugEndpoints(baseUrl, apiClient));

        } catch (Exception e) {
            System.err.println("❌ Ошибка при сканировании инвентаризации: " + e.getMessage());
            if (isDebugMode()) {
                e.printStackTrace();
            }
        }

        System.out.println("✅ Inventory scan completed. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    // Нормализация baseUrl - добавляем слэш в конце если отсутствует
    private String normalizeBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            return baseUrl;
        }
        return baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
    }

    // 5.9.1: Загрузка wordlist для common endpoints
    private List<Vulnerability> scanCommonEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        for (String endpoint : COMMON_ENDPOINTS) {
            String fullUrl = baseUrl + endpoint;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

            if (response != null && isInterestingResponse(response.getStatusCode())) {
                Vulnerability vuln = createInventoryVulnerability(
                        "Undocumented Common Endpoint Discovered",
                        "Обнаружен недокументированный common endpoint: " + endpoint +
                                " (HTTP " + response.getStatusCode() + "). " +
                                "Такие endpoints могут раскрывать чувствительную информацию или предоставлять доступ к административным функциям.",
                        "/" + endpoint,
                        response.getStatusCode(),
                        "Endpoint responded with status: " + response.getStatusCode() +
                                (response.getBody() != null ? "\nResponse preview: " +
                                        response.getBody().substring(0, Math.min(200, response.getBody().length())) : "")
                );

                // Повышаем критичность для административных endpoints
                if (endpoint.contains("admin") || endpoint.contains("debug") || endpoint.contains("secret")) {
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                }

                vulns.add(vuln);
            }
        }

        return vulns;
    }

    // 5.9.2: Брутфорс путей на основе структуры документации API
    private List<Vulnerability> bruteForceFromDocumentation(String baseUrl, ApiClient apiClient, Object openAPI) {
        List<Vulnerability> vulns = new ArrayList<>();

        // Базовые пути для брутфорса на основе common API patterns
        List<String> bruteForcePaths = generateBruteForcePaths();

        for (String path : bruteForcePaths) {
            String fullUrl = baseUrl + path;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

            if (response != null && isInterestingResponse(response.getStatusCode())) {
                Vulnerability vuln = createInventoryVulnerability(
                        "Brute-Forced Endpoint Discovered",
                        "Обнаружен endpoint через брутфорс: " + path +
                                " (HTTP " + response.getStatusCode() + "). " +
                                "Endpoint не документирован в официальной спецификации API.",
                        "/" + path,
                        response.getStatusCode(),
                        "Brute-force discovery: " + path + " -> " + response.getStatusCode()
                );
                vulns.add(vuln);
            }
        }

        return vulns;
    }

    // 5.9.3: Поиск версионированных эндпоинтов
    private List<Vulnerability> scanVersionedEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        for (String versionPath : VERSION_PATHS) {
            // Проверяем сам путь версии
            String versionUrl = baseUrl + versionPath;
            HttpApiClient.ApiResponse versionResponse = makeRequest(apiClient, versionUrl);

            if (versionResponse != null && isInterestingResponse(versionResponse.getStatusCode())) {
                Vulnerability vuln = createInventoryVulnerability(
                        "Versioned API Endpoint Discovered",
                        "Обнаружен версионированный endpoint: " + versionPath +
                                " (HTTP " + versionResponse.getStatusCode() + "). " +
                                "Устаревшие версии API могут содержать известные уязвимости.",
                        "/" + versionPath,
                        versionResponse.getStatusCode(),
                        "Versioned endpoint accessible: " + versionPath
                );
                vulns.add(vuln);
            }

            // Проверяем комбинации версий с common paths
            for (String commonPath : Arrays.asList("users", "accounts", "transactions", "auth")) {
                String fullUrl = baseUrl + versionPath + "/" + commonPath;
                HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

                if (response != null && isInterestingResponse(response.getStatusCode())) {
                    Vulnerability vuln = createInventoryVulnerability(
                            "Versioned Resource Endpoint Discovered",
                            "Обнаружен версионированный resource endpoint: " + versionPath + "/" + commonPath +
                                    " (HTTP " + response.getStatusCode() + "). " +
                                    "Устаревшие версии API могут не получать security patches.",
                            "/" + versionPath + "/" + commonPath,
                            response.getStatusCode(),
                            "Versioned resource endpoint: " + response.getStatusCode()
                    );
                    vulns.add(vuln);
                }
            }
        }

        return vulns;
    }

    // 5.9.4: Проверка стандартных мониторинг-путей
    private List<Vulnerability> scanMonitoringEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        for (String monitoringPath : MONITORING_PATHS) {
            String fullUrl = baseUrl + monitoringPath;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

            if (response != null && response.getStatusCode() == 200) {
                String evidence = "Public monitoring endpoint exposed: " + monitoringPath;
                if (response.getBody() != null) {
                    evidence += "\nResponse: " + response.getBody().substring(0, Math.min(300, response.getBody().length()));
                }

                Vulnerability vuln = createInventoryVulnerability(
                        "Public Monitoring Endpoint Exposed",
                        "Мониторинг endpoint доступен публично: " + monitoringPath +
                                " - может раскрывать чувствительную информацию о системе, включая метрики производительности, health checks и конфигурацию.",
                        "/" + monitoringPath,
                        response.getStatusCode(),
                        evidence
                );

                // Высокая критичность для monitoring endpoints
                if (monitoringPath.contains("env") || monitoringPath.contains("config") ||
                        monitoringPath.contains("heapdump") || monitoringPath.contains("threaddump")) {
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                } else {
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                }

                vulns.add(vuln);
            }
        }

        return vulns;
    }

    // 5.9.5: Анализ JavaScript файлов на наличие скрытых API-путей
    private List<Vulnerability> scanJavaScriptFiles(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        try {
            // Получаем главную страницу для поиска JS файлов
            HttpApiClient.ApiResponse mainPage = makeRequest(apiClient, baseUrl);
            if (mainPage != null && mainPage.getStatusCode() == 200) {
                List<String> jsFiles = extractJavaScriptFiles(mainPage.getBody(), baseUrl);

                for (String jsFile : jsFiles) {
                    HttpApiClient.ApiResponse jsResponse = makeRequest(apiClient, jsFile);
                    if (jsResponse != null && jsResponse.getStatusCode() == 200) {
                        List<String> hiddenEndpoints = extractHiddenEndpointsFromJS(jsResponse.getBody());

                        for (String endpoint : hiddenEndpoints) {
                            // Проверяем найденный endpoint
                            String testUrl = baseUrl + endpoint.substring(1); // убираем начальный слэш
                            HttpApiClient.ApiResponse endpointResponse = makeRequest(apiClient, testUrl);

                            if (endpointResponse != null && isInterestingResponse(endpointResponse.getStatusCode())) {
                                Vulnerability vuln = createInventoryVulnerability(
                                        "Hidden API Endpoint in JavaScript",
                                        "Скрытый API endpoint обнаружен в JavaScript файле: " + endpoint +
                                                " (HTTP " + endpointResponse.getStatusCode() + "). " +
                                                "Endpoints, скрытые в client-side коде, часто не документированы и не защищены.",
                                        endpoint,
                                        endpointResponse.getStatusCode(),
                                        "Found in JS file: " + jsFile + "\nEndpoint: " + endpoint
                                );
                                vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                                vulns.add(vuln);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при анализе JavaScript файлов: " + e.getMessage());
        }

        return vulns;
    }

    // 5.9.6: Поиск устаревших и deprecated версий API
    private List<Vulnerability> scanDeprecatedEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        // Проверяем основную документацию API
        String[] docUrls = {
                "docs",
                "swagger",
                "swagger-ui",
                "api-docs",
                "openapi",
                "v3/api-docs"
        };

        for (String docPath : docUrls) {
            String docUrl = baseUrl + docPath;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, docUrl);
            if (response != null && response.getStatusCode() == 200) {
                String body = response.getBody().toLowerCase();

                for (String keyword : DEPRECATED_KEYWORDS) {
                    if (body.contains(keyword)) {
                        Vulnerability vuln = createInventoryVulnerability(
                                "Deprecated API Version Detected",
                                "Обнаружены упоминания устаревших или deprecated версий API. Ключевое слово: '" + keyword + "'. " +
                                        "Устаревшие версии API могут содержать известные уязвимости и не получать обновления безопасности.",
                                "/" + docPath,
                                response.getStatusCode(),
                                "Deprecated keyword found: " + keyword + " in API documentation"
                        );
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vulns.add(vuln);
                        break;
                    }
                }
            }
        }

        return vulns;
    }

    // 5.9.7: Проверка debug и development эндпоинтов в production
    private List<Vulnerability> scanDebugEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        List<String> debugEndpoints = Arrays.asList(
                "debug", "api/debug", "_debug", "develop", "development",
                "env", "api/env", "configuration", "api/configuration",
                "trace", "api/trace", "dump", "api/dump", "console",
                "api/console", "phpinfo", "info", "api/info"
        );

        for (String debugPath : debugEndpoints) {
            String fullUrl = baseUrl + debugPath;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

            if (response != null && response.getStatusCode() == 200) {
                String body = response.getBody().toLowerCase();

                // Проверяем типичные debug-индикаторы
                boolean isDebugEndpoint = body.contains("debug") || body.contains("development") ||
                        body.contains("environment") || body.contains("configuration") ||
                        body.contains("php") || body.contains("java") ||
                        body.contains("spring") || body.contains("trace");

                if (isDebugEndpoint) {
                    Vulnerability vuln = createInventoryVulnerability(
                            "Debug Endpoint in Production",
                            "Debug endpoint доступен в production среде: " + debugPath +
                                    " - раскрывает чувствительную информацию о приложении и среде выполнения.",
                            "/" + debugPath,
                            response.getStatusCode(),
                            "Debug endpoint accessible in production environment\n" +
                                    "Response preview: " + response.getBody().substring(0, Math.min(500, response.getBody().length()))
                    );
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vulns.add(vuln);
                }
            }
        }

        return vulns;
    }

    // Вспомогательные методы
    private List<String> generateBruteForcePaths() {
        List<String> paths = new ArrayList<>();
        String[] resources = {"user", "users", "account", "accounts", "admin", "api", "data",
                "file", "files", "upload", "download", "config", "settings"};
        String[] actions = {"", "/list", "/all", "/get", "/create", "/update", "/delete",
                "/search", "/find", "/export", "/import"};
        String[] ids = {"", "/1", "/123", "/test", "/admin"};

        // Генерируем комбинации
        for (String resource : resources) {
            for (String action : actions) {
                for (String id : ids) {
                    paths.add(resource + action + id);
                    paths.add("api/" + resource + action + id);
                }
            }
        }

        return paths;
    }

    private List<String> extractJavaScriptFiles(String html, String baseUrl) {
        List<String> jsFiles = new ArrayList<>();
        Pattern pattern = Pattern.compile("<script[^>]*src=\"([^\"]+\\.js)[^\"]*\"", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(html);

        while (matcher.find()) {
            String jsPath = matcher.group(1);
            if (jsPath.startsWith("//")) {
                jsPath = "https:" + jsPath;
            } else if (jsPath.startsWith("/")) {
                jsPath = baseUrl + jsPath.substring(1); // убираем начальный слэш
            } else if (!jsPath.startsWith("http")) {
                jsPath = baseUrl + jsPath;
            }
            jsFiles.add(jsPath);
        }

        return jsFiles;
    }

    private List<String> extractHiddenEndpointsFromJS(String jsContent) {
        List<String> endpoints = new ArrayList<>();

        for (String patternStr : JS_PATH_PATTERNS) {
            Pattern pattern = Pattern.compile(patternStr);
            Matcher matcher = pattern.matcher(jsContent);

            while (matcher.find()) {
                String endpoint = matcher.group(1);
                // Фильтруем только релевантные endpoints
                if (endpoint.startsWith("/") && endpoint.length() > 2 &&
                        !endpoint.contains(".css") && !endpoint.contains(".png") &&
                        !endpoint.contains(".jpg") && !endpoint.contains(".gif")) {
                    endpoints.add(endpoint);
                }
            }
        }

        return endpoints.stream().distinct().toList();
    }

    private HttpApiClient.ApiResponse makeRequest(ApiClient apiClient, String url) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("User-Agent", "GOSTGuardian-Scanner/1.0");

            Object response = apiClient.executeRequest("GET", url, null, headers);
            return (HttpApiClient.ApiResponse) response;

        } catch (Exception e) {
            // Игнорируем ошибки соединения - это нормально для несуществующих endpoints
            return null;
        }
    }

    private boolean isInterestingResponse(int statusCode) {
        return statusCode == 200 || statusCode == 201 || statusCode == 301 ||
                statusCode == 302 || statusCode == 403 || statusCode == 401;
    }

    // Добавлен метод для проверки debug mode (аналогично Main.java)
    private static boolean isDebugMode() {
        return System.getProperty("debug") != null ||
                Arrays.asList(System.getenv().getOrDefault("JAVA_OPTS", "").split(" ")).contains("-Ddebug");
    }

    private Vulnerability createInventoryVulnerability(String title, String description,
                                                       String endpoint, int statusCode, String evidence) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API9:2023 - Improper Inventory Management - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(Vulnerability.Severity.LOW);
        vuln.setCategory(Vulnerability.Category.OWASP_API9_INVENTORY);
        vuln.setEndpoint(endpoint);
        vuln.setStatusCode(statusCode);
        vuln.setEvidence(evidence);
        vuln.setMethod("GET");

        List<String> recommendations = new ArrayList<>();
        recommendations.add("Регулярно обновляйте документацию API и синхронизируйте её с реализацией");
        recommendations.add("Удалите неиспользуемые и устаревшие endpoints");
        recommendations.add("Ограничьте доступ к debug, monitoring и development endpoints в production среде");
        recommendations.add("Внедрите процесс управления версиями API с четким lifecycle");
        recommendations.add("Используйте стандартизированные пути для API endpoints");
        recommendations.add("Регулярно проводите инвентаризацию всех API endpoints");
        recommendations.add("Убедитесь, что client-side код не содержит скрытых API endpoints");
        recommendations.add("Внедрите автоматическое обнаружение и документирование новых endpoints");
        vuln.setRecommendations(recommendations);

        return vuln;
    }
}