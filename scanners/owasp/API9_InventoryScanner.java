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
            "api/import", "backdoor", "shell", "cmd", "exec",
            "api/backdoor", "api/shell", "api/cmd", "api/exec",
            "phpmyadmin", "mysql", "phpinfo", "env", "/.git",
            "/.env", "DS_Store", "wp-admin", "administrator"
    );

    private static final List<String> VERSION_PATHS = Arrays.asList(
            "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10",
            "api/v1", "api/v2", "api/v3", "api/v4", "api/v5",
            "internal", "internal/api", "dev", "development",
            "staging", "test", "uat", "beta", "alpha",
            "legacy", "old", "new", "current", "previous",
            "archive", "backup", "temp", "tmp"
    );

    private static final List<String> MONITORING_PATHS = Arrays.asList(
            "health", "metrics", "status", "info", "actuator",
            "actuator/health", "actuator/metrics", "actuator/info",
            "prometheus", "grafana", "monitoring", "api/health",
            "api/metrics", "api/status", "management/health",
            "ping", "ready", "live", "heapdump", "threaddump",
            "env", "configprops", "mappings", "flyway", "liquibase",
            "beans", "conditions", "configprops", "loggers", "metrics",
            "scheduledtasks", "sessions", "shutdown", "trace"
    );

    private static final List<String> DEPRECATED_KEYWORDS = Arrays.asList(
            "deprecated", "legacy", "old", "v1", "v0", "beta", "alpha",
            "obsolete", "outdated", "removed", "sunset", "discontinued",
            "unsupported", "retired", "expired", "removal", "eol"
    );

    private static final List<String> JS_PATH_PATTERNS = Arrays.asList(
            "[\"'](/[a-zA-Z0-9_\\-\\./]+)[\"']",
            "[\"'](api/[a-zA-Z0-9_\\-\\./]+)[\"']",
            "[\"'](v[0-9]/[a-zA-Z0-9_\\-\\./]+)[\"']",
            "url:\\s*[\"']([^\"']+)[\"']",
            "endpoint:\\s*[\"']([^\"']+)[\"']",
            "path:\\s*[\"']([^\"']+)[\"']",
            "fetch\\([\"']([^\"']+)[\"']\\)",
            "axios\\.get\\([\"']([^\"']+)[\"']\\)",
            "\\.post\\([\"']([^\"']+)[\"']\\)",
            "apiUrl[\\s\\S]*?=[\\s\\S]*?[\"']([^\"']+)[\"']"
    );

    private int totalRequests = 0;
    private int foundEndpoints = 0;

    public API9_InventoryScanner() {}

    @Override
    public String getName() {
        return "OWASP API9:2023 - Improper Inventory Management";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("🔍 Starting comprehensive inventory management scan (OWASP API9:2023)...");
        System.out.println("🎯 Target: " + config.getTargetBaseUrl());

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = normalizeBaseUrl(config.getTargetBaseUrl().trim());

        // Сброс счетчиков
        totalRequests = 0;
        foundEndpoints = 0;

        try {
            // 5.9.1: Проверка common endpoints
            System.out.println("\n📋 5.9.1: Scanning common endpoints (" + COMMON_ENDPOINTS.size() + " patterns)...");
            vulnerabilities.addAll(scanCommonEndpoints(baseUrl, apiClient));

            // 5.9.2: Брутфорс путей на основе структуры документации API
            System.out.println("📋 5.9.2: Brute-forcing endpoints based on API structure...");
            vulnerabilities.addAll(bruteForceFromDocumentation(baseUrl, apiClient, openAPI));

            // 5.9.3: Поиск версионированных эндпоинтов
            System.out.println("📋 5.9.3: Scanning versioned endpoints (" + VERSION_PATHS.size() + " patterns)...");
            vulnerabilities.addAll(scanVersionedEndpoints(baseUrl, apiClient));

            // 5.9.4: Проверка стандартных мониторинг-путей
            System.out.println("📋 5.9.4: Scanning monitoring endpoints (" + MONITORING_PATHS.size() + " patterns)...");
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
            System.err.println("❌ Critical error during inventory scan: " + e.getMessage());
            if (isDebugMode()) {
                e.printStackTrace();
            }
        }

        // Детальная статистика сканирования
        System.out.println("\n📊 INVENTORY SCAN COMPLETED:");
        System.out.println("   📞 Total requests made: " + totalRequests);
        System.out.println("   🔍 Endpoints discovered: " + foundEndpoints);
        System.out.println("   🚨 Vulnerabilities found: " + vulnerabilities.size());
        System.out.println("   ⏱️  Scan duration: " + new Date());

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
        int discovered = 0;

        for (String endpoint : COMMON_ENDPOINTS) {
            String fullUrl = baseUrl + endpoint;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "COMMON_ENDPOINT");

            if (response != null && isInterestingResponse(response.getStatusCode())) {
                discovered++;
                String evidence = buildDetailedEvidence("Common Endpoint Discovery", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Undocumented Common Endpoint: " + endpoint,
                        "🚨 CRITICAL: Обнаружен недокументированный common endpoint: " + endpoint +
                                "\n📊 Статус: HTTP " + response.getStatusCode() +
                                "\n🔍 Тип: " + classifyEndpoint(endpoint, response) +
                                "\n💡 Риск: " + assessRiskLevel(endpoint, response) +
                                "\n\nEndpoint соответствует известным шаблонам административных, debug или системных путей. " +
                                "Такие endpoints часто содержат уязвимости или раскрывают чувствительную информацию.",
                        "/" + endpoint,
                        response.getStatusCode(),
                        evidence
                );

                // Определяем критичность на основе типа endpoint
                if (endpoint.contains("admin") || endpoint.contains("debug") || endpoint.contains("secret") ||
                        endpoint.contains("backdoor") || endpoint.contains("env") || endpoint.contains("git")) {
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                } else if (endpoint.contains("config") || endpoint.contains("log") || endpoint.contains("system")) {
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                }

                vulns.add(vuln);
                System.out.println("   ✅ Found: " + endpoint + " (" + response.getStatusCode() + ") - " + classifyEndpoint(endpoint, response));
            }
        }

        System.out.println("   📊 Common endpoints discovered: " + discovered + "/" + COMMON_ENDPOINTS.size());
        foundEndpoints += discovered;
        return vulns;
    }

    // 5.9.2: Брутфорс путей на основе структуры документации API
    private List<Vulnerability> bruteForceFromDocumentation(String baseUrl, ApiClient apiClient, Object openAPI) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        List<String> bruteForcePaths = generateBruteForcePaths();
        System.out.println("   🔧 Generated " + bruteForcePaths.size() + " brute-force patterns");

        for (String path : bruteForcePaths) {
            String fullUrl = baseUrl + path;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "BRUTEFORCE");

            if (response != null && isInterestingResponse(response.getStatusCode())) {
                discovered++;
                String evidence = buildDetailedEvidence("Brute-Force Discovery", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Brute-Forced Endpoint: " + path,
                        "🔍 Обнаружен endpoint через брутфорс: " + path +
                                "\n📊 Статус: HTTP " + response.getStatusCode() +
                                "\n🎯 Метод: Автоматический перебор" +
                                "\n💡 Риск: Endpoint не документирован в официальной спецификации API",
                        "/" + path,
                        response.getStatusCode(),
                        evidence
                );
                vulns.add(vuln);
            }
        }

        System.out.println("   📊 Brute-force endpoints discovered: " + discovered + "/" + bruteForcePaths.size());
        foundEndpoints += discovered;
        return vulns;
    }

    // 5.9.3: Поиск версионированных эндпоинтов
    private List<Vulnerability> scanVersionedEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        for (String versionPath : VERSION_PATHS) {
            // Проверяем сам путь версии
            String versionUrl = baseUrl + versionPath;
            HttpApiClient.ApiResponse versionResponse = makeRequest(apiClient, versionUrl, "VERSIONED");

            if (versionResponse != null && isInterestingResponse(versionResponse.getStatusCode())) {
                discovered++;
                String evidence = buildDetailedEvidence("Versioned Endpoint", versionUrl, versionResponse);

                Vulnerability vuln = createInventoryVulnerability(
                        "Versioned API Endpoint: " + versionPath,
                        "🔄 Обнаружен версионированный endpoint: " + versionPath +
                                "\n📊 Статус: HTTP " + versionResponse.getStatusCode() +
                                "\n🚨 Риск: Устаревшие версии API могут содержать известные уязвимости" +
                                "\n💡 Рекомендация: Проверить актуальность версии и наличие security patches",
                        "/" + versionPath,
                        versionResponse.getStatusCode(),
                        evidence
                );

                if (versionPath.contains("v1") || versionPath.contains("old") || versionPath.contains("legacy")) {
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                }

                vulns.add(vuln);
            }

            // Проверяем комбинации версий с common paths
            for (String commonPath : Arrays.asList("users", "accounts", "transactions", "auth", "admin")) {
                String fullUrl = baseUrl + versionPath + "/" + commonPath;
                HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "VERSIONED_RESOURCE");

                if (response != null && isInterestingResponse(response.getStatusCode())) {
                    discovered++;
                    String evidence = buildDetailedEvidence("Versioned Resource", fullUrl, response);

                    Vulnerability vuln = createInventoryVulnerability(
                            "Versioned Resource Endpoint: " + versionPath + "/" + commonPath,
                            "🔄 Обнаружен версионированный resource endpoint: " + versionPath + "/" + commonPath +
                                    "\n📊 Статус: HTTP " + response.getStatusCode() +
                                    "\n🎯 Ресурс: " + commonPath +
                                    "\n🚨 Риск: Устаревшие версии API могут не получать security patches",
                            "/" + versionPath + "/" + commonPath,
                            response.getStatusCode(),
                            evidence
                    );
                    vulns.add(vuln);
                }
            }
        }

        System.out.println("   📊 Versioned endpoints discovered: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    // 5.9.4: Проверка стандартных мониторинг-путей
    private List<Vulnerability> scanMonitoringEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        for (String monitoringPath : MONITORING_PATHS) {
            String fullUrl = baseUrl + monitoringPath;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "MONITORING");

            if (response != null && response.getStatusCode() == 200) {
                discovered++;
                String evidence = buildDetailedEvidence("Monitoring Endpoint", fullUrl, response);

                String riskAssessment = assessMonitoringRisk(monitoringPath, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Public Monitoring Endpoint: " + monitoringPath,
                        "📊 Обнаружен публичный мониторинг endpoint: " + monitoringPath +
                                "\n🚨 " + riskAssessment +
                                "\n💡 Риск: Раскрытие чувствительной информации о системе",
                        "/" + monitoringPath,
                        response.getStatusCode(),
                        evidence
                );

                // Определяем критичность на основе типа monitoring endpoint
                if (monitoringPath.contains("env") || monitoringPath.contains("config") ||
                        monitoringPath.contains("heapdump") || monitoringPath.contains("threaddump") ||
                        monitoringPath.contains("shutdown")) {
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                } else if (monitoringPath.contains("metrics") || monitoringPath.contains("health")) {
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                }

                vulns.add(vuln);
                System.out.println("   🚨 Public monitoring: " + monitoringPath + " - " + riskAssessment);
            }
        }

        System.out.println("   📊 Monitoring endpoints discovered: " + discovered + "/" + MONITORING_PATHS.size());
        foundEndpoints += discovered;
        return vulns;
    }

    // 5.9.5: Анализ JavaScript файлов на наличие скрытых API-путей
    private List<Vulnerability> scanJavaScriptFiles(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        try {
            // Получаем главную страницу для поиска JS файлов
            HttpApiClient.ApiResponse mainPage = makeRequest(apiClient, baseUrl, "MAIN_PAGE");
            if (mainPage != null && mainPage.getStatusCode() == 200) {
                List<String> jsFiles = extractJavaScriptFiles(mainPage.getBody(), baseUrl);
                System.out.println("   🔍 Found " + jsFiles.size() + " JavaScript files");

                for (String jsFile : jsFiles) {
                    HttpApiClient.ApiResponse jsResponse = makeRequest(apiClient, jsFile, "JS_FILE");
                    if (jsResponse != null && jsResponse.getStatusCode() == 200) {
                        List<String> hiddenEndpoints = extractHiddenEndpointsFromJS(jsResponse.getBody());
                        System.out.println("   📁 JS File: " + jsFile + " - " + hiddenEndpoints.size() + " endpoints found");

                        for (String endpoint : hiddenEndpoints) {
                            // Проверяем найденный endpoint
                            String testUrl = baseUrl + endpoint.substring(1); // убираем начальный слэш
                            HttpApiClient.ApiResponse endpointResponse = makeRequest(apiClient, testUrl, "HIDDEN_ENDPOINT");

                            if (endpointResponse != null && isInterestingResponse(endpointResponse.getStatusCode())) {
                                discovered++;
                                String evidence = buildDetailedEvidence("Hidden Endpoint in JS", testUrl, endpointResponse);
                                evidence += "\n\n📁 SOURCE JAVASCRIPT FILE: " + jsFile;
                                evidence += "\n🔍 ORIGINAL JS CONTEXT:\n" + extractJsContext(jsResponse.getBody(), endpoint);

                                Vulnerability vuln = createInventoryVulnerability(
                                        "Hidden API Endpoint in JavaScript: " + endpoint,
                                        "🕵️‍♂️ Скрытый API endpoint обнаружен в JavaScript файле!" +
                                                "\n📁 Файл: " + jsFile +
                                                "\n🔗 Endpoint: " + endpoint +
                                                "\n📊 Статус: HTTP " + endpointResponse.getStatusCode() +
                                                "\n🚨 Риск: Endpoints, скрытые в client-side коде, часто не документированы и не защищены" +
                                                "\n💡 Угроза: Злоумышленник может найти и использовать недокументированные API",
                                        endpoint,
                                        endpointResponse.getStatusCode(),
                                        evidence
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

        System.out.println("   📊 Hidden endpoints in JS discovered: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    // 5.9.6: Поиск устаревших и deprecated версий API
    private List<Vulnerability> scanDeprecatedEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        // Проверяем основную документацию API
        String[] docUrls = {
                "docs", "swagger", "swagger-ui", "api-docs",
                "openapi", "v3/api-docs", "swagger.json", "api.json"
        };

        for (String docPath : docUrls) {
            String docUrl = baseUrl + docPath;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, docUrl, "API_DOCS");
            if (response != null && response.getStatusCode() == 200) {
                String body = response.getBody().toLowerCase();
                List<String> foundKeywords = new ArrayList<>();

                for (String keyword : DEPRECATED_KEYWORDS) {
                    if (body.contains(keyword)) {
                        foundKeywords.add(keyword);
                    }
                }

                if (!foundKeywords.isEmpty()) {
                    discovered++;
                    String evidence = buildDetailedEvidence("Deprecated API Documentation", docUrl, response);
                    evidence += "\n\n🔍 FOUND DEPRECATION KEYWORDS: " + String.join(", ", foundKeywords);

                    Vulnerability vuln = createInventoryVulnerability(
                            "Deprecated API Version Detected",
                            "⚠️ Обнаружены упоминания устаревших или deprecated версий API!" +
                                    "\n📄 Документация: " + docPath +
                                    "\n🔍 Ключевые слова: " + String.join(", ", foundKeywords) +
                                    "\n🚨 Риск: Устаревшие версии API могут содержать известные уязвимости" +
                                    "\n💡 Угроза: Отсутствие security patches для deprecated версий",
                            "/" + docPath,
                            response.getStatusCode(),
                            evidence
                    );
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vulns.add(vuln);
                    System.out.println("   ⚠️ Deprecated API detected in: " + docPath + " - keywords: " + foundKeywords);
                }
            }
        }

        System.out.println("   📊 Deprecated API findings: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    // 5.9.7: Проверка debug и development эндпоинтов в production
    private List<Vulnerability> scanDebugEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        List<String> debugEndpoints = Arrays.asList(
                "debug", "api/debug", "_debug", "develop", "development",
                "env", "api/env", "configuration", "api/configuration",
                "trace", "api/trace", "dump", "api/dump", "console",
                "api/console", "phpinfo", "info", "api/info"
        );

        for (String debugPath : debugEndpoints) {
            String fullUrl = baseUrl + debugPath;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "DEBUG_ENDPOINT");

            if (response != null && response.getStatusCode() == 200) {
                String body = response.getBody().toLowerCase();

                // Проверяем типичные debug-индикаторы
                boolean isDebugEndpoint = body.contains("debug") || body.contains("development") ||
                        body.contains("environment") || body.contains("configuration") ||
                        body.contains("php") || body.contains("java") ||
                        body.contains("spring") || body.contains("trace") ||
                        body.contains("database") || body.contains("password");

                if (isDebugEndpoint) {
                    discovered++;
                    String evidence = buildDetailedEvidence("Debug Endpoint in Production", fullUrl, response);
                    evidence += "\n\n🔍 DEBUG INDICATORS FOUND:";
                    if (body.contains("debug")) evidence += "\n- 'debug' keyword";
                    if (body.contains("development")) evidence += "\n- 'development' keyword";
                    if (body.contains("environment")) evidence += "\n- 'environment' keyword";
                    if (body.contains("configuration")) evidence += "\n- 'configuration' keyword";
                    if (body.contains("password")) evidence += "\n- 'password' keyword (CRITICAL!)";

                    Vulnerability vuln = createInventoryVulnerability(
                            "Debug Endpoint in Production: " + debugPath,
                            "🚨 CRITICAL: Debug endpoint доступен в production среде!" +
                                    "\n🔗 Endpoint: " + debugPath +
                                    "\n📊 Статус: HTTP " + response.getStatusCode() +
                                    "\n💀 Риск: Раскрытие чувствительной информации о приложении и среде выполнения" +
                                    "\n🎯 Угроза: Получение конфигурационных данных, credentials, системной информации",
                            "/" + debugPath,
                            response.getStatusCode(),
                            evidence
                    );
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vulns.add(vuln);
                    System.out.println("   💀 CRITICAL: Debug endpoint in production: " + debugPath);
                }
            }
        }

        System.out.println("   📊 Debug endpoints discovered: " + discovered + "/" + debugEndpoints.size());
        foundEndpoints += discovered;
        return vulns;
    }

    // Вспомогательные методы
    private List<String> generateBruteForcePaths() {
        List<String> paths = new ArrayList<>();
        String[] resources = {"user", "users", "account", "accounts", "admin", "api", "data",
                "file", "files", "upload", "download", "config", "settings",
                "customer", "customers", "transaction", "transactions",
                "payment", "payments", "order", "orders", "product", "products"};
        String[] actions = {"", "/list", "/all", "/get", "/create", "/update", "/delete",
                "/search", "/find", "/export", "/import", "/count", "/total"};
        String[] ids = {"", "/1", "/123", "/test", "/admin", "/me", "/current"};

        // Генерируем комбинации
        for (String resource : resources) {
            for (String action : actions) {
                for (String id : ids) {
                    if (paths.size() < 200) { // Ограничим количество для производительности
                        paths.add(resource + action + id);
                        paths.add("api/" + resource + action + id);
                    }
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
                jsPath = baseUrl + jsPath.substring(1);
            } else if (!jsPath.startsWith("http")) {
                jsPath = baseUrl + jsPath;
            }
            jsFiles.add(jsPath);
        }

        return jsFiles.stream().distinct().limit(10).toList(); // Ограничим количество JS файлов
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
                        !endpoint.contains(".jpg") && !endpoint.contains(".gif") &&
                        !endpoint.contains(".ico") && !endpoint.contains(".svg")) {
                    endpoints.add(endpoint);
                }
            }
        }

        return endpoints.stream().distinct().toList();
    }

    private String extractJsContext(String jsContent, String endpoint) {
        // Находим контекст вокруг endpoint в JS коде
        int index = jsContent.indexOf(endpoint);
        if (index != -1) {
            int start = Math.max(0, index - 50);
            int end = Math.min(jsContent.length(), index + endpoint.length() + 50);
            return jsContent.substring(start, end).replace("\n", " ");
        }
        return "Context not found";
    }

    private HttpApiClient.ApiResponse makeRequest(ApiClient apiClient, String url, String type) {
        totalRequests++;
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

    private String buildDetailedEvidence(String title, String url, HttpApiClient.ApiResponse response) {
        StringBuilder evidence = new StringBuilder();
        evidence.append("🔍 ").append(title).append("\n");
        evidence.append("📅 Scan Time: ").append(new Date()).append("\n");
        evidence.append("🔗 URL: ").append(url).append("\n");
        evidence.append("📊 HTTP Status: ").append(response.getStatusCode()).append("\n");

        if (response.getHeaders() != null && !response.getHeaders().isEmpty()) {
            evidence.append("\n📋 RESPONSE HEADERS:\n");
            response.getHeaders().forEach((k, v) -> {
                if (k != null && v != null) {
                    evidence.append("  ").append(k).append(": ").append(v).append("\n");
                }
            });
        }

        if (response.getBody() != null && !response.getBody().isEmpty()) {
            evidence.append("\n📄 RESPONSE BODY (first 500 chars):\n");
            String bodyPreview = response.getBody().length() > 500 ?
                    response.getBody().substring(0, 500) + "..." : response.getBody();
            evidence.append(bodyPreview);

            // Анализ содержимого
            evidence.append("\n\n🔬 CONTENT ANALYSIS:\n");
            String body = response.getBody().toLowerCase();
            if (body.contains("password")) evidence.append("- Contains 'password' keyword\n");
            if (body.contains("admin")) evidence.append("- Contains 'admin' keyword\n");
            if (body.contains("debug")) evidence.append("- Contains 'debug' keyword\n");
            if (body.contains("error")) evidence.append("- Contains 'error' information\n");
            if (body.contains("version")) evidence.append("- Contains version information\n");
            if (body.contains("database")) evidence.append("- Contains database information\n");
        } else {
            evidence.append("\n📄 RESPONSE BODY: [Empty or not available]");
        }

        return evidence.toString();
    }

    private String classifyEndpoint(String endpoint, HttpApiClient.ApiResponse response) {
        if (endpoint.contains("admin")) return "Administrative Interface";
        if (endpoint.contains("debug")) return "Debug Interface";
        if (endpoint.contains("log")) return "Log Access";
        if (endpoint.contains("config")) return "Configuration Access";
        if (endpoint.contains("backup")) return "Backup Access";
        if (endpoint.contains("database")) return "Database Interface";
        if (endpoint.contains("monitor")) return "Monitoring Interface";
        if (endpoint.contains("test")) return "Testing Interface";
        return "Unknown Type";
    }

    private String assessRiskLevel(String endpoint, HttpApiClient.ApiResponse response) {
        if (endpoint.contains("admin") || endpoint.contains("debug") || endpoint.contains("secret")) {
            return "HIGH - Administrative/Debug access";
        }
        if (endpoint.contains("config") || endpoint.contains("log") || endpoint.contains("system")) {
            return "MEDIUM - System configuration access";
        }
        if (endpoint.contains("backup") || endpoint.contains("database")) {
            return "HIGH - Data access";
        }
        return "LOW - General endpoint";
    }

    private String assessMonitoringRisk(String monitoringPath, HttpApiClient.ApiResponse response) {
        if (monitoringPath.contains("env") || monitoringPath.contains("config")) {
            return "HIGH - Environment configuration exposure";
        }
        if (monitoringPath.contains("heapdump") || monitoringPath.contains("threaddump")) {
            return "HIGH - Memory dump exposure";
        }
        if (monitoringPath.contains("shutdown")) {
            return "CRITICAL - Service shutdown capability";
        }
        if (monitoringPath.contains("metrics")) {
            return "MEDIUM - Performance metrics exposure";
        }
        return "LOW - Basic health check";
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
        recommendations.add("🔒 Немедленно ограничьте доступ к обнаруженным endpoints");
        recommendations.add("📝 Проведите полную инвентаризацию всех API endpoints");
        recommendations.add("🗑️ Удалите неиспользуемые и устаревшие endpoints");
        recommendations.add("🔐 Ограничьте доступ к debug, monitoring и development endpoints в production среде");
        recommendations.add("🔄 Внедрите процесс управления версиями API с четким lifecycle");
        recommendations.add("📊 Регулярно проводите автоматическое сканирование инвентаризации");
        recommendations.add("🚫 Убедитесь, что client-side код не содержит скрытых API endpoints");
        recommendations.add("📋 Синхронизируйте документацию с реально существующими endpoints");
        vuln.setRecommendations(recommendations);

        return vuln;
    }
}