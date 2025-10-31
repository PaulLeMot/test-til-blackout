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
        System.out.println("(API-9) Запуск комплексного сканирования управления инвентаризацией (OWASP API9:2023)...");
        System.out.println("(API-9) Целевой URL: " + config.getTargetBaseUrl());

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = normalizeBaseUrl(config.getTargetBaseUrl().trim());

        // Сброс счетчиков
        totalRequests = 0;
        foundEndpoints = 0;

        try {
            // 5.9.1: Проверка common endpoints
            System.out.println("(API-9) 5.9.1: Сканирование стандартных конечных точек (" + COMMON_ENDPOINTS.size() + " шаблонов)...");
            vulnerabilities.addAll(scanCommonEndpoints(baseUrl, apiClient));

            // 5.9.2: Брутфорс путей на основе структуры документации API
            System.out.println("(API-9) 5.9.2: Перебор конечных точек на основе структуры API...");
            vulnerabilities.addAll(bruteForceFromDocumentation(baseUrl, apiClient, openAPI));

            // 5.9.3: Поиск версионированных эндпоинтов
            System.out.println("(API-9) 5.9.3: Сканирование версионированных конечных точек (" + VERSION_PATHS.size() + " шаблонов)...");
            vulnerabilities.addAll(scanVersionedEndpoints(baseUrl, apiClient));

            // 5.9.4: Проверка стандартных мониторинг-путей
            System.out.println("(API-9) 5.9.4: Сканирование мониторинговых конечных точек (" + MONITORING_PATHS.size() + " шаблонов)...");
            vulnerabilities.addAll(scanMonitoringEndpoints(baseUrl, apiClient));

            // 5.9.5: Анализ JavaScript файлов на наличие скрытых API-путей
            System.out.println("(API-9) 5.9.5: Анализ JavaScript файлов на наличие скрытых API-путей...");
            vulnerabilities.addAll(scanJavaScriptFiles(baseUrl, apiClient));

            // 5.9.6: Поиск устаревших и deprecated версий API
            System.out.println("(API-9) 5.9.6: Поиск устаревших и deprecated версий API...");
            vulnerabilities.addAll(scanDeprecatedEndpoints(baseUrl, apiClient));

            // 5.9.7: Проверка debug и development эндпоинтов в production
            System.out.println("(API-9) 5.9.7: Проверка debug и development конечных точек в production...");
            vulnerabilities.addAll(scanDebugEndpoints(baseUrl, apiClient));

        } catch (Exception e) {
            System.err.println("(API-9) Критическая ошибка при сканировании инвентаризации: " + e.getMessage());
            if (isDebugMode()) {
                e.printStackTrace();
            }
        }

        // Детальная статистика сканирования
        System.out.println("(API-9) СКАНИРОВАНИЕ ИНВЕНТАРИЗАЦИИ ЗАВЕРШЕНО:");
        System.out.println("(API-9) Всего выполнено запросов: " + totalRequests);
        System.out.println("(API-9) Обнаружено конечных точек: " + foundEndpoints);
        System.out.println("(API-9) Найдено уязвимостей: " + vulnerabilities.size());
        System.out.println("(API-9) Время сканирования: " + new Date());

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
                String evidence = buildDetailedEvidence("Обнаружение стандартной конечной точки", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Незадокументированная стандартная конечная точка: " + endpoint,
                        "КРИТИЧЕСКИЙ УРОВЕНЬ: Обнаружена незадокументированная стандартная конечная точка: " + endpoint +
                                "\nСтатус: HTTP " + response.getStatusCode() +
                                "\nТип: " + classifyEndpoint(endpoint, response) +
                                "\nУровень риска: " + assessRiskLevel(endpoint, response) +
                                "\n\nКонечная точка соответствует известным шаблонам административных, debug или системных путей. " +
                                "Такие конечные точки часто содержат уязвимости или раскрывают чувствительную информацию.",
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
                System.out.println("(API-9) Обнаружена: " + endpoint + " (" + response.getStatusCode() + ") - " + classifyEndpoint(endpoint, response));
            }
        }

        System.out.println("(API-9) Стандартных конечных точек обнаружено: " + discovered + "/" + COMMON_ENDPOINTS.size());
        foundEndpoints += discovered;
        return vulns;
    }

    // 5.9.2: Брутфорс путей на основе структуры документации API
    private List<Vulnerability> bruteForceFromDocumentation(String baseUrl, ApiClient apiClient, Object openAPI) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        List<String> bruteForcePaths = generateBruteForcePaths();
        System.out.println("(API-9) Сгенерировано " + bruteForcePaths.size() + " шаблонов для перебора");

        for (String path : bruteForcePaths) {
            String fullUrl = baseUrl + path;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "BRUTEFORCE");

            if (response != null && isInterestingResponse(response.getStatusCode())) {
                discovered++;
                String evidence = buildDetailedEvidence("Обнаружение перебором", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Конечная точка обнаружена перебором: " + path,
                        "Обнаружена конечная точка через автоматический перебор: " + path +
                                "\nСтатус: HTTP " + response.getStatusCode() +
                                "\nМетод обнаружения: Автоматический перебор" +
                                "\nРиск: Конечная точка не документирована в официальной спецификации API",
                        "/" + path,
                        response.getStatusCode(),
                        evidence
                );
                vulns.add(vuln);
            }
        }

        System.out.println("(API-9) Конечных точек обнаружено перебором: " + discovered + "/" + bruteForcePaths.size());
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
                String evidence = buildDetailedEvidence("Версионированная конечная точка", versionUrl, versionResponse);

                Vulnerability vuln = createInventoryVulnerability(
                        "Версионированная API конечная точка: " + versionPath,
                        "Обнаружена версионированная конечная точка: " + versionPath +
                                "\nСтатус: HTTP " + versionResponse.getStatusCode() +
                                "\nРиск: Устаревшие версии API могут содержать известные уязвимости" +
                                "\nРекомендация: Проверить актуальность версии и наличие security patches",
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
                    String evidence = buildDetailedEvidence("Версионированный ресурс", fullUrl, response);

                    Vulnerability vuln = createInventoryVulnerability(
                            "Версионированная ресурсная конечная точка: " + versionPath + "/" + commonPath,
                            "Обнаружена версионированная ресурсная конечная точка: " + versionPath + "/" + commonPath +
                                    "\nСтатус: HTTP " + response.getStatusCode() +
                                    "\nРесурс: " + commonPath +
                                    "\nРиск: Устаревшие версии API могут не получать security patches",
                            "/" + versionPath + "/" + commonPath,
                            response.getStatusCode(),
                            evidence
                    );
                    vulns.add(vuln);
                }
            }
        }

        System.out.println("(API-9) Версионированных конечных точек обнаружено: " + discovered);
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
                String evidence = buildDetailedEvidence("Мониторинговая конечная точка", fullUrl, response);

                String riskAssessment = assessMonitoringRisk(monitoringPath, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Публичная мониторинговая конечная точка: " + monitoringPath,
                        "Обнаружена публичная мониторинговая конечная точка: " + monitoringPath +
                                "\n" + riskAssessment +
                                "\nРиск: Раскрытие чувствительной информации о системе",
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
                System.out.println("(API-9) Публичная мониторинговая конечная точка: " + monitoringPath + " - " + riskAssessment);
            }
        }

        System.out.println("(API-9) Мониторинговых конечных точек обнаружено: " + discovered + "/" + MONITORING_PATHS.size());
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
                System.out.println("(API-9) Найдено " + jsFiles.size() + " JavaScript файлов");

                for (String jsFile : jsFiles) {
                    HttpApiClient.ApiResponse jsResponse = makeRequest(apiClient, jsFile, "JS_FILE");
                    if (jsResponse != null && jsResponse.getStatusCode() == 200) {
                        List<String> hiddenEndpoints = extractHiddenEndpointsFromJS(jsResponse.getBody());
                        System.out.println("(API-9) JS файл: " + jsFile + " - найдено конечных точек: " + hiddenEndpoints.size());

                        for (String endpoint : hiddenEndpoints) {
                            // Проверяем найденный endpoint
                            String testUrl = baseUrl + endpoint.substring(1); // убираем начальный слэш
                            HttpApiClient.ApiResponse endpointResponse = makeRequest(apiClient, testUrl, "HIDDEN_ENDPOINT");

                            if (endpointResponse != null && isInterestingResponse(endpointResponse.getStatusCode())) {
                                discovered++;
                                String evidence = buildDetailedEvidence("Скрытая конечная точка в JS", testUrl, endpointResponse);
                                evidence += "\n\nИСХОДНЫЙ JAVASCRIPT ФАЙЛ: " + jsFile;
                                evidence += "\nКОНТЕКСТ В JS КОДЕ:\n" + extractJsContext(jsResponse.getBody(), endpoint);

                                Vulnerability vuln = createInventoryVulnerability(
                                        "Скрытая API конечная точка в JavaScript: " + endpoint,
                                        "Скрытая API конечная точка обнаружена в JavaScript файле!" +
                                                "\nФайл: " + jsFile +
                                                "\nКонечная точка: " + endpoint +
                                                "\nСтатус: HTTP " + endpointResponse.getStatusCode() +
                                                "\nРиск: Конечные точки, скрытые в client-side коде, часто не документированы и не защищены" +
                                                "\nУгроза: Злоумышленник может найти и использовать недокументированные API",
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
            System.err.println("(API-9) Ошибка при анализе JavaScript файлов: " + e.getMessage());
        }

        System.out.println("(API-9) Скрытых конечных точек в JS обнаружено: " + discovered);
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
                    String evidence = buildDetailedEvidence("Устаревшая документация API", docUrl, response);
                    evidence += "\n\nНАЙДЕННЫЕ КЛЮЧЕВЫЕ СЛОВА УСТАРЕВАНИЯ: " + String.join(", ", foundKeywords);

                    Vulnerability vuln = createInventoryVulnerability(
                            "Обнаружена устаревшая версия API",
                            "Обнаружены упоминания устаревших или deprecated версий API!" +
                                    "\nДокументация: " + docPath +
                                    "\nКлючевые слова: " + String.join(", ", foundKeywords) +
                                    "\nРиск: Устаревшие версии API могут содержать известные уязвимости" +
                                    "\nУгроза: Отсутствие security patches для deprecated версий",
                            "/" + docPath,
                            response.getStatusCode(),
                            evidence
                    );
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vulns.add(vuln);
                    System.out.println("(API-9) Устаревший API обнаружен в: " + docPath + " - ключевые слова: " + foundKeywords);
                }
            }
        }

        System.out.println("(API-9) Находок устаревших API: " + discovered);
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
                    String evidence = buildDetailedEvidence("Debug конечная точка в production", fullUrl, response);
                    evidence += "\n\nИНДИКАТОРЫ DEBUG НАЙДЕНЫ:";
                    if (body.contains("debug")) evidence += "\n- ключевое слово 'debug'";
                    if (body.contains("development")) evidence += "\n- ключевое слово 'development'";
                    if (body.contains("environment")) evidence += "\n- ключевое слово 'environment'";
                    if (body.contains("configuration")) evidence += "\n- ключевое слово 'configuration'";
                    if (body.contains("password")) evidence += "\n- ключевое слово 'password' (КРИТИЧЕСКИ!)";

                    Vulnerability vuln = createInventoryVulnerability(
                            "Debug конечная точка в production: " + debugPath,
                            "КРИТИЧЕСКИЙ УРОВЕНЬ: Debug конечная точка доступна в production среде!" +
                                    "\nКонечная точка: " + debugPath +
                                    "\nСтатус: HTTP " + response.getStatusCode() +
                                    "\nРиск: Раскрытие чувствительной информации о приложении и среде выполнения" +
                                    "\nУгроза: Получение конфигурационных данных, credentials, системной информации",
                            "/" + debugPath,
                            response.getStatusCode(),
                            evidence
                    );
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vulns.add(vuln);
                    System.out.println("(API-9) КРИТИЧЕСКИЙ УРОВЕНЬ: Debug конечная точка в production: " + debugPath);
                }
            }
        }

        System.out.println("(API-9) Debug конечных точек обнаружено: " + discovered + "/" + debugEndpoints.size());
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
        return "Контекст не найден";
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
        evidence.append(title).append("\n");
        evidence.append("Время сканирования: ").append(new Date()).append("\n");
        evidence.append("URL: ").append(url).append("\n");
        evidence.append("HTTP Статус: ").append(response.getStatusCode()).append("\n");

        if (response.getHeaders() != null && !response.getHeaders().isEmpty()) {
            evidence.append("\nЗАГОЛОВКИ ОТВЕТА:\n");
            response.getHeaders().forEach((k, v) -> {
                if (k != null && v != null) {
                    evidence.append("  ").append(k).append(": ").append(v).append("\n");
                }
            });
        }

        if (response.getBody() != null && !response.getBody().isEmpty()) {
            evidence.append("\nТЕЛО ОТВЕТА (первые 500 символов):\n");
            String bodyPreview = response.getBody().length() > 500 ?
                    response.getBody().substring(0, 500) + "..." : response.getBody();
            evidence.append(bodyPreview);

            // Анализ содержимого
            evidence.append("\n\nАНАЛИЗ СОДЕРЖИМОГО:\n");
            String body = response.getBody().toLowerCase();
            if (body.contains("password")) evidence.append("- Содержит ключевое слово 'password'\n");
            if (body.contains("admin")) evidence.append("- Содержит ключевое слово 'admin'\n");
            if (body.contains("debug")) evidence.append("- Содержит ключевое слово 'debug'\n");
            if (body.contains("error")) evidence.append("- Содержит информацию об ошибках\n");
            if (body.contains("version")) evidence.append("- Содержит информацию о версии\n");
            if (body.contains("database")) evidence.append("- Содержит информацию о базе данных\n");
        } else {
            evidence.append("\nТЕЛО ОТВЕТА: [Пусто или недоступно]");
        }

        return evidence.toString();
    }

    private String classifyEndpoint(String endpoint, HttpApiClient.ApiResponse response) {
        if (endpoint.contains("admin")) return "Административный интерфейс";
        if (endpoint.contains("debug")) return "Интерфейс отладки";
        if (endpoint.contains("log")) return "Доступ к логам";
        if (endpoint.contains("config")) return "Доступ к конфигурации";
        if (endpoint.contains("backup")) return "Доступ к резервным копиям";
        if (endpoint.contains("database")) return "Интерфейс базы данных";
        if (endpoint.contains("monitor")) return "Интерфейс мониторинга";
        if (endpoint.contains("test")) return "Тестовый интерфейс";
        return "Неизвестный тип";
    }

    private String assessRiskLevel(String endpoint, HttpApiClient.ApiResponse response) {
        if (endpoint.contains("admin") || endpoint.contains("debug") || endpoint.contains("secret")) {
            return "ВЫСОКИЙ - Административный/Debug доступ";
        }
        if (endpoint.contains("config") || endpoint.contains("log") || endpoint.contains("system")) {
            return "СРЕДНИЙ - Доступ к системной конфигурации";
        }
        if (endpoint.contains("backup") || endpoint.contains("database")) {
            return "ВЫСОКИЙ - Доступ к данным";
        }
        return "НИЗКИЙ - Общая конечная точка";
    }

    private String assessMonitoringRisk(String monitoringPath, HttpApiClient.ApiResponse response) {
        if (monitoringPath.contains("env") || monitoringPath.contains("config")) {
            return "ВЫСОКИЙ УРОВЕНЬ - Раскрытие конфигурации окружения";
        }
        if (monitoringPath.contains("heapdump") || monitoringPath.contains("threaddump")) {
            return "ВЫСОКИЙ УРОВЕНЬ - Раскрытие дампа памяти";
        }
        if (monitoringPath.contains("shutdown")) {
            return "КРИТИЧЕСКИЙ УРОВЕНЬ - Возможность остановки сервиса";
        }
        if (monitoringPath.contains("metrics")) {
            return "СРЕДНИЙ УРОВЕНЬ - Раскрытие метрик производительности";
        }
        return "НИЗКИЙ УРОВЕНЬ - Базовая проверка здоровья";
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
        recommendations.add("Немедленно ограничьте доступ к обнаруженным конечным точкам");
        recommendations.add("Проведите полную инвентаризацию всех API конечных точек");
        recommendations.add("Удалите неиспользуемые и устаревшие конечные точки");
        recommendations.add("Ограничьте доступ к debug, monitoring и development конечным точкам в production среде");
        recommendations.add("Внедрите процесс управления версиями API с четким lifecycle");
        recommendations.add("Регулярно проводите автоматическое сканирование инвентаризации");
        recommendations.add("Убедитесь, что client-side код не содержит скрытых API конечных точек");
        recommendations.add("Синхронизируйте документацию с реально существующими конечными точками");
        vuln.setRecommendations(recommendations);

        return vuln;
    }
}
