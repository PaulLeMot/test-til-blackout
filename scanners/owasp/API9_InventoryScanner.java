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

    // Расширенный список подозрительных endpoints
    private static final List<String> SUSPICIOUS_ENDPOINTS = Arrays.asList(
        "admin", "debug", "test", "api/admin", "api/debug", "api/test",
        "management", "console", "api/console", "_admin", "_debug", "_test", 
        "private", "secret", "backup", "database", "config", "api/config",
        "logs", "system", "vendor", "tmp", "temp", "cache", "upload", "download",
        "export", "import", "backdoor", "shell", "cmd", "exec", "phpmyadmin", 
        "mysql", "phpinfo", "env", "/.git", "/.env", "DS_Store", "wp-admin", 
        "administrator", "actuator", "phpMyAdmin", "web-console", "jmx-console",
        "webmail", "cpanel", "plesk", "directadmin", "vhost", "virtualhost",
        "server-status", "server-info", "phpunit", "testpage", "check", "status",
        "info", "monitoring", "metrics", "health", "ping", "ready", "live"
    );

    private static final List<String> VERSION_PATHS = Arrays.asList(
        "v1", "v2", "v3", "v4", "v5", "v0", "beta", "alpha", "legacy", "old",
        "api/v1", "api/v2", "api/v3", "api/v4", "api/v5", "api/v0",
        "internal", "dev", "development", "staging", "uat"
    );

    private static final List<String> COMMON_BACKUP_FILES = Arrays.asList(
        "backup.zip", "backup.tar", "backup.tar.gz", "backup.sql", "dump.sql",
        "database.sql", "backup.rar", "backup.7z", "backup.bak", "backup.tgz",
        "www.zip", "site.tar.gz", "app.zip", "data.zip", "files.zip",
        ".git/config", ".env.backup", ".env.local", ".env.production",
        "config.php.bak", "settings.php.bak", "web.config.bak"
    );

    private int totalRequests = 0;
    private int foundEndpoints = 0;
    private Set<String> testedUrls = new HashSet<>();
    private List<String> requestLog = new ArrayList<>();
    private ScanConfig currentConfig;
    private ApiClient currentApiClient;

    public API9_InventoryScanner() {}

    @Override
    public String getName() {
        return "OWASP API9:2023 - Improper Inventory Management";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-9) Запуск расширенного сканирования управления инвентаризацией...");
        System.out.println("(API-9) Целевой URL: " + config.getTargetBaseUrl());

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = normalizeBaseUrl(config.getTargetBaseUrl().trim());
        OpenAPI openAPI = (OpenAPI) openApiObj;

        // Сохраняем конфиг и клиент для использования в других методах
        currentConfig = config;
        currentApiClient = apiClient;

        // Сброс счетчиков
        totalRequests = 0;
        foundEndpoints = 0;
        testedUrls.clear();
        requestLog.clear();

        try {
            // Получаем документированные endpoints из OpenAPI спецификации
            Set<String> documentedEndpoints = extractDocumentedEndpoints(openAPI);
            System.out.println("(API-9) Документировано endpoints: " + documentedEndpoints.size());

            // 1. Проверка подозрительных endpoints
            System.out.println("(API-9) 5.9.1: Сканирование подозрительных конечных точек (" + SUSPICIOUS_ENDPOINTS.size() + ")...");
            vulnerabilities.addAll(scanSuspiciousEndpoints(baseUrl, apiClient, documentedEndpoints));

            // 2. Проверка версионированных endpoints
            System.out.println("(API-9) 5.9.2: Сканирование версионированных конечных точек (" + VERSION_PATHS.size() + ")...");
            vulnerabilities.addAll(scanVersionedEndpoints(baseUrl, apiClient, documentedEndpoints));

            // 3. Проверка backup файлов
            System.out.println("(API-9) 5.9.3: Сканирование backup файлов (" + COMMON_BACKUP_FILES.size() + ")...");
            vulnerabilities.addAll(scanBackupFiles(baseUrl, apiClient));

            // 4. Проверка документации и debug endpoints
            System.out.println("(API-9) 5.9.4: Сканирование документации и debug endpoints...");
            vulnerabilities.addAll(scanDocumentationAndDebug(baseUrl, apiClient, documentedEndpoints));

            // 5. Проверка стандартных API paths
            System.out.println("(API-9) 5.9.5: Сканирование стандартных API paths...");
            vulnerabilities.addAll(scanCommonApiPaths(baseUrl, apiClient, documentedEndpoints));

            // 6. Проверка information leakage в 403 ошибках
            System.out.println("(API-9) 5.9.6: Анализ information leakage в 403 ошибках...");
            vulnerabilities.addAll(analyzeExisting403Responses(baseUrl, apiClient, documentedEndpoints));

        } catch (Exception e) {
            System.err.println("(API-9) Ошибка при сканировании инвентаризации: " + e.getMessage());
            e.printStackTrace();
        }

        // Выводим лог запросов
        System.out.println("(API-9) ЛОГ ЗАПРОСОВ (" + requestLog.size() + " запросов):");
        for (String logEntry : requestLog) {
            System.out.println("(API-9)   " + logEntry);
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
            System.out.println("(API-9) OpenAPI объект null, использую стандартные endpoints");
            // Добавляем стандартные endpoints из спецификации
            endpoints.addAll(Arrays.asList(
                "/auth/bank-token", "/accounts", "/accounts/{account_id}", 
                "/accounts/{account_id}/balances", "/accounts/{account_id}/transactions",
                "/account-consents/request", "/account-consents/{consent_id}",
                "/payment-consents/request", "/payment-consents/{consent_id}",
                "/payments", "/payments/{payment_id}", "/products", 
                "/products/{product_id}", "/product-agreements",
                "/product-agreements/{agreement_id}", "/product-agreement-consents/request",
                "/product-agreement-consents/{consent_id}", "/.well-known/jwks.json",
                "/", "/health"
            ));
            return endpoints;
        }

        try {
            Paths paths = openAPI.getPaths();
            if (paths != null) {
                for (String path : paths.keySet()) {
                    endpoints.add(path);
                    System.out.println("(API-9) Документированный endpoint: " + path);
                }
            } else {
                System.out.println("(API-9) Paths в OpenAPI null");
            }
        } catch (Exception e) {
            System.err.println("(API-9) Ошибка при извлечении documented endpoints: " + e.getMessage());
            // Добавляем стандартные endpoints в случае ошибки
            endpoints.addAll(Arrays.asList(
                "/auth/bank-token", "/accounts", "/accounts/{account_id}", 
                "/accounts/{account_id}/balances", "/accounts/{account_id}/transactions",
                "/account-consents/request", "/account-consents/{consent_id}",
                "/payment-consents/request", "/payment-consents/{consent_id}",
                "/payments", "/payments/{payment_id}", "/products", 
                "/products/{product_id}", "/product-agreements",
                "/product-agreements/{agreement_id}", "/product-agreement-consents/request",
                "/product-agreement-consents/{consent_id}", "/.well-known/jwks.json",
                "/", "/health"
            ));
        }

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

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "SUSPICIOUS");
            testedUrls.add(fullUrl);

            if (response != null && isInterestingResponse(response)) {
                discovered++;
                String evidence = buildEvidence("Подозрительная конечная точка", fullUrl, response);

                Vulnerability.Severity severity = assessEndpointSeverity(endpoint, response);
                
                Vulnerability vuln = createInventoryVulnerability(
                    "Обнаружена подозрительная конечная точка: " + endpoint,
                    buildVulnerabilityDescription(endpoint, response, severity),
                    "/" + endpoint,
                    response.getStatusCode(),
                    evidence,
                    severity
                );

                vulns.add(vuln);
                System.out.println("(API-9) НАЙДЕНА: " + endpoint + " (" + response.getStatusCode() + ") - " + severity);
            }
        }

        System.out.println("(API-9) Подозрительных конечных точек обнаружено: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private List<Vulnerability> scanVersionedEndpoints(String baseUrl, ApiClient apiClient, Set<String> documentedEndpoints) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        for (String versionPath : VERSION_PATHS) {
            String fullUrl = baseUrl + versionPath;
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "VERSIONED");
            testedUrls.add(fullUrl);

            if (response != null && isInterestingResponse(response)) {
                // Проверяем, действительно ли это устаревшая версия
                if (isDeprecatedVersion(versionPath, response)) {
                    discovered++;
                    String evidence = buildEvidence("Версионированная конечная точка", fullUrl, response);

                    Vulnerability vuln = createInventoryVulnerability(
                        "Обнаружена версионированная API конечная точка: " + versionPath,
                        "Устаревшая или тестовая версия API обнаружена: " + versionPath +
                        "\nСтатус: HTTP " + response.getStatusCode() +
                        "\nРиск: Устаревшие версии могут содержать известные уязвимости" +
                        "\nРекомендация: Отключить устаревшие версии или обеспечить их безопасность",
                        "/" + versionPath,
                        response.getStatusCode(),
                        evidence,
                        Vulnerability.Severity.MEDIUM
                    );

                    vulns.add(vuln);
                    System.out.println("(API-9) ВЕРСИЯ: " + versionPath + " (" + response.getStatusCode() + ")");
                }
            }

            // Также проверяем комбинации с common paths
            for (String commonPath : Arrays.asList("api", "rest", "v1/api", "v2/api")) {
                String combinedUrl = baseUrl + versionPath + "/" + commonPath;
                if (testedUrls.contains(combinedUrl)) {
                    continue;
                }

                HttpApiClient.ApiResponse combinedResponse = makeRequest(apiClient, combinedUrl, "VERSIONED_COMBINED");
                testedUrls.add(combinedUrl);

                if (combinedResponse != null && isInterestingResponse(combinedResponse)) {
                    discovered++;
                    String evidence = buildEvidence("Комбинированная версионированная конечная точка", combinedUrl, combinedResponse);

                    Vulnerability vuln = createInventoryVulnerability(
                        "Комбинированная версионированная конечная точка: " + versionPath + "/" + commonPath,
                        "Обнаружена комбинированная версионированная конечная точка" +
                        "\nСтатус: HTTP " + combinedResponse.getStatusCode() +
                        "\nРиск: Возможность доступа к устаревшим или тестовым версиям API",
                        "/" + versionPath + "/" + commonPath,
                        combinedResponse.getStatusCode(),
                        evidence,
                        Vulnerability.Severity.LOW
                    );

                    vulns.add(vuln);
                }
            }
        }

        System.out.println("(API-9) Версионированных конечных точек обнаружено: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private List<Vulnerability> scanBackupFiles(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        for (String backupFile : COMMON_BACKUP_FILES) {
            String fullUrl = baseUrl + backupFile;
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "BACKUP_FILE");
            testedUrls.add(fullUrl);

            if (response != null && response.getStatusCode() == 200) {
                discovered++;
                String evidence = buildEvidence("Backup файл", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                    "Обнаружен backup файл: " + backupFile,
                    "КРИТИЧЕСКИЙ УРОВЕНЬ: Обнаружен доступный backup файл!" +
                    "\nФайл: " + backupFile +
                    "\nСтатус: HTTP " + response.getStatusCode() +
                    "\nРиск: Раскрытие исходного кода, конфигурации или данных" +
                    "\nУгроза: Получение чувствительной информации о приложении",
                    "/" + backupFile,
                    response.getStatusCode(),
                    evidence,
                    Vulnerability.Severity.HIGH
                );

                vulns.add(vuln);
                System.out.println("(API-9) КРИТИЧЕСКИЙ: Backup файл: " + backupFile);
            }
        }

        System.out.println("(API-9) Backup файлов обнаружено: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private List<Vulnerability> scanDocumentationAndDebug(String baseUrl, ApiClient apiClient, Set<String> documentedEndpoints) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        String[] docPaths = {
            "docs", "swagger", "swagger-ui", "api-docs", "openapi", 
            "v3/api-docs", "swagger.json", "openapi.json", "api.json",
            "redoc", "rapidoc", "doc", "documentation", "api-documentation"
        };

        for (String docPath : docPaths) {
            String fullUrl = baseUrl + docPath;
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "DOCUMENTATION");
            testedUrls.add(fullUrl);

            if (response != null && isInterestingResponse(response)) {
                // Проверяем, действительно ли это документация
                if (isDocumentation(response, docPath)) {
                    discovered++;
                    String evidence = buildEvidence("Документация API", fullUrl, response);

                    Vulnerability vuln = createInventoryVulnerability(
                        "Публичная документация API: " + docPath,
                        "Обнаружена публичная документация API" +
                        "\nПуть: " + docPath +
                        "\nСтатус: HTTP " + response.getStatusCode() +
                        "\nРиск: Раскрытие структуры API и возможных attack vectors",
                        "/" + docPath,
                        response.getStatusCode(),
                        evidence,
                        Vulnerability.Severity.LOW
                    );

                    vulns.add(vuln);
                    System.out.println("(API-9) Документация: " + docPath + " (" + response.getStatusCode() + ")");
                }
            }
        }

        System.out.println("(API-9) Документационных endpoints обнаружено: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private List<Vulnerability> scanCommonApiPaths(String baseUrl, ApiClient apiClient, Set<String> documentedEndpoints) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        String[] commonApiPaths = {
            "api/v1/users", "api/v2/users", "api/v1/accounts", "api/v2/accounts",
            "api/v1/admin", "api/v2/admin", "api/v1/config", "api/v2/config",
            "v1/users", "v2/users", "v1/accounts", "v2/accounts",
            "rest/v1", "rest/v2", "graphql", "graphiql", "api/graphql"
        };

        for (String apiPath : commonApiPaths) {
            // Пропускаем если endpoint документирован
            if (isEndpointDocumented("/" + apiPath, documentedEndpoints)) {
                continue;
            }

            String fullUrl = baseUrl + apiPath;
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "COMMON_API");
            testedUrls.add(fullUrl);

            if (response != null && isInterestingResponse(response)) {
                discovered++;
                String evidence = buildEvidence("Стандартный API путь", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                    "Обнаружен стандартный API путь: " + apiPath,
                    "Обнаружен стандартный API путь, который может быть недокументированным" +
                    "\nПуть: " + apiPath +
                    "\nСтатус: HTTP " + response.getStatusCode() +
                    "\nРиск: Возможность доступа к недокументированным функциям API",
                    "/" + apiPath,
                    response.getStatusCode(),
                    evidence,
                    Vulnerability.Severity.LOW
                );

                vulns.add(vuln);
                System.out.println("(API-9) API путь: " + apiPath + " (" + response.getStatusCode() + ")");
            }
        }

        System.out.println("(API-9) Стандартных API путей обнаружено: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private List<Vulnerability> analyzeExisting403Responses(String baseUrl, ApiClient apiClient, Set<String> documentedEndpoints) {
        List<Vulnerability> vulns = new ArrayList<>();
        int discovered = 0;

        System.out.println("(API-9) Анализ information leakage в 403 ошибках...");
        
        // Ключевые endpoints для детального анализа 403
        String[] criticalEndpoints = {"admin", "debug", "config", "api/admin", "api/debug", "test", "management"};
        
        for (String endpoint : criticalEndpoints) {
            // Пропускаем если endpoint документирован
            if (isEndpointDocumented("/" + endpoint, documentedEndpoints)) {
                continue;
            }
            
            String fullUrl = baseUrl + endpoint;
            
            // Делаем запрос с детальным анализом
            HttpApiClient.ApiResponse response = makeDetailed403Analysis(apiClient, fullUrl, endpoint);
            
            if (response != null && response.getStatusCode() == 403) {
                boolean foundLeakage = false;
                
                // Анализируем заголовки
                if (containsInformationLeakageInHeaders(response)) {
                    String leakedInfo = extractLeakedHeaders(response);
                    System.out.println("(API-9) ОБНАРУЖЕН Information Leakage в заголовках: " + leakedInfo);
                    
                    String evidence = buildEvidence("Information leakage в заголовках 403", fullUrl, response);
                    Vulnerability vuln = createInventoryVulnerability(
                        "Information leakage в заголовках 403: " + endpoint,
                        "Обнаружена утечка информации в заголовках 403 ошибки\n" +
                        "Endpoint: " + endpoint + "\n" +
                        "Обнаруженная информация: " + leakedInfo + "\n" +
                        "Риск: Раскрытие информации о сервере и технологиях",
                        "/" + endpoint,
                        403,
                        evidence,
                        Vulnerability.Severity.LOW
                    );
                    vulns.add(vuln);
                    discovered++;
                    foundLeakage = true;
                }
                
                // Анализируем тело ответа
                if (containsInformationLeakage(response)) {
                    String leakedInfo = extractLeakedInformation(response);
                    System.out.println("(API-9) ОБНАРУЖЕН Information Leakage в теле: " + leakedInfo);
                    
                    String evidence = buildEvidence("Information leakage в теле 403", fullUrl, response);
                    Vulnerability vuln = createInventoryVulnerability(
                        "Information leakage в теле 403: " + endpoint,
                        "Обнаружена утечка информации в теле 403 ошибки\n" +
                        "Endpoint: " + endpoint + "\n" +
                        "Обнаруженная информация: " + leakedInfo + "\n" +
                        "Риск: Раскрытие внутренней структуры системы",
                        "/" + endpoint,
                        403,
                        evidence,
                        Vulnerability.Severity.MEDIUM
                    );
                    vulns.add(vuln);
                    discovered++;
                    foundLeakage = true;
                }
                
                if (!foundLeakage) {
                    System.out.println("(API-9) Information leakage не обнаружен для: " + endpoint);
                }
            }
        }
        
        System.out.println("(API-9) Information leakage уязвимостей обнаружено: " + discovered);
        foundEndpoints += discovered;
        return vulns;
    }

    private HttpApiClient.ApiResponse makeDetailed403Analysis(ApiClient apiClient, String url, String endpoint) {
        System.out.println("(API-9) Детальный анализ 403 для: " + endpoint);
        
        HttpApiClient.ApiResponse response = makeRequest(apiClient, url, "403_DETAILED_ANALYSIS");
        
        if (response != null && response.getStatusCode() == 403) {
            // Детальное логирование для анализа
            System.out.println("(API-9) === ДЕТАЛЬНЫЙ АНАЛИЗ 403 ===");
            System.out.println("(API-9) URL: " + url);
            
            // Логируем заголовки
            if (response.getHeaders() != null && !response.getHeaders().isEmpty()) {
                System.out.println("(API-9) ЗАГОЛОВКИ 403:");
                response.getHeaders().forEach((key, values) -> {
                    if (key != null && values != null) {
                        String headerValue = String.join(", ", values);
                        System.out.println("(API-9)   " + key + ": " + headerValue);
                    }
                });
            } else {
                System.out.println("(API-9) Заголовки 403: [ОТСУТСТВУЮТ]");
            }
            
            // Логируем тело ответа
            if (response.getBody() != null && !response.getBody().isEmpty()) {
                String bodyPreview = response.getBody().length() > 500 ? 
                    response.getBody().substring(0, 500) + "..." : response.getBody();
                System.out.println("(API-9) ТЕЛО 403 (первые 500 символов):");
                System.out.println("(API-9) " + bodyPreview);
                System.out.println("(API-9) Длина тела: " + response.getBody().length() + " символов");
            } else {
                System.out.println("(API-9) Тело 403: [ПУСТОЕ]");
            }
            System.out.println("(API-9) === КОНЕЦ АНАЛИЗА 403 ===");
        }
        
        return response;
    }

    private boolean containsInformationLeakage(HttpApiClient.ApiResponse response) {
        if (response.getBody() == null || response.getBody().isEmpty()) {
            return false;
        }
        
        String body = response.getBody().toLowerCase();
        
        // Проверяем различные индикаторы information leakage
        return body.contains("server:") || 
               body.contains("framework:") ||
               body.contains("version:") ||
               body.contains("apache") ||
               body.contains("nginx") ||
               body.contains("tomcat") ||
               body.contains("iis") ||
               body.contains("php") ||
               body.contains("java") ||
               body.contains("python") ||
               body.contains("django") ||
               body.contains("flask") ||
               body.contains("spring") ||
               body.contains("internal") ||
               body.contains("stack trace") ||
               body.contains("exception") ||
               body.contains("error in") ||
               body.length() > 200; // Слишком подробные ошибки
    }

    private boolean containsInformationLeakageInHeaders(HttpApiClient.ApiResponse response) {
        if (response.getHeaders() == null) {
            return false;
        }
        
        Map<String, List<String>> headers = response.getHeaders();
        
        // Проверяем информативные заголовки
        boolean hasLeakage = headers.containsKey("server") ||
               headers.containsKey("x-powered-by") ||
               headers.containsKey("x-aspnet-version") ||
               headers.containsKey("x-aspnetmvc-version") ||
               headers.containsKey("x-runtime");
        
        // Дополнительно проверяем значения заголовков
        if (headers.containsKey("server")) {
            List<String> serverValues = headers.get("server");
            if (serverValues != null && !serverValues.isEmpty()) {
                String serverHeader = serverValues.get(0).toLowerCase();
                // Если в server header есть конкретная информация (не просто "nginx" или "apache")
                hasLeakage = hasLeakage || serverHeader.contains("/") || serverHeader.contains("version");
            }
        }
        
        return hasLeakage;
    }

    private String extractLeakedInformation(HttpApiClient.ApiResponse response) {
        StringBuilder info = new StringBuilder();
        String body = response.getBody().toLowerCase();
        
        if (body.contains("server:")) info.append("server type, ");
        if (body.contains("framework:")) info.append("framework, ");
        if (body.contains("version:")) info.append("version, ");
        if (body.contains("apache")) info.append("Apache, ");
        if (body.contains("nginx")) info.append("Nginx, ");
        if (body.contains("tomcat")) info.append("Tomcat, ");
        if (body.contains("php")) info.append("PHP, ");
        if (body.contains("java")) info.append("Java, ");
        if (body.contains("python")) info.append("Python, ");
        if (body.contains("stack trace")) info.append("stack trace, ");
        if (body.contains("exception")) info.append("exception details, ");
        
        return info.length() > 0 ? info.substring(0, info.length() - 2) : "не определено";
    }

    private String extractLeakedHeaders(HttpApiClient.ApiResponse response) {
        StringBuilder info = new StringBuilder();
        Map<String, List<String>> headers = response.getHeaders();
        
        if (headers.containsKey("server")) {
            List<String> serverValues = headers.get("server");
            if (serverValues != null && !serverValues.isEmpty()) {
                info.append("Server: ").append(serverValues.get(0)).append(", ");
            }
        }
        if (headers.containsKey("x-powered-by")) {
            List<String> poweredByValues = headers.get("x-powered-by");
            if (poweredByValues != null && !poweredByValues.isEmpty()) {
                info.append("X-Powered-By: ").append(poweredByValues.get(0)).append(", ");
            }
        }
        if (headers.containsKey("x-aspnet-version")) {
            List<String> aspnetValues = headers.get("x-aspnet-version");
            if (aspnetValues != null && !aspnetValues.isEmpty()) {
                info.append("X-AspNet-Version: ").append(aspnetValues.get(0)).append(", ");
            }
        }
        if (headers.containsKey("x-aspnetmvc-version")) {
            List<String> mvcValues = headers.get("x-aspnetmvc-version");
            if (mvcValues != null && !mvcValues.isEmpty()) {
                info.append("X-AspNetMvc-Version: ").append(mvcValues.get(0)).append(", ");
            }
        }
        
        return info.length() > 0 ? info.substring(0, info.length() - 2) : "не определено";
    }

    // Вспомогательные методы
    private boolean isEndpointDocumented(String endpoint, Set<String> documentedEndpoints) {
        for (String documented : documentedEndpoints) {
            if (documented.equals(endpoint) || 
                documented.replace("{", "").replace("}", "").equals(endpoint.replace("{", "").replace("}", ""))) {
                return true;
            }
        }
        return false;
    }

    private boolean isInterestingResponse(HttpApiClient.ApiResponse response) {
        int status = response.getStatusCode();
        // Считаем интересными только успешные ответы и некоторые редиректы
        return status == 200 || status == 201 || status == 301 || status == 302;
    }

    private boolean isDeprecatedVersion(String versionPath, HttpApiClient.ApiResponse response) {
        String body = response.getBody().toLowerCase();
        // Проверяем индикаторы устаревшей версии
        return versionPath.contains("v0") || versionPath.contains("beta") || 
               versionPath.contains("alpha") || versionPath.contains("legacy") ||
               versionPath.contains("old") || body.contains("deprecated") ||
               body.contains("legacy") || body.contains("outdated");
    }

    private boolean isDocumentation(HttpApiClient.ApiResponse response, String path) {
        String body = response.getBody().toLowerCase();
        return body.contains("swagger") || body.contains("openapi") || 
               body.contains("api documentation") || body.contains("redoc") ||
               path.contains("docs") || path.contains("swagger") ||
               body.contains("</swagger-ui>") || body.contains("rapidoc");
    }

    private Vulnerability.Severity assessEndpointSeverity(String endpoint, HttpApiClient.ApiResponse response) {
        String body = response.getBody().toLowerCase();
        
        if (endpoint.contains("admin") || endpoint.contains("debug") || 
            endpoint.contains("secret") || endpoint.contains("backdoor")) {
            return Vulnerability.Severity.HIGH;
        }
        
        if (endpoint.contains("config") || endpoint.contains("env") || 
            endpoint.contains("database") || endpoint.contains("backup")) {
            return Vulnerability.Severity.HIGH;
        }
        
        if (body.contains("password") || body.contains("secret") || 
            body.contains("key") || body.contains("token")) {
            return Vulnerability.Severity.HIGH;
        }
        
        if (endpoint.contains("log") || endpoint.contains("system") || 
            endpoint.contains("management")) {
            return Vulnerability.Severity.MEDIUM;
        }
        
        return Vulnerability.Severity.LOW;
    }

    private String buildVulnerabilityDescription(String endpoint, HttpApiClient.ApiResponse response, Vulnerability.Severity severity) {
        StringBuilder desc = new StringBuilder();
        desc.append("УРОВЕНЬ РИСКА: ").append(severity).append("\n");
        desc.append("Обнаружена потенциально опасная конечная точка: ").append(endpoint).append("\n");
        desc.append("Статус: HTTP ").append(response.getStatusCode()).append("\n");
        desc.append("Тип: ").append(classifyEndpoint(endpoint)).append("\n");
        
        String body = response.getBody().toLowerCase();
        if (body.contains("password") || body.contains("secret")) {
            desc.append("⚠️ Обнаружены чувствительные данные (пароли/секреты)\n");
        }
        if (body.contains("admin") || body.contains("debug")) {
            desc.append("⚠️ Обнаружены административные или debug функции\n");
        }
        
        desc.append("\nКонечная точка соответствует известным шаблонам уязвимых путей. ");
        desc.append("Рекомендуется проверить необходимость существования данной конечной точки в production среде.");
        
        return desc.toString();
    }

    private String classifyEndpoint(String endpoint) {
        if (endpoint.contains("admin")) return "Административный интерфейс";
        if (endpoint.contains("debug")) return "Интерфейс отладки";
        if (endpoint.contains("log")) return "Доступ к логам";
        if (endpoint.contains("config")) return "Доступ к конфигурации";
        if (endpoint.contains("backup")) return "Доступ к резервным копиям";
        if (endpoint.contains("database")) return "Интерфейс базы данных";
        if (endpoint.contains("env")) return "Переменные окружения";
        if (endpoint.contains("docs")) return "Документация";
        if (endpoint.contains("version")) return "Версионированный API";
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
            Thread.sleep(200);
            
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("User-Agent", "GOSTGuardian-Scanner/1.0");

            Object response = apiClient.executeRequest("GET", url, null, headers);
            HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
            
            // Логируем запрос
            String logEntry = type + " " + url + " -> " + (apiResponse != null ? apiResponse.getStatusCode() : "ERROR");
            requestLog.add(logEntry);
            
            return apiResponse;

        } catch (Exception e) {
            String logEntry = type + " " + url + " -> EXCEPTION: " + e.getMessage();
            requestLog.add(logEntry);
            return null;
        }
    }

    private String buildEvidence(String title, String url, HttpApiClient.ApiResponse response) {
        StringBuilder evidence = new StringBuilder();
        evidence.append(title).append("\n");
        evidence.append("URL: ").append(url).append("\n");
        evidence.append("HTTP Статус: ").append(response.getStatusCode()).append("\n");

        // Добавляем заголовки если они есть
        if (response.getHeaders() != null && !response.getHeaders().isEmpty()) {
            evidence.append("\nЗАГОЛОВКИ:\n");
            response.getHeaders().forEach((key, values) -> {
                if (key != null && values != null) {
                    evidence.append("  ").append(key).append(": ").append(String.join(", ", values)).append("\n");
                }
            });
        }

        if (response.getBody() != null && !response.getBody().isEmpty()) {
            evidence.append("\nТЕЛО ОТВЕТА (первые 300 символов):\n");
            String bodyPreview = response.getBody().length() > 300 ?
                    response.getBody().substring(0, 300) + "..." : response.getBody();
            evidence.append(bodyPreview);
            
            // Анализ содержимого
            evidence.append("\n\nАНАЛИЗ СОДЕРЖИМОГО:\n");
            String body = response.getBody().toLowerCase();
            if (body.contains("password")) evidence.append("- Содержит 'password'\n");
            if (body.contains("secret")) evidence.append("- Содержит 'secret'\n");
            if (body.contains("admin")) evidence.append("- Содержит 'admin'\n");
            if (body.contains("debug")) evidence.append("- Содержит 'debug'\n");
            if (body.contains("token")) evidence.append("- Содержит 'token'\n");
            if (body.contains("key")) evidence.append("- Содержит 'key'\n");
        } else {
            evidence.append("\nТЕЛО ОТВЕТА: [Пусто или недоступно]");
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
        recommendations.add("Проведите полную инвентаризацию всех API конечных точек");
        recommendations.add("Удалите неиспользуемые и устаревшие конечные точки");
        recommendations.add("Ограничьте доступ к debug, monitoring и административным endpoints");
        recommendations.add("Внедрите процесс управления версиями API");
        recommendations.add("Регулярно обновляйте документацию API");
        recommendations.add("Используйте инструменты автоматического сканирования инвентаризации");
        vuln.setRecommendations(recommendations);

        return vuln;
    }
}
