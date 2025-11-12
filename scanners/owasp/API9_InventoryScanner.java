package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.servers.Server;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API9_InventoryScanner implements SecurityScanner {

    private static final Set<String> PRODUCTION_HOST_INDICATORS = Set.of(
            "api", "production", "prod", "live", "banking", "financial"
    );

    private static final Set<String> NON_PRODUCTION_HOST_INDICATORS = Set.of(
            "test", "beta", "staging", "dev", "development", "sandbox",
            "hackathon", "demo", "uat", "qa", "preprod"
    );

    private static final List<String> API_VERSION_PATHS = Arrays.asList(
            "v1", "v2", "v3", "v4", "v5", "v0", "beta", "alpha",
            "legacy", "old", "deprecated", "test", "stable"
    );

    // Расширенный список подозрительных эндпоинтов
    private static final List<String> SUSPICIOUS_ENDPOINTS = Arrays.asList(
            "admin", "debug", "test", "api/admin", "api/debug", "api/test",
            "management", "console", "api/console", "_admin", "_debug", "_test",
            "private", "secret", "backup", "database", "config", "api/config",
            "logs", "system", "vendor", "tmp", "temp", "cache", "upload", "download",
            "export", "import", "backdoor", "shell", "cmd", "exec", "phpmyadmin",
            "mysql", "phpinfo", "env", "/.git", "/.env", "DS_Store", "wp-admin",
            "administrator", "cpanel", "webmin", "jenkins", "gitlab", "grafana",
            "kibana", "elasticsearch", "swagger-ui", "swagger", "redoc", "docs",
            "api-docs", "graphql", "graphiql", "voyager", "altair", "playground"
    );

    private static final List<String> MONITORING_PATHS = Arrays.asList(
            "actuator", "actuator/health", "actuator/metrics", "actuator/info",
            "prometheus", "grafana", "monitoring", "heapdump", "threaddump",
            "configprops", "mappings", "flyway", "liquibase", "beans", "conditions",
            "loggers", "scheduledtasks", "sessions", "shutdown", "trace",
            "status", "info", "metrics", "health", "ping", "ready", "live"
    );

    private int totalRequests = 0;
    private int foundEndpoints = 0;
    private Set<String> testedUrls = new HashSet<>();
    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    public API9_InventoryScanner() {}

    @Override
    public String getName() {
        return "OWASP API9:2023 - Improper Inventory Management";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-9) Запуск расширенного сканирования управления инвентаризацией...");
        System.out.println("(API-9) Целевой URL: " + config.getTargetBaseUrl());

        vulnerabilities.clear();
        String baseUrl = normalizeBaseUrl(config.getTargetBaseUrl().trim());
        OpenAPI openAPI = (OpenAPI) openApiObj;

        // Сброс счетчиков
        totalRequests = 0;
        foundEndpoints = 0;
        testedUrls.clear();

        try {
            // Анализ OpenAPI спецификации на проблемы инвентаризации
            analyzeOpenApiSpecification(openAPI, baseUrl);

            // 1. Проверка подозрительных endpoints
            System.out.println("(API-9) 5.9.1: Сканирование подозрительных конечных точек...");
            scanSuspiciousEndpoints(baseUrl, apiClient);

            // 2. Проверка мониторинговых endpoints
            System.out.println("(API-9) 5.9.4: Сканирование мониторинговых конечных точек...");
            scanMonitoringEndpoints(baseUrl, apiClient);

            // 3. Поиск устаревших версий API
            System.out.println("(API-9) 5.9.6: Поиск устаревших версий API...");
            scanApiVersions(baseUrl, apiClient);

            // 4. Проверка среды выполнения (production vs non-production)
            System.out.println("(API-9) Проверка среды выполнения...");
            analyzeEnvironmentIndicators(baseUrl, openAPI);

            // 5. Проверка документационных слепых зон
            System.out.println("(API-9) Проверка документационных слепых зон...");
            analyzeDocumentationBlindSpots(openAPI, baseUrl);

        } catch (Exception e) {
            System.err.println("(API-9) Ошибка при сканировании инвентаризации: " + e.getMessage());
            if (isDebugMode()) {
                e.printStackTrace();
            }
        }

        System.out.println("(API-9) СКАНИРОВАНИЕ ИНВЕНТАРИЗАЦИИ ЗАВЕРШЕНО:");
        System.out.println("(API-9) Всего выполнено запросов: " + totalRequests);
        System.out.println("(API-9) Обнаружено проблемных конечных точек: " + foundEndpoints);
        System.out.println("(API-9) Найдено уязвимостей: " + vulnerabilities.size());

        return vulnerabilities;
    }

    private void analyzeOpenApiSpecification(OpenAPI openAPI, String baseUrl) {
        // Проверка наличия версии в путях
        checkApiVersioning(openAPI, baseUrl);

        // Проверка серверов и окружения
        checkServersAndEnvironment(openAPI, baseUrl);

        // Проверка документации на наличие тестовых ссылок
        checkDocumentationForTestReferences(openAPI);
    }

    private void checkApiVersioning(OpenAPI openAPI, String baseUrl) {
        Paths paths = openAPI.getPaths();
        boolean hasVersionInPaths = false;

        if (paths != null) {
            for (String path : paths.keySet()) {
                if (path.matches("/v\\d+/.*") || path.matches("/api/v\\d+/.*")) {
                    hasVersionInPaths = true;
                    break;
                }
            }
        }

        if (!hasVersionInPaths) {
            String evidence = "API не использует версионирование в путях URL.\n" +
                    "Текущая версия в info.version: " +
                    (openAPI.getInfo() != null ? openAPI.getInfo().getVersion() : "не указана") + "\n" +
                    "Все пути: " + (paths != null ? paths.keySet() : "не найдены");

            Vulnerability vuln = createInventoryVulnerability(
                    "Отсутствие версионирования API в путях",
                    "КРИТИЧЕСКАЯ ПРОБЛЕМА ИНВЕНТАРИЗАЦИИ: API не использует явное версионирование в URL путях.\n\n" +
                            "Риски:\n" +
                            "• Невозможно определить активные/устаревшие версии\n" +
                            "• Сложность управления жизненным циклом API\n" +
                            "• Потенциальное наличие скрытых устаревших версий\n" +
                            "• Нарушение best practices API design\n\n" +
                            "Рекомендации:\n" +
                            "• Внедрить версионирование в путях (например, /v1/accounts)\n" +
                            "• Вести инвентаризацию всех активных версий\n" +
                            "• Разработать политику deprecated версий",
                    baseUrl,
                    200,
                    evidence,
                    Vulnerability.Severity.HIGH
            );
            vulnerabilities.add(vuln);
            foundEndpoints++;
        }
    }

    private void checkServersAndEnvironment(OpenAPI openAPI, String baseUrl) {
        List<Server> servers = openAPI.getServers();
        if (servers != null) {
            for (Server server : servers) {
                String serverUrl = server.getUrl();
                if (serverUrl != null) {
                    // Проверка на не-production индикаторы
                    for (String indicator : NON_PRODUCTION_HOST_INDICATORS) {
                        if (serverUrl.toLowerCase().contains(indicator)) {
                            String evidence = "Обнаружен сервер с не-production индикатором: " + serverUrl +
                                    "\nОписание: " + server.getDescription();

                            Vulnerability vuln = createInventoryVulnerability(
                                    "Потенциальная не-production среда в спецификации",
                                    "ПРОБЛЕМА ИНВЕНТАРИЗАЦИИ: В спецификации указаны серверы с не-production индикаторами.\n\n" +
                                            "Обнаруженный индикатор: " + indicator + "\n" +
                                            "URL сервера: " + serverUrl + "\n\n" +
                                            "Риски:\n" +
                                            "• Возможная путаница между средами выполнения\n" +
                                            "• Использование тестовых данных в production\n" +
                                            "• Неправильная маршрутизация запросов\n\n" +
                                            "Рекомендации:\n" +
                                            "• Четко разделять спецификации для разных сред\n" +
                                            "• Удалить тестовые серверы из production документации\n" +
                                            "• Использовать разные домены для разных сред",
                                    serverUrl,
                                    200,
                                    evidence,
                                    Vulnerability.Severity.MEDIUM
                            );
                            vulnerabilities.add(vuln);
                            foundEndpoints++;
                        }
                    }
                }
            }
        }
    }

    private void checkDocumentationForTestReferences(OpenAPI openAPI) {
        // Проверка описаний на наличие тестовых ссылок
        if (openAPI.getInfo() != null && openAPI.getInfo().getDescription() != null) {
            String description = openAPI.getInfo().getDescription().toLowerCase();
            if (description.contains("хакатон") || description.contains("hackathon") ||
                    description.contains("тест") || description.contains("sandbox")) {

                String evidence = "Документация содержит ссылки на тестовую среду\n" +
                        "Фрагмент описания: " +
                        (openAPI.getInfo().getDescription().length() > 200 ?
                                openAPI.getInfo().getDescription().substring(0, 200) + "..." :
                                openAPI.getInfo().getDescription());

                Vulnerability vuln = createInventoryVulnerability(
                        "Тестовые ссылки в production документации",
                        "ПРОБЛЕМА ИНВЕНТАРИЗАЦИИ: Документация API содержит ссылки на тестовые среды или события.\n\n" +
                                "Риски:\n" +
                                "• Путаница между production и test средами\n" +
                                "• Возможное использование тестовых credentials\n" +
                                "• Непрофессиональное представление API\n\n" +
                                "Рекомендации:\n" +
                                "• Удалить все тестовые ссылки из production документации\n" +
                                "• Создать отдельную документацию для тестовых сред\n" +
                                "• Четко маркировать среды выполнения",
                        "API Documentation",
                        200,
                        evidence,
                        Vulnerability.Severity.LOW
                );
                vulnerabilities.add(vuln);
                foundEndpoints++;
            }
        }
    }

    private void scanSuspiciousEndpoints(String baseUrl, ApiClient apiClient) {
        int discovered = 0;

        for (String endpoint : SUSPICIOUS_ENDPOINTS) {
            String fullUrl = baseUrl + (endpoint.startsWith("/") ? endpoint.substring(1) : endpoint);
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "SUSPICIOUS_ENDPOINT");
            testedUrls.add(fullUrl);

            if (response != null && isSuccessStatus(response.getStatusCode())) {
                discovered++;
                String evidence = buildEvidence("Подозрительная конечная точка", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Обнаружена подозрительная конечная точка: " + endpoint,
                        "ВЫСОКИЙ УРОВЕНЬ: Обнаружена потенциально опасная конечная точка!\n\n" +
                                "Тип: " + classifySuspiciousEndpoint(endpoint) + "\n" +
                                "Статус: HTTP " + response.getStatusCode() + "\n" +
                                "Риск: " + assessSuspiciousEndpointRisk(endpoint, response) + "\n\n" +
                                "Рекомендации:\n" +
                                "• Проверить необходимость endpoint в production\n" +
                                "• Ограничить доступ к административным интерфейсам\n" +
                                "• Удалить неиспользуемые debug endpoints",
                        "/" + endpoint,
                        response.getStatusCode(),
                        evidence,
                        Vulnerability.Severity.HIGH
                );

                vulnerabilities.add(vuln);
                System.out.println("(API-9) Подозрительная конечная точка: " + endpoint + " (" + response.getStatusCode() + ")");
            }
        }

        System.out.println("(API-9) Подозрительных конечных точек обнаружено: " + discovered);
        foundEndpoints += discovered;
    }

    private void scanMonitoringEndpoints(String baseUrl, ApiClient apiClient) {
        int discovered = 0;

        for (String monitoringPath : MONITORING_PATHS) {
            String fullUrl = baseUrl + (monitoringPath.startsWith("/") ? monitoringPath.substring(1) : monitoringPath);
            if (testedUrls.contains(fullUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "MONITORING");
            testedUrls.add(fullUrl);

            if (response != null && isSuccessStatus(response.getStatusCode())) {
                discovered++;
                String evidence = buildEvidence("Мониторинговая конечная точка", fullUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Публичная мониторинговая конечная точка: " + monitoringPath,
                        "СРЕДНИЙ УРОВЕНЬ: Обнаружена публичная мониторинговая конечная точка!\n\n" +
                                "Статус: HTTP " + response.getStatusCode() + "\n" +
                                "Риск: Раскрытие системной информации и метрик\n" +
                                "Обнаруженные данные: " + identifySensitiveData(response) + "\n\n" +
                                "Рекомендации:\n" +
                                "• Ограничить доступ к мониторинговым endpoint'ам\n" +
                                "• Использовать аутентификацию для sensitive метрик\n" +
                                "• Вынести мониторинг на отдельные домены",
                        "/" + monitoringPath,
                        response.getStatusCode(),
                        evidence,
                        Vulnerability.Severity.MEDIUM
                );

                vulnerabilities.add(vuln);
                System.out.println("(API-9) Мониторинговая конечная точка: " + monitoringPath + " (" + response.getStatusCode() + ")");
            }
        }

        System.out.println("(API-9) Мониторинговых конечных точек обнаружено: " + discovered);
        foundEndpoints += discovered;
    }

    private void scanApiVersions(String baseUrl, ApiClient apiClient) {
        int discovered = 0;

        for (String version : API_VERSION_PATHS) {
            String versionUrl = baseUrl + version;
            if (testedUrls.contains(versionUrl)) {
                continue;
            }

            HttpApiClient.ApiResponse response = makeRequest(apiClient, versionUrl, "API_VERSION");
            testedUrls.add(versionUrl);

            if (response != null && isSuccessStatus(response.getStatusCode())) {
                discovered++;
                String evidence = buildEvidence("Версия API", versionUrl, response);

                Vulnerability vuln = createInventoryVulnerability(
                        "Обнаружена версия API: " + version,
                        "СРЕДНИЙ УРОВЕНЬ: Обнаружена дополнительная версия API!\n\n" +
                                "Версия: " + version + "\n" +
                                "Статус: HTTP " + response.getStatusCode() + "\n" +
                                "Риск: Расширение attack surface, потенциально устаревшие версии\n\n" +
                                "Рекомендации:\n" +
                                "• Вести инвентаризацию всех активных версий\n" +
                                "• Разработать политику deprecated\n" +
                                "• Обеспечить безопасность всех версий",
                        "/" + version,
                        response.getStatusCode(),
                        evidence,
                        Vulnerability.Severity.MEDIUM
                );

                vulnerabilities.add(vuln);
                System.out.println("(API-9) Версия API: " + version + " (" + response.getStatusCode() + ")");
            }
        }

        System.out.println("(API-9) Дополнительных версий API обнаружено: " + discovered);
        foundEndpoints += discovered;
    }

    private void analyzeEnvironmentIndicators(String baseUrl, OpenAPI openAPI) {
        // Анализ базового URL на признаки среды выполнения
        String lowerBaseUrl = baseUrl.toLowerCase();

        boolean hasProductionIndicators = PRODUCTION_HOST_INDICATORS.stream()
                .anyMatch(lowerBaseUrl::contains);

        boolean hasNonProductionIndicators = NON_PRODUCTION_HOST_INDICATORS.stream()
                .anyMatch(lowerBaseUrl::contains);

        if (hasNonProductionIndicators && !hasProductionIndicators) {
            String evidence = "Базовый URL содержит не-production индикаторы: " + baseUrl +
                    "\nОбнаруженные индикаторы: " +
                    String.join(", ", findMatchingIndicators(lowerBaseUrl, NON_PRODUCTION_HOST_INDICATORS));

            Vulnerability vuln = createInventoryVulnerability(
                    "Потенциальная не-production среда выполнения",
                    "ВЫСОКИЙ УРОВЕНЬ: Базовый URL указывает на не-production среду!\n\n" +
                            "Риски:\n" +
                            "• Использование тестовых данных в production\n" +
                            "• Отсутствие production-grade security controls\n" +
                            "• Потенциальное раскрытие тестовой информации\n\n" +
                            "Рекомендации:\n" +
                            "• Подтвердить среду выполнения\n" +
                            "• Использовать production домены для production API\n" +
                            "• Разделить инфраструктуру сред",
                    baseUrl,
                    200,
                    evidence,
                    Vulnerability.Severity.HIGH
            );
            vulnerabilities.add(vuln);
            foundEndpoints++;
        }
    }

    private void analyzeDocumentationBlindSpots(OpenAPI openAPI, String baseUrl) {
        // Проверка на "documentation blindspots"
        List<String> blindSpots = new ArrayList<>();

        if (openAPI.getInfo() == null) {
            blindSpots.add("Отсутствует информация об API (info)");
        } else {
            if (openAPI.getInfo().getDescription() == null || openAPI.getInfo().getDescription().trim().isEmpty()) {
                blindSpots.add("Отсутствует описание API");
            }
            if (openAPI.getInfo().getVersion() == null || openAPI.getInfo().getVersion().trim().isEmpty()) {
                blindSpots.add("Отсутствует версия API");
            }
        }

        if (openAPI.getPaths() == null || openAPI.getPaths().isEmpty()) {
            blindSpots.add("Отсутствуют документированные endpoints");
        }

        if (!blindSpots.isEmpty()) {
            String evidence = "Обнаружены documentation blindspots:\n" + String.join("\n", blindSpots);

            Vulnerability vuln = createInventoryVulnerability(
                    "Documentation Blind Spots",
                    "СРЕДНИЙ УРОВЕНЬ: Обнаружены пробелы в документации API!\n\n" +
                            "Проблемы:\n" + String.join("\n• ", blindSpots) + "\n\n" +
                            "Риски OWASP API9:\n" +
                            "• Сложность управления безопасностью API\n" +
                            "• Невозможность полной инвентаризации\n" +
                            "• Пропущенные уязвимости при ревью\n\n" +
                            "Рекомендации:\n" +
                            "• Внедрить полную документацию OpenAPI\n" +
                            "• Автоматизировать генерацию документации\n" +
                            "• Интегрировать документацию в CI/CD",
                    baseUrl,
                    200,
                    evidence,
                    Vulnerability.Severity.MEDIUM
            );
            vulnerabilities.add(vuln);
            foundEndpoints++;
        }
    }

    // Вспомогательные методы остаются аналогичными предыдущей версии
    private boolean isSuccessStatus(int statusCode) {
        return statusCode >= 200 && statusCode < 400 && statusCode != 204;
    }

    private List<String> findMatchingIndicators(String text, Set<String> indicators) {
        List<String> matches = new ArrayList<>();
        for (String indicator : indicators) {
            if (text.contains(indicator)) {
                matches.add(indicator);
            }
        }
        return matches;
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

    private String assessSuspiciousEndpointRisk(String endpoint, HttpApiClient.ApiResponse response) {
        if (endpoint.contains("admin") || endpoint.contains("debug") || endpoint.contains("secret")) {
            return "ВЫСОКИЙ - Административный/Debug доступ";
        }
        if (endpoint.contains("config") || endpoint.contains("log") || endpoint.contains("system")) {
            return "СРЕДНИЙ - Доступ к системной информации";
        }
        return "НИЗКИЙ - Общая конечная точка";
    }

    private String identifySensitiveData(HttpApiClient.ApiResponse response) {
        String body = response.getBody() != null ? response.getBody().toLowerCase() : "";
        List<String> foundData = new ArrayList<>();

        if (body.contains("password")) foundData.add("пароли");
        if (body.contains("secret")) foundData.add("секреты");
        if (body.contains("key")) foundData.add("ключи");
        if (body.contains("database")) foundData.add("информация о БД");
        if (body.contains("environment")) foundData.add("переменные окружения");
        if (body.contains("configuration")) foundData.add("конфигурация");

        return foundData.isEmpty() ? "не определено" : String.join(", ", foundData);
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
            Thread.sleep(100);

            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("User-Agent", "GOSTGuardian-Scanner/1.0");

            Object response = apiClient.executeRequest("GET", url, null, headers);
            return (HttpApiClient.ApiResponse) response;

        } catch (Exception e) {
            System.err.println("(API-9) Ошибка при запросе " + url + ": " + e.getMessage());
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
        recommendations.add("Проведите полную инвентаризацию всех API конечных точек");
        recommendations.add("Внедрите версионирование API в путях URL");
        recommendations.add("Разработайте политику управления жизненным циклом API");
        recommendations.add("Ограничьте доступ к административным и debug endpoint'ам");
        recommendations.add("Ведите актуальную документацию для всех версий API");
        recommendations.add("Разделяйте production и non-production среды");
        vuln.setRecommendations(recommendations);

        return vuln;
    }

    private static boolean isDebugMode() {
        return System.getProperty("debug") != null ||
                Arrays.asList(System.getenv().getOrDefault("JAVA_OPTS", "").split(" ")).contains("-Ddebug");
    }
}