package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import core.TestedEndpoint;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;

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

        // Проверка базового URL
        if (config.getTargetBaseUrl() == null || config.getTargetBaseUrl().trim().isEmpty()) {
            System.err.println("(API-9) ОШИБКА: targetBaseUrl не установлен в конфигурации");
            vulnerabilities.add(createConfigErrorVulnerability("Отсутствует targetBaseUrl в конфигурации"));
            return vulnerabilities;
        }

        String baseUrl = normalizeBaseUrl(config.getTargetBaseUrl().trim());

        // Проверка схемы URL
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            System.err.println("(API-9) ОШИБКА: targetBaseUrl должен начинаться с http:// или https://");
            vulnerabilities.add(createConfigErrorVulnerability("Некорректный targetBaseUrl: отсутствует схема (http/https)"));
            return vulnerabilities;
        }

        System.out.println("(API-9) Целевой URL: " + baseUrl);

        vulnerabilities.clear();

        // Проверка OpenAPI объекта
        if (openApiObj == null) {
            System.err.println("(API-9) ПРЕДУПРЕЖДЕНИЕ: OpenAPI объект не предоставлен, выполняется только динамический анализ");
            performDynamicAnalysisWithoutOpenAPI(baseUrl, apiClient, config);
            return vulnerabilities;
        }

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-9) ОШИБКА: Передан неправильный объект OpenAPI");
            vulnerabilities.add(createConfigErrorVulnerability("Некорректный объект OpenAPI"));
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;

        // Сброс счетчиков
        totalRequests = 0;
        foundEndpoints = 0;
        testedUrls.clear();

        try {
            // Статический анализ OpenAPI спецификации
            if (config.isStaticAnalysisEnabled()) {
                System.out.println("(API-9) Выполнение статического анализа...");
                performStaticAnalysis(openAPI, baseUrl);
            }

            // Динамический анализ
            if (config.isDynamicAnalysisEnabled()) {
                System.out.println("(API-9) Выполнение динамического анализа...");
                performDynamicAnalysis(openAPI, baseUrl, apiClient);
            }

        } catch (Exception e) {
            System.err.println("(API-9) Ошибка при сканировании инвентаризации: " + e.getMessage());
            vulnerabilities.add(createErrorVulnerability("Ошибка сканирования", e.getMessage()));
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

    @Override
    public List<Vulnerability> scanEndpoints(List<TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-9) Запуск сканирования инвентаризации на основе протестированных эндпоинтов...");

        vulnerabilities.clear();

        // Проверка базового URL
        if (config.getTargetBaseUrl() == null || config.getTargetBaseUrl().trim().isEmpty()) {
            System.err.println("(API-9) ОШИБКА: targetBaseUrl не установлен в конфигурации");
            vulnerabilities.add(createConfigErrorVulnerability("Отсутствует targetBaseUrl в конфигурации"));
            return vulnerabilities;
        }

        String baseUrl = normalizeBaseUrl(config.getTargetBaseUrl().trim());

        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            System.err.println("(API-9) ОШИБКА: targetBaseUrl должен начинаться с http:// или https://");
            vulnerabilities.add(createConfigErrorVulnerability("Некорректный targetBaseUrl: отсутствует схема (http/https)"));
            return vulnerabilities;
        }

        if (config.isStaticAnalysisEnabled()) {
            performStaticEndpointAnalysis(endpoints, config);
        }

        if (config.isDynamicAnalysisEnabled()) {
            performDynamicEndpointAnalysis(endpoints, config, apiClient);
        }

        return vulnerabilities;
    }

    /**
     * Динамический анализ без OpenAPI спецификации
     */
    private void performDynamicAnalysisWithoutOpenAPI(String baseUrl, ApiClient apiClient, ScanConfig config) {
        System.out.println("(API-9) Выполнение динамического анализа без OpenAPI спецификации...");

        // Проверка подозрительных endpoints
        scanSuspiciousEndpoints(baseUrl, apiClient);

        // Проверка мониторинговых endpoints
        scanMonitoringEndpoints(baseUrl, apiClient);

        // Поиск устаревших версий API
        scanApiVersions(baseUrl, apiClient);

        // Анализ среды выполнения
        analyzeEnvironmentIndicatorsWithoutOpenAPI(baseUrl);
    }

    private void analyzeEnvironmentIndicatorsWithoutOpenAPI(String baseUrl) {
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

    /**
     * Статический анализ на основе OpenAPI спецификации
     */
    private void performStaticAnalysis(OpenAPI openAPI, String baseUrl) {
        // 1. Анализ версионирования API
        checkApiVersioning(openAPI, baseUrl);

        // 2. Анализ серверов и окружения
        checkServersAndEnvironment(openAPI, baseUrl);

        // 3. Проверка документации на наличие тестовых ссылок
        checkDocumentationForTestReferences(openAPI);

        // 4. Анализ среды выполнения (production vs non-production)
        analyzeEnvironmentIndicators(baseUrl, openAPI);

        // 5. Проверка документационных слепых зон
        analyzeDocumentationBlindSpots(openAPI, baseUrl);

        // 6. Статический анализ подозрительных эндпоинтов в спецификации
        analyzeSuspiciousEndpointsInSpec(openAPI, baseUrl);
    }

    /**
     * Динамический анализ с выполнением запросов
     */
    private void performDynamicAnalysis(OpenAPI openAPI, String baseUrl, ApiClient apiClient) {
        // 1. Проверка подозрительных endpoints
        System.out.println("(API-9) 5.9.1: Сканирование подозрительных конечных точек...");
        scanSuspiciousEndpoints(baseUrl, apiClient);

        // 2. Проверка мониторинговых endpoints
        System.out.println("(API-9) 5.9.4: Сканирование мониторинговых конечных точек...");
        scanMonitoringEndpoints(baseUrl, apiClient);

        // 3. Поиск устаревших версий API
        System.out.println("(API-9) 5.9.6: Поиск устаревших версий API...");
        scanApiVersions(baseUrl, apiClient);
    }

    /**
     * Статический анализ на основе протестированных эндпоинтов
     */
    private void performStaticEndpointAnalysis(List<TestedEndpoint> endpoints, ScanConfig config) {
        System.out.println("(API-9) Статический анализ " + endpoints.size() + " эндпоинтов...");

        // Анализ структуры эндпоинтов
        analyzeEndpointStructure(endpoints);

        // Проверка версионирования в путях
        checkVersioningInEndpoints(endpoints);

        // Анализ метаданных эндпоинтов
        analyzeEndpointMetadata(endpoints);
    }

    /**
     * Динамический анализ на основе протестированных эндпоинтов
     */
    private void performDynamicEndpointAnalysis(List<TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-9) Динамический анализ " + endpoints.size() + " эндпоинтов...");

        String baseUrl = config.getTargetBaseUrl();

        // Дополнительное сканирование подозрительных путей
        for (TestedEndpoint endpoint : endpoints) {
            if (isSuspiciousEndpoint(endpoint.getPath())) {
                testSuspiciousEndpoint(endpoint, baseUrl, apiClient);
            }
        }

        // Сканирование соседних версий API
        scanAdjacentApiVersions(endpoints, baseUrl, apiClient);
    }

    // Остальные методы остаются без изменений...
    private void analyzeEndpointStructure(List<TestedEndpoint> endpoints) {
        Map<String, Integer> methodCount = new HashMap<>();
        Set<String> uniquePaths = new HashSet<>();

        for (TestedEndpoint endpoint : endpoints) {
            methodCount.merge(endpoint.getMethod(), 1, Integer::sum);
            uniquePaths.add(endpoint.getPath());
        }

        // Проверка разнообразия методов
        if (methodCount.size() < 3) {
            Vulnerability vuln = createInventoryVulnerability(
                    "Ограниченное разнообразие HTTP методов",
                    "Статический анализ обнаружил ограниченное использование HTTP методов в API.\n\n" +
                            "Обнаруженные методы: " + methodCount.keySet() + "\n" +
                            "Риски:\n" +
                            "• Возможное отсутствие CRUD операций\n" +
                            "• Потенциальные проблемы с дизайном API\n" +
                            "• Ограниченная функциональность",
                    "Все эндпоинты",
                    200,
                    "Методы: " + methodCount,
                    Vulnerability.Severity.LOW
            );
            vulnerabilities.add(vuln);
        }
    }

    private void checkVersioningInEndpoints(List<TestedEndpoint> endpoints) {
        boolean hasVersioning = endpoints.stream()
                .anyMatch(e -> e.getPath().matches(".*/v\\d+/.*"));

        if (!hasVersioning) {
            Vulnerability vuln = createInventoryVulnerability(
                    "Отсутствие версионирования в путях эндпоинтов",
                    "Статический анализ: API не использует явное версионирование в URL путях.\n\n" +
                            "Проанализировано эндпоинтов: " + endpoints.size() + "\n" +
                            "Риски OWASP API9:\n" +
                            "• Невозможность управления жизненным циклом версий\n" +
                            "• Сложность инвентаризации активных версий\n" +
                            "• Потенциальное наличие скрытых устаревших версий",
                    "Все эндпоинты",
                    200,
                    "Пути: " + endpoints.stream().map(TestedEndpoint::getPath).limit(10).toList(),
                    Vulnerability.Severity.MEDIUM
            );
            vulnerabilities.add(vuln);
        }
    }

    private void analyzeEndpointMetadata(List<TestedEndpoint> endpoints) {
        long endpointsWithoutDescription = endpoints.stream()
                .filter(e -> e.getDescription() == null || e.getDescription().trim().isEmpty())
                .count();

        if (endpointsWithoutDescription > endpoints.size() * 0.3) {
            Vulnerability vuln = createInventoryVulnerability(
                    "Недостаточная документация эндпоинтов",
                    "Статический анализ: Более 30% эндпоинтов не имеют описания.\n\n" +
                            "Эндпоинты без описания: " + endpointsWithoutDescription + "/" + endpoints.size() + "\n" +
                            "Риски:\n" +
                            "• Сложность понимания назначения эндпоинтов\n" +
                            "• Проблемы с инвентаризацией функциональности\n" +
                            "• Усложнение процесса тестирования безопасности",
                    "Метаданные эндпоинтов",
                    200,
                    endpointsWithoutDescription + " эндпоинтов без описания",
                    Vulnerability.Severity.LOW
            );
            vulnerabilities.add(vuln);
        }
    }

    private boolean isSuspiciousEndpoint(String path) {
        if (path == null) return false;
        String lowerPath = path.toLowerCase();
        return SUSPICIOUS_ENDPOINTS.stream().anyMatch(lowerPath::contains) ||
                MONITORING_PATHS.stream().anyMatch(lowerPath::contains);
    }

    private void testSuspiciousEndpoint(TestedEndpoint endpoint, String baseUrl, ApiClient apiClient) {
        String fullUrl = baseUrl + endpoint.getPath();
        if (testedUrls.contains(fullUrl)) {
            return;
        }

        HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl, "SUSPICIOUS_ENDPOINT_DYNAMIC");
        if (response == null) return;

        testedUrls.add(fullUrl);

        if (isSuccessStatus(response.getStatusCode())) {
            String evidence = buildEvidence("Подозрительная конечная точка (динамический)", fullUrl, response);

            Vulnerability vuln = createInventoryVulnerability(
                    "Обнаружена подозрительная конечная точка: " + endpoint.getPath(),
                    "ДИНАМИЧЕСКИЙ АНАЛИЗ: Обнаружена потенциально опасная конечная точка!\n\n" +
                            "Тип: " + classifySuspiciousEndpoint(endpoint.getPath()) + "\n" +
                            "Статус: HTTP " + response.getStatusCode() + "\n" +
                            "Риск: " + assessSuspiciousEndpointRisk(endpoint.getPath(), response) + "\n\n" +
                            "Рекомендации:\n" +
                            "• Проверить необходимость endpoint в production\n" +
                            "• Ограничить доступ к административным интерфейсам\n" +
                            "• Удалить неиспользуемые debug endpoints",
                    endpoint.getPath(),
                    response.getStatusCode(),
                    evidence,
                    Vulnerability.Severity.HIGH
            );

            vulnerabilities.add(vuln);
            foundEndpoints++;
        }
    }

    private void scanAdjacentApiVersions(List<TestedEndpoint> endpoints, String baseUrl, ApiClient apiClient) {
        // Извлекаем версии из существующих эндпоинтов
        Set<String> detectedVersions = new HashSet<>();
        Pattern versionPattern = Pattern.compile("/v(\\d+)/");

        for (TestedEndpoint endpoint : endpoints) {
            Matcher matcher = versionPattern.matcher(endpoint.getPath());
            if (matcher.find()) {
                detectedVersions.add(matcher.group(1));
            }
        }

        // Проверяем соседние версии
        for (String version : detectedVersions) {
            int verNum = Integer.parseInt(version);
            checkApiVersion(baseUrl, "v" + (verNum - 1), apiClient); // предыдущая версия
            checkApiVersion(baseUrl, "v" + (verNum + 1), apiClient); // следующая версия
        }
    }

    private void checkApiVersion(String baseUrl, String version, ApiClient apiClient) {
        String versionUrl = baseUrl + version;
        if (testedUrls.contains(versionUrl)) {
            return;
        }

        HttpApiClient.ApiResponse response = makeRequest(apiClient, versionUrl, "ADJACENT_VERSION");
        if (response == null) return;

        testedUrls.add(versionUrl);

        if (isSuccessStatus(response.getStatusCode())) {
            String evidence = buildEvidence("Соседняя версия API", versionUrl, response);

            Vulnerability vuln = createInventoryVulnerability(
                    "Обнаружена соседняя версия API: " + version,
                    "ДИНАМИЧЕСКИЙ АНАЛИЗ: Обнаружена дополнительная версия API!\n\n" +
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
            foundEndpoints++;
        }
    }

    private void analyzeSuspiciousEndpointsInSpec(OpenAPI openAPI, String baseUrl) {
        if (openAPI.getPaths() == null) return;

        int suspiciousCount = 0;
        for (String path : openAPI.getPaths().keySet()) {
            if (isSuspiciousEndpoint(path)) {
                suspiciousCount++;

                Vulnerability vuln = createInventoryVulnerability(
                        "Подозрительный эндпоинт в спецификации: " + path,
                        "СТАТИЧЕСКИЙ АНАЛИЗ: В OpenAPI спецификации обнаружен подозрительный эндпоинт.\n\n" +
                                "Тип: " + classifySuspiciousEndpoint(path) + "\n" +
                                "Риск: " + assessStaticSuspiciousEndpointRisk(path) + "\n\n" +
                                "Рекомендации:\n" +
                                "• Проверить необходимость endpoint в production\n" +
                                "• Ограничить доступ к административным интерфейсам\n" +
                                "• Удалить неиспользуемые debug endpoints из документации",
                        path,
                        200,
                        "Статический анализ OpenAPI спецификации",
                        Vulnerability.Severity.MEDIUM
                );
                vulnerabilities.add(vuln);
            }
        }

        System.out.println("(API-9) Подозрительных эндпоинтов в спецификации: " + suspiciousCount);
        foundEndpoints += suspiciousCount;
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
                                "• Непрофессиональное представение API\n\n" +
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
            if (response == null) continue;

            testedUrls.add(fullUrl);

            if (isSuccessStatus(response.getStatusCode())) {
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
            if (response == null) continue;

            testedUrls.add(fullUrl);

            if (isSuccessStatus(response.getStatusCode())) {
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
            if (response == null) continue;

            testedUrls.add(versionUrl);

            if (isSuccessStatus(response.getStatusCode())) {
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

    // Вспомогательные методы
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

    private String assessStaticSuspiciousEndpointRisk(String endpoint) {
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

            // Проверка URL на валидность
            if (url == null || url.trim().isEmpty()) {
                System.err.println("(API-9) Ошибка: пустой URL для запроса типа " + type);
                return null;
            }

            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                System.err.println("(API-9) Ошибка: URL должен начинаться с http:// или https://: " + url);
                return null;
            }

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

    private Vulnerability createConfigErrorVulnerability(String error) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("Ошибка конфигурации API9 сканера");
        vuln.setDescription("Сканер не может выполнить проверку из-за ошибки в конфигурации: " + error);
        vuln.setSeverity(Vulnerability.Severity.HIGH);
        vuln.setCategory(Vulnerability.Category.OWASP_API9_INVENTORY);
        vuln.setEvidence("Конфигурационная ошибка: " + error);
        vuln.setRecommendations(Arrays.asList(
                "Проверьте настройки targetBaseUrl в конфигурации",
                "Убедитесь, что targetBaseUrl начинается с http:// или https://",
                "Проверьте доступность OpenAPI спецификации"
        ));
        return vuln;
    }

    private Vulnerability createErrorVulnerability(String context, String error) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("Ошибка выполнения API9 сканера: " + context);
        vuln.setDescription("Во время сканирования произошла ошибка: " + error);
        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
        vuln.setCategory(Vulnerability.Category.OWASP_API9_INVENTORY);
        vuln.setEvidence("Ошибка выполнения: " + error);
        vuln.setRecommendations(Arrays.asList(
                "Проверьте корректность конфигурации",
                "Убедитесь в доступности целевого API",
                "Проверьте сетевые настройки"
        ));
        return vuln;
    }

    private static boolean isDebugMode() {
        return System.getProperty("debug") != null ||
                Arrays.asList(System.getenv().getOrDefault("JAVA_OPTS", "").split(" ")).contains("-Ddebug");
    }
}