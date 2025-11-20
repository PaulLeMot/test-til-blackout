package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API10_UnsafeConsumptionScanner implements SecurityScanner {

    private static final Set<String> EXTERNAL_API_INDICATORS = Set.of(
            "external", "third-party", "partner", "integration", "webhook",
            "callback", "oauth", "openid", "sso", "federation", "jwks", "well-known"
    );

    private static final Set<String> CLOUD_SERVICE_DOMAINS = Set.of(
            "aws.amazon.com", "azure.com", "cloud.google.com", "api.cloud.yandex.net",
            "api.digitalocean.com", "api.heroku.com", "api.cloudflare.com",
            "s3.amazonaws.com", "storage.googleapis.com"
    );

    private static final Set<String> BANK_SPECIFIC_INDICATORS = Set.of(
            "interbank", "cross-bank", "other.bank", "consent", "fapi",
            "openbanking", "psd2", "xs2a", "requesting-bank", "x-consent-id"
    );

    private static final Set<String> SENSITIVE_PERMISSIONS = Set.of(
            "ReadAccountsDetail", "ReadBalances", "ReadTransactionsDetail",
            "ReadProductAgreements", "OpenProductAgreements"
    );

    // Стандартные Open Banking заголовки, которые не должны считаться уязвимостью
    private static final Set<String> STANDARD_OPENBANKING_HEADERS = Set.of(
            "x-consent-id", "x-requesting-bank", "x-fapi-interaction-id",
            "x-fapi-customer-ip-address", "x-payment-consent-id",
            "x-product-agreement-consent-id", "x-fapi-financial-id",
            "x-customer-user-agent", "x-jws-signature"
    );

    // Для отслеживания уже обработанных эндпоинтов и предотвращения дублирования
    private final Set<String> processedEndpoints = new HashSet<>();

    public API10_UnsafeConsumptionScanner() {}

    @Override
    public String getName() {
        return "API10_UnsafeConsumption";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Сканирование уязвимостей небезопасного потребления API (OWASP API Security Top 10:2023 - API10)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        processedEndpoints.clear(); // Очищаем при каждом новом сканировании

        if (!(openApiObj instanceof OpenAPI)) {
            System.err.println("(API-10) Ошибка: передан неправильный объект OpenAPI");
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;

        try {
            // 5.10.1: Углубленный анализ зависимостей от сторонних API
            checkExternalDependencies(openAPI, vulnerabilities, config);

            // 5.10.2: Тестирование обработки некорректных данных от внешних API
            testMaliciousExternalData(openAPI, vulnerabilities, config, apiClient);

            // 5.10.3: Проверка валидации данных из доверенных источников
            testTrustedSourceValidation(openAPI, vulnerabilities, config, apiClient);

            // 5.10.4: Анализ обработки ошибок внешних сервисов
            testExternalServiceErrorHandling(openAPI, vulnerabilities, config, apiClient);

            // 5.10.5: Тестирование уязвимостей цепочки доверия
            testTrustChainVulnerabilities(openAPI, vulnerabilities, config, apiClient);

            // 5.10.6: Проверка безопасности интеграций с облачными сервисами
            checkCloudServiceIntegrations(openAPI, vulnerabilities, config, apiClient);

            // 5.10.7: Анализ межбанковских интеграций
            checkInterbankIntegrations(openAPI, vulnerabilities, config);

            // 5.10.8: Проверка JWKS и внешних ключей
            checkJwksDependencies(openAPI, vulnerabilities, config, apiClient);

            // 5.10.9: Анализ согласий и разрешений
            checkConsentPermissions(openAPI, vulnerabilities, config);

            // 5.10.10: Дедупликация уязвимостей
            deduplicateVulnerabilities(vulnerabilities);

            // 5.10.11: Генерация отчета с проблемами потребления сторонних API
            generateConsumptionReport(vulnerabilities);

        } catch (Exception e) {
            System.err.println("(API-10) Ошибка при выполнении API10 сканера: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("(API-10) Сканирование небезопасного потребления API завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * 5.10.1: Углубленный анализ зависимостей от сторонних API в спецификации
     */
    private void checkExternalDependencies(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config) {
        System.out.println("(API-10) Углубленный анализ зависимостей от сторонних API...");

        // 1. Анализ серверов
        List<Server> servers = openAPI.getServers();
        if (servers != null) {
            for (Server server : servers) {
                String serverUrl = server.getUrl();
                if (serverUrl != null && containsExternalDomain(serverUrl)) {
                    Vulnerability vuln = createBaseVulnerability();
                    vuln.setTitle("API10:2023 - External API Server Dependency");
                    vuln.setDescription("Обнаружена зависимость от внешнего API сервера: " + serverUrl +
                            "\n• Риск: Зависимость от внешнего сервиса\n• Возможность компрометации через внешний API\n• Необходима строгая валидация входящих данных");
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setEvidence("External API server in OpenAPI: " + serverUrl);
                    vuln.setRecommendations(Arrays.asList(
                            "Реализовать строгую валидацию всех данных от внешних API",
                            "Использовать взаимную аутентификацию (mTLS)",
                            "Внедрить circuit breaker для внешних вызовов",
                            "Мониторить доступность внешних сервисов"
                    ));
                    vulnerabilities.add(vuln);
                }
            }
        }

        // 2. Анализ операций на наличие внешних зависимостей
        analyzeOperationsForExternalDependencies(openAPI, vulnerabilities);

        // 3. Анализ межбанковских зависимостей
        analyzeInterbankDependencies(openAPI, vulnerabilities);
    }

    /**
     * Анализ операций на наличие внешних зависимостей
     */
    private void analyzeOperationsForExternalDependencies(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        if (openAPI.getPaths() == null) return;

        for (String path : openAPI.getPaths().keySet()) {
            PathItem pathItem = openAPI.getPaths().get(path);
            Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();

            for (Map.Entry<PathItem.HttpMethod, Operation> entry : operations.entrySet()) {
                Operation operation = entry.getValue();
                if (operation != null) {
                    String description = (operation.getDescription() != null ? operation.getDescription() : "") +
                            " " + (operation.getSummary() != null ? operation.getSummary() : "");

                    // Проверяем наличие индикаторов внешних зависимостей
                    for (String indicator : EXTERNAL_API_INDICATORS) {
                        if (description.toLowerCase().contains(indicator.toLowerCase())) {
                            String endpointKey = entry.getKey() + " " + path;
                            if (!processedEndpoints.contains(endpointKey)) {
                                processedEndpoints.add(endpointKey);

                                Vulnerability vuln = createBaseVulnerability();
                                vuln.setTitle("API10:2023 - External Dependency in API Operation");
                                vuln.setDescription("Обнаружена возможная внешняя зависимость в операции: " +
                                        entry.getKey() + " " + path +
                                        "\n• Индикатор: " + indicator +
                                        "\n• Риск: Интеграция с внешним сервисом может быть уязвима");
                                vuln.setSeverity(Vulnerability.Severity.LOW);
                                vuln.setEvidence("External indicator '" + indicator + "' in: " + path);
                                vuln.setRecommendations(Arrays.asList(
                                        "Проверить безопасность интеграции с внешним сервисом",
                                        "Реализовать валидацию всех входящих данных",
                                        "Использовать санитизацию данных от внешних источников"
                                ));
                                vulnerabilities.add(vuln);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Анализ межбанковских зависимостей
     */
    private void analyzeInterbankDependencies(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        if (openAPI.getPaths() == null) return;

        for (String path : openAPI.getPaths().keySet()) {
            PathItem pathItem = openAPI.getPaths().get(path);
            Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();

            for (Map.Entry<PathItem.HttpMethod, Operation> entry : operations.entrySet()) {
                Operation operation = entry.getValue();
                if (operation != null && operation.getParameters() != null) {

                    // Проверяем параметры на наличие межбанковых заголовков
                    for (Parameter param : operation.getParameters()) {
                        if (param.getName() != null &&
                                !STANDARD_OPENBANKING_HEADERS.contains(param.getName().toLowerCase()) &&
                                (param.getName().toLowerCase().contains("requesting-bank") ||
                                        param.getName().toLowerCase().contains("consent-id") ||
                                        param.getName().toLowerCase().contains("fapi"))) {

                            String endpointKey = "INTERBANK_" + entry.getKey() + " " + path + "_" + param.getName();
                            if (!processedEndpoints.contains(endpointKey)) {
                                processedEndpoints.add(endpointKey);

                                Vulnerability vuln = createBaseVulnerability();
                                vuln.setTitle("API10:2023 - Interbank Integration Dependency");
                                vuln.setDescription("Обнаружена межбанковая интеграция через параметр: " +
                                        param.getName() + " в " + entry.getKey() + " " + path +
                                        "\n• Риск: Зависимость от других банковских систем\n• Необходима проверка доверия между банками");
                                vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                                vuln.setEvidence("Interbank parameter: " + param.getName() + " in " + path);
                                vuln.setRecommendations(Arrays.asList(
                                        "Реализовать строгую проверку межбанковых запросов",
                                        "Использовать подписанные JWT токены для межбанковой коммуникации",
                                        "Внедрить валидацию consent ID",
                                        "Ограничить доверенные банки-партнеры"
                                ));
                                vulnerabilities.add(vuln);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * 5.10.2: Улучшенное тестирование обработки некорректных данных от внешних API
     */
    private void testMaliciousExternalData(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Улучшенное тестирование обработки некорректных данных...");

        // Банковские специфические payloads
        String[] bankTestPayloads = {
                // SQL инъекции в банковские данные
                "{\"account_id\":\"acc-001'; DROP TABLE accounts; --\",\"amount\":1000}",
                "{\"iban\":\"DE89370400440532013000<script>alert('xss')</script>\",\"name\":\"test\"}",
                "{\"amount\":1e308,\"currency\":\"USD\"}", // Переполнение числа
                "{\"transaction_id\":\"../../../etc/passwd\",\"description\":\"test\"}", // Path traversal
                "{\"consent_id\":{\"$ne\":\"valid-consent\"},\"status\":\"approved\"}", // NoSQL инъекция
                "{\"balance\":\"NaN\",\"account\":\"test\"}", // Невалидные числа
                "{\"timestamp\":\"0000-00-00T00:00:00Z\",\"value\":\"test\"}", // Невалидная дата
                "{\"client_id\":\"team200\\r\\nX-Admin: true\",\"secret\":\"test\"}", // Инъекция заголовков
                "{\"permissions\":[\"ReadAccountsDetail\",\"../../../../etc/passwd\"],\"reason\":\"test\"}", // Path traversal в массиве
                "{\"amount\":-999999999.99,\"currency\":\"RUB\"}" // Отрицательная сумма
        };

        // Тестируем только эндпоинты без path-параметров
        List<String> testableEndpoints = getTestableEndpoints(openAPI);

        for (String endpoint : testableEndpoints) {
            System.out.println("(API-10) Тестирование эндпоинта: " + endpoint);

            for (String payload : bankTestPayloads) {
                try {
                    Map<String, String> headers = createAuthHeaders(config);
                    headers.put("Content-Type", "application/json");

                    // Добавляем межбанковые заголовки для релевантных эндпоинтов
                    if (endpoint.contains("consent") || endpoint.contains("interbank")) {
                        headers.put("X-Requesting-Bank", "test-bank");
                        headers.put("X-Consent-Id", "test-consent-123");
                    }

                    String fullUrl = config.getTargetBaseUrl() + endpoint;
                    Object response = apiClient.executeRequest("POST", fullUrl, payload, headers);

                    if (response instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                        // Проверяем различные сценарии уязвимостей
                        checkResponseForVulnerabilities(apiResponse, endpoint, payload, vulnerabilities);
                    }
                } catch (Exception e) {
                    // Ожидаемое поведение для некорректных данных
                }
            }
        }
    }

    /**
     * 5.10.3: Улучшенная проверка валидации данных из доверенных источников
     */
    private void testTrustedSourceValidation(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Улучшенная проверка валидации данных из доверенных источников...");

        // Специфические сценарии для банковского API
        String[] trustedSourceScenarios = {
                "{\"amount\":-999999999,\"currency\":\"RUB\"}", // Отрицательная сумма
                "{\"account\":\" \",\"balance\":9999999999}", // Пустой account с огромным балансом
                "{\"user_id\":\"../../../etc/passwd\",\"role\":\"admin\"}", // Path traversal
                "{\"timestamp\":\"2099-12-31T23:59:59Z\",\"action\":\"future\"}", // Дата в будущем
                "{\"rate\":0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001,\"value\":\"tiny\"}", // Очень маленькое число
                "{\"description\":\"A\".repeat(10000),\"type\":\"overflow\"}", // Очень длинная строка
                "{\"client_id\":\"team200-1\",\"permissions\":[\"ReadAccountsDetail\",\"../../etc/passwd\"]}", // Path traversal в разрешениях
                "{\"requesting_bank\":\"../../../malicious\",\"client_id\":\"test\"}" // Path traversal в названии банка
        };

        List<String> dataEndpoints = getDataProcessingEndpoints(openAPI);

        for (String endpoint : dataEndpoints) {
            if (containsPathParameters(endpoint)) {
                continue; // Пропускаем эндпоинты с параметрами
            }

            for (String scenario : trustedSourceScenarios) {
                try {
                    Map<String, String> headers = createAuthHeaders(config);
                    headers.put("Content-Type", "application/json");
                    headers.put("X-Trusted-Source", "true");
                    headers.put("X-Forwarded-For", "192.168.1.1");
                    headers.put("X-Real-IP", "10.0.0.1");

                    // Для межбанковых эндпоинтов добавляем соответствующие заголовки
                    if (endpoint.contains("consent") || endpoint.contains("interbank")) {
                        headers.put("X-Requesting-Bank", "trusted-bank-partner");
                        headers.put("X-Consent-Id", "trusted-consent-456");
                    }

                    String fullUrl = config.getTargetBaseUrl() + endpoint;
                    Object response = apiClient.executeRequest("POST", fullUrl, scenario, headers);

                    if (response instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                        int statusCode = extractStatusCode(apiResponse);

                        if (statusCode == 200 || statusCode == 201) {
                            Vulnerability vuln = createBaseVulnerability();
                            vuln.setTitle("API10:2023 - Missing Validation of Trusted Source Data");
                            vuln.setDescription("Приложение принимает некорректные данные от доверенных источников:\n" +
                                    "• Эндпоинт: " + endpoint + "\n" +
                                    "• Сценарий: " + (scenario.length() > 100 ? scenario.substring(0, 100) + "..." : scenario) + "\n" +
                                    "• Статус: " + statusCode + "\n" +
                                    "• Риск: Обход валидации через доверенные каналы");
                            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                            vuln.setEvidence("Trusted source data accepted at: " + endpoint);
                            vuln.setStatusCode(statusCode);
                            vuln.setRecommendations(Arrays.asList(
                                    "Валидировать все данные независимо от источника",
                                    "Реализовать строгие схемы валидации для всех полей",
                                    "Ограничивать максимальные значения числовых полей",
                                    "Валидировать форматы строк против whitelist"
                            ));
                            vulnerabilities.add(vuln);
                            break;
                        }
                    }
                } catch (Exception e) {
                    // Ожидаемое поведение
                }
            }
        }
    }

    /**
     * 5.10.4: Анализ обработки ошибок внешних сервисов
     */
    private void testExternalServiceErrorHandling(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Тестирование обработки ошибок внешних сервисов...");

        // Тестируем эндпоинты, которые могут зависеть от внешних сервисов
        List<String> externalDependentEndpoints = findExternalDependentEndpoints(openAPI);

        for (String endpoint : externalDependentEndpoints) {
            try {
                Map<String, String> headers = createAuthHeaders(config);
                headers.put("Content-Type", "application/json");

                // Эмулируем запрос, который может вызвать ошибку внешнего сервиса
                String maliciousPayload = "{\"service\":\"invalid\",\"timeout\":1,\"external_call\":\"http://malicious-site.com\"}";
                String fullUrl = config.getTargetBaseUrl() + endpoint;

                Object response = apiClient.executeRequest("POST", fullUrl, maliciousPayload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    int statusCode = extractStatusCode(apiResponse);
                    String responseBody = apiResponse.getBody();

                    // Проверяем, не раскрывает ли приложение внутреннюю информацию об ошибках
                    if (containsSensitiveErrorInfo(responseBody)) {
                        Vulnerability vuln = createBaseVulnerability();
                        vuln.setTitle("API10:2023 - Information Disclosure in External Service Errors");
                        vuln.setDescription("Приложение раскрывает чувствительную информацию при ошибках внешних сервисов:\n" +
                                "• Эндпоинт: " + endpoint + "\n" +
                                "• Статус: " + statusCode + "\n" +
                                "• Раскрытые данные могут помочь атакующему\n" +
                                "• Риск: Утечка внутренней структуры системы\n" +
                                "• Угроза: Reconnaissance атак");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setEvidence("Sensitive error information at " + endpoint + " with status " + statusCode + ": " +
                                (responseBody.length() > 200 ? responseBody.substring(0, 200) + "..." : responseBody));
                        vuln.setStatusCode(statusCode);
                        vuln.setRecommendations(Arrays.asList(
                                "Использовать унифицированные сообщения об ошибках",
                                "Не раскрывать stack traces в production",
                                "Логировать детальные ошибки только на сервере",
                                "Реализовать graceful degradation при недоступности внешних сервисов"
                        ));
                        vulnerabilities.add(vuln);
                    }
                }
            } catch (Exception e) {
                // Ожидаемое поведение при тестировании ошибок
            }
        }
    }

    /**
     * 5.10.5: Тестирование уязвимостей цепочки доверия (trust chain)
     */
    private void testTrustChainVulnerabilities(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Тестирование цепочки доверия...");

        // Проверяем наличие слабых мест в цепочке доверия
        List<String> trustIssues = new ArrayList<>();

        // Проверка TLS/SSL конфигурации основного таргета
        if (!config.getTargetBaseUrl().startsWith("https://")) {
            trustIssues.add("Использование HTTP вместо HTTPS для основного API: " + config.getTargetBaseUrl());
        }

        // Проверка серверов в OpenAPI спецификации
        List<Server> servers = openAPI.getServers();
        if (servers != null) {
            for (Server server : servers) {
                String serverUrl = server.getUrl();
                // Игнорируем относительные пути
                if (serverUrl != null && !serverUrl.startsWith("/") && !serverUrl.startsWith("https://")) {
                    trustIssues.add("Сервер в OpenAPI спецификации использует HTTP: " + serverUrl);
                }
            }
        }

        // Проверка JWKS эндпоинта
        if (openAPI.getPaths() != null && openAPI.getPaths().containsKey("/.well-known/jwks.json")) {
            String jwksUrl = config.getTargetBaseUrl() + "/.well-known/jwks.json";
            if (!jwksUrl.startsWith("https://")) {
                trustIssues.add("JWKS endpoint использует HTTP вместо HTTPS");
            }
        }

        if (!trustIssues.isEmpty()) {
            Vulnerability vuln = createBaseVulnerability();
            vuln.setTitle("API10:2023 - Trust Chain Vulnerabilities");
            vuln.setDescription("Обнаружены проблемы в цепочке доверия:\n• " + String.join("\n• ", trustIssues) +
                    "\n\nРиски:\n• MITM атаки\n• Компрометация доверенных соединений\n• Утечка чувствительных данных\n• Подмена публичных ключей");
            vuln.setSeverity(Vulnerability.Severity.HIGH);
            vuln.setEvidence("Trust chain issues: " + String.join(", ", trustIssues));
            vuln.setRecommendations(Arrays.asList(
                    "Всегда использовать HTTPS для API коммуникаций",
                    "Валидировать SSL сертификаты",
                    "Регулярно обновлять trust stores",
                    "Использовать certificate pinning для критичных сервисов",
                    "Внедрить мониторинг скомпрометированных сертификатов"
            ));
            vulnerabilities.add(vuln);
        }
    }

    /**
     * 5.10.6: Проверка безопасности интеграций с облачными сервисами
     */
    private void checkCloudServiceIntegrations(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Проверка интеграций с облачными сервисами...");

        // Проверяем всю OpenAPI спецификацию на наличие упоминаний облачных сервисов
        String fullSpecText = extractAllTextFromOpenAPI(openAPI);

        for (String cloudDomain : CLOUD_SERVICE_DOMAINS) {
            if (fullSpecText.toLowerCase().contains(cloudDomain.toLowerCase())) {
                Vulnerability vuln = createBaseVulnerability();
                vuln.setTitle("API10:2023 - Cloud Service Integration Exposure");
                vuln.setDescription("Обнаружена интеграция с облачным сервисом: " + cloudDomain +
                        "\n• Риск: Раскрытие внутренней архитектуры\n• Угроза: Целевые атаки на облачную инфраструктуру");
                vuln.setSeverity(Vulnerability.Severity.LOW);
                vuln.setEvidence("Cloud service reference in OpenAPI spec: " + cloudDomain);
                vuln.setRecommendations(Arrays.asList(
                        "Не раскрывать информацию о внутренних интеграциях в документации",
                        "Использовать внутренние DNS имена для облачных сервисов",
                        "Реализовать API gateway для абстракции внутренней архитектуры",
                        "Регулярно аудировать конфигурации облачных сервисов"
                ));
                vulnerabilities.add(vuln);
                break;
            }
        }
    }

    /**
     * 5.10.7: Анализ межбанковых интеграций
     */
    private void checkInterbankIntegrations(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config) {
        System.out.println("(API-10) Анализ межбанковых интеграций...");

        // Ищем эндпоинты, связанные с межбанковыми операциями
        List<String> interbankEndpoints = findInterbankEndpoints(openAPI);

        for (String endpoint : interbankEndpoints) {
            String endpointKey = "INTERBANK_RISK_" + endpoint;
            if (!processedEndpoints.contains(endpointKey)) {
                processedEndpoints.add(endpointKey);

                Vulnerability vuln = createBaseVulnerability();
                vuln.setTitle("API10:2023 - Interbank Integration Risk");
                vuln.setDescription("Обнаружена межбанковая интеграция: " + endpoint +
                        "\n• Риск: Зависимость от других банковских систем\n• Угроза: Цепочка доверия между банками\n• Возможность атак через компрометированный банк-партнер");
                vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                vuln.setEvidence("Interbank endpoint: " + endpoint);
                vuln.setRecommendations(Arrays.asList(
                        "Реализовать строгую аутентификацию межбанковых запросов",
                        "Использовать подписанные JWT токены с проверкой эмитента",
                        "Внедрить rate limiting для межбанковых вызовов",
                        "Регулярно проводить аудиты безопасности банков-партнеров",
                        "Использовать whitelist доверенных банков"
                ));
                vulnerabilities.add(vuln);
            }
        }

        // Проверяем наличие согласий (consents)
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                if (path.contains("consent")) {
                    String endpointKey = "CONSENT_DEP_" + path;
                    if (!processedEndpoints.contains(endpointKey)) {
                        processedEndpoints.add(endpointKey);

                        Vulnerability vuln = createBaseVulnerability();
                        vuln.setTitle("API10:2023 - Consent Management External Dependency");
                        vuln.setDescription("Система управления согласиями может зависеть от внешних сервисов: " + path +
                                "\n• Риск: Компрометация механизма согласий\n• Угроза: Несанкционированный доступ к данным");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setEvidence("Consent management endpoint: " + path);
                        vuln.setRecommendations(Arrays.asList(
                                "Реализовать строгую валидацию consent ID",
                                "Использовать криптографически подписанные согласия",
                                "Внедрить аудит всех операций с согласиями",
                                "Ограничить срок действия согласий"
                        ));
                        vulnerabilities.add(vuln);
                    }
                }
            }
        }
    }

    /**
     * 5.10.8: Проверка JWKS и внешних ключей
     */
    private void checkJwksDependencies(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Проверка JWKS и внешних ключей...");

        // Проверяем наличие JWKS эндпоинта
        if (openAPI.getPaths() != null && openAPI.getPaths().containsKey("/.well-known/jwks.json")) {
            try {
                String jwksUrl = config.getTargetBaseUrl() + "/.well-known/jwks.json";
                Object response = apiClient.executeRequest("GET", jwksUrl, null, new HashMap<>());

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    int statusCode = extractStatusCode(apiResponse);

                    if (statusCode == 200) {
                        Vulnerability vuln = createBaseVulnerability();
                        vuln.setTitle("API10:2023 - JWKS External Key Dependency");
                        vuln.setDescription("Обнаружен JWKS endpoint для внешних ключей:\n" +
                                "• Риск: Зависимость от внешних ключей подписи\n• Угроза: Компрометация ключей проверки JWT\n• Возможность подмены identity");
                        vuln.setSeverity(Vulnerability.Severity.HIGH);
                        vuln.setEvidence("JWKS endpoint exposed: " + jwksUrl);
                        vuln.setStatusCode(statusCode);
                        vuln.setRecommendations(Arrays.asList(
                                "Реализовать rotation ключей подписи",
                                "Использовать HS256 для внутренних токенов вместо RS256",
                                "Внедрить мониторинг изменений в JWKS",
                                "Ограничить доступ к JWKS endpoint",
                                "Использовать certificate pinning для критичных ключей"
                        ));
                        vulnerabilities.add(vuln);
                    }
                }
            } catch (Exception e) {
                // JWKS endpoint недоступен - это может быть нормально
            }
        }

        // Проверяем упоминания внешних ключей в документации
        String fullSpecText = extractAllTextFromOpenAPI(openAPI);
        if (fullSpecText.toLowerCase().contains("rs256") || fullSpecText.toLowerCase().contains("jwks")) {
            String key = "EXTERNAL_CRYPTO_KEY";
            if (!processedEndpoints.contains(key)) {
                processedEndpoints.add(key);

                Vulnerability vuln = createBaseVulnerability();
                vuln.setTitle("API10:2023 - External Cryptographic Key Dependency");
                vuln.setDescription("API использует внешние криптографические ключи (RS256/JWKS)\n" +
                        "• Риск: Зависимость от внешней PKI инфраструктуры\n• Угроза: Компрометация цепочки доверия ключей");
                vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                vuln.setEvidence("Cryptographic key references found in OpenAPI spec");
                vuln.setRecommendations(Arrays.asList(
                        "Реализовать строгий rotation политику для ключей",
                        "Использовать HS256 для внутренней аутентификации",
                        "Внедрить мониторинг использования ключей",
                        "Регулярно проводить аудит PKI инфраструктуры"
                ));
                vulnerabilities.add(vuln);
            }
        }
    }

    /**
     * 5.10.9: Анализ согласий и разрешений
     */
    private void checkConsentPermissions(OpenAPI openAPI, List<Vulnerability> vulnerabilities, ScanConfig config) {
        System.out.println("(API-10) Анализ согласий и разрешений...");

        // Анализируем эндпоинты согласий
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                if (path.contains("consent")) {
                    PathItem pathItem = openAPI.getPaths().get(path);
                    Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();

                    for (Map.Entry<PathItem.HttpMethod, Operation> entry : operations.entrySet()) {
                        Operation operation = entry.getValue();
                        if (operation != null) {
                            String description = operation.getDescription() != null ? operation.getDescription() : "";

                            // Проверяем чувствительные разрешения только в контексте внешних зависимостей
                            for (String permission : SENSITIVE_PERMISSIONS) {
                                if (description.contains(permission) &&
                                        (description.toLowerCase().contains("external") ||
                                                description.toLowerCase().contains("third-party"))) {

                                    String endpointKey = "SENSITIVE_PERM_" + entry.getKey() + " " + path + "_" + permission;
                                    if (!processedEndpoints.contains(endpointKey)) {
                                        processedEndpoints.add(endpointKey);

                                        Vulnerability vuln = createBaseVulnerability();
                                        vuln.setTitle("API10:2023 - Sensitive Permission in External Consent");
                                        vuln.setDescription("Обнаружено чувствительное разрешение в согласии: " + permission +
                                                "\n• Эндпоинт: " + entry.getKey() + " " + path +
                                                "\n• Риск: Несанкционированный доступ через внешние согласия\n• Угроза: Утечка финансовых данных");
                                        vuln.setSeverity(Vulnerability.Severity.HIGH);
                                        vuln.setEvidence("Sensitive permission '" + permission + "' in consent endpoint with external dependency");
                                        vuln.setRecommendations(Arrays.asList(
                                                "Реализовать granular consent management",
                                                "Ограничивать scope разрешений для внешних приложений",
                                                "Внедрить mandatory approval для чувствительных разрешений",
                                                "Регулярно проводить аудит выданных согласий",
                                                "Реализовать автоматический отзыв неиспользуемых согласий"
                                        ));
                                        vulnerabilities.add(vuln);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * 5.10.10: Дедупликация уязвимостей
     */
    private void deduplicateVulnerabilities(List<Vulnerability> vulnerabilities) {
        System.out.println("(API-10) Дедупликация уязвимостей...");

        Map<String, Vulnerability> uniqueVulnerabilities = new LinkedHashMap<>();

        for (Vulnerability vuln : vulnerabilities) {
            String key = vuln.getTitle() + "|" + vuln.getEvidence() + "|" + vuln.getSeverity();

            if (!uniqueVulnerabilities.containsKey(key)) {
                uniqueVulnerabilities.put(key, vuln);
            }
        }

        vulnerabilities.clear();
        vulnerabilities.addAll(uniqueVulnerabilities.values());
    }

    /**
     * 5.10.11: Генерация отчета с проблемами потребления сторонних API
     */
    private void generateConsumptionReport(List<Vulnerability> vulnerabilities) {
        System.out.println("(API-10) Генерация отчета по проблемам потребления сторонних API...");

        if (vulnerabilities.isEmpty()) {
            System.out.println("(API-10) Не обнаружено проблем с потреблением сторонних API");
            return;
        }

        // Группируем уязвимости по типу
        Map<String, List<Vulnerability>> groupedVulns = new HashMap<>();
        for (Vulnerability vuln : vulnerabilities) {
            String title = vuln.getTitle();
            groupedVulns.computeIfAbsent(title, k -> new ArrayList<>()).add(vuln);
        }

        System.out.println("(API-10) ОТЧЕТ ПО ПРОБЛЕМАМ ПОТРЕБЛЕНИЯ СТОРОННИХ API:");
        System.out.println("(API-10) " + "=".repeat(80));

        for (Map.Entry<String, List<Vulnerability>> entry : groupedVulns.entrySet()) {
            System.out.println("(API-10) " + entry.getKey() + " (найдено: " + entry.getValue().size() + ")");
            for (Vulnerability vuln : entry.getValue()) {
                System.out.println("(API-10)    Серьезность: " + vuln.getSeverity());
                if (vuln.getEvidence() != null) {
                    System.out.println("(API-10)    Доказательства: " +
                            (vuln.getEvidence().length() > 100 ?
                                    vuln.getEvidence().substring(0, 100) + "..." : vuln.getEvidence()));
                }
            }
            System.out.println();
        }

        // Статистика по серьезности
        long criticalCount = vulnerabilities.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.CRITICAL).count();
        long highCount = vulnerabilities.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.HIGH).count();
        long mediumCount = vulnerabilities.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.MEDIUM).count();
        long lowCount = vulnerabilities.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.LOW).count();

        System.out.println("(API-10) СТАТИСТИКА ПО СЕРЬЕЗНОСТИ:");
        System.out.println("(API-10)    Критический: " + criticalCount);
        System.out.println("(API-10)    Высокий: " + highCount);
        System.out.println("(API-10)    Средний: " + mediumCount);
        System.out.println("(API-10)    Низкий: " + lowCount);
        System.out.println("(API-10) " + "=".repeat(80));
    }

    /**
     * Вспомогательные методы для работы с OpenAPI
     */

    // Получение всех POST эндпоинтов из OpenAPI
    private List<String> getPostEndpoints(OpenAPI openAPI) {
        List<String> endpoints = new ArrayList<>();
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                PathItem pathItem = openAPI.getPaths().get(path);
                if (pathItem.getPost() != null) {
                    endpoints.add(path);
                }
            }
        }
        return endpoints;
    }

    // Получение эндпоинтов для обработки данных
    private List<String> getDataProcessingEndpoints(OpenAPI openAPI) {
        List<String> endpoints = new ArrayList<>();
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                PathItem pathItem = openAPI.getPaths().get(path);
                // Добавляем эндпоинты, которые принимают данные (POST, PUT, PATCH)
                if (pathItem.getPost() != null || pathItem.getPut() != null || pathItem.getPatch() != null) {
                    endpoints.add(path);
                }
            }
        }
        return endpoints;
    }

    // Получение тестируемых эндпоинтов (без path-параметров)
    private List<String> getTestableEndpoints(OpenAPI openAPI) {
        List<String> endpoints = new ArrayList<>();
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                if (!containsPathParameters(path)) {
                    PathItem pathItem = openAPI.getPaths().get(path);
                    if (pathItem.getPost() != null) {
                        endpoints.add(path);
                    }
                }
            }
        }
        return endpoints;
    }

    // Поиск эндпоинтов, зависящих от внешних сервисов
    private List<String> findExternalDependentEndpoints(OpenAPI openAPI) {
        List<String> endpoints = new ArrayList<>();
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                if (!containsPathParameters(path)) {
                    PathItem pathItem = openAPI.getPaths().get(path);
                    Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();

                    for (Map.Entry<PathItem.HttpMethod, Operation> entry : operations.entrySet()) {
                        Operation operation = entry.getValue();
                        if (operation != null) {
                            String description = (operation.getDescription() != null ? operation.getDescription() : "") +
                                    " " + (operation.getSummary() != null ? operation.getSummary() : "");

                            // Ищем индикаторы внешних зависимостей
                            for (String indicator : EXTERNAL_API_INDICATORS) {
                                if (description.toLowerCase().contains(indicator.toLowerCase())) {
                                    endpoints.add(path);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        return endpoints;
    }

    // Поиск межбанковых эндпоинтов
    private List<String> findInterbankEndpoints(OpenAPI openAPI) {
        List<String> endpoints = new ArrayList<>();
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                PathItem pathItem = openAPI.getPaths().get(path);
                Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();

                for (Map.Entry<PathItem.HttpMethod, Operation> entry : operations.entrySet()) {
                    Operation operation = entry.getValue();
                    if (operation != null) {
                        String description = (operation.getDescription() != null ? operation.getDescription() : "") +
                                " " + (operation.getSummary() != null ? operation.getSummary() : "");

                        // Ищем индикаторы межбанковых операций (исключая стандартные заголовки)
                        for (String indicator : BANK_SPECIFIC_INDICATORS) {
                            if (description.toLowerCase().contains(indicator.toLowerCase()) &&
                                    !STANDARD_OPENBANKING_HEADERS.contains(indicator.toLowerCase())) {
                                endpoints.add(path);
                                break;
                            }
                        }

                        // Проверяем параметры на межбанковые заголовки (исключая стандартные)
                        if (operation.getParameters() != null) {
                            for (Parameter param : operation.getParameters()) {
                                if (param.getName() != null &&
                                        !STANDARD_OPENBANKING_HEADERS.contains(param.getName().toLowerCase()) &&
                                        (param.getName().toLowerCase().contains("requesting-bank") ||
                                                param.getName().toLowerCase().contains("consent-id"))) {
                                    endpoints.add(path);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        return endpoints.stream().distinct().collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }

    // Извлечение всего текста из OpenAPI спецификации для анализа
    private String extractAllTextFromOpenAPI(OpenAPI openAPI) {
        StringBuilder text = new StringBuilder();

        // Информация API
        if (openAPI.getInfo() != null) {
            if (openAPI.getInfo().getTitle() != null) text.append(openAPI.getInfo().getTitle()).append(" ");
            if (openAPI.getInfo().getDescription() != null) text.append(openAPI.getInfo().getDescription()).append(" ");
        }

        // Серверы
        if (openAPI.getServers() != null) {
            for (Server server : openAPI.getServers()) {
                if (server.getUrl() != null) text.append(server.getUrl()).append(" ");
                if (server.getDescription() != null) text.append(server.getDescription()).append(" ");
            }
        }

        // Пути и операции
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                text.append(path).append(" ");
                PathItem pathItem = openAPI.getPaths().get(path);

                // Проверяем все методы
                Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();
                for (Map.Entry<PathItem.HttpMethod, Operation> entry : operations.entrySet()) {
                    Operation operation = entry.getValue();
                    if (operation != null) {
                        if (operation.getSummary() != null) text.append(operation.getSummary()).append(" ");
                        if (operation.getDescription() != null) text.append(operation.getDescription()).append(" ");
                    }
                }
            }
        }

        return text.toString();
    }

    /**
     * Вспомогательные методы
     */
    private Vulnerability createBaseVulnerability() {
        Vulnerability vuln = new Vulnerability();
        vuln.setCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
        return vuln;
    }

    private Map<String, String> createAuthHeaders(ScanConfig config) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        if (config.getFirstUserToken() != null && !config.getFirstUserToken().isEmpty()) {
            headers.put("Authorization", "Bearer " + config.getFirstUserToken());
        }
        return headers;
    }

    private boolean containsExternalDomain(String url) {
        if (url == null || url.startsWith("/")) return false; // Игнорируем относительные пути
        Pattern domainPattern = Pattern.compile("https?://([^/]+)");
        Matcher matcher = domainPattern.matcher(url);
        if (matcher.find()) {
            String domain = matcher.group(1).toLowerCase();
            // Проверяем, не является ли домен внутренним
            return !domain.contains("localhost") &&
                    !domain.contains("127.0.0.1") &&
                    !domain.contains("internal") &&
                    !domain.contains("local") &&
                    !domain.contains("vbank.open.bankingapi.ru");
        }
        return false;
    }

    private boolean containsPathParameters(String path) {
        return path != null && path.contains("{");
    }

    private boolean containsSensitiveErrorInfo(String response) {
        if (response == null) return false;

        String[] sensitivePatterns = {
                "at java.", "at sun.", "Exception", "Error", "stack trace",
                "file path", "database", "password", "token", "secret",
                "internal", "debug", "traceId", "spanId", "sql",
                "connection string", "private key", "api key"
        };

        String lowerResponse = response.toLowerCase();
        for (String pattern : sensitivePatterns) {
            if (lowerResponse.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Новый метод для извлечения статус кода из различных типов ответов
     */
    private int extractStatusCode(Object response) {
        try {
            if (response instanceof core.ApiResponse) {
                return ((core.ApiResponse) response).getStatusCode();
            } else if (response instanceof HttpApiClient.ApiResponse) {
                return ((HttpApiClient.ApiResponse) response).getStatusCode();
            } else {
                return (int) response.getClass().getMethod("getStatusCode").invoke(response);
            }
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Обновленный метод для проверки ответов на уязвимости с использованием реальных статус кодов
     */
    private void checkResponseForVulnerabilities(HttpApiClient.ApiResponse apiResponse, String endpoint, String payload, List<Vulnerability> vulnerabilities) {
        int statusCode = apiResponse.getStatusCode();

        // Проверяем, не приняло ли приложение опасные данные
        if (statusCode == 200 || statusCode == 201) {
            Vulnerability vuln = createBaseVulnerability();
            vuln.setTitle("API10:2023 - Unsafe Processing of External Data");
            vuln.setDescription("Приложение некорректно обрабатывает потенциально опасные данные:\n" +
                    "• Эндпоинт: " + endpoint + "\n" +
                    "• Полезная нагрузка: " + (payload.length() > 100 ? payload.substring(0, 100) + "..." : payload) + "\n" +
                    "• Статус ответа: " + statusCode + "\n" +
                    "• Риск: Возможность внедрения вредоносных данных");
            vuln.setSeverity(Vulnerability.Severity.HIGH);
            vuln.setEvidence("Payload accepted at " + endpoint + " with status: " + statusCode);
            vuln.setStatusCode(statusCode);  // РЕАЛЬНЫЙ СТАТУС КОД
            vuln.setRecommendations(Arrays.asList(
                    "Реализовать строгую схему валидации для всех входящих данных",
                    "Использовать санитизацию входных данных",
                    "Внедрить Content Security Policy",
                    "Ограничить типы принимаемых данных"
            ));
            vulnerabilities.add(vuln);
        } else if (statusCode >= 500) {
            // ДОБАВЛЕНО: Уязвимости для серверных ошибок
            Vulnerability vuln = createBaseVulnerability();
            vuln.setTitle("API10:2023 - Server Error on Malicious Input");
            vuln.setDescription("Сервер возвращает ошибку " + statusCode + " при обработке подозрительных данных:\n" +
                    "• Эндпоинт: " + endpoint + "\n" +
                    "• Может свидетельствовать о нестабильности обработки внешних данных");
            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
            vuln.setEvidence("Server error " + statusCode + " at " + endpoint + " with malicious payload");
            vuln.setStatusCode(statusCode);  // РЕАЛЬНЫЙ СТАТУС КОД
            vulnerabilities.add(vuln);
        }
    }
}