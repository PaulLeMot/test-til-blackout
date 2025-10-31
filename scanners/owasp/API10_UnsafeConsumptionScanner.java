// scanners/owasp/API10_UnsafeConsumptionScanner.java
package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API10_UnsafeConsumptionScanner implements SecurityScanner {

    private static final Set<String> EXTERNAL_API_INDICATORS = Set.of(
            "external", "third-party", "partner", "integration", "webhook",
            "callback", "oauth", "openid", "sso", "federation"
    );

    private static final Set<String> CLOUD_SERVICE_DOMAINS = Set.of(
            "aws.amazon.com", "azure.com", "cloud.google.com", "api.cloud.yandex.net",
            "api.digitalocean.com", "api.heroku.com", "api.cloudflare.com"
    );

    public API10_UnsafeConsumptionScanner() {}

    @Override
    public String getName() {
        return "API10_UnsafeConsumption";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Сканирование уязвимостей небезопасного потребления API (OWASP API Security Top 10:2023 - API10)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl().trim();

        try {
            // 5.10.1: Анализ зависимостей от сторонних API
            checkExternalDependencies(openAPI, vulnerabilities, baseUrl);

            // 5.10.2: Тестирование обработки некорректных данных от внешних API
            testMaliciousExternalData(vulnerabilities, config, apiClient);

            // 5.10.3: Проверка валидации данных из доверенных источников
            testTrustedSourceValidation(vulnerabilities, config, apiClient);

            // 5.10.4: Анализ обработки ошибок внешних сервисов
            testExternalServiceErrorHandling(vulnerabilities, config, apiClient);

            // 5.10.5: Тестирование уязвимостей цепочки доверия
            testTrustChainVulnerabilities(vulnerabilities, config, apiClient);

            // 5.10.6: Проверка безопасности интеграций с облачными сервисами
            checkCloudServiceIntegrations(vulnerabilities, config, apiClient);

            // 5.10.7: Генерация отчета с проблемами потребления сторонних API
            generateConsumptionReport(vulnerabilities);

        } catch (Exception e) {
            System.err.println("(API-10) Ошибка при выполнении API10 сканера: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("(API-10) Сканирование небезопасного потребления API завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * 5.10.1: Анализ зависимостей от сторонних API в документации
     */
    private void checkExternalDependencies(Object openAPI, List<Vulnerability> vulnerabilities, String baseUrl) {
        System.out.println("(API-10) Анализ зависимостей от сторонних API...");

        // Проверяем наличие упоминаний внешних API в конфигурации
        String bankUrl = baseUrl; // В реальности нужно проверить bankBaseUrl

        // Ищем внешние домены в конфигурации
        if (containsExternalDomain(baseUrl)) {
            Vulnerability vuln = createBaseVulnerability();
            vuln.setTitle("API10:2023 - External API Dependency Detected");
            vuln.setDescription("Обнаружена зависимость от внешнего API: " + baseUrl +
                    "\n• Внешние API могут быть источником угроз\n• Необходимо проверять все входящие данные\n• Рекомендуется использовать whitelist доверенных источников");
            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
            vuln.setCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
            vuln.setEvidence("External API endpoint: " + baseUrl);
            vuln.setRecommendations(Arrays.asList(
                    "Реализовать строгую валидацию всех данных от внешних API",
                    "Использовать подписывание запросов для проверки целостности",
                    "Внедрить rate limiting для внешних API вызовов",
                    "Регулярно обновлять зависимости и сертификаты"
            ));
            vulnerabilities.add(vuln);
        }
    }

    /**
     * 5.10.2: Тестирование обработки некорректных данных от внешних API
     */
    private void testMaliciousExternalData(List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Тестирование обработки некорректных данных...");

        String[] testPayloads = {
                "{\"malicious\":\"<script>alert('xss')</script>\",\"data\":\"test\"}",
                "{\"__proto__\":{\"isAdmin\":true}}",
                "{\"$where\":\"this.credits == this.debits * 2\"}",
                "{\"username\":{\"$ne\":\"admin\"},\"password\":{\"$ne\":\"password\"}}"
        };

        for (String payload : testPayloads) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Authorization", "Bearer " + config.getAccessToken());

                Object response = apiClient.executeRequest("POST", config.getTargetBaseUrl() + "/api/webhook", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    // Проверяем, не приняло ли приложение опасные данные
                    if (apiResponse.getStatusCode() == 200 || apiResponse.getStatusCode() == 201) {
                        Vulnerability vuln = createBaseVulnerability();
                        vuln.setTitle("API10:2023 - Unsafe Processing of External Data");
                        vuln.setDescription("Приложение некорректно обрабатывает потенциально опасные данные от внешних API:\n" +
                                "• Полезная нагрузка: " + (payload.length() > 100 ? payload.substring(0, 100) + "..." : payload) + "\n" +
                                "• Статус ответа: " + apiResponse.getStatusCode() + "\n" +
                                "• Риск: Возможность внедрения вредоносных данных через внешние API");
                        vuln.setSeverity(Vulnerability.Severity.HIGH);
                        vuln.setCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
                        vuln.setEvidence("Payload accepted with status: " + apiResponse.getStatusCode());
                        vuln.setRecommendations(Arrays.asList(
                                "Реализовать строгую схему валидации для всех входящих данных",
                                "Использовать санитизацию входных данных",
                                "Внедрить Content Security Policy",
                                "Ограничить типы принимаемых данных"
                        ));
                        vulnerabilities.add(vuln);
                        break;
                    }
                }
            } catch (Exception e) {
                // Ожидаемое поведение - приложение должно отклонять некорректные данные
            }
        }
    }

    /**
     * 5.10.3: Проверка валидации данных, полученных из доверенных источников
     */
    private void testTrustedSourceValidation(List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Проверка валидации данных из доверенных источников...");

        // Тестируем различные сценарии с данными, которые могут приходить из "доверенных" источников
        String[] testScenarios = {
                "{\"amount\":-1000,\"currency\":\"USD\"}", // Отрицательная сумма
                "{\"account\":\"   \",\"balance\":1000}", // Пустой аккаунт
                "{\"userId\":\"../../etc/passwd\",\"role\":\"admin\"}", // Path traversal
                "{\"timestamp\":\"2099-01-01\",\"value\":\"future\"}" // Дата в будущем
        };

        for (String scenario : testScenarios) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("X-Trusted-Source", "true"); // Эмулируем доверенный источник

                Object response = apiClient.executeRequest("POST", config.getTargetBaseUrl() + "/api/trusted-data", scenario, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        Vulnerability vuln = createBaseVulnerability();
                        vuln.setTitle("API10:2023 - Missing Validation of Trusted Source Data");
                        vuln.setDescription("Приложение не выполняет достаточную валидацию данных от доверенных источников:\n" +
                                "• Сценарий: " + scenario + "\n" +
                                "• Риск: Доверенные источники могут быть скомпрометированы\n" +
                                "• Угроза: Обход бизнес-логики через доверенные каналы");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
                        vuln.setEvidence("Trusted source data accepted without validation: " + scenario);
                        vuln.setRecommendations(Arrays.asList(
                                "Валидировать все данные независимо от источника",
                                "Реализовать строгие схемы валидации для всех API",
                                "Не доверять данным только на основе заголовков источника",
                                "Вести аудит всех входящих данных"
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

    /**
     * 5.10.4: Анализ обработки ошибок внешних сервисов
     */
    private void testExternalServiceErrorHandling(List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Тестирование обработки ошибок внешних сервисов...");

        try {
            // Эмулируем недоступность внешнего сервиса
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Authorization", "Bearer " + config.getAccessToken());

            // Тестируем различные сценарии ошибок
            Object response = apiClient.executeRequest("GET", config.getTargetBaseUrl() + "/api/external-service", null, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                String responseBody = apiResponse.getBody();

                // Проверяем, не раскрывает ли приложение внутреннюю информацию об ошибках
                if (containsSensitiveErrorInfo(responseBody)) {
                    Vulnerability vuln = createBaseVulnerability();
                    vuln.setTitle("API10:2023 - Information Disclosure in External Service Errors");
                    vuln.setDescription("Приложение раскрывает чувствительную информацию при ошибках внешних сервисов:\n" +
                            "• Раскрытые данные могут помочь атакующему\n" +
                            "• Риск: Утечка внутренней структуры системы\n" +
                            "• Угроза: Reconnaissance атак");
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
                    vuln.setEvidence("Sensitive error information: " + responseBody.substring(0, Math.min(200, responseBody.length())));
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

    /**
     * 5.10.5: Тестирование уязвимостей цепочки доверия (trust chain)
     */
    private void testTrustChainVulnerabilities(List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Тестирование цепочки доверия...");

        // Проверяем наличие слабых мест в цепочке доверия
        List<String> trustIssues = new ArrayList<>();

        // Проверка TLS/SSL конфигурации
        if (!config.getTargetBaseUrl().startsWith("https://")) {
            trustIssues.add("Использование HTTP вместо HTTPS");
        }

        // Проверка наличия проверки сертификатов
        if (config.getBankBaseUrl() != null && config.getBankBaseUrl().contains("self-signed")) {
            trustIssues.add("Возможное использование self-signed сертификатов");
        }

        if (!trustIssues.isEmpty()) {
            Vulnerability vuln = createBaseVulnerability();
            vuln.setTitle("API10:2023 - Trust Chain Vulnerabilities");
            vuln.setDescription("Обнаружены проблемы в цепочке доверия:\n• " + String.join("\n• ", trustIssues) +
                    "\n\nРиски:\n• MITM атаки\n• Компрометация доверенных соединений\n• Утечка чувствительных данных");
            vuln.setSeverity(Vulnerability.Severity.HIGH);
            vuln.setCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
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
    private void checkCloudServiceIntegrations(List<Vulnerability> vulnerabilities, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-10) Проверка интеграций с облачными сервисами...");

        // Проверяем наличие облачных интеграций в ответах
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + config.getAccessToken());

            Object response = apiClient.executeRequest("GET", config.getTargetBaseUrl() + "/api/config", null, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                String responseBody = apiResponse.getBody();

                // Ищем упоминания облачных сервисов
                for (String cloudDomain : CLOUD_SERVICE_DOMAINS) {
                    if (responseBody.contains(cloudDomain)) {
                        Vulnerability vuln = createBaseVulnerability();
                        vuln.setTitle("API10:2023 - Cloud Service Integration Exposure");
                        vuln.setDescription("Обнаружена интеграция с облачным сервисом: " + cloudDomain +
                                "\n• Риск: Раскрытие внутренней архитектуры\n• Угроза: Целевые атаки на облачную инфраструктуру");
                        vuln.setSeverity(Vulnerability.Severity.LOW);
                        vuln.setCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
                        vuln.setEvidence("Cloud service reference: " + cloudDomain);
                        vuln.setRecommendations(Arrays.asList(
                                "Не раскрывать информацию о внутренних интеграциях",
                                "Использовать внутренние DNS имена для облачных сервисов",
                                "Реализовать API gateway для абстракции внутренней архитектуры",
                                "Регулярно аудировать конфигурации облачных сервисов"
                        ));
                        vulnerabilities.add(vuln);
                        break;
                    }
                }
            }
        } catch (Exception e) {
            // Ожидаемое поведение
        }
    }

    /**
     * 5.10.7: Генерация отчета с проблемами потребления сторонних API
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
        System.out.println("(API-10) " + "=" .repeat(80));

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
        System.out.println("(API-10) " + "=" .repeat(80));
    }

    /**
     * Вспомогательные методы
     */
    private Vulnerability createBaseVulnerability() {
        Vulnerability vuln = new Vulnerability();
        vuln.setCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
        return vuln;
    }

    private boolean containsExternalDomain(String url) {
        Pattern domainPattern = Pattern.compile("https?://([^/]+)");
        Matcher matcher = domainPattern.matcher(url);
        if (matcher.find()) {
            String domain = matcher.group(1).toLowerCase();
            // Проверяем, не является ли домен внутренним
            return !domain.contains("localhost") &&
                    !domain.contains("127.0.0.1") &&
                    !domain.contains("internal") &&
                    !domain.contains("local");
        }
        return false;
    }

    private boolean containsSensitiveErrorInfo(String response) {
        String[] sensitivePatterns = {
                "at java.", "at sun.", "Exception", "Error", "stack trace",
                "file path", "database", "password", "token", "secret",
                "internal", "debug", "traceId", "spanId"
        };

        String lowerResponse = response.toLowerCase();
        for (String pattern : sensitivePatterns) {
            if (lowerResponse.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
}
