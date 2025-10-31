// scanners/owasp/API8_SecurityConfigScanner.java
package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API8_SecurityConfigScanner implements SecurityScanner {

    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            "authorization", "cookie", "x-api-key", "x-auth-token",
            "x-requesting-bank", "x-consent-id", "x-payment-consent-id",
            "x-fapi-interaction-id", "x-bank-auth-token", "client_secret"
    );

    private static final Set<String> DANGEROUS_METHODS = Set.of(
            "TRACE", "OPTIONS", "HEAD"
    );

    private static final Set<String> BANK_SENSITIVE_PATHS = Set.of(
            "/.git", "/.env", "/config", "/backup", "/admin", "/test",
            "/.git/config", "/.env.backup", "/web.config", "/appsettings.json",
            "/phpinfo.php", "/debug", "/trace", "/.DS_Store",
            // Банковские специфичные пути
            "/.well-known/jwks.json", "/auth/bank-token", "/admin/teams",
            "/interbank/transfers", "/admin/capital", "/admin/key-rate",
            "/banker/clients", "/payment-consents/pending/list"
    );

    // Банковские специфичные endpoints для глубокой проверки
    private static final Set<String> BANK_CRITICAL_ENDPOINTS = Set.of(
            "/accounts", "/auth/bank-token", "/account-consents/request",
            "/payments", "/payment-consents/request", "/interbank/receive",
            "/admin/capital", "/admin/teams", "/banker/clients"
    );

    // Паттерны для поиска чувствительной информации в ответах
    private static final Pattern JWT_PATTERN = Pattern.compile("eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*");
    private static final Pattern API_KEY_PATTERN = Pattern.compile("[a-zA-Z0-9]{32,64}");
    private static final Pattern ACCOUNT_NUMBER_PATTERN = Pattern.compile("\\d{16,20}");

    public API8_SecurityConfigScanner() {}

    @Override
    public String getName() {
        return "API8_SecurityConfig";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-8) Сканирование уязвимостей Security Misconfiguration (OWASP API Security Top 10:2023 - API8)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl().trim();

        try {
            // 5.8.1: Анализ информативных заголовков
            vulnerabilities.addAll(checkInformativeHeaders(baseUrl, apiClient));

            // 5.8.2: Проверка CORS для банковских endpoints
            vulnerabilities.addAll(checkBankCORSConfiguration(baseUrl, apiClient));

            // 5.8.3: Поиск debug-режимов и stack traces в банковских ответах
            vulnerabilities.addAll(checkBankDebugInfo(baseUrl, apiClient));

            // 5.8.4: Проверка ненужных HTTP методов для банковских API
            vulnerabilities.addAll(checkBankUnnecessaryMethods(baseUrl, apiClient));

            // 5.8.5: Анализ HTTPS и редиректов для финансового API
            vulnerabilities.addAll(checkBankHTTPSConfiguration(baseUrl, apiClient));

            // 5.8.6: Поиск backup-файлов и конфигов в банковском контексте
            vulnerabilities.addAll(checkBankSensitiveFiles(baseUrl, apiClient));

            // 5.8.7: Проверка security headers для финансовых данных
            vulnerabilities.addAll(checkBankSecurityHeaders(baseUrl, apiClient));

            // 5.8.8: Анализ кэширования банковских данных
            vulnerabilities.addAll(checkBankCachingConfiguration(baseUrl, apiClient));

            // 5.8.9: Проверка экспозиции чувствительной информации в ответах
            vulnerabilities.addAll(checkSensitiveDataExposure(baseUrl, apiClient));

            // 5.8.10: Проверка конфигурации межбанковских endpoints
            vulnerabilities.addAll(checkInterbankSecurity(baseUrl, apiClient));

        } catch (Exception e) {
            System.err.println("(API-8) Ошибка при сканировании конфигурации безопасности банковского API: " + e.getMessage());
        }

        System.out.println("(API-8) Сканирование Security Configuration завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    // 5.8.1: Анализ информативных заголовков с учетом банковского контекста
    private List<Vulnerability> checkInformativeHeaders(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        try {
            Object response = apiClient.executeRequest("GET", baseUrl, null, null);
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                Map<String, List<String>> headers = apiResponse.getHeaders();

                checkHeader(vulns, headers, "server", "Раскрытие информации о сервере", baseUrl);
                checkHeader(vulns, headers, "x-powered-by", "Раскрытие информации о технологиях", baseUrl);
                checkHeader(vulns, headers, "x-aspnet-version", "Раскрытие информации о ASP.NET", baseUrl);
                checkHeader(vulns, headers, "x-aspnetmvc-version", "Раскрытие информации о ASP.NET MVC", baseUrl);

                // Банковские специфичные проверки
                if (headers.containsKey("x-api-version")) {
                    String version = headers.get("x-api-version").toString();
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("API8:2023 - Security Misconfiguration - API Version Exposure");
                    vuln.setDescription("Заголовок x-api-version раскрывает версию банковского API: " + version + 
                                       ". Доказательство: в ответах сервера присутствует заголовок x-api-version со значением " + version + 
                                       ", что раскрывает информацию о версии API потенциальным злоумышленникам.");
                    vuln.setSeverity(Vulnerability.Severity.LOW);
                    vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                    vuln.setEndpoint("/");
                    vuln.setStatusCode(200);
                    vuln.setEvidence(String.format("{\"header\":\"x-api-version\", \"value\":\"%s\"}", version));
                    vuln.setRecommendations(Arrays.asList(
                            "Удалите или ограничьте информацию о версии API в заголовках",
                            "Используйте versioning через URL path вместо заголовков",
                            "Минимизируйте раскрытие информации о внутренней структуре"
                    ));
                    vulns.add(vuln);
                    System.out.println("(API-8) УЯЗВИМОСТЬ: Раскрытие версии API через заголовок x-api-version: " + version);
                }
            }
        } catch (Exception e) {
            System.err.println("(API-8) Ошибка при проверке информативных заголовков: " + e.getMessage());
        }

        return vulns;
    }

    private void checkHeader(List<Vulnerability> vulns, Map<String, List<String>> headers,
                             String headerName, String description, String endpoint) {
        if (headers.containsKey(headerName.toLowerCase())) {
            String headerValue = headers.get(headerName.toLowerCase()).toString();

            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("API8:2023 - Security Misconfiguration - Informative Header");
            vuln.setDescription(description + ": заголовок " + headerName + " раскрывает информацию о системе. " +
                              "Доказательство: обнаружен заголовок " + headerName + " со значением " + headerValue + 
                              " в ответах сервера, что предоставляет информацию о внутренней инфраструктуре.");
            vuln.setSeverity(Vulnerability.Severity.LOW);
            vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
            vuln.setEndpoint(endpoint);
            vuln.setStatusCode(200);
            vuln.setEvidence(String.format(
                    "{\"header\":\"%s\", \"value\":\"%s\", \"risk\":\"%s\"}",
                    headerName, headerValue, description
            ));
            vuln.setRecommendations(Arrays.asList(
                    "Удалите или измените информативные заголовки",
                    "Используйте минимальное раскрытие информации о системе",
                    "Настройте веб-сервер для скрытия версий ПО"
            ));

            vulns.add(vuln);
            System.out.println("(API-8) УЯЗВИМОСТЬ: Информативный заголовок " + headerName + " раскрывает информацию: " + headerValue);
        }
    }

    // 5.8.2: Проверка CORS конфигурации для банковских endpoints
    private List<Vulnerability> checkBankCORSConfiguration(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        // Проверяем основные банковские endpoints
        String[] bankEndpoints = {"/accounts", "/auth/bank-token", "/payment-consents/request"};

        for (String endpoint : bankEndpoints) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Origin", "https://malicious-bank.com");

                Object response = apiClient.executeRequest("OPTIONS", baseUrl + endpoint, null, headers);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    Map<String, List<String>> responseHeaders = apiResponse.getHeaders();

                    if (responseHeaders.containsKey("access-control-allow-origin")) {
                        String allowOrigin = responseHeaders.get("access-control-allow-origin").toString();

                        if ("*".equals(allowOrigin) || allowOrigin.contains("malicious-bank.com")) {
                            Vulnerability vuln = new Vulnerability();
                            vuln.setTitle("API8:2023 - Security Misconfiguration - CORS Misconfiguration");
                            vuln.setDescription("Небезопасная конфигурация CORS на банковском endpoint " + endpoint + ": разрешены запросы с любых доменов. " +
                                              "Доказательство: сервер вернул заголовок Access-Control-Allow-Origin: " + allowOrigin + 
                                              " в ответ на запрос с Origin: https://malicious-bank.com, что позволяет межсайтовые запросы к банковским данным.");
                            vuln.setSeverity(Vulnerability.Severity.HIGH);
                            vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                            vuln.setEndpoint(endpoint);
                            vuln.setStatusCode(apiResponse.getStatusCode());
                            vuln.setEvidence(String.format(
                                    "{\"endpoint\":\"%s\", \"access-control-allow-origin\":\"%s\", \"origin\":\"https://malicious-bank.com\"}",
                                    endpoint, allowOrigin
                            ));
                            vuln.setRecommendations(Arrays.asList(
                                    "Ограничьте Access-Control-Allow-Origin конкретными доверенными доменами банков-партнеров",
                                    "Реализуйте проверку Origin на сервере для межбанковских запросов",
                                    "Используйте белые списки для CORS в финансовом API",
                                    "Для публичных endpoints используйте строгие ограничения"
                            ));

                            vulns.add(vuln);
                            System.out.println("(API-8) УЯЗВИМОСТЬ: Небезопасная конфигурация CORS для " + endpoint + 
                                             ". Разрешены запросы с: " + allowOrigin);
                        }
                    }
                }
            } catch (Exception e) {
                // OPTIONS может не поддерживаться - это нормально для некоторых endpoints
            }
        }

        return vulns;
    }

    // 5.8.3: Поиск debug-информации в банковских ответах
    private List<Vulnerability> checkBankDebugInfo(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        // Тестируем различные банковские endpoints на раскрытие debug информации
        String[] testEndpoints = {
                "/accounts/invalid-account-123",
                "/auth/invalid-token-endpoint",
                "/payment-consents/invalid-consent-456",
                "/interbank/check-account/invalid-account-789"
        };

        for (String endpoint : testEndpoints) {
            try {
                Object response = apiClient.executeRequest("GET", baseUrl + endpoint, null, null);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    String body = apiResponse.getBody().toLowerCase();

                    List<String> debugIndicators = Arrays.asList(
                            "stack trace", "at line", "debug", "exception", "error in",
                            "file://", "c:\\", "d:\\", "fatal error", "null pointer",
                            "sql exception", "database error", "query failed",
                            "internal server error", "traceback", "debug mode"
                    );

                    for (String indicator : debugIndicators) {
                        if (body.contains(indicator)) {
                            Vulnerability vuln = new Vulnerability();
                            vuln.setTitle("API8:2023 - Security Misconfiguration - Debug Information Exposure");
                            vuln.setDescription("В ответах ошибок банковского API раскрывается отладочная информация: " + indicator + 
                                              ". Доказательство: в ответе на запрос к " + endpoint + " обнаружен индикатор '" + indicator + 
                                              "', что свидетельствует о включенном debug режиме или некорректной обработке ошибок.");
                            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                            vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                            vuln.setEndpoint(endpoint);
                            vuln.setStatusCode(apiResponse.getStatusCode());
                            vuln.setEvidence(String.format(
                                    "{\"endpoint\":\"%s\", \"debug_indicator\":\"%s\", \"response_preview\":\"%s\"}",
                                    endpoint, indicator, body.substring(0, Math.min(200, body.length()))
                            ));
                            vuln.setRecommendations(Arrays.asList(
                                    "Отключите отладочный режим в production среде банковского API",
                                    "Настройте кастомные обработчики ошибок без раскрытия внутренней информации",
                                    "Используйте единый формат ошибок для клиентов",
                                    "Логируйте детальную информацию только во внутренние системы"
                            ));

                            vulns.add(vuln);
                            System.out.println("(API-8) УЯЗВИМОСТЬ: Раскрытие debug информации в " + endpoint + 
                                             ". Обнаружен индикатор: " + indicator);
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                // Endpoint не существует - это ожидаемо
            }
        }

        return vulns;
    }

    // 5.8.4: Проверка ненужных HTTP методов для банковских API
    private List<Vulnerability> checkBankUnnecessaryMethods(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        String[] bankEndpoints = {"/accounts", "/auth/bank-token", "/payments", "/interbank/receive"};

        for (String endpoint : bankEndpoints) {
            for (String method : DANGEROUS_METHODS) {
                try {
                    Object response = apiClient.executeRequest(method, baseUrl + endpoint, null, null);
                    if (response instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                        if (apiResponse.getStatusCode() != 405 && apiResponse.getStatusCode() != 403) {
                            Vulnerability vuln = new Vulnerability();
                            vuln.setTitle("API8:2023 - Security Misconfiguration - Unnecessary HTTP Method");
                            vuln.setDescription("Разрешен потенциально опасный HTTP метод " + method + " на банковском endpoint: " + endpoint + 
                                              ". Доказательство: метод " + method + " возвращает статус " + apiResponse.getStatusCode() + 
                                              " вместо ожидаемого 405 (Method Not Allowed) или 403 (Forbidden).");
                            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                            vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                            vuln.setEndpoint(endpoint);
                            vuln.setStatusCode(apiResponse.getStatusCode());
                            vuln.setEvidence(String.format(
                                    "{\"endpoint\":\"%s\", \"method\":\"%s\", \"status\":%d, \"risk\":\"information_disclosure\"}",
                                    endpoint, method, apiResponse.getStatusCode()
                            ));
                            vuln.setRecommendations(Arrays.asList(
                                    "Отключите ненужные HTTP методы (TRACE, OPTIONS, HEAD) на веб-сервере",
                                    "Настройте WAF для блокировки опасных методов на банковских endpoints",
                                    "Разрешайте только необходимые методы: GET, POST, PUT, DELETE, PATCH",
                                    "Реализуйте проверку методов на уровне application"
                            ));

                            vulns.add(vuln);
                            System.out.println("(API-8) УЯЗВИМОСТЬ: Разрешен опасный HTTP метод " + method + " для " + endpoint + 
                                             ". Статус: " + apiResponse.getStatusCode());
                        }
                    }
                } catch (Exception e) {
                    // Метод не поддерживается - это нормально
                }
            }
        }

        return vulns;
    }

    // 5.8.5: Анализ HTTPS конфигурации для финансового API
    private List<Vulnerability> checkBankHTTPSConfiguration(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        try {
            // Проверяем, использует ли банковский API HTTPS
            if (baseUrl.startsWith("https://")) {
                // Проверяем наличие HSTS
                Object response = apiClient.executeRequest("GET", baseUrl, null, null);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    Map<String, List<String>> headers = apiResponse.getHeaders();

                    if (!headers.containsKey("strict-transport-security")) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("API8:2023 - Security Misconfiguration - Missing HSTS");
                        vuln.setDescription("Отсутствует заголовок Strict-Transport-Security (HSTS) в банковском API. " +
                                          "Доказательство: HTTPS соединение установлено, но заголовок HSTS отсутствует в ответах сервера, " +
                                          "что оставляет возможность для SSL stripping атак.");
                        vuln.setSeverity(Vulnerability.Severity.HIGH);
                        vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                        vuln.setEndpoint("/");
                        vuln.setStatusCode(apiResponse.getStatusCode());
                        vuln.setEvidence("{\"missing_header\":\"strict-transport-security\", \"risk\":\"ssl_stripping\"}");
                        vuln.setRecommendations(Arrays.asList(
                                "Добавьте заголовок Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                                "Настройте редирект с HTTP на HTTPS",
                                "Используйте HSTS preload list для дополнительной защиты"
                        ));

                        vulns.add(vuln);
                        System.out.println("(API-8) УЯЗВИМОСТЬ: Отсутствует заголовок HSTS при использовании HTTPS");
                    }

                    // Проверяем версию TLS (косвенно)
                    if (headers.containsKey("server")) {
                        String server = headers.get("server").toString();
                        if (server.contains("nginx") || server.contains("apache") || server.contains("iis")) {
                            // Предполагаем, что могут быть устаревшие конфигурации
                            Vulnerability vuln = new Vulnerability();
                            vuln.setTitle("API8:2023 - Security Misconfiguration - Potential TLS Issues");
                            vuln.setDescription("Возможные проблемы с конфигурацией TLS в банковском API. " +
                                              "Доказательство: сервер использует " + server + ", что может указывать на устаревшую конфигурацию TLS.");
                            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                            vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                            vuln.setEndpoint("/");
                            vuln.setStatusCode(apiResponse.getStatusCode());
                            vuln.setEvidence(String.format("{\"server\":\"%s\", \"risk\":\"potential_tls_issues\"}", server));
                            vuln.setRecommendations(Arrays.asList(
                                    "Отключите устаревшие версии TLS (TLS 1.0, TLS 1.1)",
                                    "Используйте современные шифры и протоколы",
                                    "Настройте forward secrecy",
                                    "Регулярно обновляйте SSL/TLS конфигурацию"
                            ));

                            vulns.add(vuln);
                            System.out.println("(API-8) УЯЗВИМОСТЬ: Возможные проблемы с TLS конфигурацией. Сервер: " + server);
                        }
                    }
                }
            } else {
                // Bank API использует HTTP - критическая уязвимость
                Vulnerability vuln = new Vulnerability();
                vuln.setTitle("API8:2023 - Security Misconfiguration - HTTP Usage in Banking API");
                vuln.setDescription("Банковский API использует HTTP вместо HTTPS - критическая уязвимость! " +
                                  "Доказательство: API доступен по протоколу HTTP, что позволяет перехват и модификацию финансовых данных.");
                vuln.setSeverity(Vulnerability.Severity.CRITICAL);
                vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                vuln.setEndpoint("/");
                vuln.setStatusCode(200);
                vuln.setEvidence("{\"protocol\":\"http\", \"risk\":\"data_interception_manipulation\"}");
                vuln.setRecommendations(Arrays.asList(
                        "НЕМЕДЛЕННО внедрите HTTPS для всего трафика банковского API",
                        "Настройте редирект с HTTP на HTTPS",
                        "Используйте SSL/TLS сертификаты от доверенного Certificate Authority",
                        "Реализуйте certificate pinning для мобильных приложений"
                ));

                vulns.add(vuln);
                System.out.println("(API-8) УЯЗВИМОСТЬ: КРИТИЧЕСКАЯ - Банковский API использует HTTP вместо HTTPS");
            }
        } catch (Exception e) {
            System.err.println("(API-8) Ошибка при проверке HTTPS: " + e.getMessage());
        }

        return vulns;
    }

    // 5.8.6: Поиск backup-файлов и конфигов в банковском контексте
    private List<Vulnerability> checkBankSensitiveFiles(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        for (String path : BANK_SENSITIVE_PATHS) {
            try {
                Object response = apiClient.executeRequest("GET", baseUrl + path, null, null);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("API8:2023 - Security Misconfiguration - Sensitive File Exposure");
                        vuln.setDescription("Обнаружен доступ к чувствительному файлу или директории в банковской системе: " + path + 
                                          ". Доказательство: файл " + path + " доступен по HTTP с статусом 200, что раскрывает конфиденциальную информацию.");
                        vuln.setSeverity(Vulnerability.Severity.HIGH);
                        vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                        vuln.setEndpoint(path);
                        vuln.setStatusCode(200);
                        vuln.setEvidence(String.format(
                                "{\"sensitive_path\":\"%s\", \"status\":%d, \"risk\":\"information_disclosure\"}",
                                path, apiResponse.getStatusCode()
                        ));
                        vuln.setRecommendations(Arrays.asList(
                                "НЕМЕДЛЕННО удалите backup-файлы и конфиги из public directory",
                                "Настройте веб-сервер для запрета доступа к чувствительным путям",
                                "Регулярно проводите аудит файловой системы на наличие случайно опубликованных файлов",
                                "Используйте .htaccess или эквивалент для блокировки доступа к системным файлам"
                        ));

                        vulns.add(vuln);
                        System.out.println("(API-8) УЯЗВИМОСТЬ: Обнаружен доступ к чувствительному файлу: " + path);
                    }
                }
            } catch (Exception e) {
                // Файл не найден - это нормально
            }
        }

        return vulns;
    }

    // 5.8.7: Проверка security headers для финансовых данных
    private List<Vulnerability> checkBankSecurityHeaders(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        try {
            Object response = apiClient.executeRequest("GET", baseUrl, null, null);
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                Map<String, List<String>> headers = apiResponse.getHeaders();

                checkSecurityHeader(vulns, headers, "content-security-policy",
                        "Отсутствует Content-Security-Policy header в банковском API");
                checkSecurityHeader(vulns, headers, "x-content-type-options",
                        "Отсутствует X-Content-Type-Options header в банковском API");
                checkSecurityHeader(vulns, headers, "x-frame-options",
                        "Отсутствует X-Frame-Options header в банковском API");
                checkSecurityHeader(vulns, headers, "x-xss-protection",
                        "Отсутствует X-XSS-Protection header в банковском API");
                checkSecurityHeader(vulns, headers, "referrer-policy",
                        "Отсутствует Referrer-Policy header в банковском API");

                // Банковские специфичные проверки
                if (headers.containsKey("x-content-type-options")) {
                    String value = headers.get("x-content-type-options").toString();
                    if (!value.toLowerCase().contains("nosniff")) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("API8:2023 - Security Misconfiguration - Incorrect X-Content-Type-Options");
                        vuln.setDescription("Некорректное значение X-Content-Type-Options header: " + value + 
                                          ". Доказательство: заголовок присутствует, но имеет некорректное значение '" + value + "' вместо 'nosniff'.");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                        vuln.setEndpoint("/");
                        vuln.setStatusCode(200);
                        vuln.setEvidence(String.format("{\"header\":\"x-content-type-options\", \"value\":\"%s\"}", value));
                        vuln.setRecommendations(Arrays.asList(
                                "Установите X-Content-Type-Options: nosniff",
                                "Это предотвращает MIME-sniffing атаки для банковских данных"
                        ));
                        vulns.add(vuln);
                        System.out.println("(API-8) УЯЗВИМОСТЬ: Некорректное значение X-Content-Type-Options: " + value);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("(API-8) Ошибка при проверке security headers: " + e.getMessage());
        }

        return vulns;
    }

    private void checkSecurityHeader(List<Vulnerability> vulns, Map<String, List<String>> headers,
                                     String headerName, String description) {
        if (!headers.containsKey(headerName.toLowerCase())) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("API8:2023 - Security Misconfiguration - Missing Security Header");
            vuln.setDescription(description + ". Доказательство: обязательный security header '" + headerName + "' отсутствует в ответах сервера.");
            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
            vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
            vuln.setEndpoint("/");
            vuln.setStatusCode(200);
            vuln.setEvidence(String.format("{\"missing_header\":\"%s\"}", headerName));

            switch (headerName) {
                case "content-security-policy":
                    vuln.setRecommendations(Arrays.asList(
                            "Добавьте Content-Security-Policy header для банковского web interface",
                            "Настройте политику для ограничения источников скриптов, стилей и т.д.",
                            "Используйте report-uri для мониторинга нарушений"
                    ));
                    break;
                case "x-content-type-options":
                    vuln.setRecommendations(Arrays.asList(
                            "Добавьте X-Content-Type-Options: nosniff",
                            "Это предотвращает MIME-sniffing атаки для банковских данных"
                    ));
                    break;
                case "x-frame-options":
                    vuln.setRecommendations(Arrays.asList(
                            "Добавьте X-Frame-Options: DENY",
                            "Защищает от clickjacking атак на банковские интерфейсы"
                    ));
                    break;
                case "x-xss-protection":
                    vuln.setRecommendations(Arrays.asList(
                            "Добавьте X-XSS-Protection: 1; mode=block",
                            "Включает XSS защиту в браузерах для банковских приложений"
                    ));
                    break;
                case "referrer-policy":
                    vuln.setRecommendations(Arrays.asList(
                            "Добавьте Referrer-Policy: no-referrer",
                            "Контролирует передачу Referer header для банковских транзакций"
                    ));
                    break;
            }

            vulns.add(vuln);
            System.out.println("(API-8) УЯЗВИМОСТЬ: Отсутствует security header: " + headerName);
        }
    }

    // 5.8.8: Анализ кэширования банковских данных
    private List<Vulnerability> checkBankCachingConfiguration(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        // Проверяем кэширование на чувствительных банковских endpoints
        String[] sensitiveEndpoints = {"/accounts", "/auth/me", "/banker/clients"};

        for (String endpoint : sensitiveEndpoints) {
            try {
                Map<String, String> authHeaders = new HashMap<>();
                // Используем тестовый токен для проверки
                authHeaders.put("Authorization", "Bearer test-bank-token-123");

                Object response = apiClient.executeRequest("GET", baseUrl + endpoint, null, authHeaders);
                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                    Map<String, List<String>> headers = apiResponse.getHeaders();

                    if (headers.containsKey("cache-control")) {
                        String cacheControl = headers.get("cache-control").toString().toLowerCase();

                        if (!cacheControl.contains("no-store") && !cacheControl.contains("no-cache") &&
                                !cacheControl.contains("private")) {
                            Vulnerability vuln = new Vulnerability();
                            vuln.setTitle("API8:2023 - Security Misconfiguration - Sensitive Banking Data Caching");
                            vuln.setDescription("Чувствительные банковские данные могут кэшироваться: " + cacheControl + 
                                              ". Доказательство: заголовок Cache-Control содержит '" + cacheControl + 
                                              "', что позволяет кэширование чувствительных банковских данных.");
                            vuln.setSeverity(Vulnerability.Severity.HIGH);
                            vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                            vuln.setEndpoint(endpoint);
                            vuln.setStatusCode(apiResponse.getStatusCode());
                            vuln.setEvidence(String.format(
                                    "{\"endpoint\":\"%s\", \"cache_control\":\"%s\", \"risk\":\"sensitive_banking_data_caching\"}",
                                    endpoint, cacheControl
                            ));
                            vuln.setRecommendations(Arrays.asList(
                                    "Добавьте Cache-Control: no-store для всех чувствительных банковских endpoints",
                                    "Используйте no-cache или private для данных требующих валидации",
                                    "Запретите кэширование данных счетов, транзакций и клиентской информации",
                                    "Настройте кэширование только для публичных, нечувствительных данных"
                            ));

                            vulns.add(vuln);
                            System.out.println("(API-8) УЯЗВИМОСТЬ: Небезопасное кэширование банковских данных в " + endpoint + 
                                             ". Cache-Control: " + cacheControl);
                        }
                    } else {
                        // Отсутствует cache-control header
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("API8:2023 - Security Misconfiguration - Missing Cache Control");
                        vuln.setDescription("Отсутствует Cache-Control header для чувствительного банковского endpoint: " + endpoint + 
                                          ". Доказательство: заголовок Cache-Control отсутствует, что позволяет браузерам и промежуточным прокси кэшировать данные по умолчанию.");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                        vuln.setEndpoint(endpoint);
                        vuln.setStatusCode(apiResponse.getStatusCode());
                        vuln.setEvidence(String.format("{\"endpoint\":\"%s\", \"risk\":\"missing_cache_control\"}", endpoint));
                        vuln.setRecommendations(Arrays.asList(
                                "Добавьте Cache-Control: no-store для защиты банковских данных",
                                "Настройте соответствующие cache headers для всех endpoints",
                                "Проверьте конфигурацию кэширования прокси и CDN"
                        ));

                        vulns.add(vuln);
                        System.out.println("(API-8) УЯЗВИМОСТЬ: Отсутствует Cache-Control header для " + endpoint);
                    }
                }
            } catch (Exception e) {
                System.err.println("(API-8) Ошибка при проверке кэширования для " + endpoint + ": " + e.getMessage());
            }
        }

        return vulns;
    }

    // 5.8.9: Проверка экспозиции чувствительной информации в ответах
    private List<Vulnerability> checkSensitiveDataExposure(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        try {
            // Проверяем публичные endpoints на раскрытие чувствительной информации
            Object response = apiClient.executeRequest("GET", baseUrl + "/.well-known/jwks.json", null, null);
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                String body = apiResponse.getBody();

                // Проверяем на наличие JWT токенов в ответах
                Matcher jwtMatcher = JWT_PATTERN.matcher(body);
                if (jwtMatcher.find()) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("API8:2023 - Security Misconfiguration - JWT Token Exposure");
                    vuln.setDescription("В ответах обнаружены JWT токены. Доказательство: в теле ответа обнаружен JWT токен формата 'eyJ...', что раскрывает аутентификационные данные.");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                    vuln.setEndpoint("/.well-known/jwks.json");
                    vuln.setStatusCode(apiResponse.getStatusCode());
                    vuln.setEvidence(String.format(
                            "{\"jwt_found\":\"%s\", \"risk\":\"token_exposure\"}",
                            jwtMatcher.group().substring(0, Math.min(50, jwtMatcher.group().length()))
                    ));
                    vuln.setRecommendations(Arrays.asList(
                            "Убедитесь, что JWT токены не попадают в публичные ответы",
                            "Используйте разные токены для разных целей (access, refresh)",
                            "Реализуйте proper token management",
                            "Логируйте токены только в замаскированном виде"
                    ));

                    vulns.add(vuln);
                    System.out.println("(API-8) УЯЗВИМОСТЬ: Обнаружены JWT токены в публичных ответах");
                }

                // Проверяем на наличие API ключей
                Matcher apiKeyMatcher = API_KEY_PATTERN.matcher(body);
                if (apiKeyMatcher.find()) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("API8:2023 - Security Misconfiguration - API Key Exposure");
                    vuln.setDescription("В ответах обнаружены потенциальные API ключи. Доказательство: обнаружена строка, соответствующая формату API ключа: " + 
                                      apiKeyMatcher.group().substring(0, Math.min(20, apiKeyMatcher.group().length())));
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                    vuln.setEndpoint("/.well-known/jwks.json");
                    vuln.setStatusCode(apiResponse.getStatusCode());
                    vuln.setEvidence(String.format(
                            "{\"api_key_pattern_found\":\"%s\", \"risk\":\"credential_exposure\"}",
                            apiKeyMatcher.group().substring(0, Math.min(20, apiKeyMatcher.group().length()))
                    ));
                    vuln.setRecommendations(Arrays.asList(
                            "Убедитесь, что API ключи и секреты не попадают в публичные ответы",
                            "Используйте environment variables для хранения чувствительных данных",
                            "Регулярно ротируйте API ключи",
                            "Внедрите secret management system"
                    ));

                    vulns.add(vuln);
                    System.out.println("(API-8) УЯЗВИМОСТЬ: Обнаружены потенциальные API ключи в публичных ответах");
                }
            }
        } catch (Exception e) {
            System.err.println("(API-8) Ошибка при проверке экспозиции чувствительных данных: " + e.getMessage());
        }

        return vulns;
    }

    // 5.8.10: Проверка конфигурации межбанковских endpoints
    private List<Vulnerability> checkInterbankSecurity(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        try {
            // Проверяем межбанковские endpoints на безопасность
            Object response = apiClient.executeRequest("GET", baseUrl + "/interbank/check-account/test-account", null, null);
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                // Проверяем аутентификацию межбанковских endpoints
                if (apiResponse.getStatusCode() == 200) {
                    // Если endpoint доступен без аутентификации - это уязвимость
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("API8:2023 - Security Misconfiguration - Unauthenticated Interbank Access");
                    vuln.setDescription("Межбанковский endpoint доступен без proper authentication. " +
                                      "Доказательство: запрос к /interbank/check-account/test-account вернул статус 200 без предоставления аутентификационных данных.");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API8_SM);
                    vuln.setEndpoint("/interbank/check-account/{account_number}");
                    vuln.setStatusCode(200);
                    vuln.setEvidence("{\"endpoint\":\"/interbank/check-account/test-account\", \"status\":200, \"risk\":\"unauthenticated_access\"}");
                    vuln.setRecommendations(Arrays.asList(
                            "Реализуйте strict authentication для всех межбанковских endpoints",
                            "Используйте mutual TLS (mTLS) для банк-банк коммуникации",
                            "Внедрите подписание запросов между банками",
                            "Используйте whitelist IP адресов банков-партнеров"
                    ));

                    vulns.add(vuln);
                    System.out.println("(API-8) УЯЗВИМОСТЬ: Межбанковский endpoint доступен без аутентификации");
                }
            }
        } catch (Exception e) {
            // Endpoint требует аутентизации - это нормально
        }

        return vulns;
    }
}
