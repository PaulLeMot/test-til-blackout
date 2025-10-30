// scanners/owasp/API6_BusinessFlowScanner.java
package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.AuthManager;

import java.util.*;
import java.util.regex.Pattern;

public class API6_BusinessFlowScanner implements SecurityScanner {

    private static final String[] SENSITIVE_BUSINESS_ENDPOINTS = {
            "/payments",
            "/domestic-vrp-payments",
            "/product-application",
            "/product-agreements",
            "/customer-leads",
            "/account-consents/request"
    };

    private static final Map<String, String> BUSINESS_FLOW_DESCRIPTIONS = new HashMap<>();
    static {
        BUSINESS_FLOW_DESCRIPTIONS.put("/payments", "Финансовые переводы - критичный бизнес-процесс");
        BUSINESS_FLOW_DESCRIPTIONS.put("/domestic-vrp-payments", "Периодические платежи - автоматизированный процесс");
        BUSINESS_FLOW_DESCRIPTIONS.put("/product-application", "Заявки на кредиты/депозиты - доходный процесс");
        BUSINESS_FLOW_DESCRIPTIONS.put("/product-agreements", "Заключение договоров - юридически значимый процесс");
        BUSINESS_FLOW_DESCRIPTIONS.put("/customer-leads", "Генерация лидов - маркетинговый процесс");
        BUSINESS_FLOW_DESCRIPTIONS.put("/account-consents/request", "Согласия на доступ - процесс обмена данными");
    }

    @Override
    public String getName() {
        return "OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("🔍 Scanning for Business Flow vulnerabilities (OWASP API Security Top 10:2023 - API6)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl();
        String password = config.getPassword();

        if (password == null || password.isEmpty()) {
            System.err.println("⚠️ Пароль не задан в конфигурации. Business Flow сканер пропущен.");
            return vulnerabilities;
        }

        try {
            // ИСПРАВЛЕНО: Используем существующий метод getBankAccessTokensForTeam
            Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(baseUrl, password);
            if (tokens.isEmpty()) {
                System.err.println("⚠️ Не удалось получить токены для Business Flow теста.");
                return vulnerabilities;
            }

            // Берем первый доступный токен
            String token = tokens.values().iterator().next();
            System.out.println("✅ Получен токен для тестирования бизнес-процессов");

            // 5.6.1: Идентификация ключевых бизнес-процессов
            System.out.println("📋 Идентификация бизнес-процессов...");
            Map<String, Boolean> endpointAccessibility = identifyBusinessEndpoints(baseUrl, token, apiClient);

            // 5.6.2: Тестирование возможности автоматизации
            System.out.println("🤖 Тестирование автоматизации операций...");
            testAutomationCapabilities(baseUrl, token, apiClient, endpointAccessibility, vulnerabilities);

            // 5.6.3: Проверка ограничений на частоту
            System.out.println("⏱️ Проверка ограничений частоты...");
            testRateLimiting(baseUrl, token, apiClient, vulnerabilities);

            // 5.6.4: Анализ анти-бот защиты
            System.out.println("🛡️ Анализ анти-бот защиты...");
            testAntiBotProtection(baseUrl, token, apiClient, vulnerabilities);

            // 5.6.5: Тестирование обходов бизнес-логики
            System.out.println("🔄 Тестирование обходов бизнес-логики...");
            testBusinessLogicBypass(baseUrl, token, apiClient, vulnerabilities);

            // 5.6.6: Проверка целостности бизнес-процессов
            System.out.println("🔗 Проверка целостности процессов...");
            testProcessIntegrity(baseUrl, token, apiClient, vulnerabilities);

        } catch (Exception e) {
            System.err.println("❌ Ошибка в Business Flow сканере: " + e.getMessage());
            if (isDebugMode()) {
                e.printStackTrace();
            }
        }

        System.out.println("✅ Business Flow scan completed. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private Map<String, Boolean> identifyBusinessEndpoints(String baseUrl, String token, ApiClient apiClient) {
        Map<String, Boolean> accessibility = new HashMap<>();

        for (String endpoint : SENSITIVE_BUSINESS_ENDPOINTS) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Accept", "application/json");

                // Пробуем GET запрос для проверки доступности
                String fullUrl = baseUrl + endpoint;
                Object response = apiClient.executeRequest("GET", fullUrl, null, headers);

                boolean isAccessible = false;
                if (response instanceof core.HttpApiClient.ApiResponse) {
                    core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                    int statusCode = apiResponse.getStatusCode();
                    // Считаем доступным, если статус 200-399 или 404 (эндпоинт существует)
                    isAccessible = (statusCode >= 200 && statusCode < 400) || statusCode == 404;
                }

                accessibility.put(endpoint, isAccessible);
                System.out.println("   " + (isAccessible ? "✅" : "❌") + " " + endpoint +
                        " - " + BUSINESS_FLOW_DESCRIPTIONS.get(endpoint));

            } catch (Exception e) {
                accessibility.put(endpoint, false);
                System.err.println("⚠️ Ошибка при проверке эндпоинта " + endpoint + ": " + e.getMessage());
            }
        }

        return accessibility;
    }

    private void testAutomationCapabilities(String baseUrl, String token, ApiClient apiClient,
                                            Map<String, Boolean> accessibility, List<Vulnerability> vulnerabilities) {

        for (String endpoint : SENSITIVE_BUSINESS_ENDPOINTS) {
            if (!accessibility.getOrDefault(endpoint, false)) continue;

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");

                String testPayload = createTestPayload(endpoint);
                int successfulCalls = 0;

                for (int i = 0; i < 3; i++) { // Уменьшили до 3 запросов для безопасности
                    Object response = apiClient.executeRequest("POST", baseUrl + endpoint, testPayload, headers);

                    if (response instanceof core.HttpApiClient.ApiResponse) {
                        core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                        if (apiResponse.getStatusCode() >= 200 && apiResponse.getStatusCode() < 300) {
                            successfulCalls++;
                        }
                    }

                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }

                if (successfulCalls == 3) {
                    Vulnerability vuln = createBusinessFlowVulnerability(
                            endpoint,
                            "Неограниченная автоматизация бизнес-процесса",
                            "Эндпоинт " + endpoint + " позволяет выполнять " + successfulCalls +
                                    " последовательных операций без ограничений. Возможна полная автоматизация чувствительного бизнес-процесса.",
                            Vulnerability.Severity.HIGH
                    );
                    vulnerabilities.add(vuln);
                }

            } catch (Exception e) {
                System.err.println("⚠️ Ошибка при тестировании автоматизации " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private void testRateLimiting(String baseUrl, String token, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        String testEndpoint = "/payments";

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");

            String testPayload = createTestPayload(testEndpoint);
            List<Integer> responseCodes = new ArrayList<>();

            for (int i = 0; i < 5; i++) { // Уменьшили до 5 запросов
                Object response = apiClient.executeRequest("POST", baseUrl + testEndpoint, testPayload, headers);

                if (response instanceof core.HttpApiClient.ApiResponse) {
                    core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                    responseCodes.add(apiResponse.getStatusCode());
                }

                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }

            boolean hasRateLimiting = responseCodes.stream().anyMatch(code -> code == 429);
            int successCount = (int) responseCodes.stream().filter(code -> code >= 200 && code < 300).count();

            if (!hasRateLimiting && successCount >= 3) {
                Vulnerability vuln = createBusinessFlowVulnerability(
                        testEndpoint,
                        "Отсутствие rate limiting для бизнес-операций",
                        "Эндпоинт " + testEndpoint + " не имеет ограничений частоты запросов. Успешно выполнено " +
                                successCount + "/5 запросов подряд. Возможны DDoS-атаки на бизнес-процессы.",
                        Vulnerability.Severity.HIGH
                );
                vulnerabilities.add(vuln);
            }

        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при тестировании rate limiting: " + e.getMessage());
        }
    }

    private void testAntiBotProtection(String baseUrl, String token, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        List<String> criticalEndpoints = Arrays.asList("/payments", "/product-application", "/domestic-vrp-payments");

        for (String endpoint : criticalEndpoints) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);

                Object response = apiClient.executeRequest("OPTIONS", baseUrl + endpoint, null, headers);

                boolean hasAntiBotMeasures = false;
                if (response instanceof core.HttpApiClient.ApiResponse) {
                    core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;
                    String responseHeaders = apiResponse.getHeaders() != null ? apiResponse.getHeaders().toString() : "";

                    // Проверяем наличие признаков анти-бот защиты
                    hasAntiBotMeasures = responseHeaders.toLowerCase().contains("csrf") ||
                            responseHeaders.toLowerCase().contains("captcha") ||
                            responseHeaders.toLowerCase().contains("recaptcha");
                }

                if (!hasAntiBotMeasures) {
                    Vulnerability vuln = createBusinessFlowVulnerability(
                            endpoint,
                            "Отсутствие анти-бот защиты",
                            "Критичный бизнес-процесс " + endpoint + " не имеет механизмов защиты от ботов " +
                                    "(CAPTCHA, CSRF токены, поведенческий анализ). Возможна автоматическая эксплуатация.",
                            Vulnerability.Severity.MEDIUM
                    );
                    vulnerabilities.add(vuln);
                }

            } catch (Exception e) {
                System.err.println("⚠️ Ошибка при проверке анти-бот защиты " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private void testBusinessLogicBypass(String baseUrl, String token, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        testAmountValidationBypass(baseUrl, token, apiClient, vulnerabilities);
        testLimitValidationBypass(baseUrl, token, apiClient, vulnerabilities);
    }

    private void testAmountValidationBypass(String baseUrl, String token, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");

            String negativeAmountPayload = "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"-1000.00\",\"currency\":\"RUB\"}}}}";

            Object response = apiClient.executeRequest("POST", baseUrl + "/payments", negativeAmountPayload, headers);

            if (response instanceof core.HttpApiClient.ApiResponse) {
                core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() >= 200 && apiResponse.getStatusCode() < 300) {
                    Vulnerability vuln = createBusinessFlowVulnerability(
                            "/payments",
                            "Обход валидации отрицательных сумм",
                            "Эндпоинт платежей принимает отрицательные суммы (-1000.00 RUB). " +
                                    "Возможны финансовые манипуляции и обход бизнес-логики.",
                            Vulnerability.Severity.HIGH
                    );
                    vulnerabilities.add(vuln);
                }
            }

        } catch (Exception e) {
            // Игнорируем ошибки - это нормально для тестовых запросов
        }
    }

    private void testLimitValidationBypass(String baseUrl, String token, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");

            String hugeAmountPayload = "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"999999999.00\",\"currency\":\"RUB\"}}}}";

            Object response = apiClient.executeRequest("POST", baseUrl + "/payments", hugeAmountPayload, headers);

            if (response instanceof core.HttpApiClient.ApiResponse) {
                core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() >= 200 && apiResponse.getStatusCode() < 300) {
                    Vulnerability vuln = createBusinessFlowVulnerability(
                            "/payments",
                            "Обход проверки лимитов сумм",
                            "Эндпоинт платежей принимает экстремально большие суммы (999,999,999 RUB) без валидации. " +
                                    "Отсутствует проверка бизнес-логики на разумные лимиты операций.",
                            Vulnerability.Severity.HIGH
                    );
                    vulnerabilities.add(vuln);
                }
            }

        } catch (Exception e) {
            // Игнорируем ошибки
        }
    }

    private void testProcessIntegrity(String baseUrl, String token, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        testPaymentProcessIntegrity(baseUrl, token, apiClient, vulnerabilities);
    }

    private void testPaymentProcessIntegrity(String baseUrl, String token, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");

            String paymentPayload = "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"}}}}";

            Object response = apiClient.executeRequest("POST", baseUrl + "/payments", paymentPayload, headers);

            if (response instanceof core.HttpApiClient.ApiResponse) {
                core.HttpApiClient.ApiResponse apiResponse = (core.HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() >= 200 && apiResponse.getStatusCode() < 300) {
                    Vulnerability vuln = createBusinessFlowVulnerability(
                            "/payments",
                            "Нарушение целостности процесса платежей",
                            "Возможно создание платежа без предварительного согласия (x-payment-consent-id). " +
                                    "Нарушена последовательность бизнес-процесса: согласие → платеж.",
                            Vulnerability.Severity.MEDIUM
                    );
                    vulnerabilities.add(vuln);
                }
            }

        } catch (Exception e) {
            // Игнорируем ошибки
        }
    }

    private String createTestPayload(String endpoint) {
        switch (endpoint) {
            case "/payments":
                return "{\"data\":{\"initiation\":{\"instructedAmount\":{\"amount\":\"100.00\",\"currency\":\"RUB\"}}}}";
            case "/domestic-vrp-payments":
                return "{\"amount\":100,\"description\":\"Test payment\"}";
            case "/product-application":
                return "{\"product_id\":\"test-product\",\"requested_amount\":1000}";
            case "/customer-leads":
                return "{\"full_name\":\"Test User\",\"phone\":\"+79990000000\"}";
            case "/account-consents/request":
                return "{\"permissions\":[\"ReadAccountsDetail\"],\"reason\":\"Test consent\"}";
            default:
                return "{}";
        }
    }

    private Vulnerability createBusinessFlowVulnerability(String endpoint, String title, String description, Vulnerability.Severity severity) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API6:2023 - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API6_BUSINESS_FLOW);
        vuln.setEndpoint(endpoint);
        vuln.setMethod("POST");
        vuln.setStatusCode(200);

        List<String> recommendations = Arrays.asList(
                "Внедрить rate limiting для чувствительных бизнес-операций",
                "Реализовать проверку последовательности шагов бизнес-процесса",
                "Добавить анти-бот защиту (CAPTCHA, поведенческий анализ)",
                "Валидировать бизнес-логику на стороне сервера",
                "Внедрить мониторинг аномальной активности бизнес-процессов",
                "Реализовать лимиты на операции по сумме и частоте",
                "Использовать machine learning для обнаружения подозрительных паттернов"
        );
        vuln.setRecommendations(recommendations);

        return vuln;
    }

    private static boolean isDebugMode() {
        return System.getProperty("debug") != null ||
                Arrays.asList(System.getenv().getOrDefault("JAVA_OPTS", "").split(" ")).contains("-Ddebug");
    }
}