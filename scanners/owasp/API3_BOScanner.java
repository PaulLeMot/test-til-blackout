// scanners/owasp/API3_BOScanner.java
package scanners.owasp;

import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import scanners.SecurityScanner;
import java.util.*;

/**
 * Улучшенный сканер для OWASP API3: Broken Object Property Level Authorization
 * Специально адаптирован для Virtual Bank API
 */
public class API3_BOScanner implements SecurityScanner {

    private static final Set<String> SENSITIVE_PATTERNS = Set.of(
            "password", "token", "secret", "key", "auth", "credential",
            "cvv", "expiry", "pin", "signature", "signature_key"
    );

    private static final Set<String> PII_PATTERNS = Set.of(
            "email", "phone", "address", "birth_date", "birthdate", "snils",
            "first_name", "last_name", "middle_name", "full_name", "inn",
            "passport", "client_id", "user_id", "customer_id"
    );

    private static final Set<String> PRIVILEGED_PATTERNS = Set.of(
            "role", "admin", "permission", "privilege", "superuser",
            "balance", "limit", "status", "type", "level"
    );

    private static final Set<String> INTERNAL_PATTERNS = Set.of(
            "internal_", "db_", "system_", "_id", "servicer", "bank_code",
            "consent_id", "request_id", "agreement_id", "application_id"
    );

    public API3_BOScanner() {}

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl();

        System.out.println("🔍 Запуск улучшенного OWASP API3 BOPLA Scanner...");
        System.out.println("🎯 Целевой API: Virtual Bank API (OpenBanking Russia v2.1)");

        try {
            // Получаем токен для аутентификации
            String token = authenticate(baseUrl, config.getPassword());
            if (token == null) {
                System.err.println("❌ Не удалось аутентифицироваться для API3 сканирования");
                return vulnerabilities;
            }

            System.out.println("   ✅ Токен получен, начинаем тестирование...");

            // Расширенные тесты на основе документации API
            testEnhancedMassAssignment(baseUrl, token, vulnerabilities, apiClient);
            testAccountStatusManipulation(baseUrl, token, vulnerabilities, apiClient);
            testAccountCloseManipulation(baseUrl, token, vulnerabilities, apiClient);
            testEnhancedSensitiveDataExposure(baseUrl, token, vulnerabilities, apiClient);
            testEnhancedConsentManipulation(baseUrl, token, vulnerabilities, apiClient);
            testEnhancedPaymentManipulation(baseUrl, token, vulnerabilities, apiClient);
            testProductManipulation(baseUrl, token, vulnerabilities, apiClient);
            testAdminEndpointsAccess(baseUrl, token, vulnerabilities, apiClient);

        } catch (Exception e) {
            System.err.println("❌ Ошибка при сканировании API3: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("✅ API3 сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private String authenticate(String baseUrl, String password) {
        try {
            return core.AuthManager.getBankAccessToken(baseUrl, "team172-1", password);
        } catch (Exception e) {
            System.err.println("❌ Ошибка аутентификации: " + e.getMessage());
            return null;
        }
    }

    private void testEnhancedMassAssignment(String baseUrl, String token,
                                            List<Vulnerability> vulnerabilities,
                                            ApiClient apiClient) {
        System.out.println("   💰 Расширенное тестирование массового присвоения...");

        // Расширенный набор тестовых payloads
        Map<String, String> maliciousPayloads = new LinkedHashMap<>();
        maliciousPayloads.put("Высокий баланс + овердрафт",
                "{\"account_type\":\"checking\",\"initial_balance\":9999999,\"overdraft_limit\":50000}");
        maliciousPayloads.put("Премиум статус",
                "{\"account_type\":\"checking\",\"initial_balance\":0,\"status\":\"premium\",\"interest_rate\":15}");
        maliciousPayloads.put("Административные права",
                "{\"account_type\":\"checking\",\"initial_balance\":0,\"is_admin\":true,\"permissions\":\"all\"}");
        maliciousPayloads.put("Нестандартная валюта",
                "{\"account_type\":\"checking\",\"initial_balance\":1000,\"currency\":\"BTC\"}");
        maliciousPayloads.put("Расширенные разрешения",
                "{\"account_type\":\"checking\",\"initial_balance\":0,\"features\":[\"overdraft\",\"priority_support\",\"fee_waiver\"]}");

        for (Map.Entry<String, String> entry : maliciousPayloads.entrySet()) {
            String testName = entry.getKey();
            String payload = entry.getValue();

            System.out.println("     🧪 Тест: " + testName);

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("POST", baseUrl + "/accounts", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    System.out.println("     📡 Статус ответа: " + apiResponse.getStatusCode());

                    if (apiResponse.getStatusCode() == 200) {
                        // Детальный анализ ответа
                        String responseBody = apiResponse.getBody().toLowerCase();
                        Map<String, Boolean> fieldChecks = new HashMap<>();
                        fieldChecks.put("overdraft", responseBody.contains("overdraft"));
                        fieldChecks.put("premium", responseBody.contains("premium"));
                        fieldChecks.put("admin", responseBody.contains("admin"));
                        fieldChecks.put("btc", responseBody.contains("btc"));
                        fieldChecks.put("9999999", responseBody.contains("9999999"));

                        boolean acceptedMaliciousFields = fieldChecks.containsValue(true);

                        if (acceptedMaliciousFields) {
                            List<String> acceptedFields = new ArrayList<>();
                            for (Map.Entry<String, Boolean> check : fieldChecks.entrySet()) {
                                if (check.getValue()) acceptedFields.add(check.getKey());
                            }

                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Массовое присвоение при создании счета - " + testName,
                                    "Сервер принял привилегированные поля в запросе создания счета. " +
                                            "Принятые поля: " + acceptedFields + ". " +
                                            "Это указывает на отсутствие proper server-side валидации.",
                                    Vulnerability.Severity.HIGH,
                                    "/accounts",
                                    "POST",
                                    apiResponse.getStatusCode(),
                                    payload,
                                    apiResponse.getBody(),
                                    "Сервер должен отклонять запросы с неразрешенными полями. " +
                                            "Реализуйте whitelist валидацию и используйте отдельные DTO для клиентских запросов."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 УЯЗВИМОСТЬ ОБНАРУЖЕНА: " + testName);
                        } else {
                            System.out.println("     ✅ Защита работает: сервер отклонил подозрительные поля");
                        }
                    } else if (apiResponse.getStatusCode() == 422 || apiResponse.getStatusCode() == 400) {
                        System.out.println("     ✅ Защита работает: сервер вернул ошибку валидации");
                    }
                }
            } catch (Exception e) {
                System.err.println("     ⚠️ Ошибка при тесте '" + testName + "': " + e.getMessage());
            }
        }
    }

    private void testAccountStatusManipulation(String baseUrl, String token,
                                               List<Vulnerability> vulnerabilities,
                                               ApiClient apiClient) {
        System.out.println("   🔄 Расширенное тестирование манипуляции статусом...");

        String accountId = getFirstAccountId(baseUrl, token, apiClient);
        if (accountId == null) {
            System.out.println("     ℹ️ Нет доступных счетов для тестирования статусов");
            return;
        }

        System.out.println("     📝 Используем счет: " + accountId);

        Map<String, String> statusPayloads = new LinkedHashMap<>();
        statusPayloads.put("Премиум статус", "{\"status\":\"premium\"}");
        statusPayloads.put("Верифицированный статус", "{\"status\":\"verified\"}");
        statusPayloads.put("Золотой статус", "{\"status\":\"gold\"}");
        statusPayloads.put("Статус с доп. параметрами", "{\"status\":\"active\",\"overdraft_limit\":50000}");

        for (Map.Entry<String, String> entry : statusPayloads.entrySet()) {
            String testName = entry.getKey();
            String payload = entry.getValue();

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("PUT",
                        baseUrl + "/accounts/" + accountId + "/status", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        String responseBody = apiResponse.getBody().toLowerCase();
                        boolean acceptedMaliciousStatus =
                                responseBody.contains("premium") ||
                                        responseBody.contains("verified") ||
                                        responseBody.contains("gold") ||
                                        responseBody.contains("overdraft_limit");

                        if (acceptedMaliciousStatus) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Манипуляция статусом счета - " + testName,
                                    "Сервер принял недопустимый статус счета или дополнительные параметры. " +
                                            "Ответ сервера подтверждает применение изменений.",
                                    Vulnerability.Severity.MEDIUM,
                                    "/accounts/{account_id}/status",
                                    "PUT",
                                    apiResponse.getStatusCode(),
                                    payload,
                                    apiResponse.getBody(),
                                    "Ограничьте допустимые значения статуса enum'ом. " +
                                            "Реализуйте бизнес-логику проверки переходов статусов. " +
                                            "Запретите прямой произвольный выбор статуса."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 УЯЗВИМОСТЬ ОБНАРУЖЕНА: " + testName);
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("     ⚠️ Ошибка при тесте статуса '" + testName + "': " + e.getMessage());
            }
        }
    }

    private void testAccountCloseManipulation(String baseUrl, String token,
                                              List<Vulnerability> vulnerabilities,
                                              ApiClient apiClient) {
        System.out.println("   🚪 Расширенное тестирование закрытия счетов...");

        String accountId = getFirstAccountId(baseUrl, token, apiClient);
        if (accountId == null) {
            System.out.println("     ℹ️ Нет доступных счетов для тестирования закрытия");
            return;
        }

        Map<String, String> closePayloads = new LinkedHashMap<>();
        closePayloads.put("Перевод с бонусом",
                "{\"action\":\"transfer\",\"destination_account_id\":\"acc-999999\",\"bonus_amount\":1000}");
        closePayloads.put("Перевод с комиссией",
                "{\"action\":\"transfer\",\"destination_account_id\":\"acc-999999\",\"fee_override\":0}");
        closePayloads.put("Донат с наградой",
                "{\"action\":\"donate\",\"reward_points\":10000}");

        for (Map.Entry<String, String> entry : closePayloads.entrySet()) {
            String testName = entry.getKey();
            String payload = entry.getValue();

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("PUT",
                        baseUrl + "/accounts/" + accountId + "/close", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        String responseBody = apiResponse.getBody().toLowerCase();
                        boolean acceptedMaliciousParams =
                                responseBody.contains("bonus_amount") ||
                                        responseBody.contains("fee_override") ||
                                        responseBody.contains("reward_points");

                        if (acceptedMaliciousParams) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Манипуляция при закрытии счета - " + testName,
                                    "Сервер принял подозрительные параметры при закрытии счета. " +
                                            "Это может позволить обойти бизнес-логику финансовых операций.",
                                    Vulnerability.Severity.HIGH,
                                    "/accounts/{account_id}/close",
                                    "PUT",
                                    apiResponse.getStatusCode(),
                                    payload,
                                    apiResponse.getBody(),
                                    "Строго валидируйте параметры закрытия счета. " +
                                            "Запретите дополнительные поля в запросе закрытия. " +
                                            "Проверяйте принадлежность счетов и бизнес-правила."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 УЯЗВИМОСТЬ ОБНАРУЖЕНА: " + testName);
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("     ⚠️ Ошибка при тесте закрытия '" + testName + "': " + e.getMessage());
            }
        }
    }

    private void testEnhancedSensitiveDataExposure(String baseUrl, String token,
                                                   List<Vulnerability> vulnerabilities,
                                                   ApiClient apiClient) {
        System.out.println("   🔓 Расширенное тестирование раскрытия данных...");

        Map<String, String> endpointsToTest = new LinkedHashMap<>();
        endpointsToTest.put("/accounts", "GET");
        endpointsToTest.put("/auth/me", "GET");
        endpointsToTest.put("/products", "GET");
        endpointsToTest.put("/account-consents", "GET");

        for (Map.Entry<String, String> entry : endpointsToTest.entrySet()) {
            String endpoint = entry.getKey();
            String method = entry.getValue();

            System.out.println("     🔍 Проверка эндпоинта: " + endpoint);

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest(method, baseUrl + endpoint, null, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        String responseBody = apiResponse.getBody();

                        // Детальный анализ ответа
                        List<String> sensitiveFields = findFieldsByPatterns(responseBody, SENSITIVE_PATTERNS);
                        List<String> piiFields = findFieldsByPatterns(responseBody, PII_PATTERNS);
                        List<String> internalFields = findFieldsByPatterns(responseBody, INTERNAL_PATTERNS);
                        List<String> privilegedFields = findFieldsByPatterns(responseBody, PRIVILEGED_PATTERNS);

                        // Создаем детальный отчет для каждого типа уязвимости
                        if (!sensitiveFields.isEmpty()) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Раскрытие чувствительных данных в " + endpoint,
                                    "Обнаружены критические чувствительные поля: " + sensitiveFields + ". " +
                                            "Раскрытие таких данных может привести к компрометации аккаунтов.",
                                    Vulnerability.Severity.HIGH,
                                    endpoint,
                                    method,
                                    apiResponse.getStatusCode(),
                                    "N/A", // GET запрос без тела
                                    responseBody,
                                    "Маскируйте чувствительные данные в ответах API. " +
                                            "Используйте DTO для фильтрации полей. " +
                                            "Реализуйте принцип минимальных привилегий."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 ЧУВСТВИТЕЛЬНЫЕ ДАННЫЕ: " + sensitiveFields);
                        }

                        if (!piiFields.isEmpty()) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Раскрытие PII данных в " + endpoint,
                                    "Обнаружены персональные данные (PII): " + piiFields + ". " +
                                            "Нарушение GDPR и законодательства о защите данных.",
                                    Vulnerability.Severity.MEDIUM,
                                    endpoint,
                                    method,
                                    apiResponse.getStatusCode(),
                                    "N/A",
                                    responseBody,
                                    "Соблюдайте GDPR/законодательство о защите данных. " +
                                            "Маскируйте PII данные в ответах. " +
                                            "Используйте дифференцированный доступ к данным."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 PII ДАННЫЕ: " + piiFields);
                        }

                        if (!internalFields.isEmpty()) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Раскрытие внутренней информации в " + endpoint,
                                    "Обнаружены внутренние технические поля: " + internalFields + ". " +
                                            "Раскрытие внутренней структуры может помочь атакующему.",
                                    Vulnerability.Severity.LOW,
                                    endpoint,
                                    method,
                                    apiResponse.getStatusCode(),
                                    "N/A",
                                    responseBody,
                                    "Удалите внутренние технические поля из production ответов. " +
                                            "Используйте отдельные DTO для внутреннего и внешнего представления. " +
                                            "Настройте фильтрацию полей в сериализации."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 ВНУТРЕННИЕ ДАННЫЕ: " + internalFields);
                        }

                        if (!privilegedFields.isEmpty()) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Раскрытие привилегированной информации в " + endpoint,
                                    "Обнаружены поля, связанные с правами доступа: " + privilegedFields + ". " +
                                            "Может помочь в эскалации привилегий.",
                                    Vulnerability.Severity.MEDIUM,
                                    endpoint,
                                    method,
                                    apiResponse.getStatusCode(),
                                    "N/A",
                                    responseBody,
                                    "Скрывайте информацию о правах и ролях в ответах. " +
                                            "Используйте минимально необходимый набор полей в ответах."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 ПРИВИЛЕГИРОВАННЫЕ ДАННЫЕ: " + privilegedFields);
                        }

                        if (sensitiveFields.isEmpty() && piiFields.isEmpty() &&
                                internalFields.isEmpty() && privilegedFields.isEmpty()) {
                            System.out.println("     ✅ Данные защищены правильно");
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("     ⚠️ Ошибка при тесте эндпоинта " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private void testEnhancedConsentManipulation(String baseUrl, String token,
                                                 List<Vulnerability> vulnerabilities,
                                                 ApiClient apiClient) {
        System.out.println("   📝 Расширенное тестирование согласий...");

        Map<String, String> consentPayloads = new LinkedHashMap<>();
        consentPayloads.put("Административные права",
                "{\"permissions\":[\"accounts\",\"payments\",\"admin_operations\"],\"scope\":\"full_access\"}");
        consentPayloads.put("Расширенный доступ",
                "{\"permissions\":[\"*\"],\"scope\":\"*\",\"duration\":\"permanent\"}");
        consentPayloads.put("Дополнительные привилегии",
                "{\"permissions\":[\"accounts\",\"payments\"],\"max_amount\":9999999,\"override_limits\":true}");

        for (Map.Entry<String, String> entry : consentPayloads.entrySet()) {
            String testName = entry.getKey();
            String payload = entry.getValue();

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("POST",
                        baseUrl + "/account-consents/request", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        String responseBody = apiResponse.getBody().toLowerCase();
                        boolean acceptedMaliciousConsent =
                                responseBody.contains("admin_operations") ||
                                        responseBody.contains("full_access") ||
                                        responseBody.contains("permanent") ||
                                        responseBody.contains("override_limits");

                        if (acceptedMaliciousConsent) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Манипуляция правами согласия - " + testName,
                                    "Сервер принял запрос согласия с расширенными или административными правами. " +
                                            "Это может позволить несанкционированный доступ к данным.",
                                    Vulnerability.Severity.HIGH,
                                    "/account-consents/request",
                                    "POST",
                                    apiResponse.getStatusCode(),
                                    payload,
                                    apiResponse.getBody(),
                                    "Ограничьте доступные разрешения для клиентов. " +
                                            "Реализуйте проверку scope согласий. " +
                                            "Запретите клиентам выбирать административные права."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 УЯЗВИМОСТЬ ОБНАРУЖЕНА: " + testName);
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("     ⚠️ Ошибка при тесте согласия '" + testName + "': " + e.getMessage());
            }
        }
    }

    private void testEnhancedPaymentManipulation(String baseUrl, String token,
                                                 List<Vulnerability> vulnerabilities,
                                                 ApiClient apiClient) {
        System.out.println("   💸 Расширенное тестирование платежей...");

        Map<String, String> paymentPayloads = new LinkedHashMap<>();
        paymentPayloads.put("Обход комиссий",
                "{\"amount\":0.01,\"currency\":\"RUB\",\"fee_override\":0,\"priority\":\"urgent\"}");
        paymentPayloads.put("Изменение лимитов",
                "{\"amount\":1000,\"currency\":\"RUB\",\"max_limit_override\":9999999}");
        paymentPayloads.put("Привилегированный платеж",
                "{\"amount\":1000,\"currency\":\"RUB\",\"is_privileged\":true,\"skip_validation\":true}");

        for (Map.Entry<String, String> entry : paymentPayloads.entrySet()) {
            String testName = entry.getKey();
            String payload = entry.getValue();

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("POST",
                        baseUrl + "/payments", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        String responseBody = apiResponse.getBody().toLowerCase();
                        boolean acceptedMaliciousPayment =
                                responseBody.contains("fee_override") ||
                                        responseBody.contains("urgent") ||
                                        responseBody.contains("max_limit_override") ||
                                        responseBody.contains("privileged") ||
                                        responseBody.contains("skip_validation");

                        if (acceptedMaliciousPayment) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Манипуляция параметрами платежа - " + testName,
                                    "Сервер принял запрос платежа с переопределенными параметрами. " +
                                            "Это может позволить обойти бизнес-правила и финансовые ограничения.",
                                    Vulnerability.Severity.HIGH,
                                    "/payments",
                                    "POST",
                                    apiResponse.getStatusCode(),
                                    payload,
                                    apiResponse.getBody(),
                                    "Фиксируйте комиссии на сервере. " +
                                            "Ограничьте доступные приоритеты платежей. " +
                                            "Валидируйте все параметры платежа на стороне сервера."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 УЯЗВИМОСТЬ ОБНАРУЖЕНА: " + testName);
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("     ⚠️ Ошибка при тесте платежа '" + testName + "': " + e.getMessage());
            }
        }
    }

    private void testProductManipulation(String baseUrl, String token,
                                         List<Vulnerability> vulnerabilities,
                                         ApiClient apiClient) {
        System.out.println("   🏦 Тестирование манипуляции продуктами...");

        Map<String, String> productPayloads = new LinkedHashMap<>();
        productPayloads.put("Создание премиум продукта",
                "{\"name\":\"Test Product\",\"type\":\"premium\",\"interest_rate\":15,\"special_conditions\":\"vip\"}");
        productPayloads.put("Продукт с расширенными лимитами",
                "{\"name\":\"Test\",\"type\":\"standard\",\"max_limit\":9999999,\"overdraft_allowed\":true}");

        for (Map.Entry<String, String> entry : productPayloads.entrySet()) {
            String testName = entry.getKey();
            String payload = entry.getValue();

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("POST",
                        baseUrl + "/products", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        String responseBody = apiResponse.getBody().toLowerCase();
                        boolean acceptedMaliciousProduct =
                                responseBody.contains("premium") ||
                                        responseBody.contains("vip") ||
                                        responseBody.contains("9999999") ||
                                        responseBody.contains("overdraft_allowed");

                        if (acceptedMaliciousProduct) {
                            Vulnerability vuln = createEnhancedVulnerability(
                                    "Манипуляция продуктами - " + testName,
                                    "Сервер принял запрос на создание продукта с привилегированными параметрами. " +
                                            "Обычно создание продуктов должно быть ограничено административными ролями.",
                                    Vulnerability.Severity.HIGH,
                                    "/products",
                                    "POST",
                                    apiResponse.getStatusCode(),
                                    payload,
                                    apiResponse.getBody(),
                                    "Ограничьте создание продуктов административными ролями. " +
                                            "Валидируйте параметры продуктов на сервере. " +
                                            "Запретите клиентам устанавливать привилегированные параметры."
                            );
                            vulnerabilities.add(vuln);
                            System.out.println("     🚨 УЯЗВИМОСТЬ ОБНАРУЖЕНА: " + testName);
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("     ⚠️ Ошибка при тесте продукта '" + testName + "': " + e.getMessage());
            }
        }
    }

    private void testAdminEndpointsAccess(String baseUrl, String token,
                                          List<Vulnerability> vulnerabilities,
                                          ApiClient apiClient) {
        System.out.println("   👑 Тестирование доступа к админским эндпоинтам...");

        Map<String, String> adminEndpoints = new LinkedHashMap<>();
        adminEndpoints.put("/admin/stats", "GET");
        adminEndpoints.put("/admin/teams", "GET");
        adminEndpoints.put("/admin/capital", "GET");
        adminEndpoints.put("/admin/key-rate", "GET");

        for (Map.Entry<String, String> entry : adminEndpoints.entrySet()) {
            String endpoint = entry.getKey();
            String method = entry.getValue();

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest(method, baseUrl + endpoint, null, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        Vulnerability vuln = createEnhancedVulnerability(
                                "Неавторизованный доступ к админскому эндпоинту",
                                "Обычный пользователь получил доступ к административному эндпоинту: " + endpoint + ". " +
                                        "Статус ответа: " + apiResponse.getStatusCode() + ". " +
                                        "Это указывает на недостаточную проверку прав доступа.",
                                Vulnerability.Severity.HIGH,
                                endpoint,
                                method,
                                apiResponse.getStatusCode(),
                                "N/A",
                                apiResponse.getBody(),
                                "Реализуйте строгую проверку ролей и прав доступа. " +
                                        "Ограничьте административные эндпоинты только пользователями с соответствующими правами. " +
                                        "Используйте middleware для проверки авторизации."
                        );
                        vulnerabilities.add(vuln);
                        System.out.println("     🚨 ДОСТУП К АДМИНКЕ: " + endpoint);
                    } else if (apiResponse.getStatusCode() == 403 || apiResponse.getStatusCode() == 401) {
                        System.out.println("     ✅ Доступ к админке запрещен: " + endpoint);
                    }
                }
            } catch (Exception e) {
                System.err.println("     ⚠️ Ошибка при тесте админского эндпоинта " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private String getFirstAccountId(String baseUrl, String token, ApiClient apiClient) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("GET", baseUrl + "/accounts", null, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                if (apiResponse.getStatusCode() == 200) {
                    String body = apiResponse.getBody();
                    // Ищем account_id в ответе
                    java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"account_id\"\\s*:\\s*\"([^\"]+)\"");
                    java.util.regex.Matcher matcher = pattern.matcher(body);
                    if (matcher.find()) {
                        return matcher.group(1);
                    }
                    // Альтернативный вариант
                    pattern = java.util.regex.Pattern.compile("\"accountId\"\\s*:\\s*\"([^\"]+)\"");
                    matcher = pattern.matcher(body);
                    if (matcher.find()) {
                        return matcher.group(1);
                    }
                } else {
                    System.err.println("⚠️ Получен статус " + apiResponse.getStatusCode() + " при запросе счетов");
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при получении account_id: " + e.getMessage());
        }
        return null;
    }

    private Vulnerability createEnhancedVulnerability(String title, String description,
                                                      Vulnerability.Severity severity,
                                                      String endpoint, String method, int statusCode,
                                                      String requestBody, String responseBody,
                                                      String recommendation) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API3:2023 - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
        vuln.setEndpoint(endpoint);
        vuln.setMethod(method);
        vuln.setStatusCode(statusCode);

        // Детальное evidence с запросом и ответом
        String evidence = String.format(
                "=== ДЕТАЛИ УЯЗВИМОСТИ ===\n" +
                        "Эндпоинт: %s %s\n" +
                        "HTTP Статус: %d\n" +
                        "Тело запроса: %s\n" +
                        "Тело ответа: %s\n" +
                        "Описание: %s",
                method, endpoint, statusCode,
                requestBody != null ? requestBody : "N/A",
                responseBody.length() > 500 ? responseBody.substring(0, 500) + "..." : responseBody,
                description
        );
        vuln.setEvidence(evidence);

        // Специфические рекомендации
        vuln.setRecommendations(Arrays.asList(
                recommendation,
                "Реализуйте строгую схему валидации для всех входных данных",
                "Используйте whitelist подход для разрешенных полей",
                "Разделяйте DTO для клиентов и внутреннего использования",
                "Внедрите проверки прав на уровне свойств объектов"
        ));

        return vuln;
    }

    @Override
    public String getName() {
        return "OWASP API3 - Enhanced Broken Object Property Level Authorization Scanner";
    }

    private List<String> findFieldsByPatterns(String json, Set<String> patterns) {
        List<String> results = new ArrayList<>();
        String lowerJson = json.toLowerCase();

        for (String pattern : patterns) {
            java.util.regex.Pattern regex = java.util.regex.Pattern.compile("\"([^\"]*" + pattern + "[^\"]*)\"\\s*:");
            java.util.regex.Matcher matcher = regex.matcher(lowerJson);

            while (matcher.find()) {
                String fieldName = matcher.group(1);
                if (!results.contains(fieldName)) {
                    results.add(fieldName);
                }
            }
        }

        return results;
    }
}