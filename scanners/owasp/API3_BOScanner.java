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

            // Расширенные тесты на основе документации API
            testAccountMassAssignment(baseUrl, token, vulnerabilities, apiClient);
            testAccountStatusManipulation(baseUrl, token, vulnerabilities, apiClient);
            testAccountCloseManipulation(baseUrl, token, vulnerabilities, apiClient);
            testSensitiveDataExposure(baseUrl, token, vulnerabilities, apiClient);
            testConsentManipulation(baseUrl, token, vulnerabilities, apiClient);
            testPaymentManipulation(baseUrl, token, vulnerabilities, apiClient);

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

    private void testAccountMassAssignment(String baseUrl, String token,
                                           List<Vulnerability> vulnerabilities,
                                           ApiClient apiClient) {
        System.out.println("   💰 Тестирование массового присвоения при создании счета...");

        // Пытаемся создать счет с привилегированными полями
        String[] maliciousPayloads = {
                // Попытка установить высокий начальный баланс
                "{\"account_type\":\"checking\",\"initial_balance\":9999999,\"overdraft_limit\":50000}",
                // Попытка установить премиум-статус
                "{\"account_type\":\"checking\",\"initial_balance\":0,\"status\":\"premium\",\"interest_rate\":15}",
                // Попытка установить административные права
                "{\"account_type\":\"checking\",\"initial_balance\":0,\"is_admin\":true,\"permissions\":\"all\"}",
                // Попытка изменить валюту на не поддерживаемую
                "{\"account_type\":\"checking\",\"initial_balance\":1000,\"currency\":\"BTC\"}"
        };

        for (String payload : maliciousPayloads) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object response = apiClient.executeRequest("POST", baseUrl + "/accounts", payload, headers);

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        // Проверяем, принял ли сервер наши привилегированные поля
                        String responseBody = apiResponse.getBody().toLowerCase();
                        boolean acceptedMaliciousFields =
                                responseBody.contains("premium") ||
                                        responseBody.contains("9999999") ||
                                        responseBody.contains("admin") ||
                                        responseBody.contains("btc");

                        if (acceptedMaliciousFields) {
                            Vulnerability vuln = createVulnerability(
                                    "Массовое присвоение при создании счета",
                                    "Сервер принял привилегированные поля в запросе создания счета: " + payload,
                                    Vulnerability.Severity.HIGH,
                                    "/accounts",
                                    "POST",
                                    apiResponse.getStatusCode()
                            );
                            vuln.setRecommendations(Arrays.asList(
                                    "Реализуйте whitelist валидацию для полей создания счета",
                                    "Используйте отдельные DTO для запросов и ответов",
                                    "Запретите клиентам устанавливать служебные поля"
                            ));
                            vulnerabilities.add(vuln);
                            break; // Достаточно одной найденной уязвимости
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("⚠️ Ошибка при тесте массового присвоения: " + e.getMessage());
            }
        }
    }

    private void testAccountStatusManipulation(String baseUrl, String token,
                                               List<Vulnerability> vulnerabilities,
                                               ApiClient apiClient) {
        System.out.println("   🔄 Тестирование манипуляции статусом счетов...");

        // Сначала получаем список счетов
        String accountId = getFirstAccountId(baseUrl, token, apiClient);
        if (accountId == null) {
            System.out.println("   ℹ️ Нет доступных счетов для тестирования статусов");
            return;
        }

        // Пытаемся изменить статус счета на недопустимые значения
        String[] statusPayloads = {
                "{\"status\":\"premium\"}",
                "{\"status\":\"verified\"}",
                "{\"status\":\"gold\"}",
                "{\"status\":\"active\",\"overdraft_limit\":50000}"
        };

        for (String payload : statusPayloads) {
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
                                        responseBody.contains("gold");

                        if (acceptedMaliciousStatus) {
                            Vulnerability vuln = createVulnerability(
                                    "Манипуляция статусом счета",
                                    "Сервер принял недопустимый статус счета: " + payload,
                                    Vulnerability.Severity.MEDIUM,
                                    "/accounts/{account_id}/status",
                                    "PUT",
                                    apiResponse.getStatusCode()
                            );
                            vuln.setRecommendations(Arrays.asList(
                                    "Ограничьте допустимые значения статуса enum'ом",
                                    "Реализуйте бизнес-логику проверки переходов статусов",
                                    "Запретите прямой произвольный выбор статуса"
                            ));
                            vulnerabilities.add(vuln);
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("⚠️ Ошибка при тесте манипуляции статусом: " + e.getMessage());
            }
        }
    }

    private void testAccountCloseManipulation(String baseUrl, String token,
                                              List<Vulnerability> vulnerabilities,
                                              ApiClient apiClient) {
        System.out.println("   🚪 Тестирование манипуляции закрытием счетов...");

        String accountId = getFirstAccountId(baseUrl, token, apiClient);
        if (accountId == null) {
            System.out.println("   ℹ️ Нет доступных счетов для тестирования закрытия");
            return;
        }

        // Пытаемся закрыть счет с подозрительными параметрами
        String maliciousClosePayload =
                "{\"action\":\"transfer\",\"destination_account_id\":\"acc-999999\",\"bonus_amount\":1000}";

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("PUT",
                    baseUrl + "/accounts/" + accountId + "/close", maliciousClosePayload, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() == 200) {
                    String responseBody = apiResponse.getBody().toLowerCase();
                    if (responseBody.contains("bonus_amount") || responseBody.contains("999999")) {
                        Vulnerability vuln = createVulnerability(
                                "Манипуляция при закрытии счета",
                                "Сервер принял подозрительные параметры при закрытии счета",
                                Vulnerability.Severity.HIGH,
                                "/accounts/{account_id}/close",
                                "PUT",
                                apiResponse.getStatusCode()
                        );
                        vuln.setRecommendations(Arrays.asList(
                                "Строго валидируйте параметры закрытия счета",
                                "Запретите дополнительные поля в запросе закрытия",
                                "Проверяйте принадлежность счетов"
                        ));
                        vulnerabilities.add(vuln);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при тесте закрытия счета: " + e.getMessage());
        }
    }

    private void testSensitiveDataExposure(String baseUrl, String token,
                                           List<Vulnerability> vulnerabilities,
                                           ApiClient apiClient) {
        System.out.println("   🔓 Тестирование раскрытия чувствительных данных...");

        Map<String, String> endpointsToTest = new HashMap<>();
        endpointsToTest.put("/accounts", "GET");
        endpointsToTest.put("/products", "GET");
        endpointsToTest.put("/auth/me", "GET");

        for (Map.Entry<String, String> entry : endpointsToTest.entrySet()) {
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
                        String responseBody = apiResponse.getBody();
                        List<String> sensitiveFields = findFieldsByPatterns(responseBody, SENSITIVE_PATTERNS);
                        List<String> piiFields = findFieldsByPatterns(responseBody, PII_PATTERNS);
                        List<String> internalFields = findFieldsByPatterns(responseBody, INTERNAL_PATTERNS);

                        if (!sensitiveFields.isEmpty()) {
                            Vulnerability vuln = createVulnerability(
                                    "Раскрытие чувствительных данных в " + endpoint,
                                    "Обнаружены чувствительные поля: " + sensitiveFields,
                                    Vulnerability.Severity.HIGH,
                                    endpoint,
                                    method,
                                    apiResponse.getStatusCode()
                            );
                            vulnerabilities.add(vuln);
                        }

                        if (!piiFields.isEmpty()) {
                            Vulnerability vuln = createVulnerability(
                                    "Раскрытие PII данных в " + endpoint,
                                    "Обнаружены PII поля: " + piiFields,
                                    Vulnerability.Severity.MEDIUM,
                                    endpoint,
                                    method,
                                    apiResponse.getStatusCode()
                            );
                            vulnerabilities.add(vuln);
                        }

                        if (!internalFields.isEmpty()) {
                            Vulnerability vuln = createVulnerability(
                                    "Раскрытие внутренней информации в " + endpoint,
                                    "Обнаружены внутренние поля: " + internalFields,
                                    Vulnerability.Severity.LOW,
                                    endpoint,
                                    method,
                                    apiResponse.getStatusCode()
                            );
                            vulnerabilities.add(vuln);
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("⚠️ Ошибка при тесте раскрытия данных для " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private void testConsentManipulation(String baseUrl, String token,
                                         List<Vulnerability> vulnerabilities,
                                         ApiClient apiClient) {
        System.out.println("   📝 Тестирование манипуляции согласиями...");

        // Пытаемся создать согласие с расширенными правами
        String maliciousConsentPayload =
                "{\"permissions\":[\"accounts\",\"payments\",\"admin_operations\"],\"scope\":\"full_access\"}";

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("POST",
                    baseUrl + "/account-consents/request", maliciousConsentPayload, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() == 200) {
                    String responseBody = apiResponse.getBody().toLowerCase();
                    if (responseBody.contains("admin_operations") || responseBody.contains("full_access")) {
                        Vulnerability vuln = createVulnerability(
                                "Манипуляция правами согласия",
                                "Сервер принял запрос согласия с административными правами",
                                Vulnerability.Severity.HIGH,
                                "/account-consents/request",
                                "POST",
                                apiResponse.getStatusCode()
                        );
                        vuln.setRecommendations(Arrays.asList(
                                "Ограничьте доступные разрешения для клиентов",
                                "Реализуйте проверку scope согласий",
                                "Запретите клиентам выбирать административные права"
                        ));
                        vulnerabilities.add(vuln);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при тесте манипуляции согласиями: " + e.getMessage());
        }
    }

    private void testPaymentManipulation(String baseUrl, String token,
                                         List<Vulnerability> vulnerabilities,
                                         ApiClient apiClient) {
        System.out.println("   💸 Тестирование манипуляции платежами...");

        // Пытаемся создать платеж с подозрительными параметрами
        String maliciousPaymentPayload =
                "{\"amount\":0.01,\"currency\":\"RUB\",\"fee_override\":0,\"priority\":\"urgent\"}";

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");
            headers.put("Accept", "application/json");

            Object response = apiClient.executeRequest("POST",
                    baseUrl + "/payments", maliciousPaymentPayload, headers);

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() == 200) {
                    String responseBody = apiResponse.getBody().toLowerCase();
                    if (responseBody.contains("fee_override") || responseBody.contains("urgent")) {
                        Vulnerability vuln = createVulnerability(
                                "Манипуляция параметрами платежа",
                                "Сервер принял запрос платежа с переопределенными параметрами",
                                Vulnerability.Severity.MEDIUM,
                                "/payments",
                                "POST",
                                apiResponse.getStatusCode()
                        );
                        vuln.setRecommendations(Arrays.asList(
                                "Фиксируйте комиссии на сервере",
                                "Ограничьте доступные приоритеты платежей",
                                "Валидируйте все параметры платежа"
                        ));
                        vulnerabilities.add(vuln);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при тесте манипуляции платежами: " + e.getMessage());
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
                    // Ищем account_id в ответе
                    String body = apiResponse.getBody();
                    java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"account_id\"\\s*:\\s*\"([^\"]+)\"");
                    java.util.regex.Matcher matcher = pattern.matcher(body);
                    if (matcher.find()) {
                        return matcher.group(1);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при получении account_id: " + e.getMessage());
        }
        return null;
    }

    private Vulnerability createVulnerability(String title, String description,
                                              Vulnerability.Severity severity,
                                              String endpoint, String method, int statusCode) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API3:2023 - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH); // Используем существующую категорию
        vuln.setEndpoint(endpoint);
        vuln.setMethod(method);
        vuln.setStatusCode(statusCode);

        // Базовые рекомендации
        vuln.setRecommendations(Arrays.asList(
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