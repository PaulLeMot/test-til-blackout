package scanners.owasp;

import core.*;
import scanners.SecurityScanner;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class API3_BOScanner implements SecurityScanner {

    private static final List<String> SUSPICIOUS_FIELDS = Arrays.asList(
            "admin", "role", "permission", "status", "premium", "override", "bypass",
            "limit", "amount", "balance", "system", "unlimited", "force", "privilege",
            "access_level", "max_uses", "max_amount", "max_total_amount", "admin_override",
            "bypass_checks", "force_close", "admin_approval", "system_account", "premium_features",
            "unlimited_access", "bypass_approval", "max_access_level", "unlimited_duration",
            "skip_balance_check", "force_approval", "limit_override", "high_risk_approved",
            "bypass_risk_check", "auto_approved", "special_conditions", "vip_status"
    );

    private ScanConfig config;

    @Override
    public String getName() {
        return "API3_BOPLA_Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        this.config = config;
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();

        try {
            String baseUrl = config.getTargetBaseUrl();

            System.out.println("API3_BOScanner: Starting comprehensive Mass Assignment tests for " + baseUrl);

            // ИСПРАВЛЕНИЕ: Используем токены из конфигурации, а не получаем их заново
            Map<String, String> tokens = config.getUserTokens();

            if (tokens == null || tokens.isEmpty()) {
                System.out.println("API3_BOScanner: No tokens in config, skipping scan");
                return vulnerabilities;
            }

            System.out.println("API3_BOScanner: Using " + tokens.size() + " tokens from config");

            // Тестируем все возможные эндпоинты с разными комбинациями
            vulnerabilities.addAll(testAllEndpoints(baseUrl, tokens, apiClient, mapper));

            System.out.println("API3_BOScanner: Completed. Found " + vulnerabilities.size() + " vulnerabilities");

        } catch (Exception e) {
            System.err.println("API3_BOScanner error: " + e.getMessage());
            e.printStackTrace();
        }

        return vulnerabilities;
    }

    /**
     * ТЕСТИРУЕМ ВСЕ ВОЗМОЖНЫЕ ЭНДПОИНТЫ
     */
    private List<Vulnerability> testAllEndpoints(String baseUrl, Map<String, String> tokens,
                                                 ApiClient apiClient, ObjectMapper mapper) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Тестируем с каждым токеном
        for (Map.Entry<String, String> tokenEntry : tokens.entrySet()) {
            String tokenType = tokenEntry.getKey();
            String token = tokenEntry.getValue();

            // Пропускаем служебные токены
            if (tokenType.equals("bank") || tokenType.equals("default")) {
                continue;
            }

            System.out.println("API3: Testing with token: " + tokenType);

            // Тестируем все эндпоинты с этим токеном
            vulnerabilities.addAll(testAccountEndpoints(baseUrl, token, tokenType, apiClient, mapper));
            vulnerabilities.addAll(testConsentEndpoints(baseUrl, token, tokenType, apiClient, mapper));
            vulnerabilities.addAll(testPaymentEndpoints(baseUrl, token, tokenType, apiClient, mapper));
            vulnerabilities.addAll(testOtherEndpoints(baseUrl, token, tokenType, apiClient, mapper));
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testAccountEndpoints(String baseUrl, String token, String tokenType,
                                                     ApiClient apiClient, ObjectMapper mapper) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            Map<String, String> headers = createHeaders(token);

            // Тест 1: Создание счета с Mass Assignment
            Map<String, Object> accountPayload = new HashMap<>();
            accountPayload.put("account_type", "checking");
            accountPayload.put("initial_balance", 9999999.00);
            accountPayload.put("system_account", true);
            accountPayload.put("admin_override", true);
            accountPayload.put("premium_features", true);
            accountPayload.put("overdraft_limit", 9999999.00);

            String payload = mapper.writeValueAsString(accountPayload);

            System.out.println("API3: Testing account creation with " + tokenType);
            Object response = apiClient.executeRequest("POST", baseUrl + "/accounts", payload, headers);

            vulnerabilities.addAll(analyzeResponse(response,
                    "Mass Assignment в создании счета",
                    "Эндпоинт /accounts уязвим к Mass Assignment с административными полями",
                    baseUrl + "/accounts", "POST", payload, tokenType));

            // Тест 2: Получение списка счетов (для проверки доступа)
            System.out.println("API3: Testing account list access with " + tokenType);
            Object listResponse = apiClient.executeRequest("GET", baseUrl + "/accounts", null, headers);

            if (listResponse != null && extractStatusCode(listResponse) == 200) {
                System.out.println("API3: Account list accessible with " + tokenType);

                // Если доступ есть, тестируем операции модификации
                String accountId = extractFirstAccountId(extractResponseBody(listResponse), mapper);
                if (accountId != null) {
                    vulnerabilities.addAll(testAccountModification(baseUrl, token, tokenType, accountId, apiClient, mapper));
                }
            }

        } catch (Exception e) {
            System.err.println("API3: Error testing account endpoints with " + tokenType + ": " + e.getMessage());
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testAccountModification(String baseUrl, String token, String tokenType,
                                                        String accountId, ApiClient apiClient, ObjectMapper mapper) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            Map<String, String> headers = createHeaders(token);

            // Тест изменения статуса с Mass Assignment
            Map<String, Object> statusPayload = new HashMap<>();
            statusPayload.put("status", "closed");
            statusPayload.put("force_close", true);
            statusPayload.put("admin_override", true);

            String payload = mapper.writeValueAsString(statusPayload);

            System.out.println("API3: Testing account status modification with " + tokenType);
            Object response = apiClient.executeRequest("PUT",
                    baseUrl + "/accounts/" + accountId + "/status", payload, headers);

            vulnerabilities.addAll(analyzeResponse(response,
                    "Mass Assignment в изменении статуса счета",
                    "Эндпоинт /accounts/{id}/status уязвим к Mass Assignment",
                    baseUrl + "/accounts/" + accountId + "/status", "PUT", payload, tokenType));

        } catch (Exception e) {
            System.err.println("API3: Error testing account modification with " + tokenType + ": " + e.getMessage());
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testConsentEndpoints(String baseUrl, String token, String tokenType,
                                                     ApiClient apiClient, ObjectMapper mapper) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            Map<String, String> headers = createHeaders(token);

            // ИСПРАВЛЕНИЕ: Используем clientId из конфигурации или username из токена
            String clientId = config.getClientId();
            if (clientId == null) {
                clientId = tokenType; // Используем имя токена как clientId
            }

            // Тест Account Consent с Mass Assignment
            Map<String, Object> accountConsentPayload = new HashMap<>();
            accountConsentPayload.put("client_id", clientId);
            accountConsentPayload.put("permissions", Arrays.asList(
                    "ReadAccountsDetail", "ReadBalances", "ReadTransactionsDetail",
                    "AdminAccess", "WriteAccess", "DeleteAccess"
            ));
            accountConsentPayload.put("reason", "Mass Assignment Test");
            accountConsentPayload.put("requesting_bank", config.getBankId());
            accountConsentPayload.put("max_access_level", "super_admin");
            accountConsentPayload.put("unlimited_duration", true);

            String accountConsentStr = mapper.writeValueAsString(accountConsentPayload);

            System.out.println("API3: Testing account consent with " + tokenType);
            Object accountResponse = apiClient.executeRequest("POST",
                    baseUrl + "/account-consents/request", accountConsentStr, headers);

            vulnerabilities.addAll(analyzeResponse(accountResponse,
                    "Mass Assignment в согласии на доступ к счетам",
                    "Эндпоинт /account-consents/request уязвим к Mass Assignment",
                    baseUrl + "/account-consents/request", "POST", accountConsentStr, tokenType));

        } catch (Exception e) {
            System.err.println("API3: Error testing consent endpoints with " + tokenType + ": " + e.getMessage());
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testPaymentEndpoints(String baseUrl, String token, String tokenType,
                                                     ApiClient apiClient, ObjectMapper mapper) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            // Сначала создаем простой consent для тестирования
            String consentId = createSimpleConsent(baseUrl, token, apiClient, mapper);
            if (consentId == null) {
                System.out.println("API3: No consent created for payment testing with " + tokenType);
                return vulnerabilities;
            }

            Map<String, String> headers = createHeaders(token);
            headers.put("X-Payment-Consent-Id", consentId);

            // Тест платежа с Mass Assignment
            Map<String, Object> paymentPayload = new HashMap<>();
            paymentPayload.put("data", Map.of(
                    "initiation", Map.of(
                            "instructionIdentification", "mass-assignment-test",
                            "endToEndIdentification", "bypass-test",
                            "instructedAmount", Map.of("amount", "9999999.00", "currency", "RUB"),
                            "debtorAccount", Map.of("identification", "4084fcf5c6cfb514fe", "name", "Test Account"),
                            "creditorAccount", Map.of("identification", "40808e72397159347f", "name", "Test Account 2"),
                            "remittanceInformation", Map.of("reference", "Mass Assignment Test")
                    )
            ));
            paymentPayload.put("risk", Map.of(
                    "bypass_risk_check", true,
                    "admin_override", true
            ));

            String payload = mapper.writeValueAsString(paymentPayload);

            System.out.println("API3: Testing payment with Mass Assignment with " + tokenType);
            Object response = apiClient.executeRequest("POST", baseUrl + "/payments", payload, headers);

            vulnerabilities.addAll(analyzeResponse(response,
                    "Mass Assignment в платежах",
                    "Эндпоинт /payments уязвим к Mass Assignment",
                    baseUrl + "/payments", "POST", payload, tokenType));

        } catch (Exception e) {
            System.err.println("API3: Error testing payment endpoints with " + tokenType + ": " + e.getMessage());
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testOtherEndpoints(String baseUrl, String token, String tokenType,
                                                   ApiClient apiClient, ObjectMapper mapper) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            Map<String, String> headers = createHeaders(token);

            // Тестируем другие возможные эндпоинты
            String[] otherEndpoints = {
                    "/transactions",
                    "/balances",
                    "/beneficiaries"
            };

            for (String endpoint : otherEndpoints) {
                Map<String, Object> testPayload = new HashMap<>();
                testPayload.put("test", "data");
                testPayload.put("admin_override", true);

                String payload = mapper.writeValueAsString(testPayload);

                System.out.println("API3: Testing " + endpoint + " with " + tokenType);
                Object response = apiClient.executeRequest("POST", baseUrl + endpoint, payload, headers);

                vulnerabilities.addAll(analyzeResponse(response,
                        "Mass Assignment в " + endpoint,
                        "Эндпоинт " + endpoint + " потенциально уязвим к Mass Assignment",
                        baseUrl + endpoint, "POST", payload, tokenType));
            }

        } catch (Exception e) {
            System.err.println("API3: Error testing other endpoints with " + tokenType + ": " + e.getMessage());
        }

        return vulnerabilities;
    }

    private String createSimpleConsent(String baseUrl, String token, ApiClient apiClient, ObjectMapper mapper) {
        try {
            String clientId = config.getClientId();
            if (clientId == null) {
                return null; // Не можем создать consent без clientId
            }

            Map<String, Object> consentPayload = new HashMap<>();
            consentPayload.put("requesting_bank", config.getBankId());
            consentPayload.put("client_id", clientId);
            consentPayload.put("debtor_account", "4084fcf5c6cfb514fe");
            consentPayload.put("consent_type", "single_use");
            consentPayload.put("max_amount_per_payment", 1000.00);

            String payload = mapper.writeValueAsString(consentPayload);
            Map<String, String> headers = createHeaders(token);

            Object response = apiClient.executeRequest("POST",
                    baseUrl + "/payment-consents/request", payload, headers);

            if (response != null && extractStatusCode(response) == 200) {
                String responseBody = extractResponseBody(response);
                if (responseBody != null && responseBody.contains("consent_id")) {
                    JsonNode json = mapper.readTree(responseBody);
                    if (json.has("consent_id")) {
                        return json.get("consent_id").asText();
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("API3: Error creating simple consent: " + e.getMessage());
        }
        return null;
    }

    private List<Vulnerability> analyzeResponse(Object response, String title, String description,
                                                String endpoint, String method, String requestPayload, String tokenType) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (response == null) return vulnerabilities;

        int statusCode = extractStatusCode(response);
        String responseBody = extractResponseBody(response);

        System.out.println("API3: Response for " + endpoint + " with " + tokenType + ": " + statusCode);

        // Анализируем ответ на предмет уязвимостей Mass Assignment
        if (statusCode == 200 || statusCode == 201) {
            // Успешный запрос - проверяем, приняты ли подозрительные поля
            if (containsSuspiciousFields(responseBody) ||
                    (responseBody != null && (
                            responseBody.contains("auto_approved") ||
                                    responseBody.contains("admin_override") ||
                                    responseBody.contains("bypass") ||
                                    responseBody.contains("premium") ||
                                    responseBody.contains("unlimited"))
                    )) {

                Vulnerability vuln = createVulnerability(
                        title + " (" + tokenType + ")",
                        description + "\nТокен: " + tokenType + "\nСтатус: " + statusCode,
                        endpoint,
                        method,
                        requestPayload,
                        responseBody
                );
                vulnerabilities.add(vuln);
            }
        } else if (statusCode == 403) {
            System.out.println("API3: 403 Forbidden for " + endpoint + " with " + tokenType);
        } else if (statusCode >= 400) {
            System.out.println("API3: Error " + statusCode + " for " + endpoint + " with " + tokenType);
        }

        return vulnerabilities;
    }

    private String extractFirstAccountId(String responseBody, ObjectMapper mapper) {
        try {
            if (responseBody == null) return null;
            JsonNode json = mapper.readTree(responseBody);

            // Различные возможные структуры ответа
            if (json.has("data") && json.get("data").has("account")) {
                JsonNode accounts = json.get("data").get("account");
                if (accounts.isArray() && accounts.size() > 0) {
                    return accounts.get(0).get("accountId").asText();
                }
            }
            if (json.has("account")) {
                JsonNode accounts = json.get("account");
                if (accounts.isArray() && accounts.size() > 0) {
                    return accounts.get(0).get("accountId").asText();
                }
            }
            if (json.has("accounts")) {
                JsonNode accounts = json.get("accounts");
                if (accounts.isArray() && accounts.size() > 0) {
                    return accounts.get(0).get("accountId").asText();
                }
            }
        } catch (Exception e) {
            System.err.println("API3: Error extracting account ID: " + e.getMessage());
        }
        return null;
    }

    private Map<String, String> createHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Content-Type", "application/json");
        headers.put("X-Requesting-Bank", config.getBankId());
        headers.put("Accept", "application/json");
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        return headers;
    }

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

    private String extractResponseBody(Object response) {
        try {
            if (response instanceof core.ApiResponse) {
                return ((core.ApiResponse) response).getBody();
            } else if (response instanceof HttpApiClient.ApiResponse) {
                return ((HttpApiClient.ApiResponse) response).getBody();
            } else {
                return (String) response.getClass().getMethod("getBody").invoke(response);
            }
        } catch (Exception e) {
            return null;
        }
    }

    private boolean containsSuspiciousFields(String responseBody) {
        if (responseBody == null) return false;
        String lowerBody = responseBody.toLowerCase();
        for (String field : SUSPICIOUS_FIELDS) {
            if (lowerBody.contains(field.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private Vulnerability createVulnerability(String title, String description, String endpoint,
                                              String method, String requestPayload, String responseBody) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(Vulnerability.Severity.HIGH);
        vuln.setCategory(Vulnerability.Category.OWASP_API3_BOPLA);
        vuln.setEndpoint(endpoint);
        vuln.setMethod(method);

        String evidence = "Запрос (" + method + " " + endpoint + "):\n" +
                requestPayload + "\n\nОтвет:\n" +
                (responseBody != null && responseBody.length() > 1000 ?
                        responseBody.substring(0, 1000) + "..." : responseBody);
        vuln.setEvidence(evidence);

        vuln.setRecommendations(Arrays.asList(
                "Реализуйте whitelist для полей, которые могут быть установлены клиентом",
                "Используйте DTO (Data Transfer Objects) с явным указанием разрешенных полей",
                "Включите защиту от mass assignment в фреймворке",
                "Разделите поля на пользовательские и системные",
                "Валидируйте все входящие поля на сервере",
                "Используйте схемы валидации для всех входящих данных"
        ));

        return vuln;
    }
}