package scanners.owasp;

import core.*;
import scanners.SecurityScanner;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
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

    @Override
    public String getName() {
        return "API3_BOPLA_Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();

        try {
            String baseUrl = config.getTargetBaseUrl();

            System.out.println("API3_BOScanner: Starting comprehensive Mass Assignment tests for " + baseUrl);

            // Получаем свежие токены с разными методами
            Map<String, String> tokens = getAllTokens(baseUrl, config);

            if (tokens.isEmpty()) {
                System.out.println("API3_BOScanner: No tokens obtained, skipping scan");
                return vulnerabilities;
            }

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
     * ПОЛУЧАЕМ ВСЕ ВОЗМОЖНЫЕ ТОКЕНЫ РАЗНЫМИ СПОСОБАМИ
     */
    private Map<String, String> getAllTokens(String baseUrl, ScanConfig config) {
        Map<String, String> tokens = new HashMap<>();

        try {
            // Получаем учетные данные из конфигурации
            String username = "team172-1";
            String password = "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";

            if (!config.getCredentials().isEmpty()) {
                username = config.getCredentials().get(0).getUsername();
                password = config.getCredentials().get(0).getPassword();
            }

            System.out.println("API3: Getting ALL tokens for: " + username);

            // 1. Client token через /auth/login (основной)
            String clientToken1 = getTokenViaLogin(baseUrl, username, password);
            if (clientToken1 != null) {
                tokens.put("client_login", clientToken1);
                System.out.println("API3: Client token (login) obtained");
            }

            // 2. Bank token через /auth/bank-token (основной)
            String bankToken1 = getTokenViaBankToken(baseUrl, "team172", password);
            if (bankToken1 != null) {
                tokens.put("bank_token", bankToken1);
                System.out.println("API3: Bank token (bank-token) obtained");
            }

            // 3. Bank token через /auth/bank-token с client token
            if (clientToken1 != null) {
                String bankToken2 = getTokenViaBankTokenWithAuth(baseUrl, "team172", password, clientToken1);
                if (bankToken2 != null) {
                    tokens.put("bank_token_auth", bankToken2);
                    System.out.println("API3: Bank token (with auth) obtained");
                }
            }

            // 4. Пробуем другие пользователи
            for (int i = 2; i <= 3; i++) {
                String altUser = "team172-" + i;
                String altToken = getTokenViaLogin(baseUrl, altUser, password);
                if (altToken != null) {
                    tokens.put("client_" + altUser, altToken);
                    System.out.println("API3: Token for " + altUser + " obtained");
                }
            }

            System.out.println("API3: Total tokens obtained: " + tokens.size());

        } catch (Exception e) {
            System.err.println("API3: Error getting tokens: " + e.getMessage());
        }

        return tokens;
    }

    private String getTokenViaLogin(String baseUrl, String username, String password) {
        try {
            String loginUrl = baseUrl + "/auth/login";

            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("username", username);
            requestBody.put("password", password);

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String jsonBody = new ObjectMapper().writeValueAsString(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(loginUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("API3: Login response for " + username + ": " + response.statusCode());

            if (response.statusCode() == 200) {
                return extractTokenFromResponse(response.body());
            }

        } catch (Exception e) {
            System.err.println("API3: Error in getTokenViaLogin: " + e.getMessage());
        }
        return null;
    }

    private String getTokenViaBankToken(String baseUrl, String clientId, String clientSecret) {
        try {
            String authUrl = baseUrl + "/auth/bank-token?client_id=" + clientId +
                    "&client_secret=" + clientSecret + "&grant_type=client_credentials";

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("API3: Bank token response: " + response.statusCode());

            if (response.statusCode() == 200) {
                return extractTokenFromResponse(response.body());
            }

        } catch (Exception e) {
            System.err.println("API3: Error in getTokenViaBankToken: " + e.getMessage());
        }
        return null;
    }

    private String getTokenViaBankTokenWithAuth(String baseUrl, String clientId, String clientSecret, String authToken) {
        try {
            String authUrl = baseUrl + "/auth/bank-token?client_id=" + clientId +
                    "&client_secret=" + clientSecret + "&grant_type=client_credentials";

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + authToken)
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("API3: Bank token with auth response: " + response.statusCode());

            if (response.statusCode() == 200) {
                return extractTokenFromResponse(response.body());
            }

        } catch (Exception e) {
            System.err.println("API3: Error in getTokenViaBankTokenWithAuth: " + e.getMessage());
        }
        return null;
    }

    private String extractTokenFromResponse(String responseBody) {
        try {
            if (responseBody == null) return null;

            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(responseBody);

            if (json.has("access_token")) {
                return json.get("access_token").asText();
            }
            if (json.has("token")) {
                return json.get("token").asText();
            }

            // Fallback: поиск в тексте
            if (responseBody.contains("access_token")) {
                String[] parts = responseBody.split("\"access_token\"\\s*:\\s*\"");
                if (parts.length > 1) {
                    return parts[1].split("\"")[0];
                }
            }

        } catch (Exception e) {
            System.err.println("API3: Error extracting token: " + e.getMessage());
        }
        return null;
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

            // Тест 1: Создание счета с Mass Assignment (полная версия как в curl)
            Map<String, Object> accountPayload = new HashMap<>();
            accountPayload.put("account_type", "checking");
            accountPayload.put("initial_balance", 9999999.00);
            accountPayload.put("system_account", true);
            accountPayload.put("admin_override", true);
            accountPayload.put("premium_features", true);
            accountPayload.put("overdraft_limit", 9999999.00);
            accountPayload.put("interest_rate", 0.15);
            accountPayload.put("status", "premium");
            accountPayload.put("creation_date", "2024-01-01");
            accountPayload.put("bank_code", "vbank");

            String payload = mapper.writeValueAsString(accountPayload);

            System.out.println("API3: Testing account creation (full payload) with " + tokenType);
            Object response = apiClient.executeRequest("POST", baseUrl + "/accounts", payload, headers);

            vulnerabilities.addAll(analyzeResponse(response,
                    "Mass Assignment в создании счета (полная версия)",
                    "Эндпоинт /accounts уязвим к Mass Assignment с полным набором административных полей",
                    baseUrl + "/accounts", "POST", payload, tokenType));

            // Тест 2: Создание счета с минимальным Mass Assignment
            Map<String, Object> minimalPayload = new HashMap<>();
            minimalPayload.put("account_type", "checking");
            minimalPayload.put("initial_balance", 1000.00);
            minimalPayload.put("admin_override", true); // Только одно подозрительное поле

            String minimalPayloadStr = mapper.writeValueAsString(minimalPayload);

            System.out.println("API3: Testing account creation (minimal) with " + tokenType);
            Object response2 = apiClient.executeRequest("POST", baseUrl + "/accounts", minimalPayloadStr, headers);

            vulnerabilities.addAll(analyzeResponse(response2,
                    "Mass Assignment в создании счета (минимальная версия)",
                    "Эндпоинт /accounts уязвим к Mass Assignment даже с одним административным полем",
                    baseUrl + "/accounts", "POST", minimalPayloadStr, tokenType));

            // Тест 3: Получение списка счетов (для проверки доступа)
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
            statusPayload.put("bypass_checks", true);

            String payload = mapper.writeValueAsString(statusPayload);

            System.out.println("API3: Testing account status modification with " + tokenType);
            Object response = apiClient.executeRequest("PUT",
                    baseUrl + "/accounts/" + accountId + "/status", payload, headers);

            vulnerabilities.addAll(analyzeResponse(response,
                    "Mass Assignment в изменении статуса счета",
                    "Эндпоинт /accounts/{id}/status уязвим к Mass Assignment",
                    baseUrl + "/accounts/" + accountId + "/status", "PUT", payload, tokenType));

            // Тест закрытия счета с Mass Assignment
            Map<String, Object> closePayload = new HashMap<>();
            closePayload.put("action", "transfer");
            closePayload.put("destination_account_id", "acc-4698");
            closePayload.put("force_transfer", true);
            closePayload.put("admin_approval", true);

            String closePayloadStr = mapper.writeValueAsString(closePayload);

            System.out.println("API3: Testing account close with " + tokenType);
            Object closeResponse = apiClient.executeRequest("PUT",
                    baseUrl + "/accounts/" + accountId + "/close", closePayloadStr, headers);

            vulnerabilities.addAll(analyzeResponse(closeResponse,
                    "Mass Assignment в закрытии счета",
                    "Эндпоинт /accounts/{id}/close уязвим к Mass Assignment",
                    baseUrl + "/accounts/" + accountId + "/close", "PUT", closePayloadStr, tokenType));

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

            // Тест Account Consent с Mass Assignment (полная версия)
            Map<String, Object> accountConsentPayload = new HashMap<>();
            accountConsentPayload.put("client_id", "team172-1");
            accountConsentPayload.put("permissions", Arrays.asList(
                    "ReadAccountsDetail", "ReadBalances", "ReadTransactionsDetail",
                    "AdminAccess", "WriteAccess", "DeleteAccess", "SystemOverride", "BypassLimits"
            ));
            accountConsentPayload.put("reason", "Mass Assignment Test");
            accountConsentPayload.put("requesting_bank", "team172");
            accountConsentPayload.put("requesting_bank_name", "Security Test");
            accountConsentPayload.put("max_access_level", "super_admin");
            accountConsentPayload.put("unlimited_duration", true);
            accountConsentPayload.put("bypass_approval", true);

            String accountConsentStr = mapper.writeValueAsString(accountConsentPayload);

            System.out.println("API3: Testing account consent with " + tokenType);
            Object accountResponse = apiClient.executeRequest("POST",
                    baseUrl + "/account-consents/request", accountConsentStr, headers);

            vulnerabilities.addAll(analyzeResponse(accountResponse,
                    "Mass Assignment в согласии на доступ к счетам",
                    "Эндпоинт /account-consents/request уязвим к Mass Assignment",
                    baseUrl + "/account-consents/request", "POST", accountConsentStr, tokenType));

            // Тест Payment Consent с Mass Assignment (полная версия)
            Map<String, Object> paymentConsentPayload = new HashMap<>();
            paymentConsentPayload.put("requesting_bank", "team172");
            paymentConsentPayload.put("client_id", "team172-1");
            paymentConsentPayload.put("debtor_account", "4084fcf5c6cfb514fe");
            paymentConsentPayload.put("consent_type", "multi_use");
            paymentConsentPayload.put("max_uses", 999);
            paymentConsentPayload.put("max_amount_per_payment", 9999999.00);
            paymentConsentPayload.put("max_total_amount", 999999999.00);
            paymentConsentPayload.put("allowed_creditor_accounts", Arrays.asList("40808e72397159347f", "408b4a2caf1b669427"));
            paymentConsentPayload.put("vrp_max_individual_amount", 50000.00);
            paymentConsentPayload.put("vrp_daily_limit", 1000000.00);
            paymentConsentPayload.put("vrp_monthly_limit", 30000000.00);
            paymentConsentPayload.put("valid_until", "2026-12-31T23:59:59");
            paymentConsentPayload.put("admin_override", true);
            paymentConsentPayload.put("unlimited_access", true);

            String paymentConsentStr = mapper.writeValueAsString(paymentConsentPayload);

            System.out.println("API3: Testing payment consent with " + tokenType);
            Object paymentResponse = apiClient.executeRequest("POST",
                    baseUrl + "/payment-consents/request", paymentConsentStr, headers);

            vulnerabilities.addAll(analyzeResponse(paymentResponse,
                    "Mass Assignment в платежном согласии",
                    "Эндпоинт /payment-consents/request уязвим к Mass Assignment",
                    baseUrl + "/payment-consents/request", "POST", paymentConsentStr, tokenType));

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
                            "debtorAccount", Map.of("identification", "4084fcf5c6cfb514fe", "name", "Our Account"),
                            "creditorAccount", Map.of("identification", "40808e72397159347f", "name", "Our Other Account", "bank_code", "vbank"),
                            "remittanceInformation", Map.of("reference", "Mass Assignment Test")
                    )
            ));
            paymentPayload.put("risk", Map.of(
                    "bypass_risk_check", true,
                    "admin_override", true,
                    "high_risk_approved", true
            ));
            paymentPayload.put("admin_parameters", Map.of(
                    "skip_balance_check", true,
                    "force_approval", true,
                    "limit_override", true
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
                    "/product-agreements",
                    "/transactions",
                    "/balances",
                    "/beneficiaries"
            };

            for (String endpoint : otherEndpoints) {
                Map<String, Object> testPayload = new HashMap<>();
                testPayload.put("test", "data");
                testPayload.put("admin_override", true);
                testPayload.put("bypass_checks", true);

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
            Map<String, Object> consentPayload = new HashMap<>();
            consentPayload.put("requesting_bank", "team172");
            consentPayload.put("client_id", "team172-1");
            consentPayload.put("debtor_account", "4084fcf5c6cfb514fe");
            consentPayload.put("consent_type", "single_use");
            consentPayload.put("max_amount_per_payment", 1000.00);

            String payload = mapper.writeValueAsString(consentPayload);
            Map<String, String> headers = createHeaders(token);

            Object response = apiClient.executeRequest("POST",
                    baseUrl + "/payment-consents/request", payload, headers);

            if (response != null) {
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
                    responseBody.contains("auto_approved") ||
                    responseBody.contains("admin_override") ||
                    responseBody.contains("bypass")) {

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
        } catch (Exception e) {
            System.err.println("API3: Error extracting account ID: " + e.getMessage());
        }
        return null;
    }

    private Map<String, String> createHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Content-Type", "application/json");
        headers.put("X-Requesting-Bank", "team172");
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