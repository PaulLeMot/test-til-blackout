package core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScanConfig {
    private String bankId;
    private String clientId;
    private String clientSecret;
    private String bankBaseUrl;
    private String targetBaseUrl;
    private String openApiSpecUrl;
    private String consentId;
    private List<BankConfig> banks = new ArrayList<>();
    private List<UserCredentials> credentials = new ArrayList<>();
    private Map<String, String> userTokens = new HashMap<>();

    // Конструктор по умолчанию
    public ScanConfig() {}

    // Геттеры и сеттеры для основных полей
    public String getBankId() { return bankId; }
    public void setBankId(String bankId) { this.bankId = bankId; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getBankBaseUrl() { return bankBaseUrl; }
    public void setBankBaseUrl(String bankBaseUrl) { this.bankBaseUrl = bankBaseUrl; }

    public String getTargetBaseUrl() { return targetBaseUrl; }
    public void setTargetBaseUrl(String targetBaseUrl) { this.targetBaseUrl = targetBaseUrl; }

    public String getOpenApiSpecUrl() { return openApiSpecUrl; }
    public void setOpenApiSpecUrl(String openApiSpecUrl) { this.openApiSpecUrl = openApiSpecUrl; }

    public String getConsentId() { return consentId; }
    public void setConsentId(String consentId) { this.consentId = consentId; }

    public List<BankConfig> getBanks() { return banks; }
    public void setBanks(List<BankConfig> banks) { this.banks = banks; }

    public List<UserCredentials> getCredentials() { return credentials; }
    public void setCredentials(List<UserCredentials> credentials) { this.credentials = credentials; }

    public Map<String, String> getUserTokens() { return userTokens; }
    public void setUserTokens(Map<String, String> userTokens) { this.userTokens = userTokens; }

    // Методы для работы с токенами

    /**
     * Получить access token (токен по умолчанию)
     */
    public String getAccessToken() {
        if (userTokens.containsKey("default")) {
            return userTokens.get("default");
        } else if (!userTokens.isEmpty()) {
            // Возвращаем первый доступный токен
            return userTokens.values().iterator().next();
        }
        return null;
    }

    /**
     * Получить bank token
     */
    public String getBankToken() {
        if (userTokens.containsKey("bank")) {
            return userTokens.get("bank");
        } else if (bankId != null && userTokens.containsKey(bankId)) {
            return userTokens.get(bankId);
        }
        return null;
    }

    /**
     * Получить токен для конкретного пользователя
     */
    public String getTokenForUser(String username) {
        return userTokens.get(username);
    }

    /**
     * Получить токен первого пользователя
     */
    public String getFirstUserToken() {
        if (!credentials.isEmpty()) {
            String firstUsername = credentials.get(0).getUsername();
            return getTokenForUser(firstUsername);
        }
        return getAccessToken();
    }

    /**
     * Получить токен второго пользователя (для BOLA тестов)
     */
    public String getSecondUserToken() {
        if (credentials.size() >= 2) {
            String secondUsername = credentials.get(1).getUsername();
            return getTokenForUser(secondUsername);
        }
        return null;
    }

    /**
     * Добавить токен пользователя
     */
    public void addUserToken(String username, String token) {
        this.userTokens.put(username, token);
    }

    /**
     * Проверить наличие токенов
     */
    public boolean hasTokens() {
        return !userTokens.isEmpty();
    }

    /**
     * Проверить наличие bank token
     */
    public boolean hasBankToken() {
        return getBankToken() != null;
    }

    // Вложенные классы

    public static class BankConfig {
        private String baseUrl;
        private String specUrl;

        public BankConfig(String baseUrl, String specUrl) {
            this.baseUrl = baseUrl;
            this.specUrl = specUrl;
        }

        // Геттеры и сеттеры для BankConfig
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

        public String getSpecUrl() { return specUrl; }
        public void setSpecUrl(String specUrl) { this.specUrl = specUrl; }
    }

    public static class UserCredentials {
        private String username;
        private String password;

        public UserCredentials(String username, String password) {
            this.username = username;
            this.password = password;
        }

        // Геттеры и сеттеры для UserCredentials
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}