package core;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

public class ScanConfig {
    private String targetBaseUrl;
    private String password;
    private String accessToken;
    private String bankBaseUrl;
    private String clientId;
    private String clientSecret;
    private String targetUrl;
    private String openApiSpecUrl;
    private String consentId; // Новое поле для хранения ID согласия

    // Добавляем поля для хранения токенов пользователей
    private Map<String, String> userTokens = new HashMap<>();

    // Новые поля для конфигурации из UI
    private List<BankConfig> banks = new ArrayList<>();
    private List<UserCredentials> credentials = new ArrayList<>();

    public ScanConfig() {}

    // Getters and Setters
    public String getTargetBaseUrl() { return targetBaseUrl; }
    public void setTargetBaseUrl(String targetBaseUrl) { this.targetBaseUrl = targetBaseUrl; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }

    public String getBankBaseUrl() {
        if (bankBaseUrl != null) return bankBaseUrl;
        return targetBaseUrl;
    }
    public void setBankBaseUrl(String bankBaseUrl) { this.bankBaseUrl = bankBaseUrl; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }

    public String getOpenApiSpecUrl() { return openApiSpecUrl; }
    public void setOpenApiSpecUrl(String specUrl) { this.openApiSpecUrl = specUrl; }

    // Геттер и сеттер для consentId
    public String getConsentId() {
        return consentId;
    }

    public void setConsentId(String consentId) {
        this.consentId = consentId;
    }

    // Новые методы для работы с токенами пользователей
    public Map<String, String> getUserTokens() { return userTokens; }
    public void setUserTokens(Map<String, String> userTokens) { this.userTokens = userTokens; }

    public void addUserToken(String username, String token) {
        this.userTokens.put(username, token);
    }

    public String getUserToken(String username) {
        return this.userTokens.get(username);
    }

    public boolean hasUserTokens() {
        return !this.userTokens.isEmpty();
    }

    public boolean hasMultipleUserTokens() {
        return this.userTokens.size() >= 2;
    }

    // Новое поле для хранения bankId
    private String bankId;

    /**
     * Получает ID банка. Для sandbox среды использует team172
     */
    public String getBankId() {
        if (bankId == null || bankId.isEmpty()) {
            // Для sandbox среды используем только префикс team172
            if (clientId != null && clientId.startsWith("team172")) {
                return "team172"; // Фиксированный bankId для sandbox
            }
            // Для других случаев - стандартная логика
            if (clientId != null && clientId.contains("-")) {
                return clientId.split("-")[0]; // Например, team172-8 -> team172
            }
            return "default-bank"; // Дефолтное значение
        }
        return bankId;
    }

    // Метод для установки bankId
    public void setBankId(String bankId) {
        this.bankId = bankId;
    }

    /**
     * Получение токена банка для межбанковских запросов
     * @return bank token для текущей конфигурации
     */
    public String getBankToken() {
        // Сначала проверяем ключ "bank", который используется в AuthManager.getTokensForScanning()
        String bankToken = getUserToken("bank");

        // Если не нашли, пробуем получить токен по ключу bankId
        if (bankToken == null || bankToken.isEmpty()) {
            bankToken = getUserToken(getBankId());
        }

        // Если не нашли, пробуем получить токен по умолчанию
        if (bankToken == null || bankToken.isEmpty()) {
            bankToken = getUserToken("default");
        }

        // Если все еще нет токена, используем основной токен доступа
        if (bankToken == null || bankToken.isEmpty()) {
            bankToken = getAccessToken();
        }

        return bankToken;
    }

    // Getters and Setters для новой конфигурации
    public List<BankConfig> getBanks() { return banks; }
    public void setBanks(List<BankConfig> banks) { this.banks = banks; }

    public List<UserCredentials> getCredentials() { return credentials; }
    public void setCredentials(List<UserCredentials> credentials) { this.credentials = credentials; }

    // Внутренние классы для конфигурации
    public static class BankConfig {
        private String baseUrl;
        private String specUrl;

        public BankConfig() {}

        public BankConfig(String baseUrl, String specUrl) {
            this.baseUrl = baseUrl;
            this.specUrl = specUrl;
        }

        // Getters and Setters
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

        public String getSpecUrl() { return specUrl; }
        public void setSpecUrl(String specUrl) { this.specUrl = specUrl; }
    }

    public static class UserCredentials {
        private String username;
        private String password;

        public UserCredentials() {}

        public UserCredentials(String username, String password) {
            this.username = username;
            this.password = password;
        }

        // Getters and Setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}