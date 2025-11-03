package core;

import java.util.Map;
import java.util.HashMap;

public class ScanConfig {
    private String targetBaseUrl;
    private String password;
    private String accessToken;
    private String bankBaseUrl;
    private String clientId;
    private String clientSecret;
    private String targetUrl;
    private String openApiSpecUrl;

    // Добавляем поля для хранения токенов пользователей
    private Map<String, String> userTokens = new HashMap<>();

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

    // Метод для получения bankId
    public String getBankId() {
        if (bankId == null || bankId.isEmpty()) {
            // Если bankId не задан, пытаемся извлечь из clientId
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

}