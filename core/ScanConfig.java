package core;

public class ScanConfig {
    private String targetBaseUrl;
    private String password;
    private String accessToken;
    private String bankBaseUrl;
    private String clientId;
    private String clientSecret;

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
        return targetBaseUrl; // fallback to targetBaseUrl if bankBaseUrl not set
    }
    public void setBankBaseUrl(String bankBaseUrl) { this.bankBaseUrl = bankBaseUrl; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
}
