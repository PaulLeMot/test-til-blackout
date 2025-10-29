package core;

import java.util.*;

public class ScanConfig {
    private String specUrl;
    private String targetBaseUrl;
    private String outputFormat = "html";
    private int timeoutMs = 30000;
    
    private String bankBaseUrl;
    private String username;
    private String password;
    private String accessToken;
    
    // Getters and Setters
    public String getSpecUrl() { return specUrl; }
    public void setSpecUrl(String specUrl) { this.specUrl = specUrl; }
    
    public String getTargetBaseUrl() { return targetBaseUrl; }
    public void setTargetBaseUrl(String targetBaseUrl) { this.targetBaseUrl = targetBaseUrl; }
    
    public String getOutputFormat() { return outputFormat; }
    public void setOutputFormat(String outputFormat) { this.outputFormat = outputFormat; }
    
    public int getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(int timeoutMs) { this.timeoutMs = timeoutMs; }
    
    public String getBankBaseUrl() { return bankBaseUrl; }
    public void setBankBaseUrl(String bankBaseUrl) { this.bankBaseUrl = bankBaseUrl; }
    
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
}
