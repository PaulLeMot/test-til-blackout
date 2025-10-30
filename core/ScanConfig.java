// core/ScanConfig.java
package core;

public class ScanConfig {
    private String targetBaseUrl;
    private String password;

    public ScanConfig() {}

    // Getters and Setters
    public String getTargetBaseUrl() { return targetBaseUrl; }
    public void setTargetBaseUrl(String targetBaseUrl) { this.targetBaseUrl = targetBaseUrl; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}