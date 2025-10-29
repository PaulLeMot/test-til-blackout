package core;

import java.util.*;

public class ScanConfig {
    private String specUrl;
    private String targetBaseUrl;
    private String outputFormat = "html";
    private int timeoutMs = 30000;
    
    // Getters and Setters
    public String getSpecUrl() { return specUrl; }
    public void setSpecUrl(String specUrl) { this.specUrl = specUrl; }
    
    public String getTargetBaseUrl() { return targetBaseUrl; }
    public void setTargetBaseUrl(String targetBaseUrl) { this.targetBaseUrl = targetBaseUrl; }
    
    public String getOutputFormat() { return outputFormat; }
    public void setOutputFormat(String outputFormat) { this.outputFormat = outputFormat; }
    
    public int getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(int timeoutMs) { this.timeoutMs = timeoutMs; }
}
