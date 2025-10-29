package core;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class ScanResult {
    private String scanId;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private ScanConfig config;
    private List<Vulnerability> vulnerabilities = new ArrayList<>();
    private Map<String, Object> scanMetrics = new HashMap<>();
    private ScanStatus status = ScanStatus.PENDING;
    private String errorMessage;
    
    public enum ScanStatus {
        PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    }
    
    public ScanResult() {
        this.scanId = UUID.randomUUID().toString();
        this.startTime = LocalDateTime.now();
    }
    
    public void addVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }
    
    public void addVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities.addAll(vulnerabilities);
    }
    
    public void setMetric(String key, Object value) {
        this.scanMetrics.put(key, value);
    }
    
    public void complete() {
        this.endTime = LocalDateTime.now();
        this.status = ScanStatus.COMPLETED;
        calculateMetrics();
    }
    
    public void fail(String errorMessage) {
        this.endTime = LocalDateTime.now();
        this.status = ScanStatus.FAILED;
        this.errorMessage = errorMessage;
    }
    
    private void calculateMetrics() {
        long duration = java.time.Duration.between(startTime, endTime).toSeconds();
        scanMetrics.put("durationSeconds", duration);
        scanMetrics.put("totalVulnerabilities", vulnerabilities.size());
    }
    
    // Getters and Setters
    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }
    
    public LocalDateTime getStartTime() { return startTime; }
    public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }
    
    public LocalDateTime getEndTime() { return endTime; }
    public void setEndTime(LocalDateTime endTime) { this.endTime = endTime; }
    
    public ScanConfig getConfig() { return config; }
    public void setConfig(ScanConfig config) { this.config = config; }
    
    public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<Vulnerability> vulnerabilities) { this.vulnerabilities = vulnerabilities; }
    
    public Map<String, Object> getScanMetrics() { return scanMetrics; }
    public void setScanMetrics(Map<String, Object> scanMetrics) { this.scanMetrics = scanMetrics; }
    
    public ScanStatus getStatus() { return status; }
    public void setStatus(ScanStatus status) { this.status = status; }
    
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}
