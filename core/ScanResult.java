// core/ScanResult.java
package core;

import java.util.ArrayList;
import java.util.List;

public class ScanResult {
    public enum ScanStatus {
        PENDING, RUNNING, COMPLETED, FAILED
    }

    private ScanStatus status;
    private List<Vulnerability> vulnerabilities;
    private ScanConfig config;
    private String errorMessage;

    public ScanResult() {
        this.vulnerabilities = new ArrayList<>();
        this.status = ScanStatus.PENDING;
    }

    // Getters and Setters
    public ScanStatus getStatus() { return status; }
    public void setStatus(ScanStatus status) { this.status = status; }

    public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<Vulnerability> vulnerabilities) { this.vulnerabilities = vulnerabilities; }

    public ScanConfig getConfig() { return config; }
    public void setConfig(ScanConfig config) { this.config = config; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    // Вспомогательные методы
    public void addVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }

    public void complete() {
        this.status = ScanStatus.COMPLETED;
    }

    public void fail(String errorMessage) {
        this.status = ScanStatus.FAILED;
        this.errorMessage = errorMessage;
    }

    // Удален дублирующий метод getStatus() который возвращал String
    // Для получения строкового представления используйте getStatus().toString()
}