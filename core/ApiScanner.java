package core;

import java.util.*;
import java.util.concurrent.*;

public class ApiScanner {
    private List<Object> securityScanners = new ArrayList<>();
    private ExecutorService executorService;
    
    public ApiScanner() {
        this.executorService = Executors.newFixedThreadPool(2);
    }
    
    public void registerSecurityScanner(Object scanner) {
        this.securityScanners.add(scanner);
        System.out.println("Registered scanner: " + scanner.getClass().getSimpleName());
    }
    
    public ScanResult performScan(ScanConfig config) {
        ScanResult result = new ScanResult();
        result.setConfig(config);
        
        System.out.println("🚀 Starting API security scan...");
        result.setStatus(ScanResult.ScanStatus.RUNNING);
        
        try {
            // ВЫЗЫВАЕМ ВСЕ ЗАРЕГИСТРИРОВАННЫЕ СКАНЕРЫ
            ApiClient apiClient = new StandardApiClient();
            
            for (Object scanner : securityScanners) {
                if (scanner instanceof scanners.SecurityScanner) {
                    scanners.SecurityScanner secScanner = (scanners.SecurityScanner) scanner;
                    System.out.println("🔍 Running scanner: " + secScanner.getName());
                    
                    List<Vulnerability> scannerVulns = secScanner.scan(null, config, apiClient);
                    result.addVulnerabilities(scannerVulns);
                    System.out.println("✅ " + secScanner.getName() + " found: " + scannerVulns.size() + " vulnerabilities");
                }
            }
            
            result.complete();
            System.out.println("✅ Scan completed successfully!");
            
        } catch (Exception e) {
            System.err.println("❌ Scan failed: " + e.getMessage());
            result.fail(e.getMessage());
        } finally {
            executorService.shutdown();
        }
        
        return result;
    }
    
    public void shutdown() {
        if (executorService != null) {
            executorService.shutdown();
        }
    }
}
