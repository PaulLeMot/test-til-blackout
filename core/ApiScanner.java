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
            // Используем RealApiClient
            ApiClient apiClient = new RealApiClient();
            
            List<Future<List<Vulnerability>>> futures = new ArrayList<>();
            
            for (Object scanner : securityScanners) {
                if (scanner instanceof scanners.SecurityScanner) {
                    scanners.SecurityScanner secScanner = (scanners.SecurityScanner) scanner;
                    System.out.println("🔍 Running scanner: " + secScanner.getName());
                    
                    // Запускаем в отдельном потоке
                    Future<List<Vulnerability>> future = executorService.submit(() -> {
                        return secScanner.scan(null, config, apiClient);
                    });
                    futures.add(future);
                }
            }
            
            // Собираем результаты
            for (Future<List<Vulnerability>> future : futures) {
                try {
                    List<Vulnerability> scannerVulns = future.get(30, TimeUnit.SECONDS);
                    result.addVulnerabilities(scannerVulns);
                    System.out.println("✅ Scanner found: " + scannerVulns.size() + " vulnerabilities");
                } catch (TimeoutException e) {
                    System.err.println("⚠ Scanner timeout (30s)");
                } catch (Exception e) {
                    System.err.println("⚠ Scanner error: " + e.getMessage());
                }
            }
            
            result.complete();
            System.out.println("✅ Scan completed successfully!");
            
        } catch (Exception e) {
            System.err.println("❌ Scan failed: " + e.getMessage());
            result.fail(e.getMessage());
        } finally {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
            }
        }
        
        return result;
    }
    
    public void shutdown() {
        if (executorService != null) {
            executorService.shutdown();
        }
    }
}
