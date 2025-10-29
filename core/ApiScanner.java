package core;

import scanners.SecurityScanner;

import java.util.*;
import java.util.concurrent.*;

public class ApiScanner {
    private List<SecurityScanner> securityScanners = new ArrayList<>();
    private ExecutorService executorService;

    public ApiScanner() {
        this.executorService = Executors.newFixedThreadPool(2);
    }

    public void registerSecurityScanner(SecurityScanner scanner) {
        this.securityScanners.add(scanner);
        System.out.println("Registered scanner: " + scanner.getClass().getSimpleName());
    }

    public ScanResult performScan(ScanConfig config) {
        ScanResult result = new ScanResult();
        result.setConfig(config);
        result.setStatus(ScanResult.ScanStatus.RUNNING);

        try {
            List<Future<List<Vulnerability>>> futures = new ArrayList<>();

            for (SecurityScanner scanner : securityScanners) {
                System.out.println("🔍 Запуск сканера: " + scanner.getName());
                Future<List<Vulnerability>> future = executorService.submit(() -> {
                    return scanner.scan(null, config, null);
                });
                futures.add(future);
            }

            for (Future<List<Vulnerability>> future : futures) {
                try {
                    List<Vulnerability> vulns = future.get(30, TimeUnit.SECONDS);
                    for (Vulnerability v : vulns) {
                        result.addVulnerability(v);
                    }
                } catch (TimeoutException e) {
                    System.err.println("⚠️ Сканер превысил время ожидания (30s)");
                } catch (Exception e) {
                    System.err.println("⚠️ Ошибка при выполнении сканера: " + e.getMessage());
                    e.printStackTrace();
                }
            }

            result.complete();
            System.out.println("✅ Scan completed successfully!");

        } catch (Exception e) {
            System.err.println("❌ Scan failed: " + e.getMessage());
            e.printStackTrace();
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
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }
}