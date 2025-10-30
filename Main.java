import core.*;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;
import scanners.owasp.API2_BrokenAuthScanner;
import scanners.owasp.API3_BOScanner;
import scanners.owasp.API4_URCScanner;
import scanners.owasp.API5_BrokenFunctionLevelAuthScanner;
import scanners.owasp.API6_BusinessFlowScanner;
import scanners.owasp.API7_SSRFScanner;
import scanners.owasp.API8_SecurityConfigScanner;
import scanners.owasp.API9_InventoryScanner;
import scanners.owasp.API10_UnsafeConsumptionScanner;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Security Scanner");
        System.out.println("🎯 Целевые уязвимости: OWASP API Security Top 10\n");

        final String PASSWORD = "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";
        final List<String> BANKS = Arrays.asList(
                "https://vbank.open.bankingapi.ru",
                "https://abank.open.bankingapi.ru", 
                "https://sbank.open.bankingapi.ru"
        );

        // Создаём сканеры
        List<SecurityScanner> securityScanners = new ArrayList<>();
        securityScanners.add(new API1_BOLAScanner());
        securityScanners.add(new API2_BrokenAuthScanner());
        securityScanners.add(new API3_BOScanner());
        securityScanners.add(new API4_URCScanner());
        securityScanners.add(new API5_BrokenFunctionLevelAuthScanner());
	securityScanners.add(new API6_BusinessFlowScanner());
        securityScanners.add(new API7_SSRFScanner());
        securityScanners.add(new API8_SecurityConfigScanner());
        securityScanners.add(new API9_InventoryScanner());
        securityScanners.add(new API10_UnsafeConsumptionScanner());

        System.out.println("📋 Зарегистрировано сканеров: " + securityScanners.size());

        // Итоговая статистика
        int totalVulnerabilities = 0;
        int totalScannedBanks = 0;
        List<String> failedBanks = new ArrayList<>();

        for (String baseUrl : BANKS) {
            System.out.println("\n" + "=".repeat(50));
            System.out.println("🛡  Сканирование: " + baseUrl);
            System.out.println("=".repeat(50));

            try {
                ScanConfig config = new ScanConfig();
                config.setTargetBaseUrl(baseUrl);
                config.setPassword(PASSWORD);
                config.setBankBaseUrl(baseUrl);
                config.setClientId("team172");
                config.setClientSecret(PASSWORD);

                ApiScanner apiScanner = new ApiScanner();

                // Регистрируем сканеры
                for (SecurityScanner scanner : securityScanners) {
                    apiScanner.registerSecurityScanner(scanner);
                }

                ScanResult result = apiScanner.performScan(config);
                totalScannedBanks++;
                int bankVulnerabilities = result.getVulnerabilities().size();
                totalVulnerabilities += bankVulnerabilities;

                // Статистика по сканерам
                Map<String, Integer> scannerStats = new HashMap<>();
                for (Vulnerability vuln : result.getVulnerabilities()) {
                    String category = vuln.getCategory().toString();
                    scannerStats.put(category, scannerStats.getOrDefault(category, 0) + 1);
                }

                // Уровни серьезности
                long criticalCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.CRITICAL).count();
                long highCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.HIGH).count();
                long mediumCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.MEDIUM).count();
                long lowCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.LOW).count();

                System.out.println("📊 Результаты:");
                System.out.println("   ✅ Статус: " + result.getStatus());
                System.out.println("   🎯 Уязвимостей: " + bankVulnerabilities);
                System.out.println("   📈 Уровни: 💀" + criticalCount + " 🔴" + highCount + 
                                 " 🟡" + mediumCount + " 🔵" + lowCount);

                // Статистика по сканерам
                System.out.println("\n   🔍 Результаты по сканерам:");
                printScannerStats(scannerStats, "OWASP_API1_BOLA", "API1 - BOLA");
                printScannerStats(scannerStats, "OWASP_API2_BROKEN_AUTH", "API2 - Broken Auth");
                printScannerStats(scannerStats, "OWASP_API3_BOPLA", "API3 - BOPLA"); 
                printScannerStats(scannerStats, "OWASP_API4_URC", "API4 - URC");
                printScannerStats(scannerStats, "OWASP_API6_BUSINESS_FLOW", "API6 - Business Flow");
                printScannerStats(scannerStats, "OWASP_API7_SSRF", "API7 - SSRF");
                printScannerStats(scannerStats, "OWASP_API8_SM", "API8 - Security Config");
                printScannerStats(scannerStats, "OWASP_API9_INVENTORY", "API9 - Inventory");
                printScannerStats(scannerStats, "OWASP_API10_UNSAFE_CONSUMPTION", "API10 - Unsafe Consumption");

                if (highCount > 0 || criticalCount > 0) {
                    System.out.println("   🚨 Обнаружены критические уязвимости!");
                }

            } catch (Exception e) {
                System.err.println("❌ Ошибка: " + e.getMessage());
                failedBanks.add(baseUrl);
            }
        }

        // Финальная сводка
        System.out.println("\n" + "=".repeat(50));
        System.out.println("🏁 СКАНИРОВАНИЕ ЗАВЕРШЕНО");
        System.out.println("=".repeat(50));

        System.out.println("\n📊 ИТОГОВАЯ СТАТИСТИКА:");
        System.out.println("   🏦 Просканировано: " + totalScannedBanks + "/" + BANKS.size());
        System.out.println("   🎯 Всего уязвимостей: " + totalVulnerabilities);
        
        if (!failedBanks.isEmpty()) {
            System.out.println("   ❌ Ошибки: " + failedBanks.size() + " банков");
        }

        if (totalVulnerabilities == 0) {
            System.out.println("🎉 Уязвимостей не обнаружено.");
        } else {
            System.out.println("💡 Рекомендуется устранение уязвимостей HIGH/CRITICAL уровня");
        }
    }

    private static void printScannerStats(Map<String, Integer> stats, String category, String name) {
        int count = stats.getOrDefault(category, 0);
        if (count > 0) {
            System.out.println("      • " + name + ": " + count + " уязвимостей");
        }
    }
}
