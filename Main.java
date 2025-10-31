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
        System.out.println("Запуск GOSTGuardian Security Scanner");
        System.out.println("Целевые уязвимости: OWASP API Security Top 10\n");

        final String PASSWORD = "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";
        final List<String> BANKS = Arrays.asList(
                "https://vbank.open.bankingapi.ru  ",
                "https://abank.open.bankingapi.ru  ",
                "https://sbank.open.bankingapi.ru  "
        );

        // Создаём сканеры
        List<SecurityScanner> securityScanners = Arrays.asList(
                new API1_BOLAScanner(),
                new API2_BrokenAuthScanner(),
                new API3_BOScanner(),
                new API4_URCScanner(),
                new API5_BrokenFunctionLevelAuthScanner(),
                new API6_BusinessFlowScanner(),
                new API7_SSRFScanner(),
                new API8_SecurityConfigScanner(),
                new API9_InventoryScanner(),
                new API10_UnsafeConsumptionScanner()
        );

        System.out.println("Зарегистрировано сканеров: " + securityScanners.size());

        // Итоговая статистика
        int totalVulnerabilities = 0;
        int totalScannedBanks = 0;
        List<String> failedBanks = new ArrayList<>();

        for (String baseUrl : BANKS) {
            System.out.println("\n" + "=".repeat(50));
            System.out.println("Сканирование: " + baseUrl);
            System.out.println("=".repeat(50));

            String cleanBaseUrl = baseUrl.trim();
            String specUrl = cleanBaseUrl + "/openapi.json";

            // === ЗАГРУЗКА OPENAPI-СПЕЦИФИКАЦИИ ===
            io.swagger.v3.oas.models.OpenAPI openAPI = null;
            try {
                OpenApiSpecLoader loader = new OpenApiSpecLoader(specUrl);
                openAPI = loader.getOpenAPI();
                System.out.println("✅ OpenAPI-спецификация загружена: " +
                        openAPI.getInfo().getTitle() + " v" + openAPI.getInfo().getVersion());
            } catch (Exception e) {
                System.err.println("⚠️ Не удалось загрузить OpenAPI-спецификацию по адресу: " + specUrl);
                System.err.println("   Причина: " + e.getMessage());
                // Продолжаем сканирование без спецификации
            }

            try {
                ScanConfig config = new ScanConfig();
                config.setTargetBaseUrl(cleanBaseUrl);
                config.setPassword(PASSWORD);
                config.setBankBaseUrl(cleanBaseUrl);
                config.setClientId("team172");
                config.setClientSecret(PASSWORD);

                List<Vulnerability> allVulnerabilities = new ArrayList<>();

                // Последовательно запускаем каждый сканер
                for (SecurityScanner scanner : securityScanners) {
                    System.out.println("\nЗапуск сканера: " + scanner.getName());
                    System.out.println("-".repeat(40));

                    try {
                        // Передаём объект OpenAPI (может быть null)
                        List<Vulnerability> scannerResults = scanner.scan(openAPI, config, new HttpApiClient());
                        allVulnerabilities.addAll(scannerResults);

                        System.out.println("Сканер " + scanner.getName() + " завершен. Найдено уязвимостей: " + scannerResults.size());

                        if (!scannerResults.isEmpty()) {
                            for (Vulnerability vuln : scannerResults) {
                                System.out.println("  • " + vuln.getTitle() + " [" + vuln.getSeverity() + "]");
                            }
                        }

                    } catch (Exception e) {
                        System.err.println("Ошибка в сканере " + scanner.getName() + ": " + e.getMessage());
                        e.printStackTrace(); // для отладки в хакатоне
                    }

                    try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                }

                totalScannedBanks++;
                int bankVulnerabilities = allVulnerabilities.size();
                totalVulnerabilities += bankVulnerabilities;

                // Статистика по сканерам
                Map<String, Integer> scannerStats = new HashMap<>();
                for (Vulnerability vuln : allVulnerabilities) {
                    String category = vuln.getCategory().toString();
                    scannerStats.put(category, scannerStats.getOrDefault(category, 0) + 1);
                }

                // Уровни серьезности
                long criticalCount = allVulnerabilities.stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.CRITICAL).count();
                long highCount = allVulnerabilities.stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.HIGH).count();
                long mediumCount = allVulnerabilities.stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.MEDIUM).count();
                long lowCount = allVulnerabilities.stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.LOW).count();

                System.out.println("\nРезультаты сканирования " + cleanBaseUrl + ":");
                System.out.println("   Статус: ЗАВЕРШЕНО");
                System.out.println("   Уязвимостей: " + bankVulnerabilities);
                System.out.println("   Уровни: КРИТИЧЕСКИХ-" + criticalCount + " ВЫСОКИХ-" + highCount +
                        " СРЕДНИХ-" + mediumCount + " НИЗКИХ-" + lowCount);

                // Статистика по сканерам
                System.out.println("\n   Результаты по сканерам:");
                printScannerStats(scannerStats, "OWASP_API1_BOLA", "API1 - BOLA");
                printScannerStats(scannerStats, "OWASP_API2_BROKEN_AUTH", "API2 - Broken Auth");
                printScannerStats(scannerStats, "OWASP_API3_BOPLA", "API3 - BOPLA");
                printScannerStats(scannerStats, "OWASP_API4_URC", "API4 - URC");
                printScannerStats(scannerStats, "OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH", "API5 - Broken Function Level Auth");
                printScannerStats(scannerStats, "OWASP_API6_BUSINESS_FLOW", "API6 - Business Flow");
                printScannerStats(scannerStats, "OWASP_API7_SSRF", "API7 - SSRF");
                printScannerStats(scannerStats, "OWASP_API8_SM", "API8 - Security Config");
                printScannerStats(scannerStats, "OWASP_API9_INVENTORY", "API9 - Inventory");
                printScannerStats(scannerStats, "OWASP_API10_UNSAFE_CONSUMPTION", "API10 - Unsafe Consumption");

                if (highCount > 0 || criticalCount > 0) {
                    System.out.println("   Обнаружены критические уязвимости!");
                }

            } catch (Exception e) {
                System.err.println("Ошибка при сканировании банка " + cleanBaseUrl + ": " + e.getMessage());
                e.printStackTrace();
                failedBanks.add(cleanBaseUrl);
            }

            System.out.println("\n" + "=".repeat(50));
            System.out.println("Завершено сканирование: " + cleanBaseUrl);
            System.out.println("=".repeat(50));

            try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
        }

        // Финальная сводка
        System.out.println("\n" + "=".repeat(50));
        System.out.println("СКАНИРОВАНИЕ ЗАВЕРШЕНО");
        System.out.println("=".repeat(50));

        System.out.println("\nИТОГОВАЯ СТАТИСТИКА:");
        System.out.println("   Просканировано банков: " + totalScannedBanks + "/" + BANKS.size());
        System.out.println("   Всего уязвимостей: " + totalVulnerabilities);

        if (!failedBanks.isEmpty()) {
            System.out.println("   Ошибки сканирования: " + failedBanks.size() + " банков");
            for (String failedBank : failedBanks) {
                System.out.println("     • " + failedBank);
            }
        }

        if (totalVulnerabilities == 0) {
            System.out.println("Уязвимостей не обнаружено.");
        } else {
            System.out.println("Рекомендуется устранение уязвимостей ВЫСОКОГО и КРИТИЧЕСКОГО уровня");
        }
    }

    private static void printScannerStats(Map<String, Integer> stats, String category, String name) {
        int count = stats.getOrDefault(category, 0);
        if (count > 0) {
            System.out.println("      • " + name + ": " + count + " уязвимостей");
        }
    }
}