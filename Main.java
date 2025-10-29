import core.*;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;

import java.util.Arrays;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Scanner для всех банков...");

        // Общие учётные данные
        final String PASSWORD = "***REMOVED***";
        final List<String> BANKS = Arrays.asList(
                "https://vbank.open.bankingapi.ru",
                "https://abank.open.bankingapi.ru",
                "https://sbank.open.bankingapi.ru"
        );

        // Создаём один экземпляр сканера
        SecurityScanner bolaScanner = new API1_BOLAScanner();

        for (String baseUrl : BANKS) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("🛡️ Сканирование банка: " + baseUrl);
            System.out.println("=".repeat(60));

            try {
                ScanConfig config = new ScanConfig();
                config.setTargetBaseUrl(baseUrl);
                config.setPassword(PASSWORD);
                // specUrl не обязателен для BOLA

                ApiScanner apiScanner = new ApiScanner();
                apiScanner.registerSecurityScanner(bolaScanner);

                ScanResult result = apiScanner.performScan(config);

                System.out.println("\n📊 Результаты для " + baseUrl + ":");
                System.out.println("Статус: " + result.getStatus());
                System.out.println("Найдено уязвимостей: " + result.getVulnerabilities().size());

                if (result.getVulnerabilities().isEmpty()) {
                    System.out.println("✅ Уязвимостей не обнаружено.");
                } else {
                    for (var vuln : result.getVulnerabilities()) {
                        System.out.println("⚠️ " + vuln.getTitle() + " — " + vuln.getSeverity());
                        System.out.println("   Эндпоинт: " + vuln.getEndpoint());
                        System.out.println("   HTTP-статус: " + vuln.getStatusCode());
                        System.out.println("   Описание: " + vuln.getDescription());
                    }
                }

            } catch (Exception e) {
                System.err.println("❌ Ошибка при сканировании " + baseUrl + ": " + e.getMessage());
                e.printStackTrace();
            }
        }

        System.out.println("\n🏁 Сканирование всех банков завершено.");
    }
}