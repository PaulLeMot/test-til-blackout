import core.*;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Scanner...");

        try {
            ScanConfig config = new ScanConfig();
            config.setTargetBaseUrl("https://vbank.open.bankingapi.ru"); // ← без пробелов!
            config.setPassword("***REMOVED***");

            config.setSpecUrl("https://open.bankingapi.ru/vbank/openapi.json"); // ← без пробелов!

            SecurityScanner bolaScanner = new API1_BOLAScanner();

            ApiScanner apiScanner = new ApiScanner();
            apiScanner.registerSecurityScanner(bolaScanner);

            System.out.println("🛡️ Запуск BOLA-сканера против Virtual Bank...");
            ScanResult result = apiScanner.performScan(config);

            System.out.println("\n📊 Сканирование завершено!");
            System.out.println("Статус: " + result.getStatus());
            System.out.println("Найдено " + result.getVulnerabilities().size() + " уязвимостей:");

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
            System.err.println("❌ Ошибка: " + e.getMessage());
            e.printStackTrace();
        }
    }
}