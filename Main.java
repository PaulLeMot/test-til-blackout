import core.*;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;
import scanners.owasp.API2_BrokenAuthScanner;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Scanner для хакатона...");
        
        try {
            // 1. Настраиваем конфигурацию для реального банка
            ScanConfig config = new ScanConfig();
            config.setBankBaseUrl("https://vbank.open.bankingapi.ru");
            config.setTargetBaseUrl("https://vbank.open.bankingapi.ru");
            config.setClientId("team172-1"); // твой client_id
            config.setClientSecret("***REMOVED***"); // твой client_secret
            
            // 2. Создаем сканеры и клиент
            SecurityScanner bolaScanner = new API1_BOLAScanner();
            SecurityScanner brokenAuthScanner = new API2_BrokenAuthScanner();
            ApiClient apiClient = new RealApiClient();
            
            // 3. Создаем и настраиваем основной сканер
            ApiScanner apiScanner = new ApiScanner();
            apiScanner.registerSecurityScanner(bolaScanner);
            apiScanner.registerSecurityScanner(brokenAuthScanner);
            
            // 4. Запускаем сканирование
            System.out.println("🛡 Запуск сканеров...");
            ScanResult result = apiScanner.performScan(config);
            
            // 5. Выводим результаты
            System.out.println("📊 Сканирование завершено!");
            System.out.println("Статус: " + result.getStatus());
            System.out.println("Найдено " + result.getVulnerabilities().size() + " уязвимостей:");
            
            for (var vuln : result.getVulnerabilities()) {
                System.out.println("⚠ " + vuln.getTitle() + " - " + vuln.getSeverity());
                System.out.println("   Эндпоинт: " + vuln.getEndpoint());
                if (vuln.getEvidence() != null) {
                    System.out.println("   Доказательство: " + vuln.getEvidence());
                }
            }
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
