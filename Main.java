import core.ApiScanner;
import core.ScanConfig;
import core.ScanResult;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;
import scanners.owasp.ApiClient;
import scanners.owasp.StandardApiClient;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Scanner...");
        
        try {
            // 1. Настраиваем конфигурацию
            ScanConfig config = new ScanConfig();
            config.setSpecUrl("test");
            config.setTargetBaseUrl("https://api.example.com");
            
            // 2. Создаем сканер и клиент
            SecurityScanner bolaScanner = new API1_BOLAScanner();
            ApiClient apiClient = new StandardApiClient();
            
            // 3. Создаем и настраиваем основной сканер
            ApiScanner apiScanner = new ApiScanner();
            apiScanner.registerSecurityScanner(bolaScanner);
            
            // 4. Запускаем сканирование
            System.out.println("🛡️ Запуск BOLA сканера...");
            ScanResult result = apiScanner.performScan(config);
            
            // 5. Выводим результаты
            System.out.println("📊 Сканирование завершено!");
            System.out.println("Статус: " + result.getStatus());
            System.out.println("Найдено " + result.getVulnerabilities().size() + " уязвимостей:");
            
            for (var vuln : result.getVulnerabilities()) {
                System.out.println("⚠️ " + vuln.getTitle() + " - " + vuln.getSeverity());
                System.out.println("   Эндпоинт: " + vuln.getEndpoint());
            }
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
