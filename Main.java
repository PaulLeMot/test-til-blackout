// Main.java
import core.*;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;
import scanners.owasp.API2_BrokenAuthScanner;  // ← ДОБАВЬ ЭТОТ ИМПОРТ

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Scanner...");
        
        try {
            // 1. Настраиваем конфигурацию
            ScanConfig config = new ScanConfig();
            config.setSpecUrl("test");
            config.setTargetBaseUrl("https://api.example.com");
            
            // 2. Создаем сканеры и клиент
            SecurityScanner bolaScanner = new API1_BOLAScanner();
            SecurityScanner brokenAuthScanner = new API2_BrokenAuthScanner();  // ← СОЗДАЕМ СКАНЕР
            ApiClient apiClient = new StandardApiClient();
            
            // 3. Создаем и настраиваем основной сканер
            ApiScanner apiScanner = new ApiScanner();  // ← СОЗДАЕМ apiScanner
            apiScanner.registerSecurityScanner(bolaScanner);
            apiScanner.registerSecurityScanner(brokenAuthScanner);  // ← РЕГИСТРИРУЕМ НОВЫЙ СКАНЕР
            
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
            }
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
