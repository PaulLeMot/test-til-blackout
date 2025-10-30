import core.*;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;
import scanners.owasp.API2_BrokenAuthScanner;

import java.util.Arrays;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Scanner для всех банков...");

        // Общие учётные данные
        final String CLIENT_SECRET = "***REMOVED***";
        final String CLIENT_ID = "team172";
        
        final List<String> BANKS = Arrays.asList(
                "https://vbank.open.bankingapi.ru",
                "https://abank.open.bankingapi.ru", 
                "https://sbank.open.bankingapi.ru"
        );

        for (String baseUrl : BANKS) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("🛡 Сканирование банка: " + baseUrl);
            System.out.println("=".repeat(60));

            try {
                // 1. Настраиваем конфигурацию для банка
                ScanConfig config = new ScanConfig();
                config.setBankBaseUrl(baseUrl);
                config.setTargetBaseUrl(baseUrl);
                config.setClientId(CLIENT_ID);
                config.setClientSecret(CLIENT_SECRET);
                config.setPassword(CLIENT_SECRET);  // ← ДОБАВЛЕНО ДЛЯ BOLA
                config.setUsername(CLIENT_ID);      // ← ДОБАВЛЕНО ДЛЯ BOLA
                
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
                
                if (result.getVulnerabilities().isEmpty()) {
                    System.out.println("✅ Уязвимостей не обнаружено.");
                } else {
                    for (var vuln : result.getVulnerabilities()) {
                        System.out.println("=== УЯЗВИМОСТЬ ===");
                        System.out.println("🔴 " + vuln.getTitle());
                        System.out.println("📝 " + vuln.getDescription());
                        System.out.println("🚨 Уровень: " + vuln.getSeverity());
                        System.out.println("📍 Эндпоинт: " + vuln.getEndpoint());
                        System.out.println("🔧 Метод: " + vuln.getMethod());
                        if (vuln.getEvidence() != null) {
                            System.out.println("📋 Доказательство: " + vuln.getEvidence());
                        }
                        System.out.println("💡 Рекомендации:");
                        for (String rec : vuln.getRecommendations()) {
                            System.out.println("   - " + rec);
                        }
                        System.out.println();
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
