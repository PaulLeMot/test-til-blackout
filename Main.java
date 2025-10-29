// Main.java
import core.*;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Scanner...");

        try {
            // 1. Настраиваем конфигурацию для Virtual Bank
            ScanConfig config = new ScanConfig();
            config.setTargetBaseUrl("https://vbank.open.bankingapi.ru"); // без пробелов!
            config.setPassword("***REMOVED***");      // общий пароль команды

            // (опционально) указываем specUrl, если понадобится в будущем
            config.setSpecUrl("https://open.bankingapi.ru/vbank/openapi.json");

            // 2. Создаём BOLA-сканер
            SecurityScanner bolaScanner = new API1_BOLAScanner();

            // 3. Создаём и настраиваем основной оркестратор
            ApiScanner apiScanner = new ApiScanner();
            apiScanner.registerSecurityScanner(bolaScanner);

            // 4. Запускаем сканирование
            System.out.println("🛡️ Запуск BOLA-сканера против Virtual Bank...");
            ScanResult result = apiScanner.performScan(config);

            // 5. Выводим результаты
            System.out.println("\n📊 Сканирование завершено!");
            System.out.println("Статус: " + result.getStatus());
            System.out.println("Найдено " + result.getVulnerabilities().size() + " уязвимостей:");

            if (result.getVulnerabilities().isEmpty()) {
                System.out.println("✅ Уязвимостей не обнаружено.");
            } else {
                for (var vuln : result.getVulnerabilities()) {
                    System.out.println("⚠️ " + vuln.getTitle() + " — " + vuln.getSeverity());
                    System.out.println("   Эндпоинт: " + vuln.getEndpoint());
                    System.out.println("   Описание: " + vuln.getDescription());
                }
            }

        } catch (Exception e) {
            System.err.println("❌ Ошибка: " + e.getMessage());
            e.printStackTrace();
        }
    }
}