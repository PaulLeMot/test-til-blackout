import core.*;
import scanners.SecurityScanner;
import scanners.owasp.API1_BOLAScanner;
import scanners.owasp.API3_BOScanner;

import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 Запуск GOSTGuardian Security Scanner для банков Open Banking API...");
        System.out.println("🎯 Целевые уязвимости: OWASP API Security Top 10");

        // Общие учётные данные
        final String PASSWORD = "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";
        final List<String> BANKS = Arrays.asList(
                "https://vbank.open.bankingapi.ru",
                "https://abank.open.bankingapi.ru",
                "https://sbank.open.bankingapi.ru"
        );

        // Создаём сканеры OWASP API с правильным типом
        List<SecurityScanner> securityScanners = new ArrayList<>();
        securityScanners.add(new API1_BOLAScanner());
        securityScanners.add(new API3_BOScanner());

        System.out.println("📋 Зарегистрировано сканеров: " + securityScanners.size());
        securityScanners.forEach(scanner ->
                System.out.println("   • " + scanner.getName())
        );

        // Статистика по всем сканированиям
        int totalVulnerabilities = 0;
        int totalScannedBanks = 0;
        List<String> failedBanks = new ArrayList<>();

        for (String baseUrl : BANKS) {
            System.out.println("\n" + "=".repeat(80));
            System.out.println("🛡️  Сканирование банка: " + baseUrl);
            System.out.println("=".repeat(80));

            try {
                ScanConfig config = new ScanConfig();
                config.setTargetBaseUrl(baseUrl);
                config.setPassword(PASSWORD);

                ApiScanner apiScanner = new ApiScanner();

                // Регистрируем все сканеры
                for (SecurityScanner scanner : securityScanners) {
                    apiScanner.registerSecurityScanner(scanner);
                    System.out.println("✅ Зарегистрирован: " + scanner.getName());
                }

                ScanResult result = apiScanner.performScan(config);
                totalScannedBanks++;

                System.out.println("\n📊 РЕЗУЛЬТАТЫ ДЛЯ " + baseUrl + ":");
                System.out.println("✅ Статус: " + result.getStatus().toString());
                System.out.println("🎯 Найдено уязвимостей: " + result.getVulnerabilities().size());
                totalVulnerabilities += result.getVulnerabilities().size();

                // Статистика по уровням серьезности - используем enum Severity из core.Vulnerability
                long highCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.HIGH).count();
                long mediumCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.MEDIUM).count();
                long lowCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.LOW).count();
                long infoCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.INFO).count();
                long criticalCount = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == Vulnerability.Severity.CRITICAL).count();

                System.out.println("📈 Уровни серьезности:");
                System.out.println("   💀 Критический: " + criticalCount);
                System.out.println("   🔴 Высокий: " + highCount);
                System.out.println("   🟡 Средний: " + mediumCount);
                System.out.println("   🔵 Низкий: " + lowCount);
                System.out.println("   ⚪ Информационный: " + infoCount);

                if (result.getVulnerabilities().isEmpty()) {
                    System.out.println("✅ Уязвимостей не обнаружено.");
                } else {
                    System.out.println("\n⚠️  ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ:");

                    // Группируем по OWASP категориям
                    long bolaCount = result.getVulnerabilities().stream()
                            .filter(v -> v.getCategory() == Vulnerability.Category.OWASP_API1_BOLA).count();
                    long brokenAuthCount = result.getVulnerabilities().stream()
                            .filter(v -> v.getCategory() == Vulnerability.Category.OWASP_API2_BROKEN_AUTH).count();
                    long contractCount = result.getVulnerabilities().stream()
                            .filter(v -> v.getCategory() == Vulnerability.Category.CONTRACT_VALIDATION).count();

                    System.out.println("🎯 Распределение по категориям:");
                    System.out.println("   🔓 OWASP API1 - BOLA: " + bolaCount + " уязвимостей");
                    System.out.println("   🔓 OWASP API2 - Broken Auth: " + brokenAuthCount + " уязвимостей");
                    System.out.println("   📝 Contract Validation: " + contractCount + " уязвимостей");

                    // Выводим уязвимости, отсортированные по серьезности
                    result.getVulnerabilities().stream()
                            .sorted((v1, v2) -> {
                                // Сортируем по уровню серьезности: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
                                int severity1 = getSeverityWeight(v1.getSeverity());
                                int severity2 = getSeverityWeight(v2.getSeverity());
                                return severity2 - severity1;
                            })
                            .forEach(vuln -> {
                                String severityIcon = getSeverityIcon(vuln.getSeverity());
                                System.out.println("\n" + severityIcon + " " + vuln.getTitle());
                                System.out.println("   📍 Эндпоинт: " + vuln.getEndpoint());
                                System.out.println("   🚨 Уровень: " + vuln.getSeverity());
                                System.out.println("   🏷️  Категория: " + vuln.getCategory());
                                System.out.println("   📖 Описание: " + vuln.getDescription());

                                // Используем getRecommendations() (множественное число)
                                if (vuln.getRecommendations() != null && !vuln.getRecommendations().isEmpty()) {
                                    System.out.println("   💡 Рекомендации:");
                                    vuln.getRecommendations().forEach(rec -> System.out.println("      • " + rec));
                                }

                                System.out.println("   🔢 HTTP-статус: " + vuln.getStatusCode());
                                if (vuln.getMethod() != null) {
                                    System.out.println("   📋 Метод: " + vuln.getMethod());
                                }
                            });
                }

                // Проверяем наличие критических уязвимостей
                if (criticalCount > 0 || highCount > 0) {
                    System.out.println("\n🚨 ВНИМАНИЕ: Обнаружены критические уязвимости!");
                    System.out.println("   Рекомендуется немедленное устранение.");
                }

            } catch (Exception e) {
                System.err.println("❌ Ошибка при сканировании " + baseUrl + ": " + e.getMessage());
                failedBanks.add(baseUrl);
                if (isDebugMode()) {
                    e.printStackTrace();
                }
            }
        }

        // Финальная сводка
        System.out.println("\n" + "=".repeat(80));
        System.out.println("🏁 СКАНИРОВАНИЕ ВСЕХ БАНКОВ ЗАВЕРШЕНО");
        System.out.println("=".repeat(80));

        System.out.println("\n📊 ИТОГОВАЯ СТАТИСТИКА:");
        System.out.println("   🏦 Успешно просканировано: " + totalScannedBanks + " из " + BANKS.size());
        if (!failedBanks.isEmpty()) {
            System.out.println("   ❌ Не удалось просканировать: " + failedBanks.size() + " банков");
            failedBanks.forEach(bank -> System.out.println("      • " + bank));
        }
        System.out.println("   🎯 Общее количество уязвимостей: " + totalVulnerabilities);
        System.out.println("   🔧 Использовано сканеров: " + securityScanners.size());

        if (totalVulnerabilities == 0) {
            System.out.println("\n🎉 Отлично! Уязвимостей не обнаружено.");
        } else {
            System.out.println("\n💡 РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ:");
            System.out.println("   1. 🔓 BOLA: Реализуйте проверки авторизации на уровне объектов");
            System.out.println("   2. 🔐 Broken Auth: Усильте аутентификацию и управление сессиями");
            System.out.println("   3. 📝 Contract: Следуйте спецификациям OpenAPI");
            System.out.println("   4. 🛡️  Приоритетно устраните уязвимости КРИТИЧЕСКОГО и ВЫСОКОГО риска");
            System.out.println("   5. 🔄 Регулярно проводите security scanning в CI/CD");
        }

        System.out.println("\n🔗 Полезные ресурсы:");
        System.out.println("   • OWASP API Security Top 10: https://owasp.org/www-project-api-security/");
        System.out.println("   • OpenAPI Specification: https://swagger.io/specification/");
        System.out.println("   • Banking API Standards: https://openbankingapi.ru/");

        System.out.println("\n" + "=".repeat(80));
    }

    // Обновленные методы для работы с enum Severity из core.Vulnerability
    private static int getSeverityWeight(Vulnerability.Severity severity) {
        switch (severity) {
            case CRITICAL: return 5;
            case HIGH: return 4;
            case MEDIUM: return 3;
            case LOW: return 2;
            case INFO: return 1;
            default: return 0;
        }
    }

    private static String getSeverityIcon(Vulnerability.Severity severity) {
        switch (severity) {
            case CRITICAL: return "💀";
            case HIGH: return "🔴";
            case MEDIUM: return "🟡";
            case LOW: return "🔵";
            case INFO: return "⚪";
            default: return "⚪";
        }
    }

    private static boolean isDebugMode() {
        return System.getProperty("debug") != null ||
                Arrays.asList(System.getenv().getOrDefault("JAVA_OPTS", "").split(" ")).contains("-Ddebug");
    }
}