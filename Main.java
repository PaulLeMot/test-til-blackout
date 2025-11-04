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
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Main {
    private static PrintWriter logWriter;
    
    public static void main(String[] args) {
        // Инициализация логгера
        try {
            String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
            String logFileName = "security_scan_" + timestamp + ".txt";
            logWriter = new PrintWriter(new FileWriter(logFileName, true));
            log("Логирование в файл: " + logFileName);
        } catch (Exception e) {
            System.err.println("Не удалось создать файл лога: " + e.getMessage());
        }
        
        try {
            log("Запуск GOSTGuardian Security Scanner");
            log("Целевые уязвимости: OWASP API Security Top 10\n");

            final String PASSWORD = "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";
            final List<String> BANKS = Arrays.asList(
                    "https://vbank.open.bankingapi.ru",
                    "https://abank.open.bankingapi.ru",
                    "https://sbank.open.bankingapi.ru"
            );

            // Создаём сканеры - начинаем с основных
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

            log("Зарегистрировано сканеров: " + securityScanners.size());

            // Итоговая статистика
            int totalVulnerabilities = 0;
            int totalScannedBanks = 0;
            List<String> failedBanks = new ArrayList<>();
            Map<String, Integer> bankVulnerabilities = new HashMap<>();

            for (String baseUrl : BANKS) {
                log("\n" + "=".repeat(50));
                log("Сканирование: " + baseUrl);
                log("=".repeat(50));

                String cleanBaseUrl = baseUrl.trim();
                String specUrl = cleanBaseUrl + "/openapi.json";

                // === ЗАГРУЗКА OPENAPI-СПЕЦИФИКАЦИИ ===
                io.swagger.v3.oas.models.OpenAPI openAPI = null;
                try {
                    OpenApiSpecLoader loader = new OpenApiSpecLoader(specUrl);
                    openAPI = loader.getOpenAPI();
                    log("OpenAPI-спецификация загружена: " +
                            openAPI.getInfo().getTitle() + " v" + openAPI.getInfo().getVersion());
                } catch (Exception e) {
                    log("Не удалось загрузить OpenAPI-спецификацию по адресу: " + specUrl);
                    log("   Причина: " + e.getMessage());
                    // Продолжаем сканирование без спецификации
                }

                int currentBankVulnerabilities = 0;
                try {
                    ScanConfig config = new ScanConfig();
                    config.setTargetBaseUrl(cleanBaseUrl);
                    config.setPassword(PASSWORD);
                    config.setBankBaseUrl(cleanBaseUrl);
                    config.setClientId("team172-8");
                    config.setClientSecret(PASSWORD);

                    // === ЦЕНТРАЛИЗОВАННОЕ ПОЛУЧЕНИЕ ТОКЕНОВ ===
                    log("Получение токенов для пользователей...");
                    Map<String, String> tokens = AuthManager.getBankAccessTokensForTeam(cleanBaseUrl, PASSWORD);
                    config.setUserTokens(tokens);

                    log("Получено токенов: " + tokens.size());

                    // Проверяем, есть ли валидные токены
                    if (tokens.isEmpty()) {
                        log("❌ Не удалось получить токены для сканирования. Пропускаем банк.");
                        failedBanks.add(cleanBaseUrl);
                        continue;
                    }

                    // Выбираем основного пользователя для сканирования
                    String primaryUser = null;
                    String primaryToken = null;
                    for (Map.Entry<String, String> entry : tokens.entrySet()) {
                        if (entry.getValue() != null && AuthManager.isTokenValid(entry.getValue())) {
                            primaryUser = entry.getKey();
                            primaryToken = entry.getValue();
                            break;
                        }
                    }

                    if (primaryToken == null) {
                        log("❌ Нет валидных токенов. Пропускаем банк.");
                        failedBanks.add(cleanBaseUrl);
                        continue;
                    }

                    log("Основной пользователь для сканирования: " + primaryUser);

                    for (String user : tokens.keySet()) {
                        String tokenPreview = tokens.get(user).length() > 20 ?
                                tokens.get(user).substring(0, 20) + "..." : tokens.get(user);
                        log(user + ": " + tokenPreview);
                    }

                    List<Vulnerability> allVulnerabilities = new ArrayList<>();

                    // Последовательно запускаем каждый сканер с увеличенными задержками
                    for (SecurityScanner scanner : securityScanners) {
                        log("\nЗапуск сканера: " + scanner.getName());
                        log("-".repeat(40));

                        try {
                            // Передаём объект OpenAPI и config с токенами
                            List<Vulnerability> scannerResults = scanner.scan(openAPI, config, new HttpApiClient());
                            allVulnerabilities.addAll(scannerResults);

                            log("Сканер " + scanner.getName() + " завершен. Найдено уязвимостей: " + scannerResults.size());

                            if (!scannerResults.isEmpty()) {
                                for (Vulnerability vuln : scannerResults) {
                                    log("  • " + vuln.getTitle() + " [" + vuln.getSeverity() + "]");
                                }
                            }

                        } catch (Exception e) {
                            log("Ошибка в сканере " + scanner.getName() + ": " + e.getMessage());
                            e.printStackTrace();
                        }

                        // Увеличиваем задержку между сканерами
                        try { Thread.sleep(3000); } catch (InterruptedException ignored) {}
                    }

                    totalScannedBanks++;
                    currentBankVulnerabilities = allVulnerabilities.size();
                    totalVulnerabilities += currentBankVulnerabilities;
                    bankVulnerabilities.put(cleanBaseUrl, currentBankVulnerabilities);

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

                    log("\nРезультаты сканирования " + cleanBaseUrl + ":");
                    log("   Статус: ЗАВЕРШЕНО");
                    log("   Уязвимостей: " + currentBankVulnerabilities);
                    log("   Уровни: КРИТИЧЕСКИХ-" + criticalCount + " ВЫСОКИХ-" + highCount +
                            " СРЕДНИХ-" + mediumCount + " НИЗКИХ-" + lowCount);

                    // Статистика по сканерам
                    log("\n   Результаты по сканерам:");
                    printScannerStats(scannerStats, "OWASP_API1_BOLA", "API1 - BOLA");
                    printScannerStats(scannerStats, "OWASP_API2_BROKEN_AUTH", "API2 - Broken Auth");
                    printScannerStats(scannerStats, "OWASP_API3_BOPLA", "API3 - BOPLA");

                } catch (Exception e) {
                    log("Ошибка при сканировании банка " + cleanBaseUrl + ": " + e.getMessage());
                    e.printStackTrace();
                    failedBanks.add(cleanBaseUrl);
                } finally {
                    // Всегда добавляем результат в карту, даже если были ошибки
                    bankVulnerabilities.put(cleanBaseUrl, currentBankVulnerabilities);
                }

                log("\n" + "=".repeat(50));
                log("Завершено сканирование: " + cleanBaseUrl);
                log("=".repeat(50));

                // Увеличиваем задержку между банками
                try { Thread.sleep(5000); } catch (InterruptedException ignored) {}
            }

            // Финальная сводка
            log("\n" + "=".repeat(50));
            log("СКАНИРОВАНИЕ ЗАВЕРШЕНО");
            log("=".repeat(50));

            log("\nИТОГОВАЯ СТАТИСТИКА:");
            log("   Просканировано банков: " + totalScannedBanks + "/" + BANKS.size());
            log("   Всего уязвимостей: " + totalVulnerabilities);

            // Результаты анализа по всем банкам
            log("\nРезультаты по банкам:");
            for (String bank : BANKS) {
                String cleanBank = bank.trim();
                int vulnCount = bankVulnerabilities.getOrDefault(cleanBank, 0);
                log("   • " + cleanBank + ": " + vulnCount + " уязвимостей");
            }

            if (!failedBanks.isEmpty()) {
                log("\n   Ошибки сканирования: " + failedBanks.size() + " банков");
                for (String failedBank : failedBanks) {
                    log("     • " + failedBank);
                }
            }

            if (totalVulnerabilities == 0) {
                log("\nУязвимостей не обнаружено.");
            } else {
                log("\nРекомендуется устранение уязвимостей ВЫСОКОГО и КРИТИЧЕСКОГО уровня");
            }

        } catch (Exception e) {
            log("Критическая ошибка в main: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Закрытие файла лога
            if (logWriter != null) {
                logWriter.close();
                System.out.println("Лог сохранен в файл");
            }
        }
    }

    // Метод для логирования в консоль и файл
    private static void log(String message) {
        System.out.println(message);
        if (logWriter != null) {
            logWriter.println(message);
            logWriter.flush(); // Сбрасываем буфер после каждой записи
        }
    }
    
    // Перегруженный метод для логирования без перевода строки
    private static void logNoNewline(String message) {
        System.out.print(message);
        if (logWriter != null) {
            logWriter.print(message);
            logWriter.flush();
        }
    }

    private static void printScannerStats(Map<String, Integer> stats, String category, String name) {
        int count = stats.getOrDefault(category, 0);
        if (count > 0) {
            log("      • " + name + ": " + count + " уязвимостей");
        }
    }
}
