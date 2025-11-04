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
import java.util.HashSet;
import java.util.Set;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.io.File;
import java.io.IOException;

public class Main {
    private static PrintWriter logWriter;
    private static WebServer webServer;

    public static void main(String[] args) {
        // Запуск веб-сервера с PostgreSQL
        try {
            webServer = new WebServer(8081);
            webServer.start();
        } catch (IOException e) {
            System.err.println("❌ Не удалось запустить веб-сервер: " + e.getMessage());
            e.printStackTrace();
        }

        // Создаем папку logs, если она не существует
        File logsDir = new File("logs");
        if (!logsDir.exists()) {
            if (logsDir.mkdirs()) {
                System.out.println("Создана папка logs");
            } else {
                System.err.println("Не удалось создать папку logs");
            }
        }

        // Инициализация логгера
        try {
            String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
            String logFileName = "logs/security_scan_" + timestamp + ".txt";
            logWriter = new PrintWriter(new FileWriter(logFileName, true));
            log("Логирование в файл: " + logFileName);
        } catch (Exception e) {
            System.err.println("Не удалось создать файл лога: " + e.getMessage());
        }

        try {
            log("Запуск GOSTGuardian Security Scanner");
            log("Целевые уязвимости: OWASP API Security Top 10\n");

            final String PASSWORD = "***REMOVED***";
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

                            // ✅ СОХРАНЯЕМ РЕЗУЛЬТАТЫ В POSTGRESQL
                            for (Vulnerability vuln : scannerResults) {
                                saveVulnerabilityToDatabase(vuln, cleanBaseUrl, scanner.getName());
                            }

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

                    // Статистика по сканерам - ВЫВОДИМ ВСЕ КАТЕГОРИИ
                    log("\n   Результаты по сканерам:");
                    printAllScannerStats(scannerStats);

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
                System.out.println("Лог сохранен в папку logs/");
            }
            // Остановка веб-сервера
            if (webServer != null) {
                webServer.stop();
                System.out.println("Веб-сервер остановлен");
            }
        }
    }

    // Метод для сохранения уязвимости в PostgreSQL
    private static void saveVulnerabilityToDatabase(Vulnerability vuln, String bankName, String scannerName) {
        if (webServer != null) {
            // Получаем доказательства и рекомендации из уязвимости
            String proof = extractProofFromVulnerability(vuln);
            String recommendation = extractRecommendationFromVulnerability(vuln);

            webServer.saveScanResult(
                    bankName,
                    vuln.getTitle(),
                    vuln.getSeverity().toString(),
                    vuln.getCategory().toString(),
                    "200", // Можно получить реальный статус если доступен
                    proof,
                    recommendation,
                    scannerName
            );
        }
    }

    private static String extractProofFromVulnerability(Vulnerability vuln) {
        // Получаем реальное доказательство из поля evidence
        if (vuln.getEvidence() != null && !vuln.getEvidence().isEmpty()) {
            return vuln.getEvidence();
        }

        // Если evidence пустой, пробуем другие поля
        StringBuilder proofBuilder = new StringBuilder();

        if (vuln.getEndpoint() != null) {
            proofBuilder.append("Эндпоинт: ").append(vuln.getEndpoint()).append("\n");
        }

        if (vuln.getMethod() != null) {
            proofBuilder.append("Метод: ").append(vuln.getMethod()).append("\n");
        }

        if (vuln.getParameter() != null) {
            proofBuilder.append("Параметр: ").append(vuln.getParameter()).append("\n");
        }

        if (vuln.getStatusCode() != -1) {
            proofBuilder.append("Статус код: ").append(vuln.getStatusCode()).append("\n");
        }

        if (proofBuilder.length() > 0) {
            return proofBuilder.toString();
        }

        // Если нет никаких данных, возвращаем описание
        return "Доказательство не доступно для уязвимости: " + vuln.getTitle();
    }

    private static String extractRecommendationFromVulnerability(Vulnerability vuln) {
        // Базовые рекомендации по категориям OWASP
        switch (vuln.getCategory().toString()) {
            case "OWASP_API1_BOLA":
                return "Реализуйте проверки авторизации на уровне объектов. Убедитесь, что пользователи могут access только свои данные.";
            case "OWASP_API2_BROKEN_AUTH":
                return "Усильте механизмы аутентификации. Внедрите ограничение попыток входа и многофакторную аутентификацию.";
            case "OWASP_API3_BOPLA":
                return "Валидируйте и фильтруйте свойства объектов на основе привилегий пользователя.";
            case "OWASP_API4_URC":
                return "Внедрите лимиты на потребление ресурсов и мониторинг.";
            case "OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH":
                return "Реализуйте проверки авторизации на уровне функций.";
            case "OWASP_API6_BUSINESS_FLOW":
                return "Защитите чувствительные бизнес-процессы дополнительными контролями.";
            case "OWASP_API7_SSRF":
                return "Валидируйте и санируйте все URL, предоставленные пользователем.";
            case "OWASP_API8_SM":
                return "Усильте конфигурацию безопасности и устраните раскрытие информации.";
            case "OWASP_API9_INVENTORY":
                return "Ведите правильную инвентаризацию API и документацию.";
            case "OWASP_API10_UNSAFE_CONSUMPTION":
                return "Валидируйте все данные от сторонних API.";
            default:
                return "Проверьте и исправьте выявленную уязвимость безопасности.";
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


    private static void printAllScannerStats(Map<String, Integer> stats) {
        // Создаем маппинг категорий к читаемым названиям
        Map<String, String> categoryNames = new HashMap<>();
        categoryNames.put("OWASP_API1_BOLA", "API1 - BOLA");
        categoryNames.put("OWASP_API2_BROKEN_AUTH", "API2 - Broken Auth");
        categoryNames.put("OWASP_API3_BOPLA", "API3 - BOPLA");
        categoryNames.put("OWASP_API4_URC", "API4 - URC");
        categoryNames.put("OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH", "API5 - Broken Function Level Auth");
        categoryNames.put("OWASP_API6_BUSINESS_FLOW", "API6 - Business Flow");
        categoryNames.put("OWASP_API7_SSRF", "API7 - SSRF");
        categoryNames.put("OWASP_API8_SM", "API8 - Security Misconfiguration");
        categoryNames.put("OWASP_API9_INVENTORY", "API9 - Inventory");
        categoryNames.put("OWASP_API10_UNSAFE_CONSUMPTION", "API10 - Unsafe Consumption");
        categoryNames.put("CONTRACT_VALIDATION", "Contract Validation");

        // Дополнительные категории, которые могут использоваться в сканерах
        categoryNames.put("API1_BOLA", "API1 - BOLA");
        categoryNames.put("API2_BROKEN_AUTH", "API2 - Broken Auth");
        categoryNames.put("API3_BOPLA", "API3 - BOPLA");
        categoryNames.put("API4_URC", "API4 - URC");
        categoryNames.put("API5_BROKEN_FUNCTION_LEVEL_AUTH", "API5 - Broken Function Level Auth");
        categoryNames.put("API6_BUSINESS_FLOW", "API6 - Business Flow");
        categoryNames.put("API7_SSRF", "API7 - SSRF");
        categoryNames.put("API8_SM", "API8 - Security Misconfiguration");
        categoryNames.put("API9_INVENTORY", "API9 - Inventory");
        categoryNames.put("API10_UNSAFE_CONSUMPTION", "API10 - Unsafe Consumption");

        // Выводим все категории, где есть уязвимости
        boolean hasResults = false;

        // Сначала выводим известные категории в правильном порядке
        String[] orderedCategories = {
                "OWASP_API1_BOLA", "API1_BOLA",
                "OWASP_API2_BROKEN_AUTH", "API2_BROKEN_AUTH",
                "OWASP_API3_BOPLA", "API3_BOPLA",
                "OWASP_API4_URC", "API4_URC",
                "OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH", "API5_BROKEN_FUNCTION_LEVEL_AUTH",
                "OWASP_API6_BUSINESS_FLOW", "API6_BUSINESS_FLOW",
                "OWASP_API7_SSRF", "API7_SSRF",
                "OWASP_API8_SM", "API8_SM",
                "OWASP_API9_INVENTORY", "API9_INVENTORY",
                "OWASP_API10_UNSAFE_CONSUMPTION", "API10_UNSAFE_CONSUMPTION",
                "CONTRACT_VALIDATION"
        };

        // Используем Set для отслеживания уже выведенных категорий
        Set<String> displayedCategories = new HashSet<>();

        for (String category : orderedCategories) {
            if (stats.containsKey(category)) {
                int count = stats.get(category);
                if (count > 0) {
                    String displayName = categoryNames.getOrDefault(category, category);
                    // Проверяем, не выводили ли мы уже эту категорию
                    if (!displayedCategories.contains(displayName)) {
                        log("      • " + displayName + ": " + count + " уязвимостей");
                        displayedCategories.add(displayName);
                        hasResults = true;
                    }
                }
            }
        }

        // Затем выводим любые другие категории, которые не были обработаны
        for (Map.Entry<String, Integer> entry : stats.entrySet()) {
            String category = entry.getKey();
            int count = entry.getValue();
            if (count > 0 && !displayedCategories.contains(categoryNames.getOrDefault(category, category))) {
                String displayName = categoryNames.getOrDefault(category, category);
                log("      • " + displayName + ": " + count + " уязвимостей");
                hasResults = true;
            }
        }

        // Если нет результатов, выводим сообщение
        if (!hasResults) {
            log("      • Уязвимостей не обнаружено");
        }
    }
}