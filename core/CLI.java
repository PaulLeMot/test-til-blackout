package core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

public class CLI {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static PrintWriter logWriter;
    private static ScannerService scannerService;
    private static PostgresManager databaseManager;
    private static boolean isScanning = false;

    static {
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            return;
        }

        // Инициализация логгера
        initializeLogger();

        try {
            Map<String, String> params = parseArgs(args);

            if (params.containsKey("help")) {
                printUsage();
                return;
            }

            if (params.containsKey("config")) {
                String configFile = params.get("config");
                runScanFromConfig(configFile, params);
            } else if (params.containsKey("scan")) {
                runQuickScan(params);
            } else {
                System.err.println("❌ Неизвестная команда. Используйте --help для справки.");
                System.exit(1);
            }

        } catch (Exception e) {
            System.err.println("❌ Ошибка: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } finally {
            if (logWriter != null) logWriter.close();
            if (databaseManager != null) databaseManager.close();
        }
    }

    private static void initializeLogger() {
        try {
            String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
            String logFileName = "logs/cli_scan_" + timestamp + ".txt";
            Files.createDirectories(Paths.get("logs"));
            logWriter = new PrintWriter(new FileWriter(logFileName, true));
            log("CLI логгер инициализирован: " + logFileName);
        } catch (Exception e) {
            System.err.println("Не удалось создать файл лога: " + e.getMessage());
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--config":
                case "-c":
                    if (i + 1 < args.length) params.put("config", args[++i]);
                    break;
                case "--output":
                case "-o":
                    if (i + 1 < args.length) params.put("output", args[++i]);
                    break;
                case "--format":
                case "-f":
                    if (i + 1 < args.length) params.put("format", args[++i]);
                    break;
                case "--fail-on":
                    if (i + 1 < args.length) params.put("fail-on", args[++i]);
                    break;
                case "--timeout":
                case "-t":
                    if (i + 1 < args.length) params.put("timeout", args[++i]);
                    break;
                case "--help":
                case "-h":
                    params.put("help", "true");
                    break;
                case "scan":
                    params.put("scan", "true");
                    break;
                default:
                    // Если аргумент без префикса, считаем его значением предыдущего ключа
                    if (i > 0 && !args[i-1].startsWith("-")) {
                        System.err.println("❌ Неизвестный аргумент: " + args[i]);
                    }
            }
        }
        return params;
    }

    private static void runScanFromConfig(String configFile, Map<String, String> params) {
        try {
            log("📁 Загрузка конфигурации из: " + configFile);
            String configJson = new String(Files.readAllBytes(Paths.get(configFile)));

            log("🔧 Парсинг конфигурации...");
            ScanConfig config = ConfigParser.parseConfig(configJson);

            log("✅ Конфигурация загружена:");
            log("   Банков: " + config.getBanks().size());
            log("   Учетных записей: " + config.getCredentials().size());
            log("   Bank ID: " + config.getBankId());

            // Инициализация базы данных
            databaseManager = new PostgresManager();

            // Инициализация сервиса сканирования
            scannerService = new ScannerService(null, databaseManager);
            scannerService.setConfig(config);

            // Запуск сканирования
            runScan(params);

        } catch (Exception e) {
            throw new RuntimeException("Ошибка загрузки конфигурации: " + e.getMessage(), e);
        }
    }

    private static void runQuickScan(Map<String, String> params) {
        try {
            log("🚀 Быстрый запуск сканирования...");

            // Создаем базовую конфигурацию
            ScanConfig config = new ScanConfig();

            // Здесь можно добавить логику для быстрого сканирования
            // Например, использование переменных окружения или параметров командной строки

            databaseManager = new PostgresManager();
            scannerService = new ScannerService(null, databaseManager);
            scannerService.setConfig(config);

            runScan(params);

        } catch (Exception e) {
            throw new RuntimeException("Ошибка быстрого сканирования: " + e.getMessage(), e);
        }
    }

    private static void runScan(Map<String, String> params) {
        if (isScanning) {
            System.err.println("❌ Сканирование уже выполняется");
            return;
        }

        isScanning = true;
        String sessionId = null;

        try {
            // Таймаут
            int timeout = Integer.parseInt(params.getOrDefault("timeout", "3600"));

            log("⏱️  Таймаут сканирования: " + timeout + " секунд");

            // Запускаем сканирование в отдельном потоке с таймаутом
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<Boolean> future = executor.submit(() -> {
                try {
                    return scannerService.startScan();
                } catch (Exception e) {
                    log("❌ Ошибка сканирования: " + e.getMessage());
                    return false;
                }
            });

            try {
                boolean started = future.get(timeout, TimeUnit.SECONDS);
                if (!started) {
                    throw new RuntimeException("Не удалось запустить сканирование");
                }

                // Ждем завершения сканирования
                while (scannerService.isScanning()) {
                    Thread.sleep(5000);
                    log("⏳ Сканирование выполняется...");
                }

                log("✅ Сканирование завершено");

                // Генерация отчета
                generateReport(params);

                // Проверка на fail-on условия
                checkFailConditions(params);

            } catch (TimeoutException e) {
                log("❌ Сканирование превысило таймаут (" + timeout + " секунд)");
                System.exit(2);
            } catch (InterruptedException e) {
                log("❌ Сканирование прервано");
                Thread.currentThread().interrupt();
                System.exit(3);
            } finally {
                executor.shutdownNow();
            }

        } catch (Exception e) {
            log("❌ Критическая ошибка: " + e.getMessage());
            throw new RuntimeException(e);
        } finally {
            isScanning = false;
        }
    }

    private static void generateReport(Map<String, String> params) {
        try {
            String outputFile = params.getOrDefault("output", "scan_report_" +
                    new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()));
            String format = params.getOrDefault("format", "json");

            log("📊 Генерация отчета...");
            log("   Формат: " + format);
            log("   Файл: " + outputFile);

            // Получаем результаты из базы данных
            List<Map<String, Object>> results = databaseManager.getScanResults(null, null, null, null);
            Map<String, Object> stats = databaseManager.getStats();

            switch (format.toLowerCase()) {
                case "json":
                    generateJsonReport(outputFile, results, stats);
                    break;
                case "txt":
                case "text":
                    generateTextReport(outputFile, results, stats);
                    break;
                case "csv":
                    generateCsvReport(outputFile, results);
                    break;
                default:
                    log("❌ Неподдерживаемый формат: " + format);
                    generateJsonReport(outputFile, results, stats);
            }

            log("✅ Отчет сохранен: " + outputFile);

        } catch (Exception e) {
            log("❌ Ошибка генерации отчета: " + e.getMessage());
        }
    }

    private static void generateJsonReport(String outputFile, List<Map<String, Object>> results,
                                           Map<String, Object> stats) throws IOException {
        String fullPath = outputFile.endsWith(".json") ? outputFile : outputFile + ".json";

        Map<String, Object> report = new HashMap<>();
        report.put("timestamp", new Date().toString());
        report.put("statistics", stats);
        report.put("vulnerabilities", results);
        report.put("summary", createSummary(stats));

        mapper.writeValue(new File(fullPath), report);
    }

    private static void generateTextReport(String outputFile, List<Map<String, Object>> results,
                                           Map<String, Object> stats) throws IOException {
        String fullPath = outputFile.endsWith(".txt") ? outputFile : outputFile + ".txt";

        try (PrintWriter writer = new PrintWriter(new FileWriter(fullPath))) {
            writer.println("=".repeat(80));
            writer.println("               ОТЧЕТ О СКАНИРОВАНИИ БЕЗОПАСНОСТИ");
            writer.println("=".repeat(80));
            writer.println("Время генерации: " + new Date());
            writer.println();

            // Статистика
            writer.println("СТАТИСТИКА:");
            writer.println("-".repeat(40));
            writer.printf("Всего уязвимостей: %d%n", stats.get("total"));
            writer.printf("Критические: %d%n", stats.get("critical"));
            writer.printf("Высокие: %d%n", stats.get("high"));
            writer.printf("Средние: %d%n", stats.get("medium"));
            writer.printf("Низкие: %d%n", stats.get("low"));
            writer.println();

            // Детали уязвимостей
            if (!results.isEmpty()) {
                writer.println("ДЕТАЛИ УЯЗВИМОСТЕЙ:");
                writer.println("-".repeat(40));

                for (Map<String, Object> result : results) {
                    writer.printf("Банк: %s%n", result.get("bankName"));
                    writer.printf("Уязвимость: %s%n", result.get("vulnerabilityTitle"));
                    writer.printf("Уровень: %s%n", result.get("severity"));
                    writer.printf("Категория: %s%n", result.get("category"));
                    writer.printf("Сканер: %s%n", result.get("scannerName"));
                    writer.printf("Дата: %s%n", result.get("scanDate"));
                    writer.println("-".repeat(20));
                }
            }
        }
    }

    private static void generateCsvReport(String outputFile, List<Map<String, Object>> results) throws IOException {
        String fullPath = outputFile.endsWith(".csv") ? outputFile : outputFile + ".csv";

        try (PrintWriter writer = new PrintWriter(new FileWriter(fullPath))) {
            // Заголовок
            writer.println("Bank,Severity,Category,Title,Scanner,Date,Status");

            // Данные
            for (Map<String, Object> result : results) {
                writer.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                        escapeCsv(result.get("bankName").toString()),
                        result.get("severity"),
                        result.get("category"),
                        escapeCsv(result.get("vulnerabilityTitle").toString()),
                        result.get("scannerName"),
                        result.get("scanDate"),
                        result.get("statusCode")
                );
            }
        }
    }

    private static String escapeCsv(String value) {
        return value.replace("\"", "\"\"");
    }

    private static Map<String, Object> createSummary(Map<String, Object> stats) {
        Map<String, Object> summary = new HashMap<>();
        summary.put("total", stats.get("total"));
        summary.put("critical", stats.get("critical"));
        summary.put("high", stats.get("high"));
        summary.put("medium", stats.get("medium"));
        summary.put("low", stats.get("low"));

        // Определяем общий статус
        int critical = (int) stats.get("critical");
        int high = (int) stats.get("high");

        String status = "PASS";
        if (critical > 0) status = "CRITICAL";
        else if (high > 0) status = "HIGH";
        else if ((int) stats.get("total") > 0) status = "WARNING";

        summary.put("status", status);
        return summary;
    }

    private static void checkFailConditions(Map<String, String> params) {
        if (!params.containsKey("fail-on")) return;

        String failOn = params.get("fail-on").toUpperCase();
        Map<String, Object> stats = databaseManager.getStats();

        int count = 0;
        switch (failOn) {
            case "CRITICAL":
                count = (int) stats.get("critical");
                break;
            case "HIGH":
                count = (int) stats.get("critical") + (int) stats.get("high");
                break;
            case "MEDIUM":
                count = (int) stats.get("critical") + (int) stats.get("high") + (int) stats.get("medium");
                break;
            case "LOW":
                count = (int) stats.get("total");
                break;
        }

        if (count > 0) {
            log("❌ Обнаружены уязвимости уровня " + failOn + ": " + count);
            System.exit(1);
        } else {
            log("✅ Уязвимостей уровня " + failOn + " не обнаружено");
        }
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("🌐 GOSTGuardian Security Scanner - CLI");
        System.out.println();
        System.out.println("Использование:");
        System.out.println("  java -cp . core.CLI [команда] [параметры]");
        System.out.println();
        System.out.println("Команды:");
        System.out.println("  scan                    Быстрое сканирование");
        System.out.println("  --config, -c <file>     Конфигурационный JSON файл");
        System.out.println();
        System.out.println("Параметры:");
        System.out.println("  --output, -o <file>     Файл для сохранения отчета");
        System.out.println("  --format, -f <format>   Формат отчета (json, txt, csv)");
        System.out.println("  --fail-on <level>       Завершить с ошибкой при уязвимостях уровня");
        System.out.println("                          (CRITICAL, HIGH, MEDIUM, LOW)");
        System.out.println("  --timeout, -t <sec>     Таймаут сканирования в секундах (по умолчанию: 3600)");
        System.out.println("  --help, -h              Показать эту справку");
        System.out.println();
        System.out.println("Примеры:");
        System.out.println("  java -cp . core.CLI --config scan_config.json --output report.json");
        System.out.println("  java -cp . core.CLI --config config.json --fail-on CRITICAL --format csv");
        System.out.println("  java -cp . core.CLI scan --output quick_scan.txt");
        System.out.println();
    }

    private static void log(String message) {
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
        String logMessage = "[" + timestamp + "] " + message;

        System.out.println(logMessage);
        if (logWriter != null) {
            logWriter.println(logMessage);
            logWriter.flush();
        }
    }
}