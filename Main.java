import core.*;
import scanners.SecurityScanner;
import scanners.owasp.*;
import java.util.*;
import java.io.*;
import java.text.SimpleDateFormat;

// Исправленный JSON парсер для конфигурации
class ConfigParser {
    public static ScanConfig parseConfig(String json) {
        ScanConfig config = new ScanConfig();

        try {
            log("Исходный JSON: " + json);

            // Удаляем пробелы и переносы строк для упрощения парсинга
            json = json.trim().replaceAll("\\s+", " ");

            if (json.startsWith("{") && json.endsWith("}")) {
                json = json.substring(1, json.length() - 1).trim();

                List<ScanConfig.BankConfig> banks = new ArrayList<>();
                List<ScanConfig.UserCredentials> credentials = new ArrayList<>();

                // Парсим банки
                String banksPart = extractPart(json, "banks");
                if (banksPart != null && banksPart.startsWith("[") && banksPart.endsWith("]")) {
                    banksPart = banksPart.substring(1, banksPart.length() - 1).trim();
                    log("Banks part: " + banksPart);

                    if (!banksPart.isEmpty()) {
                        String[] bankObjects = splitObjects(banksPart);
                        log("Found " + bankObjects.length + " bank objects");

                        for (String bankObj : bankObjects) {
                            bankObj = bankObj.trim();
                            if (bankObj.startsWith("{") && bankObj.endsWith("}")) {
                                String baseUrl = extractValueFromObject(bankObj, "baseUrl");
                                String specUrl = extractValueFromObject(bankObj, "specUrl");
                                // Убираем пробелы в конце URL
                                if (baseUrl != null) baseUrl = baseUrl.trim();
                                if (specUrl != null) specUrl = specUrl.trim();
                                log("Parsed bank - baseUrl: " + baseUrl + ", specUrl: " + specUrl);
                                if (baseUrl != null && specUrl != null) {
                                    banks.add(new ScanConfig.BankConfig(baseUrl, specUrl));
                                }
                            }
                        }
                    }
                }

                // Парсим учетные данные
                String credsPart = extractPart(json, "credentials");
                if (credsPart != null && credsPart.startsWith("[") && credsPart.endsWith("]")) {
                    credsPart = credsPart.substring(1, credsPart.length() - 1).trim();
                    log("Credentials part: " + credsPart);

                    if (!credsPart.isEmpty()) {
                        String[] credObjects = splitObjects(credsPart);
                        log("Found " + credObjects.length + " credential objects");

                        for (String credObj : credObjects) {
                            credObj = credObj.trim();
                            if (credObj.startsWith("{") && credObj.endsWith("}")) {
                                String username = extractValueFromObject(credObj, "username");
                                String password = extractValueFromObject(credObj, "password");
                                log("Parsed credential - username: " + username + ", password: " + (password != null ? "***" : "null"));
                                if (username != null && password != null) {
                                    credentials.add(new ScanConfig.UserCredentials(username, password));
                                }
                            }
                        }
                    }
                }

                config.setBanks(banks);
                config.setCredentials(credentials);
            }
        } catch (Exception e) {
            System.err.println("Error parsing config: " + e.getMessage());
            e.printStackTrace();
        }

        return config;
    }

    private static String extractPart(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int start = json.indexOf(searchKey);
        if (start == -1) {
            log("Key '" + key + "' not found in JSON");
            return null;
        }

        start += searchKey.length();
        int braceCount = 0;
        boolean inQuotes = false;
        char quoteChar = '"';
        int contentStart = -1;

        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);

            if (c == '"' && (i == 0 || json.charAt(i-1) != '\\')) {
                if (!inQuotes) {
                    inQuotes = true;
                    quoteChar = c;
                } else if (c == quoteChar) {
                    inQuotes = false;
                }
            }

            if (!inQuotes) {
                if (c == '[' || c == '{') {
                    if (braceCount == 0) {
                        contentStart = i;
                    }
                    braceCount++;
                } else if (c == ']' || c == '}') {
                    braceCount--;
                    if (braceCount == 0 && contentStart != -1) {
                        return json.substring(contentStart, i + 1);
                    }
                } else if (braceCount == 0 && c == ',') {
                    // Достигли конца текущего элемента
                    break;
                }
            }
        }

        return null;
    }

    private static String[] splitObjects(String arrayContent) {
        List<String> objects = new ArrayList<>();
        int braceCount = 0;
        boolean inQuotes = false;
        char quoteChar = '"';
        int start = -1;

        for (int i = 0; i < arrayContent.length(); i++) {
            char c = arrayContent.charAt(i);

            if (c == '"' && (i == 0 || arrayContent.charAt(i-1) != '\\')) {
                if (!inQuotes) {
                    inQuotes = true;
                    quoteChar = c;
                } else if (c == quoteChar) {
                    inQuotes = false;
                }
            }

            if (!inQuotes) {
                if (c == '{') {
                    if (braceCount == 0) {
                        start = i;
                    }
                    braceCount++;
                } else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0 && start != -1) {
                        objects.add(arrayContent.substring(start, i + 1));
                        start = -1;
                    }
                }
            }
        }

        return objects.toArray(new String[0]);
    }

    private static String extractValueFromObject(String obj, String key) {
        // Ищем ключ в кавычках
        String search = "\"" + key + "\":";
        int keyStart = obj.indexOf(search);
        if (keyStart == -1) return null;

        int valueStart = keyStart + search.length();

        // Пропускаем пробелы
        while (valueStart < obj.length() && Character.isWhitespace(obj.charAt(valueStart))) {
            valueStart++;
        }

        if (valueStart >= obj.length()) return null;

        char firstChar = obj.charAt(valueStart);
        if (firstChar == '"') {
            // Строковое значение в кавычках
            int stringStart = valueStart + 1;
            int stringEnd = stringStart;
            boolean inEscape = false;

            while (stringEnd < obj.length()) {
                char c = obj.charAt(stringEnd);
                if (inEscape) {
                    inEscape = false;
                } else if (c == '\\') {
                    inEscape = true;
                } else if (c == '"') {
                    return obj.substring(stringStart, stringEnd);
                }
                stringEnd++;
            }
        }

        return null;
    }

    private static void log(String message) {
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
        String logMessage = "[CONFIG_PARSER][" + timestamp + "] " + message;
        System.out.println(logMessage);
    }
}

// Реализуем интерфейс ScanLauncher
public class Main implements core.ScanLauncher {
    private static PrintWriter logWriter;
    private static WebServer webServer;
    private static boolean isScanning = false;

    public static void main(String[] args) {
        // Создаем папку logs, если она не существует
        File logsDir = new File("logs");
        if (!logsDir.exists()) {
            logsDir.mkdirs();
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

        // Запуск веб-сервера
        try {
            webServer = new WebServer(8081);

            // Устанавливаем ссылку на Main (который реализует ScanLauncher)
            webServer.setScanLauncher(new Main());

            webServer.start();
            log("✅ Web server started on http://localhost:8081");
            log("🌐 Open your browser and go to: http://localhost:8081");
        } catch (IOException e) {
            log("❌ Не удалось запустить веб-сервер: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        log("GOSTGuardian Security Scanner готов к работе");
        log("Откройте http://localhost:8081 и нажмите 'Запустить сканирование'");

        // Ожидаем завершения работы
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (logWriter != null) logWriter.close();
            if (webServer != null) webServer.stop();
            log("Приложение завершено");
        }));

        // Бесконечный цикл для поддержания работы приложения
        try {
            while (true) {
                Thread.sleep(1000);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // Реализуем метод из интерфейса ScanLauncher
    @Override
    public void startScan(String configJson) {
        startScanFromWeb(configJson);
    }

    public static void startScanFromWeb(String configJson) {
        if (isScanning) {
            log("Сканирование уже выполняется");
            return;
        }

        isScanning = true;
        new Thread(() -> {
            try {
                log("🚀 Запуск сканирования по запросу из веб-интерфейса");
                runSecurityScan(configJson);
                log("✅ Сканирование завершено");
            } catch (Exception e) {
                log("❌ Ошибка сканирования: " + e.getMessage());
                e.printStackTrace();
            } finally {
                isScanning = false;
            }
        }).start();
    }

    private static void runSecurityScan(String configJson) {
        try {
            log("Полученный JSON конфигурации:");
            log(configJson);

            // Парсим конфигурацию из JSON
            ScanConfig config = ConfigParser.parseConfig(configJson);

            log("Результаты парсинга:");
            log("  Банки: " + config.getBanks().size());
            for (ScanConfig.BankConfig bank : config.getBanks()) {
                log("    - " + bank.getBaseUrl() + " -> " + bank.getSpecUrl());
            }
            log("  Учетные данные: " + config.getCredentials().size());
            for (ScanConfig.UserCredentials cred : config.getCredentials()) {
                log("    - " + cred.getUsername() + " : " + (cred.getPassword() != null ? "***" : "null"));
            }

            if (config.getBanks().isEmpty() || config.getCredentials().isEmpty()) {
                log("❌ Неверная конфигурация: отсутствуют банки или учетные данные");
                webServer.broadcastMessage("scan_error", "Неверная конфигурация: отсутствуют банки или учетные данные");
                return;
            }

            log("Загружена конфигурация:");
            log("  Банков: " + config.getBanks().size());
            log("  Учетных записей: " + config.getCredentials().size());

            // Создаём сканеры
            List<SecurityScanner> securityScanners = Arrays.asList(
//                    new scanners.fuzzing.AdvancedFuzzingScanner(),
//                    new API1_BOLAScanner(),
//                    new API2_BrokenAuthScanner(),
                    new API3_BOScanner(),
//                    new API4_URCScanner(),
//                    new API5_BrokenFunctionLevelAuthScanner(),
                    new API6_BusinessFlowScanner(),
                    new API7_SSRFScanner(),
                    new API8_SecurityConfigScanner(),
                    new API9_InventoryScanner(),
                    new API10_UnsafeConsumptionScanner()
            );

            log("Зарегистрировано сканеров: " + securityScanners.size());

            int totalVulnerabilities = 0;
            int totalScannedBanks = 0;
            List<String> failedBanks = new ArrayList<>();
            Map<String, Integer> bankVulnerabilities = new HashMap<>();

            for (ScanConfig.BankConfig bankConfig : config.getBanks()) {
                String baseUrl = bankConfig.getBaseUrl();
                String specUrl = bankConfig.getSpecUrl();

                log("\n" + "=".repeat(50));
                log("Сканирование: " + baseUrl);
                log("Спецификация: " + specUrl);
                log("=".repeat(50));

                String cleanBaseUrl = baseUrl.trim();

                // Отправляем уведомление в веб-интерфейс
                webServer.broadcastMessage("scan_progress", "Сканирование банка: " + cleanBaseUrl);

                int currentBankVulnerabilities = 0;
                try {
                    // ЗАГРУЖАЕМ OPENAPI СПЕЦИФИКАЦИЮ с помощью OpenApiSpecLoader
                    Object openApiSpec = loadOpenApiSpec(specUrl);
                    if (openApiSpec == null) {
                        log("❌ Не удалось загрузить OpenAPI спецификацию для " + cleanBaseUrl);
                        failedBanks.add(cleanBaseUrl);
                        continue;
                    }

                    log("✅ OpenAPI спецификация успешно загружена");

                    ScanConfig scanConfig = new ScanConfig();
                    scanConfig.setTargetBaseUrl(cleanBaseUrl);
                    scanConfig.setOpenApiSpecUrl(specUrl);
                    scanConfig.setBankBaseUrl(cleanBaseUrl);

                    // Устанавливаем обязательные параметры для получения bank token
                    if (!config.getCredentials().isEmpty()) {
                        // Берем первого пользователя как основного
                        ScanConfig.UserCredentials primaryCred = config.getCredentials().get(0);
                        scanConfig.setClientId(primaryCred.getUsername());
                        scanConfig.setClientSecret(primaryCred.getPassword());
                        // Используем team172 как банк ID
                        scanConfig.setBankId("team172");
                    }

                    // Получение всех токенов, включая bank token
                    log("Получение всех токенов для сканирования...");
                    Map<String, String> tokens = AuthManager.getTokensForScanning(scanConfig);

                    // Устанавливаем токены в конфигурацию СНАЧАЛА
                    scanConfig.setUserTokens(tokens);

                    // Проверяем, получен ли bank token
                    String bankToken = scanConfig.getBankToken();
                    if (bankToken != null && !bankToken.isEmpty()) {
                        log("✅ Bank token успешно получен и доступен");
                    } else {
                        log("⚠️ Bank token не получен, возможно, проблема с аутентификацией");
                    }

                    log("Получено токенов: " + tokens.size());
                    for (String key : tokens.keySet()) {
                        log("   - " + key + ": ***");
                    }

                    if (tokens.isEmpty()) {
                        log("❌ Не удалось получить токены для сканирования. Пропускаем банк.");
                        failedBanks.add(cleanBaseUrl);
                        continue;
                    }

                    List<Vulnerability> allVulnerabilities = new ArrayList<>();

                    // Запуск сканеров - передаем загруженную спецификацию
                    for (SecurityScanner scanner : securityScanners) {
                        log("\nЗапуск сканера: " + scanner.getName());
                        webServer.broadcastMessage("scanner_start", "Запуск: " + scanner.getName());

                        try {
                            List<Vulnerability> scannerResults = scanner.scan(openApiSpec, scanConfig, new HttpApiClient());
                            allVulnerabilities.addAll(scannerResults);

                            // Сохранение результатов в реальном времени
                            for (Vulnerability vuln : scannerResults) {
                                saveVulnerabilityToDatabase(vuln, cleanBaseUrl, scanner.getName());

                                // Отправка уведомления о новой уязвимости
                                Map<String, Object> vulnData = new HashMap<>();
                                vulnData.put("bankName", cleanBaseUrl);
                                vulnData.put("title", vuln.getTitle());
                                vulnData.put("severity", vuln.getSeverity().toString());
                                vulnData.put("category", vuln.getCategory().toString());
                                vulnData.put("scanner", scanner.getName());
                                webServer.broadcastMessage("new_vulnerability", vulnData);
                            }

                            log("Сканер " + scanner.getName() + " завершен. Найдено: " + scannerResults.size());
                            webServer.broadcastMessage("scanner_complete",
                                    scanner.getName() + " завершен: " + scannerResults.size() + " уязвимостей");

                        } catch (Exception e) {
                            log("Ошибка в сканере " + scanner.getName() + ": " + e.getMessage());
                            webServer.broadcastMessage("scanner_error",
                                    "Ошибка в " + scanner.getName() + ": " + e.getMessage());
                        }

                        try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
                    }

                    totalScannedBanks++;
                    currentBankVulnerabilities = allVulnerabilities.size();
                    totalVulnerabilities += currentBankVulnerabilities;
                    bankVulnerabilities.put(cleanBaseUrl, currentBankVulnerabilities);

                    log("\nРезультаты сканирования " + cleanBaseUrl + ":");
                    log("   Статус: ЗАВЕРШЕНО");
                    log("   Уязвимостей: " + currentBankVulnerabilities);

                    // Отправка итогов по банку
                    Map<String, Object> bankResult = new HashMap<>();
                    bankResult.put("bank", cleanBaseUrl);
                    bankResult.put("vulnerabilities", currentBankVulnerabilities);
                    webServer.broadcastMessage("bank_complete", bankResult);

                } catch (Exception e) {
                    log("Ошибка при сканировании банка " + cleanBaseUrl + ": " + e.getMessage());
                    failedBanks.add(cleanBaseUrl);
                    webServer.broadcastMessage("bank_error", "Ошибка сканирования " + cleanBaseUrl);
                }

                try { Thread.sleep(3000); } catch (InterruptedException ignored) {}
            }

            // Финальная сводка
            log("\n" + "=".repeat(50));
            log("СКАНИРОВАНИЕ ЗАВЕРШЕНО");
            log("=".repeat(50));
            log("   Просканировано банков: " + totalScannedBanks + "/" + config.getBanks().size());
            log("   Всего уязвимостей: " + totalVulnerabilities);

            // Отправка финальных результатов
            Map<String, Object> finalResults = new HashMap<>();
            finalResults.put("totalBanks", totalScannedBanks);
            finalResults.put("totalVulnerabilities", totalVulnerabilities);
            finalResults.put("failedBanks", failedBanks.size());
            webServer.broadcastMessage("scan_complete", finalResults);

        } catch (Exception e) {
            log("Критическая ошибка в сканировании: " + e.getMessage());
            e.printStackTrace();
            webServer.broadcastMessage("scan_error", "Критическая ошибка: " + e.getMessage());
        }
    }

    /**
     * Метод для загрузки OpenAPI спецификации с использованием OpenApiSpecLoader
     */
    private static Object loadOpenApiSpec(String specUrl) {
        try {
            log("📥 Загрузка OpenAPI спецификации: " + specUrl);

            OpenApiSpecLoader loader = new OpenApiSpecLoader(specUrl);
            Object openApi = loader.getOpenAPI();

            if (openApi != null) {
                log("✅ OpenAPI спецификация успешно загружена через OpenApiSpecLoader");
                return openApi; // ВОЗВРАЩАЕМ ОБЪЕКТ OpenAPI, а не null
            } else {
                log("❌ OpenApiSpecLoader вернул null");
            }
        } catch (Exception e) {
            log("❌ Ошибка при загрузке OpenAPI спецификации через OpenApiSpecLoader: " + e.getMessage());
        }
        return null;
    }
    // Метод для сохранения уязвимости в PostgreSQL
    private static void saveVulnerabilityToDatabase(Vulnerability vuln, String bankName, String scannerName) {
        if (webServer != null) {
            String proof = extractProofFromVulnerability(vuln);
            String recommendation = extractRecommendationFromVulnerability(vuln);

            webServer.saveScanResult(
                    bankName,
                    vuln.getTitle(),
                    vuln.getSeverity().toString(),
                    vuln.getCategory().toString(),
                    "200",
                    proof,
                    recommendation,
                    scannerName
            );
        }
    }

    private static String extractProofFromVulnerability(Vulnerability vuln) {
        if (vuln.getEvidence() != null && !vuln.getEvidence().isEmpty()) {
            return vuln.getEvidence();
        }

        StringBuilder proofBuilder = new StringBuilder();
        if (vuln.getEndpoint() != null) proofBuilder.append("Эндпоинт: ").append(vuln.getEndpoint()).append("\n");
        if (vuln.getMethod() != null) proofBuilder.append("Метод: ").append(vuln.getMethod()).append("\n");
        if (vuln.getParameter() != null) proofBuilder.append("Параметр: ").append(vuln.getParameter()).append("\n");
        if (vuln.getStatusCode() != -1) proofBuilder.append("Статус код: ").append(vuln.getStatusCode()).append("\n");

        return proofBuilder.length() > 0 ? proofBuilder.toString() :
                "Доказательство не доступно для уязвимости: " + vuln.getTitle();
    }

    private static String extractRecommendationFromVulnerability(Vulnerability vuln) {
        switch (vuln.getCategory().toString()) {
            case "OWASP_API1_BOLA": return "Реализуйте проверки авторизации на уровне объектов.";
            case "OWASP_API2_BROKEN_AUTH": return "Усильте механизмы аутентификации.";
            case "OWASP_API3_BOPLA": return "Валидируйте и фильтруйте свойства объектов.";
            case "OWASP_API4_URC": return "Внедрите лимиты на потребление ресурсов.";
            case "OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH": return "Реализуйте проверки авторизации на уровне функций.";
            case "OWASP_API6_BUSINESS_FLOW": return "Защитите чувствительные бизнес-процессы.";
            case "OWASP_API7_SSRF": return "Валидируйте и санируйте все URL.";
            case "OWASP_API8_SM": return "Усильте конфигурацию безопасности.";
            case "OWASP_API9_INVENTORY": return "Ведите правильную инвентаризацию API.";
            case "OWASP_API10_UNSAFE_CONSUMPTION": return "Валидируйте все данные от сторонних API.";
            default: return "Проверьте и исправьте выявленную уязвимость безопасности.";
        }
    }

    // Метод для логирования
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