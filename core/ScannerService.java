package core;

import scanners.SecurityScanner;
import scanners.owasp.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.text.SimpleDateFormat;

public class ScannerService {
    private final WebServer webServer;
    private final PostgresManager databaseManager;
    private final ExecutorService executor;
    private boolean isScanning = false;
    private Consumer<String> messageListener;
    private ScanConfig config;
    private String currentSessionId;

    // Настройки параллелизма
    private final int SCANNER_THREAD_POOL_SIZE = 5; // Максимум 5 сканеров одновременно
    private final int BANK_THREAD_POOL_SIZE = 2;    // Максимум 2 банка одновременно
    private final long SCANNER_TIMEOUT_MINUTES = 5; // Таймаут на сканер
    private final long BANK_TIMEOUT_MINUTES = 10;   // Таймаут на банк

    public ScannerService(WebServer webServer, PostgresManager dbManager) {
        this.webServer = webServer;
        this.databaseManager = dbManager;
        this.executor = Executors.newSingleThreadExecutor();
    }

    public void setMessageListener(Consumer<String> listener) {
        this.messageListener = listener;
    }

    // Обновленный метод для установки конфигурации из UI
    public void setConfig(ScanConfig config) {
        this.config = config;
    }

    public synchronized boolean startScan() {
        if (isScanning) {
            return false;
        }
        if (config == null || config.getBanks().isEmpty() || config.getCredentials().isEmpty()) {
            notifyMessage("scan_error", "Конфигурация не задана. Сначала сохраните настройки в UI.");
            return false;
        }

        isScanning = true;
        notifyMessage("scan_started", "Сканирование запущено. Ожидайте результатов...");
        executor.submit(() -> {
            try {
                runScan();
                notifyMessage("scan_completed", "Сканирование успешно завершено");
            } catch (Exception e) {
                notifyMessage("scan_error", "Ошибка сканирования: " + e.getMessage());
                e.printStackTrace();
            } finally {
                isScanning = false;
            }
        });
        return true;
    }

    private void runScan() throws Exception {
        // Создаем сессию сканирования
        currentSessionId = databaseManager.createSession(
                "Сканирование " + new SimpleDateFormat("dd.MM.yyyy HH:mm").format(new Date()),
                configToJson(config)
        );

        if (currentSessionId == null) {
            notifyMessage("error", "Не удалось создать сессию сканирования");
            return;
        }

        notifyMessage("info", "Зарегистрировано сканеров: 11");
        notifyMessage("info", "Идентификатор сессии: " + currentSessionId);
        notifyMessage("info", "Параллелизм: " + BANK_THREAD_POOL_SIZE + " банков, " + SCANNER_THREAD_POOL_SIZE + " сканеров");

        // Получение токенов для пользователей ДО запуска сканеров
        notifyMessage("info", "Получение токенов для пользователей...");
        Map<String, String> tokens = AuthManager.getTokensForScanning(config);

        if (tokens == null || tokens.isEmpty()) {
            notifyMessage("error", "Не удалось получить токены для сканирования");
            return;
        }

        // Сохраняем токены в конфигурацию
        config.setUserTokens(tokens);
        notifyMessage("info", "Получено токенов: " + tokens.size());

        int totalVulnerabilities = 0;
        int totalScannedBanks = 0;

        // Создаем ExecutorService для параллельного сканирования банков
        ExecutorService bankExecutor = Executors.newFixedThreadPool(BANK_THREAD_POOL_SIZE);
        List<Future<BankScanResult>> bankFutures = new ArrayList<>();

        // Запускаем сканирование каждого банка в отдельном потоке
        for (ScanConfig.BankConfig bankConfig : config.getBanks()) {
            Future<BankScanResult> future = bankExecutor.submit(() -> {
                return scanSingleBank(bankConfig, tokens);
            });
            bankFutures.add(future);
        }

        // Собираем результаты от всех банков
        for (Future<BankScanResult> future : bankFutures) {
            try {
                BankScanResult result = future.get(BANK_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                if (result != null) {
                    totalVulnerabilities += result.vulnerabilitiesCount;
                    totalScannedBanks++;
                    notifyMessage("info", "Банк " + result.bankName + " завершен. Уязвимостей: " + result.vulnerabilitiesCount);
                }
            } catch (TimeoutException e) {
                notifyMessage("warning", "Сканирование банка превысило время выполнения (" + BANK_TIMEOUT_MINUTES + " минут)");
            } catch (Exception e) {
                notifyMessage("error", "Ошибка при сканировании банка: " + e.getMessage());
            }
        }

        // Завершаем executor банков
        bankExecutor.shutdown();
        try {
            if (!bankExecutor.awaitTermination(1, TimeUnit.MINUTES)) {
                bankExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            bankExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // Завершаем сессию
        databaseManager.completeSession(currentSessionId, totalScannedBanks, totalVulnerabilities);

        notifyMessage("info", "=".repeat(50));
        notifyMessage("info", "СКАНИРОВАНИЕ ЗАВЕРШЕНО");
        notifyMessage("info", "Всего банков: " + totalScannedBanks);
        notifyMessage("info", "Всего уязвимостей: " + totalVulnerabilities);
        notifyMessage("info", "Идентификатор сессии: " + currentSessionId);
        notifyMessage("info", "=".repeat(50));
    }

    /**
     * Сканирует один банк параллельно всеми сканерами
     */
    private BankScanResult scanSingleBank(ScanConfig.BankConfig bankConfig, Map<String, String> tokens) {
        String baseUrl = bankConfig.getBaseUrl();
        String specUrl = bankConfig.getSpecUrl();

        notifyMessage("info", "=".repeat(50));
        notifyMessage("info", "Сканирование: " + baseUrl);
        notifyMessage("info", "=".repeat(50));

        String cleanBaseUrl = baseUrl.trim();
        notifyMessage("info", "Загрузка OpenAPI-спецификации: " + specUrl);

        try {
            // Загружаем OpenAPI спецификацию
            Object openApiSpec = loadOpenApiSpec(specUrl);
            if (openApiSpec == null) {
                notifyMessage("warning", "Не удалось загрузить OpenAPI спецификацию для " + cleanBaseUrl);
            }

            // Создаем конфигурацию для конкретного банка
            ScanConfig bankScanConfig = createBankScanConfig(config, cleanBaseUrl, specUrl, tokens);

            // Создаем список сканеров
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
                    new API10_UnsafeConsumptionScanner(),
                    new Validation()
            );

            // Создаем ExecutorService для параллельного выполнения сканеров
            ExecutorService scannerExecutor = Executors.newFixedThreadPool(SCANNER_THREAD_POOL_SIZE);
            List<Future<List<Vulnerability>>> scannerFutures = new ArrayList<>();

            // Запускаем все сканеры параллельно
            for (SecurityScanner scanner : securityScanners) {
                Future<List<Vulnerability>> future = scannerExecutor.submit(() -> {
                    return executeScanner(scanner, openApiSpec, bankScanConfig, cleanBaseUrl);
                });
                scannerFutures.add(future);
            }

            // Собираем результаты от всех сканеров
            List<Vulnerability> allVulnerabilities = new ArrayList<>();
            int completedScanners = 0;

            for (Future<List<Vulnerability>> future : scannerFutures) {
                try {
                    List<Vulnerability> scannerResults = future.get(SCANNER_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                    allVulnerabilities.addAll(scannerResults);
                    completedScanners++;
                } catch (TimeoutException e) {
                    notifyMessage("warning", "Сканер превысил время выполнения (" + SCANNER_TIMEOUT_MINUTES + " минут) для банка " + cleanBaseUrl);
                    future.cancel(true);
                } catch (Exception e) {
                    notifyMessage("error", "Ошибка выполнения сканера для банка " + cleanBaseUrl + ": " + e.getMessage());
                }
            }

            // Завершаем executor сканеров
            scannerExecutor.shutdown();
            try {
                if (!scannerExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                    scannerExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                scannerExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }

            notifyMessage("info", "Банк " + cleanBaseUrl + ": завершено сканеров " + completedScanners + "/" + securityScanners.size() +
                    ", найдено уязвимостей: " + allVulnerabilities.size());

            return new BankScanResult(allVulnerabilities.size(), cleanBaseUrl);

        } catch (Exception e) {
            notifyMessage("error", "Критическая ошибка при сканировании банка " + cleanBaseUrl + ": " + e.getMessage());
            e.printStackTrace();
            return new BankScanResult(0, cleanBaseUrl);
        }
    }

    /**
     * Выполняет один сканер и сохраняет результаты
     */
    private List<Vulnerability> executeScanner(SecurityScanner scanner, Object openApiSpec, ScanConfig bankScanConfig, String bankName) {
        String scannerName = scanner.getName();
        notifyMessage("info", "-".repeat(40));
        notifyMessage("info", "Запуск сканера: " + scannerName + " для " + bankName);

        try {
            List<Vulnerability> scannerResults = scanner.scan(openApiSpec, bankScanConfig, new HttpApiClient());

            // Сохраняем результаты в базу данных
            for (Vulnerability vuln : scannerResults) {
                saveVulnerabilityToDatabase(vuln, bankName, scannerName);
            }

            notifyMessage("info", "Сканер " + scannerName + " завершен. Найдено: " + scannerResults.size() + " уязвимостей");
            return scannerResults;

        } catch (Exception e) {
            notifyMessage("error", "Ошибка в сканере " + scannerName + " для " + bankName + ": " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Создает конфигурацию для сканирования конкретного банка
     */
    private ScanConfig createBankScanConfig(ScanConfig mainConfig, String baseUrl, String specUrl, Map<String, String> tokens) {
        ScanConfig bankScanConfig = new ScanConfig();

        bankScanConfig.setBankId(mainConfig.getBankId());
        bankScanConfig.setClientId(mainConfig.getClientId());
        bankScanConfig.setClientSecret(mainConfig.getClientSecret());
        bankScanConfig.setTargetBaseUrl(baseUrl);
        bankScanConfig.setBankBaseUrl(baseUrl);
        bankScanConfig.setOpenApiSpecUrl(specUrl);
        bankScanConfig.setUserTokens(tokens);
        bankScanConfig.setCredentials(mainConfig.getCredentials());
        bankScanConfig.setConsentId(mainConfig.getConsentId());

        return bankScanConfig;
    }

    /**
     * Сохраняет уязвимость в базу данных
     */
    private void saveVulnerabilityToDatabase(Vulnerability vuln, String bankName, String scannerName) {
        String proof = extractProofFromVulnerability(vuln);
        String recommendation = extractRecommendationFromVulnerability(vuln);
        String statusCode = extractStatusCodeFromVulnerability(vuln);

        databaseManager.saveVulnerability(
                bankName,
                vuln.getTitle(),
                vuln.getSeverity().toString(),
                vuln.getCategory().toString(),
                statusCode,
                proof,
                recommendation,
                scannerName,
                currentSessionId
        );

        // Отправка уведомления о новой уязвимости
        notifyNewVulnerability(vuln, bankName, scannerName);
    }

    /**
     * Загружает OpenAPI спецификацию из URL
     */
    private Object loadOpenApiSpec(String specUrl) {
        if (specUrl == null || specUrl.trim().isEmpty()) {
            System.out.println("❌ URL спецификации не указан");
            return null;
        }

        try {
            System.out.println("📥 Загрузка OpenAPI спецификации: " + specUrl);

            // Используем OpenAPIV3Parser для загрузки спецификации
            io.swagger.v3.parser.OpenAPIV3Parser parser = new io.swagger.v3.parser.OpenAPIV3Parser();
            io.swagger.v3.parser.core.models.ParseOptions options = new io.swagger.v3.parser.core.models.ParseOptions();
            options.setResolve(true);
            options.setResolveFully(true);

            io.swagger.v3.parser.core.models.SwaggerParseResult result = parser.readLocation(specUrl, null, options);

            if (result.getOpenAPI() != null) {
                System.out.println("✅ OpenAPI спецификация успешно загружена");
                return result.getOpenAPI();
            } else {
                System.err.println("❌ Не удалось загрузить OpenAPI спецификацию: " + result.getMessages());
                return null;
            }
        } catch (Exception e) {
            System.err.println("❌ Ошибка при загрузке OpenAPI спецификации: " + e.getMessage());
            return null;
        }
    }

    private String configToJson(ScanConfig config) {
        // Простая сериализация конфигурации в JSON
        try {
            StringBuilder json = new StringBuilder("{");
            json.append("\"bankId\":\"").append(config.getBankId()).append("\",");
            json.append("\"banks\":").append(config.getBanks().size()).append(",");
            json.append("\"credentials\":").append(config.getCredentials().size()).append(",");
            json.append("\"bankUrls\":[");

            for (int i = 0; i < config.getBanks().size(); i++) {
                if (i > 0) json.append(",");
                json.append("\"").append(config.getBanks().get(i).getBaseUrl()).append("\"");
            }
            json.append("]}");
            return json.toString();
        } catch (Exception e) {
            return "{\"bankId\":\"unknown\",\"banks\":0,\"credentials\":0}";
        }
    }

    private String extractProofFromVulnerability(Vulnerability vuln) {
        if (vuln.getEvidence() != null && !vuln.getEvidence().isEmpty()) {
            return vuln.getEvidence();
        }
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
        return "Доказательство не доступно для уязвимости: " + vuln.getTitle();
    }

    private String extractRecommendationFromVulnerability(Vulnerability vuln) {
        // ПЕРВОЕ: Используем конкретные рекомендации из уязвимости, если они есть
        if (vuln.getRecommendations() != null && !vuln.getRecommendations().isEmpty()) {
            return String.join("\n", vuln.getRecommendations());
        }

        // ВТОРОЕ: Если конкретных рекомендаций нет, используем общие по категории
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

    private String extractStatusCodeFromVulnerability(Vulnerability vuln) {
        int statusCode = vuln.getStatusCode();
        if (statusCode == -1 || statusCode == 0) {
            return "N/A";
        }
        return String.valueOf(statusCode);
    }

    private void notifyNewVulnerability(Vulnerability vuln, String bankName, String scannerName) {
        Map<String, Object> data = new HashMap<>();
        data.put("id", UUID.randomUUID().toString());
        data.put("bankName", bankName);
        data.put("vulnerabilityTitle", vuln.getTitle());
        data.put("severity", vuln.getSeverity().toString());
        data.put("category", vuln.getCategory().toString());
        data.put("statusCode", "200");
        data.put("scanDate", new Date().toString());
        data.put("proof", extractProofFromVulnerability(vuln));
        data.put("recommendation", extractRecommendationFromVulnerability(vuln));
        data.put("scannerName", scannerName);
        data.put("sessionId", currentSessionId);
        notifyMessage("new_vulnerability", data);
    }

    private void notifyMessage(String type, Object message) {
        if (messageListener != null) {
            try {
                String jsonMessage;
                if (message instanceof String) {
                    jsonMessage = String.format("{\"type\":\"%s\",\"message\":\"%s\"}",
                            type, ((String)message).replace("\"", "\\\""));
                } else {
                    jsonMessage = String.format("{\"type\":\"%s\",\"data\":%s}",
                            type, message.toString());
                }
                messageListener.accept(jsonMessage);
            } catch (Exception e) {
                System.err.println("Error sending message: " + e.getMessage());
            }
        }
    }

    /**
     * Внутренний класс для хранения результатов сканирования банка
     */
    private static class BankScanResult {
        int vulnerabilitiesCount;
        String bankName;

        BankScanResult(int vulnerabilitiesCount, String bankName) {
            this.vulnerabilitiesCount = vulnerabilitiesCount;
            this.bankName = bankName;
        }
    }

    public boolean isScanning() {
        return isScanning;
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}