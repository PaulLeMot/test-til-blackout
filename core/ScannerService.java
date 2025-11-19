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
    private final int SCANNER_THREAD_POOL_SIZE = 5;
    private final int BANK_THREAD_POOL_SIZE = 2;
    private final long SCANNER_TIMEOUT_MINUTES = 5;
    private final long BANK_TIMEOUT_MINUTES = 10;

    public ScannerService(WebServer webServer, PostgresManager dbManager) {
        this.webServer = webServer;
        this.databaseManager = dbManager;
        this.executor = Executors.newSingleThreadExecutor();
    }

    public void setMessageListener(Consumer<String> listener) {
        this.messageListener = listener;
    }

    public void setConfig(ScanConfig config) {
        this.config = config;
    }

    public synchronized boolean startScan() {
        if (isScanning) {
            return false;
        }
        if (config == null || config.getBanks().isEmpty()) {
            notifyMessage("scan_error", "Конфигурация не задана. Укажите хотя бы один банк для сканирования.");
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

        // Получение токенов для пользователей (опционально)
        final Map<String, String> tokens = new HashMap<>();
        final boolean hasValidTokens;

        if (hasAuthCredentials(config)) {
            notifyMessage("info", "Попытка получения токенов для аутентифицированного сканирования...");
            boolean tokensReceived = false;
            try {
                Map<String, String> receivedTokens = AuthManager.getTokensForScanning(config);
                if (receivedTokens != null && !receivedTokens.isEmpty()) {
                    tokens.putAll(receivedTokens);
                    tokensReceived = true;
                    config.setUserTokens(tokens);
                    notifyMessage("info", "Получено токенов: " + tokens.size() + " - будет выполнено полное сканирование");
                } else {
                    tokensReceived = false;
                    notifyMessage("warning", "Токены не получены. Будут запущены только сканеры, не требующие аутентификации.");
                }
            } catch (Exception e) {
                tokensReceived = false;
                notifyMessage("warning", "Ошибка при получении токенов: " + e.getMessage() + ". Будут запущены только сканеры, не требующие аутентификации.");
            }
            hasValidTokens = tokensReceived;
        } else {
            hasValidTokens = false;
            notifyMessage("warning", "Учетные данные для аутентификации не указаны. Будут запущены только сканеры, не требующие аутентификации.");
        }

        int totalVulnerabilities = 0;
        int totalScannedBanks = 0;

        // Создаем ExecutorService для параллельного сканирования банков
        ExecutorService bankExecutor = Executors.newFixedThreadPool(BANK_THREAD_POOL_SIZE);
        List<Future<BankScanResult>> bankFutures = new ArrayList<>();

        // Запускаем сканирование каждого банка в отдельном потоке
        for (ScanConfig.BankConfig bankConfig : config.getBanks()) {
            final ScanConfig.BankConfig finalBankConfig = bankConfig;
            Future<BankScanResult> future = bankExecutor.submit(() -> {
                return scanSingleBank(finalBankConfig, tokens, hasValidTokens);
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
     * Проверяет, есть ли учетные данные для аутентификации
     */
    private boolean hasAuthCredentials(ScanConfig config) {
        return (config.getClientId() != null && !config.getClientId().trim().isEmpty()) ||
                (config.getClientSecret() != null && !config.getClientSecret().trim().isEmpty()) ||
                (config.getCredentials() != null && !config.getCredentials().isEmpty());
    }

    /**
     * Сканирует один банк параллельно всеми сканерами
     */
    private BankScanResult scanSingleBank(ScanConfig.BankConfig bankConfig, Map<String, String> tokens, boolean hasValidTokens) {
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

            // Запускаем глубокий анализ схем
            List<Vulnerability> deepAnalysisVulnerabilities = performDeepAnalysis(openApiSpec, cleanBaseUrl);

            // Создаем конфигурацию для конкретного банка
            ScanConfig bankScanConfig = createBankScanConfig(config, cleanBaseUrl, specUrl, tokens);

            // Создаем список всех сканеров
            List<SecurityScanner> allScanners = Arrays.asList(
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

            // Фильтруем сканеры в зависимости от доступности токенов
            List<SecurityScanner> securityScanners = new ArrayList<>();
            if (hasValidTokens) {
                // Если есть токены, запускаем все сканеры
                securityScanners.addAll(allScanners);
                notifyMessage("info", "Запуск всех 11 сканеров (токены доступны)");
            } else {
                // Если токенов нет, запускаем только сканеры, не требующие аутентификации
                for (SecurityScanner scanner : allScanners) {
                    if (canScannerWorkWithoutAuth(scanner)) {
                        securityScanners.add(scanner);
                    }
                }
                notifyMessage("warning", "Запуск только сканеров, не требующих аутентификации: " + securityScanners.size() + " из " + allScanners.size());
            }

            // Если нет сканеров для запуска, возвращаем результат с уже найденными уязвимостями
            if (securityScanners.isEmpty()) {
                List<Vulnerability> allVulnerabilities = new ArrayList<>();
                allVulnerabilities.addAll(deepAnalysisVulnerabilities);
                notifyMessage("warning", "Нет доступных сканеров для запуска без токенов");
                return new BankScanResult(allVulnerabilities.size(), cleanBaseUrl);
            }

            // Создаем ExecutorService для параллельного выполнения сканеров
            ExecutorService scannerExecutor = Executors.newFixedThreadPool(SCANNER_THREAD_POOL_SIZE);
            List<Future<List<Vulnerability>>> scannerFutures = new ArrayList<>();

            // Запускаем все сканеры параллельно
            for (SecurityScanner scanner : securityScanners) {
                Future<List<Vulnerability>> future = scannerExecutor.submit(() -> {
                    return executeScanner(scanner, openApiSpec, bankScanConfig, cleanBaseUrl, hasValidTokens);
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

            // Добавляем результаты глубокого анализа
            allVulnerabilities.addAll(deepAnalysisVulnerabilities);
            // Запускаем корреляцию уязвимостей
            List<Vulnerability> correlatedVulnerabilities = performCorrelationAnalysis(allVulnerabilities);
            allVulnerabilities.addAll(correlatedVulnerabilities);

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
     * Определяет, может ли сканер работать без аутентификации
     */
    private boolean canScannerWorkWithoutAuth(SecurityScanner scanner) {
        String scannerName = scanner.getName();

        // Сканеры, которые могут работать без токенов:
        return scannerName.contains("API8") || // SecurityConfigScanner - проверяет конфигурацию
                scannerName.contains("API9") || // InventoryScanner - инвентаризация API
                scannerName.contains("Validation") || // Валидация контрактов
                scannerName.contains("SecurityConfig") ||
                scannerName.contains("Inventory");
    }

    /**
     * Выполняет один сканер и возвращает результаты
     */
    private List<Vulnerability> executeScanner(SecurityScanner scanner, Object openApiSpec, ScanConfig bankScanConfig, String bankName, boolean hasValidTokens) {
        String scannerName = scanner.getName();
        notifyMessage("info", "-".repeat(40));
        notifyMessage("info", "Запуск сканера: " + scannerName + " для " + bankName);

        // Проверяем, требует ли сканер токены и доступны ли они
        boolean requiresAuth = requiresAuthentication(scanner);

        if (requiresAuth && !hasValidTokens) {
            notifyMessage("warning", "Сканер " + scannerName + " пропущен - требует аутентификации, но токены недоступны");
            return new ArrayList<>();
        }

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
     * Определяет, требует ли сканер аутентификации
     */
    private boolean requiresAuthentication(SecurityScanner scanner) {
        String scannerName = scanner.getName();

        // Сканеры, требующие аутентификации:
        return scannerName.contains("API1") || // BOLA
                scannerName.contains("API2") || // Broken Auth
                scannerName.contains("API3") || // BOPLA
                scannerName.contains("API4") || // URC
                scannerName.contains("API5") || // Broken Function Level Auth
                scannerName.contains("API6") || // Business Flow
                scannerName.contains("API7") || // SSRF
                scannerName.contains("API10") || // Unsafe Consumption
                scannerName.contains("BOLA") ||
                scannerName.contains("SSRF") ||
                scannerName.contains("UnsafeConsumption");
    }

    /**
     * Выполняет глубокий анализ схем OpenAPI
     */
    private List<Vulnerability> performDeepAnalysis(Object openApiSpec, String bankName) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (openApiSpec instanceof io.swagger.v3.oas.models.OpenAPI) {
            try {
                notifyMessage("info", "Запуск глубокого анализа схем...");
                DeepSchemaAnalyzer schemaAnalyzer = new DeepSchemaAnalyzer((io.swagger.v3.oas.models.OpenAPI) openApiSpec);
                List<Vulnerability> schemaVulnerabilities = schemaAnalyzer.analyze();

                // Сохраняем результаты глубокого анализа
                for (Vulnerability vuln : schemaVulnerabilities) {
                    saveVulnerabilityToDatabase(vuln, bankName, "DeepSchemaAnalyzer");
                }

                vulnerabilities.addAll(schemaVulnerabilities);
                notifyMessage("info", "Глубокий анализ схем завершен. Найдено: " + schemaVulnerabilities.size());
            } catch (Exception e) {
                notifyMessage("error", "Ошибка при глубоком анализе схем: " + e.getMessage());
            }
        }

        return vulnerabilities;
    }


    /**
     * Выполняет корреляцию уязвимостей
     */
    private List<Vulnerability> performCorrelationAnalysis(List<Vulnerability> allVulnerabilities) {
        List<Vulnerability> correlatedVulnerabilities = new ArrayList<>();

        try {
            if (allVulnerabilities.size() > 1) {
                notifyMessage("info", "Запуск корреляции уязвимостей...");
                CorrelationEngine correlationEngine = new CorrelationEngine(allVulnerabilities);
                correlatedVulnerabilities = correlationEngine.correlate();

                // Сохраняем результаты корреляции
                for (Vulnerability vuln : correlatedVulnerabilities) {
                    saveVulnerabilityToDatabase(vuln, "Multiple", "CorrelationEngine");
                }

                notifyMessage("info", "Корреляция завершена. Найдено цепочек: " + correlatedVulnerabilities.size());
            }
        } catch (Exception e) {
            notifyMessage("error", "Ошибка при корреляции уязвимостей: " + e.getMessage());
        }

        return correlatedVulnerabilities;
    }

    /**
     * Создает конфигурацию для сканирования конкретного банка
     */
    private ScanConfig createBankScanConfig(ScanConfig mainConfig, String baseUrl, String specUrl, Map<String, String> tokens) {
        ScanConfig bankScanConfig = new ScanConfig();

        // Копируем только необходимые поля
        if (mainConfig.getBankId() != null) {
            bankScanConfig.setBankId(mainConfig.getBankId());
        }
        if (mainConfig.getClientId() != null) {
            bankScanConfig.setClientId(mainConfig.getClientId());
        }
        if (mainConfig.getClientSecret() != null) {
            bankScanConfig.setClientSecret(mainConfig.getClientSecret());
        }

        bankScanConfig.setTargetBaseUrl(baseUrl);
        bankScanConfig.setBankBaseUrl(baseUrl);
        bankScanConfig.setOpenApiSpecUrl(specUrl);
        bankScanConfig.setUserTokens(tokens);

        if (mainConfig.getCredentials() != null) {
            bankScanConfig.setCredentials(mainConfig.getCredentials());
        }

        if (mainConfig.getConsentId() != null) {
            bankScanConfig.setConsentId(mainConfig.getConsentId());
        }

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
            System.out.println("URL спецификации не указан");
            return null;
        }

        try {
            System.out.println("Загрузка OpenAPI спецификации: " + specUrl);

            // Используем OpenAPIV3Parser для загрузки спецификации
            io.swagger.v3.parser.OpenAPIV3Parser parser = new io.swagger.v3.parser.OpenAPIV3Parser();
            io.swagger.v3.parser.core.models.ParseOptions options = new io.swagger.v3.parser.core.models.ParseOptions();
            options.setResolve(true);
            options.setResolveFully(true);

            io.swagger.v3.parser.core.models.SwaggerParseResult result = parser.readLocation(specUrl, null, options);

            if (result.getOpenAPI() != null) {
                System.out.println("OpenAPI спецификация успешно загружена");
                return result.getOpenAPI();
            } else {
                System.err.println("Не удалось загрузить OpenAPI спецификацию: " + result.getMessages());
                return null;
            }
        } catch (Exception e) {
            System.err.println("Ошибка при загрузке OpenAPI спецификации: " + e.getMessage());
            return null;
        }
    }

    private String configToJson(ScanConfig config) {
        // Простая сериализация конфигурации в JSON
        try {
            StringBuilder json = new StringBuilder("{");
            json.append("\"banks\":").append(config.getBanks().size()).append(",");
            json.append("\"bankUrls\":[");

            for (int i = 0; i < config.getBanks().size(); i++) {
                if (i > 0) json.append(",");
                json.append("\"").append(config.getBanks().get(i).getBaseUrl()).append("\"");
            }
            json.append("]");

            // Добавляем информацию о наличии учетных данных
            if (config.getBankId() != null) {
                json.append(",\"bankId\":\"").append(config.getBankId()).append("\"");
            }
            if (config.getClientId() != null) {
                json.append(",\"clientId\":\"").append(config.getClientId()).append("\"");
            }
            if (config.getCredentials() != null) {
                json.append(",\"credentials\":").append(config.getCredentials().size());
            }

            json.append("}");
            return json.toString();
        } catch (Exception e) {
            return "{\"banks\":0,\"credentials\":0}";
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