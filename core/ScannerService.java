package core;

import scanners.SecurityScanner;
import scanners.owasp.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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

        notifyMessage("info", "Зарегистрировано сканеров: 10");
        notifyMessage("info", "Идентификатор сессии: " + currentSessionId);

        // Создаём сканеры
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

        int totalVulnerabilities = 0;
        int totalScannedBanks = 0;

        // Используем банки из конфигурации UI вместо хардкода
        for (ScanConfig.BankConfig bankConfig : config.getBanks()) {
            String baseUrl = bankConfig.getBaseUrl();
            String specUrl = bankConfig.getSpecUrl();

            notifyMessage("info", "=".repeat(50));
            notifyMessage("info", "Сканирование: " + baseUrl);
            notifyMessage("info", "=".repeat(50));

            String cleanBaseUrl = baseUrl.trim();
            notifyMessage("info", "Загрузка OpenAPI-спецификации: " + specUrl);

            // Инициализация конфигурации для конкретного банка
            ScanConfig bankScanConfig = new ScanConfig();
            bankScanConfig.setTargetBaseUrl(cleanBaseUrl);
            bankScanConfig.setBankBaseUrl(cleanBaseUrl);

            // Используем учетные данные из UI конфигурации
            if (!config.getCredentials().isEmpty()) {
                // Берем первого пользователя как основного
                ScanConfig.UserCredentials primaryCred = config.getCredentials().get(0);
                bankScanConfig.setClientId(primaryCred.getUsername());
                bankScanConfig.setClientSecret(primaryCred.getPassword());
                bankScanConfig.setBankId("team172"); // Используем префикс команды
            }

            // Получение токенов для пользователей из UI
            notifyMessage("info", "Получение токенов для пользователей...");
            Map<String, String> tokens = AuthManager.getTokensForScanning(bankScanConfig);

            bankScanConfig.setUserTokens(tokens);
            notifyMessage("info", "Получено токенов: " + tokens.size());

            // Запуск сканеров
            List<Vulnerability> allVulnerabilities = new ArrayList<>();
            for (SecurityScanner scanner : securityScanners) {
                notifyMessage("info", "-".repeat(40));
                notifyMessage("info", "Запуск сканера: " + scanner.getName());
                try {
                    List<Vulnerability> scannerResults = scanner.scan(null, bankScanConfig, new HttpApiClient());
                    allVulnerabilities.addAll(scannerResults);

                    // Сохранение результатов в реальном времени с sessionId
                    for (Vulnerability vuln : scannerResults) {
                        String proof = extractProofFromVulnerability(vuln);
                        String recommendation = extractRecommendationFromVulnerability(vuln);
                        webServer.saveScanResult(
                                cleanBaseUrl,
                                vuln.getTitle(),
                                vuln.getSeverity().toString(),
                                vuln.getCategory().toString(),
                                "200",
                                proof,
                                recommendation,
                                scanner.getName(),
                                currentSessionId  // Передаем sessionId
                        );
                        // Отправка уведомления о новой уязвимости
                        notifyNewVulnerability(vuln, cleanBaseUrl, scanner.getName());
                    }
                    notifyMessage("info", "Сканер " + scanner.getName() +
                            " завершен. Найдено уязвимостей: " + scannerResults.size());
                } catch (Exception e) {
                    notifyMessage("error", "Ошибка в сканере " + scanner.getName() + ": " + e.getMessage());
                }
                // Задержка между сканерами
                Thread.sleep(2000);
            }

            totalScannedBanks++;
            totalVulnerabilities += allVulnerabilities.size();
            notifyMessage("info", "Банк " + cleanBaseUrl + " завершен. Найдено уязвимостей: " + allVulnerabilities.size());

            // Задержка между банками
            Thread.sleep(3000);
        }

        // Завершаем сессию
        databaseManager.completeSession(currentSessionId, totalScannedBanks, totalVulnerabilities);

        notifyMessage("info", "=".repeat(50));
        notifyMessage("info", "СКАНИРОВАНИЕ ЗАВЕРШЕНО");
        notifyMessage("info", "Всего уязвимостей: " + totalVulnerabilities);
        notifyMessage("info", "Идентификатор сессии: " + currentSessionId);
    }

    private String configToJson(ScanConfig config) {
        // Простая сериализация конфигурации в JSON
        try {
            StringBuilder json = new StringBuilder("{");
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

    public boolean isScanning() {
        return isScanning;
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}