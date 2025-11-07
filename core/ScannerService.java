package core;

import scanners.SecurityScanner;
import scanners.owasp.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class ScannerService {
    private static final List<String> BANKS = Arrays.asList(
            "https://vbank.open.bankingapi.ru    ",
            "https://abank.open.bankingapi.ru    ",
            "https://sbank.open.bankingapi.ru    "
    );
    private static final String PASSWORD = "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";
    private final WebServer webServer;
    private final ExecutorService executor;
    private boolean isScanning = false;
    private Consumer<String> messageListener;

    public ScannerService(WebServer webServer) {
        this.webServer = webServer;
        this.executor = Executors.newSingleThreadExecutor();
    }

    public void setMessageListener(Consumer<String> listener) {
        this.messageListener = listener;
    }

    public synchronized boolean startScan() {
        if (isScanning) {
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
        notifyMessage("info", "Зарегистрировано сканеров: 10");

        // Создаём сканеры
        List<SecurityScanner> securityScanners = Arrays.asList(
                new API1_BOLAScanner(),
                new API2_BrokenAuthScanner(),
                new API3_BOScanner(),
                new API4_URCScanner(),
                new API5_BrokenFunctionLevelAuthScanner(),
                new API6_BusinessFlowScanner(), // Уже исправлен
                new API7_SSRFScanner(),
                new API8_SecurityConfigScanner(),
                new API9_InventoryScanner(),
                new API10_UnsafeConsumptionScanner()
        );

        int totalVulnerabilities = 0;
        for (String baseUrl : BANKS) {
            notifyMessage("info", "=".repeat(50));
            notifyMessage("info", "Сканирование: " + baseUrl);
            notifyMessage("info", "=".repeat(50));

            String cleanBaseUrl = baseUrl.trim();
            String specUrl = cleanBaseUrl + "/openapi.json";
            notifyMessage("info", "Загрузка OpenAPI-спецификации: " + specUrl);

            // Инициализация конфигурации
            ScanConfig config = new ScanConfig();
            config.setTargetBaseUrl(cleanBaseUrl);
            config.setPassword(PASSWORD);
            config.setBankBaseUrl(cleanBaseUrl);
            config.setClientId("team172-8");
            config.setClientSecret(PASSWORD);
            config.setBankId("team172");

            // ИСПРАВЛЕНО: Используем правильный метод для получения токенов
            notifyMessage("info", "Получение токенов для пользователей...");

            // Настраиваем конфиг для получения токенов
            ScanConfig tokenConfig = new ScanConfig();
            tokenConfig.setBankBaseUrl(cleanBaseUrl);
            tokenConfig.setClientSecret(PASSWORD);
            tokenConfig.setClientId("team172-8");
            tokenConfig.setBankId("team172");

            Map<String, String> tokens = AuthManager.getTokensForScanning(tokenConfig);

            config.setUserTokens(tokens);
            notifyMessage("info", "Получено токенов: " + tokens.size());

            // Запуск сканеров
            List<Vulnerability> allVulnerabilities = new ArrayList<>();
            for (SecurityScanner scanner : securityScanners) {
                notifyMessage("info", "-".repeat(40));
                notifyMessage("info", "Запуск сканера: " + scanner.getName());
                try {
                    List<Vulnerability> scannerResults = scanner.scan(null, config, new HttpApiClient());
                    allVulnerabilities.addAll(scannerResults);
                    // Сохранение результатов в реальном времени
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
                                scanner.getName()
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

            totalVulnerabilities += allVulnerabilities.size();
            notifyMessage("info", "Банк " + cleanBaseUrl + " завершен. Найдено уязвимостей: " + allVulnerabilities.size());
            // Задержка между банками
            Thread.sleep(3000);
        }

        notifyMessage("info", "=".repeat(50));
        notifyMessage("info", "СКАНИРОВАНИЕ ЗАВЕРШЕНО");
        notifyMessage("info", "Всего уязвимостей: " + totalVulnerabilities);
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