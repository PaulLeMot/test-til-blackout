// scanners/owasp/API4_URCScanner.java
package scanners.owasp;

import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;
import scanners.SecurityScanner;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Сканер для OWASP API4: Unrestricted Resource Consumption
 * Проверка неограниченного потребления ресурсов (DoS, операционные затраты)
 */
public class API4_URCScanner implements SecurityScanner {

    private static final int RATE_LIMIT_TEST_REQUESTS = 20;
    private static final int LARGE_PAYLOAD_SIZE_KB = 100;
    private static final int DEEP_NESTING_LEVELS = 20;
    private static final int ZIP_BOMB_SIZE = 1000;

    public API4_URCScanner() {}

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl();

        System.out.println("(API-4) Запуск OWASP API4 Unrestricted Resource Consumption Scanner...");
        System.out.println("(API-4) Цель: Проверка устойчивости к атакам на ресурсы");

        try {
            // ИСПРАВЛЕНО: Используем уже полученные токены из конфига
            Map<String, String> tokens = config.getUserTokens();
            if (tokens == null || tokens.isEmpty()) {
                System.err.println("(API-4) Не удалось получить токены для API4 сканирования");
                return vulnerabilities;
            }

            // Берем первого доступного пользователя
            String username = tokens.keySet().iterator().next();
            String token = tokens.get(username);

            System.out.println("(API-4) Используем токен для пользователя: " + username + ", начинаем нагрузочное тестирование...");

            // Выполняем основные тесты в последовательном режиме
            testRateLimiting(baseUrl, token, vulnerabilities, apiClient);
            testLargePayloads(baseUrl, token, vulnerabilities, apiClient);
            testDeepNesting(baseUrl, token, vulnerabilities, apiClient);
            testMemoryConsumption(baseUrl, token, vulnerabilities, apiClient);
            testExpensiveOperations(baseUrl, token, vulnerabilities, apiClient);
            testZipBomb(baseUrl, token, vulnerabilities, apiClient);
            testConcurrentRequests(baseUrl, token, vulnerabilities, apiClient);

        } catch (Exception e) {
            System.err.println("(API-4) Ошибка при сканировании API4: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("(API-4) API4 сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private void testRateLimiting(String baseUrl, String token,
                                  List<Vulnerability> vulnerabilities,
                                  ApiClient apiClient) {
        System.out.println("(API-4) Тестирование Rate Limiting...");

        String targetEndpoint = baseUrl + "/accounts";
        AtomicInteger successfulRequests = new AtomicInteger(0);
        AtomicInteger rateLimitedRequests = new AtomicInteger(0);
        AtomicInteger errorRequests = new AtomicInteger(0);
        List<Long> responseTimes = new ArrayList<>();

        ExecutorService executor = Executors.newFixedThreadPool(3);
        List<Future<?>> futures = new ArrayList<>();

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < RATE_LIMIT_TEST_REQUESTS; i++) {
            final int requestNum = i;
            futures.add(executor.submit(() -> {
                try {
                    Map<String, String> headers = new HashMap<>();
                    headers.put("Authorization", "Bearer " + token);
                    headers.put("Accept", "application/json");

                    long requestStart = System.currentTimeMillis();
                    Object response = apiClient.executeRequest("GET", targetEndpoint, null, headers);
                    long responseTime = System.currentTimeMillis() - requestStart;

                    responseTimes.add(responseTime);

                    if (response instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                        if (apiResponse.getStatusCode() == 200) {
                            successfulRequests.incrementAndGet();
                        } else if (apiResponse.getStatusCode() == 429) {
                            rateLimitedRequests.incrementAndGet();
                        } else {
                            errorRequests.incrementAndGet();
                        }
                    } else {
                        errorRequests.incrementAndGet();
                    }
                } catch (Exception e) {
                    errorRequests.incrementAndGet();
                }
            }));

            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
        }

        for (Future<?> future : futures) {
            try {
                future.get(30, TimeUnit.SECONDS);
            } catch (Exception e) {
                // Продолжаем выполнение
            }
        }

        executor.shutdownNow();

        long totalTime = System.currentTimeMillis() - startTime;
        double requestsPerSecond = totalTime > 0 ? (double) successfulRequests.get() / (totalTime / 1000.0) : 0;

        System.out.println("(API-4) Результаты Rate Limiting теста:");
        System.out.println("(API-4) Всего запросов: " + RATE_LIMIT_TEST_REQUESTS);
        System.out.println("(API-4) Успешных: " + successfulRequests.get());
        System.out.println("(API-4) Заблокированных (429): " + rateLimitedRequests.get());
        System.out.println("(API-4) Ошибок: " + errorRequests.get());
        System.out.println("(API-4) Запросов в секунду: " + String.format("%.2f", requestsPerSecond));

        if (!responseTimes.isEmpty()) {
            double avgResponseTime = responseTimes.stream().mapToLong(Long::longValue).average().orElse(0);
            System.out.println("(API-4) Среднее время ответа: " + String.format("%.2f", avgResponseTime) + "ms");
        }

        if (rateLimitedRequests.get() == 0 && successfulRequests.get() > RATE_LIMIT_TEST_REQUESTS * 0.5) {
            Vulnerability vuln = createURCVulnerability(
                    "Отсутствие Rate Limiting",
                    "Сервер обработал " + successfulRequests.get() + " из " + RATE_LIMIT_TEST_REQUESTS +
                            " запросов без ограничений. Средняя скорость: " +
                            String.format("%.2f", requestsPerSecond) + " запросов/секунду. " +
                            "Это позволяет злоумышленнику выполнять DoS атаки.",
                    Vulnerability.Severity.HIGH,
                    "/accounts",
                    "GET",
                    200,
                    "Rate Limiting отсутствует - " + successfulRequests.get() + " запросов обработаны успешно"
            );
            vulnerabilities.add(vuln);
            System.out.println("(API-4) УЯЗВИМОСТЬ: Отсутствие Rate Limiting");
        } else if (errorRequests.get() > RATE_LIMIT_TEST_REQUESTS * 0.7) {
            Vulnerability vuln = createURCVulnerability(
                    "Нестабильность при нагрузке",
                    "Сервер не справился с нагрузкой: " + errorRequests.get() + " из " + RATE_LIMIT_TEST_REQUESTS +
                            " запросов завершились ошибкой. Это может быть использовано для DoS атак.",
                    Vulnerability.Severity.MEDIUM,
                    "/accounts",
                    "GET",
                    500,
                    "Высокий процент ошибок: " + errorRequests.get() + "/" + RATE_LIMIT_TEST_REQUESTS
            );
            vulnerabilities.add(vuln);
        }
    }

    private void testLargePayloads(String baseUrl, String token,
                                   List<Vulnerability> vulnerabilities,
                                   ApiClient apiClient) {
        System.out.println("(API-4) Тестирование обработки больших payload...");

        StringBuilder largePayload = new StringBuilder();
        largePayload.append("{\"data\":\"");

        int targetSize = LARGE_PAYLOAD_SIZE_KB * 1024;
        for (int i = 0; i < targetSize; i++) {
            largePayload.append("X");
            if (largePayload.length() >= targetSize) break;
        }
        largePayload.append("\"}");

        String payload = largePayload.toString();
        System.out.println("(API-4) Размер payload: " + (payload.length() / 1024) + "KB");

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");

            long startTime = System.currentTimeMillis();
            Object response = apiClient.executeRequest("POST", baseUrl + "/accounts", payload, headers);
            long responseTime = System.currentTimeMillis() - startTime;

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                System.out.println("(API-4) Время обработки: " + responseTime + "ms");
                System.out.println("(API-4) Статус ответа: " + apiResponse.getStatusCode());

                if (apiResponse.getStatusCode() == 200 || apiResponse.getStatusCode() == 201) {
                    Vulnerability vuln = createURCVulnerability(
                            "Уязвимость к большим payload",
                            "Сервер принял и обработал большой payload (" +
                                    (payload.length() / 1024) + "KB) за " + responseTime + "ms. " +
                                    "Это может быть использовано для исчерпания ресурсов сервера.",
                            Vulnerability.Severity.HIGH,
                            "/accounts",
                            "POST",
                            apiResponse.getStatusCode(),
                            "Большой payload принят - размер: " + (payload.length() / 1024) + "KB"
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-4) УЯЗВИМОСТЬ: Сервер уязвим к большим payload");
                } else if (apiResponse.getStatusCode() == 413) {
                    System.out.println("(API-4) Сервер правильно отклонил большой payload с кодом 413");
                }
            }
        } catch (Exception e) {
            System.out.println("(API-4) Сервер отклонил большой payload: " + e.getMessage());
        }
    }

    private void testDeepNesting(String baseUrl, String token,
                                 List<Vulnerability> vulnerabilities,
                                 ApiClient apiClient) {
        System.out.println("(API-4) Тестирование глубокой вложенности JSON...");

        StringBuilder nestedPayload = new StringBuilder();
        nestedPayload.append("{\"level1\": {");

        for (int i = 2; i <= DEEP_NESTING_LEVELS; i++) {
            nestedPayload.append("\"level").append(i).append("\": {");
        }

        for (int i = 0; i < DEEP_NESTING_LEVELS; i++) {
            nestedPayload.append("}");
        }

        String payload = nestedPayload.toString();
        System.out.println("(API-4) Уровней вложенности: " + DEEP_NESTING_LEVELS);

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");

            long startTime = System.currentTimeMillis();
            Object response = apiClient.executeRequest("POST", baseUrl + "/accounts", payload, headers);
            long responseTime = System.currentTimeMillis() - startTime;

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() == 200 || apiResponse.getStatusCode() == 201) {
                    Vulnerability vuln = createURCVulnerability(
                            "Уязвимость к глубокой вложенности JSON",
                            "Сервер обработал JSON с " + DEEP_NESTING_LEVELS + " уровнями вложенности. " +
                                    "Глубокая вложенность может вызвать переполнение стека или высокое потребление памяти.",
                            Vulnerability.Severity.MEDIUM,
                            "/accounts",
                            "POST",
                            apiResponse.getStatusCode(),
                            "Глубоко вложенный JSON принят - уровней: " + DEEP_NESTING_LEVELS
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-4) УЯЗВИМОСТЬ: Сервер уязвим к глубокой вложенности");
                } else {
                    System.out.println("(API-4) Сервер правильно отклонил глубоко вложенный JSON");
                }
            }
        } catch (Exception e) {
            System.out.println("(API-4) Сервер отклонил глубоко вложенный JSON: " + e.getMessage());
        }
    }

    private void testMemoryConsumption(String baseUrl, String token,
                                       List<Vulnerability> vulnerabilities,
                                       ApiClient apiClient) {
        System.out.println("(API-4) Тестирование потребления памяти...");

        String[] endpoints = {"/accounts", "/products"};

        for (String endpoint : endpoints) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                headers.put("Accept", "application/json");

                long startTime = System.currentTimeMillis();
                Object response = apiClient.executeRequest("GET", baseUrl + endpoint, null, headers);
                long responseTime = System.currentTimeMillis() - startTime;

                if (response instanceof HttpApiClient.ApiResponse) {
                    HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                    if (apiResponse.getStatusCode() == 200) {
                        String responseBody = apiResponse.getBody();
                        int responseSize = responseBody != null ? responseBody.length() : 0;

                        if (responseSize > 100000) {
                            Vulnerability vuln = createURCVulnerability(
                                    "Большой размер ответа - " + endpoint,
                                    "Эндпоинт " + endpoint + " возвращает большой ответ (" +
                                            (responseSize / 1024) + "KB). Может быть использовано для истощения ресурсов клиента.",
                                    Vulnerability.Severity.LOW,
                                    endpoint,
                                    "GET",
                                    apiResponse.getStatusCode(),
                                    "Большой размер ответа: " + (responseSize / 1024) + "KB"
                            );
                            vulnerabilities.add(vuln);
                        }

                        if (responseTime > 5000) {
                            Vulnerability vuln = createURCVulnerability(
                                    "Высокое время ответа - " + endpoint,
                                    "Эндпоинт " + endpoint + " отвечает " + responseTime + "ms. " +
                                            "Может быть использовано для Slowloris атак.",
                                    Vulnerability.Severity.MEDIUM,
                                    endpoint,
                                    "GET",
                                    apiResponse.getStatusCode(),
                                    "Медленный ответ: " + responseTime + "ms"
                            );
                            vulnerabilities.add(vuln);
                        }
                    }
                }
            } catch (Exception e) {
                // Пропускаем ошибки
            }
        }
    }

    private void testExpensiveOperations(String baseUrl, String token,
                                         List<Vulnerability> vulnerabilities,
                                         ApiClient apiClient) {
        System.out.println("(API-4) Тестирование дорогостоящих операций...");

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");

            String[] expensiveEndpoints = {
                    "/account-consents/request",
                    "/accounts",
                    "/products"
            };

            for (String endpoint : expensiveEndpoints) {
                try {
                    String payload = "{\"permissions\":[\"accounts\"]}";

                    long startTime = System.currentTimeMillis();
                    Object response = apiClient.executeRequest("POST", baseUrl + endpoint, payload, headers);
                    long responseTime = System.currentTimeMillis() - startTime;

                    if (response instanceof HttpApiClient.ApiResponse) {
                        HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                        if ((apiResponse.getStatusCode() == 200 || apiResponse.getStatusCode() == 201) &&
                                responseTime > 3000) {
                            Vulnerability vuln = createURCVulnerability(
                                    "Дорогостоящая операция - " + endpoint,
                                    "Операция " + endpoint + " выполняется " + responseTime + "ms. " +
                                            "Может быть использована для истощения ресурсов сервера.",
                                    Vulnerability.Severity.MEDIUM,
                                    endpoint,
                                    "POST",
                                    apiResponse.getStatusCode(),
                                    "Медленная операция: " + responseTime + "ms"
                            );
                            vulnerabilities.add(vuln);
                        }
                    }
                } catch (Exception e) {
                    // Пропускаем ошибки для этого endpoint
                }
            }
        } catch (Exception e) {
            // Пропускаем общие ошибки
        }
    }

    private void testZipBomb(String baseUrl, String token,
                             List<Vulnerability> vulnerabilities,
                             ApiClient apiClient) {
        System.out.println("(API-4) Тестирование уязвимости к Zip Bomb...");

        StringBuilder zipBombPayload = new StringBuilder();
        zipBombPayload.append("{\"data\":[");

        for (int i = 0; i < ZIP_BOMB_SIZE; i++) {
            if (i > 0) zipBombPayload.append(",");
            zipBombPayload.append("\"").append("A".repeat(100)).append("\"");
        }
        zipBombPayload.append("]}");

        String payload = zipBombPayload.toString();

        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("Content-Type", "application/json");

            long startTime = System.currentTimeMillis();
            Object response = apiClient.executeRequest("POST", baseUrl + "/accounts", payload, headers);
            long responseTime = System.currentTimeMillis() - startTime;

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                if ((apiResponse.getStatusCode() == 200 || apiResponse.getStatusCode() == 201) &&
                        responseTime < 2000) {
                    Vulnerability vuln = createURCVulnerability(
                            "Потенциальная уязвимость к сжатым/избыточным данным",
                            "Сервер быстро обработал payload с высокой избыточностью за " +
                                    responseTime + "ms. Может быть уязвим к атакам на парсер.",
                            Vulnerability.Severity.LOW,
                            "/accounts",
                            "POST",
                            apiResponse.getStatusCode(),
                            "Быстрая обработка избыточных данных: " + responseTime + "ms"
                    );
                    vulnerabilities.add(vuln);
                }
            }
        } catch (Exception e) {
            System.out.println("(API-4) Сервер отклонил избыточный payload: " + e.getMessage());
        }
    }

    private void testConcurrentRequests(String baseUrl, String token,
                                        List<Vulnerability> vulnerabilities,
                                        ApiClient apiClient) {
        System.out.println("(API-4) Тестирование конкурентных запросов...");

        int concurrentUsers = 5;
        int requestsPerUser = 2;
        AtomicInteger successfulRequests = new AtomicInteger(0);
        AtomicInteger failedRequests = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(concurrentUsers);
        List<Future<?>> futures = new ArrayList<>();

        long startTime = System.currentTimeMillis();

        for (int user = 0; user < concurrentUsers; user++) {
            futures.add(executor.submit(() -> {
                for (int request = 0; request < requestsPerUser; request++) {
                    try {
                        Map<String, String> headers = new HashMap<>();
                        headers.put("Authorization", "Bearer " + token);
                        headers.put("Accept", "application/json");

                        Object response = apiClient.executeRequest("GET", baseUrl + "/accounts", null, headers);

                        if (response instanceof HttpApiClient.ApiResponse) {
                            HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                            if (apiResponse.getStatusCode() == 200) {
                                successfulRequests.incrementAndGet();
                            } else {
                                failedRequests.incrementAndGet();
                            }
                        } else {
                            failedRequests.incrementAndGet();
                        }

                        try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                    } catch (Exception e) {
                        failedRequests.incrementAndGet();
                    }
                }
            }));
        }

        for (Future<?> future : futures) {
            try {
                future.get(60, TimeUnit.SECONDS);
            } catch (Exception e) {
                // Продолжаем
            }
        }

        executor.shutdownNow();

        int totalRequests = concurrentUsers * requestsPerUser;
        double failureRate = totalRequests > 0 ? (double) failedRequests.get() / totalRequests : 0;

        System.out.println("(API-4) Результаты конкурентного теста:");
        System.out.println("(API-4) Успешных: " + successfulRequests.get());
        System.out.println("(API-4) Неудачных: " + failedRequests.get());
        System.out.println("(API-4) Процент ошибок: " + String.format("%.1f", failureRate * 100) + "%");

        if (failureRate > 0.5) {
            Vulnerability vuln = createURCVulnerability(
                    "Низкая устойчивость к конкурентной нагрузке",
                    "При " + concurrentUsers + " конкурентных пользователей failure rate составил " +
                            String.format("%.1f", failureRate * 100) + "%. Сервер не справляется с нагрузкой.",
                    Vulnerability.Severity.MEDIUM,
                    "/accounts",
                    "GET",
                    200,
                    "Высокий процент ошибок при конкурентной нагрузке: " + String.format("%.1f", failureRate * 100) + "%"
            );
            vulnerabilities.add(vuln);
        }
    }

    private Vulnerability createURCVulnerability(String title, String description,
                                                 Vulnerability.Severity severity,
                                                 String endpoint, String method, int statusCode,
                                                 String evidence) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API4:2023 - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.OWASP_API4_URC);
        vuln.setEndpoint(endpoint);
        vuln.setMethod(method);
        vuln.setStatusCode(statusCode);

        String fullEvidence = String.format(
                "Эндпоинт: %s %s\nСтатус: %d\nДоказательства: %s",
                method, endpoint, statusCode, evidence
        );
        vuln.setEvidence(fullEvidence);

        vuln.setRecommendations(Arrays.asList(
                "Реализуйте механизм ограничения запросов (rate limiting)",
                "Ограничьте максимальный размер принимаемых запросов",
                "Настройте лимиты для JSON парсера",
                "Реализуйте мониторинг потребления ресурсов",
                "Используйте кэширование для тяжелых операций",
                "Настройте таймауты для обработки запросов",
                "Ограничьте глубину вложенности JSON"
        ));

        return vuln;
    }

    @Override
    public String getName() {
        return "OWASP API4 - Unrestricted Resource Consumption Scanner";
    }
}