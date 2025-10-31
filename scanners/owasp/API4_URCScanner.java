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

    private static final int RATE_LIMIT_TEST_REQUESTS = 50; // Уменьшим для избежания таймаута
    private static final int LARGE_PAYLOAD_SIZE_MB = 2; // Уменьшим размер для теста
    private static final int DEEP_NESTING_LEVELS = 50;
    private static final int ZIP_BOMB_SIZE = 10000;

    public API4_URCScanner() {}

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl();

        System.out.println("(API-4) Запуск OWASP API4 Unrestricted Resource Consumption Scanner...");
        System.out.println("(API-4) Цель: Проверка устойчивости к атакам на ресурсы");

        try {
            // Получаем токен для аутентификации
            String token = authenticate(baseUrl, config.getPassword());
            if (token == null) {
                System.err.println("(API-4) Не удалось аутентифицироваться для API4 сканирования");
                return vulnerabilities;
            }

            System.out.println("(API-4) Токен получен, начинаем нагрузочное тестирование...");

            // Выполняем основные тесты
            testRateLimiting(baseUrl, token, vulnerabilities, apiClient);
            testLargePayloads(baseUrl, token, vulnerabilities, apiClient);
            testDeepNesting(baseUrl, token, vulnerabilities, apiClient);
            testMemoryConsumption(baseUrl, token, vulnerabilities, apiClient);

            // Пропускаем самые тяжелые тесты если предыдущие упали
            if (!vulnerabilities.isEmpty()) {
                testExpensiveOperations(baseUrl, token, vulnerabilities, apiClient);
                testZipBomb(baseUrl, token, vulnerabilities, apiClient);
                testConcurrentRequests(baseUrl, token, vulnerabilities, apiClient);
            }

        } catch (Exception e) {
            System.err.println("(API-4) Ошибка при сканировании API4: " + e.getMessage());
        }

        System.out.println("(API-4) API4 сканирование завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private String authenticate(String baseUrl, String password) {
        try {
            return core.AuthManager.getBankAccessToken(baseUrl, "team172-1", password);
        } catch (Exception e) {
            System.err.println("(API-4) Ошибка аутентификации: " + e.getMessage());
            return null;
        }
    }

    private void testRateLimiting(String baseUrl, String token,
                                  List<Vulnerability> vulnerabilities,
                                  ApiClient apiClient) {
        System.out.println("(API-4) Тестирование Rate Limiting...");

        String targetEndpoint = baseUrl + "/accounts";
        AtomicInteger successfulRequests = new AtomicInteger(0);
        AtomicInteger rateLimitedRequests = new AtomicInteger(0);
        List<Long> responseTimes = new ArrayList<>();

        ExecutorService executor = Executors.newFixedThreadPool(5); // Уменьшим пул потоков
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
                        }
                    }
                } catch (Exception e) {
                    // Игнорируем ошибки для этого теста
                }
            }));
        }

        // Ждем завершения всех запросов с таймаутом
        for (Future<?> future : futures) {
            try {
                future.get(10, TimeUnit.SECONDS); // Уменьшим таймаут
            } catch (Exception e) {
                // Продолжаем выполнение
            }
        }

        executor.shutdownNow();

        long totalTime = System.currentTimeMillis() - startTime;
        double requestsPerSecond = totalTime > 0 ? (double) successfulRequests.get() / (totalTime / 1000.0) : 0;

        // Анализируем результаты
        System.out.println("(API-4) Результаты Rate Limiting теста:");
        System.out.println("(API-4) Всего запросов: " + RATE_LIMIT_TEST_REQUESTS);
        System.out.println("(API-4) Успешных: " + successfulRequests.get());
        System.out.println("(API-4) Заблокированных (429): " + rateLimitedRequests.get());
        System.out.println("(API-4) Запросов в секунду: " + String.format("%.2f", requestsPerSecond));

        // Проверяем среднее время ответа
        double avgResponseTime = responseTimes.stream().mapToLong(Long::longValue).average().orElse(0);
        System.out.println("(API-4) Среднее время ответа: " + String.format("%.2f", avgResponseTime) + "ms");

        // Определяем уязвимости
        if (rateLimitedRequests.get() == 0 && successfulRequests.get() >= RATE_LIMIT_TEST_REQUESTS * 0.8) {
            Vulnerability vuln = createURCVulnerability(
                    "Отсутствие Rate Limiting",
                    "Сервер обработал " + successfulRequests.get() + " из " + RATE_LIMIT_TEST_REQUESTS +
                            " запросов без ограничений. Средняя скорость: " +
                            String.format("%.2f", requestsPerSecond) + " запросов/секунду. " +
                            "Это позволяет злоумышленнику выполнять DoS атаки. Доказательство: система не вернула ни одного кода 429 (Too Many Requests) при интенсивной нагрузке.",
                    Vulnerability.Severity.HIGH,
                    "/accounts",
                    "GET",
                    200,
                    "Rate Limiting отсутствует - все " + successfulRequests.get() + " запросов обработаны успешно"
            );
            vulnerabilities.add(vuln);
            System.out.println("(API-4) УЯЗВИМОСТЬ: Отсутствие Rate Limiting - система не ограничивает количество запросов");
        }
    }

    private void testLargePayloads(String baseUrl, String token,
                                   List<Vulnerability> vulnerabilities,
                                   ApiClient apiClient) {
        System.out.println("(API-4) Тестирование обработки больших payload...");

        // Создаем большой JSON payload правильно
        StringBuilder largePayload = new StringBuilder();
        largePayload.append("{\"data\":\"");

        // Добавляем данные для создания payload (~2MB)
        int targetSize = LARGE_PAYLOAD_SIZE_MB * 50000; // Примерно 2MB
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

                if (apiResponse.getStatusCode() == 200) {
                    Vulnerability vuln = createURCVulnerability(
                            "Уязвимость к большим payload",
                            "Сервер принял и обработал большой payload (" +
                                    (payload.length() / 1024) + "KB) за " + responseTime + "ms. " +
                                    "Это может быть использовано для исчерпания ресурсов сервера. Доказательство: система успешно обработала чрезмерно большой запрос размером " + 
                                    (payload.length() / 1024) + "KB без ограничений.",
                            Vulnerability.Severity.HIGH,
                            "/accounts",
                            "POST",
                            apiResponse.getStatusCode(),
                            "Большой payload принят - размер: " + (payload.length() / 1024) + "KB, время обработки: " + responseTime + "ms"
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-4) УЯЗВИМОСТЬ: Сервер уязвим к большим payload - принял запрос размером " + (payload.length() / 1024) + "KB");
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

        // Создаем глубоко вложенный JSON
        StringBuilder nestedPayload = new StringBuilder();
        nestedPayload.append("{\"level1\": {");

        for (int i = 2; i <= DEEP_NESTING_LEVELS; i++) {
            nestedPayload.append("\"level").append(i).append("\": {");
        }

        // Завершаем вложенность
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

                if (apiResponse.getStatusCode() == 200) {
                    Vulnerability vuln = createURCVulnerability(
                            "Уязвимость к глубокой вложенности JSON",
                            "Сервер обработал JSON с " + DEEP_NESTING_LEVELS + " уровнями вложенности за " +
                                    responseTime + "ms. Глубокая вложенность может вызвать переполнение стека. Доказательство: система приняла JSON с " + 
                                    DEEP_NESTING_LEVELS + " уровнями вложенности без ограничений.",
                            Vulnerability.Severity.MEDIUM,
                            "/accounts",
                            "POST",
                            apiResponse.getStatusCode(),
                            "Глубоко вложенный JSON принят - уровней: " + DEEP_NESTING_LEVELS + ", время обработки: " + responseTime + "ms"
                    );
                    vulnerabilities.add(vuln);
                    System.out.println("(API-4) УЯЗВИМОСТЬ: Сервер уязвим к глубокой вложенности - принял JSON с " + DEEP_NESTING_LEVELS + " уровнями");
                }
            }
        } catch (Exception e) {
            System.out.println("(API-4) Сервер отклонил глубоко вложенный JSON");
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
                        int responseSize = apiResponse.getBody().length();

                        if (responseTime > 3000) {
                            Vulnerability vuln = createURCVulnerability(
                                    "Высокое время ответа - " + endpoint,
                                    "Эндпоинт " + endpoint + " отвечает " + responseTime + "ms. " +
                                            "Может быть использовано для Slowloris атак. Доказательство: измеренное время ответа превышает допустимые пределы.",
                                    Vulnerability.Severity.MEDIUM,
                                    endpoint,
                                    "GET",
                                    apiResponse.getStatusCode(),
                                    "Медленный ответ: " + responseTime + "ms, размер ответа: " + responseSize + " байт"
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

            String payload = "{\"permissions\":[\"accounts\"]}";

            long startTime = System.currentTimeMillis();
            Object response = apiClient.executeRequest("POST", baseUrl + "/account-consents/request", payload, headers);
            long responseTime = System.currentTimeMillis() - startTime;

            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;

                if (apiResponse.getStatusCode() == 200 && responseTime > 2000) {
                    Vulnerability vuln = createURCVulnerability(
                            "Дорогостоящая операция - создание согласия",
                            "Операция создания согласия выполняется " + responseTime + "ms. " +
                                    "Может быть использована для истощения ресурсов сервера. Доказательство: операция требует значительного времени выполнения.",
                            Vulnerability.Severity.MEDIUM,
                            "/account-consents/request",
                            "POST",
                            apiResponse.getStatusCode(),
                            "Медленная операция: " + responseTime + "ms"
                    );
                    vulnerabilities.add(vuln);
                }
            }
        } catch (Exception e) {
            // Пропускаем ошибки
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
            zipBombPayload.append("\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"");
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

                if (apiResponse.getStatusCode() == 200 && responseTime < 1000) {
                    Vulnerability vuln = createURCVulnerability(
                            "Потенциальная уязвимость к Zip Bomb",
                            "Сервер быстро обработал payload с высокой избыточностью за " +
                                    responseTime + "ms. Может быть уязвим к атакам на парсер. Доказательство: система быстро обработала избыточные данные без деградации производительности.",
                            Vulnerability.Severity.LOW,
                            "/accounts",
                            "POST",
                            apiResponse.getStatusCode(),
                            "Быстрая обработка избыточных данных: " + responseTime + "ms для " + ZIP_BOMB_SIZE + " элементов"
                    );
                    vulnerabilities.add(vuln);
                }
            }
        } catch (Exception e) {
            // Пропускаем ошибки
        }
    }

    private void testConcurrentRequests(String baseUrl, String token,
                                        List<Vulnerability> vulnerabilities,
                                        ApiClient apiClient) {
        System.out.println("(API-4) Тестирование конкурентных запросов...");

        int concurrentUsers = 10; // Уменьшим количество
        int requestsPerUser = 3;
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
                        }
                    } catch (Exception e) {
                        failedRequests.incrementAndGet();
                    }
                }
            }));
        }

        // Ждем завершения с таймаутом
        for (Future<?> future : futures) {
            try {
                future.get(15, TimeUnit.SECONDS);
            } catch (Exception e) {
                // Продолжаем
            }
        }

        executor.shutdownNow();

        double failureRate = (double) failedRequests.get() / (concurrentUsers * requestsPerUser);
        if (failureRate > 0.3) {
            Vulnerability vuln = createURCVulnerability(
                    "Низкая устойчивость к конкурентной нагрузке",
                    "При " + concurrentUsers + " конкурентных пользователей failure rate составил " +
                            String.format("%.1f", failureRate * 100) + "%. Сервер не справляется с нагрузкой. Доказательство: высокий процент ошибок при одновременных запросах.",
                    Vulnerability.Severity.MEDIUM,
                    "/accounts",
                    "GET",
                    200,
                    "Высокий процент ошибок при конкурентной нагрузке: " + String.format("%.1f", failureRate * 100) + "% неудачных запросов"
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
        vuln.setCategory(Vulnerability.Category.OWASP_API4_URC); // Правильная категория!
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
                "Используйте кэширование для тяжелых операций"
        ));

        return vuln;
    }

    @Override
    public String getName() {
        return "OWASP API4 - Unrestricted Resource Consumption Scanner";
    }
}
