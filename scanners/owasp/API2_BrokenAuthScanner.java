package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.TestedEndpoint;
import core.EndpointParameter;
import java.util.*;

public class API2_BrokenAuthScanner implements SecurityScanner {

    // Кэш для токенов в рамках одного сканирования
    private Map<String, String> tokenCache = new HashMap<>();
    private String cachedValidToken = null;
    private long lastRequestTime = 0;
    private final long MIN_REQUEST_INTERVAL = 1000; // 1 секунда между запросами

    public API2_BrokenAuthScanner() {}

    @Override
    public String getName() {
        return "OWASP API2: Broken Authentication Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-2) Запуск сканирования на уязвимости Broken Authentication (OWASP API Security Top 10:2023 - API2)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Если включен статический анализ, используем эндпоинты из конфигурации
        if (config.isStaticAnalysisEnabled() && config.getTestedEndpoints() != null) {
            vulnerabilities.addAll(scanEndpoints(config.getTestedEndpoints(), config, apiClient));
        }

        // Динамический анализ только если включен
        if (config.isDynamicAnalysisEnabled()) {
            // Используем токены из конфигурации вместо повторной аутентификации
            if (!preloadTokensFromConfig(config)) {
                System.out.println("(API-2) Предупреждение: не удалось загрузить валидные токены из конфигурации");
                return vulnerabilities;
            }

            vulnerabilities.addAll(performDynamicAuthTests(config, apiClient));
        }

        System.out.println("(API-2) Сканирование Broken Authentication завершено. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    @Override
    public List<Vulnerability> scanEndpoints(List<TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-2) Запуск СТАТИЧЕСКОГО анализа Broken Authentication на " + endpoints.size() + " эндпоинтах");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Анализ структуры эндпоинтов
        vulnerabilities.addAll(analyzeAuthenticationEndpoints(endpoints, config));
        vulnerabilities.addAll(analyzeSensitiveParameters(endpoints, config));
        vulnerabilities.addAll(analyzeSecuritySchemes(endpoints, config));
        vulnerabilities.addAll(analyzeTokenSecurity(endpoints, config));

        // Комбинированный анализ с динамическими тестами
        if (config.getAnalysisMode() == ScanConfig.AnalysisMode.COMBINED) {
            vulnerabilities.addAll(performCombinedAuthTests(endpoints, config, apiClient));
        }

        System.out.println("(API-2) Статический анализ Broken Authentication завершен. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Анализ эндпоинтов аутентификации
     */
    private List<Vulnerability> analyzeAuthenticationEndpoints(List<TestedEndpoint> endpoints, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Паттерны для идентификации эндпоинтов аутентификации
        String[] authPatterns = {
                "/auth", "/login", "/token", "/oauth", "/signin", "/signup",
                "/register", "/password", "/reset", "/forgot", "/logout"
        };

        for (TestedEndpoint endpoint : endpoints) {
            String path = endpoint.getPath().toLowerCase();
            String method = endpoint.getMethod();

            // Проверяем, является ли эндпоинт аутентификационным
            boolean isAuthEndpoint = Arrays.stream(authPatterns)
                    .anyMatch(pattern -> path.contains(pattern));

            if (isAuthEndpoint) {
                // Проверяем различные уязвимости аутентификации
                Vulnerability vuln = analyzeAuthEndpointVulnerabilities(endpoint, config);
                if (vuln != null) {
                    vulnerabilities.add(vuln);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Анализ уязвимостей конкретного эндпоинта аутентификации
     */
    private Vulnerability analyzeAuthEndpointVulnerabilities(TestedEndpoint endpoint, ScanConfig config) {
        List<String> issues = new ArrayList<>();

        // 1. Проверка использования HTTP вместо HTTPS
        if (endpoint.getSource() != null && endpoint.getSource().toLowerCase().startsWith("http:")) {
            issues.add("Используется HTTP вместо HTTPS");
        }

        // 2. Проверка чувствительных параметров в URL
        if (endpoint.getParameters() != null) {
            for (EndpointParameter param : endpoint.getParameters()) {
                if (param.isSensitive() && "query".equals(param.getIn())) {
                    issues.add("Чувствительный параметр '" + param.getName() + "' передается в query string");
                }
            }
        }

        // 3. Проверка слабых методов аутентификации
        if (endpoint.getSummary() != null) {
            String summary = endpoint.getSummary().toLowerCase();
            if (summary.contains("basic auth") || summary.contains("basic authentication")) {
                issues.add("Используется Basic Authentication без HTTPS");
            }
        }

        // 4. Проверка отсутствия ограничений попыток входа
        if (endpoint.getDescription() != null) {
            String description = endpoint.getDescription().toLowerCase();
            if (!description.contains("rate limit") && !description.contains("throttling") &&
                    !description.contains("attempt") && !description.contains("lockout")) {
                issues.add("Возможно отсутствие ограничений попыток входа");
            }
        }

        if (!issues.isEmpty()) {
            return createAuthVulnerability(endpoint, issues, config);
        }

        return null;
    }

    /**
     * Анализ чувствительных параметров
     */
    private List<Vulnerability> analyzeSensitiveParameters(List<TestedEndpoint> endpoints, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (TestedEndpoint endpoint : endpoints) {
            if (endpoint.getParameters() != null) {
                for (EndpointParameter param : endpoint.getParameters()) {
                    if (param.isSensitive()) {
                        Vulnerability vuln = createSensitiveParameterVulnerability(endpoint, param, config);
                        vulnerabilities.add(vuln);
                    }
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Анализ схем безопасности
     */
    private List<Vulnerability> analyzeSecuritySchemes(List<TestedEndpoint> endpoints, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Проверяем наличие security headers в протестированных эндпоинтах
        for (TestedEndpoint endpoint : endpoints) {
            if (endpoint.isTested() && endpoint.getRequestHeaders() != null) {
                Map<String, String> headers = endpoint.getRequestHeaders();

                // Проверка отсутствия security headers
                List<String> missingHeaders = new ArrayList<>();
                if (!headers.containsKey("Authorization") && !headers.containsKey("X-API-Key")) {
                    missingHeaders.add("Authorization/X-API-Key");
                }

                if (!missingHeaders.isEmpty()) {
                    Vulnerability vuln = createSecurityHeadersVulnerability(endpoint, missingHeaders, config);
                    vulnerabilities.add(vuln);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Анализ безопасности токенов
     */
    private List<Vulnerability> analyzeTokenSecurity(List<TestedEndpoint> endpoints, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Проверяем токены из конфигурации
        Map<String, String> tokens = config.getUserTokens();
        if (tokens != null) {
            for (Map.Entry<String, String> entry : tokens.entrySet()) {
                String token = entry.getValue();
                if (token != null) {
                    vulnerabilities.addAll(analyzeTokenVulnerabilities(token, entry.getKey(), config));
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Создание уязвимости для проблем аутентификации
     */
    private Vulnerability createAuthVulnerability(TestedEndpoint endpoint, List<String> issues, ScanConfig config) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API2:2023 - Broken Authentication");
        vuln.setDescription(
                "Обнаружены проблемы в механизме аутентификации для эндпоинта " +
                        endpoint.getMethod() + " " + endpoint.getPath() + ":\n\n" +
                        String.join("\n• ", issues) + "\n\n" +
                        "Эти проблемы могут позволить злоумышленнику обойти аутентификацию или перехватить учетные данные."
        );
        vuln.setSeverity(Vulnerability.Severity.HIGH);
        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
        vuln.setEndpoint(endpoint.getPath());
        vuln.setMethod(endpoint.getMethod());
        vuln.setEvidence(
                "Статический анализ выявил следующие проблемы:\n" +
                        "- Эндпоинт: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "- Источник: " + endpoint.getSource() + "\n" +
                        "- Проблемы: " + String.join(", ", issues) + "\n" +
                        "- Параметры: " + (endpoint.getParameters() != null ? endpoint.getParameters().size() : 0)
        );

        vuln.setRecommendations(Arrays.asList(
                "Использовать HTTPS для всех эндпоинтов аутентификации",
                "Реализовать многофакторную аутентификацию для критических операций",
                "Внедрить ограничение попыток входа и механизмы блокировки",
                "Использовать безопасные методы хранения и передачи токенов",
                "Регулярно обновлять и проверять механизмы аутентификации",
                "Использовать стандартные протоколы аутентификации (OAuth 2.0, OpenID Connect)"
        ));

        return vuln;
    }

    /**
     * Создание уязвимости для чувствительных параметров
     */
    private Vulnerability createSensitiveParameterVulnerability(TestedEndpoint endpoint, EndpointParameter param, ScanConfig config) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API2:2023 - Sensitive Data Exposure in Parameters");
        vuln.setDescription(
                "Чувствительный параметр '" + param.getName() + "' обнаружен в эндпоинте " +
                        endpoint.getMethod() + " " + endpoint.getPath() + ".\n\n" +
                        "Параметр передается через: " + param.getIn() + "\n" +
                        "Это может привести к раскрытию конфиденциальной информации через логи, кеши браузера или history."
        );
        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
        vuln.setEndpoint(endpoint.getPath());
        vuln.setMethod(endpoint.getMethod());
        vuln.setParameter(param.getName());
        vuln.setEvidence(
                "Обнаружен чувствительный параметр:\n" +
                        "- Имя параметра: " + param.getName() + "\n" +
                        "- Расположение: " + param.getIn() + "\n" +
                        "- Обязательный: " + param.isRequired() + "\n" +
                        "- Эндпоинт: " + endpoint.getMethod() + " " + endpoint.getPath()
        );

        vuln.setRecommendations(Arrays.asList(
                "Не передавать чувствительные данные через URL parameters",
                "Использовать заголовки Authorization для передачи токенов",
                "Шифровать чувствительные данные при передаче",
                "Регулярно проверять логи на наличие чувствительной информации",
                "Использовать безопасные методы хранения паролей (хеширование с salt)"
        ));

        return vuln;
    }

    /**
     * Создание уязвимости для security headers
     */
    private Vulnerability createSecurityHeadersVulnerability(TestedEndpoint endpoint, List<String> missingHeaders, ScanConfig config) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API2:2023 - Missing Security Headers");
        vuln.setDescription(
                "Отсутствуют важные security headers в запросах к эндпоинту " +
                        endpoint.getMethod() + " " + endpoint.getPath() + ".\n\n" +
                        "Отсутствующие заголовки: " + String.join(", ", missingHeaders) + "\n\n" +
                        "Это может указывать на слабую реализацию механизмов аутентификации и авторизации."
        );
        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
        vuln.setEndpoint(endpoint.getPath());
        vuln.setMethod(endpoint.getMethod());
        vuln.setEvidence(
                "Анализ заголовков запроса выявил отсутствие:\n" +
                        "- Эндпоинт: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "- Отсутствующие заголовки: " + String.join(", ", missingHeaders) + "\n" +
                        "- Всего заголовков в запросе: " +
                        (endpoint.getRequestHeaders() != null ? endpoint.getRequestHeaders().size() : 0)
        );

        vuln.setRecommendations(Arrays.asList(
                "Всегда использовать заголовок Authorization для передачи токенов доступа",
                "Реализовать стандартные security headers (X-Content-Type-Options, X-Frame-Options)",
                "Использовать HTTPS для всех запросов",
                "Внедрить механизм CORS для контроля доступа к API",
                "Регулярно обновлять и проверять security headers"
        ));

        return vuln;
    }

    /**
     * Анализ уязвимостей токенов
     */
    private List<Vulnerability> analyzeTokenVulnerabilities(String token, String tokenType, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Проверка длины токена
        if (token.length() < 100) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("API2:2023 - Short JWT Token");
            vuln.setDescription("JWT token для " + tokenType + " слишком короткий, что может указывать на слабую безопасность");
            vuln.setSeverity(Vulnerability.Severity.LOW);
            vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
            vuln.setEvidence("Длина токена: " + token.length() + " символов");
            vuln.setRecommendations(Arrays.asList(
                    "Использовать более длинные JWT токены (минимум 128 символов)",
                    "Обеспечить достаточную энтропию при генерации токенов"
            ));
            vulnerabilities.add(vuln);
        }

        // Анализ JWT структуры
        if (token.startsWith("eyJ")) {
            try {
                String[] parts = token.split("\\.");
                if (parts.length == 3) {
                    String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
                    String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));

                    // Проверка алгоритма подписи
                    if (header.contains("none") || header.contains("HS256")) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("API2:2023 - Weak JWT Signature Algorithm");
                        vuln.setDescription("JWT token для " + tokenType + " использует слабый алгоритм подписи");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                        vuln.setEvidence("JWT header: " + header);
                        vuln.setRecommendations(Arrays.asList(
                                "Использовать сильные алгоритмы подписи (RS256)",
                                "Избегать алгоритма 'none' в production",
                                "Регулярно ротировать ключи подписи"
                        ));
                        vulnerabilities.add(vuln);
                    }

                    // Проверка срока действия
                    if (!payload.contains("\"exp\"")) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("API2:2023 - JWT Token Without Expiration");
                        vuln.setDescription("JWT token для " + tokenType + " не имеет срока действия");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                        vuln.setEvidence("JWT payload missing 'exp' claim");
                        vuln.setRecommendations(Arrays.asList(
                                "Всегда устанавливать срок действия для JWT токенов",
                                "Использовать разумное время жизни токенов (15-60 минут)",
                                "Реализовать механизм обновления токенов"
                        ));
                        vulnerabilities.add(vuln);
                    }

                    // Проверка на чувствительные данные
                    if (payload.contains("\"password\"") || payload.contains("\"secret\"") || payload.contains("\"private_key\"")) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("API2:2023 - Sensitive Data in JWT Payload");
                        vuln.setDescription("JWT token для " + tokenType + " содержит чувствительные данные");
                        vuln.setSeverity(Vulnerability.Severity.HIGH);
                        vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                        vuln.setEvidence("JWT payload contains sensitive fields");
                        vuln.setRecommendations(Arrays.asList(
                                "Никогда не хранить чувствительные данные в JWT payload",
                                "Использовать reference tokens для чувствительной информации",
                                "Шифровать JWT payload при необходимости хранения чувствительных данных"
                        ));
                        vulnerabilities.add(vuln);
                    }
                }
            } catch (Exception e) {
                System.out.println("(API-2) Ошибка анализа JWT токена: " + e.getMessage());
            }
        }

        return vulnerabilities;
    }

    // ========== ДИНАМИЧЕСКИЕ МЕТОДЫ ==========

    /**
     * Загружаем токены из конфигурации вместо повторной аутентификации
     */
    private boolean preloadTokensFromConfig(ScanConfig config) {
        System.out.println("(API-2) Загрузка токенов из конфигурации...");

        Map<String, String> tokens = config.getUserTokens();

        if (tokens == null || tokens.isEmpty()) {
            System.out.println("(API-2) В конфигурации нет доступных токенов");
            return false;
        }

        tokenCache.putAll(tokens);
        System.out.println("(API-2) Загружено токенов из конфигурации: " + tokens.size());

        // Сохраняем первый валидный токен
        for (String token : tokens.values()) {
            if (token != null && isTokenValid(token)) {
                cachedValidToken = token;
                System.out.println("(API-2) Валидный токен найден");
                return true;
            }
        }

        System.out.println("(API-2) В конфигурации нет валидных токенов");
        return false;
    }

    /**
     * Простая проверка валидности токена по формату
     */
    private boolean isTokenValid(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        // JWT токены обычно начинаются с eyJ и содержат 2 точки
        boolean isJWT = token.startsWith("eyJ") && token.chars().filter(ch -> ch == '.').count() == 2;
        boolean hasMinLength = token.length() >= 10;

        return isJWT && hasMinLength;
    }

    /**
     * Умная задержка между запросами для избежания 429 ошибок
     */
    private void smartDelay() {
        long currentTime = System.currentTimeMillis();
        long timeSinceLastRequest = currentTime - lastRequestTime;

        if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
            long delayNeeded = MIN_REQUEST_INTERVAL - timeSinceLastRequest;
            try {
                Thread.sleep(delayNeeded);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        lastRequestTime = System.currentTimeMillis();
    }

    /**
     * Выполняет запрос с интеллектуальной задержкой
     */
    private Object executeRequestWithDelay(ApiClient apiClient, String method, String url, String body, Map<String, String> headers) {
        smartDelay();
        return apiClient.executeRequest(method, url, body, headers);
    }

    /**
     * Динамические тесты аутентификации
     */
    private List<Vulnerability> performDynamicAuthTests(ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        testUnauthorizedAccess(config, apiClient, vulnerabilities);
        testInvalidTokens(config, apiClient, vulnerabilities);
        testAuthHeaders(config, apiClient, vulnerabilities);
        testSensitiveEndpoints(config, apiClient, vulnerabilities);
        testWithValidToken(config, apiClient, vulnerabilities);
        testBruteforceProtection(config, apiClient, vulnerabilities);
        testRateLimiting(config, apiClient, vulnerabilities);

        return vulnerabilities;
    }

    /**
     * Комбинированные тесты аутентификации
     */
    private List<Vulnerability> performCombinedAuthTests(List<TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        System.out.println("(API-2) Выполнение комбинированных тестов аутентификации...");

        // Здесь можно добавить логику, комбинирующую статические данные с динамическими тестами
        // Например, тестировать только те эндпоинты, которые были выявлены как потенциально уязвимые в статическом анализе

        return vulnerabilities;
    }

    // Оригинальные методы тестирования
    private void testUnauthorizedAccess(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование несанкционированного доступа к защищенным endpoint...");

        String[] protectedEndpoints = {
                "/",
                "/health",
                "/api/version",
                "/admin",
                "/config",
                "/docs",
                "/swagger"
        };

        for (String endpoint : protectedEndpoints) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;

            try {
                Map<String, String> noAuthHeaders = new HashMap<>();
                noAuthHeaders.put("Content-Type", "application/json");
                noAuthHeaders.put("Accept", "application/json");

                Object responseObj = executeRequestWithDelay(apiClient, "GET", fullUrl, null, noAuthHeaders);
                core.ApiResponse response = (core.ApiResponse) responseObj;

                if (isSuccessResponse(response) && !endpoint.equals("/") && !endpoint.equals("/health")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Unauthorized Access to Protected Endpoint");
                    vuln.setDescription("Endpoint " + endpoint + " is accessible without authentication");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint(endpoint);
                    vuln.setMethod("GET");
                    vuln.setEvidence("Status " + response.getStatusCode() + " without Authorization header");
                    vuln.setStatusCode(response.getStatusCode());
                    vuln.setRecommendations(Arrays.asList(
                            "Implement proper authentication checks",
                            "Require valid JWT tokens for all protected endpoints",
                            "Return 401 Unauthorized for unauthenticated requests"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Endpoint " + endpoint + " доступен без аутентификации");
                } else {
                    System.out.println("(API-2) Endpoint " + endpoint + " корректно защищен (статус: " + response.getStatusCode() + ")");
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private void testInvalidTokens(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование с невалидными/просроченными токенами...");

        String[] invalidTokens = {
                "invalid_token_123",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZWFtMTcyLTgiLCJ0eXBlIjoiY2xpZW50IiwiYmFuayI6InNlbGYiLCJleHAiOjE3NjIyNjI1MzF9.C3e_h5RSYuNHeFNH_oyPAbH1B7-4z3BLrLGMgOQpLGE",
                "Bearer invalid",
                "null",
                ""
        };

        String testEndpoint = config.getTargetBaseUrl() + "/health";

        for (String token : invalidTokens) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                if (token != null && !token.isEmpty() && !token.equals("null")) {
                    headers.put("Authorization", "Bearer " + token);
                }

                Object responseObj = executeRequestWithDelay(apiClient, "GET", testEndpoint, null, headers);
                core.ApiResponse response = (core.ApiResponse) responseObj;

                if (isSuccessResponse(response)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Accepts Invalid JWT Token");
                    vuln.setDescription("API accepts invalid/expired JWT tokens");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/health");
                    vuln.setMethod("GET");
                    vuln.setEvidence("Accepted invalid token and returned status " + response.getStatusCode());
                    vuln.setStatusCode(response.getStatusCode());
                    vuln.setRecommendations(Arrays.asList(
                            "Validate JWT signature and expiration",
                            "Reject tokens with invalid format",
                            "Implement proper token validation middleware"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: API принимает невалидный JWT токен");
                    break;
                } else {
                    System.out.println("(API-2) Невалидный токен корректно отклонен: " + response.getStatusCode());
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования невалидного токена: " + e.getMessage());
            }
        }
    }

    private void testAuthHeaders(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование различных заголовков аутентификации...");

        String testEndpoint = config.getTargetBaseUrl() + "/health";

        if (cachedValidToken == null) {
            System.out.println("(API-2) Нет валидного токена для тестирования заголовков аутентификации");
            return;
        }

        Map<String, String> authHeaderTests = new HashMap<>();
        authHeaderTests.put("Authorization", "Bearer " + cachedValidToken);
        authHeaderTests.put("authorization", "Bearer " + cachedValidToken);
        authHeaderTests.put("AUTHORIZATION", "Bearer " + cachedValidToken);
        authHeaderTests.put("X-API-Key", cachedValidToken);
        authHeaderTests.put("Token", cachedValidToken);
        authHeaderTests.put("X-Auth-Token", cachedValidToken);

        for (Map.Entry<String, String> test : authHeaderTests.entrySet()) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                headers.put(test.getKey(), test.getValue());

                Object responseObj = executeRequestWithDelay(apiClient, "GET", testEndpoint, null, headers);
                core.ApiResponse response = (core.ApiResponse) responseObj;

                if (isSuccessResponse(response) && !test.getKey().equals("Authorization")) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Multiple Authentication Header Support");
                    vuln.setDescription("API accepts authentication via non-standard headers: " + test.getKey());
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/health");
                    vuln.setMethod("GET");
                    vuln.setEvidence("Accepted non-standard header: " + test.getKey() + " with status " + response.getStatusCode());
                    vuln.setStatusCode(response.getStatusCode());
                    vuln.setRecommendations(Arrays.asList(
                            "Use only standard Authorization header with Bearer scheme",
                            "Reject authentication via non-standard headers",
                            "Document proper authentication method"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: API принимает нестандартные заголовки аутентификации");
                } else if (isSuccessResponse(response) && test.getKey().equals("Authorization")) {
                    System.out.println("(API-2) Стандартный заголовок Authorization работает корректно");
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования заголовка " + test.getKey() + ": " + e.getMessage());
            }
        }
    }

    private void testSensitiveEndpoints(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование чувствительных endpoint без аутентификации...");

        String[] sensitiveEndpoints = {
                "/admin",
                "/config",
                "/logs",
                "/debug",
                "/env",
                "/metrics",
                "/actuator",
                "/phpmyadmin",
                "/.git",
                "/backup"
        };

        for (String endpoint : sensitiveEndpoints) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");

                Object responseObj = executeRequestWithDelay(apiClient, "GET", fullUrl, null, headers);
                core.ApiResponse response = (core.ApiResponse) responseObj;

                if (isSuccessResponse(response)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Sensitive Endpoint Accessible Without Authentication");
                    vuln.setDescription("Highly sensitive endpoint " + endpoint + " is accessible without any authentication");
                    vuln.setSeverity(Vulnerability.Severity.CRITICAL);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint(endpoint);
                    vuln.setMethod("GET");
                    vuln.setEvidence("Status " + response.getStatusCode() + " for sensitive endpoint without auth");
                    vuln.setStatusCode(response.getStatusCode());
                    vuln.setRecommendations(Arrays.asList(
                            "Implement strict authentication for all sensitive endpoints",
                            "Use role-based access control",
                            "Regularly audit endpoint access controls"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) КРИТИЧЕСКАЯ УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Чувствительный endpoint доступен без аутентификации");
                } else if (response.getStatusCode() != 404) {
                    System.out.println("(API-2) Чувствительный endpoint " + endpoint + " вернул: " + response.getStatusCode());
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования чувствительного endpoint " + endpoint + ": " + e.getMessage());
            }
        }
    }

    private void testWithValidToken(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование с валидным токеном...");

        if (cachedValidToken == null) {
            System.out.println("(API-2) Нет валидного токена для тестирования");
            return;
        }

        String[] endpointsWithToken = {
                "/",
                "/health"
        };

        for (String endpoint : endpointsWithToken) {
            String fullUrl = config.getTargetBaseUrl() + endpoint;

            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");
                headers.put("Accept", "application/json");
                headers.put("Authorization", "Bearer " + cachedValidToken);

                Object responseObj = executeRequestWithDelay(apiClient, "GET", fullUrl, null, headers);
                core.ApiResponse response = (core.ApiResponse) responseObj;

                if (response.getStatusCode() == 403) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Valid Token Rejected - Authorization Issue");
                    vuln.setDescription("Valid JWT token is rejected with 403 Forbidden");
                    vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint(endpoint);
                    vuln.setMethod("GET");
                    vuln.setEvidence("Status 403 with valid token");
                    vuln.setStatusCode(response.getStatusCode());
                    vuln.setRecommendations(Arrays.asList(
                            "Check token validation logic",
                            "Ensure proper scope/permission validation",
                            "Verify token signature verification"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Валидный токен отклонен с ошибкой 403");
                } else if (isSuccessResponse(response)) {
                    System.out.println("(API-2) " + endpoint + " корректно работает с валидным токеном (статус: " + response.getStatusCode() + ")");
                } else {
                    System.out.println("(API-2) " + endpoint + " вернул статус: " + response.getStatusCode() + " с валидным токеном");
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования " + endpoint + " с валидным токеном: " + e.getMessage());
            }
        }
    }

    private void testBruteforceProtection(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование защиты от брутфорс-атак...");

        String loginUrl = config.getBankBaseUrl() + "/auth/bank-token";
        int maxAttempts = 10;
        boolean protectionDetected = false;

        for (int i = 1; i <= maxAttempts; i++) {
            try {
                String fakeClientId = "team" + (1000 + i);
                String fakeSecret = "fake_secret_" + i;

                String requestBody = "client_id=" + fakeClientId + "&client_secret=" + fakeSecret;

                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/x-www-form-urlencoded");

                Object responseObj = executeRequestWithDelay(apiClient, "POST", loginUrl, requestBody, headers);
                core.ApiResponse response = (core.ApiResponse) responseObj;

                System.out.println("(API-2) Попытка брутфорс-атаки " + i + ": " + response.getStatusCode());

                if (response.getStatusCode() == 429) {
                    protectionDetected = true;
                    System.out.println("(API-2) Защита от брутфорс-атак обнаружена на попытке " + i);
                    break;
                }

                if (i >= 5 && (response.getStatusCode() == 401 || response.getStatusCode() == 422)) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Missing Bruteforce Protection");
                    vuln.setDescription("No rate limiting or account lockout after " + i + " failed authentication attempts");
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
                    vuln.setEndpoint("/auth/bank-token");
                    vuln.setMethod("POST");
                    vuln.setEvidence("Still returns " + response.getStatusCode() + " after " + i + " failed attempts");
                    vuln.setStatusCode(response.getStatusCode());
                    vuln.setRecommendations(Arrays.asList(
                            "Implement account lockout after 5-10 failed attempts",
                            "Add rate limiting for authentication endpoints",
                            "Use CAPTCHA or delay mechanisms"
                    ));
                    vulnerabilities.add(vuln);
                    System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Отсутствует защита от брутфорс-атак");
                    break;
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования брутфорс-защиты: " + e.getMessage());
            }
        }

        if (protectionDetected) {
            System.out.println("(API-2) Защита от брутфорс-атак реализована корректно");
        }
    }

    private void testRateLimiting(ScanConfig config, ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        System.out.println("(API-2) Тестирование ограничения частоты запросов (rate limiting)...");

        String testEndpoint = config.getTargetBaseUrl() + "/health";
        int rapidRequests = 10;
        int rateLimitTriggered = 0;

        for (int i = 1; i <= rapidRequests; i++) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Content-Type", "application/json");

                Object responseObj = apiClient.executeRequest("GET", testEndpoint, null, headers);
                core.ApiResponse response = (core.ApiResponse) responseObj;

                System.out.println("(API-2) Тест rate limiting " + i + ": " + response.getStatusCode());

                if (response.getStatusCode() == 429) {
                    rateLimitTriggered++;
                }

                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }

            } catch (Exception e) {
                System.out.println("(API-2) Ошибка тестирования rate limiting: " + e.getMessage());
            }
        }

        if (rateLimitTriggered == 0) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("Missing Rate Limiting");
            vuln.setDescription("No rate limiting detected after " + rapidRequests + " rapid requests");
            vuln.setSeverity(Vulnerability.Severity.MEDIUM);
            vuln.setCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);
            vuln.setEndpoint("/health");
            vuln.setMethod("GET");
            vuln.setEvidence("No 429 responses after " + rapidRequests + " requests");
            vuln.setStatusCode(200);
            vuln.setRecommendations(Arrays.asList(
                    "Implement rate limiting for all API endpoints",
                    "Use sliding window or token bucket algorithm",
                    "Set reasonable limits per IP/user"
            ));
            vulnerabilities.add(vuln);
            System.out.println("(API-2) УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: Отсутствует ограничение частоты запросов");
        } else {
            System.out.println("(API-2) Ограничение частоты запросов обнаружено: " + rateLimitTriggered + "/" + rapidRequests + " запросов заблокировано");
        }
    }

    // Вспомогательные методы
    private Map<String, String> createDefaultHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        return headers;
    }

    private boolean isSuccessResponse(core.ApiResponse response) {
        int status = response.getStatusCode();
        return status >= 200 && status < 300;
    }
}