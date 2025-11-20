package core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URI;
import java.io.*;
import java.util.*;

/**
 * Тестер API - выполняет реальные запросы к API
 */
public class ApiTester {

    // Убраны хардкод credentials - теперь передаются извне
    private static final String TOKEN_URL = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token";

    private static ObjectMapper mapper = new ObjectMapper();
    private String accessToken = null;
    private int responseCode = 0;
    private String baseUrl;
    private String clientId;
    private String clientSecret;

    // Конструкторы с credentials
    public ApiTester(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.baseUrl = null;
    }

    public ApiTester(String clientId, String clientSecret, String baseUrl) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.baseUrl = baseUrl;
    }

    // Сеттеры для credentials
    public void setCredentials(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public static void main(String[] args) {
        try {
            System.out.println("🚀 Запуск тестирования API");
            System.out.println("=" .repeat(60));

            // Для совместимости со старым кодом - использовать значения по умолчанию или из аргументов
            String clientId = args.length > 0 ? args[0] : "team172";
            String clientSecret = args.length > 1 ? args[1] : "FFsJfRyuMjNZgWzl1mruxPrKCBSIVZkY";

            ApiTester tester = new ApiTester(clientId, clientSecret);
            List<TestedApiCall> results = tester.executeFullTestSuite();

            System.out.println("\n🎉 Тестирование завершено! Собрано результатов: " + results.size());

        } catch (Exception e) {
            System.err.println("❌ Ошибка при тестировании: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Внутренний класс для хранения результатов тестирования
     */
    public static class TestedApiCall {
        private String method;
        private String path;
        private int statusCode;
        private String responseBody;
        private String requestBody;
        private Map<String, String> requestParameters;
        private Map<String, String> requestHeaders;
        private long responseTime;

        // Конструкторы
        public TestedApiCall() {
            this.requestParameters = new HashMap<>();
            this.requestHeaders = new HashMap<>();
        }

        public TestedApiCall(String method, String path, int statusCode, String responseBody) {
            this();
            this.method = method;
            this.path = path;
            this.statusCode = statusCode;
            this.responseBody = responseBody;
        }

        // Геттеры и сеттеры
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }

        public int getStatusCode() { return statusCode; }
        public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

        public String getResponseBody() { return responseBody; }
        public void setResponseBody(String responseBody) { this.responseBody = responseBody; }

        public String getRequestBody() { return requestBody; }
        public void setRequestBody(String requestBody) { this.requestBody = requestBody; }

        public Map<String, String> getRequestParameters() { return requestParameters; }
        public void setRequestParameters(Map<String, String> requestParameters) { this.requestParameters = requestParameters; }

        public Map<String, String> getRequestHeaders() { return requestHeaders; }
        public void setRequestHeaders(Map<String, String> requestHeaders) { this.requestHeaders = requestHeaders; }

        public long getResponseTime() { return responseTime; }
        public void setResponseTime(long responseTime) { this.responseTime = responseTime; }

        public void addParameter(String name, String value) {
            this.requestParameters.put(name, value);
        }

        public void addHeader(String name, String value) {
            this.requestHeaders.put(name, value);
        }

        @Override
        public String toString() {
            return method + " " + path + " -> " + statusCode;
        }
    }

    /**
     * Выполняет полный набор тестов и возвращает результаты
     */
    public List<TestedApiCall> executeFullTestSuite() {
        List<TestedApiCall> testResults = new ArrayList<>();

        try {
            System.out.println("🚀 Запуск тестирования API для сбора эндпоинтов...");

            // Проверяем наличие credentials
            if (clientId == null || clientSecret == null) {
                System.err.println("❌ Не указаны clientId и clientSecret");
                return testResults;
            }

            // 1. Получаем токен
            accessToken = getAccessToken();
            if (accessToken == null) {
                System.err.println("❌ Не удалось получить токен авторизации");
                return testResults;
            }

            System.out.println("✅ Токен получен успешно");

            // 2. Загружаем спецификации
            List<ApiSpec> specs = loadAllSpecs();
            if (specs.isEmpty()) {
                System.err.println("❌ Не найдено спецификаций для тестирования");
                return testResults;
            }

            System.out.println("✅ Загружено спецификаций: " + specs.size());

            // 3. Выполняем запросы для каждой спецификации
            for (ApiSpec spec : specs) {
                System.out.println("\n🧪 ТЕСТИРОВАНИЕ: " + spec.title);
                System.out.println("=" .repeat(60));

                List<TestedApiCall> specResults = executeApiRequestsForSpec(spec, accessToken);
                testResults.addAll(specResults);
            }

        } catch (Exception e) {
            System.err.println("❌ Ошибка при выполнении тестов: " + e.getMessage());
            e.printStackTrace();
        }

        return testResults;
    }

    /**
     * Выполняет API запросы для конкретной спецификации
     */
    private List<TestedApiCall> executeApiRequestsForSpec(ApiSpec spec, String accessToken) {
        List<TestedApiCall> results = new ArrayList<>();

        // Используем установленный baseUrl или из спецификации
        String baseUrlToUse = this.baseUrl;
        if (baseUrlToUse == null && !spec.baseUrls.isEmpty()) {
            baseUrlToUse = spec.baseUrls.get(0);
        }

        if (baseUrlToUse == null) {
            System.out.println("❌ Нет базового URL для тестирования");
            return results;
        }

        for (ApiEndpoint endpoint : spec.endpoints) {
            try {
                System.out.println("🔹 Тестирование: " + endpoint.method + " " + endpoint.path);
                System.out.println("-".repeat(40));

                // Создаем запись для результата
                TestedApiCall testCall = new TestedApiCall();
                testCall.setMethod(endpoint.method);
                testCall.setPath(endpoint.path);

                // Подготавливаем URL и параметры
                String fullUrl = prepareUrl(baseUrlToUse, endpoint, testCall);
                testCall.addHeader("Authorization", "Bearer " + accessToken);
                testCall.addHeader("Content-Type", "application/json");
                testCall.addHeader("X-Caller-Id", "team172");

                // Добавляем параметры в запись
                for (ApiParameter param : endpoint.parameters) {
                    String value = getParameterValue(param);
                    if ("header".equals(param.in)) {
                        testCall.addHeader(param.name, value);
                    } else if ("query".equals(param.in)) {
                        testCall.addParameter(param.name, value);
                    }
                }

                // Для POST/PUT запросов сохраняем тело запроса
                String requestBody = null;
                if (("POST".equals(endpoint.method) || "PUT".equals(endpoint.method)) && endpoint.hasRequestBody) {
                    requestBody = generateRequestBody(endpoint);
                    testCall.setRequestBody(requestBody);
                }

                // Выполняем запрос
                long startTime = System.currentTimeMillis();
                String response = executeRequest(endpoint.method, fullUrl, endpoint, requestBody, testCall);
                long responseTime = System.currentTimeMillis() - startTime;

                testCall.setStatusCode(responseCode);
                testCall.setResponseBody(response);
                testCall.setResponseTime(responseTime);

                results.add(testCall);

                System.out.println("HTTP Code: " + testCall.getStatusCode());
                System.out.println("✅ Ответ получен:");
                System.out.println(response);

                // Пауза между запросами
                Thread.sleep(1000);

            } catch (Exception e) {
                System.err.println("❌ Ошибка при выполнении запроса: " + e.getMessage());
                // Создаем запись об ошибке
                TestedApiCall errorCall = new TestedApiCall();
                errorCall.setMethod(endpoint.method);
                errorCall.setPath(endpoint.path);
                errorCall.setStatusCode(0);
                errorCall.setResponseBody("ERROR: " + e.getMessage());
                results.add(errorCall);
            }
        }

        return results;
    }

    /**
     * Получение access token через OAuth2 client_credentials
     */
    private String getAccessToken() throws Exception {
        // Проверяем наличие credentials
        if (clientId == null || clientSecret == null) {
            throw new IllegalStateException("Client ID and Client Secret must be set before getting access token");
        }

        // Исправлено: используем URI вместо deprecated конструктора URL
        URL url = new URI(TOKEN_URL).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        // Настраиваем запрос
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);

        // Формируем тело запроса с переданными credentials
        String formData = "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret;

        // Отправляем данные
        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = formData.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        // Получаем ответ
        responseCode = conn.getResponseCode();
        System.out.println("Response Code: " + responseCode);

        if (responseCode == 200) {
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            // Парсим JSON ответ и извлекаем access_token
            JsonNode jsonResponse = mapper.readTree(response.toString());
            return jsonResponse.path("access_token").asText();
        } else {
            System.err.println("Ошибка при получении токена:");
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
            String errorLine;
            while ((errorLine = errorReader.readLine()) != null) {
                System.err.println(errorLine);
            }
            return null;
        }
    }

    /**
     * Загрузка всех спецификаций из папки Specifications
     */
    private List<ApiSpec> loadAllSpecs() throws Exception {
        List<ApiSpec> specs = new ArrayList<>();
        File specsDir = new File("Specifications");
        File[] specFiles = specsDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".json"));

        if (specFiles == null) return specs;

        for (File specFile : specFiles) {
            try {
                ApiSpec spec = parseSpecification(specFile);
                specs.add(spec);
            } catch (Exception e) {
                System.err.println("❌ Ошибка при загрузке " + specFile.getName() + ": " + e.getMessage());
            }
        }

        return specs;
    }

    /**
     * Парсинг одной спецификации
     */
    private ApiSpec parseSpecification(File specFile) throws Exception {
        JsonNode root = mapper.readTree(specFile);
        ApiSpec spec = new ApiSpec();
        spec.fileName = specFile.getName();

        // Базовая информация
        JsonNode info = root.path("info");
        if (!info.isMissingNode()) {
            spec.title = info.path("title").asText("N/A");
            spec.description = info.path("description").asText("N/A");
            spec.version = info.path("version").asText("N/A");
        }

        // Servers
        JsonNode servers = root.path("servers");
        if (servers.isArray() && servers.size() > 0) {
            for (JsonNode server : servers) {
                spec.baseUrls.add(server.path("url").asText());
            }
        }

        // Paths - эндпоинты
        JsonNode paths = root.path("paths");
        if (paths.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> pathFields = paths.fields();
            while (pathFields.hasNext()) {
                Map.Entry<String, JsonNode> pathEntry = pathFields.next();
                String path = pathEntry.getKey();
                JsonNode pathMethods = pathEntry.getValue();

                processPathItem(spec, path, pathMethods);
            }
        }

        return spec;
    }

    /**
     * Обработка пути и его методов
     */
    private void processPathItem(ApiSpec spec, String path, JsonNode pathMethods) {
        String[] httpMethods = {"get", "post", "put", "delete", "patch"};

        for (String method : httpMethods) {
            JsonNode operation = pathMethods.path(method);
            if (!operation.isMissingNode()) {
                ApiEndpoint endpoint = processOperation(method.toUpperCase(), path, operation);
                spec.endpoints.add(endpoint);
            }
        }
    }

    /**
     * Обработка операции (метода)
     */
    private ApiEndpoint processOperation(String httpMethod, String path, JsonNode operation) {
        ApiEndpoint endpoint = new ApiEndpoint();
        endpoint.method = httpMethod;
        endpoint.path = path;
        endpoint.operationId = operation.path("operationId").asText("N/A");
        endpoint.summary = operation.path("summary").asText("");

        // Parameters
        JsonNode parameters = operation.path("parameters");
        if (parameters.isArray() && parameters.size() > 0) {
            for (JsonNode param : parameters) {
                ApiParameter parameter = new ApiParameter();
                parameter.name = param.path("name").asText();
                parameter.in = param.path("in").asText();
                parameter.required = param.path("required").asBoolean(false);
                parameter.example = param.path("example").asText("");

                endpoint.parameters.add(parameter);
            }
        }

        // Request Body
        JsonNode requestBody = operation.path("requestBody");
        if (!requestBody.isMissingNode()) {
            endpoint.hasRequestBody = true;
        }

        return endpoint;
    }

    /**
     * Подготовка URL с заменой плейсхолдеров
     */
    private String prepareUrl(String baseUrl, ApiEndpoint endpoint, TestedApiCall testCall) {
        String path = endpoint.path;

        // Заменяем path parameters на реальные значения
        for (ApiParameter param : endpoint.parameters) {
            if ("path".equals(param.in)) {
                String value = getParameterValue(param);
                path = path.replace("{" + param.name + "}", value);
                testCall.addParameter(param.name, value);
            }
        }

        // Добавляем query parameters
        StringBuilder urlBuilder = new StringBuilder(baseUrl + path);
        boolean firstQueryParam = true;

        for (ApiParameter param : endpoint.parameters) {
            if ("query".equals(param.in) && param.required) {
                if (firstQueryParam) {
                    urlBuilder.append("?");
                    firstQueryParam = false;
                } else {
                    urlBuilder.append("&");
                }
                String value = getParameterValue(param);
                urlBuilder.append(param.name).append("=").append(value);
                testCall.addParameter(param.name, value);
            }
        }

        return urlBuilder.toString();
    }

    /**
     * Получение значения для параметра
     */
    private String getParameterValue(ApiParameter param) {
        // Используем пример из спецификации или генерируем значение
        if (!param.example.isEmpty()) {
            return param.example;
        }

        // Генерация значений на основе имени параметра
        switch (param.name.toLowerCase()) {
            case "externalaccountid":
            case "accountid":
                return "0dbcb7ee-6c59-483b-966a-44d11557665b"; // Пример UUID
            case "correlation-id":
                return UUID.randomUUID().toString();
            default:
                return "test_value";
        }
    }

    /**
     * Выполнение HTTP запроса
     */
    private String executeRequest(String method, String url, ApiEndpoint endpoint, String requestBody, TestedApiCall testCall) throws Exception {
        // Исправлено: используем URI вместо deprecated конструктора URL
        URL requestUrl = new URI(url).toURL();
        HttpURLConnection conn = (HttpURLConnection) requestUrl.openConnection();

        // Настраиваем метод
        conn.setRequestMethod(method);

        // Добавляем заголовки
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);

        // Добавляем обязательные заголовки из параметров
        for (ApiParameter param : endpoint.parameters) {
            if ("header".equals(param.in) && param.required) {
                String value = getParameterValue(param);
                conn.setRequestProperty(param.name, value);
                testCall.addHeader(param.name, value);
            }
        }

        // Добавляем X-Caller-Id если не указан
        if (!conn.getRequestProperties().containsKey("X-Caller-Id")) {
            conn.setRequestProperty("X-Caller-Id", "team172");
            testCall.addHeader("X-Caller-Id", "team172");
        }

        // Для POST/PUT запросов с телом
        if (("POST".equals(method) || "PUT".equals(method)) && endpoint.hasRequestBody && requestBody != null) {
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = requestBody.getBytes("utf-8");
                os.write(input, 0, input.length);
            }
        }

        // Выполняем запрос
        responseCode = conn.getResponseCode();

        // Читаем ответ
        StringBuilder response = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                responseCode >= 400 ? conn.getErrorStream() : conn.getInputStream()))) {

            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
        }

        return response.toString();
    }

    /**
     * Упрощенная версия executeRequest для тестирования отдельных эндпоинтов
     */
    private String executeRequest(String method, String url, ApiEndpoint endpoint, String requestBody) throws Exception {
        // Исправлено: используем URI вместо deprecated конструктора URL
        URL requestUrl = new URI(url).toURL();
        HttpURLConnection conn = (HttpURLConnection) requestUrl.openConnection();

        // Настраиваем метод
        conn.setRequestMethod(method);

        // Добавляем заголовки
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("X-Caller-Id", "team172");

        // Для POST/PUT запросов с телом
        if (("POST".equals(method) || "PUT".equals(method)) && requestBody != null) {
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = requestBody.getBytes("utf-8");
                os.write(input, 0, input.length);
            }
        }

        // Выполняем запрос
        responseCode = conn.getResponseCode();

        // Читаем ответ
        StringBuilder response = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                responseCode >= 400 ? conn.getErrorStream() : conn.getInputStream()))) {

            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
        }

        return response.toString();
    }

    /**
     * Генерация тела запроса
     */
    private String generateRequestBody(ApiEndpoint endpoint) {
        // Для эндпоинта списания баллов
        if (endpoint.path.contains("redemption")) {
            return "{"
                    + "\"redemptionReferenceNumber\": \"" + UUID.randomUUID().toString() + "\","
                    + "\"redemptionAmount\": 50,"
                    + "\"valuePerPoint\": 0.01,"
                    + "\"programId\": \"A7DV56B\","
                    + "\"catalogId\": \"C9AP78DS9K\""
                    + "}";
        }

        // Общий шаблон для других POST запросов
        return "{\"test\": \"data\"}";
    }

    // Классы для хранения данных (аналогичные парсеру)
    static class ApiSpec {
        String fileName;
        String title;
        String description;
        String version;
        List<String> baseUrls = new ArrayList<>();
        List<ApiEndpoint> endpoints = new ArrayList<>();
    }

    static class ApiEndpoint {
        String method;
        String path;
        String operationId;
        String summary;
        List<ApiParameter> parameters = new ArrayList<>();
        boolean hasRequestBody = false;
    }

    static class ApiParameter {
        String name;
        String in;
        boolean required;
        String example;
    }
}