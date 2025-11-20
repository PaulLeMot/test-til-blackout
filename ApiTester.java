import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.*;
import java.util.*;

/**
 * Тестер API - выполняет реальные запросы к API
 * Компиляция: javac -cp "lib/*" ApiTester.java
 * Запуск: java -cp ".:lib/*" ApiTester
 */
public class ApiTester {
    
    // Хардкод credentials
    private static final String CLIENT_ID = "team172";
    private static final String CLIENT_SECRET = "";
    private static final String TOKEN_URL = "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token";
    
    private static ObjectMapper mapper = new ObjectMapper();
    private static String accessToken = null;
    
    public static void main(String[] args) {
        try {
            System.out.println("🚀 Запуск тестирования API");
            System.out.println("=" .repeat(60));
            
            // 1. Получаем токен
            System.out.println("🔐 Получение access token...");
            accessToken = getAccessToken();
            
            if (accessToken == null) {
                System.err.println("❌ Не удалось получить токен авторизации");
                return;
            }
            
            System.out.println("✅ Токен получен успешно");
            System.out.println("Токен: " + accessToken.substring(0, 50) + "...");
            
            // 2. Загружаем спецификации и выполняем запросы
            System.out.println("\n📁 Загрузка спецификаций...");
            List<ApiSpec> specs = loadAllSpecs();
            
            if (specs.isEmpty()) {
                System.err.println("❌ Не найдено спецификаций для тестирования");
                return;
            }
            
            System.out.println("✅ Загружено спецификаций: " + specs.size());
            
            // 3. Выполняем запросы для каждой спецификации
            for (ApiSpec spec : specs) {
                System.out.println("\n" + "=" .repeat(60));
                System.out.println("🧪 ТЕСТИРОВАНИЕ: " + spec.title);
                System.out.println("=" .repeat(60));
                
                executeApiRequests(spec);
            }
            
            System.out.println("\n🎉 Тестирование завершено!");
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка при тестировании: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Получение access token через OAuth2 client_credentials
     */
    private static String getAccessToken() throws Exception {
        URL url = new URL(TOKEN_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        // Настраиваем запрос
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        
        // Формируем тело запроса
        String formData = "grant_type=client_credentials&client_id=" + CLIENT_ID + "&client_secret=" + CLIENT_SECRET;
        
        // Отправляем данные
        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = formData.getBytes("utf-8");
            os.write(input, 0, input.length);
        }
        
        // Получаем ответ
        int responseCode = conn.getResponseCode();
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
    private static List<ApiSpec> loadAllSpecs() throws Exception {
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
    private static ApiSpec parseSpecification(File specFile) throws Exception {
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
    private static void processPathItem(ApiSpec spec, String path, JsonNode pathMethods) {
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
    private static ApiEndpoint processOperation(String httpMethod, String path, JsonNode operation) {
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
     * Выполнение API запросов для спецификации
     */
    private static void executeApiRequests(ApiSpec spec) {
        if (spec.baseUrls.isEmpty()) {
            System.out.println("❌ Нет базовых URL для тестирования");
            return;
        }
        
        String baseUrl = spec.baseUrls.get(0);
        
        for (ApiEndpoint endpoint : spec.endpoints) {
            try {
                System.out.println("\n🔹 Тестирование: " + endpoint.method + " " + endpoint.path);
                System.out.println("-".repeat(40));
                
                // Подготавливаем URL
                String fullUrl = prepareUrl(baseUrl, endpoint);
                
                // Выполняем запрос
                String response = executeRequest(endpoint.method, fullUrl, endpoint);
                
                // Выводим результат
                System.out.println("✅ Ответ получен:");
                System.out.println(response);
                
                // Пауза между запросами
                Thread.sleep(1000);
                
            } catch (Exception e) {
                System.err.println("❌ Ошибка при выполнении запроса: " + e.getMessage());
            }
        }
    }
    
    /**
     * Подготовка URL с заменой плейсхолдеров
     */
    private static String prepareUrl(String baseUrl, ApiEndpoint endpoint) {
        String path = endpoint.path;
        
        // Заменяем path parameters на реальные значения
        for (ApiParameter param : endpoint.parameters) {
            if ("path".equals(param.in)) {
                String value = getParameterValue(param);
                path = path.replace("{" + param.name + "}", value);
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
            }
        }
        
        return urlBuilder.toString();
    }
    
    /**
     * Получение значения для параметра
     */
    private static String getParameterValue(ApiParameter param) {
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
    private static String executeRequest(String method, String url, ApiEndpoint endpoint) throws Exception {
        URL requestUrl = new URL(url);
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
            }
        }
        
        // Добавляем X-Caller-Id если не указан
        if (!conn.getRequestProperties().containsKey("X-Caller-Id")) {
            conn.setRequestProperty("X-Caller-Id", "team172");
        }
        
        // Для POST/PUT запросов с телом
        if (("POST".equals(method) || "PUT".equals(method)) && endpoint.hasRequestBody) {
            conn.setDoOutput(true);
            String requestBody = generateRequestBody(endpoint);
            
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = requestBody.getBytes("utf-8");
                os.write(input, 0, input.length);
            }
        }
        
        // Выполняем запрос
        int responseCode = conn.getResponseCode();
        System.out.println("HTTP Code: " + responseCode);
        
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
    private static String generateRequestBody(ApiEndpoint endpoint) {
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
