package core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import java.io.File;

/**
 * Утилита для анализа OpenAPI спецификаций
 * Компиляция: javac -cp "lib/*" OpenApiSpecParser.java
 * Запуск: java -cp ".:lib/*" OpenApiSpecParser
 */
public class OpenApiSpecParser {
    
    private static ObjectMapper mapper = new ObjectMapper();
    private static List<ApiSpec> allSpecs = new ArrayList<>();
    
    public static void main(String[] args) {
        try {
            System.out.println("🔍 Поиск спецификаций в папке Specifications...");
            
            // Получаем все JSON файлы из папки Specifications
            File specsDir = new File("Specifications");
            File[] specFiles = specsDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".json"));
            
            if (specFiles == null || specFiles.length == 0) {
                System.err.println("❌ В папке Specifications не найдено .json файлов");
                return;
            }
            
            System.out.println("📁 Найдено файлов: " + specFiles.length);
            System.out.println("=" .repeat(80));
            
            // Обрабатываем каждый файл
            for (File specFile : specFiles) {
                try {
                    System.out.println("\n📋 Анализ файла: " + specFile.getName());
                    System.out.println("-".repeat(40));
                    
                    ApiSpec apiSpec = analyzeOpenApiSpec(specFile.getAbsolutePath());
                    allSpecs.add(apiSpec);
                    
                    // Выводим информацию о спецификации
                    printApiSpec(apiSpec);
                    
                } catch (Exception e) {
                    System.err.println("❌ Ошибка при анализе файла " + specFile.getName() + ": " + e.getMessage());
                }
            }
            
            // Генерируем готовые шаблоны запросов
            System.out.println("\n" + "=" .repeat(80));
            System.out.println("🚀 ГОТОВЫЕ ШАБЛОНЫ ЗАПРОСОВ ДЛЯ ТЕСТИРОВАНИЯ:");
            System.out.println("=" .repeat(80));
            
            generateRequestTemplates();
            
        } catch (Exception e) {
            System.err.println("❌ Критическая ошибка: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Анализ OpenAPI спецификации
     */
    private static ApiSpec analyzeOpenApiSpec(String specFilePath) throws Exception {
        JsonNode root = mapper.readTree(new File(specFilePath));
        ApiSpec apiSpec = new ApiSpec();
        apiSpec.fileName = new File(specFilePath).getName();
        
        // Базовая информация
        JsonNode info = root.path("info");
        if (!info.isMissingNode()) {
            apiSpec.title = info.path("title").asText("N/A");
            apiSpec.description = info.path("description").asText("N/A");
            apiSpec.version = info.path("version").asText("N/A");
        }
        
        // Servers
        JsonNode servers = root.path("servers");
        if (servers.isArray() && servers.size() > 0) {
            for (JsonNode server : servers) {
                apiSpec.baseUrls.add(server.path("url").asText());
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
                
                analyzePathItem(apiSpec, path, pathMethods);
            }
        }
        
        return apiSpec;
    }
    
    /**
     * Анализ конкретного пути (эндпоинта)
     */
    private static void analyzePathItem(ApiSpec apiSpec, String path, JsonNode pathMethods) {
        String[] httpMethods = {"get", "post", "put", "delete", "patch", "head", "options"};
        
        for (String method : httpMethods) {
            JsonNode operation = pathMethods.path(method);
            if (!operation.isMissingNode()) {
                ApiEndpoint endpoint = analyzeOperation(method.toUpperCase(), path, operation);
                apiSpec.endpoints.add(endpoint);
            }
        }
    }
    
    /**
     * Анализ операции (метода) эндпоинта
     */
    private static ApiEndpoint analyzeOperation(String httpMethod, String path, JsonNode operation) {
        ApiEndpoint endpoint = new ApiEndpoint();
        endpoint.method = httpMethod;
        endpoint.path = path;
        endpoint.operationId = operation.path("operationId").asText("N/A");
        endpoint.summary = operation.path("summary").asText("");
        endpoint.description = operation.path("description").asText("");
        
        // Parameters
        JsonNode parameters = operation.path("parameters");
        if (parameters.isArray() && parameters.size() > 0) {
            for (JsonNode param : parameters) {
                ApiParameter parameter = new ApiParameter();
                parameter.name = param.path("name").asText();
                parameter.in = param.path("in").asText();
                parameter.required = param.path("required").asBoolean(false);
                parameter.description = param.path("description").asText("");
                parameter.example = param.path("example").asText("");
                
                endpoint.parameters.add(parameter);
            }
        }
        
        // Request Body
        JsonNode requestBody = operation.path("requestBody");
        if (!requestBody.isMissingNode()) {
            endpoint.hasRequestBody = true;
            // Можно добавить анализ схемы тела запроса
        }
        
        return endpoint;
    }
    
    /**
     * Вывод информации о спецификации
     */
    private static void printApiSpec(ApiSpec apiSpec) {
        System.out.println("Название: " + apiSpec.title);
        System.out.println("Версия: " + apiSpec.version);
        System.out.println("Базовые URL: " + apiSpec.baseUrls);
        System.out.println("Эндпоинтов: " + apiSpec.endpoints.size());
        
        for (ApiEndpoint endpoint : apiSpec.endpoints) {
            System.out.println("\n" + endpoint.method + " " + endpoint.path);
            System.out.println("  OperationId: " + endpoint.operationId);
            if (!endpoint.summary.isEmpty()) {
                System.out.println("  Summary: " + endpoint.summary);
            }
            
            if (!endpoint.parameters.isEmpty()) {
                System.out.println("  Parameters:");
                for (ApiParameter param : endpoint.parameters) {
                    System.out.println("    - " + param.name + " (in: " + param.in + 
                                     ", required: " + param.required + ")");
                }
            }
        }
    }
    
    /**
     * Генерация готовых шаблонов запросов
     */
    private static void generateRequestTemplates() {
        for (ApiSpec apiSpec : allSpecs) {
            System.out.println("\n📁 Файл: " + apiSpec.fileName);
            System.out.println("API: " + apiSpec.title + " v" + apiSpec.version);
            System.out.println("-".repeat(60));
            
            for (ApiEndpoint endpoint : apiSpec.endpoints) {
                System.out.println("\n🔹 " + endpoint.method + " " + endpoint.path);
                System.out.println("OperationId: " + endpoint.operationId);
                
                // Генерируем полный URL
                String baseUrl = apiSpec.baseUrls.isEmpty() ? "https://api.example.com" : apiSpec.baseUrls.get(0);
                String fullUrl = baseUrl + endpoint.path;
                System.out.println("URL: " + fullUrl);
                
                // Заголовки
                System.out.println("Headers:");
                System.out.println("  Content-Type: application/json");
                
                // Обязательные заголовки из параметров
                for (ApiParameter param : endpoint.parameters) {
                    if ("header".equals(param.in) && param.required) {
                        String value = param.example.isEmpty() ? "<" + param.name + ">" : param.example;
                        System.out.println("  " + param.name + ": " + value);
                    }
                }
                
                // Path параметры
                boolean hasPathParams = false;
                for (ApiParameter param : endpoint.parameters) {
                    if ("path".equals(param.in)) {
                        if (!hasPathParams) {
                            System.out.println("Path Parameters:");
                            hasPathParams = true;
                        }
                        String value = param.example.isEmpty() ? "<" + param.name + ">" : param.example;
                        System.out.println("  " + param.name + ": " + value);
                    }
                }
                
                // Query параметры
                boolean hasQueryParams = false;
                for (ApiParameter param : endpoint.parameters) {
                    if ("query".equals(param.in) && param.required) {
                        if (!hasQueryParams) {
                            System.out.println("Query Parameters:");
                            hasQueryParams = true;
                        }
                        String value = param.example.isEmpty() ? "<" + param.name + ">" : param.example;
                        System.out.println("  " + param.name + ": " + value);
                    }
                }
                
                // Тело запроса для POST/PUT
                if (endpoint.hasRequestBody && ("POST".equals(endpoint.method) || "PUT".equals(endpoint.method))) {
                    System.out.println("Request Body:");
                    // Генерируем пример тела на основе availableBalance из примера в спецификации
                    if (endpoint.path.contains("rewards/balance") || endpoint.path.contains("rewards/redemption")) {
                        System.out.println("  {");
                        System.out.println("    \"redemptionReferenceNumber\": \"<UUID>\",");
                        System.out.println("    \"redemptionAmount\": <amount>, ");
                        System.out.println("    \"programId\": \"<program_id>\",");
                        System.out.println("    \"catalogId\": \"<catalog_id>\"");
                        System.out.println("  }");
                    } else {
                        System.out.println("  {");
                        System.out.println("    \"example_field\": \"example_value\"");
                        System.out.println("  }");
                    }
                }
                
                System.out.println("-".repeat(40));
            }
        }
        
        // Выводим инструкцию по использованию
        System.out.println("\n💡 ИНСТРУКЦИЯ ПО ИСПОЛЬЗОВАНИЮ:");
        System.out.println("=" .repeat(60));
        System.out.println("1. Скопируйте нужные шаблоны запросов");
        System.out.println("2. Замените следующие плейсхолдеры реальными значениями:");
        System.out.println("   - <UUID> → сгенерируйте UUID (например, с помощью uuidgen)");
        System.out.println("   - <amount> → сумма для списания (например, 50)");
        System.out.println("   - <program_id> → идентификатор программы из ответа balance API");
        System.out.println("   - <catalog_id> → идентификатор каталога из ответа balance API");
        System.out.println("   - Authorization заголовок → реальный Bearer token");
        System.out.println("   - Correlation-ID → уникальный UUID для каждого запроса");
        System.out.println("3. Используйте curl, Postman или другой HTTP клиент для отправки запросов");
    }
    
    // Классы для хранения структурированных данных
    
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
        String description;
        List<ApiParameter> parameters = new ArrayList<>();
        boolean hasRequestBody = false;
    }
    
    static class ApiParameter {
        String name;
        String in;
        boolean required;
        String description;
        String example;
    }
}
