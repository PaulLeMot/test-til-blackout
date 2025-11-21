package core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import java.io.File;

/**
 * Парсер OpenAPI спецификаций для извлечения полной информации о контрактах API
 */
public class OpenApiSpecParser {
    
    private static ObjectMapper mapper = new ObjectMapper();
    
    /**
     * Основной метод для получения всех спецификаций
     */
    public static List<ApiSpec> parseAllSpecs() {
        List<ApiSpec> allSpecs = new ArrayList<>();
        
        try {
            System.out.println("🔍 Загрузка спецификаций из папки Specifications...");
            
            File specsDir = new File("Specifications");
            File[] specFiles = specsDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".json"));
            
            if (specFiles == null || specFiles.length == 0) {
                System.err.println("❌ В папке Specifications не найдено .json файлов");
                return allSpecs;
            }
            
            System.out.println("📁 Найдено файлов: " + specFiles.length);
            
            for (File specFile : specFiles) {
                try {
                    ApiSpec apiSpec = analyzeOpenApiSpec(specFile.getAbsolutePath());
                    allSpecs.add(apiSpec);
                    System.out.println("✅ Загружено: " + apiSpec.title + " (" + apiSpec.endpoints.size() + " эндпоинтов)");
                    
                } catch (Exception e) {
                    System.err.println("❌ Ошибка при анализе файла " + specFile.getName() + ": " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            System.err.println("❌ Критическая ошибка: " + e.getMessage());
            e.printStackTrace();
        }
        
        return allSpecs;
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
        
        // Security schemes
        JsonNode components = root.path("components");
        if (components.isObject()) {
            JsonNode securitySchemes = components.path("securitySchemes");
            if (securitySchemes.isObject()) {
                apiSpec.securitySchemes = new HashMap<>();
                Iterator<Map.Entry<String, JsonNode>> schemeFields = securitySchemes.fields();
                while (schemeFields.hasNext()) {
                    Map.Entry<String, JsonNode> schemeEntry = schemeFields.next();
                    String schemeName = schemeEntry.getKey();
                    JsonNode scheme = schemeEntry.getValue();
                    
                    SecurityScheme securityScheme = new SecurityScheme();
                    securityScheme.type = scheme.path("type").asText();
                    securityScheme.scheme = scheme.path("scheme").asText();
                    securityScheme.in = scheme.path("in").asText();
                    securityScheme.bearerFormat = scheme.path("bearerFormat").asText();
                    
                    apiSpec.securitySchemes.put(schemeName, securityScheme);
                }
            }
        }
        
        // Global security
        JsonNode globalSecurity = root.path("security");
        if (globalSecurity.isArray() && globalSecurity.size() > 0) {
            apiSpec.globalSecurity = new ArrayList<>();
            for (JsonNode securityReq : globalSecurity) {
                if (securityReq.isObject()) {
                    Iterator<String> securityNames = securityReq.fieldNames();
                    while (securityNames.hasNext()) {
                        apiSpec.globalSecurity.add(securityNames.next());
                    }
                }
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
                ApiParameter parameter = analyzeParameter(param);
                endpoint.parameters.add(parameter);
            }
        }
        
        // Request Body
        JsonNode requestBody = operation.path("requestBody");
        if (!requestBody.isMissingNode()) {
            endpoint.hasRequestBody = true;
            
            // Request body schema
            JsonNode content = requestBody.path("content");
            if (content.isObject()) {
                JsonNode jsonContent = content.path("application/json");
                if (!jsonContent.isMissingNode()) {
                    JsonNode schema = jsonContent.path("schema");
                    if (!schema.isMissingNode()) {
                        endpoint.requestBodySchema = schema;
                    }
                }
            }
            
            // Required flag for request body
            endpoint.requestBodyRequired = requestBody.path("required").asBoolean(false);
        }
        
        // Response schemas
        JsonNode responses = operation.path("responses");
        if (responses.isObject()) {
            endpoint.responseSchemas = new HashMap<>();
            Iterator<Map.Entry<String, JsonNode>> responseFields = responses.fields();
            while (responseFields.hasNext()) {
                Map.Entry<String, JsonNode> responseEntry = responseFields.next();
                String statusCode = responseEntry.getKey();
                JsonNode response = responseEntry.getValue();
                
                ResponseSchema responseSchema = new ResponseSchema();
                responseSchema.description = response.path("description").asText("");
                
                // Response content schema
                JsonNode content = response.path("content");
                if (content.isObject()) {
                    JsonNode jsonContent = content.path("application/json");
                    if (!jsonContent.isMissingNode()) {
                        JsonNode schema = jsonContent.path("schema");
                        if (!schema.isMissingNode()) {
                            responseSchema.schema = schema;
                        }
                    }
                }
                
                endpoint.responseSchemas.put(statusCode, responseSchema);
            }
        }
        
        // Security requirements for this operation
        JsonNode security = operation.path("security");
        if (security.isArray() && security.size() > 0) {
            endpoint.securityRequirements = new ArrayList<>();
            for (JsonNode securityReq : security) {
                if (securityReq.isObject()) {
                    Iterator<String> securityNames = securityReq.fieldNames();
                    while (securityNames.hasNext()) {
                        endpoint.securityRequirements.add(securityNames.next());
                    }
                }
            }
        }
        
        return endpoint;
    }
    
    /**
     * Анализ параметра
     */
    private static ApiParameter analyzeParameter(JsonNode param) {
        ApiParameter parameter = new ApiParameter();
        parameter.name = param.path("name").asText();
        parameter.in = param.path("in").asText();
        parameter.required = param.path("required").asBoolean(false);
        parameter.description = param.path("description").asText("");
        parameter.example = param.path("example").asText("");
        
        // Parameter schema
        JsonNode schema = param.path("schema");
        if (!schema.isMissingNode()) {
            parameter.schema = schema;
            parameter.type = schema.path("type").asText("");
            parameter.format = schema.path("format").asText("");
            parameter.pattern = schema.path("pattern").asText("");
            
            // Enum values
            JsonNode enumValues = schema.path("enum");
            if (enumValues.isArray()) {
                parameter.enumValues = new ArrayList<>();
                for (JsonNode enumValue : enumValues) {
                    parameter.enumValues.add(enumValue.asText());
                }
            }
            
            // Min/Max constraints
            parameter.minimum = schema.path("minimum").asDouble(Double.NaN);
            parameter.maximum = schema.path("maximum").asDouble(Double.NaN);
            parameter.minLength = schema.path("minLength").asInt(-1);
            parameter.maxLength = schema.path("maxLength").asInt(-1);
        }
        
        return parameter;
    }
    
    // Классы для хранения структурированных данных
    
    public static class ApiSpec {
        public String fileName;
        public String title;
        public String description;
        public String version;
        public List<String> baseUrls = new ArrayList<>();
        public Map<String, SecurityScheme> securitySchemes;
        public List<String> globalSecurity;
        public List<ApiEndpoint> endpoints = new ArrayList<>();
    }
    
    public static class ApiEndpoint {
        public String method;
        public String path;
        public String operationId;
        public String summary;
        public String description;
        public List<ApiParameter> parameters = new ArrayList<>();
        public boolean hasRequestBody = false;
        public boolean requestBodyRequired = false;
        public JsonNode requestBodySchema;
        public Map<String, ResponseSchema> responseSchemas;
        public List<String> securityRequirements;
    }
    
    public static class ApiParameter {
        public String name;
        public String in;
        public boolean required;
        public String description;
        public String example;
        public JsonNode schema;
        public String type;
        public String format;
        public String pattern;
        public List<String> enumValues;
        public double minimum = Double.NaN;
        public double maximum = Double.NaN;
        public int minLength = -1;
        public int maxLength = -1;
    }
    
    public static class ResponseSchema {
        public String description;
        public JsonNode schema;
    }
    
    public static class SecurityScheme {
        public String type;
        public String scheme;
        public String in;
        public String bearerFormat;
    }
    
    /**
     * Утилитарный метод для быстрого тестирования парсера
     */
    public static void main(String[] args) {
        List<ApiSpec> specs = parseAllSpecs();
        
        System.out.println("\n" + "=" .repeat(80));
        System.out.println("📊 СВОДКА ПО СПЕЦИФИКАЦИЯМ:");
        System.out.println("=" .repeat(80));
        
        for (ApiSpec spec : specs) {
            System.out.println("\n📁 " + spec.fileName);
            System.out.println("API: " + spec.title + " v" + spec.version);
            System.out.println("Эндпоинтов: " + spec.endpoints.size());
            System.out.println("Базовые URL: " + spec.baseUrls);
            
            if (spec.securitySchemes != null) {
                System.out.println("Схемы безопасности: " + spec.securitySchemes.keySet());
            }
            
            // Детальная информация по эндпоинтам
            for (ApiEndpoint endpoint : spec.endpoints) {
                System.out.println("\n  " + endpoint.method + " " + endpoint.path);
                System.out.println("    OperationId: " + endpoint.operationId);
                System.out.println("    Параметров: " + endpoint.parameters.size());
                System.out.println("    Request Body: " + (endpoint.hasRequestBody ? "Да" : "Нет"));
                
                if (endpoint.responseSchemas != null) {
                    System.out.println("    Response schemas: " + endpoint.responseSchemas.keySet());
                }
                
                // Детали параметров
                for (ApiParameter param : endpoint.parameters) {
                    System.out.println("      - " + param.name + " (" + param.in + 
                                     ", required: " + param.required + 
                                     ", type: " + param.type + ")");
                }
            }
        }
        
        System.out.println("\n🎯 Всего спецификаций: " + specs.size());
        int totalEndpoints = specs.stream().mapToInt(s -> s.endpoints.size()).sum();
        System.out.println("🎯 Всего эндпоинтов: " + totalEndpoints);
    }
}
