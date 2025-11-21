package core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.util.*;

/**
 * Улучшенный парсер OpenAPI спецификаций
 */
public class OpenApiSpecParser {
    
    private static final ObjectMapper mapper = new ObjectMapper();
    
    /**
     * Загружает все спецификации из папки Specifications
     */
    public static List<ApiSpec> parseAllSpecs() throws Exception {
        List<ApiSpec> specs = new ArrayList<>();
        File specsDir = new File("Specifications");
        
        if (!specsDir.exists() || !specsDir.isDirectory()) {
            System.err.println("❌ Папка Specifications не найдена");
            return specs;
        }
        
        File[] specFiles = specsDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".json"));
        
        if (specFiles == null || specFiles.length == 0) {
            System.err.println("❌ В папке Specifications не найдено JSON файлов");
            return specs;
        }
        
        System.out.println("🔍 Загрузка спецификаций из папки Specifications...");
        System.out.println("📁 Найдено файлов: " + specFiles.length);
        
        for (File specFile : specFiles) {
            try {
                ApiSpec spec = parseSpecification(specFile);
                if (spec != null) {
                    specs.add(spec);
                    System.out.println("✅ Загружено: " + spec.title + " (" + spec.endpoints.size() + " эндпоинтов)");
                }
            } catch (Exception e) {
                System.err.println("❌ Ошибка при загрузке " + specFile.getName() + ": " + e.getMessage());
            }
        }
        
        return specs;
    }
    
    /**
     * Парсит одну спецификацию
     */
    public static ApiSpec parseSpecification(File specFile) throws Exception {
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
        if (servers.isArray()) {
            for (JsonNode server : servers) {
                spec.baseUrls.add(server.path("url").asText());
            }
        }
        
        // Components - предзагружаем параметры и схемы
        Map<String, JsonNode> components = loadComponents(root.path("components"));
        
        // Paths - эндпоинты
        JsonNode paths = root.path("paths");
        if (paths.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> pathFields = paths.fields();
            while (pathFields.hasNext()) {
                Map.Entry<String, JsonNode> pathEntry = pathFields.next();
                String path = pathEntry.getKey();
                JsonNode pathMethods = pathEntry.getValue();
                
                processPathItem(spec, path, pathMethods, components);
            }
        }
        
        return spec;
    }
    
    /**
     * Загружает компоненты (parameters, schemas, etc.)
     */
    private static Map<String, JsonNode> loadComponents(JsonNode components) {
        Map<String, JsonNode> componentMap = new HashMap<>();
        
        if (components.isMissingNode()) {
            return componentMap;
        }
        
        // Parameters
        JsonNode parameters = components.path("parameters");
        if (parameters.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> paramFields = parameters.fields();
            while (paramFields.hasNext()) {
                Map.Entry<String, JsonNode> paramEntry = paramFields.next();
                componentMap.put("#/components/parameters/" + paramEntry.getKey(), paramEntry.getValue());
            }
        }
        
        // Schemas
        JsonNode schemas = components.path("schemas");
        if (schemas.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> schemaFields = schemas.fields();
            while (schemaFields.hasNext()) {
                Map.Entry<String, JsonNode> schemaEntry = schemaFields.next();
                componentMap.put("#/components/schemas/" + schemaEntry.getKey(), schemaEntry.getValue());
            }
        }
        
        return componentMap;
    }
    
    /**
     * Обрабатывает путь и все его методы
     */
    private static void processPathItem(ApiSpec spec, String path, JsonNode pathMethods, Map<String, JsonNode> components) {
        // Все возможные HTTP методы
        String[] httpMethods = {"get", "post", "put", "delete", "patch", "head", "options", "trace"};
        
        for (String method : httpMethods) {
            JsonNode operation = pathMethods.path(method);
            if (!operation.isMissingNode()) {
                ApiEndpoint endpoint = processOperation(method.toUpperCase(), path, operation, components);
                if (endpoint != null) {
                    spec.endpoints.add(endpoint);
                }
            }
        }
    }
    
    /**
     * Обрабатывает операцию (метод)
     */
    private static ApiEndpoint processOperation(String httpMethod, String path, JsonNode operation, Map<String, JsonNode> components) {
        ApiEndpoint endpoint = new ApiEndpoint();
        endpoint.method = httpMethod;
        endpoint.path = path;
        endpoint.operationId = operation.path("operationId").asText("N/A");
        endpoint.summary = operation.path("summary").asText("");
        endpoint.description = operation.path("description").asText("");
        
        // Parameters - обрабатываем как прямые, так и ссылки $ref
        JsonNode parameters = operation.path("parameters");
        if (parameters.isArray()) {
            for (JsonNode param : parameters) {
                ApiParameter parameter = processParameter(param, components);
                if (parameter != null) {
                    endpoint.parameters.add(parameter);
                }
            }
        }
        
        // Request Body
        JsonNode requestBody = operation.path("requestBody");
        if (!requestBody.isMissingNode()) {
            endpoint.hasRequestBody = true;
            endpoint.requestBodySchema = extractRequestBodySchema(requestBody, components);
        }
        
        // Tags
        JsonNode tags = operation.path("tags");
        if (tags.isArray()) {
            for (JsonNode tag : tags) {
                endpoint.tags.add(tag.asText());
            }
        }
        
        return endpoint;
    }
    
    /**
     * Обрабатывает параметр (прямой или через $ref)
     */
    private static ApiParameter processParameter(JsonNode paramNode, Map<String, JsonNode> components) {
        ApiParameter parameter = new ApiParameter();
        
        // Проверяем $ref ссылку
        if (paramNode.has("$ref")) {
            String ref = paramNode.get("$ref").asText();
            JsonNode resolvedParam = components.get(ref);
            if (resolvedParam != null) {
                // Рекурсивно обрабатываем resolved параметр
                return processParameter(resolvedParam, components);
            } else {
                System.err.println("⚠️  Не удалось разрешить $ref: " + ref);
                return null;
            }
        }
        
        // Прямой параметр
        parameter.name = paramNode.path("name").asText();
        parameter.in = paramNode.path("in").asText();
        parameter.required = paramNode.path("required").asBoolean(false);
        parameter.description = paramNode.path("description").asText("");
        
        // Example
        if (paramNode.has("example")) {
            parameter.example = paramNode.path("example").asText("");
        }
        
        // Schema
        if (paramNode.has("schema")) {
            parameter.schema = paramNode.path("schema");
        }
        
        return parameter;
    }
    
    /**
     * Извлекает схему тела запроса
     */
    private static JsonNode extractRequestBodySchema(JsonNode requestBody, Map<String, JsonNode> components) {
        JsonNode content = requestBody.path("content");
        if (!content.isMissingNode() && content.has("application/json")) {
            JsonNode jsonContent = content.path("application/json");
            JsonNode schema = jsonContent.path("schema");
            
            // Обрабатываем $ref в схеме
            if (schema.has("$ref")) {
                String ref = schema.get("$ref").asText();
                return components.getOrDefault(ref, schema);
            }
            
            return schema;
        }
        return null;
    }
    
    // Классы данных
    public static class ApiSpec {
        public String fileName;
        public String title;
        public String description;
        public String version;
        public List<String> baseUrls = new ArrayList<>();
        public List<ApiEndpoint> endpoints = new ArrayList<>();
    }
    
    public static class ApiEndpoint {
        public String method;
        public String path;
        public String operationId;
        public String summary;
        public String description;
        public List<ApiParameter> parameters = new ArrayList<>();
        public List<String> tags = new ArrayList<>();
        public boolean hasRequestBody = false;
        public JsonNode requestBodySchema;
    }
    
    public static class ApiParameter {
        public String name;
        public String in; // path, query, header, cookie
        public boolean required;
        public String description;
        public String example;
        public JsonNode schema;
    }
}
