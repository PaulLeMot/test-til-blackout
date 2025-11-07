package scanners.fuzzing;

import java.util.*;
import java.util.logging.Logger;

public class OpenApiParser {

    private static final Logger logger = Logger.getLogger(OpenApiParser.class.getName());

    @SuppressWarnings("unchecked")
    public List<ApiEndpoint> parseOpenApi(Object openApiObj) {
        List<ApiEndpoint> endpoints = new ArrayList<>();

        if (!(openApiObj instanceof Map)) {
            logger.warning("❌ OpenAPI object is not a Map");
            return endpoints;
        }

        try {
            Map<String, Object> openApi = (Map<String, Object>) openApiObj;
            Map<String, Object> paths = (Map<String, Object>) openApi.get("paths");

            if (paths == null) {
                logger.warning("❌ No 'paths' found in OpenAPI specification");
                return endpoints;
            }

            logger.info("📊 Found " + paths.size() + " paths in OpenAPI specification");

            for (Map.Entry<String, Object> pathEntry : paths.entrySet()) {
                String path = pathEntry.getKey();
                Map<String, Object> pathMethods = (Map<String, Object>) pathEntry.getValue();

                for (Map.Entry<String, Object> methodEntry : pathMethods.entrySet()) {
                    String methodName = methodEntry.getKey().toUpperCase();
                    Map<String, Object> operation = (Map<String, Object>) methodEntry.getValue();

                    try {
                        HttpMethod method = HttpMethod.valueOf(methodName);
                        List<ApiParameter> parameters = parseParameters(operation);

                        endpoints.add(new ApiEndpoint(path, method, parameters));

                        logger.fine("✅ Parsed endpoint: " + method + " " + path + " (" + parameters.size() + " parameters)");

                    } catch (IllegalArgumentException e) {
                        logger.warning("⚠️ Unknown HTTP method: " + methodName + " for path: " + path);
                    }
                }
            }

            logger.info("✅ Successfully parsed " + endpoints.size() + " API endpoints");

        } catch (Exception e) {
            logger.severe("❌ Error parsing OpenAPI specification: " + e.getMessage());
            e.printStackTrace();
        }

        return endpoints;
    }

    @SuppressWarnings("unchecked")
    private List<ApiParameter> parseParameters(Map<String, Object> operation) {
        List<ApiParameter> parameters = new ArrayList<>();

        try {
            List<Map<String, Object>> params = (List<Map<String, Object>>) operation.get("parameters");
            if (params == null) {
                return parameters;
            }

            for (Map<String, Object> param : params) {
                try {
                    String name = (String) param.get("name");
                    String in = (String) param.get("in");
                    boolean required = Boolean.TRUE.equals(param.get("required"));

                    String type = "string";
                    Map<String, Object> schema = (Map<String, Object>) param.get("schema");
                    if (schema != null) {
                        Object typeObj = schema.get("type");
                        if (typeObj != null) {
                            type = typeObj.toString();
                        }
                    }

                    ParameterLocation location = parseParameterLocation(in);
                    parameters.add(new ApiParameter(name, type, location, required));

                } catch (Exception e) {
                    logger.warning("⚠️ Error parsing parameter: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            logger.warning("⚠️ Error parsing parameters: " + e.getMessage());
        }

        return parameters;
    }

    private ParameterLocation parseParameterLocation(String location) {
        if (location == null) {
            return ParameterLocation.QUERY;
        }

        switch (location.toLowerCase()) {
            case "query": return ParameterLocation.QUERY;
            case "header": return ParameterLocation.HEADER;
            case "path": return ParameterLocation.PATH;
            case "body": return ParameterLocation.BODY;
            default: return ParameterLocation.QUERY;
        }
    }
}