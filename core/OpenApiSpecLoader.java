package core;

import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OpenApiSpecLoader {

    private final OpenAPI openAPI;

    public OpenApiSpecLoader(String specUrl) {
        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setResolveFully(true);

        SwaggerParseResult result = new OpenAPIV3Parser().readLocation(specUrl, null, options);
        if (result.getMessages() != null && !result.getMessages().isEmpty()) {
            System.err.println("OpenAPI parse warnings: " + result.getMessages());
        }

        this.openAPI = result.getOpenAPI();
        if (this.openAPI == null) {
            throw new RuntimeException("Failed to parse OpenAPI spec from: " + specUrl);
        }
    }

    public OpenAPI getOpenAPI() {
        return openAPI;
    }

    /**
     * Извлекает все эндпоинты из OpenAPI спецификации
     */
    public List<ApiEndpoint> extractEndpoints() {
        List<ApiEndpoint> endpoints = new ArrayList<>();

        if (openAPI == null || openAPI.getPaths() == null) {
            return endpoints;
        }

        for (String path : openAPI.getPaths().keySet()) {
            PathItem pathItem = openAPI.getPaths().get(path);

            // Обрабатываем каждый HTTP метод
            extractOperationsFromPathItem(path, pathItem, endpoints);
        }

        System.out.println("✅ Extracted " + endpoints.size() + " endpoints from OpenAPI spec");
        return endpoints;
    }

    private void extractOperationsFromPathItem(String path, PathItem pathItem, List<ApiEndpoint> endpoints) {
        if (pathItem.getGet() != null) {
            endpoints.add(createEndpoint(path, "GET", pathItem.getGet()));
        }
        if (pathItem.getPost() != null) {
            endpoints.add(createEndpoint(path, "POST", pathItem.getPost()));
        }
        if (pathItem.getPut() != null) {
            endpoints.add(createEndpoint(path, "PUT", pathItem.getPut()));
        }
        if (pathItem.getDelete() != null) {
            endpoints.add(createEndpoint(path, "DELETE", pathItem.getDelete()));
        }
        if (pathItem.getPatch() != null) {
            endpoints.add(createEndpoint(path, "PATCH", pathItem.getPatch()));
        }
        if (pathItem.getHead() != null) {
            endpoints.add(createEndpoint(path, "HEAD", pathItem.getHead()));
        }
        if (pathItem.getOptions() != null) {
            endpoints.add(createEndpoint(path, "OPTIONS", pathItem.getOptions()));
        }
    }

    private ApiEndpoint createEndpoint(String path, String method, Operation operation) {
        ApiEndpoint endpoint = new ApiEndpoint();
        endpoint.setPath(path);
        endpoint.setMethod(method);
        endpoint.setSummary(operation.getSummary());
        endpoint.setDescription(operation.getDescription());

        if (operation.getTags() != null) {
            endpoint.setTags(operation.getTags());
        }

        // Извлекаем параметры
        if (operation.getParameters() != null) {
            List<core.Parameter> parameters = new ArrayList<>();
            for (Parameter swaggerParam : operation.getParameters()) {
                core.Parameter param = new core.Parameter();
                param.setName(swaggerParam.getName());
                param.setIn(swaggerParam.getIn());
                param.setRequired(swaggerParam.getRequired() != null ? swaggerParam.getRequired() : false);
                param.setDescription(swaggerParam.getDescription());
                parameters.add(param);
            }
            endpoint.setParameters(parameters);
        }

        // Извлекаем responses
        if (operation.getResponses() != null) {
            Map<String, core.Response> responses = new HashMap<>();
            for (Map.Entry<String, ApiResponse> responseEntry : operation.getResponses().entrySet()) {
                core.Response response = new core.Response();
                response.setCode(responseEntry.getKey());
                response.setDescription(responseEntry.getValue().getDescription());
                responses.put(responseEntry.getKey(), response);
            }
            endpoint.setResponses(responses);
        }

        return endpoint;
    }

    /**
     * Получает базовый URL из серверов, указанных в спецификации
     */
    public String getBaseUrl() {
        if (openAPI.getServers() != null && !openAPI.getServers().isEmpty()) {
            return openAPI.getServers().get(0).getUrl();
        }
        return null;
    }
}