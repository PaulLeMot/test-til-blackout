package core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.util.*;

/**
 * Сборщик эндпоинтов из спецификаций и реальных тестов
 */
public class ApiEndpointCollector {
    private static ObjectMapper mapper = new ObjectMapper();

    public static List<TestedEndpoint> collectAllEndpoints(String clientId, String clientSecret) {
        List<TestedEndpoint> endpoints = new ArrayList<>();

        try {
            // 1. Собираем эндпоинты из спецификаций
            endpoints.addAll(collectFromSpecifications());

            // 2. Собираем эндпоинты из реальных тестов ApiTester
            endpoints.addAll(collectFromApiTester(clientId, clientSecret));

            System.out.println("✅ Собрано всего эндпоинтов: " + endpoints.size());

        } catch (Exception e) {
            System.err.println("❌ Ошибка при сборе эндпоинтов: " + e.getMessage());
        }

        return endpoints;
    }

    /**
     * Сбор эндпоинтов из одного файла спецификации
     */
    public static List<TestedEndpoint> collectFromSpecificationFile(File specFile) {
        List<TestedEndpoint> endpoints = new ArrayList<>();

        try {
            JsonNode root = mapper.readTree(specFile);
            JsonNode paths = root.path("paths");

            if (paths.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> pathFields = paths.fields();
                while (pathFields.hasNext()) {
                    Map.Entry<String, JsonNode> pathEntry = pathFields.next();
                    String path = pathEntry.getKey();
                    JsonNode pathMethods = pathEntry.getValue();

                    // Обрабатываем методы для этого пути
                    processPathMethods(endpoints, path, pathMethods, "Local: " + specFile.getName());
                }
            }

            System.out.println("✅ Обработан файл " + specFile.getName() + " - " + endpoints.size() + " эндпоинтов");
        } catch (Exception e) {
            System.err.println("❌ Ошибка при обработке файла " + specFile.getName() + ": " + e.getMessage());
            throw new RuntimeException("Ошибка при обработке файла спецификации", e);
        }

        return endpoints;
    }

    /**
     * Сбор эндпоинтов из OpenAPI спецификаций
     */
    private static List<TestedEndpoint> collectFromSpecifications() throws Exception {
        List<TestedEndpoint> endpoints = new ArrayList<>();
        File specsDir = new File("Specifications");
        File[] specFiles = specsDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".json"));

        if (specFiles == null) return endpoints;

        for (File specFile : specFiles) {
            try {
                JsonNode root = mapper.readTree(specFile);
                JsonNode paths = root.path("paths");

                if (paths.isObject()) {
                    Iterator<Map.Entry<String, JsonNode>> pathFields = paths.fields();
                    while (pathFields.hasNext()) {
                        Map.Entry<String, JsonNode> pathEntry = pathFields.next();
                        String path = pathEntry.getKey();
                        JsonNode pathMethods = pathEntry.getValue();

                        // Обрабатываем методы для этого пути
                        processPathMethods(endpoints, path, pathMethods, specFile.getName());
                    }
                }
            } catch (Exception e) {
                System.err.println("❌ Ошибка при обработке " + specFile.getName() + ": " + e.getMessage());
            }
        }

        return endpoints;
    }

    /**
     * Сбор эндпоинтов из реальных тестов ApiTester
     */
    private static List<TestedEndpoint> collectFromApiTester(String clientId, String clientSecret) {
        List<TestedEndpoint> endpoints = new ArrayList<>();

        try {
            // Запускаем ApiTester и получаем реальные результаты
            System.out.println("🚀 Запуск ApiTester для сбора реальных эндпоинтов...");

            // Создаем экземпляр ApiTester с переданными учетными данными
            ApiTester tester = new ApiTester(clientId, clientSecret);
            List<ApiTester.TestedApiCall> testResults = tester.executeFullTestSuite();

            // Конвертируем результаты ApiTester в TestedEndpoint
            for (ApiTester.TestedApiCall testCall : testResults) {
                TestedEndpoint endpoint = new TestedEndpoint();
                endpoint.setMethod(testCall.getMethod());
                endpoint.setPath(testCall.getPath());
                endpoint.setSource("ApiTester - Real Test");
                endpoint.setStatusCode(testCall.getStatusCode());
                endpoint.setResponseBody(testCall.getResponseBody());
                endpoint.setRequestBody(testCall.getRequestBody());
                endpoint.setTested(true);
                endpoint.setResponseTime(testCall.getResponseTime());

                // Добавляем параметры из запроса
                if (testCall.getRequestParameters() != null) {
                    List<EndpointParameter> parameters = new ArrayList<>();
                    for (Map.Entry<String, String> param : testCall.getRequestParameters().entrySet()) {
                        EndpointParameter endpointParam = new EndpointParameter();
                        endpointParam.setName(param.getKey());
                        endpointParam.setValue(param.getValue());
                        // Определяем тип параметра на основе имени и пути
                        endpointParam.setIn(determineParameterLocation(param.getKey(), testCall.getPath()));
                        parameters.add(endpointParam);
                    }
                    endpoint.setParameters(parameters);
                }

                endpoints.add(endpoint);

                System.out.println("📊 Собран эндпоинт: " + testCall.getMethod() + " " + testCall.getPath() +
                        " → " + testCall.getStatusCode());
            }

            System.out.println("✅ Собрано реальных тестов из ApiTester: " + testResults.size());

        } catch (Exception e) {
            System.err.println("❌ Ошибка при сборе данных из ApiTester: " + e.getMessage());
            e.printStackTrace();
        }

        return endpoints;
    }

    /**
     * Определяет местоположение параметра (path, query, header, body)
     */
    private static String determineParameterLocation(String paramName, String path) {
        // Если параметр в пути URL
        if (path.contains("{" + paramName + "}")) {
            return "path";
        }

        // Если параметр похож на заголовок
        if (paramName.toLowerCase().startsWith("x-") ||
                paramName.equalsIgnoreCase("authorization") ||
                paramName.equalsIgnoreCase("content-type") ||
                paramName.equalsIgnoreCase("accept")) {
            return "header";
        }

        // По умолчанию считаем query параметром
        return "query";
    }

    private static void processPathMethods(List<TestedEndpoint> endpoints, String path,
                                           JsonNode pathMethods, String source) {
        String[] httpMethods = {"get", "post", "put", "delete", "patch", "head", "options"};

        for (String method : httpMethods) {
            JsonNode operation = pathMethods.path(method);
            if (!operation.isMissingNode()) {
                TestedEndpoint endpoint = new TestedEndpoint();
                endpoint.setMethod(method.toUpperCase());
                endpoint.setPath(path);
                endpoint.setSource("Specification: " + source);
                endpoint.setOperationId(operation.path("operationId").asText("N/A"));
                endpoint.setSummary(operation.path("summary").asText(""));
                endpoint.setDescription(operation.path("description").asText(""));
                endpoint.setTested(false); // Из спецификации - еще не протестирован

                // Собираем параметры из спецификации
                List<EndpointParameter> parameters = new ArrayList<>();
                JsonNode paramsNode = operation.path("parameters");
                if (paramsNode.isArray()) {
                    for (JsonNode param : paramsNode) {
                        EndpointParameter parameter = new EndpointParameter();
                        parameter.setName(param.path("name").asText());
                        parameter.setIn(param.path("in").asText("query"));
                        parameter.setRequired(param.path("required").asBoolean(false));
                        parameter.setType(param.path("schema").path("type").asText("string"));
                        parameter.setDescription(param.path("description").asText(""));
                        parameters.add(parameter);
                    }
                }
                endpoint.setParameters(parameters);

                endpoints.add(endpoint);
            }
        }
    }

    /**
     * Конвертирует TestedApiCall в TestedEndpoint
     */
    private static TestedEndpoint convertToTestedEndpoint(ApiTester.TestedApiCall testCall) {
        TestedEndpoint endpoint = new TestedEndpoint();
        endpoint.setMethod(testCall.getMethod());
        endpoint.setPath(testCall.getPath());
        endpoint.setSource("ApiTester - Dynamic Test");
        endpoint.setStatusCode(testCall.getStatusCode());
        endpoint.setResponseBody(testCall.getResponseBody());
        endpoint.setRequestBody(testCall.getRequestBody());
        endpoint.setTested(true);
        endpoint.setResponseTime(testCall.getResponseTime());

        // Добавляем параметры из запроса
        if (testCall.getRequestParameters() != null) {
            List<EndpointParameter> parameters = new ArrayList<>();
            for (Map.Entry<String, String> param : testCall.getRequestParameters().entrySet()) {
                EndpointParameter endpointParam = new EndpointParameter();
                endpointParam.setName(param.getKey());
                endpointParam.setValue(param.getValue());
                endpointParam.setIn(determineParameterLocation(param.getKey(), testCall.getPath()));
                parameters.add(endpointParam);
            }
            endpoint.setParameters(parameters);
        }

        return endpoint;
    }
}