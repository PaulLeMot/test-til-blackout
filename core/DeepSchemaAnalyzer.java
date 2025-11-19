package core;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class DeepSchemaAnalyzer {
    private final OpenAPI openAPI;
    private final List<Vulnerability> vulnerabilities;
    private final Set<String> analyzedPaths;

    // Регулярные выражения для поиска чувствительных данных
    private static final Pattern SENSITIVE_FIELD_PATTERN = Pattern.compile(
            "(password|token|secret|key|auth|credential|private|sensitive)",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern ID_FIELD_PATTERN = Pattern.compile(
            "(id|identifier|guid|uuid|account|user)",
            Pattern.CASE_INSENSITIVE
    );

    public DeepSchemaAnalyzer(OpenAPI openAPI) {
        this.openAPI = openAPI;
        this.vulnerabilities = new ArrayList<>();
        this.analyzedPaths = new HashSet<>();
    }

    public List<Vulnerability> analyze() {
        if (openAPI == null) {
            return vulnerabilities;
        }

        System.out.println("Запуск глубокого анализа схем OpenAPI...");

        try {
            analyzeSecuritySchemes();
            analyzeSchemas();
            analyzeParameters();
            analyzePaths();
            analyzeBusinessLogicFlows();
            analyzeDataRelationships();
        } catch (Exception e) {
            System.err.println("Ошибка при глубоком анализе: " + e.getMessage());
        }

        System.out.println("Глубокий анализ завершен. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Анализ схем безопасности
     */
    private void analyzeSecuritySchemes() {
        if (openAPI.getComponents() == null || openAPI.getComponents().getSecuritySchemes() == null) {
            addVulnerability(
                    "Отсутствуют схемы безопасности",
                    "API не определяет схемы аутентификации и авторизации",
                    Vulnerability.Severity.HIGH,
                    Vulnerability.Category.OWASP_API8_SM
            );
            return;
        }

        var securitySchemes = openAPI.getComponents().getSecuritySchemes();
        boolean hasOAuth = false;
        boolean hasApiKey = false;
        boolean hasBearer = false;

        for (var entry : securitySchemes.entrySet()) {
            var scheme = entry.getValue();
            if (scheme.getType() == null) continue;

            switch (scheme.getType().toString().toLowerCase()) {
                case "oauth2":
                    hasOAuth = true;
                    analyzeOAuthScheme(scheme, entry.getKey());
                    break;
                case "apikey":
                    hasApiKey = true;
                    analyzeApiKeyScheme(scheme, entry.getKey());
                    break;
                case "http":
                    if ("bearer".equalsIgnoreCase(scheme.getScheme())) {
                        hasBearer = true;
                    }
                    break;
            }
        }

        if (!hasOAuth && !hasApiKey && !hasBearer) {
            addVulnerability(
                    "Недостаточные схемы безопасности",
                    "API использует слабые или устаревшие схемы аутентификации",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API2_BROKEN_AUTH
            );
        }
    }

    private void analyzeOAuthScheme(io.swagger.v3.oas.models.security.SecurityScheme scheme, String name) {
        if (scheme.getFlows() == null) {
            addVulnerability(
                    "Неполная конфигурация OAuth2",
                    "Схема OAuth2 '" + name + "' не определяет потоки авторизации",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API2_BROKEN_AUTH
            );
            return;
        }

        // Проверка scope
        if (scheme.getFlows().getAuthorizationCode() != null) {
            var flow = scheme.getFlows().getAuthorizationCode();
            if (flow.getScopes() == null || flow.getScopes().isEmpty()) {
                addVulnerability(
                        "Отсутствуют scope в OAuth2",
                        "Схема OAuth2 '" + name + "' не определяет scope для контроля доступа",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH
                );
            }
        }
    }

    private void analyzeApiKeyScheme(io.swagger.v3.oas.models.security.SecurityScheme scheme, String name) {
        if (scheme.getIn() == null) {
            addVulnerability(
                    "Неопределенное местоположение API Key",
                    "Схема API Key '" + name + "' не определяет, где передается ключ",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        } else if ("query".equalsIgnoreCase(scheme.getIn().toString())) {
            addVulnerability(
                    "API Key в query параметрах",
                    "Ключ API передается в query параметрах, что может привести к его утечке в логах",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }
    }

    /**
     * Глубокий анализ схем данных
     */
    private void analyzeSchemas() {
        if (openAPI.getComponents() == null || openAPI.getComponents().getSchemas() == null) {
            return;
        }

        for (var entry : openAPI.getComponents().getSchemas().entrySet()) {
            analyzeSchema(entry.getKey(), entry.getValue(), new HashSet<>());
        }
    }

    private void analyzeSchema(String schemaName, Schema<?> schema, Set<String> visited) {
        if (visited.contains(schemaName)) {
            return; // Предотвращение циклических ссылок
        }
        visited.add(schemaName);

        if (schema.getProperties() != null) {
            for (var propEntry : schema.getProperties().entrySet()) {
                String propertyName = propEntry.getKey();
                Schema<?> propertySchema = (Schema<?>) propEntry.getValue();

                analyzeProperty(schemaName, propertyName, propertySchema);

                // Рекурсивный анализ вложенных схем
                if (propertySchema.get$ref() != null) {
                    String refSchemaName = extractSchemaName(propertySchema.get$ref());
                    if (refSchemaName != null && openAPI.getComponents().getSchemas() != null) {
                        Schema<?> refSchema = openAPI.getComponents().getSchemas().get(refSchemaName);
                        if (refSchema != null) {
                            analyzeSchema(refSchemaName, refSchema, visited);
                        }
                    }
                }
            }
        }

        // Анализ наследования (allOf, anyOf, oneOf)
        analyzeSchemaComposition(schemaName, schema, visited);
    }

    private void analyzeProperty(String schemaName, String propertyName, Schema<?> propertySchema) {
        // Поиск чувствительных полей
        if (SENSITIVE_FIELD_PATTERN.matcher(propertyName).find()) {
            if (propertySchema.getFormat() == null || !"password".equals(propertySchema.getFormat())) {
                addVulnerability(
                        "Чувствительное поле без маскирования",
                        "Поле '" + propertyName + "' в схеме '" + schemaName + "' содержит чувствительные данные, но не помечено как password",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API8_SM
                );
            }
        }

        // Поиск идентификаторов
        if (ID_FIELD_PATTERN.matcher(propertyName).find() && propertySchema.getType() != null) {
            String type = propertySchema.getType();
            if ("string".equals(type) && propertySchema.getFormat() == null) {
                addVulnerability(
                        "Идентификатор без формата",
                        "Поле идентификатора '" + propertyName + "' в схеме '" + schemaName + "' не имеет формата (uuid, etc)",
                        Vulnerability.Severity.LOW,
                        Vulnerability.Category.OWASP_API1_BOLA
                );
            }
        }

        // Проверка минимальных/максимальных ограничений
        if (propertySchema.getType() != null) {
            switch (propertySchema.getType()) {
                case "string":
                    if (propertySchema.getMinLength() == null && propertySchema.getMaxLength() == null) {
                        addVulnerability(
                                "Отсутствуют ограничения длины строки",
                                "Строковое поле '" + propertyName + "' в схеме '" + schemaName + "' не имеет ограничений длины",
                                Vulnerability.Severity.LOW,
                                Vulnerability.Category.OWASP_API8_SM
                        );
                    }
                    break;
                case "integer":
                case "number":
                    if (propertySchema.getMinimum() == null && propertySchema.getMaximum() == null) {
                        addVulnerability(
                                "Отсутствуют ограничения числового поля",
                                "Числовое поле '" + propertyName + "' в схеме '" + schemaName + "' не имеет минимальных/максимальных значений",
                                Vulnerability.Severity.LOW,
                                Vulnerability.Category.OWASP_API8_SM
                        );
                    }
                    break;
            }
        }
    }

    private void analyzeSchemaComposition(String schemaName, Schema<?> schema, Set<String> visited) {
        if (schema.getAllOf() != null) {
            for (Schema<?> subSchema : schema.getAllOf()) {
                if (subSchema.get$ref() != null) {
                    String refName = extractSchemaName(subSchema.get$ref());
                    if (refName != null && openAPI.getComponents().getSchemas() != null) {
                        Schema<?> refSchema = openAPI.getComponents().getSchemas().get(refName);
                        if (refSchema != null) {
                            analyzeSchema(refName, refSchema, visited);
                        }
                    }
                }
            }
        }
    }

    /**
     * Анализ параметров
     */
    private void analyzeParameters() {
        if (openAPI.getPaths() == null) return;

        for (var pathEntry : openAPI.getPaths().entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();

            for (Operation op : Arrays.asList(
                    pathItem.getGet(), pathItem.getPost(), pathItem.getPut(),
                    pathItem.getDelete(), pathItem.getPatch())) {

                if (op != null && op.getParameters() != null) {
                    for (Parameter param : op.getParameters()) {
                        analyzeParameter(path, op, param);
                    }
                }
            }
        }
    }

    private void analyzeParameter(String path, Operation operation, Parameter param) {
        if (param.getSchema() == null) return;

        // Проверка параметров пути
        if ("path".equals(param.getIn())) {
            if (param.getRequired() == null || !param.getRequired()) {
                addVulnerability(
                        "Необязательный path параметр",
                        "Path параметр '" + param.getName() + "' в '" + path + "' должен быть обязательным",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API8_SM
                );
            }
        }

        // Проверка query параметров
        if ("query".equals(param.getIn())) {
            Schema<?> schema = param.getSchema();
            if (schema.getType() != null && "array".equals(schema.getType())) {
                addVulnerability(
                        "Массив в query параметрах",
                        "Query параметр '" + param.getName() + "' в '" + path + "' имеет тип array, что может привести к инъекциям",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API8_SM
                );
            }
        }
    }

    /**
     * Анализ путей и их взаимосвязей
     */
    private void analyzePaths() {
        if (openAPI.getPaths() == null) return;

        Map<String, List<OperationInfo>> operationsByTag = new HashMap<>();

        for (var pathEntry : openAPI.getPaths().entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();

            analyzePathItem(path, pathItem, operationsByTag);
        }

        analyzeCrossEndpointRelationships(operationsByTag);
    }

    private void analyzePathItem(String path, PathItem pathItem, Map<String, List<OperationInfo>> operationsByTag) {
        analyzeOperation(path, "GET", pathItem.getGet(), operationsByTag);
        analyzeOperation(path, "POST", pathItem.getPost(), operationsByTag);
        analyzeOperation(path, "PUT", pathItem.getPut(), operationsByTag);
        analyzeOperation(path, "DELETE", pathItem.getDelete(), operationsByTag);
        analyzeOperation(path, "PATCH", pathItem.getPatch(), operationsByTag);
    }

    private void analyzeOperation(String path, String method, Operation operation,
                                  Map<String, List<OperationInfo>> operationsByTag) {
        if (operation == null) return;

        OperationInfo opInfo = new OperationInfo(path, method, operation);

        // Группировка по тегам для анализа бизнес-процессов
        if (operation.getTags() != null) {
            for (String tag : operation.getTags()) {
                operationsByTag.computeIfAbsent(tag, k -> new ArrayList<>()).add(opInfo);
            }
        }

        // Проверка операций с ID в пути
        if (path.contains("{") && path.contains("}")) {
            analyzeIdBasedOperation(path, method, operation);
        }
    }

    private void analyzeIdBasedOperation(String path, String method, Operation operation) {
        // Извлечение паттернов ID из пути
        Pattern idPattern = Pattern.compile("\\{([^}]*id[^}]*)\\}", Pattern.CASE_INSENSITIVE);
        Matcher matcher = idPattern.matcher(path);

        if (matcher.find()) {
            String idParam = matcher.group(1);

            // Проверка безопасности операций с ID
            if (!hasSecurityRequirement(operation)) {
                addVulnerability(
                        "Операция с ID без проверки авторизации",
                        method + " " + path + " работает с идентификаторами объектов без явных требований безопасности",
                        Vulnerability.Severity.HIGH,
                        Vulnerability.Category.OWASP_API1_BOLA
                );
            }

            // Проверка на массовое присвоение
            if ("PUT".equals(method) || "PATCH".equals(method)) {
                if (operation.getRequestBody() != null) {
                    analyzeMassAssignmentRisk(path, method, operation);
                }
            }
        }
    }

    private void analyzeMassAssignmentRisk(String path, String method, Operation operation) {
        addVulnerability(
                "Риск массового присвоения",
                method + " " + path + " может позволять массовое присвоение (mass assignment)",
                Vulnerability.Severity.MEDIUM,
                Vulnerability.Category.OWASP_API3_BOPLA
        );
    }

    /**
     * Анализ бизнес-логических потоков
     */
    private void analyzeBusinessLogicFlows() {
        // Анализ последовательностей операций (создание -> чтение -> обновление -> удаление)
        analyzeCRUDFlows();

        // Анализ финансовых транзакций
        analyzeFinancialFlows();

        // Анализ рабочих процессов
        analyzeWorkflowFlows();
    }

    private void analyzeCRUDFlows() {
        // Поиск стандартных CRUD операций и проверка их согласованности
        Map<String, CRUDOperations> resourceOperations = new HashMap<>();

        if (openAPI.getPaths() != null) {
            for (var pathEntry : openAPI.getPaths().entrySet()) {
                String path = pathEntry.getKey();
                PathItem pathItem = pathEntry.getValue();

                // Извлечение имени ресурса из пути
                String resourceName = extractResourceName(path);
                if (resourceName != null) {
                    CRUDOperations ops = resourceOperations.computeIfAbsent(resourceName, k -> new CRUDOperations());

                    if (pathItem.getPost() != null) ops.setCreate(true);
                    if (pathItem.getGet() != null) ops.setRead(true);
                    if (pathItem.getPut() != null || pathItem.getPatch() != null) ops.setUpdate(true);
                    if (pathItem.getDelete() != null) ops.setDelete(true);
                }
            }
        }

        // Проверка несогласованностей CRUD
        for (var entry : resourceOperations.entrySet()) {
            String resource = entry.getKey();
            CRUDOperations ops = entry.getValue();

            if (ops.hasCreate() && !ops.hasRead()) {
                addVulnerability(
                        "Несогласованность CRUD: создание без чтения",
                        "Ресурс '" + resource + "' позволяет создание, но не предоставляет операцию чтения",
                        Vulnerability.Severity.LOW,
                        Vulnerability.Category.OWASP_API9_INVENTORY
                );
            }

            if (ops.hasUpdate() && !ops.hasRead()) {
                addVulnerability(
                        "Несогласованность CRUD: обновление без чтения",
                        "Ресурс '" + resource + "' позволяет обновление, но не предоставляет операцию чтения",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API6_BUSINESS_FLOW
                );
            }
        }
    }

    private void analyzeFinancialFlows() {
        // Поиск финансовых операций
        List<OperationInfo> financialOps = findFinancialOperations();

        for (OperationInfo op : financialOps) {
            // Проверка дополнительной аутентификации для финансовых операций
            if (!hasStrongSecurity(op.operation)) {
                addVulnerability(
                        "Финансовая операция без усиленной безопасности",
                        op.method + " " + op.path + " - финансовая операция должна иметь MFA или дополнительные проверки",
                        Vulnerability.Severity.HIGH,
                        Vulnerability.Category.OWASP_API6_BUSINESS_FLOW
                );
            }
        }
    }

    private void analyzeWorkflowFlows() {
        // Анализ последовательностей операций, образующих рабочие процессы
        // Например: заявка -> одобрение -> выполнение
    }

    /**
     * Анализ взаимосвязей данных между эндпоинтами
     */
    private void analyzeDataRelationships() {
        // Поиск связей между ресурсами (например, account -> transactions)
        analyzeResourceRelationships();

        // Анализ прав доступа на основе связей данных
        analyzeDataAccessPatterns();
    }

    private void analyzeResourceRelationships() {
        if (openAPI.getComponents() == null || openAPI.getComponents().getSchemas() == null) {
            return;
        }

        // Построение графа связей между схемами
        Map<String, Set<String>> schemaRelationships = new HashMap<>();

        for (var entry : openAPI.getComponents().getSchemas().entrySet()) {
            String schemaName = entry.getKey();
            Schema<?> schema = entry.getValue();

            findSchemaReferences(schema, schemaName, schemaRelationships, new HashSet<>());
        }

        // Анализ связей на предмет уязвимостей доступа
        analyzeRelationshipAccessRisks(schemaRelationships);
    }

    private void findSchemaReferences(Schema<?> schema, String currentSchema,
                                      Map<String, Set<String>> relationships, Set<String> visited) {
        if (visited.contains(currentSchema)) return;
        visited.add(currentSchema);

        if (schema.getProperties() != null) {
            for (var propEntry : schema.getProperties().entrySet()) {
                Schema<?> propSchema = (Schema<?>) propEntry.getValue();

                if (propSchema.get$ref() != null) {
                    String refSchema = extractSchemaName(propSchema.get$ref());
                    if (refSchema != null) {
                        relationships.computeIfAbsent(currentSchema, k -> new HashSet<>()).add(refSchema);

                        // Рекурсивный поиск
                        if (openAPI.getComponents().getSchemas() != null) {
                            Schema<?> nestedSchema = openAPI.getComponents().getSchemas().get(refSchema);
                            if (nestedSchema != null) {
                                findSchemaReferences(nestedSchema, refSchema, relationships, visited);
                            }
                        }
                    }
                }
            }
        }
    }

    private void analyzeRelationshipAccessRisks(Map<String, Set<String>> relationships) {
        for (var entry : relationships.entrySet()) {
            String sourceSchema = entry.getKey();
            Set<String> relatedSchemas = entry.getValue();

            for (String targetSchema : relatedSchemas) {
                // Проверка, могут ли связанные схемы создавать риски горизонтального доступа
                if (isSensitiveSchema(sourceSchema) && isSensitiveSchema(targetSchema)) {
                    addVulnerability(
                            "Риск цепочки доступа к чувствительным данным",
                            "Связь между '" + sourceSchema + "' и '" + targetSchema + "' может позволить несанкционированный доступ через связанные объекты",
                            Vulnerability.Severity.MEDIUM,
                            Vulnerability.Category.OWASP_API1_BOLA
                    );
                }
            }
        }
    }

    /**
     * Анализ паттернов доступа к данным
     */
    private void analyzeDataAccessPatterns() {
        if (openAPI.getPaths() == null) return;

        // Анализ операций чтения/записи чувствительных данных
        for (var pathEntry : openAPI.getPaths().entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();

            analyzeDataAccessInPath(path, pathItem);
        }
    }

    private void analyzeDataAccessInPath(String path, PathItem pathItem) {
        // Анализ операций GET для потенциального раскрытия излишней информации
        if (pathItem.getGet() != null) {
            analyzeDataExposure(path, "GET", pathItem.getGet());
        }

        // Анализ операций POST/PUT для потенциальной перезаписи данных
        if (pathItem.getPost() != null) {
            analyzeDataModification(path, "POST", pathItem.getPost());
        }
        if (pathItem.getPut() != null) {
            analyzeDataModification(path, "PUT", pathItem.getPut());
        }
    }

    private void analyzeDataExposure(String path, String method, Operation operation) {
        // Проверка на раскрытие излишней информации в ответах
        if (operation.getResponses() != null) {
            var successResponse = operation.getResponses().get("200");
            if (successResponse != null && successResponse.getContent() != null) {
                // Проверяем, возвращаются ли чувствительные данные
                for (var mediaType : successResponse.getContent().values()) {
                    if (mediaType.getSchema() != null) {
                        checkSchemaForSensitiveDataExposure(path, method, mediaType.getSchema());
                    }
                }
            }
        }
    }

    private void analyzeDataModification(String path, String method, Operation operation) {
        // Проверка на возможность модификации чувствительных данных
        if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            for (var mediaType : operation.getRequestBody().getContent().values()) {
                if (mediaType.getSchema() != null) {
                    checkSchemaForSensitiveDataModification(path, method, mediaType.getSchema());
                }
            }
        }
    }

    private void checkSchemaForSensitiveDataExposure(String path, String method, Schema<?> schema) {
        // Проверка схемы на раскрытие чувствительных данных
        if (containsSensitiveFields(schema)) {
            addVulnerability(
                    "Раскрытие чувствительных данных",
                    method + " " + path + " возвращает чувствительные данные в ответе",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM
            );
        }
    }

    private void checkSchemaForSensitiveDataModification(String path, String method, Schema<?> schema) {
        // Проверка схемы на возможность модификации чувствительных данных
        if (containsSensitiveFields(schema)) {
            addVulnerability(
                    "Модификация чувствительных данных",
                    method + " " + path + " позволяет изменять чувствительные данные",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API3_BOPLA
            );
        }
    }

    private boolean containsSensitiveFields(Schema<?> schema) {
        // Рекурсивная проверка на наличие чувствительных полей в схеме
        if (schema.getProperties() != null) {
            for (var propEntry : schema.getProperties().entrySet()) {
                String propertyName = propEntry.getKey();
                if (SENSITIVE_FIELD_PATTERN.matcher(propertyName).find()) {
                    return true;
                }

                // Рекурсивная проверка вложенных свойств
                Schema<?> propertySchema = (Schema<?>) propEntry.getValue();
                if (containsSensitiveFields(propertySchema)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void analyzeCrossEndpointRelationships(Map<String, List<OperationInfo>> operationsByTag) {
        // Анализ отношений между эндпоинтами в рамках одного тега (бизнес-процесса)
        for (var entry : operationsByTag.entrySet()) {
            String tag = entry.getKey();
            List<OperationInfo> operations = entry.getValue();

            if (operations.size() > 1) {
                analyzeEndpointSequence(tag, operations);
            }
        }
    }

    private void analyzeEndpointSequence(String tag, List<OperationInfo> operations) {
        // Поиск последовательностей операций, которые должны выполняться в определенном порядке
        // Например: создание платежа -> подтверждение платежа -> выполнение платежа

        Map<String, List<OperationInfo>> operationsByResource = groupOperationsByResource(operations);

        for (var resourceEntry : operationsByResource.entrySet()) {
            List<OperationInfo> resourceOps = resourceEntry.getValue();
            analyzeResourceWorkflow(tag, resourceOps);
        }
    }

    private void analyzeResourceWorkflow(String tag, List<OperationInfo> operations) {
        // Проверка наличия необходимых операций в workflow
        boolean hasStateTransitions = operations.stream()
                .anyMatch(op -> op.path.contains("status") || op.path.contains("state") ||
                        (op.operation.getSummary() != null &&
                                op.operation.getSummary().toLowerCase().contains("status")));

        if (hasStateTransitions) {
            // Проверка безопасности переходов состояний
            boolean hasStateSecurity = operations.stream()
                    .anyMatch(op -> hasStrongSecurity(op.operation));

            if (!hasStateSecurity) {
                addVulnerability(
                        "Небезопасные переходы состояний",
                        "Workflow '" + tag + "' имеет операции изменения состояния без должной безопасности",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API6_BUSINESS_FLOW
                );
            }
        }
    }

    // Вспомогательные методы
    private boolean hasSecurityRequirement(Operation operation) {
        return operation.getSecurity() != null && !operation.getSecurity().isEmpty();
    }

    private boolean hasStrongSecurity(Operation operation) {
        if (operation.getSecurity() == null) return false;

        return operation.getSecurity().stream()
                .anyMatch(secReq -> secReq != null && !secReq.isEmpty());
    }

    private String extractSchemaName(String ref) {
        if (ref == null) return null;
        if (ref.startsWith("#/components/schemas/")) {
            return ref.substring("#/components/schemas/".length());
        }
        return null;
    }

    private String extractResourceName(String path) {
        // Извлечение имени ресурса из пути (например, /accounts/{id} -> accounts)
        String[] parts = path.split("/");
        for (String part : parts) {
            if (!part.isEmpty() && !part.startsWith("{") && !part.startsWith("$")) {
                return part;
            }
        }
        return null;
    }

    private List<OperationInfo> findFinancialOperations() {
        List<OperationInfo> financialOps = new ArrayList<>();

        if (openAPI.getPaths() != null) {
            for (var pathEntry : openAPI.getPaths().entrySet()) {
                String path = pathEntry.getKey().toLowerCase();
                PathItem pathItem = pathEntry.getValue();

                // Поиск финансовых операций по ключевым словам в пути
                if (path.contains("payment") || path.contains("transfer") || path.contains("transaction") ||
                        path.contains("balance") || path.contains("account") || path.contains("fund")) {

                    addOperationsFromPathItem(path, pathItem, financialOps);
                }
            }
        }

        return financialOps;
    }

    private void addOperationsFromPathItem(String path, PathItem pathItem, List<OperationInfo> operations) {
        if (pathItem.getGet() != null)
            operations.add(new OperationInfo(path, "GET", pathItem.getGet()));
        if (pathItem.getPost() != null)
            operations.add(new OperationInfo(path, "POST", pathItem.getPost()));
        if (pathItem.getPut() != null)
            operations.add(new OperationInfo(path, "PUT", pathItem.getPut()));
        if (pathItem.getDelete() != null)
            operations.add(new OperationInfo(path, "DELETE", pathItem.getDelete()));
        if (pathItem.getPatch() != null)
            operations.add(new OperationInfo(path, "PATCH", pathItem.getPatch()));
    }

    private Map<String, List<OperationInfo>> groupOperationsByResource(List<OperationInfo> operations) {
        Map<String, List<OperationInfo>> grouped = new HashMap<>();

        for (OperationInfo op : operations) {
            String resource = extractResourceName(op.path);
            if (resource != null) {
                grouped.computeIfAbsent(resource, k -> new ArrayList<>()).add(op);
            }
        }

        return grouped;
    }

    private boolean isSensitiveSchema(String schemaName) {
        return schemaName.toLowerCase().contains("user") ||
                schemaName.toLowerCase().contains("account") ||
                schemaName.toLowerCase().contains("payment") ||
                schemaName.toLowerCase().contains("transaction") ||
                schemaName.toLowerCase().contains("personal");
    }

    private void addVulnerability(String title, String description,
                                  Vulnerability.Severity severity, Vulnerability.Category category) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(category);
        vuln.setEvidence("Обнаружено при глубоком анализе схем OpenAPI");

        vulnerabilities.add(vuln);
    }

    // Вспомогательные классы
    private static class OperationInfo {
        String path;
        String method;
        Operation operation;

        OperationInfo(String path, String method, Operation operation) {
            this.path = path;
            this.method = method;
            this.operation = operation;
        }
    }

    private static class CRUDOperations {
        boolean create = false;
        boolean read = false;
        boolean update = false;
        boolean delete = false;

        boolean hasCreate() { return create; }
        boolean hasRead() { return read; }
        boolean hasUpdate() { return update; }
        boolean hasDelete() { return delete; }

        void setCreate(boolean create) { this.create = create; }
        void setRead(boolean read) { this.read = read; }
        void setUpdate(boolean update) { this.update = update; }
        void setDelete(boolean delete) { this.delete = delete; }
    }
}