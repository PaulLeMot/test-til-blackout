package core;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.media.MediaType;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class DeepSchemaAnalyzer {
    private final OpenAPI openAPI;
    private final List<Vulnerability> vulnerabilities;
    private final Set<String> analyzedPaths;

    // Регулярные выражения для поиска чувствительных данных
    private static final Pattern SENSITIVE_FIELD_PATTERN = Pattern.compile(
            "(password|token|secret|key|auth|credential|private|sensitive|admin|system|privilege|root|override|internal|config|setting)",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern ID_FIELD_PATTERN = Pattern.compile(
            "(id|identifier|guid|uuid|account|user|customer)",
            Pattern.CASE_INSENSITIVE
    );

    // Поля, которые могут указывать на массовое присвоение
    private static final Set<String> RISKY_FIELDS = Set.of(
            "role", "permission", "privilege", "access_level", "is_admin", "admin",
            "system", "internal", "config", "settings", "flags", "status",
            "balance", "amount", "limit", "overdraft", "premium", "feature"
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
                    Vulnerability.Category.OWASP_API8_SM,
                    "Проверка components.securitySchemes в OpenAPI спецификации: отсутствует\n\n" +
                            "Без определения схем безопасности невозможно гарантировать:\n" +
                            "- Аутентификацию пользователей\n" +
                            "- Авторизацию запросов\n" +
                            "- Защиту от несанкционированного доступа"
            );
            return;
        }

        var securitySchemes = openAPI.getComponents().getSecuritySchemes();
        StringBuilder evidence = new StringBuilder();
        evidence.append("Обнаружены схемы безопасности:\n");

        for (var entry : securitySchemes.entrySet()) {
            var scheme = entry.getValue();
            evidence.append("- ").append(entry.getKey()).append(": ").append(scheme.getType()).append("\n");
        }

        // Проверка использования security в операциях
        boolean hasGlobalSecurity = openAPI.getSecurity() != null && !openAPI.getSecurity().isEmpty();
        evidence.append("\nГлобальная безопасность: ").append(hasGlobalSecurity ? "настроена" : "отсутствует").append("\n");

        if (!hasGlobalSecurity) {
            addVulnerability(
                    "Отсутствует глобальная безопасность",
                    "OpenAPI спецификация не определяет глобальные требования безопасности",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API8_SM,
                    evidence.toString()
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
            return;
        }
        visited.add(schemaName);

        if (schema.getProperties() != null) {
            for (var propEntry : schema.getProperties().entrySet()) {
                String propertyName = propEntry.getKey();
                Schema<?> propertySchema = (Schema<?>) propEntry.getValue();

                analyzeProperty(schemaName, propertyName, propertySchema);

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

        analyzeSchemaComposition(schemaName, schema, visited);
    }

    private void analyzeProperty(String schemaName, String propertyName, Schema<?> propertySchema) {
        // Поиск чувствительных полей
        if (SENSITIVE_FIELD_PATTERN.matcher(propertyName).find()) {
            if (propertySchema.getFormat() == null || !"password".equals(propertySchema.getFormat())) {
                addVulnerability(
                        "Чувствительное поле без маскирования",
                        "Поле '" + propertyName + "' в схеме '" + schemaName + "' содержит чувствительные данные",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API8_SM,
                        "Схема: " + schemaName + "\n" +
                                "Поле: " + propertyName + "\n" +
                                "Тип: " + propertySchema.getType() + "\n" +
                                "Формат: " + propertySchema.getFormat() + "\n\n" +
                                "Рекомендация: установить формат 'password' для маскирования ввода"
                );
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

            // Анализируем каждую операцию с указанием метода
            if (pathItem.getGet() != null) {
                analyzeOperationParameters(path, "GET", pathItem.getGet());
                analyzeRequestBody(path, "GET", pathItem.getGet());
            }
            if (pathItem.getPost() != null) {
                analyzeOperationParameters(path, "POST", pathItem.getPost());
                analyzeRequestBody(path, "POST", pathItem.getPost());
            }
            if (pathItem.getPut() != null) {
                analyzeOperationParameters(path, "PUT", pathItem.getPut());
                analyzeRequestBody(path, "PUT", pathItem.getPut());
            }
            if (pathItem.getDelete() != null) {
                analyzeOperationParameters(path, "DELETE", pathItem.getDelete());
                analyzeRequestBody(path, "DELETE", pathItem.getDelete());
            }
            if (pathItem.getPatch() != null) {
                analyzeOperationParameters(path, "PATCH", pathItem.getPatch());
                analyzeRequestBody(path, "PATCH", pathItem.getPatch());
            }
        }
    }

    private void analyzeOperationParameters(String path, String method, Operation operation) {
        if (operation == null || operation.getParameters() == null) return;

        for (Parameter param : operation.getParameters()) {
            analyzeParameter(path, method, operation, param);
        }
    }

    private void analyzeRequestBody(String path, String method, Operation operation) {
        if (operation == null || operation.getRequestBody() == null) return;

        RequestBody requestBody = operation.getRequestBody();

        if (requestBody.getContent() != null) {
            for (MediaType mediaType : requestBody.getContent().values()) {
                if (mediaType.getSchema() != null) {
                    analyzeRequestSchema(path, method, mediaType.getSchema());
                }
            }
        }
    }

    private void analyzeRequestSchema(String path, String method, Schema<?> schema) {
        // Анализ схемы запроса на риск массового присвоения
        List<String> riskyFields = findRiskyFieldsInSchema(schema);

        if (!riskyFields.isEmpty()) {
            String evidence = buildMassAssignmentEvidence(path, method, schema, riskyFields);

            addVulnerability(
                    "Риск массового присвоения в " + method + " " + path,
                    "Обнаружены потенциально опасные поля, которые могут быть изменены клиентом",
                    Vulnerability.Severity.HIGH,
                    Vulnerability.Category.OWASP_API3_BOPLA,
                    evidence
            );
        }
    }

    private List<String> findRiskyFieldsInSchema(Schema<?> schema) {
        List<String> riskyFields = new ArrayList<>();

        if (schema.getProperties() != null) {
            for (String fieldName : schema.getProperties().keySet()) {
                if (isRiskyField(fieldName)) {
                    riskyFields.add(fieldName);
                }
            }
        }

        // Рекурсивная проверка вложенных схем
        if (schema.getProperties() != null) {
            for (var propEntry : schema.getProperties().entrySet()) {
                Schema<?> propSchema = (Schema<?>) propEntry.getValue();
                if (propSchema.getProperties() != null) {
                    riskyFields.addAll(findRiskyFieldsInSchema(propSchema));
                }
            }
        }

        return riskyFields;
    }

    private boolean isRiskyField(String fieldName) {
        String lowerFieldName = fieldName.toLowerCase();

        // Проверка по ключевым словам
        for (String risky : RISKY_FIELDS) {
            if (lowerFieldName.contains(risky.toLowerCase())) {
                return true;
            }
        }

        // Проверка по паттернам
        return SENSITIVE_FIELD_PATTERN.matcher(fieldName).find() ||
                fieldName.toLowerCase().contains("role") ||
                fieldName.toLowerCase().contains("permission") ||
                fieldName.toLowerCase().contains("access") ||
                fieldName.toLowerCase().contains("privilege") ||
                fieldName.toLowerCase().contains("admin") ||
                fieldName.toLowerCase().contains("system");
    }

    private String buildMassAssignmentEvidence(String path, String method, Schema<?> schema, List<String> riskyFields) {
        StringBuilder evidence = new StringBuilder();
        evidence.append("Эндпоинт: ").append(method).append(" ").append(path).append("\n\n");

        evidence.append("Обнаружены потенциально опасные поля:\n");
        for (String field : riskyFields) {
            evidence.append("• ").append(field).append("\n");
        }

        evidence.append("\nСхема запроса: ").append(schema.getClass().getSimpleName()).append("\n");

        if (schema.getRequired() != null && !schema.getRequired().isEmpty()) {
            evidence.append("Обязательные поля: ").append(String.join(", ", schema.getRequired())).append("\n");
        }

        evidence.append("\nРиск: Клиент может изменить поля, влияющие на:\n");
        evidence.append("- Уровень привилегий (role, permission)\n");
        evidence.append("- Системные настройки (system, config)\n");
        evidence.append("- Финансовые лимиты (balance, limit)\n");
        evidence.append("- Флаги функциональности (premium, feature)\n");

        // Пример уязвимого запроса
        evidence.append("\nПример потенциально уязвимого запроса:\n");
        evidence.append(method).append(" ").append(path).append("\n");
        evidence.append("Content-Type: application/json\n");
        evidence.append("{\n");

        for (int i = 0; i < Math.min(riskyFields.size(), 5); i++) {
            String field = riskyFields.get(i);
            evidence.append("  \"").append(field).append("\": \"злонамеренное_значение\"");
            if (i < Math.min(riskyFields.size(), 5) - 1) {
                evidence.append(",");
            }
            evidence.append("\n");
        }
        if (riskyFields.size() > 5) {
            evidence.append("  ... и еще ").append(riskyFields.size() - 5).append(" полей\n");
        }
        evidence.append("}");

        return evidence.toString();
    }

    private void analyzeParameter(String path, String method, Operation operation, Parameter param) {
        if (param.getSchema() == null) return;

        // Проверка параметров пути
        if ("path".equals(param.getIn())) {
            if (param.getRequired() == null || !param.getRequired()) {
                addVulnerability(
                        "Необязательный path параметр",
                        "Path параметр должен быть обязательным",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API8_SM,
                        "Эндпоинт: " + method + " " + path + "\n" +
                                "Параметр: " + param.getName() + "\n" +
                                "Тип: " + param.getIn() + "\n" +
                                "Обязательный: " + param.getRequired() + "\n\n" +
                                "Path параметры должны быть обязательными для корректной маршрутизации"
                );
            }
        }

        // Проверка query параметров на инъекции
        if ("query".equals(param.getIn())) {
            Schema<?> schema = param.getSchema();
            if (schema.getType() != null && "array".equals(schema.getType())) {
                addVulnerability(
                        "Массив в query параметрах",
                        "Query параметр типа array может привести к инъекциям",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API8_SM,
                        "Эндпоинт: " + method + " " + path + "\n" +
                                "Параметр: " + param.getName() + "\n" +
                                "Тип: array\n\n" +
                                "Риск: параметры массива в query могут быть использованы для инъекций"
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
        // Теперь передаем метод явно для каждой операции
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

        if (operation.getTags() != null) {
            for (String tag : operation.getTags()) {
                operationsByTag.computeIfAbsent(tag, k -> new ArrayList<>()).add(opInfo);
            }
        }

        // Проверка операций с ID в пути
        if (path.contains("{") && path.contains("}")) {
            analyzeIdBasedOperation(path, method, operation);
        }

        // Проверка безопасности операций
        analyzeOperationSecurity(path, method, operation);
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
                        method + " " + path + " работает с идентификаторами объектов",
                        Vulnerability.Severity.HIGH,
                        Vulnerability.Category.OWASP_API1_BOLA,
                        "Эндпоинт: " + method + " " + path + "\n" +
                                "ID параметр: " + idParam + "\n" +
                                "Требования безопасности: отсутствуют\n\n" +
                                "Риск: Broken Object Level Authorization (BOLA)\n" +
                                "Атакующий может подменить ID для доступа к чужим данным"
                );
            }
        }
    }

    private void analyzeOperationSecurity(String path, String method, Operation operation) {
        if (!hasSecurityRequirement(operation)) {
            addVulnerability(
                    "Операция без требований безопасности",
                    method + " " + path + " не имеет настроек безопасности",
                    Vulnerability.Severity.MEDIUM,
                    Vulnerability.Category.OWASP_API2_BROKEN_AUTH,
                    "Эндпоинт: " + method + " " + path + "\n" +
                            "Описание: " + (operation.getSummary() != null ? operation.getSummary() : "не указано") + "\n\n" +
                            "Риск: отсутствие аутентификации и авторизации\n" +
                            "Рекомендация: добавить security requirements в операцию"
            );
        }
    }

    /**
     * Анализ бизнес-логических потоков
     */
    private void analyzeBusinessLogicFlows() {
        analyzeCRUDFlows();
        analyzeFinancialFlows();
    }

    private void analyzeCRUDFlows() {
        Map<String, CRUDOperations> resourceOperations = new HashMap<>();

        if (openAPI.getPaths() != null) {
            for (var pathEntry : openAPI.getPaths().entrySet()) {
                String path = pathEntry.getKey();
                PathItem pathItem = pathEntry.getValue();

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
                        "Ресурс позволяет создание, но не предоставляет операцию чтения",
                        Vulnerability.Severity.LOW,
                        Vulnerability.Category.OWASP_API9_INVENTORY,
                        "Ресурс: " + resource + "\n" +
                                "Операции: CREATE=" + ops.hasCreate() + ", READ=" + ops.hasRead() +
                                ", UPDATE=" + ops.hasUpdate() + ", DELETE=" + ops.hasDelete() + "\n\n" +
                                "Несогласованность: можно создавать объекты, но нельзя их читать\n" +
                                "Это может указывать на неполную реализацию API"
                );
            }

            if (ops.hasUpdate() && !ops.hasRead()) {
                addVulnerability(
                        "Несогласованность CRUD: обновление без чтения",
                        "Ресурс позволяет обновление, но не предоставляет операцию чтения",
                        Vulnerability.Severity.MEDIUM,
                        Vulnerability.Category.OWASP_API6_BUSINESS_FLOW,
                        "Ресурс: " + resource + "\n" +
                                "Операции: CREATE=" + ops.hasCreate() + ", READ=" + ops.hasRead() +
                                ", UPDATE=" + ops.hasUpdate() + ", DELETE=" + ops.hasDelete() + "\n\n" +
                                "Риск: обновление данных без возможности их просмотра\n" +
                                "Может привести к ошибкам бизнес-логики"
                );
            }
        }
    }

    private void analyzeFinancialFlows() {
        List<OperationInfo> financialOps = findFinancialOperations();

        for (OperationInfo op : financialOps) {
            if (!hasStrongSecurity(op.operation)) {
                addVulnerability(
                        "Финансовая операция без усиленной безопасности",
                        op.method + " " + op.path + " - финансовая операция",
                        Vulnerability.Severity.HIGH,
                        Vulnerability.Category.OWASP_API6_BUSINESS_FLOW,
                        "Эндпоинт: " + op.method + " " + op.path + "\n" +
                                "Тип: финансовая операция\n" +
                                "Требования безопасности: " + (hasSecurityRequirement(op.operation) ? "базовые" : "отсутствуют") + "\n\n" +
                                "Риск: финансовые операции должны иметь усиленную безопасность\n" +
                                "Рекомендация: MFA, лимиты, аудит транзакций"
                );
            }
        }
    }

    /**
     * Анализ взаимосвязей данных между эндпоинтами
     */
    private void analyzeDataRelationships() {
        analyzeResourceRelationships();
        analyzeDataAccessPatterns();
    }

    private void analyzeResourceRelationships() {
        if (openAPI.getComponents() == null || openAPI.getComponents().getSchemas() == null) {
            return;
        }

        Map<String, Set<String>> schemaRelationships = new HashMap<>();

        for (var entry : openAPI.getComponents().getSchemas().entrySet()) {
            String schemaName = entry.getKey();
            Schema<?> schema = entry.getValue();

            findSchemaReferences(schema, schemaName, schemaRelationships, new HashSet<>());
        }

        analyzeRelationshipAccessRisks(schemaRelationships);
    }

    private void analyzeDataAccessPatterns() {
        if (openAPI.getPaths() == null) return;

        for (var pathEntry : openAPI.getPaths().entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();

            analyzeDataAccessInPath(path, pathItem);
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
                if (isSensitiveSchema(sourceSchema) && isSensitiveSchema(targetSchema)) {
                    addVulnerability(
                            "Риск цепочки доступа к чувствительным данным",
                            "Связь между схемами может позволить несанкционированный доступ",
                            Vulnerability.Severity.MEDIUM,
                            Vulnerability.Category.OWASP_API1_BOLA,
                            "Схема источника: " + sourceSchema + "\n" +
                                    "Связанная схема: " + targetSchema + "\n\n" +
                                    "Риск: через связи между схемами можно получить доступ к чувствительным данным\n" +
                                    "Пример: доступ к транзакциям через связь с аккаунтом"
                    );
                }
            }
        }
    }

    private void analyzeSchemaComposition(String schemaName, Schema<?> schema, Set<String> visited) {
        // Базовая реализация - можно расширить для анализа allOf, anyOf, oneOf
    }

    private void analyzeCrossEndpointRelationships(Map<String, List<OperationInfo>> operationsByTag) {
        // Базовая реализация анализа кросс-эндпоинтных связей
    }

    private void analyzeDataAccessInPath(String path, PathItem pathItem) {
        // Базовая реализация анализа доступа к данным в пути
    }

    private boolean isSensitiveSchema(String schemaName) {
        return schemaName.toLowerCase().contains("user") ||
                schemaName.toLowerCase().contains("account") ||
                schemaName.toLowerCase().contains("payment") ||
                schemaName.toLowerCase().contains("transaction") ||
                schemaName.toLowerCase().contains("personal");
    }

    private void addVulnerability(String title, String description,
                                  Vulnerability.Severity severity, Vulnerability.Category category,
                                  String evidence) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(category);
        vuln.setEvidence(evidence);

        // Специфические рекомендации в зависимости от категории
        List<String> recommendations = new ArrayList<>();

        switch (category) {
            case OWASP_API3_BOPLA:
                recommendations.addAll(Arrays.asList(
                        "Реализуйте whitelist для полей, которые могут быть установлены клиентом",
                        "Используйте DTO (Data Transfer Objects) с явным указанием разрешенных полей",
                        "Включите защиту от mass assignment в фреймворке",
                        "Разделите поля на пользовательские и системные",
                        "Валидируйте все входящие поля на сервере",
                        "Используйте схемы валидации для всех входящих данных"
                ));
                break;
            case OWASP_API1_BOLA:
                recommendations.addAll(Arrays.asList(
                        "Реализуйте проверки авторизации на уровне объектов",
                        "Убедитесь, что пользователи могут access только свои данные",
                        "Используйте модель 'Deny by default'",
                        "Добавьте middleware для проверки прав доступа",
                        "Залогируйте все попытки доступа к чужим ресурсам"
                ));
                break;
            case OWASP_API2_BROKEN_AUTH:
                recommendations.addAll(Arrays.asList(
                        "Усильте механизмы аутентификации",
                        "Внедрите ограничение попыток входа",
                        "Реализуйте многофакторную аутентификацию",
                        "Используйте безопасное хранение токенов",
                        "Регулярно обновляйте секретные ключи"
                ));
                break;
            default:
                recommendations.addAll(Arrays.asList(
                        "Проверьте и исправьте выявленную уязвимость безопасности",
                        "Проведите код-ревью соответствующего функционала",
                        "Обновите документацию по безопасности",
                        "Протестируйте исправление в тестовой среде"
                ));
        }

        vuln.setRecommendations(recommendations);
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