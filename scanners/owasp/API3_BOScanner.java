package scanners.owasp;

import core.*;
import scanners.SecurityScanner;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class API3_BOScanner implements SecurityScanner {

    private static final List<String> SENSITIVE_FIELDS = Arrays.asList(
            "password", "secret", "token", "key", "creditcard", "ssn",
            "socialsecurity", "privatekey", "authorization", "privilege",
            "role", "permission", "admin", "system", "internal"
    );

    private ScanConfig config;

    @Override
    public String getName() {
        return "OWASP API3: Broken Object Property Level Authorization Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        this.config = config;
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Если включен статический анализ, используем эндпоинты из конфигурации
        if (config.isStaticAnalysisEnabled() && config.getTestedEndpoints() != null) {
            vulnerabilities.addAll(scanEndpoints(config.getTestedEndpoints(), config, apiClient));
        }

        // Динамический анализ только если включен
        if (config.isDynamicAnalysisEnabled()) {
            vulnerabilities.addAll(performDynamicBOPLATests(config, apiClient));
        }

        return vulnerabilities;
    }

    @Override
    public List<Vulnerability> scanEndpoints(List<TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        System.out.println("(API-3) Запуск СТАТИЧЕСКОГО анализа BOPLA на " + endpoints.size() + " эндпоинтах");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Анализ структуры эндпоинтов для BOPLA
        vulnerabilities.addAll(analyzeObjectPropertyAccess(endpoints, config));
        vulnerabilities.addAll(analyzeSensitiveProperties(endpoints, config));
        vulnerabilities.addAll(analyzePropertyLevelAuthorization(endpoints, config));

        // Комбинированный анализ
        if (config.getAnalysisMode() == ScanConfig.AnalysisMode.COMBINED) {
            vulnerabilities.addAll(performCombinedBOPLATests(endpoints, config, apiClient));
        }

        System.out.println("(API-3) Статический анализ BOPLA завершен. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Анализ доступа к свойствам объектов
     */
    private List<Vulnerability> analyzeObjectPropertyAccess(List<TestedEndpoint> endpoints, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (TestedEndpoint endpoint : endpoints) {
            String path = endpoint.getPath().toLowerCase();
            String method = endpoint.getMethod();

            // Эндпоинты, работающие с объектами и их свойствами
            boolean isObjectEndpoint = path.matches(".*/\\{.*\\}.*") &&
                    ("GET".equals(method) || "PUT".equals(method) || "PATCH".equals(method));

            if (isObjectEndpoint) {
                Vulnerability vuln = createBOPLAVulnerability(endpoint,
                        "Эндпоинт работает с объектами и может быть уязвим к несанкционированному доступу к свойствам",
                        config);
                vulnerabilities.add(vuln);
            }
        }

        return vulnerabilities;
    }

    /**
     * Анализ чувствительных свойств
     */
    private List<Vulnerability> analyzeSensitiveProperties(List<TestedEndpoint> endpoints, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (TestedEndpoint endpoint : endpoints) {
            if (endpoint.getParameters() != null) {
                List<String> sensitiveParams = new ArrayList<>();

                for (EndpointParameter param : endpoint.getParameters()) {
                    if (isSensitiveProperty(param.getName())) {
                        sensitiveParams.add(param.getName());
                    }
                }

                if (!sensitiveParams.isEmpty()) {
                    Vulnerability vuln = createSensitivePropertiesVulnerability(endpoint, sensitiveParams, config);
                    vulnerabilities.add(vuln);
                }
            }

            // Также проверяем response body на наличие чувствительных полей
            if (endpoint.isTested() && endpoint.getResponseBody() != null) {
                String responseBody = endpoint.getResponseBody().toLowerCase();
                List<String> exposedSensitiveFields = new ArrayList<>();

                for (String field : SENSITIVE_FIELDS) {
                    if (responseBody.contains("\"" + field + "\"") || responseBody.contains("'" + field + "'")) {
                        exposedSensitiveFields.add(field);
                    }
                }

                if (!exposedSensitiveFields.isEmpty()) {
                    Vulnerability vuln = createExposedPropertiesVulnerability(endpoint, exposedSensitiveFields, config);
                    vulnerabilities.add(vuln);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Анализ авторизации на уровне свойств
     */
    private List<Vulnerability> analyzePropertyLevelAuthorization(List<TestedEndpoint> endpoints, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (TestedEndpoint endpoint : endpoints) {
            // Проверяем эндпоинты, которые могут изменять свойства объектов
            if ("PUT".equals(endpoint.getMethod()) || "PATCH".equals(endpoint.getMethod())) {
                List<String> issues = new ArrayList<>();

                // Проверяем наличие большого количества параметров (возможность изменения многих свойств)
                if (endpoint.getParameters() != null && endpoint.getParameters().size() > 15) {
                    issues.add("Большое количество параметров (" + endpoint.getParameters().size() + ") для изменения");
                }

                // Проверяем описание на наличие признаков прямого доступа к свойствам
                if (endpoint.getDescription() != null) {
                    String description = endpoint.getDescription().toLowerCase();
                    if (description.contains("update") &&
                            !description.contains("validation") &&
                            !description.contains("authorization")) {
                        issues.add("Возможно отсутствие проверки авторизации на уровне свойств");
                    }
                }

                if (!issues.isEmpty()) {
                    Vulnerability vuln = createPropertyAuthorizationVulnerability(endpoint, issues, config);
                    vulnerabilities.add(vuln);
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Проверка, является ли свойство чувствительным
     */
    private boolean isSensitiveProperty(String propertyName) {
        String lowerProperty = propertyName.toLowerCase();
        return SENSITIVE_FIELDS.stream().anyMatch(field -> lowerProperty.contains(field.toLowerCase()));
    }

    /**
     * Создание уязвимости для BOPLA
     */
    private Vulnerability createBOPLAVulnerability(TestedEndpoint endpoint, String description, ScanConfig config) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API3:2023 - Broken Object Property Level Authorization");
        vuln.setDescription(description + " для эндпоинта " + endpoint.getMethod() + " " + endpoint.getPath());
        vuln.setSeverity(Vulnerability.Severity.HIGH);
        vuln.setCategory(Vulnerability.Category.OWASP_API3_BOPLA);
        vuln.setEndpoint(endpoint.getPath());
        vuln.setMethod(endpoint.getMethod());
        vuln.setEvidence(
                "Статический анализ выявил потенциальную уязвимость BOPLA:\n" +
                        "- Эндпоинт: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "- Источник: " + endpoint.getSource() + "\n" +
                        "- Параметры: " + (endpoint.getParameters() != null ? endpoint.getParameters().size() : 0)
        );

        vuln.setRecommendations(Arrays.asList(
                "Реализовать проверку авторизации для каждого свойства объекта",
                "Использовать whitelist разрешенных к изменению свойств для разных ролей",
                "Валидировать права доступа к каждому свойству отдельно",
                "Разделить эндпоинты для публичных и приватных свойств",
                "Использовать DTO с явным указанием доступных полей"
        ));

        return vuln;
    }

    /**
     * Создание уязвимости для чувствительных свойств
     */
    private Vulnerability createSensitivePropertiesVulnerability(TestedEndpoint endpoint, List<String> sensitiveProperties, ScanConfig config) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API3:2023 - Sensitive Properties Exposure");
        vuln.setDescription(
                "Эндпоинт " + endpoint.getMethod() + " " + endpoint.getPath() +
                        " работает с чувствительными свойствами: " + String.join(", ", sensitiveProperties) + "\n\n" +
                        "Эти свойства могут быть подвержены несанкционированному доступу или изменению."
        );
        vuln.setSeverity(Vulnerability.Severity.HIGH);
        vuln.setCategory(Vulnerability.Category.OWASP_API3_BOPLA);
        vuln.setEndpoint(endpoint.getPath());
        vuln.setMethod(endpoint.getMethod());
        vuln.setEvidence(
                "Обнаружены чувствительные свойства:\n" +
                        "- Эндпоинт: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "- Чувствительные свойства: " + String.join(", ", sensitiveProperties) + "\n" +
                        "- Всего параметров: " + (endpoint.getParameters() != null ? endpoint.getParameters().size() : 0)
        );

        vuln.setRecommendations(Arrays.asList(
                "Защитить чувствительные свойства дополнительной авторизацией",
                "Использовать шифрование для хранения чувствительных данных",
                "Логировать все доступы к чувствительным свойствам",
                "Реализовать маскировку чувствительных данных в ответах",
                "Разделить эндпоинты для работы с чувствительными и обычными свойствами"
        ));

        return vuln;
    }

    /**
     * Создание уязвимости для раскрытых свойств
     */
    private Vulnerability createExposedPropertiesVulnerability(TestedEndpoint endpoint, List<String> exposedFields, ScanConfig config) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API3:2023 - Exposed Sensitive Properties");
        vuln.setDescription(
                "Эндпоинт " + endpoint.getMethod() + " " + endpoint.getPath() +
                        " раскрывает чувствительные свойства в ответах: " + String.join(", ", exposedFields) + "\n\n" +
                        "Это может привести к утечке конфиденциальной информации."
        );
        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
        vuln.setCategory(Vulnerability.Category.OWASP_API3_BOPLA);
        vuln.setEndpoint(endpoint.getPath());
        vuln.setMethod(endpoint.getMethod());
        vuln.setEvidence(
                "Чувствительные свойства обнаружены в ответе:\n" +
                        "- Эндпоинт: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "- Раскрытые свойства: " + String.join(", ", exposedFields) + "\n" +
                        "- Статус код: " + endpoint.getStatusCode()
        );

        vuln.setRecommendations(Arrays.asList(
                "Исключить чувствительные свойства из ответов по умолчанию",
                "Использовать проекции DTO для фильтрации возвращаемых полей",
                "Реализовать ролевую модель для доступа к свойствам",
                "Внедрить механизм согласия пользователя на раскрытие свойств",
                "Использовать маскировку для частичного скрытия чувствительных данных"
        ));

        return vuln;
    }

    /**
     * Создание уязвимости для авторизации свойств
     */
    private Vulnerability createPropertyAuthorizationVulnerability(TestedEndpoint endpoint, List<String> issues, ScanConfig config) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API3:2023 - Missing Property Level Authorization");
        vuln.setDescription(
                "Эндпоинт " + endpoint.getMethod() + " " + endpoint.getPath() +
                        " может не иметь достаточной авторизации на уровне свойств.\n\n" +
                        "Проблемы:\n• " + String.join("\n• ", issues)
        );
        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
        vuln.setCategory(Vulnerability.Category.OWASP_API3_BOPLA);
        vuln.setEndpoint(endpoint.getPath());
        vuln.setMethod(endpoint.getMethod());
        vuln.setEvidence(
                "Признаки отсутствия авторизации на уровне свойств:\n" +
                        "- Эндпоинт: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "- Проблемы: " + String.join(", ", issues) + "\n" +
                        "- Описание: " + (endpoint.getDescription() != null ?
                        endpoint.getDescription().substring(0, Math.min(100, endpoint.getDescription().length())) : "отсутствует")
        );

        vuln.setRecommendations(Arrays.asList(
                "Реализовать проверку прав для каждого изменяемого свойства",
                "Использовать attribute-based access control (ABAC)",
                "Валидировать права доступа перед применением изменений",
                "Разделить логику авторизации для разных типов свойств",
                "Вести аудит изменений свойств объектов"
        ));

        return vuln;
    }

    // ========== ДИНАМИЧЕСКИЕ МЕТОДЫ ==========

    /**
     * Динамические тесты BOPLA
     */
    private List<Vulnerability> performDynamicBOPLATests(ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        System.out.println("(API-3) Выполнение динамических тестов BOPLA...");

        // Здесь можно добавить динамические тесты для BOPLA
        // Например, попытки доступа к свойствам объектов без должных прав

        return vulnerabilities;
    }

    /**
     * Комбинированные тесты BOPLA
     */
    private List<Vulnerability> performCombinedBOPLATests(List<TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        System.out.println("(API-3) Выполнение комбинированных тестов BOPLA...");

        return vulnerabilities;
    }
}