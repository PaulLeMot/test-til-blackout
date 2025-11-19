package core;

import java.util.*;
import java.util.stream.Collectors;

public class CorrelationEngine {
    private final List<Vulnerability> allVulnerabilities;
    private final List<Vulnerability> correlatedVulnerabilities;

    public CorrelationEngine(List<Vulnerability> vulnerabilities) {
        this.allVulnerabilities = new ArrayList<>(vulnerabilities);
        this.correlatedVulnerabilities = new ArrayList<>();
    }

    public List<Vulnerability> correlate() {
        System.out.println("🔗 Запуск корреляции уязвимостей...");

        try {
            correlateBOLAWithBrokenAuth();
            correlateSSRFWithBusinessFlows();
            correlateMassAssignmentWithBOPLA();
            correlateUnsafeConsumptionWithExternalDependencies();
            findAttackChains();
            analyzePrivilegeEscalationPaths();
        } catch (Exception e) {
            System.err.println("❌ Ошибка при корреляции уязвимостей: " + e.getMessage());
        }

        System.out.println("✅ Корреляция завершена. Найдено цепочек: " + correlatedVulnerabilities.size());
        return correlatedVulnerabilities;
    }

    /**
     * Корреляция BOLA с Broken Authentication
     */
    private void correlateBOLAWithBrokenAuth() {
        List<Vulnerability> bolaVulns = filterByCategory(Vulnerability.Category.OWASP_API1_BOLA);
        List<Vulnerability> brokenAuthVulns = filterByCategory(Vulnerability.Category.OWASP_API2_BROKEN_AUTH);

        if (!bolaVulns.isEmpty() && !brokenAuthVulns.isEmpty()) {
            Vulnerability chain = createChainVulnerability(
                    "Цепочка: Broken Authentication → BOLA",
                    "Найдены уязвимости аутентификации в сочетании с BOLA. " +
                            "Злоумышленник может сначала скомпрометировать аутентификацию, " +
                            "а затем получить доступ к чужим данным через BOLA.\n\n" +
                            "Уязвимости аутентификации: " + brokenAuthVulns.size() + "\n" +
                            "Уязвимости BOLA: " + bolaVulns.size(),
                    Vulnerability.Severity.CRITICAL,
                    "AUTH_BOLA_CHAIN",
                    combineEvidences(bolaVulns, brokenAuthVulns)
            );
            correlatedVulnerabilities.add(chain);
        }
    }

    /**
     * Корреляция SSRF с бизнес-процессами
     */
    private void correlateSSRFWithBusinessFlows() {
        List<Vulnerability> ssrfVulns = filterByCategory(Vulnerability.Category.OWASP_API7_SSRF);
        List<Vulnerability> businessFlowVulns = filterByCategory(Vulnerability.Category.OWASP_API6_BUSINESS_FLOW);

        if (!ssrfVulns.isEmpty() && !businessFlowVulns.isEmpty()) {
            Vulnerability chain = createChainVulnerability(
                    "Цепочка: SSRF в бизнес-процессах",
                    "SSRF уязвимости обнаружены в критических бизнес-процессах. " +
                            "Это позволяет атаковать внутренние системы через бизнес-функции.\n\n" +
                            "Уязвимости SSRF: " + ssrfVulns.size() + "\n" +
                            "Бизнес-процессы: " + businessFlowVulns.size(),
                    Vulnerability.Severity.HIGH,
                    "SSRF_BUSINESS_CHAIN",
                    combineEvidences(ssrfVulns, businessFlowVulns)
            );
            correlatedVulnerabilities.add(chain);
        }
    }

    /**
     * Корреляция Mass Assignment с BOPLA
     */
    private void correlateMassAssignmentWithBOPLA() {
        List<Vulnerability> massAssignmentVulns = allVulnerabilities.stream()
                .filter(v -> v.getTitle().toLowerCase().contains("mass assignment"))
                .collect(Collectors.toList());

        List<Vulnerability> boplaVulns = filterByCategory(Vulnerability.Category.OWASP_API3_BOPLA);

        if (!massAssignmentVulns.isEmpty() && !boplaVulns.isEmpty()) {
            Vulnerability chain = createChainVulnerability(
                    "Цепочка: Mass Assignment → BOPLA",
                    "Mass assignment позволяет изменять свойства объектов, " +
                            "а BOPLA уязвимости позволяют обходить проверки привилегий.\n\n" +
                            "Уязвимости Mass Assignment: " + massAssignmentVulns.size() + "\n" +
                            "Уязвимости BOPLA: " + boplaVulns.size(),
                    Vulnerability.Severity.HIGH,
                    "MASS_ASSIGNMENT_BOPLA_CHAIN",
                    combineEvidences(massAssignmentVulns, boplaVulns)
            );
            correlatedVulnerabilities.add(chain);
        }
    }

    /**
     * Корреляция Unsafe Consumption с внешними зависимостями
     */
    private void correlateUnsafeConsumptionWithExternalDependencies() {
        List<Vulnerability> unsafeConsumptionVulns = filterByCategory(Vulnerability.Category.OWASP_API10_UNSAFE_CONSUMPTION);
        List<Vulnerability> inventoryVulns = filterByCategory(Vulnerability.Category.OWASP_API9_INVENTORY);

        if (!unsafeConsumptionVulns.isEmpty() && !inventoryVulns.isEmpty()) {
            // Поиск внешних API в инвентаризации
            boolean hasExternalAPIs = inventoryVulns.stream()
                    .anyMatch(v -> v.getDescription().toLowerCase().contains("external") ||
                            v.getDescription().toLowerCase().contains("third-party"));

            if (hasExternalAPIs) {
                Vulnerability chain = createChainVulnerability(
                        "Цепочка: Небезопасное потребление внешних API",
                        "Обнаружены внешние API в сочетании с небезопасным потреблением. " +
                                "Это создает риски цепочки доверия и атак через сторонние сервисы.\n\n" +
                                "Небезопасное потребление: " + unsafeConsumptionVulns.size() + "\n" +
                                "Внешние зависимости: найдены",
                        Vulnerability.Severity.HIGH,
                        "UNSAFE_EXTERNAL_CHAIN",
                        combineEvidences(unsafeConsumptionVulns, inventoryVulns)
                );
                correlatedVulnerabilities.add(chain);
            }
        }
    }

    /**
     * Поиск сложных цепочек атак
     */
    private void findAttackChains() {
        Map<String, List<Vulnerability>> vulnerabilitiesByEndpoint = groupByEndpoint();

        for (var entry : vulnerabilitiesByEndpoint.entrySet()) {
            String endpoint = entry.getKey();
            List<Vulnerability> endpointVulns = entry.getValue();

            if (endpointVulns.size() >= 2) {
                analyzeEndpointAttackChain(endpoint, endpointVulns);
            }
        }

        // Поиск меж-эндпоинтных цепочек
        findCrossEndpointChains();
    }

    private void analyzeEndpointAttackChain(String endpoint, List<Vulnerability> vulnerabilities) {
        // Группировка по типам уязвимостей
        boolean hasAuth = vulnerabilities.stream().anyMatch(this::isAuthenticationRelated);
        boolean hasDataAccess = vulnerabilities.stream().anyMatch(this::isDataAccessRelated);
        boolean hasInjection = vulnerabilities.stream().anyMatch(this::isInjectionRelated);

        if (hasAuth && hasDataAccess) {
            Vulnerability chain = createChainVulnerability(
                    "Комплексная уязвимость эндпоинта: " + endpoint,
                    "Эндпоинт " + endpoint + " содержит комбинацию уязвимостей аутентификации и доступа к данным. " +
                            "Это позволяет проводить сложные атаки на одном эндпоинте.\n\n" +
                            "Всего уязвимостей на эндпоинте: " + vulnerabilities.size() + "\n" +
                            "Уязвимости аутентификации: " + countByType(vulnerabilities, this::isAuthenticationRelated) + "\n" +
                            "Уязвимости доступа к данным: " + countByType(vulnerabilities, this::isDataAccessRelated),
                    calculateChainSeverity(vulnerabilities),
                    "ENDPOINT_COMPLEX_CHAIN",
                    combineEvidences(vulnerabilities)
            );
            correlatedVulnerabilities.add(chain);
        }

        if (hasInjection && hasDataAccess) {
            Vulnerability chain = createChainVulnerability(
                    "Цепочка инъекций на эндпоинте: " + endpoint,
                    "Эндпоинт " + endpoint + " уязвим к инъекциям и имеет проблемы с доступом к данным. " +
                            "Это может привести к компрометации всей базы данных через один эндпоинт.",
                    calculateChainSeverity(vulnerabilities),
                    "INJECTION_DATA_CHAIN",
                    combineEvidences(vulnerabilities)
            );
            correlatedVulnerabilities.add(chain);
        }
    }

    private void findCrossEndpointChains() {
        // Поиск цепочек между разными эндпоинтами
        // Например: эндпоинт регистрации -> эндпоинт администрирования

        List<Vulnerability> registrationVulns = findVulnerabilitiesInRegistration();
        List<Vulnerability> adminVulns = findVulnerabilitiesInAdminEndpoints();

        if (!registrationVulns.isEmpty() && !adminVulns.isEmpty()) {
            Vulnerability chain = createChainVulnerability(
                    "Меж-эндпоинтная цепочка: Регистрация → Администрирование",
                    "Обнаружены уязвимости в процессе регистрации в сочетании с уязвимостями администрирования. " +
                            "Это может позволить создание привилегированных учетных записей.\n\n" +
                            "Уязвимости регистрации: " + registrationVulns.size() + "\n" +
                            "Уязвимости администрирования: " + adminVulns.size(),
                    Vulnerability.Severity.HIGH,
                    "CROSS_ENDPOINT_CHAIN",
                    combineEvidences(registrationVulns, adminVulns)
            );
            correlatedVulnerabilities.add(chain);
        }
    }

    /**
     * Анализ путей эскалации привилегий
     */
    private void analyzePrivilegeEscalationPaths() {
        List<Vulnerability> horizontalEscalation = findHorizontalEscalationRisks();
        List<Vulnerability> verticalEscalation = findVerticalEscalationRisks();

        if (!horizontalEscalation.isEmpty()) {
            Vulnerability chain = createChainVulnerability(
                    "Риск горизонтальной эскалации привилегий",
                    "Обнаружены условия для горизонтальной эскалации привилегий. " +
                            "Пользователи могут получать доступ к данным других пользователей того же уровня.\n\n" +
                            "Количество рисков: " + horizontalEscalation.size(),
                    Vulnerability.Severity.HIGH,
                    "HORIZONTAL_ESCALATION",
                    combineEvidences(horizontalEscalation)
            );
            correlatedVulnerabilities.add(chain);
        }

        if (!verticalEscalation.isEmpty()) {
            Vulnerability chain = createChainVulnerability(
                    "Риск вертикальной эскалации привилегий",
                    "Обнаружены условия для вертикальной эскалации привилегий. " +
                            "Пользователи могут повышать свои привилегии до административного уровня.\n\n" +
                            "Количество рисков: " + verticalEscalation.size(),
                    Vulnerability.Severity.CRITICAL,
                    "VERTICAL_ESCALATION",
                    combineEvidences(verticalEscalation)
            );
            correlatedVulnerabilities.add(chain);
        }
    }

    // Вспомогательные методы
    private List<Vulnerability> filterByCategory(Vulnerability.Category category) {
        return allVulnerabilities.stream()
                .filter(v -> v.getCategory() == category)
                .collect(Collectors.toList());
    }

    private Map<String, List<Vulnerability>> groupByEndpoint() {
        return allVulnerabilities.stream()
                .filter(v -> v.getEndpoint() != null)
                .collect(Collectors.groupingBy(Vulnerability::getEndpoint));
    }

    private boolean isAuthenticationRelated(Vulnerability vuln) {
        return vuln.getCategory() == Vulnerability.Category.OWASP_API2_BROKEN_AUTH ||
                vuln.getTitle().toLowerCase().contains("auth") ||
                vuln.getDescription().toLowerCase().contains("authentic");
    }

    private boolean isDataAccessRelated(Vulnerability vuln) {
        return vuln.getCategory() == Vulnerability.Category.OWASP_API1_BOLA ||
                vuln.getCategory() == Vulnerability.Category.OWASP_API3_BOPLA ||
                vuln.getTitle().toLowerCase().contains("access") ||
                vuln.getDescription().toLowerCase().contains("access");
    }

    private boolean isInjectionRelated(Vulnerability vuln) {
        return vuln.getTitle().toLowerCase().contains("injection") ||
                vuln.getTitle().toLowerCase().contains("ssrf") ||
                vuln.getDescription().toLowerCase().contains("inject");
    }

    private long countByType(List<Vulnerability> vulnerabilities, java.util.function.Predicate<Vulnerability> predicate) {
        return vulnerabilities.stream().filter(predicate).count();
    }

    private Vulnerability.Severity calculateChainSeverity(List<Vulnerability> vulnerabilities) {
        // Определение максимальной серьезности в цепочке
        return vulnerabilities.stream()
                .map(Vulnerability::getSeverity)
                .max(Comparator.comparingInt(Enum::ordinal))
                .orElse(Vulnerability.Severity.MEDIUM);
    }

    private List<Vulnerability> findVulnerabilitiesInRegistration() {
        return allVulnerabilities.stream()
                .filter(v -> v.getEndpoint() != null &&
                        (v.getEndpoint().toLowerCase().contains("register") ||
                                v.getEndpoint().toLowerCase().contains("signup") ||
                                v.getEndpoint().toLowerCase().contains("create")))
                .collect(Collectors.toList());
    }

    private List<Vulnerability> findVulnerabilitiesInAdminEndpoints() {
        return allVulnerabilities.stream()
                .filter(v -> v.getEndpoint() != null &&
                        (v.getEndpoint().toLowerCase().contains("admin") ||
                                v.getEndpoint().toLowerCase().contains("manage") ||
                                v.getEndpoint().toLowerCase().contains("root")))
                .collect(Collectors.toList());
    }

    private List<Vulnerability> findHorizontalEscalationRisks() {
        return allVulnerabilities.stream()
                .filter(v -> v.getCategory() == Vulnerability.Category.OWASP_API1_BOLA ||
                        (v.getDescription() != null &&
                                v.getDescription().toLowerCase().contains("horizontal")))
                .collect(Collectors.toList());
    }

    private List<Vulnerability> findVerticalEscalationRisks() {
        return allVulnerabilities.stream()
                .filter(v -> v.getCategory() == Vulnerability.Category.OWASP_API5_BROKEN_FUNCTION_LEVEL_AUTH ||
                        (v.getDescription() != null &&
                                (v.getDescription().toLowerCase().contains("vertical") ||
                                        v.getDescription().toLowerCase().contains("privilege") ||
                                        v.getDescription().toLowerCase().contains("admin"))))
                .collect(Collectors.toList());
    }

    private String combineEvidences(List<Vulnerability>... vulnerabilityLists) {
        StringBuilder evidence = new StringBuilder();
        evidence.append("КОРРЕЛЯЦИЯ УЯЗВИМОСТЕЙ\n");
        evidence.append("=").append("=".repeat(50)).append("\n\n");

        int listNumber = 1;
        for (List<Vulnerability> vulnList : vulnerabilityLists) {
            evidence.append("Группа ").append(listNumber++).append(":\n");
            evidence.append("-".repeat(30)).append("\n");

            for (Vulnerability vuln : vulnList) {
                evidence.append("• ").append(vuln.getTitle()).append("\n");
                evidence.append("  Категория: ").append(vuln.getCategory()).append("\n");
                evidence.append("  Серьезность: ").append(vuln.getSeverity()).append("\n");
                if (vuln.getEndpoint() != null) {
                    evidence.append("  Эндпоинт: ").append(vuln.getEndpoint()).append("\n");
                }
                evidence.append("\n");
            }
        }

        evidence.append("ОБЩАЯ ОЦЕНКА РИСКА: ");
        if (correlatedVulnerabilities.stream().anyMatch(v -> v.getSeverity() == Vulnerability.Severity.CRITICAL)) {
            evidence.append("КРИТИЧЕСКИЙ");
        } else if (correlatedVulnerabilities.stream().anyMatch(v -> v.getSeverity() == Vulnerability.Severity.HIGH)) {
            evidence.append("ВЫСОКИЙ");
        } else {
            evidence.append("СРЕДНИЙ");
        }

        return evidence.toString();
    }

    private Vulnerability createChainVulnerability(String title, String description,
                                                   Vulnerability.Severity severity, String chainType,
                                                   String evidence) {
        Vulnerability chain = new Vulnerability();
        chain.setTitle(title);
        chain.setDescription(description);
        chain.setSeverity(severity);
        chain.setCategory(Vulnerability.Category.BUSINESS_LOGIC);
        chain.setEvidence(evidence);

        List<String> recommendations = Arrays.asList(
                "Провести комплексный аудит безопасности всех связанных компонентов",
                "Реализовать мониторинг аномальной активности между связанными эндпоинтами",
                "Внедрить систему обнаружения сложных атак (UEBA)",
                "Провести тестирование на проникновение с фокусом на цепочки атак",
                "Обновить документацию по безопасности с учетом выявленных цепочек"
        );
        chain.setRecommendations(recommendations);

        return chain;
    }
}