// scanners/owasp/API9_InventoryScanner.java
package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.HttpApiClient;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class API9_InventoryScanner implements SecurityScanner {

    private static final List<String> COMMON_ENDPOINTS = Arrays.asList(
            "/admin", "/debug", "/test", "/api/admin", "/api/debug", "/api/test",
            "/management", "/monitoring", "/console", "/api/console",
            "/_admin", "/_debug", "/_test", "/private", "/secret",
            "/backup", "/database", "/config", "/api/config",
            "/logs", "/api/logs", "/system", "/api/system"
    );

    private static final List<String> VERSION_PATHS = Arrays.asList(
            "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
            "/api/v1/", "/api/v2/", "/api/v3/", "/api/v4/", "/api/v5/",
            "/internal/", "/internal/api/", "/dev/", "/development/",
            "/staging/", "/test/", "/uat/"
    );

    private static final List<String> MONITORING_PATHS = Arrays.asList(
            "/health", "/metrics", "/status", "/info", "/actuator",
            "/actuator/health", "/actuator/metrics", "/actuator/info",
            "/prometheus", "/grafana", "/monitoring", "/api/health",
            "/api/metrics", "/api/status", "/management/health"
    );

    private static final List<String> DEPRECATED_KEYWORDS = Arrays.asList(
            "deprecated", "legacy", "old", "v1", "v0", "beta", "alpha"
    );

    public API9_InventoryScanner() {}

    @Override
    public String getName() {
        return "API9_Inventory";
    }

    @Override
    public List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient) {
        System.out.println("🔍 Scanning for Improper Inventory Management vulnerabilities (OWASP API Security Top 10:2023 - API9)...");

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String baseUrl = config.getTargetBaseUrl().trim();

        try {
            // 5.9.1: Проверка common endpoints
            vulnerabilities.addAll(scanCommonEndpoints(baseUrl, apiClient));

            // 5.9.3: Поиск версионированных эндпоинтов
            vulnerabilities.addAll(scanVersionedEndpoints(baseUrl, apiClient));

            // 5.9.4: Проверка мониторинг-путей
            vulnerabilities.addAll(scanMonitoringEndpoints(baseUrl, apiClient));

            // 5.9.6: Поиск устаревших версий API
            vulnerabilities.addAll(scanDeprecatedEndpoints(baseUrl, apiClient));

            // 5.9.7: Проверка debug endpoints в production
            vulnerabilities.addAll(scanDebugEndpoints(baseUrl, apiClient));

        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при сканировании инвентаризации: " + e.getMessage());
        }

        System.out.println("✅ Inventory scan completed. Найдено уязвимостей: " + vulnerabilities.size());
        return vulnerabilities;
    }

    private List<Vulnerability> scanCommonEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        for (String endpoint : COMMON_ENDPOINTS) {
            String fullUrl = baseUrl + endpoint;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

            if (response != null && isInterestingResponse(response.getStatusCode())) {
                Vulnerability vuln = createInventoryVulnerability(
                        "Обнаружен common endpoint",
                        "Найден потенциально недокументированный endpoint: " + endpoint,
                        endpoint,
                        response.getStatusCode(),
                        "Common endpoint discovery"
                );
                vulns.add(vuln);
                System.out.println("🔍 Найден common endpoint: " + endpoint + " (HTTP " + response.getStatusCode() + ")");
            }
        }

        return vulns;
    }

    private List<Vulnerability> scanVersionedEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        for (String versionPath : VERSION_PATHS) {
            String fullUrl = baseUrl + versionPath + "test"; // Добавляем test для проверки существования
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

            if (response != null && isInterestingResponse(response.getStatusCode())) {
                Vulnerability vuln = createInventoryVulnerability(
                        "Обнаружен версионированный endpoint",
                        "Найден endpoint с версией: " + versionPath + " - может указывать на устаревшую версию API",
                        versionPath,
                        response.getStatusCode(),
                        "Versioned endpoint discovery"
                );
                vulns.add(vuln);
                System.out.println("🔍 Найден версионированный endpoint: " + versionPath + " (HTTP " + response.getStatusCode() + ")");
            }
        }

        return vulns;
    }

    private List<Vulnerability> scanMonitoringEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        for (String monitoringPath : MONITORING_PATHS) {
            String fullUrl = baseUrl + monitoringPath;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

            if (response != null && response.getStatusCode() == 200) {
                Vulnerability vuln = createInventoryVulnerability(
                        "Обнаружен мониторинг endpoint",
                        "Мониторинг endpoint доступен публично: " + monitoringPath + " - может раскрывать чувствительную информацию",
                        monitoringPath,
                        response.getStatusCode(),
                        "Public monitoring endpoint: " + response.getBody().substring(0, Math.min(100, response.getBody().length()))
                );
                vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                vulns.add(vuln);
                System.out.println("🚨 Публичный мониторинг endpoint: " + monitoringPath);
            }
        }

        return vulns;
    }

    private List<Vulnerability> scanDeprecatedEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        // Получаем основную страницу API для поиска deprecated endpoints
        String mainApiUrl = baseUrl + "/";
        HttpApiClient.ApiResponse response = makeRequest(apiClient, mainApiUrl);

        if (response != null && response.getStatusCode() == 200) {
            String body = response.getBody().toLowerCase();

            for (String keyword : DEPRECATED_KEYWORDS) {
                if (body.contains(keyword)) {
                    Vulnerability vuln = createInventoryVulnerability(
                            "Обнаружены устаревшие endpoints",
                            "В ответе API найдены упоминания устаревших версий или deprecated endpoints. Ключевое слово: " + keyword,
                            "/",
                            response.getStatusCode(),
                            "Deprecated keyword found: " + keyword
                    );
                    vuln.setSeverity(Vulnerability.Severity.LOW);
                    vulns.add(vuln);
                    System.out.println("⚠️ Найдено упоминание устаревшего API: " + keyword);
                }
            }
        }

        return vulns;
    }

    private List<Vulnerability> scanDebugEndpoints(String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulns = new ArrayList<>();

        // Специфичные debug endpoints
        List<String> debugEndpoints = Arrays.asList(
                "/debug", "/api/debug", "/_debug", "/develop", "/development",
                "/env", "/api/env", "/configuration", "/api/configuration",
                "/trace", "/api/trace", "/dump", "/api/dump"
        );

        for (String debugPath : debugEndpoints) {
            String fullUrl = baseUrl + debugPath;
            HttpApiClient.ApiResponse response = makeRequest(apiClient, fullUrl);

            if (response != null && response.getStatusCode() == 200) {
                // Проверяем, содержит ли ответ debug информацию
                String body = response.getBody().toLowerCase();
                if (body.contains("debug") || body.contains("development") ||
                        body.contains("environment") || body.contains("configuration")) {

                    Vulnerability vuln = createInventoryVulnerability(
                            "Debug endpoint в production",
                            "Debug endpoint доступен в production среде: " + debugPath + " - может раскрывать чувствительную информацию",
                            debugPath,
                            response.getStatusCode(),
                            "Debug endpoint accessible in production"
                    );
                    vuln.setSeverity(Vulnerability.Severity.HIGH);
                    vulns.add(vuln);
                    System.out.println("🚨 CRITICAL: Debug endpoint в production: " + debugPath);
                }
            }
        }

        return vulns;
    }

    private HttpApiClient.ApiResponse makeRequest(ApiClient apiClient, String url) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            headers.put("User-Agent", "GOSTGuardian-Scanner/1.0");

            Object response = apiClient.executeRequest("GET", url, null, headers);
            return (HttpApiClient.ApiResponse) response;

        } catch (Exception e) {
            System.err.println("⚠️ Ошибка при запросе к " + url + ": " + e.getMessage());
            return null;
        }
    }

    private boolean isInterestingResponse(int statusCode) {
        // Нас интересуют не только 200, но и другие коды, которые могут указывать на существование endpoint
        return statusCode == 200 || statusCode == 201 || statusCode == 301 ||
                statusCode == 302 || statusCode == 403 || statusCode == 401;
    }

    private Vulnerability createInventoryVulnerability(String title, String description,
                                                       String endpoint, int statusCode, String evidence) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle("API9:2023 - Improper Inventory Management - " + title);
        vuln.setDescription(description);
        vuln.setSeverity(Vulnerability.Severity.LOW); // По умолчанию LOW, можно переопределить
        vuln.setCategory(Vulnerability.Category.CONTRACT_VALIDATION);
        vuln.setEndpoint(endpoint);
        vuln.setStatusCode(statusCode);
        vuln.setEvidence(evidence);
        vuln.setMethod("GET");

        // Добавляем рекомендации
        List<String> recommendations = new ArrayList<>();
        recommendations.add("Регулярно обновляйте документацию API");
        recommendations.add("Удалите неиспользуемые и устаревшие endpoints");
        recommendations.add("Ограничьте доступ к debug и monitoring endpoints в production");
        recommendations.add("Внедрите процесс управления версиями API");
        recommendations.add("Используйте стандартизированные пути для API");
        vuln.setRecommendations(recommendations);

        return vuln;
    }
}