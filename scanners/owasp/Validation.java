package scanners.owasp;

import scanners.SecurityScanner;
import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import core.HttpApiClient;

import java.util.*;

public class Validation implements SecurityScanner {
    
    private static final boolean DEBUG = true;
    
    @Override
    public String getName() {
        return "API Contract Validation Scanner";
    }

    @Override
    public List<Vulnerability> scan(Object openApiObj, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (!(openApiObj instanceof OpenAPI)) {
            vulnerabilities.add(createVulnerability(
                "OpenAPI Specification Not Available",
                "Cannot perform contract validation without OpenAPI specification",
                Vulnerability.Severity.MEDIUM,
                "N/A", "N/A",
                "No OpenAPI specification was loaded during scan"
            ));
            return vulnerabilities;
        }

        OpenAPI openAPI = (OpenAPI) openApiObj;
        String baseUrl = config.getTargetBaseUrl();
        
        try {
            logDebug("Starting contract validation for: " + baseUrl);
            
            // Test basic connectivity first
            if (!testBasicConnectivity(baseUrl, apiClient)) {
                vulnerabilities.add(createVulnerability(
                    "API Server Connectivity Issue",
                    "Cannot establish connection to API server",
                    Vulnerability.Severity.HIGH,
                    "N/A", "N/A",
                    "Cannot connect to public endpoints"
                ));
                return vulnerabilities;
            }
            
            vulnerabilities.addAll(validateSpecificationCompleteness(openAPI));
            vulnerabilities.addAll(validatePublicEndpoints(openAPI, baseUrl, apiClient));
            vulnerabilities.addAll(validateProtectedEndpoints(openAPI, baseUrl, config, apiClient));
            
            logDebug("Contract validation completed. Found: " + vulnerabilities.size() + " vulnerabilities");
        } catch (Exception e) {
            vulnerabilities.add(createVulnerability(
                "Contract Validation Error",
                "Error during contract validation: " + e.getMessage(),
                Vulnerability.Severity.MEDIUM,
                "N/A", "N/A",
                "Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage()
            ));
        }
        
        return vulnerabilities;
    }

    private boolean testBasicConnectivity(String baseUrl, ApiClient apiClient) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "curl/7.68.0");
            headers.put("Accept", "*/*");
            
            String testUrl = baseUrl + "/health";
            logDebug("Testing basic connectivity to: " + testUrl);
            
            Object response = apiClient.executeRequest("GET", testUrl, null, headers);
            
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                int statusCode = apiResponse.getStatusCode();
                
                logDebug("Connectivity test - Status: " + statusCode);
                return statusCode == 200;
            }
        } catch (Exception e) {
            logDebug("Connectivity test failed: " + e.getMessage());
        }
        return false;
    }

    private List<Vulnerability> validateSpecificationCompleteness(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        Map<String, PathItem> paths = openAPI.getPaths();
        
        if (paths == null || paths.isEmpty()) {
            vulnerabilities.add(createVulnerability(
                "No Paths Defined in OpenAPI Specification",
                "OpenAPI specification does not contain any API endpoints",
                Vulnerability.Severity.HIGH,
                "N/A", "N/A",
                "Paths object is null or empty in OpenAPI spec"
            ));
            return vulnerabilities;
        }

        logDebug("Checking specification completeness for " + paths.size() + " paths");
        
        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            
            for (Map.Entry<PathItem.HttpMethod, Operation> operationEntry : getOperations(pathItem).entrySet()) {
                PathItem.HttpMethod method = operationEntry.getKey();
                Operation operation = operationEntry.getValue();
                
                // Check for operationId
                if (operation.getOperationId() == null || operation.getOperationId().trim().isEmpty()) {
                    vulnerabilities.add(createVulnerability(
                        "Missing Operation ID in OpenAPI Specification",
                        "API operation is missing operationId in OpenAPI specification",
                        Vulnerability.Severity.LOW,
                        path, method.name(),
                        "No operationId defined for " + method.name() + " " + path
                    ));
                }
                
                // Check for response definitions
                if (operation.getResponses() == null || operation.getResponses().isEmpty()) {
                    vulnerabilities.add(createVulnerability(
                        "Missing Response Definitions",
                        "API operation has no response definitions in OpenAPI specification",
                        Vulnerability.Severity.MEDIUM,
                        path, method.name(),
                        "No responses defined for " + method.name() + " " + path
                    ));
                }
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> validatePublicEndpoints(OpenAPI openAPI, String baseUrl, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        String[] publicEndpoints = {
            "/health",
            "/.well-known/jwks.json",
            "/",
            "/products"
        };
        
        logDebug("Testing " + publicEndpoints.length + " public endpoints");
        
        for (String endpoint : publicEndpoints) {
            testPublicEndpoint(endpoint, openAPI, baseUrl, apiClient, vulnerabilities);
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> validateProtectedEndpoints(OpenAPI openAPI, String baseUrl, ScanConfig config, ApiClient apiClient) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Test protected endpoints that we can access with available tokens
        logDebug("Testing protected endpoints with available authentication");
        
        // Test /accounts with client token (own accounts)
        testAccountsWithClientToken(openAPI, baseUrl, config, apiClient, vulnerabilities);
        
        // Test /auth/bank-token (should work with query params)
        testBankTokenEndpoint(openAPI, baseUrl, apiClient, vulnerabilities);
        
        return vulnerabilities;
    }

    private void testPublicEndpoint(String endpoint, OpenAPI openAPI, String baseUrl, 
                                  ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        String fullUrl = baseUrl + endpoint;
        
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "curl/7.68.0");
        headers.put("Accept", "*/*");
        
        try {
            logDebug("Testing public endpoint: GET " + endpoint);
            Object response = apiClient.executeRequest("GET", fullUrl, null, headers);
            
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                int statusCode = apiResponse.getStatusCode();
                
                boolean documented = isEndpointDocumented(endpoint, "GET", openAPI);
                boolean accessible = statusCode == 200;
                
                logDebug("Public endpoint " + endpoint + " - Status: " + statusCode + 
                        ", Documented: " + documented + ", Accessible: " + accessible);
                
                if (accessible && !documented) {
                    vulnerabilities.add(createVulnerability(
                        "Undocumented Public API Endpoint",
                        "Public API endpoint exists but is not documented in OpenAPI specification",
                        Vulnerability.Severity.MEDIUM,
                        endpoint, "GET",
                        "Public endpoint " + endpoint + " exists (status: " + statusCode + ") but not in OpenAPI spec"
                    ));
                } else if (!accessible && documented) {
                    vulnerabilities.add(createVulnerability(
                        "Documented Public Endpoint Not Accessible",
                        "Public API endpoint documented in OpenAPI specification is not accessible",
                        Vulnerability.Severity.HIGH,
                        endpoint, "GET",
                        "Public endpoint " + endpoint + " documented but returns " + statusCode
                    ));
                }
            }
        } catch (Exception e) {
            logDebug("Error testing public endpoint " + endpoint + ": " + e.getMessage());
        }
    }

    private void testAccountsWithClientToken(OpenAPI openAPI, String baseUrl, ScanConfig config, 
                                           ApiClient apiClient, List<Vulnerability> vulnerabilities) {
        String endpoint = "/accounts";
        String fullUrl = baseUrl + endpoint;
        
        // Use client token for own accounts (no additional headers needed)
        String clientToken = config.getUserToken("team172-8");
        if (clientToken == null) {
            logDebug("No client token available for testing /accounts");
            return;
        }
        
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "curl/7.68.0");
        headers.put("Accept", "application/json");
        headers.put("Authorization", "Bearer " + clientToken);
        
        try {
            logDebug("Testing protected endpoint: GET " + endpoint + " with client token");
            Object response = apiClient.executeRequest("GET", fullUrl, null, headers);
            
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                int statusCode = apiResponse.getStatusCode();
                
                boolean documented = isEndpointDocumented(endpoint, "GET", openAPI);
                boolean accessible = statusCode == 200;
                
                logDebug("Protected endpoint " + endpoint + " with client token - Status: " + statusCode + 
                        ", Documented: " + documented + ", Accessible: " + accessible);
                
                if (!accessible && documented) {
                    vulnerabilities.add(createVulnerability(
                        "Protected Endpoint Authentication Issue",
                        "Protected API endpoint documented in OpenAPI specification returns error with valid authentication",
                        Vulnerability.Severity.MEDIUM,
                        endpoint, "GET",
                        "Protected endpoint " + endpoint + " documented but returns " + statusCode + " with valid client token"
                    ));
                }
                
                // Log response for debugging
                if (apiResponse.getBody() != null && !apiResponse.getBody().trim().isEmpty()) {
                    logDebug("Response from " + endpoint + ": " + 
                            (apiResponse.getBody().length() > 200 ? 
                             apiResponse.getBody().substring(0, 200) + "..." : apiResponse.getBody()));
                }
            }
        } catch (Exception e) {
            logDebug("Error testing protected endpoint " + endpoint + ": " + e.getMessage());
        }
    }

    private void testBankTokenEndpoint(OpenAPI openAPI, String baseUrl, ApiClient apiClient, 
                                     List<Vulnerability> vulnerabilities) {
        String endpoint = "/auth/bank-token";
        String fullUrl = baseUrl + endpoint + "?client_id=team172&client_secret="***REMOVED***"";
        
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "curl/7.68.0");
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        
        try {
            logDebug("Testing authentication endpoint: POST " + endpoint);
            Object response = apiClient.executeRequest("POST", fullUrl, "", headers);
            
            if (response instanceof HttpApiClient.ApiResponse) {
                HttpApiClient.ApiResponse apiResponse = (HttpApiClient.ApiResponse) response;
                int statusCode = apiResponse.getStatusCode();
                
                boolean documented = isEndpointDocumented(endpoint, "POST", openAPI);
                boolean accessible = statusCode == 200;
                
                logDebug("Authentication endpoint " + endpoint + " - Status: " + statusCode + 
                        ", Documented: " + documented + ", Accessible: " + accessible);
                
                if (!accessible && documented) {
                    vulnerabilities.add(createVulnerability(
                        "Authentication Endpoint Issue",
                        "Authentication endpoint documented in OpenAPI specification returns error",
                        Vulnerability.Severity.HIGH,
                        endpoint, "POST",
                        "Authentication endpoint " + endpoint + " documented but returns " + statusCode
                    ));
                }
            }
        } catch (Exception e) {
            logDebug("Error testing authentication endpoint " + endpoint + ": " + e.getMessage());
        }
    }

    private Map<PathItem.HttpMethod, Operation> getOperations(PathItem pathItem) {
        Map<PathItem.HttpMethod, Operation> operations = new HashMap<>();
        
        if (pathItem.getGet() != null) operations.put(PathItem.HttpMethod.GET, pathItem.getGet());
        if (pathItem.getPost() != null) operations.put(PathItem.HttpMethod.POST, pathItem.getPost());
        if (pathItem.getPut() != null) operations.put(PathItem.HttpMethod.PUT, pathItem.getPut());
        if (pathItem.getDelete() != null) operations.put(PathItem.HttpMethod.DELETE, pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.put(PathItem.HttpMethod.PATCH, pathItem.getPatch());
        
        return operations;
    }

    private boolean isEndpointDocumented(String endpoint, String method, OpenAPI openAPI) {
        Map<String, PathItem> paths = openAPI.getPaths();
        if (paths == null) return false;
        
        PathItem pathItem = paths.get(endpoint);
        if (pathItem == null) return false;
        
        switch (method) {
            case "GET": return pathItem.getGet() != null;
            case "POST": return pathItem.getPost() != null;
            case "PUT": return pathItem.getPut() != null;
            case "DELETE": return pathItem.getDelete() != null;
            case "PATCH": return pathItem.getPatch() != null;
            default: return false;
        }
    }

    private Vulnerability createVulnerability(String title, String description, 
                                            Vulnerability.Severity severity, 
                                            String endpoint, String method, String evidence) {
        Vulnerability vuln = new Vulnerability();
        vuln.setTitle(title);
        vuln.setDescription(description);
        vuln.setSeverity(severity);
        vuln.setCategory(Vulnerability.Category.CONTRACT_VALIDATION);
        vuln.setEndpoint(endpoint);
        vuln.setMethod(method);
        vuln.setEvidence(evidence);
        
        List<String> recommendations = new ArrayList<>();
        if (title.contains("Undocumented")) {
            recommendations.add("Document all existing API endpoints in OpenAPI specification");
            recommendations.add("Ensure specification reflects actual API capabilities");
        } else if (title.contains("Not Accessible")) {
            recommendations.add("Verify the endpoint is properly implemented on the server");
            recommendations.add("Check server configuration and routing");
        } else if (title.contains("Missing Operation ID")) {
            recommendations.add("Add unique operationId for each API operation");
            recommendations.add("Use meaningful operationId names (e.g., getAccounts, createPayment)");
        } else if (title.contains("Missing Response")) {
            recommendations.add("Define at least one response for each API operation");
            recommendations.add("Include both success (2xx) and error (4xx, 5xx) responses");
        } else if (title.contains("Authentication")) {
            recommendations.add("Check authentication requirements for the endpoint");
            recommendations.add("Verify token validity and permissions");
        }
        
        vuln.setRecommendations(recommendations);
        return vuln;
    }

    private void logDebug(String message) {
        if (DEBUG) {
            System.out.println("[DEBUG Validation] " + message);
        }
    }
}
