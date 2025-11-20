package core;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Класс для представления протестированного эндпоинта
 */
public class TestedEndpoint {
    private String method;
    private String path;
    private String source;
    private String operationId;
    private String summary;
    private String description;
    private List<EndpointParameter> parameters;
    private boolean tested = false;
    private int statusCode;
    private String responseBody;
    private String requestBody;
    private long responseTime;
    private Map<String, String> requestHeaders;

    // Геттеры и сеттеры
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public String getOperationId() { return operationId; }
    public void setOperationId(String operationId) { this.operationId = operationId; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public List<EndpointParameter> getParameters() { return parameters; }
    public void setParameters(List<EndpointParameter> parameters) { this.parameters = parameters; }

    public boolean isTested() { return tested; }
    public void setTested(boolean tested) { this.tested = tested; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }

    public String getRequestBody() { return requestBody; }
    public void setRequestBody(String requestBody) { this.requestBody = requestBody; }

    public long getResponseTime() { return responseTime; }
    public void setResponseTime(long responseTime) { this.responseTime = responseTime; }

    public Map<String, String> getRequestHeaders() { return requestHeaders; }
    public void setRequestHeaders(Map<String, String> requestHeaders) { this.requestHeaders = requestHeaders; }

    @Override
    public String toString() {
        return method + " " + path + " (" + source + ")";
    }

    public String getFullUrl(String baseUrl) {
        return baseUrl + path;
    }

    /**
     * Проверяет, был ли эндпоинт успешно протестирован
     */
    public boolean isSuccess() {
        return tested && statusCode >= 200 && statusCode < 400;
    }

    /**
     * Проверяет, содержит ли ответ ошибку
     */
    public boolean hasError() {
        return tested && statusCode >= 400;
    }

    /**
     * Получает краткое описание результата теста
     */
    public String getTestResult() {
        if (!tested) return "Not tested";
        if (isSuccess()) return "Success (" + statusCode + ")";
        if (hasError()) return "Error (" + statusCode + ")";
        return "Unknown";
    }
}