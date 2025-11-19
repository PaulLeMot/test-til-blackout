package core;

import java.util.List;
import java.util.Map;

public class ApiEndpoint {
    private String path;
    private String method;
    private String summary;
    private String description;
    private List<Parameter> parameters;
    private Map<String, Response> responses;
    private List<String> tags;

    public ApiEndpoint() {}

    public ApiEndpoint(String path, String method, String summary) {
        this.path = path;
        this.method = method;
        this.summary = summary;
    }

    // Getters and Setters
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public List<Parameter> getParameters() { return parameters; }
    public void setParameters(List<Parameter> parameters) { this.parameters = parameters; }

    public Map<String, Response> getResponses() { return responses; }
    public void setResponses(Map<String, Response> responses) { this.responses = responses; }

    public List<String> getTags() { return tags; }
    public void setTags(List<String> tags) { this.tags = tags; }

    @Override
    public String toString() {
        return method + " " + path;
    }
}