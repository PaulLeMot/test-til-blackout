package scanners.fuzzing;

import java.util.ArrayList;
import java.util.List;

public class ApiEndpoint {
    private String path;
    private HttpMethod method;
    private List<ApiParameter> parameters;

    public ApiEndpoint(String path, HttpMethod method, List<ApiParameter> parameters) {
        this.path = path;
        this.method = method;
        this.parameters = parameters != null ? parameters : new ArrayList<>();
    }

    // Getters
    public String getPath() { return path; }
    public HttpMethod getMethod() { return method; }
    public List<ApiParameter> getParameters() { return parameters; }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public String toString() {
        return String.format("ApiEndpoint{path='%s', method=%s, parameters=%s}",
                path, method, parameters.size());
    }
}