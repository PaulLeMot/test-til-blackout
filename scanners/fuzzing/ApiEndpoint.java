package scanners.fuzzing;

import java.util.List;

public class ApiEndpoint {
    public String path;
    public HttpMethod method;
    public List<ApiParameter> parameters;

    public ApiEndpoint(String path, HttpMethod method, List<ApiParameter> parameters) {
        this.path = path;
        this.method = method;
        this.parameters = parameters;
    }

    public String getPath() { return path; }
    public HttpMethod getMethod() { return method; }
    public List<ApiParameter> getParameters() { return parameters; }
}