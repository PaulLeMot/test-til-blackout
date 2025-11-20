package core;

public class Response {
    private String code;
    private String description;
    private Object schema;

    public Response() {}

    public Response(String code, String description) {
        this.code = code;
        this.description = description;
    }

    // Getters and Setters
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Object getSchema() { return schema; }
    public void setSchema(Object schema) { this.schema = schema; }
}