package scanners.fuzzing;

public class ApiParameter {
    private String name;
    private String type;
    private ParameterLocation location;
    private boolean required;

    public ApiParameter(String name, String type, ParameterLocation location, boolean required) {
        this.name = name;
        this.type = type;
        this.location = location;
        this.required = required;
    }

    // Геттеры
    public String getName() { return name; }
    public String getType() { return type; }
    public ParameterLocation getLocation() { return location; }
    public boolean isRequired() { return required; }

    @Override
    public String toString() {
        return String.format("ApiParameter{name='%s', type='%s', location=%s, required=%s}",
                name, type, location, required);
    }
}