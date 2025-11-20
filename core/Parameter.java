package core;

public class Parameter {
    private String name;
    private String in; // query, header, path, cookie
    private String type;
    private boolean required;
    private String description;
    private Object example;

    public Parameter() {}

    public Parameter(String name, String in, boolean required) {
        this.name = name;
        this.in = in;
        this.required = required;
    }

    // Getters and Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getIn() { return in; }
    public void setIn(String in) { this.in = in; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public boolean isRequired() { return required; }
    public void setRequired(boolean required) { this.required = required; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Object getExample() { return example; }
    public void setExample(Object example) { this.example = example; }
}