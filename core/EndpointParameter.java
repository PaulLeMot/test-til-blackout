package core;

/**
 * Параметр эндпоинта
 */
public class EndpointParameter {
    private String name;
    private String in; // path, query, header, body
    private boolean required;
    private String type;
    private String example;
    private String value;
    private String format;
    private String description;

    // Геттеры и сеттеры
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getIn() { return in; }
    public void setIn(String in) { this.in = in; }

    public boolean isRequired() { return required; }
    public void setRequired(boolean required) { this.required = required; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getExample() { return example; }
    public void setExample(String example) { this.example = example; }

    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    /**
     * Проверяет, является ли параметр чувствительным (пароль, токен и т.д.)
     */
    public boolean isSensitive() {
        if (name == null) return false;
        String lowerName = name.toLowerCase();
        return lowerName.contains("password") ||
                lowerName.contains("secret") ||
                lowerName.contains("token") ||
                lowerName.contains("key");
    }
}