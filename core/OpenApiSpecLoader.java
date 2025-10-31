// core/OpenApiSpecLoader.java
package core;

import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import io.swagger.v3.oas.models.OpenAPI;

public class OpenApiSpecLoader {

    private final OpenAPI openAPI;

    public OpenApiSpecLoader(String specUrl) {
        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setResolveFully(true);

        SwaggerParseResult result = new OpenAPIV3Parser().readLocation(specUrl, null, options);
        if (result.getMessages() != null && !result.getMessages().isEmpty()) {
            System.err.println("OpenAPI parse warnings: " + result.getMessages());
        }

        this.openAPI = result.getOpenAPI();
        if (this.openAPI == null) {
            throw new RuntimeException("Failed to parse OpenAPI spec from: " + specUrl);
        }
    }

    public OpenAPI getOpenAPI() {
        return openAPI;
    }
}
