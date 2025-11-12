package scanners.fuzzing;

public interface FuzzingStrategy {
    boolean shouldSkipEndpoint(String path, String method);
    boolean isFinancialEndpoint(String path, String method);
    String getTestPayloadForEndpoint(String path, String method, String payloadType);
}