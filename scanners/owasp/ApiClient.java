package scanners.owasp;

import java.util.Map;

public interface ApiClient {
    Object executeRequest(String method, String url, String body, Map<String, String> headers);
}
