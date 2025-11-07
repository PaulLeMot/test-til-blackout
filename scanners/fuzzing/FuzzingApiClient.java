// scanners/fuzzing/FuzzingApiClient.java
package scanners.fuzzing;

import java.util.Map;

public interface FuzzingApiClient {
    HttpResponse sendRequest(String method, String url, Map<String, String> params,
                             Map<String, String> headers, Map<String, String> bodyParams);
}