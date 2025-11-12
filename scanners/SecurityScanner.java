// scanners/SecurityScanner.java
package scanners;

import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import java.util.List;

public interface SecurityScanner {
    String getName();
    List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient);
}
