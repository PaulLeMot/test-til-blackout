// scanners/SecurityScanner.java
package scanners;

import core.ScanConfig;
import core.Vulnerability;
import core.ApiClient;
import core.TestedEndpoint;
import java.util.List;
import java.util.ArrayList;

public interface SecurityScanner {
    String getName();

    // Старый метод для обратной совместимости
    List<Vulnerability> scan(Object openAPI, ScanConfig config, ApiClient apiClient);

    // Новый метод для работы с собранными эндпоинтами
    default List<Vulnerability> scanEndpoints(List<TestedEndpoint> endpoints, ScanConfig config, ApiClient apiClient) {
        // По умолчанию используем старый метод для обратной совместимости
        System.out.println("⚠️ Сканер " + getName() + " использует старый метод scan()");
        return scan(null, config, apiClient);
    }
}