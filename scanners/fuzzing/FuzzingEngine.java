package scanners.fuzzing;

import java.util.*;

public class FuzzingEngine {

    private PayloadLibrary payloadLibrary = new PayloadLibrary();
    private ObfuscationEngine obfuscationEngine = new ObfuscationEngine();

    public List<String> generatePayloads(ApiParameter parameter) {
        List<String> payloads = new ArrayList<>();

        // Получаем специфичные payloads для параметра
        List<String> basePayloads = payloadLibrary.getPayloadsForParameter(
                parameter.getName(), parameter.getType()
        );

        // Применяем обфускацию к каждому payload
        for (String basePayload : basePayloads) {
            payloads.add(basePayload); // Оригинальный payload
            payloads.addAll(obfuscationEngine.obfuscatePayload(basePayload));
        }

        // Ограничиваем количество payloads для производительности
        if (payloads.size() > 50) {
            payloads = payloads.subList(0, 50);
        }

        return payloads;
    }

    public List<String> generatePriorityPayloads(ApiParameter parameter) {
        List<String> priorityPayloads = new ArrayList<>();

        // Критичные payloads для быстрого тестирования
        String paramName = parameter.getName().toLowerCase();
        String paramType = parameter.getType().toLowerCase();

        // SQL Injection для критичных параметров
        if (paramName.contains("id") || paramName.contains("query")) {
            priorityPayloads.addAll(Arrays.asList("' OR '1'='1", "' OR 1=1--"));
        }

        // XSS для пользовательского ввода
        if (paramType.contains("string") && paramName.contains("name")) {
            priorityPayloads.addAll(Arrays.asList("<script>alert(1)</script>", "<img src=x onerror=alert(1)>"));
        }

        // Path Traversal
        if (paramName.contains("file") || paramName.contains("path")) {
            priorityPayloads.add("../../../../etc/passwd");
        }

        // Business Logic для финансовых параметров
        if (paramName.contains("amount") || paramName.contains("balance")) {
            priorityPayloads.addAll(Arrays.asList("-1000000", "999999999.99"));
        }

        return priorityPayloads;
    }
}