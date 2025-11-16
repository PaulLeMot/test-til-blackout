package core;

import java.util.*;
import java.text.SimpleDateFormat;

public class ConfigParser {
    public static ScanConfig parseConfig(String json) {
        ScanConfig config = new ScanConfig();

        try {
            log("Исходный JSON: " + json);

            // Удаляем пробелы и переносы строк для упрощения парсинга
            json = json.trim().replaceAll("\\s+", " ");

            if (json.startsWith("{") && json.endsWith("}")) {
                json = json.substring(1, json.length() - 1).trim();

                // Парсим bankId
                String bankId = extractValueFromObject(json, "bankId");
                if (bankId != null) {
                    config.setBankId(bankId.trim());
                    log("Parsed bankId: " + bankId);
                }

                List<ScanConfig.BankConfig> banks = new ArrayList<>();
                List<ScanConfig.UserCredentials> credentials = new ArrayList<>();

                // Парсим банки
                String banksPart = extractPart(json, "banks");
                if (banksPart != null && banksPart.startsWith("[") && banksPart.endsWith("]")) {
                    banksPart = banksPart.substring(1, banksPart.length() - 1).trim();
                    log("Banks part: " + banksPart);

                    if (!banksPart.isEmpty()) {
                        String[] bankObjects = splitObjects(banksPart);
                        log("Found " + bankObjects.length + " bank objects");

                        for (String bankObj : bankObjects) {
                            bankObj = bankObj.trim();
                            if (bankObj.startsWith("{") && bankObj.endsWith("}")) {
                                String baseUrl = extractValueFromObject(bankObj, "baseUrl");
                                String specUrl = extractValueFromObject(bankObj, "specUrl");
                                // Убираем пробелы в конце URL
                                if (baseUrl != null) baseUrl = baseUrl.trim();
                                if (specUrl != null) specUrl = specUrl.trim();
                                log("Parsed bank - baseUrl: " + baseUrl + ", specUrl: " + specUrl);
                                if (baseUrl != null && specUrl != null) {
                                    banks.add(new ScanConfig.BankConfig(baseUrl, specUrl));
                                }
                            }
                        }
                    }
                }

                // Парсим учетные данные
                String credsPart = extractPart(json, "credentials");
                if (credsPart != null && credsPart.startsWith("[") && credsPart.endsWith("]")) {
                    credsPart = credsPart.substring(1, credsPart.length() - 1).trim();
                    log("Credentials part: " + credsPart);

                    if (!credsPart.isEmpty()) {
                        String[] credObjects = splitObjects(credsPart);
                        log("Found " + credObjects.length + " credential objects");

                        for (String credObj : credObjects) {
                            credObj = credObj.trim();
                            if (credObj.startsWith("{") && credObj.endsWith("}")) {
                                String username = extractValueFromObject(credObj, "username");
                                String password = extractValueFromObject(credObj, "password");
                                log("Parsed credential - username: " + username + ", password: " + (password != null ? "***" : "null"));
                                if (username != null && password != null) {
                                    credentials.add(new ScanConfig.UserCredentials(username, password));
                                }
                            }
                        }
                    }
                }

                config.setBanks(banks);
                config.setCredentials(credentials);
            }
        } catch (Exception e) {
            System.err.println("Error parsing config: " + e.getMessage());
            e.printStackTrace();
        }

        return config;
    }

    // Остальные методы ConfigParser остаются без изменений...
    private static String extractPart(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int start = json.indexOf(searchKey);
        if (start == -1) {
            log("Key '" + key + "' not found in JSON");
            return null;
        }

        start += searchKey.length();
        int braceCount = 0;
        boolean inQuotes = false;
        char quoteChar = '"';
        int contentStart = -1;

        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);

            if (c == '"' && (i == 0 || json.charAt(i-1) != '\\')) {
                if (!inQuotes) {
                    inQuotes = true;
                    quoteChar = c;
                } else if (c == quoteChar) {
                    inQuotes = false;
                }
            }

            if (!inQuotes) {
                if (c == '[' || c == '{') {
                    if (braceCount == 0) {
                        contentStart = i;
                    }
                    braceCount++;
                } else if (c == ']' || c == '}') {
                    braceCount--;
                    if (braceCount == 0 && contentStart != -1) {
                        return json.substring(contentStart, i + 1);
                    }
                } else if (braceCount == 0 && c == ',') {
                    // Достигнули конца текущего элемента
                    break;
                }
            }
        }

        return null;
    }

    private static String[] splitObjects(String arrayContent) {
        List<String> objects = new ArrayList<>();
        int braceCount = 0;
        boolean inQuotes = false;
        char quoteChar = '"';
        int start = -1;

        for (int i = 0; i < arrayContent.length(); i++) {
            char c = arrayContent.charAt(i);

            if (c == '"' && (i == 0 || arrayContent.charAt(i-1) != '\\')) {
                if (!inQuotes) {
                    inQuotes = true;
                    quoteChar = c;
                } else if (c == quoteChar) {
                    inQuotes = false;
                }
            }

            if (!inQuotes) {
                if (c == '{') {
                    if (braceCount == 0) {
                        start = i;
                    }
                    braceCount++;
                } else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0 && start != -1) {
                        objects.add(arrayContent.substring(start, i + 1));
                        start = -1;
                    }
                }
            }
        }

        return objects.toArray(new String[0]);
    }

    private static String extractValueFromObject(String obj, String key) {
        // Ищем ключ в кавычках
        String search = "\"" + key + "\":";
        int keyStart = obj.indexOf(search);
        if (keyStart == -1) return null;

        int valueStart = keyStart + search.length();

        // Пропускаем пробелы
        while (valueStart < obj.length() && Character.isWhitespace(obj.charAt(valueStart))) {
            valueStart++;
        }

        if (valueStart >= obj.length()) return null;

        char firstChar = obj.charAt(valueStart);
        if (firstChar == '"') {
            // Строковое значение в кавычках
            int stringStart = valueStart + 1;
            int stringEnd = stringStart;
            boolean inEscape = false;

            while (stringEnd < obj.length()) {
                char c = obj.charAt(stringEnd);
                if (inEscape) {
                    inEscape = false;
                } else if (c == '\\') {
                    inEscape = true;
                } else if (c == '"') {
                    return obj.substring(stringStart, stringEnd);
                }
                stringEnd++;
            }
        }

        return null;
    }

    private static void log(String message) {
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
        String logMessage = "[CONFIG_PARSER][" + timestamp + "] " + message;
        System.out.println(logMessage);
    }
}