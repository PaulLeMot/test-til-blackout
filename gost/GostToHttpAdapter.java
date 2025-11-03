package gost;

import core.ApiClient;
import core.HttpApiClient;
import java.util.*;
import java.io.*;
import java.nio.file.*;

public class GostToHttpAdapter implements ApiClient {
    private final String pfxPath;
    private final String password;
    
    public GostToHttpAdapter(String pfxPath) {
        this(pfxPath, null);
    }
    
    public GostToHttpAdapter(String pfxPath, String password) {
        this.pfxPath = pfxPath;
        this.password = password;
    }
    
    @Override
    public Object executeRequest(String method, String url, String body, Map<String, String> headers) {
        try {
            System.out.println("🔐 Выполняется GOST запрос: " + method + " " + url);
            
            // Формируем команду curl
            List<String> command = new ArrayList<>();
            command.add("curl");
            
            // Настройки GOST и SSL
            command.add("--cert-type");
            command.add("P12");
            
            // Прямое использование пути к сертификату
            String certArgument = pfxPath;
            if (password != null) {
                certArgument += ":" + password;
            }
            command.add("--cert");
            command.add(certArgument);
            
            // Дополнительные настройки
            command.add("--insecure");
            command.add("--location");
            command.add("--silent");
            command.add("--show-error");
            command.add("--write-out");
            command.add("%{http_code}");
            command.add("--legacy-ssl-renegotiation");
            // Метод запроса
            command.add("-X");
            command.add(method);
            
            // Заголовки
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    command.add("-H");
                    command.add(header.getKey() + ": " + header.getValue());
                }
            }
            
            // Тело запроса
            if (body != null && !body.isEmpty() && 
                (method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))) {
                command.add("--data");
                command.add(body);
            }
            
            // URL
            command.add(url.trim());
            
            // Логируем команду (без пароля)
            System.out.println("🔐 Команда: curl --cert [сертификат] " + url);
            
            // Выполняем команду
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();
            
            // Читаем ответ
            String output = new String(process.getInputStream().readAllBytes());
            String error = new String(process.getErrorStream().readAllBytes());
            
            int exitCode = process.waitFor();
            
            if (exitCode != 0) {
                System.err.println("❌ Ошибка GOST: " + error);
                return new HttpApiClient.ApiResponse(500, "GOST Error: " + error, Map.of());
            }
            
            // Извлекаем статус код (последняя строка)
            String[] lines = output.split("\n");
            int statusCode = 500;
            String responseBody = "";
            
            if (lines.length > 0) {
                try {
                    statusCode = Integer.parseInt(lines[lines.length - 1].trim());
                    // Тело ответа - все кроме последней строки
                    if (lines.length > 1) {
                        responseBody = String.join("\n", Arrays.copyOf(lines, lines.length - 1));
                    }
                } catch (NumberFormatException e) {
                    System.err.println("❌ Не удалось распарсить статус: " + lines[lines.length - 1]);
                }
            }
            
            return new HttpApiClient.ApiResponse(statusCode, responseBody, Map.of());
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка GOST запроса: " + e.getMessage());
            return new HttpApiClient.ApiResponse(500, "GOST Error: " + e.getMessage(), Map.of());
        }
    }
}
