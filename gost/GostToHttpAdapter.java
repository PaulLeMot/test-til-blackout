package gost;

//Dima lox
//Dima lox
//Dima lox
//Dima lox
//Dima lox
//Dima lox
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
            // Создаем временный файл для тела ответа
            Path tempBodyFile = Files.createTempFile("gost_response", ".txt");
            tempBodyFile.toFile().deleteOnExit();
            
            // Копируем сертификат во временный файл с простым путем
            Path tempCertFile = copyCertToTempLocation();
            if (tempCertFile == null) {
                return new HttpApiClient.ApiResponse(500, "Failed to copy certificate to temp location", Map.of());
            }
            
            // Формируем команду curl с GOST поддержкой
            List<String> command = new ArrayList<>();
            command.add("curl");
            
            // Настройки GOST и SSL
            command.add("--cert-type");
            command.add("P12");
            
            // Используем временный файл сертификата
            String certArgument;
            if (password != null) {
                certArgument = "\"" + tempCertFile.toString() + "\":" + password;
            } else {
                certArgument = "\"" + tempCertFile.toString() + "\"";
            }
            command.add("--cert");
            command.add(certArgument);
            
            // Дополнительные настройки для обхода проблем
            command.add("--insecure");
            command.add("--location");
            
            // Опции для вывода
            command.add("--silent");
            command.add("--show-error");
            command.add("--write-out");
            command.add("%{http_code}");
            command.add("--output");
            command.add(tempBodyFile.toString());
            
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
                // Для тела запроса создаем временный файл
                Path tempInputFile = Files.createTempFile("gost_input", ".txt");
                Files.writeString(tempInputFile, body, java.nio.charset.StandardCharsets.UTF_8);
                tempInputFile.toFile().deleteOnExit();
                command.add("--data-binary");
                command.add("@" + tempInputFile.toString());
            }
            
            // URL - проверяем и исправляем если нужно
            String fixedUrl = fixUrl(url);
            command.add(fixedUrl);
            
            // Логируем команду для отладки (без пароля)
            System.out.println("🔐 Выполняется GOST команда: curl --cert [временный_файл] " + fixedUrl);
            
            // Выполняем команду
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);
            
            Process process = processBuilder.start();
            
            // Читаем вывод процесса
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder processOutput = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                processOutput.append(line).append("\n");
            }
            
            // Ждем завершения процесса
            int exitCode = process.waitFor();
            
            // Читаем тело ответа
            String responseBody = "";
            try {
                responseBody = Files.readString(tempBodyFile, java.nio.charset.StandardCharsets.UTF_8);
            } catch (IOException e) {
                System.err.println("❌ Ошибка чтения ответа: " + e.getMessage());
            }
            
            // Удаляем временный файл сертификата
            try {
                Files.deleteIfExists(tempCertFile);
            } catch (IOException e) {
                System.err.println("⚠️ Не удалось удалить временный файл сертификата: " + e.getMessage());
            }
            
            // Получаем статус код
            int statusCode = extractStatusCode(processOutput.toString(), exitCode);
            
            if (exitCode != 0) {
                System.err.println("❌ GOST curl exited with code: " + exitCode);
                System.err.println("Вывод curl: " + processOutput);
                return new HttpApiClient.ApiResponse(500, "Curl error: " + processOutput, Map.of());
            }
            
            return new HttpApiClient.ApiResponse(statusCode, responseBody, Map.of());
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка GOST запроса: " + e.getMessage());
            e.printStackTrace();
            return new HttpApiClient.ApiResponse(500, "GOST Error: " + e.getMessage(), Map.of());
        }
    }
    
    /**
     * Копирует сертификат во временную директорию с простым путем
     */
    private Path copyCertToTempLocation() {
        try {
            // Создаем временный файл с расширением .pfx
            Path tempCert = Files.createTempFile("gost_cert", ".pfx");
            tempCert.toFile().deleteOnExit();
            
            // Копируем содержимое оригинального сертификата
            File originalCert = new File(pfxPath);
            if (!originalCert.exists()) {
                System.err.println("❌ Исходный сертификат не найден: " + pfxPath);
                return null;
            }
            
            Files.copy(originalCert.toPath(), tempCert, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            System.out.println("✅ Сертификат скопирован во временный файл: " + tempCert);
            
            return tempCert;
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка копирования сертификата: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Исправляет URL если есть проблемы с портом
     */
    private String fixUrl(String url) {
        // Убираем лишние пробелы
        String fixed = url.trim();
        
        // Проверяем URL на наличие нестандартных символов
        if (fixed.contains(" ")) {
            fixed = fixed.replace(" ", "");
        }
        
        System.out.println("🔗 Исправленный URL: " + fixed);
        return fixed;
    }
    
    /**
     * Извлекает статус код из вывода curl
     */
    private int extractStatusCode(String curlOutput, int exitCode) {
        // По умолчанию 500 если не удалось определить
        int statusCode = 500;
        
        try {
            // Ищем последнюю строку с тремя цифрами (HTTP статус)
            String[] lines = curlOutput.split("\n");
            for (int i = lines.length - 1; i >= 0; i--) {
                String line = lines[i].trim();
                if (line.matches("^\\d{3}$")) {
                    statusCode = Integer.parseInt(line);
                    break;
                }
            }
            
            // Если не нашли в выводе, используем exit code как индикатор
            if (statusCode == 500 && exitCode == 0) {
                statusCode = 200; // Предполагаем успех если curl завершился без ошибок
            }
            
        } catch (Exception e) {
            System.err.println("❌ Ошибка извлечения статус кода: " + e.getMessage());
        }
        
        return statusCode;
    }
}