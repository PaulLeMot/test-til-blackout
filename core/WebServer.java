package core;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

// Добавляем импорты для PDF
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;

public class WebServer {
    private HttpServer server;
    private int port;
    private PostgresManager databaseManager;
    private final Set<WebSocketConnection> webSocketConnections = new CopyOnWriteArraySet<>();
    private ScanLauncher scanLauncher;
    private ApiController apiController; // ДОБАВЛЕНО: ApiController для CI/CD

    public WebServer(int port) {
        this.port = port;
        this.databaseManager = new PostgresManager();
    }

    public void setScanLauncher(ScanLauncher scanLauncher) {
        this.scanLauncher = scanLauncher;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);

        // ДОБАВЛЕНО: Инициализация ApiController
        this.apiController = new ApiController(
                new ScannerService(this, databaseManager),
                databaseManager
        );

        // Статические файлы из папки webapp
        server.createContext("/", new StaticFileHandler());

        // API endpoints
        server.createContext("/api/scan/start", new ScanStartHandler());
        server.createContext("/api/scan/results", new ScanResultsHandler());
        server.createContext("/api/scan/stats", new ScanStatsHandler());
        server.createContext("/api/scan/clear", new ClearResultsHandler());
        server.createContext("/api/scan/export/pdf", new ExportPdfHandler());

        // Новые endpoints для работы с сессиями
        server.createContext("/api/sessions/list", new SessionsListHandler());
        server.createContext("/api/sessions/compare", new SessionsCompareHandler());

        // ДОБАВЛЕНО: API endpoints для CI/CD интеграции
        server.createContext("/api/v1/scan", apiController.createScanHandler());
        server.createContext("/api/v1/status", apiController.createStatusHandler());
        server.createContext("/api/v1/results", apiController.createResultsHandler());

        server.setExecutor(null);
        server.start();
        System.out.println("✅ Web server started on http://localhost:" + port);
        System.out.println("🔌 API endpoints available:");
        System.out.println("   - POST /api/v1/scan     - Start security scan");
        System.out.println("   - GET  /api/v1/status   - Check scan status");
        System.out.println("   - GET  /api/v1/results  - Get scan results");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
        if (databaseManager != null) {
            databaseManager.close();
        }
    }

    // Старый метод для обратной совместимости
    public void saveScanResult(String bankName, String title, String severity,
                               String category, String statusCode, String proof,
                               String recommendation, String scannerName) {
        saveScanResult(bankName, title, severity, category, statusCode, proof, recommendation, scannerName, "default_session");
    }

    // Новый метод с поддержкой сессий
    public void saveScanResult(String bankName, String title, String severity,
                               String category, String statusCode, String proof,
                               String recommendation, String scannerName, String scanSessionId) {
        databaseManager.saveVulnerability(bankName, title, severity, category,
                statusCode, proof, recommendation, scannerName, scanSessionId);
    }

    public void broadcastMessage(String type, Object data) {
        System.out.println("Broadcasting: " + type + " - " + data);
    }

    static class WebSocketConnection {
    }

    // Новый обработчик для экспорта PDF
    class ExportPdfHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    String query = exchange.getRequestURI().getQuery();
                    String severityFilter = null;
                    String categoryFilter = null;
                    String bankFilter = null;
                    String sessionFilter = null;

                    if (query != null) {
                        for (String pair : query.split("&")) {
                            String[] keyValue = pair.split("=");
                            if (keyValue.length == 2) {
                                String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                                String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);

                                switch (key) {
                                    case "severity":
                                        severityFilter = value;
                                        break;
                                    case "category":
                                        categoryFilter = value;
                                        break;
                                    case "bank":
                                        bankFilter = value;
                                        break;
                                    case "session":
                                        sessionFilter = value;
                                        break;
                                }
                            }
                        }
                    }

                    // Получаем отфильтрованные результаты
                    List<Map<String, Object>> results = databaseManager.getScanResults(
                            severityFilter, categoryFilter, bankFilter, sessionFilter
                    );

                    // Создаем PDF документ
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    Document document = new Document(PageSize.A4.rotate()); // Альбомная ориентация для таблицы

                    try {
                        PdfWriter writer = PdfWriter.getInstance(document, baos);
                        document.open();

                        // Создаем шрифт с поддержкой кириллицы
                        BaseFont baseFont = BaseFont.createFont(
                                "c:/windows/fonts/arial.ttf", // Путь к шрифту Arial в Windows
                                BaseFont.IDENTITY_H,
                                BaseFont.EMBEDDED
                        );

                        // Альтернативные пути к шрифтам для разных ОС
                        if (!new File("c:/windows/fonts/arial.ttf").exists()) {
                            try {
                                baseFont = BaseFont.createFont(
                                        "/usr/share/fonts/truetype/freefont/FreeSans.ttf", // Linux
                                        BaseFont.IDENTITY_H,
                                        BaseFont.EMBEDDED
                                );
                            } catch (Exception e) {
                                // Если шрифты не найдены, используем стандартный без поддержки кириллицы
                                baseFont = BaseFont.createFont(BaseFont.HELVETICA, BaseFont.WINANSI, BaseFont.EMBEDDED);
                            }
                        }

                        Font titleFont = new Font(baseFont, 16, Font.BOLD);
                        Font headerFont = new Font(baseFont, 10, Font.BOLD);
                        Font normalFont = new Font(baseFont, 8, Font.NORMAL);
                        Font boldFont = new Font(baseFont, 8, Font.BOLD);

                        // Заголовок
                        Paragraph title = new Paragraph("Отчет о сканировании безопасности", titleFont);
                        title.setAlignment(Element.ALIGN_CENTER);
                        title.setSpacingAfter(20);
                        document.add(title);

                        // Дата генерации
                        Paragraph date = new Paragraph(
                                "Сгенерировано: " + new java.util.Date().toString(),
                                normalFont
                        );
                        date.setSpacingAfter(10);
                        document.add(date);

                        // Информация о фильтрах
                        if (severityFilter != null || categoryFilter != null || bankFilter != null) {
                            StringBuilder filterInfo = new StringBuilder("Примененные фильтры: ");
                            if (severityFilter != null) filterInfo.append("Уровень: ").append(severityFilter).append("; ");
                            if (categoryFilter != null) filterInfo.append("Категория: ").append(categoryFilter).append("; ");
                            if (bankFilter != null) filterInfo.append("Банк: ").append(bankFilter).append("; ");

                            Paragraph filters = new Paragraph(filterInfo.toString(), normalFont);
                            filters.setSpacingAfter(10);
                            document.add(filters);
                        }

                        // Статистика
                        Map<String, Object> stats = databaseManager.getStats();
                        Paragraph statsTitle = new Paragraph("Статистика:", boldFont);
                        statsTitle.setSpacingAfter(5);
                        document.add(statsTitle);

                        document.add(new Paragraph("Всего уязвимостей: " + stats.get("total"), normalFont));
                        document.add(new Paragraph("Критические: " + stats.get("critical"), normalFont));
                        document.add(new Paragraph("Высокие: " + stats.get("high"), normalFont));
                        document.add(new Paragraph("Средние: " + stats.get("medium"), normalFont));
                        document.add(new Paragraph("Низкие: " + stats.get("low"), normalFont));

                        document.add(new Paragraph(" "));
                        document.add(new Paragraph(" "));

                        // Таблица с уязвимостями
                        if (!results.isEmpty()) {
                            Paragraph tableTitle = new Paragraph("Детали уязвимостей:", boldFont);
                            tableTitle.setSpacingAfter(10);
                            document.add(tableTitle);

                            PdfPTable table = new PdfPTable(6);
                            table.setWidthPercentage(100);
                            table.setSpacingBefore(10);

                            // Устанавливаем ширины колонок
                            float[] columnWidths = {2f, 3f, 1.5f, 2f, 1f, 1.5f};
                            table.setWidths(columnWidths);

                            // Заголовки таблицы
                            String[] headers = {"Банк", "Уязвимость", "Уровень", "Категория", "Статус", "Дата"};
                            for (String header : headers) {
                                PdfPCell cell = new PdfPCell(new Phrase(header, headerFont));
                                cell.setBackgroundColor(BaseColor.LIGHT_GRAY);
                                cell.setHorizontalAlignment(Element.ALIGN_CENTER);
                                cell.setPadding(5);
                                table.addCell(cell);
                            }

                            // Данные таблицы
                            for (Map<String, Object> result : results) {
                                addTableCell(table, getStringValue(result.get("bankName")), normalFont);
                                addTableCell(table, getStringValue(result.get("vulnerabilityTitle")), normalFont);

                                // Цвета для уровней серьезности
                                String severity = getStringValue(result.get("severity"));
                                Font severityFont = normalFont;
                                if ("CRITICAL".equals(severity)) {
                                    severityFont = new Font(baseFont, 8, Font.BOLD, BaseColor.RED);
                                } else if ("HIGH".equals(severity)) {
                                    severityFont = new Font(baseFont, 8, Font.BOLD, BaseColor.ORANGE);
                                }
                                addTableCell(table, severity, severityFont);

                                addTableCell(table, getStringValue(result.get("category")), normalFont);
                                addTableCell(table, getStringValue(result.get("statusCode")), normalFont);
                                addTableCell(table, getStringValue(result.get("scanDate")), normalFont);
                            }

                            document.add(table);
                        } else {
                            document.add(new Paragraph("Нет данных для отображения", normalFont));
                        }

                        document.close();

                        // Отправляем PDF
                        exchange.getResponseHeaders().set("Content-Type", "application/pdf");
                        exchange.getResponseHeaders().set("Content-Disposition",
                                "attachment; filename=security_scan_report_" +
                                        System.currentTimeMillis() + ".pdf");
                        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                        exchange.sendResponseHeaders(200, baos.size());

                        try (OutputStream os = exchange.getResponseBody()) {
                            baos.writeTo(os);
                        }

                    } catch (DocumentException e) {
                        throw new IOException("PDF generation error: " + e.getMessage(), e);
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                    String response = "{\"error\": \"Failed to generate PDF: " + e.getMessage() + "\"}";
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(500, response.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private void addTableCell(PdfPTable table, String text, Font font) {
            PdfPCell cell = new PdfPCell(new Phrase(text, font));
            cell.setPadding(4);
            cell.setHorizontalAlignment(Element.ALIGN_LEFT);
            table.addCell(cell);
        }

        private String getStringValue(Object value) {
            return value != null ? value.toString() : "N/A";
        }
    }

    class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/")) path = "/index.html";

            File file = new File("webapp" + path);
            if (!file.exists()) {
                send404(exchange);
                return;
            }

            String mimeType = getMimeType(file.getName());
            exchange.getResponseHeaders().set("Content-Type", mimeType);
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, file.length());

            try (OutputStream os = exchange.getResponseBody();
                 FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
        }

        private String getMimeType(String filename) {
            if (filename.endsWith(".html")) return "text/html";
            if (filename.endsWith(".css")) return "text/css";
            if (filename.endsWith(".js")) return "application/javascript";
            if (filename.endsWith(".png")) return "image/png";
            if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) return "image/jpeg";
            return "text/plain";
        }

        private void send404(HttpExchange exchange) throws IOException {
            String response = "404 Not Found";
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(404, response.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
    }

    class ScanStartHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                // Читаем тело запроса с конфигурацией
                String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

                try {
                    System.out.println("Received configuration: " + requestBody);

                    if (scanLauncher != null) {
                        scanLauncher.startScan(requestBody);
                        String response = "{\"status\": \"success\", \"message\": \"Сканирование запущено с пользовательской конфигурацией\"}";

                        exchange.getResponseHeaders().set("Content-Type", "application/json");
                        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                        exchange.sendResponseHeaders(200, response.length());

                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(response.getBytes());
                        }
                    } else {
                        String response = "{\"status\": \"error\", \"message\": \"ScanLauncher not initialized\"}";
                        exchange.getResponseHeaders().set("Content-Type", "application/json");
                        exchange.sendResponseHeaders(500, response.length());
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(response.getBytes());
                        }
                    }
                } catch (Exception e) {
                    String response = "{\"status\": \"error\", \"message\": \"Invalid configuration: \" + e.getMessage()}";
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(400, response.length());
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    class ScanResultsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String query = exchange.getRequestURI().getQuery();
                // Объявляем переменные в начале метода
                String severityFilter = null;
                String categoryFilter = null;
                String bankFilter = null;
                String sessionFilter = null; // Добавляем sessionFilter

                if (query != null) {
                    for (String pair : query.split("&")) {
                        String[] keyValue = pair.split("=");
                        if (keyValue.length == 2) {
                            String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                            String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);

                            switch (key) {
                                case "severity":
                                    severityFilter = value;
                                    break;
                                case "category":
                                    categoryFilter = value;
                                    break;
                                case "bank":
                                    bankFilter = value;
                                    break;
                                case "session":
                                    sessionFilter = value; // Устанавливаем значение
                                    break;
                            }
                        }
                    }
                }

                // Теперь sessionFilter доступна здесь, даже если query был null
                List<Map<String, Object>> results = databaseManager.getScanResults(
                        severityFilter, categoryFilter, bankFilter, sessionFilter
                );

                String response = convertResultsToJson(results);

                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, response.getBytes().length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private String convertResultsToJson(List<Map<String, Object>> results) {
            StringBuilder json = new StringBuilder("[");
            for (int i = 0; i < results.size(); i++) {
                Map<String, Object> result = results.get(i);
                json.append("{");
                json.append("\"id\":").append(result.get("id")).append(",");
                json.append("\"bankName\":\"").append(escapeJson(result.get("bankName").toString())).append("\",");
                json.append("\"vulnerabilityTitle\":\"").append(escapeJson(result.get("vulnerabilityTitle").toString())).append("\",");
                json.append("\"severity\":\"").append(result.get("severity")).append("\",");
                json.append("\"category\":\"").append(result.get("category")).append("\",");
                json.append("\"statusCode\":\"").append(result.get("statusCode")).append("\",");
                json.append("\"scanDate\":\"").append(escapeJson(result.get("scanDate").toString())).append("\",");
                json.append("\"proof\":\"").append(escapeJson(result.get("proof").toString())).append("\",");
                json.append("\"recommendation\":\"").append(escapeJson(result.get("recommendation").toString())).append("\",");
                json.append("\"scannerName\":\"").append(result.get("scannerName")).append("\",");
                json.append("\"scanSessionId\":\"").append(result.get("scanSessionId") != null ? result.get("scanSessionId") : "").append("\"");
                json.append("}");
                if (i < results.size() - 1) json.append(",");
            }
            json.append("]");
            return json.toString();
        }

        private String escapeJson(String str) {
            return str.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
        }
    }

    class SessionsCompareHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String query = exchange.getRequestURI().getQuery();
                String sessionId1 = null, sessionId2 = null;

                if (query != null) {
                    for (String pair : query.split("&")) {
                        String[] keyValue = pair.split("=");
                        if (keyValue.length == 2) {
                            String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                            String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);

                            if ("session1".equals(key)) sessionId1 = value;
                            else if ("session2".equals(key)) sessionId2 = value;
                        }
                    }
                }

                if (sessionId1 != null && sessionId2 != null) {
                    Map<String, Object> comparison = databaseManager.compareSessions(sessionId1, sessionId2);
                    String response = convertComparisonToJson(comparison);

                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                    exchange.sendResponseHeaders(200, response.getBytes().length);

                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                } else {
                    String response = "{\"error\": \"Missing session parameters\"}";
                    exchange.sendResponseHeaders(400, response.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        @SuppressWarnings("unchecked")
        private String convertComparisonToJson(Map<String, Object> comparison) {
            StringBuilder json = new StringBuilder("{");

            // Статистика по сессиям
            json.append("\"session1Stats\":").append(mapToJson((Map<String, Integer>)comparison.get("session1Stats"))).append(",");
            json.append("\"session2Stats\":").append(mapToJson((Map<String, Integer>)comparison.get("session2Stats"))).append(",");
            json.append("\"newCount\":").append(comparison.get("newCount")).append(",");
            json.append("\"fixedCount\":").append(comparison.get("fixedCount")).append(",");

            // Новые уязвимости
            json.append("\"newVulnerabilities\":[");
            List<Map<String, Object>> newVulns = (List<Map<String, Object>>) comparison.get("newVulnerabilities");
            for (int i = 0; i < newVulns.size(); i++) {
                Map<String, Object> vuln = newVulns.get(i);
                json.append("{");
                json.append("\"bankName\":\"").append(escapeJson(vuln.get("bankName").toString())).append("\",");
                json.append("\"vulnerabilityTitle\":\"").append(escapeJson(vuln.get("vulnerabilityTitle").toString())).append("\",");
                json.append("\"severity\":\"").append(vuln.get("severity")).append("\",");
                json.append("\"category\":\"").append(vuln.get("category")).append("\",");
                json.append("\"scannerName\":\"").append(vuln.get("scannerName")).append("\",");
                json.append("\"scanDate\":\"").append(vuln.get("scanDate")).append("\"");
                json.append("}");
                if (i < newVulns.size() - 1) json.append(",");
            }
            json.append("],");

            // Исправленные уязвимости
            json.append("\"fixedVulnerabilities\":[");
            List<Map<String, Object>> fixedVulns = (List<Map<String, Object>>) comparison.get("fixedVulnerabilities");
            for (int i = 0; i < fixedVulns.size(); i++) {
                Map<String, Object> vuln = fixedVulns.get(i);
                json.append("{");
                json.append("\"bankName\":\"").append(escapeJson(vuln.get("bankName").toString())).append("\",");
                json.append("\"vulnerabilityTitle\":\"").append(escapeJson(vuln.get("vulnerabilityTitle").toString())).append("\",");
                json.append("\"severity\":\"").append(vuln.get("severity")).append("\",");
                json.append("\"category\":\"").append(vuln.get("category")).append("\",");
                json.append("\"scannerName\":\"").append(vuln.get("scannerName")).append("\",");
                json.append("\"scanDate\":\"").append(vuln.get("scanDate")).append("\"");
                json.append("}");
                if (i < fixedVulns.size() - 1) json.append(",");
            }
            json.append("]");

            json.append("}");
            return json.toString();
        }

        private String mapToJson(Map<String, Integer> map) {
            StringBuilder json = new StringBuilder("{");
            int i = 0;
            for (Map.Entry<String, Integer> entry : map.entrySet()) {
                json.append("\"").append(entry.getKey()).append("\":").append(entry.getValue());
                if (i++ < map.size() - 1) json.append(",");
            }
            json.append("}");
            return json.toString();
        }

        private String escapeJson(String str) {
            if (str == null) return "";
            return str.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
        }
    }

    class ClearResultsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                databaseManager.clearResults();
                String response = "{\"status\": \"success\", \"message\": \"All results cleared\"}";

                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, response.getBytes().length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    class SessionsListHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                List<Map<String, Object>> sessions = databaseManager.getAllSessions();
                String response = convertSessionsToJson(sessions);

                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, response.getBytes().length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private String convertSessionsToJson(List<Map<String, Object>> sessions) {
            StringBuilder json = new StringBuilder("[");
            for (int i = 0; i < sessions.size(); i++) {
                Map<String, Object> session = sessions.get(i);
                json.append("{");
                json.append("\"sessionId\":\"").append(session.get("sessionId")).append("\",");
                json.append("\"sessionName\":\"").append(WebServer.this.escapeJson(session.get("sessionName").toString())).append("\",");
                json.append("\"banksCount\":").append(session.get("banksCount")).append(",");
                json.append("\"vulnerabilitiesCount\":").append(session.get("vulnerabilitiesCount")).append(",");
                json.append("\"startTime\":\"").append(session.get("startTime")).append("\",");
                json.append("\"endTime\":\"").append(session.get("endTime") != null ? session.get("endTime") : "").append("\",");
                json.append("\"status\":\"").append(session.get("status")).append("\"");
                json.append("}");
                if (i < sessions.size() - 1) json.append(",");
            }
            json.append("]");
            return json.toString();
        }
    }

    class ScanStatsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> stats = databaseManager.getStats();
                String response = convertStatsToJson(stats);

                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, response.getBytes().length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        @SuppressWarnings("unchecked")
        private String convertStatsToJson(Map<String, Object> stats) {
            StringBuilder json = new StringBuilder("{");
            json.append("\"total\":").append(stats.get("total")).append(",");
            json.append("\"critical\":").append(stats.get("critical")).append(",");
            json.append("\"high\":").append(stats.get("high")).append(",");
            json.append("\"medium\":").append(stats.get("medium")).append(",");
            json.append("\"low\":").append(stats.get("low")).append(",");
            json.append("\"byCategory\":").append(mapToJson((Map<String, Integer>)stats.get("byCategory"))).append(",");
            json.append("\"byBank\":").append(mapToJson((Map<String, Integer>)stats.get("byBank")));
            json.append("}");
            return json.toString();
        }

        private String mapToJson(Map<String, Integer> map) {
            StringBuilder json = new StringBuilder("{");
            int i = 0;
            for (Map.Entry<String, Integer> entry : map.entrySet()) {
                json.append("\"").append(entry.getKey()).append("\":").append(entry.getValue());
                if (i++ < map.size() - 1) json.append(",");
            }
            json.append("}");
            return json.toString();
        }
    }

    public PostgresManager getDatabaseManager() {
        return databaseManager;
    }

    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}