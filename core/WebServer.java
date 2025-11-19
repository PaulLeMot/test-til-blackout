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
import java.util.ArrayList;

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

        // НОВЫЕ ENDPOINTS ДЛЯ ГРАФА API
        server.createContext("/api/graph", new ApiGraphHandler());
        server.createContext("/api/test", new ApiTestHandler());

        server.setExecutor(null);
        server.start();
        System.out.println("✅ Web server started on http://localhost:" + port);
        System.out.println("🔌 API endpoints available:");
        System.out.println("   - POST /api/v1/scan     - Start security scan");
        System.out.println("   - GET  /api/v1/status   - Check scan status");
        System.out.println("   - GET  /api/v1/results  - Get scan results");
        System.out.println("   - GET  /api/graph       - Get API graph data");
        System.out.println("   - POST /api/test        - Test API endpoint");
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

    // НОВЫЙ ОБРАБОТЧИК ДЛЯ ГРАФА API
    class ApiGraphHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    // Получаем параметры из запроса
                    String query = exchange.getRequestURI().getQuery();
                    String specUrl = null;

                    if (query != null) {
                        for (String pair : query.split("&")) {
                            String[] keyValue = pair.split("=");
                            if (keyValue.length == 2 && "spec".equals(keyValue[0])) {
                                specUrl = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                            }
                        }
                    }

                    if (specUrl == null) {
                        sendResponse(exchange, 400, "{\"error\": \"Missing spec parameter\"}");
                        return;
                    }

                    // Загружаем и парсим OpenAPI спецификацию
                    List<ApiEndpoint> endpoints = loadEndpointsFromSpec(specUrl);
                    Map<String, Object> graphData = buildGraphData(endpoints, specUrl);

                    String response = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(graphData);

                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                    exchange.sendResponseHeaders(200, response.getBytes().length);

                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    sendResponse(exchange, 500, "{\"error\": \"Failed to load API graph: " + e.getMessage() + "\"}");
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private List<ApiEndpoint> loadEndpointsFromSpec(String specUrl) {
            try {
                OpenApiSpecLoader loader = new OpenApiSpecLoader(specUrl);
                return loader.extractEndpoints();
            } catch (Exception e) {
                System.err.println("❌ Error loading OpenAPI spec: " + e.getMessage());
                return new ArrayList<>();
            }
        }

        private Map<String, Object> buildGraphData(List<ApiEndpoint> endpoints, String specUrl) {
            Map<String, Object> graph = new HashMap<>();

            List<Map<String, Object>> nodes = new ArrayList<>();
            List<Map<String, Object>> edges = new ArrayList<>();

            // Группируем эндпоинты по тегам
            Map<String, List<ApiEndpoint>> endpointsByTag = new HashMap<>();
            for (ApiEndpoint endpoint : endpoints) {
                List<String> tags = endpoint.getTags();
                if (tags == null || tags.isEmpty()) {
                    tags = java.util.List.of("default");
                }

                for (String tag : tags) {
                    endpointsByTag.computeIfAbsent(tag, k -> new ArrayList<>()).add(endpoint);
                }
            }

            // Создаем узлы для каждого эндпоинта
            int nodeId = 1;
            Map<String, Integer> nodeIdMap = new HashMap<>();

            for (ApiEndpoint endpoint : endpoints) {
                String nodeKey = endpoint.getMethod() + ":" + endpoint.getPath();
                Map<String, Object> node = new HashMap<>();
                node.put("id", nodeId);
                node.put("label", endpoint.getMethod() + "\\n" + endpoint.getPath());
                node.put("title", endpoint.getSummary() != null ? endpoint.getSummary() : endpoint.getPath());
                node.put("method", endpoint.getMethod());
                node.put("path", endpoint.getPath());
                node.put("summary", endpoint.getSummary());
                node.put("description", endpoint.getDescription());

                // Определяем группу на основе тегов
                String group = "default";
                if (endpoint.getTags() != null && !endpoint.getTags().isEmpty()) {
                    group = endpoint.getTags().get(0);
                }
                node.put("group", group);

                // Цвет в зависимости от метода HTTP
                String color = getColorForMethod(endpoint.getMethod());
                node.put("color", color);

                nodes.add(node);
                nodeIdMap.put(nodeKey, nodeId);
                nodeId++;
            }

            // Создаем связи между эндпоинтами с общими тегами
            for (Map.Entry<String, List<ApiEndpoint>> entry : endpointsByTag.entrySet()) {
                List<ApiEndpoint> tagEndpoints = entry.getValue();

                // Связываем эндпоинты в пределах одной группы
                for (int i = 0; i < tagEndpoints.size(); i++) {
                    for (int j = i + 1; j < tagEndpoints.size(); j++) {
                        ApiEndpoint e1 = tagEndpoints.get(i);
                        ApiEndpoint e2 = tagEndpoints.get(j);

                        String key1 = e1.getMethod() + ":" + e1.getPath();
                        String key2 = e2.getMethod() + ":" + e2.getPath();

                        Integer fromId = nodeIdMap.get(key1);
                        Integer toId = nodeIdMap.get(key2);

                        if (fromId != null && toId != null) {
                            Map<String, Object> edge = new HashMap<>();
                            edge.put("from", fromId);
                            edge.put("to", toId);
                            edge.put("value", 1);
                            edges.add(edge);
                        }
                    }
                }
            }

            graph.put("nodes", nodes);
            graph.put("edges", edges);
            graph.put("specUrl", specUrl);
            graph.put("totalEndpoints", endpoints.size());
            graph.put("totalTags", endpointsByTag.size());

            return graph;
        }

        private String getColorForMethod(String method) {
            switch (method.toUpperCase()) {
                case "GET": return "#61affe";
                case "POST": return "#49cc90";
                case "PUT": return "#fca130";
                case "DELETE": return "#f93e3e";
                case "PATCH": return "#50e3c2";
                default: return "#9012fe";
            }
        }

        private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
    }

    // НОВЫЙ ОБРАБОТЧИК ДЛЯ ТЕСТИРОВАНИЯ API
    class ApiTestHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                    Map<String, Object> testRequest = new com.fasterxml.jackson.databind.ObjectMapper().readValue(requestBody, Map.class);

                    String method = (String) testRequest.get("method");
                    String url = (String) testRequest.get("url");
                    Map<String, String> headers = (Map<String, String>) testRequest.get("headers");
                    String body = (String) testRequest.get("body");

                    if (method == null || url == null) {
                        sendResponse(exchange, 400, "{\"error\": \"Method and URL are required\"}");
                        return;
                    }

                    // Используем существующий HttpApiClient
                    HttpApiClient client = new HttpApiClient();
                    Object response = client.executeRequest(method, url, body, headers);

                    String responseJson = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(response);

                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                    exchange.sendResponseHeaders(200, responseJson.getBytes().length);

                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(responseJson.getBytes());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    sendResponse(exchange, 500, "{\"error\": \"API test failed: " + e.getMessage() + "\"}");
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
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
                    Document document = new Document(PageSize.A4);

                    try {
                        PdfWriter writer = PdfWriter.getInstance(document, baos);
                        document.open();

                        // Создаем шрифт с поддержкой кириллицы
                        BaseFont baseFont = getBaseFont();
                        Font titleFont = new Font(baseFont, 16, Font.BOLD);
                        Font headerFont = new Font(baseFont, 12, Font.BOLD);
                        Font normalFont = new Font(baseFont, 10, Font.NORMAL);
                        Font boldFont = new Font(baseFont, 10, Font.BOLD);
                        Font smallFont = new Font(baseFont, 9, Font.NORMAL);

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
                        Paragraph statsTitle = new Paragraph("Статистика:", headerFont);
                        statsTitle.setSpacingAfter(5);
                        document.add(statsTitle);

                        document.add(new Paragraph("Всего уязвимостей: " + stats.get("total"), normalFont));
                        document.add(new Paragraph("Критические: " + stats.get("critical"), normalFont));
                        document.add(new Paragraph("Высокие: " + stats.get("high"), normalFont));
                        document.add(new Paragraph("Средние: " + stats.get("medium"), normalFont));
                        document.add(new Paragraph("Низкие: " + stats.get("low"), normalFont));

                        document.add(new Paragraph(" "));
                        document.add(new Paragraph(" "));

                        // Детальная информация по уязвимостям
                        if (!results.isEmpty()) {
                            Paragraph detailsTitle = new Paragraph("Детали уязвимостей:", headerFont);
                            detailsTitle.setSpacingAfter(15);
                            document.add(detailsTitle);

                            for (int i = 0; i < results.size(); i++) {
                                Map<String, Object> result = results.get(i);

                                // Создаем раздел для каждой уязвимости
                                addVulnerabilitySection(document, result, i + 1, baseFont);

                                // Добавляем разрыв страницы после каждой 3-й уязвимости для лучшей читаемости
                                if ((i + 1) % 3 == 0 && i < results.size() - 1) {
                                    document.newPage();
                                }
                            }
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

        private BaseFont getBaseFont() throws DocumentException, IOException {
            try {
                // Попробуем разные пути к шрифтам
                String[] fontPaths = {
                        "c:/windows/fonts/arial.ttf",
                        "c:/windows/fonts/tahoma.ttf",
                        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
                        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
                };

                for (String fontPath : fontPaths) {
                    if (new File(fontPath).exists()) {
                        return BaseFont.createFont(fontPath, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
                    }
                }

                // Если шрифты не найдены, используем стандартный
                return BaseFont.createFont(BaseFont.HELVETICA, BaseFont.WINANSI, BaseFont.EMBEDDED);
            } catch (Exception e) {
                return BaseFont.createFont(BaseFont.HELVETICA, BaseFont.WINANSI, BaseFont.EMBEDDED);
            }
        }

        private void addVulnerabilitySection(Document document, Map<String, Object> result, int index, BaseFont baseFont)
                throws DocumentException {

            Font headerFont = new Font(baseFont, 12, Font.BOLD, BaseColor.DARK_GRAY);
            Font labelFont = new Font(baseFont, 10, Font.BOLD);
            Font normalFont = new Font(baseFont, 10, Font.NORMAL);
            Font proofFont = new Font(baseFont, 9, Font.NORMAL, BaseColor.DARK_GRAY);
            Font recommendationFont = new Font(baseFont, 10, Font.NORMAL, new BaseColor(0, 100, 0)); // Темно-зеленый

            // Заголовок уязвимости с номером
            Paragraph vulnHeader = new Paragraph(index + ". " + getStringValue(result.get("vulnerabilityTitle")), headerFont);
            vulnHeader.setSpacingAfter(8);
            document.add(vulnHeader);

            // Основная информация в таблице
            PdfPTable infoTable = new PdfPTable(2);
            infoTable.setWidthPercentage(100);
            infoTable.setSpacingBefore(5);
            infoTable.setSpacingAfter(10);

            // Настройка ширины колонок
            float[] columnWidths = {30f, 70f};
            infoTable.setWidths(columnWidths);

            addInfoRow(infoTable, "Банк:", getStringValue(result.get("bankName")), labelFont, normalFont);

            String severity = getStringValue(result.get("severity"));
            Font severityFont = getSeverityFont(baseFont, severity);
            addInfoRow(infoTable, "Уровень критичности:", severity, labelFont, severityFont);

            addInfoRow(infoTable, "Категория:", getStringValue(result.get("category")), labelFont, normalFont);
            addInfoRow(infoTable, "Статус код:", getStringValue(result.get("statusCode")), labelFont, normalFont);
            addInfoRow(infoTable, "Сканер:", getStringValue(result.get("scannerName")), labelFont, normalFont);
            addInfoRow(infoTable, "Дата обнаружения:", getStringValue(result.get("scanDate")), labelFont, normalFont);

            document.add(infoTable);

            // Раздел с доказательством
            String proof = getStringValue(result.get("proof"));
            if (!proof.isEmpty() && !proof.equals("N/A") && !proof.equals("Нет информации")) {
                Paragraph proofTitle = new Paragraph("Доказательство:", labelFont);
                proofTitle.setSpacingAfter(3);
                document.add(proofTitle);

                // Обрабатываем доказательство для лучшего отображения
                String formattedProof = formatProofText(proof);
                Paragraph proofContent = new Paragraph(formattedProof, proofFont);
                proofContent.setSpacingAfter(10);
                document.add(proofContent);
            }

            // Раздел с рекомендациями
            String recommendation = getStringValue(result.get("recommendation"));
            if (!recommendation.isEmpty() && !recommendation.equals("N/A") && !recommendation.equals("Нет рекомендаций")) {
                Paragraph recTitle = new Paragraph("Рекомендации по устранению:", labelFont);
                recTitle.setSpacingAfter(3);
                document.add(recTitle);

                Paragraph recContent = new Paragraph(recommendation, recommendationFont);
                recContent.setSpacingAfter(15);
                document.add(recContent);
            }

            // Разделительная линия между уязвимостями
            Paragraph separator = new Paragraph("_________________________________________________________________________");
            separator.setSpacingBefore(5);
            separator.setSpacingAfter(15);
            document.add(separator);
        }

        private void addInfoRow(PdfPTable table, String label, String value, Font labelFont, Font valueFont) {
            PdfPCell labelCell = new PdfPCell(new Phrase(label, labelFont));
            labelCell.setBorderWidth(0);
            labelCell.setPadding(3);
            labelCell.setBackgroundColor(new BaseColor(240, 240, 240));

            PdfPCell valueCell = new PdfPCell(new Phrase(value, valueFont));
            valueCell.setBorderWidth(0);
            valueCell.setPadding(3);

            table.addCell(labelCell);
            table.addCell(valueCell);
        }

        private Font getSeverityFont(BaseFont baseFont, String severity) {
            switch (severity.toUpperCase()) {
                case "CRITICAL":
                    return new Font(baseFont, 10, Font.BOLD, BaseColor.RED);
                case "HIGH":
                    return new Font(baseFont, 10, Font.BOLD, new BaseColor(255, 140, 0)); // Orange
                case "MEDIUM":
                    return new Font(baseFont, 10, Font.BOLD, BaseColor.ORANGE);
                case "LOW":
                    return new Font(baseFont, 10, Font.NORMAL, new BaseColor(0, 128, 0)); // Green
                default:
                    return new Font(baseFont, 10, Font.NORMAL, BaseColor.BLACK);
            }
        }

        private String formatProofText(String proof) {
            // Упрощаем текст доказательства для лучшей читаемости в PDF
            if (proof.length() > 500) {
                proof = proof.substring(0, 500) + "... [сокращено]";
            }
            return proof.replace("\n", " ").replace("  ", " ");
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