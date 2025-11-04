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

public class WebServer {
    private HttpServer server;
    private int port;
    private PostgresManager databaseManager;

    public WebServer(int port) {
        this.port = port;
        this.databaseManager = new PostgresManager();
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Статические файлы из папки webapp
        server.createContext("/", new StaticFileHandler());

        // API endpoints
        server.createContext("/api/scan/start", new ScanStartHandler());
        server.createContext("/api/scan/results", new ScanResultsHandler());
        server.createContext("/api/scan/stats", new ScanStatsHandler());
        server.createContext("/api/scan/clear", new ClearResultsHandler());

        server.setExecutor(null);
        server.start();
        System.out.println("✅ Web server started on http://localhost:" + port);
        System.out.println("🌐 Open your browser and go to: http://localhost:" + port);
        System.out.println("🗄️  Connected to PostgreSQL database");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
        if (databaseManager != null) {
            databaseManager.close();
        }
    }

    // Метод для сохранения результатов сканирования из основного кода
    public void saveScanResult(String bankName, String title, String severity,
                               String category, String statusCode, String proof,
                               String recommendation, String scannerName) {
        databaseManager.saveVulnerability(bankName, title, severity, category,
                statusCode, proof, recommendation, scannerName);
    }

    class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/")) {
                path = "/index.html";
            }

            // Ищем файл в папке webapp
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
                String response = "{\"status\": \"scan_started\", \"message\": \"Запустите сканирование через основной интерфейс (Main.java)\"}";
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, response.length());

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }

                System.out.println("📢 Запустите сканирование через основной класс Main.java");
                System.out.println("📊 Результаты будут автоматически сохраняться в PostgreSQL");

            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    class ScanResultsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                // Получаем параметры фильтрации из URL
                String query = exchange.getRequestURI().getQuery();
                String severityFilter = null;
                String categoryFilter = null;
                String bankFilter = null;

                if (query != null) {
                    String[] pairs = query.split("&");
                    for (String pair : pairs) {
                        String[] keyValue = pair.split("=");
                        if (keyValue.length == 2) {
                            String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                            String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);

                            switch (key) {
                                case "severity": severityFilter = value; break;
                                case "category": categoryFilter = value; break;
                                case "bank": bankFilter = value; break;
                            }
                        }
                    }
                }

                // Получаем реальные данные из базы с фильтрами
                List<Map<String, Object>> results = databaseManager.getScanResults(severityFilter, categoryFilter, bankFilter);

                // Конвертируем в JSON
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
                json.append("\"scannerName\":\"").append(result.get("scannerName")).append("\"");
                json.append("}");
                if (i < results.size() - 1) {
                    json.append(",");
                }
            }
            json.append("]");
            return json.toString();
        }

        private String escapeJson(String str) {
            if (str == null || str.isEmpty()) return "Нет данных";            return str.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
        }
    }

    class ScanStatsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                // Получаем реальную статистику из базы
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
                if (i++ < map.size() - 1) {
                    json.append(",");
                }
            }
            json.append("}");
            return json.toString();
        }
    }

    class ClearResultsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                databaseManager.clearResults();

                String response = "{\"status\": \"success\", \"message\": \"All results cleared from database\"}";
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
}