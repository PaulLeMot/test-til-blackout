package core;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public class ApiController {
    private final ScannerService scannerService;
    private final PostgresManager databaseManager;
    private final ExecutorService executor;

    public ApiController(ScannerService scannerService, PostgresManager databaseManager) {
        this.scannerService = scannerService;
        this.databaseManager = databaseManager;
        this.executor = Executors.newCachedThreadPool();
    }

    public HttpHandler createScanHandler() {
        return new ScanHandler();
    }

    public HttpHandler createStatusHandler() {
        return new StatusHandler();
    }

    public HttpHandler createResultsHandler() {
        return new ResultsHandler();
    }

    class ScanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                handlePost(exchange);
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
            }
        }

        private void handlePost(HttpExchange exchange) throws IOException {
            try {
                String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

                // Парсим конфигурацию
                ScanConfig config = ConfigParser.parseConfig(requestBody);

                // Устанавливаем конфигурацию
                scannerService.setConfig(config);

                // Запускаем сканирование асинхронно
                CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
                    return scannerService.startScan();
                }, executor);

                Map<String, Object> response = new HashMap<>();
                response.put("status", "started");
                response.put("timestamp", new Date().toString());
                response.put("message", "Сканирование запущено");

                sendJsonResponse(exchange, 202, response);

            } catch (Exception e) {
                sendResponse(exchange, 400, "{\"error\": \"Invalid configuration: " + e.getMessage() + "\"}");
            }
        }
    }

    class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, Object> status = new HashMap<>();
                status.put("is_scanning", scannerService.isScanning());
                status.put("timestamp", new Date().toString());

                sendJsonResponse(exchange, 200, status);
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
            }
        }
    }

    class ResultsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                handleGet(exchange);
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
            }
        }

        private void handleGet(HttpExchange exchange) throws IOException {
            try {
                // Получаем параметры запроса
                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());

                String format = params.getOrDefault("format", "json");
                String severity = params.getOrDefault("severity", null);

                // Получаем результаты
                List<Map<String, Object>> results = databaseManager.getScanResults(
                        severity, null, null, null
                );

                Map<String, Object> stats = databaseManager.getStats();

                Map<String, Object> response = new HashMap<>();
                response.put("timestamp", new Date().toString());
                response.put("statistics", stats);
                response.put("vulnerabilities", results);
                response.put("count", results.size());

                if ("json".equals(format)) {
                    sendJsonResponse(exchange, 200, response);
                } else {
                    // Для других форматов можно добавить конвертацию
                    sendJsonResponse(exchange, 200, response);
                }

            } catch (Exception e) {
                sendResponse(exchange, 500, "{\"error\": \"Internal server error: " + e.getMessage() + "\"}");
            }
        }
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        if (query != null) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=");
                if (pair.length > 1) {
                    params.put(pair[0], pair[1]);
                } else {
                    params.put(pair[0], "");
                }
            }
        }
        return params;
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, Object data) throws IOException {
        String response = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(data);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, response.getBytes().length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, response.getBytes().length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }
}