package core;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ScannerManager {
    private final ExecutorService executor;
    private final WebServer webServer;
    private boolean isScanning = false;

    public ScannerManager(WebServer webServer) {
        this.webServer = webServer;
        this.executor = Executors.newSingleThreadExecutor();
    }

    public void startScan() {
        if (isScanning) {
            webServer.broadcastMessage("error", "Сканирование уже выполняется");
            return;
        }

        isScanning = true;
        executor.submit(() -> {
            try {
                webServer.broadcastMessage("scan_started", "Сканирование запущено");
                // Здесь будет логика сканирования
                Thread.sleep(5000); // Имитация сканирования
                webServer.broadcastMessage("scan_completed", "Сканирование завершено");
            } catch (Exception e) {
                webServer.broadcastMessage("scan_error", "Ошибка: " + e.getMessage());
            } finally {
                isScanning = false;
            }
        });
    }

    public boolean isScanning() {
        return isScanning;
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}