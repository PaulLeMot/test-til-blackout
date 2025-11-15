package core;

import java.sql.*;
import java.util.*;
import java.text.SimpleDateFormat;

public class ScanSessionManager {
    private PostgresManager dbManager;

    public ScanSessionManager(PostgresManager dbManager) {
        this.dbManager = dbManager;
    }

    /**
     * Создает новую сессию сканирования
     */
    public String createSession(String sessionName, String configJson) {
        String sessionId = generateSessionId();

        String sql = """
            INSERT INTO scan_sessions 
            (session_id, session_name, start_time, config_json, status)
            VALUES (?, ?, CURRENT_TIMESTAMP, ?, 'RUNNING')
        """;

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, sessionId);
            pstmt.setString(2, sessionName);
            pstmt.setString(3, configJson);
            pstmt.executeUpdate();

            System.out.println("✅ Создана сессия сканирования: " + sessionId);
            return sessionId;
        } catch (SQLException e) {
            System.err.println("❌ Ошибка создания сессии: " + e.getMessage());
            return null;
        }
    }

    /**
     * Завершает сессию и сохраняет статистику
     */
    public void completeSession(String sessionId, int banksCount, int vulnerabilitiesCount) {
        String sql = """
            UPDATE scan_sessions 
            SET end_time = CURRENT_TIMESTAMP, 
                status = 'COMPLETED',
                banks_count = ?,
                vulnerabilities_count = ?
            WHERE session_id = ?
        """;

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, banksCount);
            pstmt.setInt(2, vulnerabilitiesCount);
            pstmt.setString(3, sessionId);
            pstmt.executeUpdate();

            System.out.println("✅ Сессия завершена: " + sessionId);
        } catch (SQLException e) {
            System.err.println("❌ Ошибка завершения сессии: " + e.getMessage());
        }
    }

    /**
     * Получает список всех сессий
     */
    public List<Map<String, Object>> getAllSessions() {
        List<Map<String, Object>> sessions = new ArrayList<>();
        String sql = """
            SELECT session_id, session_name, banks_count, vulnerabilities_count, 
                   start_time, end_time, status
            FROM scan_sessions 
            ORDER BY start_time DESC
        """;

        try (Connection conn = dbManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Map<String, Object> session = new HashMap<>();
                session.put("sessionId", rs.getString("session_id"));
                session.put("sessionName", rs.getString("session_name"));
                session.put("banksCount", rs.getInt("banks_count"));
                session.put("vulnerabilitiesCount", rs.getInt("vulnerabilities_count"));
                session.put("startTime", rs.getTimestamp("start_time").toString());
                session.put("endTime", rs.getTimestamp("end_time") != null ?
                        rs.getTimestamp("end_time").toString() : null);
                session.put("status", rs.getString("status"));
                sessions.add(session);
            }
        } catch (SQLException e) {
            System.err.println("❌ Ошибка получения сессий: " + e.getMessage());
        }

        return sessions;
    }

    /**
     * Сравнивает две сессии сканирования
     */
    public Map<String, Object> compareSessions(String sessionId1, String sessionId2) {
        Map<String, Object> comparison = new HashMap<>();

        // Получаем статистику по уязвимостям для обеих сессий
        String sql = """
            SELECT severity, COUNT(*) as count, scan_session_id
            FROM scan_results 
            WHERE scan_session_id IN (?, ?)
            GROUP BY severity, scan_session_id
            ORDER BY severity
        """;

        Map<String, Map<String, Integer>> severityStats = new HashMap<>();
        severityStats.put(sessionId1, new HashMap<>());
        severityStats.put(sessionId2, new HashMap<>());

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, sessionId1);
            pstmt.setString(2, sessionId2);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                String sessionId = rs.getString("scan_session_id");
                String severity = rs.getString("severity");
                int count = rs.getInt("count");
                severityStats.get(sessionId).put(severity, count);
            }
        } catch (SQLException e) {
            System.err.println("❌ Ошибка сравнения сессий: " + e.getMessage());
        }

        // Анализ новых/исправленных уязвимостей
        List<Map<String, Object>> newVulnerabilities = findNewVulnerabilities(sessionId1, sessionId2);
        List<Map<String, Object>> fixedVulnerabilities = findFixedVulnerabilities(sessionId1, sessionId2);

        comparison.put("session1Stats", severityStats.get(sessionId1));
        comparison.put("session2Stats", severityStats.get(sessionId2));
        comparison.put("newVulnerabilities", newVulnerabilities);
        comparison.put("fixedVulnerabilities", fixedVulnerabilities);
        comparison.put("newCount", newVulnerabilities.size());
        comparison.put("fixedCount", fixedVulnerabilities.size());

        return comparison;
    }

    private List<Map<String, Object>> findNewVulnerabilities(String oldSessionId, String newSessionId) {
        // Находим уязвимости, которые есть в новой сессии, но нет в старой
        String sql = """
            SELECT r2.* 
            FROM scan_results r2 
            WHERE r2.scan_session_id = ?
            AND NOT EXISTS (
                SELECT 1 FROM scan_results r1 
                WHERE r1.scan_session_id = ? 
                AND r1.vulnerability_title = r2.vulnerability_title 
                AND r1.bank_name = r2.bank_name
                AND r1.severity = r2.severity
            )
        """;

        return executeVulnerabilityQuery(sql, newSessionId, oldSessionId);
    }

    private List<Map<String, Object>> findFixedVulnerabilities(String oldSessionId, String newSessionId) {
        // Находим уязвимости, которые были в старой сессии, но исправлены в новой
        String sql = """
            SELECT r1.* 
            FROM scan_results r1 
            WHERE r1.scan_session_id = ?
            AND NOT EXISTS (
                SELECT 1 FROM scan_results r2 
                WHERE r2.scan_session_id = ? 
                AND r2.vulnerability_title = r1.vulnerability_title 
                AND r2.bank_name = r1.bank_name
                AND r2.severity = r1.severity
            )
        """;

        return executeVulnerabilityQuery(sql, oldSessionId, newSessionId);
    }

    private List<Map<String, Object>> executeVulnerabilityQuery(String sql, String sessionId1, String sessionId2) {
        List<Map<String, Object>> vulnerabilities = new ArrayList<>();

        try (Connection conn = dbManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, sessionId1);
            pstmt.setString(2, sessionId2);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                Map<String, Object> vuln = new HashMap<>();
                vuln.put("id", rs.getInt("id"));
                vuln.put("bankName", rs.getString("bank_name"));
                vuln.put("vulnerabilityTitle", rs.getString("vulnerability_title"));
                vuln.put("severity", rs.getString("severity"));
                vuln.put("category", rs.getString("category"));
                vuln.put("scannerName", rs.getString("scanner_name"));
                vuln.put("scanDate", rs.getTimestamp("scan_date").toString());
                vulnerabilities.add(vuln);
            }
        } catch (SQLException e) {
            System.err.println("❌ Ошибка выполнения запроса уязвимостей: " + e.getMessage());
        }

        return vulnerabilities;
    }

    private String generateSessionId() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd_HHmmss");
        // Используем полное имя класса, чтобы избежать неоднозначности
        return "scan_" + sdf.format(new java.util.Date()) + "_" + UUID.randomUUID().toString().substring(0, 8);
    }
}